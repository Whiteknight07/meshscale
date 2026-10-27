import AppKit
import MeshscaleCore
import ServiceManagement

@MainActor final class NativeClient: MeshscaleClient {
    let executable: URL
    private let data: CLIDataClient
    private let commands: ClientCommandRunner
    private let terminalCommands: ClientCommandRunner
    private var status = AppStatus()
    private var listeners: [UUID: @MainActor (AppStatus) -> Void] = [:]
    private var login: Task<Void, Error>?
    private var connection: Task<Void, Error>?
    private var generation = 0
    private var activeActions: Set<Int> = []
    private var fetchSequence = 0
    private var completedFetch = 0
    private var localObservation = 0
    // Unknown until a successful local observation or down; safety is separate.
    private var tunnelMayBeActive = true
    private var terminating = false
    private var identityReadAt = Date.distantPast
    private var lastEmitted: AppStatus?
    private let cleanupTimeout: TimeInterval
    private let launchAtLogin: @MainActor () -> Bool
    convenience init(executable: URL, environment: [String: String]? = nil) {
        self.init(executable: executable, runner: CLIProcessRunner(executable: executable, environment: environment), launchAtLogin: { SMAppService.mainApp.status == .enabled })
    }
    // Inject command execution without invoking the OS or the user's real CLI in tests.
    init(executable: URL, runner: any CommandRunning, terminalRunner: (any CommandRunning)? = nil, cleanupTimeout: TimeInterval = 14, launchAtLogin: @escaping @MainActor () -> Bool = { false }) {
        self.executable = executable
        let commands = ClientCommandRunner(runner: runner)
        self.commands = commands; self.data = CLIDataClient(runner: commands)
        self.terminalCommands = ClientCommandRunner(runner: terminalRunner ?? CLIProcessRunner(executable: URL(fileURLWithPath: "/usr/bin/osascript")))
        self.launchAtLogin = launchAtLogin; self.cleanupTimeout = cleanupTimeout
    }
    private func beginAction() -> Int {
        generation += 1
        activeActions.insert(generation)
        return generation
    }
    private func endAction(_ token: Int) {
        activeActions.remove(token)
        if token == generation { generation += 1 }
    }
    func getStatus() async throws -> AppStatus {
        guard activeActions.isEmpty, !terminating else { return status }
        return await refreshStatus()
    }
    private func refreshStatus() async -> AppStatus {
        let token = generation
        fetchSequence += 1
        let fetch = fetchSequence
        func current() -> Bool { token == generation && fetch > completedFetch && !terminating }
        // Publish one observation, so a late fetch cannot overwrite a newer one.
        var observed = status
        var readAt = identityReadAt
        if observed.account == nil || Date().timeIntervalSince(readAt) >= 60 {
            do {
                let account = try await data.account()
                guard current() else { return status }
                observed.account = account; observed.auth = .signedIn
                readAt = Date(); observed.identityIssue = nil
            } catch {
                guard current(), !(error is CancellationError) else { return status }
                if isSignedOut(error) {
                    observed = AppStatus(); observed.actionIssue = status.actionIssue
                    completedFetch = fetch; status = observed; emit(); return status
                }
                observed.identityIssue = issue(for: error, context: "account")
            }
        }
        // Local tunnel observations must survive an unrelated inventory failure.
        do {
            let local = try await data.localConnection()
            guard current() else { return status }
            // The CLI's connected flag is safety-filtered. Its raw state may still
            // be connected for consumer, wrong-org or unsafe registrations.
            if fetch > localObservation {
                localObservation = fetch
                tunnelMayBeActive = local.installed && (local.connected || local.state != "disconnected" || local.enrollment == "registration_error")
            }
            observed.connection = local.connected && local.safe ? .connected : .disconnected
            observed.connectionProgress = ConnectionProgress(rawValue: local.enrollment)
            observed.localIssue = observed.connectionProgress.flatMap { progress in
                progress.failed ? AppIssue(code: progress.rawValue, message: "Connection needs attention", recovery: progress.message) : nil
            }
        } catch {
            guard current(), !(error is CancellationError) else { return status }
            if fetch > localObservation { localObservation = fetch; tunnelMayBeActive = true }
            observed.connection = .error
            observed.localIssue = issue(for: error, context: "local connection")
        }
        do {
            let devices = try await data.devices()
            guard current() else { return status }
            observed.devices = devices; observed.updatedAt = Date(); observed.inventoryIssue = nil
        } catch {
            guard current(), !(error is CancellationError) else { return status }
            observed.inventoryIssue = issue(for: error, context: "device inventory")
        }
        guard current() else { return status }
        observed.actionIssue = status.actionIssue
        observed.launchAtLogin = launchAtLogin()
        completedFetch = fetch; identityReadAt = readAt
        status = observed; emit(); return status
    }
    private func isSignedOut(_ error: any Error) -> Bool {
        if error as? ClientError == .signedOut { return true }
        if case .commandFailed(_, .signedOut) = error as? ProcessError { return true }
        return false
    }
    private func issue(for error: any Error, context: String) -> AppIssue {
        if error is DecodingError {
            return AppIssue(code: "invalid-response", message: "Cannot read meshscale \(context)", recovery: "The CLI returned an invalid response. Update meshscale, then choose Refresh.")
        }
        if error as? ProcessError == .launchFailed {
            return AppIssue(code: "cli-unavailable", message: "Cannot launch meshscale CLI", recovery: ProcessError.launchFailed.localizedDescription)
        }
        return AppIssue(code: "fetch-\(context)", message: "Cannot refresh \(context)", recovery: error.localizedDescription)
    }
    func dismissActionIssue() { status.actionIssue = nil; emit() }
    func connect() async throws { try await connect(replaceConsumer: false) }
    func clearPersonalRegistrationAndConnect() async throws { try await connect(replaceConsumer: true) }
    private func connect(replaceConsumer: Bool) async throws {
        guard connection == nil, !terminating else { return }
        let token = beginAction()
        defer { endAction(token) }
        tunnelMayBeActive = true
        status.connection = .connecting; status.connectionProgress = .preparing; status.actionIssue = nil; status.localIssue = nil; emit()
        let data = self.data
        let task = Task { [weak self, data] in
            try await data.connect(replaceConsumer: replaceConsumer) { [weak self] progress in
                Task { @MainActor [weak self] in
                    guard let self, self.generation == token, self.connection != nil else { return }
                    self.status.connectionProgress = progress
                    if progress.failed {
                        self.status.connection = .error
                        self.status.actionIssue = AppIssue(code: progress.rawValue, message: "Connection needs attention", recovery: progress.message)
                    }
                    self.emit()
                }
            }
        }
        connection = task
        do {
            try await task.value
            guard token == generation else { return }
            connection = nil
            _ = await refreshStatus()
        } catch {
            guard token == generation else { return }
            connection = nil
            if error is CancellationError { return }
            status.connection = .error
            if status.actionIssue == nil {
                if status.connectionProgress == .registration_pending {
                    status.actionIssue = AppIssue(code: "registration_pending", message: "Sign-in is still pending", recovery: "Finish signing in in your browser, then choose Connect.")
                } else if error as? ProcessError == .launchFailed || error is DecodingError {
                    status.actionIssue = issue(for: error, context: "connection")
                } else {
                    status.actionIssue = AppIssue(code: "connection_failed", message: "Connection failed", recovery: ConnectionProgress.connection_failed.message)
                }
            }
            emit()
        }
    }
    func disconnect() async throws {
        guard !terminating else { return }
        let token = beginAction()
        defer { endAction(token) }
        status.actionIssue = nil
        try await disconnectTunnel(token: token)
        guard token == generation else { return }
        status.connection = .disconnected; status.connectionProgress = nil; status.localIssue = nil; emit()
        _ = await refreshStatus()
    }
    private func disconnectTunnel(token: Int) async throws {
        let pending = connection; connection = nil; pending?.cancel()
        // The runner kills up after its 12s cleanup grace. Also cap this wait so a
        // nonresponsive command adapter cannot indefinitely block the escape action.
        if let pending { await waitForCleanup(pending, seconds: cleanupTimeout) }
        guard token == generation, !terminating else { return }
        do { try await data.disconnect() }
        catch { tunnelMayBeActive = true; throw error }
        guard token == generation else { return }
        tunnelMayBeActive = false
    }
    private func waitForCleanup(_ task: Task<Void, Error>, seconds: TimeInterval) async {
        await withCheckedContinuation { continuation in
            var resumed = false
            let timeout = Task { @MainActor in
                do { try await Task.sleep(for: .seconds(seconds)) } catch { return }
                if !resumed { resumed = true; continuation.resume() }
            }
            Task { @MainActor in
                _ = await task.result
                if !resumed { resumed = true; continuation.resume() }
                timeout.cancel()
            }
        }
    }
    func signIn() async throws {
        guard !terminating else { return }
        // Capture restart intent before releasing the previous loopback listener.
        let token = beginAction()
        defer { endAction(token) }
        let pending = login; login = nil; pending?.cancel()
        if let pending { _ = await pending.result }
        guard token == generation, !terminating, !Task.isCancelled else { return }
        status.auth = .signingIn; status.actionIssue = nil; status.localIssue = nil; emit()
        let task = Task { try await data.signIn() }
        login = task
        do {
            try await task.value
            guard token == generation else { return }
            login = nil; identityReadAt = .distantPast
            _ = await refreshStatus()
        } catch {
            guard token == generation else { return }
            login = nil; status.auth = .signedOut; emit()
            if error is CancellationError { return }
            throw error
        }
    }
    func cancelSignIn() async {
        let token = beginAction()
        defer { endAction(token) }
        let pending = login; login = nil; pending?.cancel()
        // Also invalidates a restart that is waiting for the previous login.
        if let pending { _ = await pending.result }
        guard token == generation else { return }
        if status.auth == .signingIn { status.auth = .signedOut; emit() }
    }
    func signOut() async throws {
        guard !terminating else { return }
        let token = beginAction()
        defer { endAction(token) }
        let pending = login; login = nil; pending?.cancel()
        if let pending { _ = await pending.result }
        guard token == generation, !terminating else { return }
        var disconnectFailure: (any Error)?
        if tunnelMayBeActive || connection != nil {
            do { try await disconnectTunnel(token: token) }
            catch { disconnectFailure = error }
        }
        guard token == generation, !terminating else { return }
        if let disconnectFailure {
            status.actionIssue = AppIssue(code: "disconnect_failed", message: "Cloudflare may still be connected", recovery: "Sign-out could not turn off the tunnel. Open Cloudflare One to disconnect. " + disconnectFailure.localizedDescription)
            emit()
        }
        // Credential removal must still be attempted when down fails.
        try await data.signOut()
        guard token == generation else { return }
        let actionIssue = status.actionIssue
        status = AppStatus(); status.actionIssue = actionIssue; identityReadAt = .distantPast; emit()
        _ = await refreshStatus()
        guard token == generation else { return }
        if let disconnectFailure { throw disconnectFailure }
        if status.auth == .signedIn {
            throw NSError(domain: "meshscale", code: 1, userInfo: [NSLocalizedDescriptionKey: "Cloudflare API credentials are still configured. Remove them to sign out of this account."])
        }
    }
    func copy(text: String) throws {
        NSPasteboard.general.clearContents()
        guard NSPasteboard.general.setString(text, forType: .string) else { throw ClientError.clipboardUnavailable }
    }
    func openSSH(deviceID: String) async throws {
        guard !terminating, activeActions.isEmpty else { throw CancellationError() }
        let token = generation
        _ = try await getStatus()
        guard token == generation, !terminating else { throw CancellationError() }
        try Task.checkCancellation()
        guard !status.inventoryIsStale(), let device = status.devices.first(where: { $0.id == deviceID }) else { throw ClientError.sshUnavailable }
        let command = try TerminalCommand.ssh(executable: executable.path, username: NSUserName(), device: device, status: status)
        let script = TerminalCommand.appleScript(command: command)
        // Pass the script as an argument. No shell interpolation of remote names.
        _ = try await terminalCommands.run(["-e", script], timeout: 15, gracePeriod: 1)
    }
    func cancelPendingActions() {
        generation += 1
        login?.cancel(); connection?.cancel()
    }
    func prepareToTerminate() async {
        terminating = true
        cancelPendingActions()
        let commands = self.commands
        let terminalCommands = self.terminalCommands
        let cleanup = Task<Void, Error> {
            async let cli: Void = commands.cancelAndWait()
            async let terminal: Void = terminalCommands.cancelAndWait()
            _ = await (cli, terminal)
        }
        // Production runners finish after SIGTERM/SIGKILL, including the 12s
        // enrollment grace. Retain a 14s cap for a nonresponsive injected runner.
        await waitForCleanup(cleanup, seconds: cleanupTimeout)
    }
    func quit() { NSApplication.shared.terminate(nil) }
    func setLaunchAtLogin(enabled: Bool) async throws {
        guard !terminating else { return }
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try await SMAppService.mainApp.unregister() }
            status.launchAtLogin = SMAppService.mainApp.status == .enabled
            emit()
            if enabled && !status.launchAtLogin { throw ClientError.launchAtLoginFailed }
        } catch { status.launchAtLogin = SMAppService.mainApp.status == .enabled; emit(); throw ClientError.launchAtLoginFailed }
    }
    func onChange(_ callback: @escaping @MainActor (AppStatus) -> Void) -> UUID {
        let token = UUID(); listeners[token] = callback; return token
    }
    func unsubscribe(_ token: UUID) { listeners[token] = nil }
    private func emit() {
        guard status != lastEmitted else { return }
        lastEmitted = status
        for callback in listeners.values { callback(status) }
    }
}
