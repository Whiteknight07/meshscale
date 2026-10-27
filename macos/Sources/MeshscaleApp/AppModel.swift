import AppKit
import Combine
import MeshscaleCore
import SwiftUI

@MainActor final class AppModel: ObservableObject {
    enum Screen { case devices, detail, account, settings }
    enum Action: Hashable { case connect, disconnect, signIn, restartSignIn, cancelSignIn, signOut, ssh, launchAtLogin }
    @Published var status = AppStatus()
    @Published var screen: Screen = .devices
    @Published var selectedID: String?
    @Published var notice = ""
    @Published var noticeIsError = false
    @Published private(set) var actions: Set<Action> = []
    let client: (any MeshscaleClient)?
    private var termination: AnyCancellable?
    private var subscription: UUID?
    private var polling: Task<Void, Never>?
    private var pollDelay: Task<Void, Never>?
    private var noticeTask: Task<Void, Never>?
    private var refreshing = false
    private var refreshRequested = false
    private(set) var visible = false
    init(client: (any MeshscaleClient)? = nil, startPolling: Bool = true) {
        self.client = client
        if let client {
            termination = NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification).sink { [weak self] _ in
                MainActor.assumeIsolated { self?.shutdown() }
            }
            subscription = client.onChange { [weak self] status in
                guard let self else { return }
                if self.status != status { self.status = status }
                if status.auth != .signedIn { self.screen = .devices }
            }
            if startPolling { schedulePolling() }
        }
    }
    var now: Date { Date() }
    func setVisible(_ visible: Bool) {
        guard self.visible != visible else { return }
        self.visible = visible
        // Only interrupt the delay. An active refresh keeps its task and queues a
        // follow-up, so reopening cannot lose its immediate refresh to cancellation.
        if refreshing { refreshRequested = true }
        pollDelay?.cancel()
    }
    private func schedulePolling() {
        guard client != nil, polling == nil else { return }
        polling = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.refresh()
                guard !Task.isCancelled else { return }
                let delay = Task<Void, Never> { try? await Task.sleep(for: .seconds(self.visible ? 4 : 30)) }
                self.pollDelay = delay
                await delay.value
                self.pollDelay = nil
            }
        }
    }
    func refresh() async {
        guard let client else { return }
        if refreshing { refreshRequested = true; return }
        refreshing = true
        defer { refreshing = false }
        repeat {
            refreshRequested = false
            do {
                let status = try await client.getStatus()
                if self.status != status { self.status = status }
            } catch { if !(error is CancellationError) { notify(error.localizedDescription, error: true) } }
        } while refreshRequested && !Task.isCancelled
    }
    func navigate(_ screen: Screen, deviceID: String? = nil) {
        if !noticeIsError { notice = "" }
        self.screen = screen
        if let deviceID { selectedID = deviceID }
    }
    func canPerform(_ action: Action) -> Bool {
        guard !actions.contains(action) else { return false }
        switch action {
        case .connect, .signIn:
            return actions.isDisjoint(with: [.connect, .disconnect, .signIn, .restartSignIn, .cancelSignIn, .signOut])
        case .restartSignIn: return actions.isDisjoint(with: [.connect, .disconnect, .cancelSignIn, .signOut])
        case .cancelSignIn: return actions.isDisjoint(with: [.connect, .disconnect, .signOut])
        case .disconnect: return actions.isDisjoint(with: [.signIn, .restartSignIn, .cancelSignIn, .signOut, .ssh])
        case .signOut: return actions.isDisjoint(with: [.disconnect, .restartSignIn, .cancelSignIn, .ssh])
        case .ssh: return actions.isDisjoint(with: [.connect, .disconnect, .signIn, .restartSignIn, .cancelSignIn, .signOut])
        case .launchAtLogin: return !actions.contains(.signOut)
        }
    }
    // Resolve the user's intent before perform() can publish a changed status.
    func performConnectionAction() {
        let disconnect = status.connection == .connected || status.connection == .connecting
        if disconnect { perform(.disconnect) { try await $0.disconnect() } }
        else { perform(.connect) { try await $0.connect() } }
    }
    func perform(_ kind: Action, _ action: @escaping @MainActor (any MeshscaleClient) async throws -> Void, success: String? = nil) {
        guard let client else { return }
        guard canPerform(kind) else { notify("Wait for the current action to finish.", error: true); return }
        actions.insert(kind)
        noticeTask?.cancel(); notice = ""; client.dismissActionIssue()
        Task { [weak self] in
            defer { self?.actions.remove(kind) }
            do { try await action(client); if let success { self?.notify(success) } }
            catch { if !(error is CancellationError) { self?.notify(error.localizedDescription, error: true) } }
        }
    }
    func copy(_ text: String, command: Bool = false) {
        guard let client else { return }
        do { try client.copy(text: text); notify(command ? "Copied command" : "Copied \(text)") }
        catch { notify(error.localizedDescription, error: true) }
    }
    func dismissNotice() { noticeTask?.cancel(); notice = "" }
    func notify(_ text: String, error: Bool = false) {
        noticeTask?.cancel(); notice = text; noticeIsError = error
        if #available(macOS 14.0, *) { AccessibilityNotification.Announcement(text).post() }
        guard !error else { return }
        noticeTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(4))
            if !Task.isCancelled { self?.notice = "" }
        }
    }
    func escape() {
        if !notice.isEmpty { dismissNotice() }
        else if status.actionIssue != nil { client?.dismissActionIssue() }
        else if screen != .devices { navigate(.devices) }
        else { NSApplication.shared.keyWindow?.close() }
    }
    func prepareToTerminate() async {
        shutdown()
        await (client as? NativeClient)?.prepareToTerminate()
    }
    func shutdown() {
        polling?.cancel(); pollDelay?.cancel(); noticeTask?.cancel()
        (client as? NativeClient)?.cancelPendingActions()
        if let subscription { client?.unsubscribe(subscription) }
    }
}
