import Foundation

/// Native equivalent of MeshBridge. The UI owns no CLI or OS side effects.
@MainActor public protocol MeshscaleClient: AnyObject {
    func dismissActionIssue()
    func getStatus() async throws -> AppStatus
    func connect() async throws
    func clearPersonalRegistrationAndConnect() async throws
    func disconnect() async throws
    func signIn() async throws
    func cancelSignIn() async
    func signOut() async throws
    func copy(text: String) throws
    func openSSH(deviceID: String) async throws
    func quit()
    func setLaunchAtLogin(enabled: Bool) async throws
    func onChange(_ callback: @escaping @MainActor (AppStatus) -> Void) -> UUID
    func unsubscribe(_ token: UUID)
}

/// Pure CLI data adapter, also used by the executable's real-data check.
public actor CLIDataClient {
    private let runner: any CommandRunning
    private let persistAssociationCache: Bool
    public init(runner: any CommandRunning, persistAssociationCache: Bool = true) {
        self.runner = runner; self.persistAssociationCache = persistAssociationCache
    }
    public func devices() async throws -> [MeshDevice] {
        let data = try await runner.run(persistAssociationCache ? ["status", "--json"] : ["status", "--json", "--no-cache"], timeout: 30, gracePeriod: 1)
        let devices = try JSONDecoder().decode([MeshDevice].self, from: data)
        var identifiers: Set<String> = []
        guard devices.allSatisfy({ !$0.id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && identifiers.insert($0.id).inserted }),
              devices.filter(\.thisMachine).count <= 1 else {
            throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Ambiguous device identifiers in CLI response"))
        }
        return devices
    }
    public func account() async throws -> Account {
        let data = try await runner.run(["whoami", "--json"], timeout: 30, gracePeriod: 1)
        let account = try JSONDecoder().decode(Account.self, from: data)
        guard !account.id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Missing account identifier in CLI response"))
        }
        return account
    }
    public func signIn() async throws { _ = try await runner.run(["login"], timeout: 600, gracePeriod: 1) }
    public func signOut() async throws { _ = try await runner.run(["logout"], timeout: 30, gracePeriod: 1) }
    public func localConnection() async throws -> LocalConnection {
        let data = try await runner.run(["local-status", "--json"], timeout: 30, gracePeriod: 1)
        return try JSONDecoder().decode(LocalConnection.self, from: data)
    }
    public func connect(replaceConsumer: Bool = false, onProgress: @escaping @Sendable (ConnectionProgress) -> Void) async throws {
        let arguments = ["up", "--json"] + (replaceConsumer ? ["--replace-consumer"] : [])
        _ = try await runner.run(arguments, timeout: 330, gracePeriod: 12) { line in
            struct Event: Decodable { var state: ConnectionProgress }
            if let event = try? JSONDecoder().decode(Event.self, from: line) { onProgress(event.state) }
        }
    }
    public func disconnect() async throws { _ = try await runner.run(["down"], timeout: 20, gracePeriod: 1) }
}

public enum TerminalCommand {
    public static func shellQuote(_ string: String) -> String { "'" + string.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    public static func ssh(executable: String, username: String, device: MeshDevice, status: AppStatus) throws -> String {
        guard status.devices.contains(where: { $0.id == device.id && $0 == device }), status.canSSH(device),
              let target = device.address, !target.isEmpty,
              !username.isEmpty, !username.hasPrefix("-"), !target.hasPrefix("-"),
              !username.contains("@"), !target.contains("@"),
              !username.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              !target.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
        else { throw ClientError.sshUnavailable }
        return "\(shellQuote(executable)) ssh \(shellQuote(username + "@" + target))"
    }
    public static func appleScript(command: String) -> String {
        let escaped = command.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        return "tell application \"Terminal\"\nactivate\ndo script \"\(escaped)\"\nend tell"
    }
}
