import Foundation

public struct SecurePeer: Codable, Equatable, Sendable {
    public var enabled: Bool
    public var ip: String
    public var dnsName: String
    public var publicKey: String
    public var lastHandshake: String?
    public var handshakeAgeSeconds: Int64?
    enum CodingKeys: String, CodingKey {
        case enabled, ip
        case dnsName = "dns_name", publicKey = "public_key"
        case lastHandshake = "last_handshake", handshakeAgeSeconds = "handshake_age_seconds"
    }
}

public struct MeshDevice: Codable, Identifiable, Equatable, Sendable {
    public var id: String
    public var registrationID: String?
    public var deviceID: String?
    public var kind: String
    public var name: String
    public var dnsName: String?
    public var user: String?
    public var ipv4: String?
    public var ipv6: String?
    public var os: String?
    public var online: Bool
    public var onlineSource: String? = nil
    public var sshPolicy: String? = nil
    public var lastSeenAt: String?
    public var thisMachine: Bool
    public var connectionState: String?
    public var secure: SecurePeer? = nil
    public var offersExitNode: Bool? = nil
    public var exitNode: String? = nil
    public var exitState: String? = nil
    public var exitNodeAllowLANAccess: Bool? = nil

    enum CodingKeys: String, CodingKey {
        case id, kind, name, user, ipv4, ipv6, os, online, secure
        case onlineSource = "online_source", sshPolicy = "ssh_policy"
        case offersExitNode = "offers_exit_node", exitNode = "exit_node", exitState = "exit_state"
        case exitNodeAllowLANAccess = "exit_node_allow_lan_access"
        case registrationID = "registration_id", deviceID = "device_id", dnsName = "dns_name"
        case lastSeenAt = "last_seen_at", thisMachine = "this_machine", connectionState = "connection_state"
    }
    public var address: String? { [ipv4, ipv6].compactMap { $0 }.first { !$0.isEmpty } }
    /// Peer capability and observations; these never imply this Mac uses secure mode.
    public var peerStatusNotes: [String] {
        var notes: [String] = []
        if let sshPolicy, sshPolicy != "configured" { notes.append("SSH: \(sshPolicy)") }
        if online && onlineSource == "probe" { notes.append("Online via probe") }
        if let secure, secure.enabled {
            if let age = secure.handshakeAgeSeconds {
                notes.append("Secure peer · handshake \(max(0, age))s ago")
            } else if secure.lastHandshake != nil {
                notes.append("Secure peer · handshake recorded")
            } else {
                notes.append("Secure peer · no handshake observed")
            }
        }
        if let exitNode, !exitNode.isEmpty {
            notes.append("Exit node: \(exitNode)")
            if let exitState, !exitState.isEmpty { notes.append(exitState) }
        } else if offersExitNode == true {
            notes.append("Offers an exit node")
        }
        return notes
    }
    public var isMobile: Bool { ["android", "ios", "ipados", "phone"].contains(os?.lowercased() ?? "") }
    public var systemName: String {
        switch os?.lowercased() {
        case "mac", "macos": "macOS"
        case "linux": "Linux"
        case "android": "Android"
        case "ios": "iOS"
        case "ipados": "iPadOS"
        case "windows": "Windows"
        default: os ?? "Device"
        }
    }
    public func lastSeen(now: Date = Date()) -> String {
        guard let lastSeenAt, let date = Self.parseDate(lastSeenAt) else { return "Last seen unknown" }
        let age = max(0, now.timeIntervalSince(date))
        if age < 60 { return "Last seen just now" }
        let (n, unit) = age < 3600 ? (Int(age / 60), "minute") : age < 86400 ? (Int(age / 3600), "hour") : (Int(age / 86400), "day")
        return "Last seen \(n) \(unit)\(n == 1 ? "" : "s") ago"
    }
    private static let dateParser = DateParser()
    private static func parseDate(_ string: String) -> Date? { dateParser.parse(string) }

}

public struct Account: Codable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var email: String?
    public var credentials: String?
    /// Account name for display. Cloudflare's default name is "<email>'s Account",
    /// which only repeats the email shown above it.
    public var displayName: String {
        guard let email, name.caseInsensitiveCompare("\(email)'s Account") == .orderedSame else { return name }
        return "Cloudflare account"
    }

    public init(id: String, name: String, email: String? = nil, credentials: String? = nil) {
        self.id = id; self.name = name; self.email = email; self.credentials = credentials
    }
}
public enum AuthState: String, Sendable { case signedOut, signingIn, signedIn }
public enum ConnectionState: String, Sendable { case connected, connecting, disconnected, error }
public enum ConnectionProgress: String, Codable, Sendable {
    case preparing, registration_pending, checking_safety, connecting, connected
    case not_installed, consumer, different_org, registration_error, setup_failed, safety_blocked, connection_failed, error
    public var message: String {
        switch self {
        case .preparing: "Preparing device enrollment"
        case .registration_pending: "Finish signing in in your browser"
        case .checking_safety: "Checking safety settings"
        case .connecting: "Connecting"
        case .connected: "Connected"
        case .not_installed: "Install Cloudflare One to connect this Mac."
        case .consumer: "This Mac has a personal Cloudflare registration. Clear it to sign in to your team."
        case .different_org: "This Mac belongs to another Cloudflare organization. Leave that organization in Cloudflare One before connecting."
        case .registration_error: "Open Cloudflare One and check that its service is running."
        case .setup_failed: "Device enrollment setup needs attention. Run meshscale setup --devices in Terminal."
        case .safety_blocked: "Cloudflare’s current profile could route all traffic. Select the meshscale Include profile before connecting."
        case .connection_failed, .error: "Cloudflare did not connect. Turn off the connection, then try again."
        }
    }
    public var failed: Bool {
        switch self { case .preparing, .registration_pending, .checking_safety, .connecting, .connected: false; default: true }
    }
}
public struct LocalConnection: Codable, Equatable, Sendable {
    public var installed: Bool
    public var state: String
    public var connected: Bool
    public var safe: Bool
    public var enrollment: String
}
public struct AppIssue: Equatable, Sendable {
    public var code: String
    public var message: String
    public var recovery: String
    public var canTurnOffConnection: Bool { ["safety_blocked", "connection_failed", "error", "different_org", "disconnect_failed"].contains(code) }
    public init(code: String, message: String, recovery: String) { self.code = code; self.message = message; self.recovery = recovery }
}
public struct AppStatus: Equatable, Sendable {
    public var auth: AuthState = .signedOut
    public var account: Account?
    public var connection: ConnectionState = .disconnected
    public var devices: [MeshDevice] = []
    public var updatedAt: Date?
    public var localIssue: AppIssue?
    public var identityIssue: AppIssue?
    public var inventoryIssue: AppIssue?
    public var actionIssue: AppIssue?
    public var issues: [AppIssue] {
        var result: [AppIssue] = []
        for issue in [actionIssue, localIssue, identityIssue, inventoryIssue].compactMap({ $0 }) {
            if !result.contains(where: { $0.code == issue.code }) { result.append(issue) }
        }
        return result
    }
    public func inventoryIsStale(now: Date = Date()) -> Bool {
        inventoryIssue != nil || updatedAt.map { now.timeIntervalSince($0) > 60 } ?? true
    }
    public var launchAtLogin = false
    public var connectionProgress: ConnectionProgress?
    public init() {}
    public func canSSH(_ device: MeshDevice) -> Bool {
        (device.sshPolicy == nil || device.sshPolicy == "configured") && connection == .connected && device.online && !device.thisMachine && !device.isMobile && device.address != nil
    }
}
public enum ClientError: Error, LocalizedError, Equatable {
    case signedOut, unavailable, signInFailed, accountSelectionRequired, connectivityUnavailable, sshUnavailable, clipboardUnavailable, launchAtLoginFailed
    public var errorDescription: String? {
        switch self {
        case .signedOut: "Sign in with Cloudflare to see your devices."
        case .unavailable: "Cannot reach Cloudflare. Check your internet connection, then choose Refresh to try again."
        case .signInFailed: "Sign in with Cloudflare did not finish. Choose Sign in with Cloudflare to try again."
        case .accountSelectionRequired: "Choose a Cloudflare account with the bundled meshscale login in Terminal, then reopen meshscale."
        case .connectivityUnavailable: "Open Cloudflare One and check that its service is running, then choose Connect."
        case .sshUnavailable: "SSH is unavailable for this device."
        case .clipboardUnavailable: "Cannot copy to the clipboard. Try again."
        case .launchAtLoginFailed: "Cannot change Launch at login. Check Login Items in System Settings, then try again."
        }
    }
}

private final class DateParser: @unchecked Sendable {
    private let lock = NSLock()
    private let plain = ISO8601DateFormatter()
    private let fractional: ISO8601DateFormatter = {
        let parser = ISO8601DateFormatter()
        parser.formatOptions.insert(.withFractionalSeconds)
        return parser
    }()
    func parse(_ string: String) -> Date? {
        lock.lock(); defer { lock.unlock() }
        return plain.date(from: string) ?? fractional.date(from: string)
    }
}
