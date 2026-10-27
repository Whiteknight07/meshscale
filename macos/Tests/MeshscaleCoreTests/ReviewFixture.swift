import Foundation
@testable import MeshscaleCore

public enum ReviewFixture {
    public static let states = ["signed-out", "signing-in", "connected", "disconnected", "connecting", "error", "empty", "device-detail", "offline-detail", "account", "settings", "mac-unavailable", "mac-empty", "mac-device-detail", "mac-error", "mac-account", "enrollment-pending", "checking-safety", "consumer-registration", "wrong-organization", "client-missing", "safety-blocked", "connected-mac", "disconnected-mac", "connecting-mac", "ssh-enabled", "secure-detail", "secure-pending-detail", "exit-selected-detail"]
    public static let now = ISO8601DateFormatter().date(from: "2026-10-26T12:00:00Z")!
    public static func status(_ state: String) -> AppStatus {
        // Copied verbatim from the approved frontend mock; never used by the live client.
        let json = #"""
        [
          {"id":"reg-mac","device_id":"dev-mac","kind":"device","name":"macbook-air","dns_name":"macbook-air.mesh","user":"alex@hey.com","ipv4":"100.96.0.2","os":"mac","online":true,"last_seen_at":"2026-10-26T12:00:00Z","this_machine":true},
          {"id":"node-homelab","registration_id":"reg-homelab","kind":"node","name":"homelab","dns_name":"homelab.mesh","user":"Mesh node","ipv4":"100.96.0.10","os":"linux","online":true,"last_seen_at":"2026-10-26T12:00:00Z","this_machine":false,"connection_state":"healthy"},
          {"id":"reg-pixel","device_id":"dev-pixel","kind":"device","name":"pixel-9","dns_name":"pixel-9.mesh","user":"alex@hey.com","ipv4":"100.96.0.12","os":"android","online":true,"last_seen_at":"2026-10-26T12:00:00Z","this_machine":false},
          {"id":"node-nas","registration_id":"reg-nas","kind":"node","name":"nas","dns_name":"nas.mesh","user":"Mesh node","ipv4":"100.96.0.20","os":"linux","online":true,"last_seen_at":"2026-10-26T12:00:00Z","this_machine":false},
          {"id":"reg-thinkpad","kind":"device","name":"old-thinkpad","dns_name":"old-thinkpad.mesh","user":"alex@hey.com","ipv4":"100.96.0.31","os":"linux","online":false,"last_seen_at":"2026-10-23T12:00:00Z","this_machine":false}
        ]
        """#
        var value = AppStatus()
        value.auth = .signedIn
        value.account = Account(id: "account-personal", name: "Personal account", email: "alex@hey.com")
        value.devices = try! JSONDecoder().decode([MeshDevice].self, from: Data(json.utf8))
        value.connection = .connected
        value.updatedAt = now; value.launchAtLogin = true
        if state == "signed-out" || state == "signing-in" {
            value.auth = state == "signed-out" ? .signedOut : .signingIn
            value.account = nil; value.devices = []; value.connection = .disconnected
        }
        if ["disconnected", "connecting", "error"].contains(state) {
            value.connection = state == "disconnected" ? .disconnected : state == "connecting" ? .connecting : .error
            value.devices[0].online = false
        }
        if state == "error" { value.localIssue = AppIssue(code: "cloudflare-unreachable", message: "Cannot reach Cloudflare", recovery: "Check your internet connection, then choose Connect to try again.") }
        if state == "empty" { value.devices = Array(value.devices.prefix(1)) }
        if state.hasPrefix("mac-") {
            value.connection = .disconnected
            value.devices.removeAll { $0.thisMachine }
            if state == "mac-empty" { value.devices = [] }
            if state == "mac-error" {
                value.connection = .error
                value.localIssue = AppIssue(code: "cloudflare-unreachable", message: "Cannot reach Cloudflare", recovery: "Check your internet connection, then choose Refresh to try again.")
            }
        }
        if ["enrollment-pending", "checking-safety", "connecting-mac"].contains(state) {
            value.connection = .connecting
            value.connectionProgress = state == "enrollment-pending" ? .registration_pending : state == "checking-safety" ? .checking_safety : .connecting
            value.devices[0].online = false
            if state == "enrollment-pending" { value.devices.removeAll { $0.thisMachine } }
        }
        if state == "disconnected-mac" { value.connection = .disconnected; value.devices[0].online = false }
        if state == "connected-mac" { value.devices[0].ipv4 = "100.96.0.6" }
        let failures: [String: ConnectionProgress] = ["consumer-registration": .consumer, "wrong-organization": .different_org, "client-missing": .not_installed, "safety-blocked": .safety_blocked]
        if let progress = failures[state] {
            value.connection = .error; value.connectionProgress = progress
            value.localIssue = AppIssue(code: progress.rawValue, message: "Connection needs attention", recovery: progress.message)
            value.devices.removeAll { $0.thisMachine }
        }
        if ["secure-detail", "secure-pending-detail", "exit-selected-detail"].contains(state) {
            value.devices[1].onlineSource = "probe"
            value.devices[1].secure = SecurePeer(enabled: true, ip: "fd6d:6573:6873::10", dnsName: "homelab.secure", publicKey: "fixture", lastHandshake: nil, handshakeAgeSeconds: state == "secure-pending-detail" ? nil : 12)
            value.devices[1].offersExitNode = true
            if state == "exit-selected-detail" {
                value.devices[1].offersExitNode = false
                value.devices[1].exitNode = "nas"
                value.devices[1].exitState = "ready (egress not probed)"
            }
        }
        return value
    }
}
