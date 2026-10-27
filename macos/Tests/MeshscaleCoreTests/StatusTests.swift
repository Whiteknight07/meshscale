import Foundation
import XCTest
@testable import MeshscaleCore

final class StatusTests: XCTestCase {
    func testFreshnessTracksFetchSuccessAndAgeRatherThanLocalConnection() {
        let now = Date()
        var status = AppStatus()
        XCTAssertTrue(status.inventoryIsStale(now: now))
        status.updatedAt = now
        status.connection = .disconnected
        XCTAssertFalse(status.inventoryIsStale(now: now))
        status.connection = .connected
        XCTAssertTrue(status.inventoryIsStale(now: now.addingTimeInterval(61)))
        status.inventoryIssue = AppIssue(code: "inventory", message: "Failed", recovery: "Refresh")
        XCTAssertTrue(status.inventoryIsStale(now: now))
    }
    func testTurnOffOnlyAppearsForPossiblyConnectedIssues() {
        let allowed: Set<String> = ["safety_blocked", "connection_failed", "error", "different_org"]
        for progress in [ConnectionProgress.not_installed, .consumer, .different_org, .registration_error, .setup_failed, .safety_blocked, .connection_failed, .error, .registration_pending] {
            let issue = AppIssue(code: progress.rawValue, message: "", recovery: "")
            XCTAssertEqual(issue.canTurnOffConnection, allowed.contains(progress.rawValue))
        }
        XCTAssertFalse(AppIssue(code: "cli-unavailable", message: "", recovery: "").canTurnOffConnection)
    }
    func testDeviceKindIncludesIPadOSAndAllSSHChecksUseIt() throws {
        var status = ReviewFixture.status("connected")
        var device = try XCTUnwrap(status.devices.first { $0.id == "node-homelab" })
        for os in ["iOS", "iPadOS", "ANDROID", "phone"] {
            device.os = os; status.devices = [device]
            XCTAssertTrue(device.isMobile)
            XCTAssertFalse(status.canSSH(device))
        }
        for os in ["macos", "linux", "windows"] {
            device.os = os; status.devices = [device]
            XCTAssertFalse(device.isMobile)
            XCTAssertTrue(status.canSSH(device))
        }
    }
    func testIssuesKeepActionAndInventoryFailuresSeparateAndDeduplicateSameCode() {
        var status = AppStatus()
        let action = AppIssue(code: "connection_failed", message: "Action failed", recovery: "Retry")
        status.actionIssue = action
        status.localIssue = AppIssue(code: "connection_failed", message: "Local failed", recovery: "Refresh")
        status.inventoryIssue = AppIssue(code: "inventory", message: "Stale inventory", recovery: "Refresh")
        XCTAssertEqual(status.issues.map(\.code), ["connection_failed", "inventory"])
        XCTAssertEqual(status.issues.first, action)
    }
}
