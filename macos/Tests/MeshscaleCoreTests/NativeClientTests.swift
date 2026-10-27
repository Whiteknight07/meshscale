import AppKit
import Foundation
import XCTest
@testable import MeshscaleApp
@testable import MeshscaleCore

actor TestGate {
    private var opened = false
    private var cancellationObserved = false
    private var cancellationWaiters: [CheckedContinuation<Void, Never>] = []
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func wait() async {
        if opened { return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func cancelled() {
        cancellationObserved = true
        for waiter in cancellationWaiters { waiter.resume() }; cancellationWaiters.removeAll()
    }
    func waitForCancellation() async {
        if cancellationObserved { return }
        await withCheckedContinuation { cancellationWaiters.append($0) }
    }
    func open() { opened = true; for waiter in waiters { waiter.resume() }; waiters.removeAll() }
}

actor ScriptedRunner: CommandRunning {
    struct Reply: Sendable {
        var data = Data()
        var error: ProcessError?
        var gate: TestGate?
    }
    struct Call: Sendable { var command: String; var gracePeriod: TimeInterval }
    private(set) var calls: [Call] = []
    private var replies: [String: [Reply]] = [:]
    private var waiters: [(String, Int, CheckedContinuation<Void, Never>)] = []
    private var loggedOut = false
    func enqueue(_ command: String, _ reply: Reply) { replies[command, default: []].append(reply) }
    func waitForCall(_ command: String, count: Int = 1) async {
        if calls.filter({ $0.command == command }).count >= count { return }
        await withCheckedContinuation { waiters.append((command, count, $0)) }
    }
    func run(_ arguments: [String], timeout: TimeInterval, gracePeriod: TimeInterval) async throws -> Data {
        let command = arguments[0]
        calls.append(Call(command: command, gracePeriod: gracePeriod))
        let ready = waiters.filter { command, count, _ in calls.filter { $0.command == command }.count >= count }
        waiters.removeAll { command, count, _ in calls.filter { $0.command == command }.count >= count }
        for (_, _, waiter) in ready { waiter.resume() }
        var reply: Reply
        if var queued = replies[command], !queued.isEmpty {
            reply = queued.removeFirst(); replies[command] = queued
        } else {
            switch command {
            case "whoami":
                reply = loggedOut ? Reply(error: .commandFailed(exitCode: 1, stderr: .signedOut)) : Reply(data: Data(#"{"id":"account","name":"Test account"}"#.utf8))
            case "local-status": reply = Reply(data: Data(#"{"installed":true,"state":"connected","connected":true,"safe":true,"enrollment":"connected"}"#.utf8))
            case "status": reply = Reply(data: Data("[]".utf8))
            default: reply = Reply()
            }
        }
        if let gate = reply.gate {
            await withTaskCancellationHandler { await gate.wait() } onCancel: { Task { await gate.cancelled() } }
        }
        if let error = reply.error { throw error }
        if command == "logout" { loggedOut = true }
        return reply.data
    }
}

@MainActor private func testClient(runner: any CommandRunning, cleanupTimeout: TimeInterval = 14) -> NativeClient {
    NativeClient(executable: URL(fileURLWithPath: "/test/meshscale"), runner: runner, cleanupTimeout: cleanupTimeout)
}

@MainActor final class NativeClientTests: XCTestCase {
    func testInventoryFailurePreservesLocalConnectionAndLastInventory() async throws {
        let runner = ScriptedRunner()
        let subject = testClient(runner: runner)
        let inventory = try JSONEncoder().encode(ReviewFixture.status("connected").devices)
        await runner.enqueue("status", .init(data: inventory))
        let first = try await subject.getStatus()
        await runner.enqueue("status", .init(error: .commandFailed(exitCode: 4, stderr: .other)))
        let stale = try await subject.getStatus()
        XCTAssertEqual(stale.connection, .connected)
        XCTAssertEqual(stale.auth, .signedIn)
        XCTAssertEqual(stale.devices, first.devices)
        XCTAssertEqual(stale.updatedAt, first.updatedAt)
        XCTAssertNotNil(stale.inventoryIssue)
        XCTAssertNil(stale.localIssue)
        XCTAssertTrue(stale.inventoryIsStale())
        let recovered = try await subject.getStatus()
        XCTAssertNil(recovered.inventoryIssue)
        XCTAssertFalse(recovered.inventoryIsStale())
    }
    func testSignedInRequiresDecodedAccountAndFailuresHaveSpecificMessages() async throws {
        for (reply, code) in [(ScriptedRunner.Reply(error: .launchFailed), "cli-unavailable"), (.init(data: Data("invalid".utf8)), "invalid-response")] {
            let runner = ScriptedRunner()
            await runner.enqueue("whoami", reply)
            let status = try await testClient(runner: runner).getStatus()
            XCTAssertEqual(status.auth, .signedOut)
            XCTAssertNil(status.account)
            XCTAssertEqual(status.identityIssue?.code, code)
            XCTAssertEqual(status.connection, .connected, "Account errors cannot overwrite local observations")
            XCTAssertFalse(status.identityIssue?.message.contains("Cannot reach Cloudflare") ?? true)
        }
        let runner = ScriptedRunner()
        await runner.enqueue("status", .init(data: Data("invalid".utf8)))
        let status = try await testClient(runner: runner).getStatus()
        XCTAssertEqual(status.auth, .signedIn, "Decoded identity is enough even when inventory decoding fails")
        XCTAssertEqual(status.inventoryIssue?.code, "invalid-response")
    }
    func testSignedOutCategoryWorksWithAnyExitCode() async throws {
        let runner = ScriptedRunner()
        await runner.enqueue("whoami", .init(error: .commandFailed(exitCode: 7, stderr: .signedOut)))
        let status = try await testClient(runner: runner).getStatus()
        XCTAssertEqual(status.auth, .signedOut)
        XCTAssertTrue(status.issues.isEmpty)
    }
    func testLocalFailureDoesNotDiscardSuccessfulInventory() async throws {
        let runner = ScriptedRunner()
        await runner.enqueue("local-status", .init(data: Data("bad JSON".utf8)))
        let status = try await testClient(runner: runner).getStatus()
        XCTAssertEqual(status.connection, .error)
        XCTAssertEqual(status.localIssue?.code, "invalid-response")
        XCTAssertNotNil(status.updatedAt)
        XCTAssertNil(status.inventoryIssue)
    }
    func testSignOutSurfacesDisconnectFailureButStillRemovesCredentials() async throws {
        let runner = ScriptedRunner(), client = testClient(runner: runner)
        _ = try await client.getStatus()
        await runner.enqueue("down", .init(error: .timedOut))
        do { try await client.signOut(); XCTFail("Expected disconnect failure") }
        catch { XCTAssertEqual(error as? ProcessError, .timedOut) }
        let calls = await runner.calls.map(\.command)
        XCTAssertLessThan(try XCTUnwrap(calls.firstIndex(of: "down")), try XCTUnwrap(calls.firstIndex(of: "logout")))
        let status = try await client.getStatus()
        XCTAssertEqual(status.auth, .signedOut)
        XCTAssertEqual(status.actionIssue?.code, "disconnect_failed")
        XCTAssertEqual(status.actionIssue?.canTurnOffConnection, true, "Recovery remains available after logout")
    }
    func testSignOutDisconnectsUnsafeRawConnectionsAndUnknownObservations() async throws {
        // local-status can suppress connected=true while the physical tunnel is up.
        let replies: [ScriptedRunner.Reply?] = [nil,
            .init(data: Data(#"{"installed":true,"state":"connected","connected":false,"safe":false,"enrollment":"safety_blocked"}"#.utf8)),
            .init(data: Data(#"{"installed":true,"state":"connected","connected":false,"safe":false,"enrollment":"different_org"}"#.utf8)),
            .init(data: Data(#"{"installed":true,"state":"connected","connected":false,"safe":false,"enrollment":"consumer"}"#.utf8)),
            .init(data: Data(#"{"installed":true,"state":"disconnected","connected":false,"safe":false,"enrollment":"registration_error"}"#.utf8)),
            .init(error: .timedOut)]
        for reply in replies {
            let runner = ScriptedRunner(), client = testClient(runner: runner)
            if let reply { await runner.enqueue("local-status", reply); _ = try await client.getStatus() }
            try await client.signOut()
            let calls = await runner.calls.map(\.command)
            XCTAssertTrue(calls.contains("down"))
            XCTAssertTrue(calls.contains("logout"))
        }
    }
    func testSignOutUsesPhysicalObservationWhileInventoryIsPending() async throws {
        let runner = ScriptedRunner(), inventory = TestGate()
        let client = testClient(runner: runner)
        await runner.enqueue("local-status", .init(data: Data(#"{"installed":true,"state":"disconnected","connected":false,"safe":true,"enrollment":"registered"}"#.utf8)))
        _ = try await client.getStatus()
        await runner.enqueue("local-status", .init(data: Data(#"{"installed":true,"state":"connected","connected":false,"safe":false,"enrollment":"different_org"}"#.utf8)))
        await runner.enqueue("status", .init(data: Data("[]".utf8), gate: inventory))
        let poll = Task { try await client.getStatus() }
        await runner.waitForCall("status", count: 2)
        try await client.signOut()
        let calls = await runner.calls.map(\.command)
        XCTAssertTrue(calls.contains("down"), "Remote inventory cannot delay knowledge that the tunnel may be active")
        await inventory.open(); _ = try await poll.value
    }
    func testSignOutSkipsDownOnlyAfterObservedPhysicalDisconnection() async throws {
        let runner = ScriptedRunner(), client = testClient(runner: runner)
        await runner.enqueue("local-status", .init(data: Data(#"{"installed":true,"state":"disconnected","connected":false,"safe":true,"enrollment":"registered"}"#.utf8)))
        _ = try await client.getStatus()
        try await client.signOut()
        let calls = await runner.calls.map(\.command)
        XCTAssertFalse(calls.contains("down"))
        XCTAssertTrue(calls.contains("logout"))
    }
    func testQuitDefersReplyUntilCancelledAndSupersededChildrenFinish() async throws {
        let runner = ScriptedRunner(), login = TestGate(), enrollment = TestGate()
        let client = testClient(runner: runner)
        await runner.enqueue("login", .init(gate: login))
        await runner.enqueue("up", .init(gate: enrollment))
        let first = Task { try await client.signIn() }
        await runner.waitForCall("login")
        let restart = Task { try await client.signIn() }
        await login.waitForCancellation()
        let connect = Task { try await client.connect() }
        await runner.waitForCall("up")
        let delegate = AppDelegate(), replied = TestGate()
        delegate.model = AppModel(client: client, startPolling: false)
        var replyCount = 0
        delegate.terminationReply = { replyCount += 1; Task { await replied.open() } }
        XCTAssertEqual(delegate.applicationShouldTerminate(NSApplication.shared), .terminateLater)
        XCTAssertEqual(delegate.applicationShouldTerminate(NSApplication.shared), .terminateLater)
        await enrollment.waitForCancellation()
        XCTAssertEqual(replyCount, 0, "Cancellation alone cannot allow the app to exit")
        await enrollment.open(); try await connect.value
        XCTAssertEqual(replyCount, 0, "Superseded login is still owned during cleanup")
        await login.open()
        await replied.wait()
        try await first.value; try await restart.value
        XCTAssertEqual(replyCount, 1)
        try await client.signIn(); try await client.connect()
        let calls = await runner.calls.map(\.command)
        XCTAssertEqual(calls.filter { $0 == "login" }.count, 1)
        XCTAssertEqual(calls.filter { $0 == "up" }.count, 1)
        XCTAssertFalse(calls.contains("down"), "Quit only cleans up child processes")
    }
    func testQuitOwnsPendingTerminalAutomationAndPreventsAnotherLaunch() async throws {
        let runner = ScriptedRunner(), terminalRunner = ScriptedRunner(), terminal = TestGate()
        let client = NativeClient(executable: URL(fileURLWithPath: "/test/meshscale"), runner: runner, terminalRunner: terminalRunner)
        let inventory = try JSONEncoder().encode(ReviewFixture.status("connected").devices)
        await runner.enqueue("status", .init(data: inventory))
        await terminalRunner.enqueue("-e", .init(gate: terminal))
        let ssh = Task { try await client.openSSH(deviceID: "node-homelab") }
        await terminalRunner.waitForCall("-e")
        var finished = false
        let cleanup = Task { await client.prepareToTerminate(); finished = true }
        await terminal.waitForCancellation()
        XCTAssertFalse(finished, "Quit waits for the automation child to exit")
        await terminal.open(); await cleanup.value
        do { try await ssh.value; XCTFail("Expected cancelled automation") }
        catch { XCTAssertTrue(error is CancellationError) }
        do { try await client.openSSH(deviceID: "node-homelab"); XCTFail("Expected termination to prevent SSH") }
        catch { XCTAssertTrue(error is CancellationError) }
        let calls = await terminalRunner.calls
        XCTAssertEqual(calls.count, 1)
    }
    func testSSHDoesNotLaunchAfterDisconnectSupersedesItsRefresh() async throws {
        let runner = ScriptedRunner(), terminalRunner = ScriptedRunner(), inventory = TestGate()
        let client = NativeClient(executable: URL(fileURLWithPath: "/test/meshscale"), runner: runner, terminalRunner: terminalRunner)
        let devices = try JSONEncoder().encode(ReviewFixture.status("connected").devices)
        await runner.enqueue("status", .init(data: devices, gate: inventory))
        let ssh = Task { try await client.openSSH(deviceID: "node-homelab") }
        await runner.waitForCall("status")
        try await client.disconnect()
        await inventory.open()
        do { try await ssh.value; XCTFail("Expected superseded SSH to be cancelled") }
        catch { XCTAssertTrue(error is CancellationError) }
        let calls = await terminalRunner.calls
        XCTAssertTrue(calls.isEmpty)
    }
    func testSSHRequiresSuccessfulFreshInventory() async throws {
        let runner = ScriptedRunner(), terminalRunner = ScriptedRunner()
        let client = NativeClient(executable: URL(fileURLWithPath: "/test/meshscale"), runner: runner, terminalRunner: terminalRunner)
        let devices = try JSONEncoder().encode(ReviewFixture.status("connected").devices)
        await runner.enqueue("status", .init(data: devices))
        _ = try await client.getStatus()
        await runner.enqueue("status", .init(error: .timedOut))
        do { try await client.openSSH(deviceID: "node-homelab"); XCTFail("Expected stale inventory to block SSH") }
        catch { XCTAssertEqual(error as? ClientError, .sshUnavailable) }
        let calls = await terminalRunner.calls
        XCTAssertTrue(calls.isEmpty)
    }
    func testSSHDoesNotLaunchWhileDisconnectIsPending() async throws {
        let runner = ScriptedRunner(), terminalRunner = ScriptedRunner(), down = TestGate()
        let client = NativeClient(executable: URL(fileURLWithPath: "/test/meshscale"), runner: runner, terminalRunner: terminalRunner)
        let devices = try JSONEncoder().encode(ReviewFixture.status("connected").devices)
        await runner.enqueue("status", .init(data: devices))
        _ = try await client.getStatus()
        await runner.enqueue("down", .init(gate: down))
        let disconnect = Task { try await client.disconnect() }
        await runner.waitForCall("down")
        do { try await client.openSSH(deviceID: "node-homelab"); XCTFail("Expected active disconnect to block SSH") }
        catch { XCTAssertTrue(error is CancellationError) }
        let calls = await terminalRunner.calls
        XCTAssertTrue(calls.isEmpty)
        await down.open(); try await disconnect.value
    }
    func testDisconnectSuppressesPollsAndRejectsPreActionObservation() async throws {
        let runner = ScriptedRunner(), local = TestGate(), down = TestGate()
        let client = testClient(runner: runner)
        _ = try await client.getStatus()
        await runner.enqueue("local-status", .init(data: Data(#"{"installed":true,"state":"connected","connected":true,"safe":true,"enrollment":"connected"}"#.utf8), gate: local))
        let oldPoll = Task { try await client.getStatus() }
        await runner.waitForCall("local-status", count: 2)
        await runner.enqueue("down", .init(gate: down))
        let disconnect = Task { try await client.disconnect() }
        await runner.waitForCall("down")
        _ = try await client.getStatus()
        let during = await runner.calls.map(\.command)
        XCTAssertEqual(during.filter { $0 == "local-status" }.count, 2)
        await runner.enqueue("local-status", .init(data: Data(#"{"installed":true,"state":"disconnected","connected":false,"safe":true,"enrollment":"registered"}"#.utf8)))
        await down.open(); try await disconnect.value
        var emitted: [AppStatus] = []
        let subscription = client.onChange { emitted.append($0) }
        await local.open()
        let stale = try await oldPoll.value
        XCTAssertEqual(stale.connection, .disconnected)
        XCTAssertTrue(emitted.isEmpty, "A pre-disconnect fetch cannot publish after completion")
        client.unsubscribe(subscription)
    }
    func testLogoutSuppressesPollsAndRejectsDelayedIdentity() async throws {
        let runner = ScriptedRunner(), identity = TestGate(), logout = TestGate()
        let client = testClient(runner: runner)
        await runner.enqueue("whoami", .init(data: Data(#"{"id":"old-account","name":"Old account"}"#.utf8), gate: identity))
        let oldPoll = Task { try await client.getStatus() }
        await runner.waitForCall("whoami")
        await runner.enqueue("logout", .init(gate: logout))
        let signOut = Task { try await client.signOut() }
        await runner.waitForCall("logout")
        _ = try await client.getStatus()
        let during = await runner.calls.map(\.command)
        XCTAssertEqual(during.filter { $0 == "whoami" }.count, 1)
        await logout.open(); try await signOut.value
        await identity.open()
        let stale = try await oldPoll.value
        XCTAssertEqual(stale.auth, .signedOut)
        XCTAssertNil(stale.account)
    }
    func testNewerCompletedFetchWinsOverDelayedLocalObservation() async throws {
        let runner = ScriptedRunner(), local = TestGate()
        let client = testClient(runner: runner)
        _ = try await client.getStatus()
        await runner.enqueue("local-status", .init(data: Data(#"{"installed":true,"state":"connected","connected":true,"safe":true,"enrollment":"connected"}"#.utf8), gate: local))
        let oldPoll = Task { try await client.getStatus() }
        await runner.waitForCall("local-status", count: 2)
        await runner.enqueue("local-status", .init(data: Data(#"{"installed":true,"state":"disconnected","connected":false,"safe":true,"enrollment":"registered"}"#.utf8)))
        let latest = try await client.getStatus()
        XCTAssertEqual(latest.connection, .disconnected)
        await local.open()
        let stale = try await oldPoll.value
        XCTAssertEqual(stale, latest)
    }
    func testCancelInvalidatesRestartWhilePreviousLoginCleansUp() async throws {
        let runner = ScriptedRunner(), login = TestGate()
        let client = testClient(runner: runner)
        await runner.enqueue("login", .init(gate: login))
        let first = Task { try await client.signIn() }
        await runner.waitForCall("login")
        let restart = Task { try await client.signIn() }
        await login.waitForCancellation()
        await client.cancelSignIn()
        await login.open()
        try await first.value; try await restart.value
        let calls = await runner.calls.map(\.command)
        XCTAssertEqual(calls.filter { $0 == "login" }.count, 1, "Cancel must prevent a second login/browser flow")
    }
    func testConnectFailurePersistsAcrossPollsUntilDismissedOrNextAction() async throws {
        let runner = ScriptedRunner(), failure = ProcessError.commandFailed(exitCode: 2, stderr: .other)
        let client = testClient(runner: runner)
        _ = try await client.getStatus()
        await runner.enqueue("up", .init(error: failure))
        try await client.connect()
        let first = try await client.getStatus()
        XCTAssertEqual(first.actionIssue?.code, "connection_failed")
        let second = try await client.getStatus()
        XCTAssertEqual(second.actionIssue, first.actionIssue)
        XCTAssertEqual(second.connection, .connected, "The last action error is separate from current local state")
        client.dismissActionIssue()
        let dismissed = try await client.getStatus()
        XCTAssertNil(dismissed.actionIssue)
        await runner.enqueue("up", .init(error: failure))
        try await client.connect()
        try await client.disconnect()
        let afterAction = try await client.getStatus()
        XCTAssertNil(afterAction.actionIssue)
    }
    func testDisconnectChecksGenerationAfterWaitingForEnrollment() async throws {
        let runner = ScriptedRunner(), oldUp = TestGate(), newUp = TestGate()
        let client = testClient(runner: runner)
        await runner.enqueue("up", .init(gate: oldUp))
        await runner.enqueue("up", .init(gate: newUp))
        let first = Task { try await client.connect() }
        await runner.waitForCall("up")
        let disconnect = Task { try await client.disconnect() }
        await oldUp.waitForCancellation()
        let second = Task { try await client.connect() }
        await runner.waitForCall("up", count: 2)
        await oldUp.open()
        try await first.value; try await disconnect.value
        let calls = await runner.calls.map(\.command)
        XCTAssertFalse(calls.contains("down"), "A superseded disconnect must not turn off the newer action")
        let status = try await client.getStatus()
        XCTAssertEqual(status.connection, .connecting)
        await newUp.open(); try await second.value
    }
    func testDisconnectBoundsWaitForUnresponsiveEnrollment() async throws {
        let runner = ScriptedRunner(), up = TestGate()
        let client = testClient(runner: runner, cleanupTimeout: 0.05)
        await runner.enqueue("up", .init(gate: up))
        let connect = Task { try await client.connect() }
        await runner.waitForCall("up")
        let start = Date()
        try await client.disconnect()
        XCTAssertLessThan(Date().timeIntervalSince(start), 1)
        let calls = await runner.calls.map(\.command)
        XCTAssertTrue(calls.contains("down"))
        await up.open(); try await connect.value
    }
    func testDisconnectChecksGenerationAfterDown() async throws {
        let runner = ScriptedRunner(), down = TestGate(), up = TestGate()
        let client = testClient(runner: runner)
        _ = try await client.getStatus()
        await runner.enqueue("down", .init(gate: down))
        await runner.enqueue("up", .init(gate: up))
        let disconnect = Task { try await client.disconnect() }
        await runner.waitForCall("down")
        let connect = Task { try await client.connect() }
        await runner.waitForCall("up")
        await down.open(); try await disconnect.value
        let status = try await client.getStatus()
        XCTAssertEqual(status.connection, .connecting)
        let calls = await runner.calls.map(\.command)
        XCTAssertEqual(calls.filter { $0 == "local-status" }.count, 1, "Stale completion must not refresh or emit disconnected")
        await up.open(); try await connect.value
    }
    func testUnchangedStatusDoesNotEmitAgain() {
        let client = testClient(runner: ScriptedRunner())
        var emissions = 0
        let token = client.onChange { _ in emissions += 1 }
        client.dismissActionIssue(); client.dismissActionIssue()
        XCTAssertEqual(emissions, 1)
        client.unsubscribe(token)
    }
    func testEnrollmentGracePeriodIsChosenByDataAdapter() async throws {
        let runner = ScriptedRunner()
        let subject = CLIDataClient(runner: runner)
        try await subject.connect { _ in }
        try await subject.disconnect()
        let calls = await runner.calls
        XCTAssertEqual(calls.map(\.gracePeriod), [12, 1])
    }
}
