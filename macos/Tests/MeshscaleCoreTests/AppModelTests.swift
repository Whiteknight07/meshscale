import Foundation
import XCTest
@testable import MeshscaleApp
@testable import MeshscaleCore

@MainActor private final class ModelClient: MeshscaleClient {
    var status = AppStatus()
    var refreshes = 0
    var connectionCalls: [String] = []
    let connectionCalled = TestGate()
    var statusOnDismiss: AppStatus?
    var copies: [String] = []
    var cancelledRefresh = false
    var refreshGate: TestGate?
    let refreshStarted = TestGate()
    var callback: (@MainActor (AppStatus) -> Void)?
    func getStatus() async throws -> AppStatus {
        refreshes += 1
        await refreshStarted.open()
        if refreshes == 1, let refreshGate { await refreshGate.wait() }
        cancelledRefresh = cancelledRefresh || Task.isCancelled
        return status
    }
    func dismissActionIssue() {
        status.actionIssue = nil
        if let statusOnDismiss { status = statusOnDismiss; callback?(status) }
    }
    func connect() async throws { connectionCalls.append("connect"); await connectionCalled.open() }
    func clearPersonalRegistrationAndConnect() async throws {}
    func disconnect() async throws { connectionCalls.append("disconnect"); await connectionCalled.open() }
    func signIn() async throws {}
    func cancelSignIn() async {}
    func signOut() async throws {}
    func copy(text: String) throws { copies.append(text) }
    func openSSH(deviceID: String) async throws {}
    func quit() {}
    func setLaunchAtLogin(enabled: Bool) async throws {}
    func onChange(_ callback: @escaping @MainActor (AppStatus) -> Void) -> UUID { self.callback = callback; return UUID() }
    func unsubscribe(_ token: UUID) { callback = nil }
}

@MainActor final class AppModelTests: XCTestCase {
    func testConnectionButtonKeepsClickIntentWhenDismissPublishesNewState() async {
        for state in [ConnectionState.connected, .connecting, .disconnected] {
            let client = ModelClient()
            let model = AppModel(client: client, startPolling: false)
            model.status = ReviewFixture.status("connected")
            model.status.connection = state
            var changed = model.status
            changed.connection = state == .disconnected ? .connected : .disconnected
            client.statusOnDismiss = changed
            model.performConnectionAction()
            XCTAssertEqual(model.status.connection, changed.connection)
            await client.connectionCalled.wait()
            XCTAssertEqual(client.connectionCalls, [state == .disconnected ? "connect" : "disconnect"])
            while !model.actions.isEmpty { await Task.yield() }
            model.shutdown()
        }
    }
    func testVisibilityChangeQueuesRefreshWithoutCancellingInFlightFetch() async {
        let client = ModelClient(), gate = TestGate()
        client.refreshGate = gate
        client.status.auth = .signedIn
        let model = AppModel(client: client, startPolling: false)
        let refresh = Task { await model.refresh() }
        await client.refreshStarted.wait()
        model.setVisible(true); model.setVisible(false); model.setVisible(true)
        await gate.open(); await refresh.value
        XCTAssertEqual(client.refreshes, 2, "Visibility changes should coalesce into one immediate follow-up")
        XCTAssertFalse(client.cancelledRefresh)
        XCTAssertEqual(model.status.auth, .signedIn)
        model.shutdown()
    }
    func testCopyIsSynchronousAndIndependentOfInFlightActions() async {
        let client = ModelClient(), gate = TestGate()
        let model = AppModel(client: client, startPolling: false)
        model.perform(.connect) { _ in await gate.wait() }
        model.copy("100.96.0.12")
        XCTAssertEqual(client.copies, ["100.96.0.12"])
        XCTAssertEqual(model.notice, "Copied 100.96.0.12")
        XCTAssertTrue(model.actions.contains(.connect))
        await gate.open()
        model.shutdown()
    }
    func testActionsRemainTrackedWhenInterruptingActionFinishesFirst() async {
        let client = ModelClient(), connect = TestGate(), disconnect = TestGate()
        let model = AppModel(client: client, startPolling: false)
        model.perform(.connect) { _ in await connect.wait() }
        XCTAssertFalse(model.canPerform(.connect))
        XCTAssertTrue(model.canPerform(.disconnect))
        XCTAssertFalse(model.canPerform(.ssh))
        model.perform(.disconnect) { _ in await disconnect.wait() }
        await disconnect.open()
        // Await task completion on the main actor without relying on wall-clock delays.
        while model.actions.contains(.disconnect) { await Task.yield() }
        XCTAssertTrue(model.actions.contains(.connect))
        XCTAssertFalse(model.canPerform(.connect), "A finishing interrupt cannot clear another action's in-flight state")
        XCTAssertTrue(model.canPerform(.launchAtLogin), "Independent settings actions remain available")
        await connect.open()
        while !model.actions.isEmpty { await Task.yield() }
        XCTAssertTrue(model.canPerform(.connect))
        model.shutdown()
    }
    func testBlockedDuplicateDoesNotRunAndErrorNoticeSurvivesNavigation() async {
        let client = ModelClient(), gate = TestGate()
        let model = AppModel(client: client, startPolling: false)
        var invocations = 0
        model.perform(.connect) { _ in invocations += 1; await gate.wait() }
        model.perform(.connect) { _ in invocations += 1 }
        model.navigate(.settings)
        XCTAssertFalse(model.notice.isEmpty)
        XCTAssertTrue(model.noticeIsError)
        await gate.open()
        while !model.actions.isEmpty { await Task.yield() }
        XCTAssertEqual(invocations, 1)
        model.dismissNotice()
        XCTAssertTrue(model.notice.isEmpty)
        model.shutdown()
    }
    func testArtworkReusesCachedTemplateImages() {
        let first = Artwork.image("menu-connected")
        XCTAssertTrue(first === Artwork.image("menu-connected"))
        XCTAssertTrue(first.isTemplate)
        XCTAssertEqual(first.size.width, 18)
    }
    func testProductionDefaultsContainNoFixtureSelection() {
        let model = AppModel()
        XCTAssertNil(model.selectedID)
        XCTAssertTrue(model.status.devices.isEmpty)
        XCTAssertEqual(model.screen, .devices)
    }
}
