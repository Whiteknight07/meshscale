import Foundation
import XCTest
@testable import MeshscaleCore

private actor RecordingRunner: CommandRunning {
    var calls: [[String]] = []
    let status: Data
    let identity: Data
    let failure: ClientError?
    init(status: Data = Data("[]".utf8), identity: Data = Data(#"{"id":"account","name":"Personal account"}"#.utf8), failure: ClientError? = nil) {
        self.status = status; self.identity = identity; self.failure = failure
    }
    func run(_ arguments: [String], timeout: TimeInterval, gracePeriod: TimeInterval) async throws -> Data {
        calls.append(arguments)
        if let failure { throw failure }
        return arguments.first == "status" ? status : identity
    }
}

final class ClientTests: XCTestCase {
    func testExampleStatusDecodesAndRoundTripsEveryOptionalField() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "status-example", withExtension: "json", subdirectory: "Fixtures"))
        let source = try Data(contentsOf: url)
        let devices = try JSONDecoder().decode([MeshDevice].self, from: source)
        XCTAssertFalse(devices.isEmpty, "Example inventory must exercise all device fields")
        let roundTrip = try JSONDecoder().decode([MeshDevice].self, from: JSONEncoder().encode(devices))
        XCTAssertEqual(devices, roundTrip)
        let raw = try XCTUnwrap(JSONSerialization.jsonObject(with: source) as? [[String: Any]])
        XCTAssertEqual(devices.count, raw.count)
        for (device, record) in zip(devices, raw) {
            XCTAssertEqual(device.id, record["id"] as? String)
            XCTAssertEqual(device.thisMachine, record["this_machine"] as? Bool)
            XCTAssertEqual(device.connectionState, record["connection_state"] as? String)
            XCTAssertEqual(device.dnsName, record["dns_name"] as? String)
            XCTAssertEqual(device.registrationID, record["registration_id"] as? String)
        }
    }
    func testBareArrayAbsentOptionalFieldsAndIPv6() throws {
        let json = #"[{"id":"device","kind":"device","name":"phone","online":false,"this_machine":false,"ipv6":"fd00::1"}]"#
        let device = try XCTUnwrap(JSONDecoder().decode([MeshDevice].self, from: Data(json.utf8)).first)
        XCTAssertEqual(device.address, "fd00::1")
        XCTAssertNil(device.dnsName)
        XCTAssertNil(device.lastSeenAt)
        XCTAssertNil(device.secure)
        XCTAssertNil(device.offersExitNode)
        XCTAssertNil(device.exitNode)
        XCTAssertNil(device.exitState)
        XCTAssertNil(device.exitNodeAllowLANAccess)
        XCTAssertTrue(device.peerStatusNotes.isEmpty)
        XCTAssertEqual(device.lastSeen(), "Last seen unknown")
        XCTAssertEqual(try JSONDecoder().decode([MeshDevice].self, from: Data("[]".utf8)), [])
        XCTAssertThrowsError(try JSONDecoder().decode([MeshDevice].self, from: Data(#"{"devices":[]}"#.utf8)))
    }
    func testOnlineSourceDecodesWithOlderAndFutureBinaries() throws {
        for source in ["cloudflare", "probe", "future-source"] {
            let json = "[{\"id\":\"phone\",\"kind\":\"device\",\"name\":\"phone\",\"online\":true,\"this_machine\":false,\"online_source\":\"\(source)\"}]"
            let device = try XCTUnwrap(JSONDecoder().decode([MeshDevice].self, from: Data(json.utf8)).first)
            XCTAssertEqual(device.onlineSource, source)
        }
        let oldJSON = #"[{"id":"phone","kind":"device","name":"phone","online":true,"this_machine":false}]"#
        let oldDevice = try XCTUnwrap(JSONDecoder().decode([MeshDevice].self, from: Data(oldJSON.utf8)).first)
        XCTAssertNil(oldDevice.onlineSource)
    }
    func testSecureAndExitStatusMatchesCLIJSONWithoutEnablingMacCapabilities() throws {
        let json = #"[{"id":"node","kind":"node","name":"server","online":true,"online_source":"probe","this_machine":false,"offers_exit_node":true,"exit_node":"gateway","exit_state":"ready (egress not probed)","exit_node_allow_lan_access":false,"secure":{"enabled":true,"ip":"fd6d:6573:6873::10","dns_name":"server.secure","public_key":"public-key","last_handshake":"2026-10-26T12:00:00Z","handshake_age_seconds":12,"future_field":true}}]"#
        let devices = try JSONDecoder().decode([MeshDevice].self, from: Data(json.utf8))
        let device = try XCTUnwrap(devices.first)
        let peer = try XCTUnwrap(device.secure)
        XCTAssertEqual(peer.ip, "fd6d:6573:6873::10")
        XCTAssertEqual(peer.dnsName, "server.secure")
        XCTAssertEqual(peer.publicKey, "public-key")
        XCTAssertEqual(peer.lastHandshake, "2026-10-26T12:00:00Z")
        XCTAssertEqual(peer.handshakeAgeSeconds, 12)
        XCTAssertEqual(device.offersExitNode, true)
        XCTAssertEqual(device.exitNodeAllowLANAccess, false)
        XCTAssertEqual(device.peerStatusNotes, ["Online via probe", "Secure peer · handshake 12s ago", "Exit node: gateway", "ready (egress not probed)"])
        XCTAssertEqual(try JSONDecoder().decode([MeshDevice].self, from: JSONEncoder().encode(devices)), devices)
        var status = AppStatus()
        status.devices = devices
        XCTAssertEqual(status.connection, .disconnected)
        XCTAssertFalse(status.canSSH(device))
    }
    func testPeerNotesDistinguishCapabilityFromHandshakeAndEgress() throws {
        let pending = try XCTUnwrap(ReviewFixture.status("secure-pending-detail").devices.first { $0.id == "node-homelab" })
        XCTAssertEqual(pending.peerStatusNotes, ["Online via probe", "Secure peer · no handshake observed", "Offers an exit node"])
        var device = pending
        device.online = false
        device.secure?.handshakeAgeSeconds = -1
        XCTAssertEqual(device.peerStatusNotes, ["Secure peer · handshake 0s ago", "Offers an exit node"])
        device.secure?.enabled = false
        XCTAssertEqual(device.peerStatusNotes, ["Offers an exit node"])
    }
    func testDataClientUsesJSONContract() async throws {
        let runner = RecordingRunner()
        let client = CLIDataClient(runner: runner)
        let devices = try await client.devices()
        let account = try await client.account()
        XCTAssertTrue(devices.isEmpty)
        XCTAssertEqual(account.name, "Personal account")
        XCTAssertNil(account.email)
        let calls = await runner.calls
        XCTAssertEqual(calls, [["status", "--json"], ["whoami", "--json"]])
    }
    func testDataClientPropagatesMissingLoginAndMalformedJSON() async throws {
        let missing = CLIDataClient(runner: RecordingRunner(failure: .signedOut))
        do { _ = try await missing.devices(); XCTFail("Expected missing login") }
        catch { XCTAssertEqual(error as? ClientError, .signedOut) }
        let malformed = CLIDataClient(runner: RecordingRunner(status: Data("not JSON".utf8)))
        do { _ = try await malformed.devices(); XCTFail("Expected decoding error") }
        catch { XCTAssertTrue(error is DecodingError) }
    }
    func testDeviceInventoryRejectsAmbiguousIdentifiers() async throws {
        for identifiers in [["same", "same"], [""], ["   "]] {
            let records = identifiers.map { id in
                ["id": id, "kind": "node", "name": "server", "online": true, "this_machine": false] as [String: Any]
            }
            let data = try JSONSerialization.data(withJSONObject: records)
            do {
                _ = try await CLIDataClient(runner: RecordingRunner(status: data)).devices()
                XCTFail("Expected ambiguous identifiers to be rejected")
            } catch { XCTAssertTrue(error is DecodingError) }
        }
    }
    func testAccountRequiresANonemptyIdentifier() async throws {
        for id in ["", "   "] {
            let data = try JSONEncoder().encode(Account(id: id, name: "Test account"))
            do {
                _ = try await CLIDataClient(runner: RecordingRunner(identity: data)).account()
                XCTFail("Expected an invalid account identifier to be rejected")
            } catch { XCTAssertTrue(error is DecodingError) }
        }
    }
    func testDeviceInventoryRejectsMultipleLocalDevices() async throws {
        var devices = ReviewFixture.status("connected").devices
        devices[0].thisMachine = true; devices[1].thisMachine = true
        let data = try JSONEncoder().encode(devices)
        do {
            _ = try await CLIDataClient(runner: RecordingRunner(status: data)).devices()
            XCTFail("Expected ambiguous local-device identity to be rejected")
        } catch { XCTAssertTrue(error is DecodingError) }
    }
    func testRemoteOnlineNeverEnablesLocalConnectionOrSSH() {
        var status = ReviewFixture.status("mac-unavailable")
        XCTAssertEqual(status.connection, .disconnected)
        XCTAssertTrue(status.devices.contains(where: \.online))
        XCTAssertTrue(status.devices.allSatisfy { !status.canSSH($0) })
        status.connection = .connected
        XCTAssertTrue(status.devices.contains { status.canSSH($0) }, "Desktop eligibility needs no fabricated CLI capability signal")
    }
    func testSSHRequiresAllCapabilitiesAndQuotesArguments() throws {
        var status = ReviewFixture.status("connected")
        var device = try XCTUnwrap(status.devices.first { $0.id == "node-homelab" })
        let command = try TerminalCommand.ssh(executable: "/path with space/meshscale", username: "alex", device: device, status: status)
        XCTAssertEqual(command, "'/path with space/meshscale' ssh 'alex@100.96.0.10'")
        XCTAssertEqual(TerminalCommand.shellQuote("a'b$(touch /tmp/x)"), "'a'\\''b$(touch /tmp/x)'")
        XCTAssertTrue(TerminalCommand.appleScript(command: "echo \"test\" \\" ).contains("\\\"test\\\""))
        for state: ConnectionState in [.disconnected, .connecting, .error] {
            status.connection = state
            XCTAssertThrowsError(try TerminalCommand.ssh(executable: "/cli", username: "alex", device: device, status: status))
        }
        status.connection = .connected
        XCTAssertThrowsError(try TerminalCommand.ssh(executable: "/cli", username: "-bad", device: device, status: status))
        device.online = false
        XCTAssertThrowsError(try TerminalCommand.ssh(executable: "/cli", username: "alex", device: device, status: status))
        let phone = try XCTUnwrap(status.devices.first { $0.os == "android" })
        XCTAssertFalse(status.canSSH(phone))
        let local = try XCTUnwrap(status.devices.first { $0.thisMachine })
        XCTAssertFalse(status.canSSH(local))
    }
    func testLastSeenFractionalDateAndFutureDate() throws {
        var device = try XCTUnwrap(ReviewFixture.status("connected").devices.last)
        XCTAssertEqual(device.lastSeen(now: ReviewFixture.now), "Last seen 3 days ago")
        device.lastSeenAt = "2026-10-26T11:58:00.123456Z"
        XCTAssertEqual(device.lastSeen(now: ReviewFixture.now), "Last seen 1 minute ago")
        device.lastSeenAt = "2099-01-01T00:00:00Z"
        XCTAssertEqual(device.lastSeen(now: ReviewFixture.now), "Last seen just now")
    }
    func testAccountDisplayNameHidesCloudflareDefault() {
        XCTAssertEqual(Account(id: "a", name: "Operator@example.com's Account", email: "operator@example.com").displayName, "Cloudflare account")
        XCTAssertEqual(Account(id: "a", name: "Homelab", email: "operator@example.com").displayName, "Homelab")
        XCTAssertEqual(Account(id: "a", name: "Homelab").displayName, "Homelab")
    }
    func testProcessRunnerDrainsBothPipesAndSanitizesErrors() async throws {
        let runner = CLIProcessRunner(executable: URL(fileURLWithPath: "/bin/sh"))
        let data = try await runner.run(["-c", "i=0; while [ $i -lt 2000 ]; do echo diagnostic >&2; echo device; i=$((i + 1)); done"], timeout: 10)
        XCTAssertEqual(String(decoding: data, as: UTF8.self).split(separator: "\n").count, 2000)
        do {
            _ = try await runner.run(["-c", "echo 'secret=must-not-surface' >&2; exit 1"], timeout: 5)
            XCTFail("Expected failure")
        } catch { XCTAssertEqual(error as? ProcessError, .commandFailed(exitCode: 1, stderr: .other)); XCTAssertFalse(error.localizedDescription.contains("secret")) }
    }
    func testCancellationStopsCLI() async throws {
        let runner = CLIProcessRunner(executable: URL(fileURLWithPath: "/bin/sleep"))
        let start = Date()
        let task = Task { try await runner.run(["30"], timeout: 40) }
        try await Task.sleep(for: .milliseconds(100))
        task.cancel()
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertLessThan(Date().timeIntervalSince(start), 5)
    }
    func testTimeoutIsAnActionableFailure() async throws {
        let runner = CLIProcessRunner(executable: URL(fileURLWithPath: "/bin/sleep"))
        do { _ = try await runner.run(["30"], timeout: 0.1); XCTFail("Expected timeout") }
        catch { XCTAssertEqual(error as? ProcessError, .timedOut) }
    }

    func testVerificationRequestsNonpersistentStatus() async throws {
        let runner = RecordingRunner()
        let client = CLIDataClient(runner: runner, persistAssociationCache: false)
        _ = try await client.devices()
        let calls = await runner.calls
        XCTAssertEqual(calls, [["status", "--json", "--no-cache"]])
    }

}
