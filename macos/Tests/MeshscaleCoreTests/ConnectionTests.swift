import Foundation
import XCTest
@testable import MeshscaleCore

private actor ConnectionRunner: CommandRunning {
    var calls: [[String]] = []
    func run(_ arguments: [String], timeout: TimeInterval, gracePeriod: TimeInterval) async throws -> Data {
        calls.append(arguments)
        switch arguments.first {
        case "local-status": return Data(#"{"installed":true,"state":"connected","connected":true,"safe":true,"enrollment":"registered"}"#.utf8)
        case "up": return Data("{\"state\":\"registration_pending\",\"message\":\"secret must not display\"}\n{\"state\":\"checking_safety\"}\n{\"state\":\"connected\"}\n".utf8)
        default: return Data()
        }
    }
}

private final class ProgressLog: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [Data] = []
    func append(_ line: Data) { lock.lock(); lines.append(line); lock.unlock() }
    var values: [Data] { lock.lock(); defer { lock.unlock() }; return lines }
}

final class ConnectionTests: XCTestCase {
    func testConnectProgressIsTypedAndUsesExplicitConsumerConsent() async throws {
        let runner = ConnectionRunner(), log = ProgressLog()
        let client = CLIDataClient(runner: runner)
        let local = try await client.localConnection()
        XCTAssertTrue(local.connected && local.safe)
        try await client.connect(replaceConsumer: true) { log.append(Data($0.message.utf8)) }
        try await client.disconnect()
        let calls = await runner.calls
        XCTAssertEqual(calls, [["local-status", "--json"], ["up", "--json", "--replace-consumer"], ["down"]])
        XCTAssertEqual(log.values.map { String(decoding: $0, as: UTF8.self) }, ["Finish signing in in your browser", "Checking safety settings", "Connected"])
        XCTAssertFalse(log.values.contains { String(decoding: $0, as: UTF8.self).contains("secret") })
    }
    func testProgressStreamsBeforeProcessFinishesAndJoinsPartialLines() async throws {
        let log = ProgressLog()
        let runner = CLIProcessRunner(executable: URL(fileURLWithPath: "/bin/sh"))
        let task = Task { try await runner.run(["-c", "printf '{\"state\":'; printf '\"checking_safety\"}\\n'; sleep 1; printf '{\"state\":\"connected\"}\\n'"], timeout: 5) { log.append($0) } }
        try await Task.sleep(for: .milliseconds(300))
        XCTAssertEqual(log.values.count, 1, "The pending state must arrive while the CLI is running")
        _ = try await task.value
        XCTAssertEqual(log.values.count, 2)
        XCTAssertEqual(String(decoding: log.values[0], as: UTF8.self), #"{"state":"checking_safety"}"#)
    }
    func testPhoneSSHStaysDisabled() throws {
        var status = ReviewFixture.status("connected-mac")
        let phone = try XCTUnwrap(status.devices.first { $0.os == "android" })
        XCTAssertFalse(status.canSSH(phone))
        let server = try XCTUnwrap(status.devices.first { $0.id == "node-homelab" })
        XCTAssertTrue(status.canSSH(server))
        status.connection = .disconnected
        XCTAssertFalse(status.canSSH(server))
    }
}
