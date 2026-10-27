import Foundation
import XCTest
@testable import MeshscaleCore

final class ProcessRunnerTests: XCTestCase {
    func testOversizedOutputFailsWithoutReturningUntrustedBytes() async {
        let runner = CLIProcessRunner(executable: URL(fileURLWithPath: "/bin/sh"))
        for command in ["exec /bin/dd if=/dev/zero bs=1024 count=9216", "exec /bin/dd if=/dev/zero bs=1024 count=512 1>&2"] {
            do {
                _ = try await runner.run(["-c", command], timeout: 10, gracePeriod: 0.1)
                XCTFail("Expected an output limit failure")
            } catch {
                XCTAssertTrue(error.localizedDescription.contains("too much output"))
            }
        }
    }
    func testLaunchFailureIsDistinct() async {
        do {
            _ = try await CLIProcessRunner(executable: URL(fileURLWithPath: "/nonexistent/meshscale")).run([])
            XCTFail("Expected launch failure")
        } catch { XCTAssertEqual(error as? ProcessError, .launchFailed) }
    }
    func testCommandFailurePreservesExitCodeAndSanitizedCategory() async {
        let runner = CLIProcessRunner(executable: URL(fileURLWithPath: "/bin/sh"))
        for (diagnostic, category) in [("not logged in: secret", StderrCategory.signedOut), ("choose an account number secret", .accountSelectionRequired), ("token=secret", .other)] {
            do {
                _ = try await runner.run(["-c", "echo '\(diagnostic)' >&2; exit 7"])
                XCTFail("Expected command failure")
            } catch {
                XCTAssertEqual(error as? ProcessError, .commandFailed(exitCode: 7, stderr: category))
                XCTAssertFalse(error.localizedDescription.contains("secret"))
            }
        }
    }
    func testPATHIsPinnedEvenWhenCallerSuppliesAnotherPATH() async throws {
        let runner = CLIProcessRunner(executable: URL(fileURLWithPath: "/usr/bin/env"), environment: ["PATH": "/untrusted", "TEST_SENTINEL": "retained"])
        let data = try await runner.run([])
        let lines = String(decoding: data, as: UTF8.self).split(separator: "\n")
        XCTAssertTrue(lines.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"))
        XCTAssertTrue(lines.contains("TEST_SENTINEL=retained"))
    }
    func testPinnedPATHIncludesBothHomebrewPrefixesAfterSystemDirectories() async throws {
        for environment in [nil, ["PATH": "/untrusted"]] as [[String: String]?] {
            let runner = CLIProcessRunner(executable: URL(fileURLWithPath: "/usr/bin/env"), environment: environment)
            let output = String(decoding: try await runner.run([]), as: UTF8.self)
            let path = try XCTUnwrap(output.split(separator: "\n").first { $0.hasPrefix("PATH=") })
            XCTAssertEqual(String(path.dropFirst(5)).split(separator: ":"), ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/opt/homebrew/bin", "/usr/local/bin"])
        }
    }
    func testTimeoutKillsProcessThatIgnoresSIGTERM() async throws {
        let runner = CLIProcessRunner(executable: URL(fileURLWithPath: "/bin/sh"))
        let start = Date()
        do {
            _ = try await runner.run(["-c", "trap '' TERM INT; while :; do :; done"], timeout: 0.2, gracePeriod: 0.1)
            XCTFail("Expected timeout")
        } catch { XCTAssertEqual(error as? ProcessError, .timedOut) }
        XCTAssertLessThan(Date().timeIntervalSince(start), 3)
    }
    func testCancellationKillsProcessThatIgnoresSIGTERM() async throws {
        let runner = CLIProcessRunner(executable: URL(fileURLWithPath: "/bin/sh"))
        let start = Date()
        let task = Task { try await runner.run(["-c", "trap '' TERM INT; while :; do :; done"], timeout: 30, gracePeriod: 0.1) }
        try await Task.sleep(for: .milliseconds(200))
        task.cancel()
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertLessThan(Date().timeIntervalSince(start), 3)
    }
    func testTimeoutIsBoundedWhenDescendantKeepsPipesOpen() async {
        let runner = CLIProcessRunner(executable: URL(fileURLWithPath: "/bin/sh"))
        let start = Date()
        do {
            _ = try await runner.run(["-c", "trap '' TERM INT; sleep 2 & while :; do :; done"], timeout: 0.1, gracePeriod: 0.1)
            XCTFail("Expected timeout")
        } catch { XCTAssertEqual(error as? ProcessError, .timedOut) }
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.5)
    }
    func testTimeoutIsBoundedWhenExitedParentLeavesDescendantPipesOpen() async {
        let runner = CLIProcessRunner(executable: URL(fileURLWithPath: "/bin/sh"))
        let start = Date()
        do {
            _ = try await runner.run(["-c", "sleep 2 & exit 0"], timeout: 0.1, gracePeriod: 0.1)
            XCTFail("Expected timeout while awaiting pipe EOF")
        } catch { XCTAssertEqual(error as? ProcessError, .timedOut) }
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.5)
    }
    func testCancellationBeforeLaunchResumesExactlyOnce() async {
        let runner = CLIProcessRunner(executable: URL(fileURLWithPath: "/bin/sleep"))
        let task = Task { try await runner.run(["30"], timeout: 30, gracePeriod: 0.01) }
        task.cancel()
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch { XCTAssertTrue(error is CancellationError) }
    }
}
