import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

public enum StderrCategory: Equatable, Sendable {
    case signedOut, accountSelectionRequired, other
    static func classify(_ data: Data) -> Self {
        let diagnostic = String(decoding: data, as: UTF8.self)
        if diagnostic.contains("not logged in:") { return .signedOut }
        if diagnostic.contains("choose an account number") { return .accountSelectionRequired }
        return .other
    }
}

public enum ProcessError: Error, LocalizedError, Equatable, Sendable {
    case launchFailed
    case commandFailed(exitCode: Int32, stderr: StderrCategory)
    case timedOut
    case outputTooLarge
    public var errorDescription: String? {
        switch self {
        case .launchFailed: "Cannot launch the bundled meshscale CLI. Reinstall meshscale, then choose Refresh."
        case .commandFailed(_, .signedOut): ClientError.signedOut.errorDescription
        case .commandFailed(_, .accountSelectionRequired): ClientError.accountSelectionRequired.errorDescription
        case .commandFailed: "The meshscale command failed. Choose Refresh to try again."
        case .timedOut: "The meshscale command timed out. Choose Refresh to try again."
        case .outputTooLarge: "The meshscale command returned too much output. Update meshscale, then choose Refresh."
        }
    }
}

public protocol CommandRunning: Sendable {
    func run(_ arguments: [String], timeout: TimeInterval, gracePeriod: TimeInterval) async throws -> Data
    func run(_ arguments: [String], timeout: TimeInterval, gracePeriod: TimeInterval, onLine: @escaping @Sendable (Data) -> Void) async throws -> Data
}
public extension CommandRunning {
    func run(_ arguments: [String], timeout: TimeInterval, gracePeriod: TimeInterval, onLine: @escaping @Sendable (Data) -> Void) async throws -> Data {
        let data = try await run(arguments, timeout: timeout, gracePeriod: gracePeriod)
        for line in data.split(separator: 10) { onLine(Data(line)) }
        return data
    }
}

public struct CLIProcessRunner: CommandRunning {
    public let executable: URL
    public let environment: [String: String]?
    public init(executable: URL, environment: [String: String]? = nil) { self.executable = executable; self.environment = environment }
    public func run(_ arguments: [String], timeout: TimeInterval = 30, gracePeriod: TimeInterval = 1) async throws -> Data {
        try await execute(arguments, timeout: timeout, gracePeriod: gracePeriod, onLine: nil)
    }
    public func run(_ arguments: [String], timeout: TimeInterval, gracePeriod: TimeInterval = 1, onLine: @escaping @Sendable (Data) -> Void) async throws -> Data {
        try await execute(arguments, timeout: timeout, gracePeriod: gracePeriod, onLine: onLine)
    }
    private func execute(_ arguments: [String], timeout: TimeInterval, gracePeriod: TimeInterval, onLine: (@Sendable (Data) -> Void)?) async throws -> Data {
        let job = ProcessJob(executable: executable, arguments: arguments, environment: environment, gracePeriod: gracePeriod, onLine: onLine)
        return try await withTaskCancellationHandler {
            let data = try await withCheckedThrowingContinuation { job.start(timeout: timeout, continuation: $0) }
            try Task.checkCancellation()
            return data
        } onCancel: { job.cancel() }
    }
}

// All mutable state and process lifetime operations are confined to this queue.
// Pipe callbacks drain concurrently, without occupying Swift's cooperative pool.
private final class ProcessJob: @unchecked Sendable {
    private let queue = DispatchQueue(label: "meshscale.cli-process")
    private let process = Process()
    private let output = Pipe(), diagnostic = Pipe()
    private let gracePeriod: TimeInterval
    private let onLine: (@Sendable (Data) -> Void)?
    private var continuation: CheckedContinuation<Data, any Error>?
    private var cancellation: (any Error)?
    private var finished = false
    private var exitCode: Int32?
    private var outputEnded = false, diagnosticEnded = false
    private var data = Data(), stderr = Data(), pending = Data()
    // Inventory is bounded independently of diagnostics. Neither a broken CLI
    // nor a large remote response should consume memory until the login timeout.
    private let outputLimit = 8 * 1024 * 1024
    private let diagnosticLimit = 256 * 1024
    private var deadline: DispatchSourceTimer?
    private var escalation: DispatchSourceTimer?

    init(executable: URL, arguments: [String], environment: [String: String]?, gracePeriod: TimeInterval, onLine: (@Sendable (Data) -> Void)?) {
        self.gracePeriod = gracePeriod; self.onLine = onLine
        var environment = environment ?? ProcessInfo.processInfo.environment
        environment["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"
        process.environment = environment
        process.executableURL = executable; process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output; process.standardError = diagnostic
    }
    func start(timeout: TimeInterval, continuation: CheckedContinuation<Data, any Error>) {
        queue.async { [self] in
            self.continuation = continuation
            if let cancellation { finish(.failure(cancellation)); return }
            output.fileHandleForReading.readabilityHandler = { [weak self] handle in
                let chunk = handle.availableData
                if chunk.isEmpty { handle.readabilityHandler = nil }
                self?.receive(chunk, isOutput: true)
            }
            diagnostic.fileHandleForReading.readabilityHandler = { [weak self] handle in
                let chunk = handle.availableData
                if chunk.isEmpty { handle.readabilityHandler = nil }
                self?.receive(chunk, isOutput: false)
            }
            process.terminationHandler = { [weak self] process in
                let code = process.terminationStatus
                self?.didExit(code)
            }
            do { try process.run() }
            catch { finish(.failure(ProcessError.launchFailed)); return }
            // The child owns the write ends now; EOF must not depend on our copies.
            try? output.fileHandleForWriting.close(); try? diagnostic.fileHandleForWriting.close()
            deadline = timer(after: timeout) { [weak self] in self?.stop(error: ProcessError.timedOut) }
        }
    }
    func cancel() { queue.async { [self] in stop(error: CancellationError()) } }
    private func timer(after seconds: TimeInterval, action: @escaping @Sendable () -> Void) -> DispatchSourceTimer {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + max(0, seconds))
        timer.setEventHandler(handler: action); timer.resume(); return timer
    }
    private func stop(error: any Error) {
        guard !finished, cancellation == nil else { return }
        cancellation = error
        guard process.isRunning else { completeIfReady(); return }
        process.terminate()
        escalation = timer(after: gracePeriod) { [weak self] in
            guard let self, !self.finished else { return }
            if self.process.isRunning { kill(self.process.processIdentifier, SIGKILL) }
        }
    }
    private func receive(_ chunk: Data, isOutput: Bool) {
        queue.async { [self] in
            guard !finished else { return }
            guard cancellation == nil else { completeIfReady(); return }
            let retained = isOutput ? data.count : stderr.count
            let limit = isOutput ? outputLimit : diagnosticLimit
            guard chunk.count <= limit - retained else {
                stop(error: ProcessError.outputTooLarge)
                return
            }
            if isOutput {
                if chunk.isEmpty { outputEnded = true }
                data.append(chunk)
                if let onLine {
                    pending.append(chunk)
                    while let newline = pending.firstIndex(of: 10) {
                        onLine(Data(pending[..<newline])); pending.removeSubrange(...newline)
                    }
                    if outputEnded && !pending.isEmpty { onLine(pending); pending.removeAll() }
                }
            } else {
                if chunk.isEmpty { diagnosticEnded = true }
                stderr.append(chunk)
            }
            completeIfReady()
        }
    }
    private func didExit(_ code: Int32) {
        queue.async { [self] in exitCode = code; completeIfReady() }
    }
    private func completeIfReady() {
        guard let exitCode else { return }
        // Cancellation does not need output. An orphaned descendant may still own
        // a pipe, so waiting for EOF here could defeat the timeout after SIGKILL.
        if let cancellation { finish(.failure(cancellation)); return }
        guard outputEnded, diagnosticEnded else { return }
        if exitCode != 0 { finish(.failure(ProcessError.commandFailed(exitCode: exitCode, stderr: .classify(stderr)))) }
        else { finish(.success(data)) }
    }
    private func finish(_ result: Result<Data, any Error>) {
        guard !finished else { return }
        finished = true
        deadline?.cancel(); escalation?.cancel()
        output.fileHandleForReading.readabilityHandler = nil; diagnostic.fileHandleForReading.readabilityHandler = nil
        // Let the read handles close on deallocation, after any callback already
        // draining a chunk has released its reference to the handle.
        try? output.fileHandleForWriting.close(); try? diagnostic.fileHandleForWriting.close()
        process.terminationHandler = nil
        continuation?.resume(with: result); continuation = nil
    }
}
