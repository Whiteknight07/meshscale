import Foundation
import MeshscaleCore

// Keep cancelled and superseded commands owned until their process has exited.
// Closing the scope also prevents a suspended action from launching a late child.
actor ClientCommandRunner: CommandRunning {
    private let runner: any CommandRunning
    private var children: [UUID: Task<Data, Error>] = [:]
    private var closing = false
    init(runner: any CommandRunning) { self.runner = runner }
    func run(_ arguments: [String], timeout: TimeInterval, gracePeriod: TimeInterval) async throws -> Data {
        try await run(arguments, timeout: timeout, gracePeriod: gracePeriod, onLine: { _ in })
    }
    func run(_ arguments: [String], timeout: TimeInterval, gracePeriod: TimeInterval, onLine: @escaping @Sendable (Data) -> Void) async throws -> Data {
        guard !closing else { throw CancellationError() }
        try Task.checkCancellation()
        let id = UUID()
        let child = Task {
            try Task.checkCancellation()
            let result = try await runner.run(arguments, timeout: timeout, gracePeriod: gracePeriod, onLine: onLine)
            try Task.checkCancellation()
            return result
        }
        children[id] = child
        defer { children[id] = nil }
        return try await withTaskCancellationHandler {
            let result = try await child.value
            try Task.checkCancellation()
            return result
        } onCancel: { child.cancel() }
    }
    func cancelAndWait() async {
        closing = true
        let pending = Array(children.values)
        for child in pending { child.cancel() }
        for child in pending { _ = await child.result }
    }
}
