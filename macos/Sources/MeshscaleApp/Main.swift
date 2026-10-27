import AppKit
import MeshscaleCore
import SwiftUI

@MainActor enum Runtime {
    static var executable: URL {
        Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/meshscale")
    }
    static var cliEnvironment: [String: String] {
        var env = ProcessInfo.processInfo.environment
        if let home = env["MESHSCALE_RUNTIME_HOME"] { env["HOME"] = home }
        return env
    }
}

@main struct Main {
    @MainActor static func main() async {
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments.first == "--client-check" {
            let data = CLIDataClient(runner: CLIProcessRunner(executable: Runtime.executable, environment: Runtime.cliEnvironment), persistAssociationCache: false)
            do {
                let devices = try await data.devices()
                let account = try await data.account()
                let local = try await data.localConnection()
                guard !account.id.isEmpty else { fail("Client check failed: missing account identity") }
                if local.connected && !devices.contains(where: \.thisMachine) { fail("Client check failed: connected Mac not identified in inventory") }
                print("Client check passed: \(devices.count) devices decoded; account identity decoded; local connected=\(local.connected), safe=\(local.safe); this Mac entries=\(devices.filter(\.thisMachine).count).")
            } catch { fail("Client check failed: \(error.localizedDescription)") }
            return
        }
        MeshscaleMenuApp.main()
    }
    private static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data((message + "\n").utf8)); exit(1)
    }
}

@MainActor final class AppDelegate: NSObject, NSApplicationDelegate {
    var model: AppModel?
    var terminationReply: @MainActor () -> Void = { NSApplication.shared.reply(toApplicationShouldTerminate: true) }
    private var terminationTask: Task<Void, Never>?
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard terminationTask == nil else { return .terminateLater }
        terminationTask = Task {
            await model?.prepareToTerminate()
            terminationReply()
        }
        return .terminateLater
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.setActivationPolicy(.accessory)
        Task {
            do {
                let data = try await CLIProcessRunner(executable: Runtime.executable, environment: Runtime.cliEnvironment).run(["--version"], timeout: 5)
                let version = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                print("meshscale: embedded CLI reachable (\(version))")
                fflush(stdout)
            } catch { print("meshscale: embedded CLI unavailable"); fflush(stdout) }
        }
    }
    func applicationWillTerminate(_ notification: Notification) {
        model?.shutdown()
    }
}

struct MeshscaleMenuApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model: AppModel
    init() {
        let client = NativeClient(executable: Runtime.executable, environment: Runtime.cliEnvironment)
        let model = AppModel(client: client)
        _model = StateObject(wrappedValue: model)
        delegate.model = model
    }
    var body: some Scene {
        MenuBarExtra {
            PopoverView(model: model).onAppear { delegate.model = model }
        } label: {
            Image(nsImage: Artwork.image(model.status.connection == .connected ? "menu-connected" : "menu-disconnected"))
                .accessibilityLabel("meshscale: \(model.status.connection == .connected ? "Connected" : "Not connected")")
        }.menuBarExtraStyle(.window)
    }
}
