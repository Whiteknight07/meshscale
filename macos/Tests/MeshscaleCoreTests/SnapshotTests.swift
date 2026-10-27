import AppKit
import SwiftUI
import XCTest
@testable import MeshscaleApp
@testable import MeshscaleCore

// Snapshot fixtures and rendering belong to the test bundle, never the shipped app.
@MainActor final class SnapshotTests: XCTestCase {
    func testExportSnapshots() throws {
        guard let directory = ProcessInfo.processInfo.environment["MESHSCALE_SNAPSHOT_DIRECTORY"] else {
            throw XCTSkip("Set MESHSCALE_SNAPSHOT_DIRECTORY to export review images")
        }
        let output = URL(fileURLWithPath: directory)
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        for state in ReviewFixture.states {
            for dark in [false, true] {
                let model = AppModel()
                model.status = ReviewFixture.status(state)
                model.status.updatedAt = Date()
                if state.contains("detail") || state == "ssh-enabled" { model.screen = .detail; model.selectedID = state == "offline-detail" ? "reg-thinkpad" : "node-homelab" }
                if state == "account" || state == "mac-account" { model.screen = .account }
                if state == "settings" { model.screen = .settings }
                let host = NSHostingView(rootView: PopoverView(model: model).environment(\.colorScheme, dark ? .dark : .light))
                // Attach to an unshown window so AppKit scroll hosts perform layout.
                let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 360, height: 800), styleMask: .borderless, backing: .buffered, defer: false)
                window.contentView = host
                host.frame = NSRect(x: 0, y: 0, width: 360, height: 800)
                host.layoutSubtreeIfNeeded()
                RunLoop.main.run(until: Date().addingTimeInterval(0.05))
                host.layoutSubtreeIfNeeded()
                XCTAssertGreaterThan(window.frame.height, 150, "Pane content must contribute to the window height for \(state)")
                host.layoutSubtreeIfNeeded()
                let bitmap = try XCTUnwrap(host.bitmapImageRepForCachingDisplay(in: host.bounds))
                host.cacheDisplay(in: host.bounds, to: bitmap)
                let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
                try png.write(to: output.appendingPathComponent("\(state)-\(dark ? "dark" : "light").png"))
            }
        }
    }
}
