import AppKit
import SwiftUI
import XCTest
@testable import MeshscaleApp
@testable import MeshscaleCore

@MainActor final class ViewLayoutTests: XCTestCase {
    func testWindowMeasuresPaneContentAndPreservesTopWhenSwitchingToShorterPane() async {
        let model = AppModel()
        model.status = ReviewFixture.status("connected")
        let host = NSHostingView(rootView: PopoverView(model: model))
        // Never order this test window on screen or touch the running menu app.
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 360, height: 800), styleMask: .borderless, backing: .buffered, defer: false)
        window.contentView = host
        host.layoutSubtreeIfNeeded()
        try? await Task.sleep(for: .milliseconds(100))
        host.layoutSubtreeIfNeeded()
        let devicesHeight = window.frame.height
        let top = window.frame.maxY
        XCTAssertGreaterThan(devicesHeight, 400, "Measured content must include the scroll pane, not just header and footer")
        model.navigate(.account)
        try? await Task.sleep(for: .milliseconds(100))
        host.layoutSubtreeIfNeeded()
        XCTAssertGreaterThan(window.frame.height, 200)
        XCTAssertLessThan(window.frame.height, devicesHeight)
        XCTAssertEqual(window.frame.maxY, top, accuracy: 1)
        model.navigate(.settings)
        try? await Task.sleep(for: .milliseconds(100))
        host.layoutSubtreeIfNeeded()
        XCTAssertGreaterThan(window.frame.height, 150)
        XCTAssertEqual(window.frame.maxY, top, accuracy: 1)
    }
}
