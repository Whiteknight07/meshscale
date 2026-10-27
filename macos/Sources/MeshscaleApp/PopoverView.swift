import AppKit
import MeshscaleCore
import SwiftUI

struct PopoverView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    @FocusState private var focus: String?
    @State private var paneHeight: CGFloat = 1
    @State private var chromeHeight: CGFloat = 1
    private var p: Palette { Palette(dark: scheme == .dark) }
    private var status: AppStatus { model.status }
    private var connected: Bool { status.connection == .connected }
    private var isAuth: Bool { status.auth != .signedIn }
    private var separator: some View { p.separator.frame(height: 1) }
    private var height: CGFloat { min(paneHeight + chromeHeight, (NSScreen.main?.visibleFrame.height ?? 800) - 16) }
    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 0) {
                header
                if !isAuth && model.screen != .devices { back }
            }.background { GeometryReader { geometry in
                Color.clear.preference(key: ChromeHeight.self, value: geometry.size.height)
            } }
            ScrollView {
                VStack(spacing: 0) {
                    if isAuth {
                        VStack(spacing: 0) { authentication; StatusIssues(model: model, p: p, focus: $focus) }
                    }
                    else {
                        switch model.screen {
                        case .devices: DevicesPane(model: model, p: p, focus: $focus)
                        case .detail: DeviceDetailPane(model: model, p: p, focus: $focus)
                        case .account: AccountPane(model: model, p: p, focus: $focus)
                        case .settings: SettingsPane(model: model, p: p, focus: $focus)
                        }
                    }
                }.frame(width: 360).fixedSize(horizontal: false, vertical: true)
                    .background { GeometryReader { geometry in
                        Color.clear.preference(key: PaneHeight.self, value: geometry.size.height)
                    } }
            }.scrollIndicators(.automatic).frame(height: max(1, height - chromeHeight))
            footer.background { GeometryReader { geometry in
                Color.clear.preference(key: ChromeHeight.self, value: geometry.size.height)
            } }
        }
        .onPreferenceChange(PaneHeight.self) { paneHeight = ceil($0) }
        .onPreferenceChange(ChromeHeight.self) { chromeHeight = ceil($0) }
        .frame(width: 360, height: height)
        .background(p.surface).foregroundStyle(p.ink)
        .font(.system(size: 13)).buttonStyle(QuietButton(palette: p))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .background(WindowHeight(height: height))
        .frame(maxHeight: .infinity, alignment: .top)
        .overlay(alignment: .bottom) { feedback }
        .onExitCommand { model.escape() }
        .onMoveCommand { direction in moveFocus(direction) }
        .onChange(of: model.screen) { old, new in
            focus = new == .devices && old == .detail ? model.selectedID.map { "device-\($0)" } : "back"
        }
        .onAppear {
            model.setVisible(true)
            if focus == nil { focus = isAuth ? "sign-in" : "settings" }
        }
        .onDisappear { model.setVisible(false) }
        .accessibilityElement(children: .contain).accessibilityLabel("meshscale")
    }
    private func iconButton(_ label: String, icon: String, focusID: String, action: @escaping () -> Void) -> some View {
        Button(action: action) { Icon(name: icon, size: 17).frame(width: 28, height: 28).foregroundStyle(p.secondary) }
            .help(label).accessibilityLabel(label).focused($focus, equals: focusID)
    }
    private var header: some View {
        HStack(spacing: 8) {
            Icon(name: connected ? "mesh" : "broken", size: 17)
            Text("meshscale").font(.system(size: 13, weight: .semibold))
            Spacer()
            if !isAuth { iconButton("Settings", icon: "settings", focusID: "settings") { model.navigate(.settings) } }
        }.padding(.leading, 16).padding(.trailing, 12).frame(height: 44)
    }
    private var authentication: some View {
        VStack(alignment: .leading, spacing: 0) {
            Group {
                if status.auth == .signingIn { WaitingIndicator(palette: p) }
                else { Icon(name: "mesh", size: 35).foregroundStyle(p.secondary) }
            }.frame(width: 38, height: 38, alignment: .leading).padding(.bottom, 16)
            Text(status.auth == .signingIn ? "Sign in with Cloudflare" : "Your devices, connected")
                .font(.system(size: 20, weight: .semibold)).tracking(-0.45).frame(height: 25).accessibilityAddTraits(.isHeader)
            Text(status.auth == .signingIn ? "Finish signing in in your browser, then come back here." : "Connect your devices by signing in to Cloudflare in your browser.")
                .font(.system(size: 13)).lineSpacing(2).foregroundStyle(p.secondary).padding(.top, 8).frame(maxWidth: 280, alignment: .leading).fixedSize(horizontal: false, vertical: true)
            if status.auth == .signingIn {
                HStack(spacing: 7) { Circle().fill(p.secondary).frame(width: 5, height: 5); text("Waiting for browser") }
                    .foregroundStyle(p.secondary).padding(.top, 16)
                HStack(spacing: 10) {
                    Button("Open browser again") { model.perform(.restartSignIn) { try await $0.signIn() } }
                        .buttonStyle(UtilityButton(palette: p)).focused($focus, equals: "sign-in").disabled(!model.canPerform(.restartSignIn))
                    Button("Cancel") { model.perform(.cancelSignIn) { await $0.cancelSignIn() } }
                        .font(.system(size: 12)).foregroundStyle(p.secondary).padding(4).focused($focus, equals: "cancel-sign-in").disabled(!model.canPerform(.cancelSignIn))
                }.padding(.top, 17)
            } else {
                Button { model.perform(.signIn) { try await $0.signIn() } } label: {
                    HStack(spacing: 8) { Icon(name: "cloud", size: 17); Text("Sign in with Cloudflare") }
                }.buttonStyle(UtilityButton(palette: p, primary: true, compact: false)).padding(.top, 23)
                    .disabled(!model.canPerform(.signIn)).focused($focus, equals: "sign-in")
            }
        }.padding(.horizontal, 24).padding(.top, 22).padding(.bottom, 30).frame(maxWidth: .infinity, alignment: .leading)
    }
    private var back: some View {
        HStack {
            Button { model.navigate(.devices) } label: {
                HStack(spacing: 1) { Icon(name: "back", size: 17); Text("Devices").font(.system(size: 12)) }.padding(.vertical, 4)
            }.foregroundStyle(p.action).focused($focus, equals: "back").accessibilityLabel("Back to devices")
            Spacer()
        }.padding(.horizontal, 12).padding(.top, 5)
    }
    private var footer: some View {
        VStack(spacing: 0) {
            separator
            HStack(spacing: 12) {
                if isAuth { text("Private network for your devices", size: 11).foregroundStyle(p.secondary) }
                else if model.screen == .account { text("Signed in with Cloudflare").foregroundStyle(p.secondary) }
                else {
                    Button { model.navigate(.account) } label: {
                        HStack(spacing: 12) {
                            VStack(alignment: .leading, spacing: 1) {
                                text(status.account?.email ?? "Cloudflare account", height: 17).lineLimit(1)
                                text(status.account?.displayName ?? "Account details unavailable", size: 11, height: 15).foregroundStyle(p.secondary).lineLimit(1)
                            }
                            Icon(name: "chevron", size: 13).foregroundStyle(p.secondary)
                        }
                    }.accessibilityLabel("Account and sign out").focused($focus, equals: "account")
                }
                Spacer(minLength: 0)
                Button("Quit") { model.client?.quit() }.font(.system(size: 12)).foregroundStyle(p.secondary).padding(.vertical, 4)
                    .keyboardShortcut("q").focused($focus, equals: "quit")
            }.padding(.horizontal, 16).frame(height: isAuth ? 43 : 62)
        }
    }
    @ViewBuilder private var feedback: some View {
        if !model.notice.isEmpty {
            HStack(alignment: .top, spacing: 8) {
                Icon(name: model.noticeIsError ? "alert" : "check", size: 16)
                Text(model.notice).font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                Button("Dismiss") { model.dismissNotice() }.font(.system(size: 11)).focused($focus, equals: "dismiss")
            }.foregroundStyle(model.noticeIsError ? p.error : p.ink).padding(12).background(p.inset, in: RoundedRectangle(cornerRadius: 6))
                .overlay { RoundedRectangle(cornerRadius: 6).strokeBorder(p.separator) }.padding(8)
                .accessibilityElement(children: .contain).accessibilityLabel(model.notice)
        }
    }
    private func moveFocus(_ direction: MoveCommandDirection) {
        guard direction == .up || direction == .down else { return }
        var keys: [String] = []
        if !isAuth { keys.append("settings") }
        if isAuth {
            keys += status.auth == .signingIn ? ["sign-in", "cancel-sign-in"] : ["sign-in"]
            keys += status.issues.map { "refresh-\($0.code)" }
        }
        else if model.screen == .devices {
            keys.append("connect")
            if status.localIssue?.code == "consumer" { keys.append("clear-personal") }
            if status.issues.contains(where: \.canTurnOffConnection) { keys.append("turn-off") }
            keys += status.issues.map { "refresh-\($0.code)" }
            for device in status.devices {
                keys.append("device-\(device.id)")
            }
            if status.devices.filter({ !$0.thisMachine }).isEmpty { keys.append("copy-command") }
        } else {
            keys.append("back")
            switch model.screen {
            case .detail:
                if let device = status.devices.first(where: { $0.id == model.selectedID }) {
                    if device.address != nil { keys.append("copy-ip") }
                    if device.dnsName != nil { keys.append("copy-name") }
                    if status.canSSH(device) { keys.append("ssh") }
                }
            case .account: keys.append("sign-out")
            case .settings: keys.append("launch-at-login")
            case .devices: break
            }
        }
        if !isAuth && model.screen != .account { keys.append("account") }
        keys.append("quit")
        let index = focus.flatMap { keys.firstIndex(of: $0) } ?? (direction == .down ? -1 : 0)
        focus = keys[(index + (direction == .down ? 1 : -1) + keys.count) % keys.count]
    }
}

private struct PaneHeight: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}
private struct ChromeHeight: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value += nextValue() }
}

/// MenuBarExtra keeps its window at the first pane's height, so a shorter pane would
/// float in the middle of it. Resize the window to the pane, keeping its top edge under the menu bar.
private struct WindowHeight: NSViewRepresentable {
    let height: CGFloat
    func makeNSView(context: Context) -> NSView { NSView() }
    func updateNSView(_ view: NSView, context: Context) {
        // The window is attached after the first update, so resize on the next main-actor turn.
        Task { @MainActor in
            guard let window = view.window, window.frame.height != height else { return }
            var frame = window.frame
            frame.origin.y = frame.maxY - height
            frame.size.height = height
            window.setFrame(frame, display: true)
        }
    }
}
