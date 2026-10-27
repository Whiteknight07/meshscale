import MeshscaleCore
import SwiftUI

struct DevicesPane: View {
    @ObservedObject var model: AppModel
    let p: Palette
    @FocusState.Binding var focus: String?
    private var status: AppStatus { model.status }
    private var connected: Bool { status.connection == .connected }
    private var separator: some View { p.separator.frame(height: 1) }
    private func iconButton(_ label: String, icon: String, focusID: String, action: @escaping () -> Void) -> some View {
        Button(action: action) { Icon(name: icon, size: 17).frame(width: 28, height: 28).foregroundStyle(p.secondary) }
            .help(label).accessibilityLabel(label).focused($focus, equals: focusID)
    }
    var body: some View { VStack(spacing: 0) { connection; inventory } }
    private var connection: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Group {
                    if status.connection == .connecting { WaitingIndicator(palette: p) }
                    else { Icon(name: connected ? "mesh" : "broken", size: 28).foregroundStyle(connected ? p.online : p.secondary) }
                }.frame(width: 30)
                VStack(alignment: .leading, spacing: 2) {
                    text(connectionLabel, size: 16, height: 20, weight: .semibold)
                    text(connectionDescription).foregroundStyle(p.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading)
                Group {
                    Button(connected ? "Disconnect" : status.connection == .connecting ? "Cancel" : "Connect") {
                        model.performConnectionAction()
                    }.buttonStyle(UtilityButton(palette: p, primary: !connected && status.connection != .connecting))
                        .disabled(!model.canPerform(connected || status.connection == .connecting ? .disconnect : .connect)).focused($focus, equals: "connect")
                }
            }.padding(.horizontal, 16).padding(.top, 15).padding(.bottom, 19)
            if status.connection == .connecting, let progress = status.connectionProgress {
                Text(progress.message).font(.system(size: 12)).foregroundStyle(p.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 16).padding(.bottom, 12)
                    .accessibilityLabel(progress.message)
            }
            separator
        }
    }
    private var connectionLabel: String {
        switch status.connection {
        case .connected: return "Connected"
        case .connecting: return "Connecting"
        case .disconnected: return "Disconnected"
        case .error: return "Connection failed"
        }
    }
    private var connectionDescription: String {
        switch status.connection {
        case .connected: return "via Cloudflare"
        case .connecting: return "Connecting to Cloudflare…"
        default: return "This device is off the mesh"
        }
    }
    private var inventory: some View {
        VStack(spacing: 0) {
            StatusIssues(model: model, p: p, focus: $focus)
            VStack(alignment: .leading, spacing: 0) {
                text("This device", weight: .medium).foregroundStyle(p.secondary).padding(.leading, 8).padding(.top, 2).padding(.bottom, 5)
                if let local = status.devices.first(where: \.thisMachine) { deviceRow(local, local: true) }
                else {
                    HStack(alignment: .top, spacing: 11) {
                        Icon(name: "laptop", size: 21).foregroundStyle(p.secondary).frame(width: 22).padding(.top, 2)
                        VStack(alignment: .leading, spacing: 3) {
                            text("This Mac has no Mesh IP yet.", size: 13, height: 18, weight: .medium)
                            if status.issues.isEmpty {
                            Text(status.connection == .connecting ? "Waiting for your Mesh address." : "Choose Connect to join your mesh. You may need to finish signing in in your browser.")
                                .font(.system(size: 12)).lineSpacing(2).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.leading, 8).padding(.trailing, 8).padding(.vertical, status.issues.isEmpty ? 7 : 4)
                }
            }.padding(.horizontal, 8)
                .padding(.top, !status.issues.isEmpty ? 6 : 10)
                .padding(.bottom, !status.issues.isEmpty ? 4 : 9)
            separator
            let others = status.devices.filter { !$0.thisMachine }
            if others.isEmpty { empty }
            else {
                VStack(spacing: 0) {
                    HStack {
                        text("Other devices", weight: .medium)
                        Spacer()
                        text(inventoryFreshness(others))
                            .help(status.updatedAt.map { "Updated \($0.formatted(date: .omitted, time: .standard))" } ?? "Not updated yet")
                    }.foregroundStyle(p.secondary).padding(.horizontal, 8).padding(.top, 12).padding(.bottom, 5)
                    ForEach(others) { deviceRow($0) }
                }.padding(.horizontal, 8)
            }
        }.padding(.bottom, 8)
    }
    private func inventoryFreshness(_ others: [MeshDevice]) -> String {
        status.inventoryIsStale(now: model.now) ? "Last known status" : "\(others.filter(\.online).count) online"
    }
    private func deviceRow(_ device: MeshDevice, local: Bool = false) -> some View {
        let isOnline = local ? connected : device.online
        return Button { model.navigate(.detail, deviceID: device.id) } label: {
            HStack(spacing: 11) {
                Icon(name: deviceIcon(device), size: 21).foregroundStyle(p.secondary).frame(width: 22)
                VStack(alignment: .leading, spacing: 0) {
                    Text(device.name).font(.system(size: 13, weight: .medium)).lineLimit(1).frame(height: 21)
                    if !isOnline && !local { text(device.lastSeen(now: model.now), height: 19).foregroundStyle(p.secondary) }
                    else { text(device.address ?? "No Mesh IP assigned", height: 19).monospacedDigit().foregroundStyle(p.secondary) }
                }.frame(maxWidth: .infinity, alignment: .leading)
                HStack(spacing: 3) {
                    if local { text("This Mac", size: 11).foregroundStyle(p.secondary) }
                    else { online(isOnline, p: p).help(device.online && device.onlineSource == "probe" ? "Online via probe" : device.online ? "Online" : "Offline") }
                    Icon(name: "chevron", size: 14).foregroundStyle(p.secondary).frame(width: 22, height: 30).accessibilityHidden(true)
                }
            }.padding(.leading, 8).padding(.trailing, 4).frame(height: !status.issues.isEmpty ? 44 : status.connectionProgress != nil && status.connection == .connecting ? 52 : 56)
                .contentShape(Rectangle())
        }.focused($focus, equals: "device-\(device.id)")
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("\(device.name), \(isOnline ? "Online" : "Offline"), \(device.address ?? "No Mesh IP assigned")")
    }
    private var empty: some View {
        VStack(alignment: .leading, spacing: 0) {
            text("Add another device", size: 13, height: 18, weight: .semibold)
            Text("On another Linux device with meshscale installed and signed in, run:")
                .font(.system(size: 12)).lineSpacing(2).foregroundStyle(p.secondary).padding(.top, 6).fixedSize(horizontal: false, vertical: true)
            HStack {
                Text("meshscale up").font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                Spacer()
                iconButton("Copy command", icon: "copy", focusID: "copy-command") { model.copy("meshscale up", command: true) }
            }.padding(.leading, 11).padding(.trailing, 7).padding(.vertical, 7).background(p.inset, in: RoundedRectangle(cornerRadius: 6)).padding(.top, 12)
            text("It will appear here when it connects.").foregroundStyle(p.secondary).padding(.top, 9)
        }.padding(.horizontal, 20).padding(.top, 19).padding(.bottom, 17)
    }
}
