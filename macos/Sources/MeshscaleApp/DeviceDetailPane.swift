import MeshscaleCore
import SwiftUI

struct DeviceDetailPane: View {
    @ObservedObject var model: AppModel
    let p: Palette
    @FocusState.Binding var focus: String?
    private var status: AppStatus { model.status }
    private var connected: Bool { status.connection == .connected }
    private var separator: some View { p.separator.frame(height: 1) }
    @AccessibilityFocusState private var headingFocused: Bool
    private func accessibleHeading<Content: View>(_ content: Content) -> some View {
        content.accessibilityFocused($headingFocused).onAppear { headingFocused = true }
    }
    @ViewBuilder var body: some View {
        if let device = status.devices.first(where: { $0.id == model.selectedID }) {
            let isOnline = device.thisMachine ? connected : device.online
            VStack(spacing: 0) {
                HStack(spacing: 12) {
                    Icon(name: deviceIcon(device), size: 29).foregroundStyle(p.secondary).frame(width: 30)
                    VStack(alignment: .leading, spacing: 3) {
                        accessibleHeading(text(device.name, size: 16, height: 21, weight: .semibold).accessibilityAddTraits(.isHeader))
                        text(device.systemName).foregroundStyle(p.secondary)
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    online(isOnline, p: p)
                }.padding(.horizontal, 20).padding(.top, 20).padding(.bottom, isOnline ? 19 : 0)
                if !isOnline {
                    HStack { text(device.lastSeen(now: model.now)).foregroundStyle(p.secondary); Spacer() }
                        .padding(.leading, 62).padding(.trailing, 20).padding(.top, 11).padding(.bottom, 19)
                }
                if !device.peerStatusNotes.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(device.peerStatusNotes, id: \.self) { note in
                            Text(note).font(.system(size: 11)).foregroundStyle(p.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 20).padding(.bottom, 12)
                }
                VStack(spacing: 0) {
                    separator
                    copyAction("Copy Mesh IP", value: device.address, key: "copy-ip")
                    separator
                    copyAction("Copy name", value: device.dnsName, key: "copy-name")
                    separator
                    Button { model.perform(.ssh, { try await $0.openSSH(deviceID: device.id) }, success: "Opened SSH in Terminal") } label: {
                        HStack(spacing: 8) { Icon(name: "terminal", size: 16).foregroundStyle(p.secondary); Text("SSH in Terminal"); Spacer(); Icon(name: "external", size: 13) }
                            .font(.system(size: 12)).foregroundStyle(p.action).frame(height: 42)
                    }.disabled(!status.canSSH(device) || !model.canPerform(.ssh)).focused($focus, equals: "ssh").help(sshReason(device))
                    separator
                }.padding(.horizontal, 16)
                Text(sshReason(device)).font(.system(size: 12)).lineSpacing(2).foregroundStyle(p.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 20).padding(.top, 13).padding(.bottom, 21)
            }
        } else {
            VStack(alignment: .leading, spacing: 8) { Text("Device no longer available").font(.system(size: 16, weight: .semibold)); Text("Return to your devices to see the current list.") }.padding(20)
        }
    }
    private func sshReason(_ device: MeshDevice) -> String {
        if let sshPolicy = device.sshPolicy, sshPolicy != "configured" { return "SSH: \(sshPolicy)" }
        if device.thisMachine { return "This is the device you’re using." }
        if !device.online { return "This device is offline. Connect it to use SSH." }
        if !connected { return "Connect this Mac to use SSH." }
        if device.isMobile { return "SSH is unavailable on mobile devices." }
        if device.address == nil { return "This device has no Mesh IP assigned." }
        return "Open SSH in Terminal using this Mac’s username. The target must allow SSH access."
    }
    private func copyAction(_ label: String, value: String?, key: String) -> some View {
        Button { if let value { model.copy(value) } } label: {
            HStack(spacing: 8) {
                Icon(name: "copy", size: 16).foregroundStyle(p.secondary)
                Text(label)
                Spacer(minLength: 8)
                Text(value ?? "Not assigned").foregroundStyle(value == nil ? p.secondary : p.action).monospacedDigit().lineLimit(2)
            }.font(.system(size: 12)).frame(height: 42)
        }.disabled(value == nil).focused($focus, equals: key).accessibilityLabel("\(label): \(value ?? "Not assigned")")
    }
}
