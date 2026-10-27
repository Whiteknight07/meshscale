import MeshscaleCore
import SwiftUI

struct SettingsPane: View {
    @ObservedObject var model: AppModel
    let p: Palette
    @FocusState.Binding var focus: String?
    @AccessibilityFocusState private var headingFocused: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            text("Settings", size: 16, height: 21, weight: .semibold)
                .accessibilityAddTraits(.isHeader).accessibilityFocused($headingFocused).padding(.bottom, 18)
            Toggle(isOn: Binding(get: { model.status.launchAtLogin }, set: { enabled in
                model.perform(.launchAtLogin, { try await $0.setLaunchAtLogin(enabled: enabled) }, success: enabled ? "Launch at login enabled" : "Launch at login disabled")
            })) {
                VStack(alignment: .leading, spacing: 3) {
                    text("Launch at login", size: 13, height: 18)
                    text("Keep meshscale in your menu bar.").foregroundStyle(p.secondary)
                }
            }.toggleStyle(.checkbox).tint(p.action).disabled(!model.canPerform(.launchAtLogin)).focused($focus, equals: "launch-at-login")
        }.padding(.horizontal, 20).padding(.top, 19).padding(.bottom, 26).frame(maxWidth: .infinity, alignment: .leading)
            .onAppear { headingFocused = true }
    }
}
