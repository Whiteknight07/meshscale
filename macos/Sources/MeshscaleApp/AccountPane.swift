import MeshscaleCore
import SwiftUI

struct AccountPane: View {
    @ObservedObject var model: AppModel
    let p: Palette
    @FocusState.Binding var focus: String?
    private var status: AppStatus { model.status }
    @AccessibilityFocusState private var headingFocused: Bool
    private func accessibleHeading<Content: View>(_ content: Content) -> some View {
        content.accessibilityFocused($headingFocused).onAppear { headingFocused = true }
    }
    private func paneHeading(_ title: String) -> some View {
        accessibleHeading(text(title, size: 16, height: 21, weight: .semibold).accessibilityAddTraits(.isHeader)).padding(.bottom, 18)
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            paneHeading("Account")
            text(status.account?.email ?? "Email unavailable", size: 13, height: 18, weight: .medium)
            text(status.account?.displayName ?? "Account unavailable").foregroundStyle(p.secondary).padding(.top, 3)
            HStack(spacing: 7) { Icon(name: "cloud", size: 16); text("Signed in with Cloudflare") }.foregroundStyle(p.secondary).padding(.top, 23)
            Text("Sign out disconnects this Mac from your mesh.")
                .font(.system(size: 12)).lineSpacing(2).foregroundStyle(p.secondary).padding(.top, 12).padding(.bottom, 14)
            Button { model.perform(.signOut) { try await $0.signOut() } } label: { HStack(spacing: 7) { Icon(name: "signout", size: 15); Text("Sign out") } }
                .buttonStyle(UtilityButton(palette: p)).disabled(!model.canPerform(.signOut)).focused($focus, equals: "sign-out")
        }.padding(.horizontal, 20).padding(.top, 19).padding(.bottom, 26).frame(maxWidth: .infinity, alignment: .leading)
    }
}
