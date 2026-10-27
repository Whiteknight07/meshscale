import MeshscaleCore
import SwiftUI

struct StatusIssues: View {
    @ObservedObject var model: AppModel
    let p: Palette
    @FocusState.Binding var focus: String?
    private var status: AppStatus { model.status }
    var body: some View {
        ForEach(status.issues, id: \.code) { issue in
            HStack(alignment: .top, spacing: 9) {
                Icon(name: "alert", size: 17).foregroundStyle(p.error).padding(.top, 2)
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(issue.message).font(.system(size: 12, weight: .semibold)).foregroundStyle(p.error)
                        Spacer()
                        Button("Refresh") { Task { await model.refresh() } }.foregroundStyle(p.action).focused($focus, equals: "refresh-\(issue.code)")
                    }
                    Text(issue.recovery).font(.system(size: 12)).lineSpacing(2).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
                    if issue.code == "consumer" {
                        Button("Clear personal registration and connect") { model.perform(.connect) { try await $0.clearPersonalRegistrationAndConnect() } }
                            .font(.system(size: 12)).foregroundStyle(p.action).disabled(!model.canPerform(.connect)).focused($focus, equals: "clear-personal")
                    }
                    if issue.code == "not_installed" {
                        Link("Install Cloudflare One", destination: URL(string: "https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/download/")!)
                            .font(.system(size: 12)).foregroundStyle(p.action)
                    }
                    if issue.canTurnOffConnection {
                        Button("Turn off Cloudflare connection") { model.perform(.disconnect) { try await $0.disconnect() } }
                            .font(.system(size: 12)).foregroundStyle(p.action).disabled(!model.canPerform(.disconnect)).focused($focus, equals: "turn-off")
                    }
                    if issue == status.actionIssue {
                        Button("Dismiss") { model.client?.dismissActionIssue() }.font(.system(size: 11)).foregroundStyle(p.secondary)
                    }
                }
                Spacer(minLength: 0)
            }.padding(.horizontal, 16).padding(.top, 8).padding(.bottom, 8)
        }
    }
}
