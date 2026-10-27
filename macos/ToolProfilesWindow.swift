import SwiftUI

struct ToolProfilesView: View {
    @ObservedObject var model: WorkbenchModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Tool access").font(.title2.bold())
                Text(model.busy ? "Stop Workbench before changing its tools. Your saved data will be retained."
                               : "Changes apply the next time you start Workbench.")
                    .foregroundStyle(.secondary)
                ForEach(ToolProfileSettings.profiles) { choice in
                    Button {
                        model.capabilityProfile = choice.id; model.save()
                    } label: {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: model.capabilityProfile == choice.id ? "largecircle.fill.circle" : "circle")
                                .foregroundStyle(model.capabilityProfile == choice.id ? Color.accentColor : Color.secondary)
                            VStack(alignment: .leading, spacing: 5) {
                                Text(choice.label).font(.headline)
                                Text(choice.explanation).foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer()
                        }.padding(12).contentShape(Rectangle())
                    }.buttonStyle(.plain).disabled(model.busy)
                        .background(RoundedRectangle(cornerRadius: 10)
                            .fill(model.capabilityProfile == choice.id ? Color.accentColor.opacity(0.08) : Color.primary.opacity(0.04)))
                        .overlay(RoundedRectangle(cornerRadius: 10)
                            .stroke(model.capabilityProfile == choice.id ? Color.accentColor.opacity(0.45) : Color.clear, lineWidth: 1))
                }
                Divider()
                Toggle("Saved evidence tools", isOn: $model.historyAccess)
                    .disabled(model.busy).onChange(of: model.historyAccess) { _ in model.save() }
                Text("Includes previous results, job output and session records. Turning this off also disables artifact paging. Permitted commands can still read files on your Mac.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                Text("Project access and macOS approvals also apply. App operation requires run access in the main window; the selected-app profile still keeps general commands off.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }.padding(22)
        }.frame(minWidth: 440, minHeight: 450)
    }
}
