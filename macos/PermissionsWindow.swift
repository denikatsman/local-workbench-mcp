import SwiftUI
import AppKit

struct PermissionsView: View {
    @ObservedObject var model: PermissionsModel
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Permissions").font(.title2.bold())
                    Text("Choose what Local Workbench can access.").foregroundStyle(.secondary)
                }
                Spacer()
                Button("Set Up Access…") { model.startPreparation() }
                    .buttonStyle(.borderedProminent).disabled(model.requestInProgress != nil || model.preparing || !model.setupStateWritable)
            }.padding(20)
            HStack {
                TextField("Find a permission", text: $model.search).textFieldStyle(.roundedBorder)
                Picker("View", selection: $model.filter) {
                    ForEach(["Setup", "Needs attention", "Pending restart", "Full catalogue"], id: \.self) { Text($0) }
                }.frame(width: 210)
            }.padding(.horizontal, 20).padding(.bottom, 14)
            if model.preparing {
                HStack {
                    Text("Step \(model.queueIndex + 1) of \(model.queue.count) · \(model.queueCurrent?.name ?? "")").font(.callout.bold())
                    Spacer()
                    Button("Next") { model.nextInQueue() }.disabled(model.requestInProgress != nil)
                    Button("Stop setup") { model.stopPreparation() }
                }.padding(12).background(Color.accentColor.opacity(0.08))
            }
            Divider()
            HSplitView {
                List(selection: $model.selection) {
                    ForEach(Array(Set(model.filtered.map(\.group))).sorted(), id: \.self) { group in
                        Section(group) {
                            ForEach(model.filtered.filter { $0.group == group }) { entry in
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(entry.name)
                                    Text(status(entry)).font(.caption).foregroundStyle(.secondary)
                                }.padding(.vertical, 4).tag(entry.id)
                            }
                        }
                    }
                }.listStyle(.sidebar).frame(minWidth: 235, idealWidth: 270, maxWidth: 320)
                ScrollView {
                    if let entry = model.current { detail(entry).padding(26).frame(maxWidth: .infinity, alignment: .leading) }
                    else { Text("Choose a permission from the list.").foregroundStyle(.secondary).padding(30) }
                }.frame(minWidth: 420, maxWidth: .infinity)
            }
            Divider()
            VStack(alignment: .leading, spacing: 8) {
                if model.restartPhase != "none" {
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(model.restartCancellationPending ? "Restart held: cancellation could not be saved" :
                                (model.restartPhase == "queued" ? "Restart waiting for work to finish" : "Restarting Workbench…")).font(.callout.bold())
                            Text(model.activity).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if model.restartPhase == "queued" { Button("Cancel restart") { model.cancelRestart() } }
                    }
                }
                HStack {
                    Text(model.message).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("Restart Workbench…") { model.queueRestart() }
                        .disabled(model.requestInProgress != nil || ["queued", "committed"].contains(model.restartPhase))
                        .help("Wait for active jobs, browser contexts and tool calls to finish, then restart.")
                }
            }.padding(16)
        }.frame(minWidth: 850, minHeight: 590)
            .sheet(isPresented: $model.showPreparation) { preparation }
            .onAppear { model.refresh() }
    }

    private func status(_ entry: PermissionEntry) -> String {
        let value = model.observations[entry.id] ?? PermissionObservation()
        if !entry.available || value.readiness == "unavailable" { return "Not available for this app" }
        if value.condition == "target_not_running" { return "Open the selected app to check" }
        if model.requestInProgress == entry.id { return "Waiting for macOS" }
        if model.preferences.restart_categories.contains(entry.id) && model.restartPhase != "none" { return "Restart queued" }
        if entry.adapter == "settings" { return "Managed in macOS · \(value.readinessLabel)" }
        return value.summaryLabel
    }

    private func primaryTitle(_ entry: PermissionEntry) -> String {
        let value = model.observations[entry.id] ?? PermissionObservation()
        if value.condition == "target_not_running" { return "Open Selected App…" }
        if entry.adapter == "folder" { return model.preferences.targets[entry.id] == nil ? "Choose Folder…" : "Change Folder…" }
        if entry.adapter == "keychain" { return "Check Keychain Access" }
        if entry.adapter == "automation" && model.preferences.targets[entry.id] == nil { return "Choose App…" }
        if entry.adapter == "settings" || entry.guidedSettings { return "Open \(settingsName(entry))…" }
        if entry.adapter == "clipboard" { return value.approval == "not_requested" ? "Clipboard Setup…" : "Open Clipboard Settings…" }
        if ["allowed", "limited", "denied", "restricted"].contains(value.approval), !entry.settings.isEmpty { return "Manage in System Settings…" }
        return "Enable \(entry.name)"
    }

    private func primary(_ entry: PermissionEntry) {
        let value = model.observations[entry.id] ?? PermissionObservation()
        if value.condition == "target_not_running" { model.openAutomationTarget() }
        else if entry.adapter == "folder" { model.chooseTarget(entry) }
        else if entry.adapter == "keychain" { model.verify(entry) }
        else if entry.guidedSettings { model.request(entry) }
        else if entry.adapter == "settings" || entry.adapter == "clipboard" || (["allowed", "limited", "denied", "restricted"].contains(value.approval) && !entry.settings.isEmpty) { model.openSettings(entry) }
        else { model.request(entry) }
    }

    @ViewBuilder private func detail(_ entry: PermissionEntry) -> some View {
        let value = model.observations[entry.id] ?? PermissionObservation()
        VStack(alignment: .leading, spacing: 20) {
            Text(entry.name).font(.title2.bold())
            Text(shortDescription(entry)).fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 6) {
                Text("Approval: \(value.approvalLabel)").font(.headline)
                Label("Check: \(value.readinessLabel)", systemImage: value.needsAttention ? "exclamationmark.circle" : "info.circle")
                    .foregroundStyle(value.needsAttention ? Color.orange : Color.secondary)
            }
            if entry.available && value.readiness != "unavailable" {
                if entry.id == "system_audio", model.preferences.audio_probe?.unresolved == true {
                    Text("Audio verification is paused").font(.headline)
                    Text("A previous temporary audio probe has no confirmed cleanup. No new probe or cleanup retry will run while it remains unresolved.")
                        .font(.callout).fixedSize(horizontal: false, vertical: true)
                    Text("Restart alone does not confirm release. This is a cleanup check, not a request for new consent. Other Workbench capabilities remain available.")
                        .font(.callout).foregroundStyle(.secondary)
                } else if entry.adapter != "clipboard" || value.approval != "allowed" {
                    Button(primaryTitle(entry)) { primary(entry) }.buttonStyle(.borderedProminent)
                        .disabled(model.requestInProgress != nil || model.restartPhase == "committed")
                }
                if entry.guidedSettings || entry.adapter == "settings" {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("In System Settings").font(.headline)
                        Text(settingsInstructions(entry)).fixedSize(horizontal: false, vertical: true)
                        if ["accessibility", "input_monitoring", "post_events", "screen", "full_disk", "app_management", "developer_tools"].contains(entry.id) {
                            Button("Show Local Workbench in Finder") { NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL]) }
                            Text("Use this exact installed app when adding it with the + button.").font(.callout).foregroundStyle(.secondary)
                        }
                    }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.secondary.opacity(0.06)).clipShape(RoundedRectangle(cornerRadius: 10))
                }
                if entry.adapter == "clipboard" {
                    Text(value.approval == "allowed" ? "macOS currently allows clipboard access. No setup is needed." : "macOS controls clipboard access per app. If Workbench is not listed yet, it has not triggered the first clipboard-access prompt. This screen checks the policy without reading your clipboard.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                if let target = model.preferences.targets[entry.id] {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(entry.adapter == "automation" ? "Selected app" : "Selected folder").font(.caption).foregroundStyle(.secondary)
                        Text(target).font(.callout).textSelection(.enabled)
                        if entry.adapter == "automation" { Button("Choose a different app…") { model.chooseTarget(entry) } }
                    }
                }
                if entry.adapter == "calendar" && !["allowed", "limited"].contains(value.approval) {
                    Button("Allow adding events only") { model.request(entry, writeOnly: true) }.disabled(model.requestInProgress != nil)
                }
                if model.requestInProgress == entry.id {
                    HStack { ProgressView().controlSize(.small); Text("Respond to the macOS permission dialog.").font(.callout) }
                    Button("The dialog is closed — check again") { model.finishedRequest(entry.id) }.buttonStyle(.link)
                }
                if entry.guidedSettings {
                    Text("Changes are checked automatically while this window is open. If macOS asks you to quit and reopen the app, use Restart Workbench below.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            } else {
                Text("This category is included for reference. It cannot be enabled for this native Workbench build.")
                Text(entry.prerequisite ?? entry.description).font(.callout).foregroundStyle(.secondary)
            }
            Divider()
            DisclosureGroup("Details and diagnostics") {
                VStack(alignment: .leading, spacing: 8) {
                    Text(value.note)
                    Text("Observed approval: \(value.approval) · Check: \(value.readiness)")
                    Text("Owner: \(Bundle.main.bundleIdentifier ?? "unknown")")
                    Text("Last checked: \(Date(timeIntervalSince1970: value.checked_at).formatted())")
                    Text("Scope: \(entry.scope) · Evidence: \(value.verification)")
                    if let service = entry.service { Text("macOS service: \(service)") }
                    if let levels = value.access_levels { ForEach(levels.keys.sorted(), id: \.self) { Text("\($0): \(levels[$0] ?? "unknown")") } }
                    Text(entry.feature_available ? "A related Workbench capability exists; this check covers only its stated scope." : "This prepares permission only. A tool using it may be added in a future version.")
                    Button("Check now") { model.verify(entry) }.disabled(model.requestInProgress != nil)
                    if let url = URL(string: entry.source) { Link("Apple documentation", destination: url) }
                }.font(.caption).textSelection(.enabled).padding(.top, 10)
            }
        }
    }

    private func settingsName(_ entry: PermissionEntry) -> String {
        switch entry.id {
        case "post_events", "accessibility": return "Device Control and Data Access / Accessibility Settings"
        case "input_monitoring": return "Input Monitoring Settings"
        case "screen": return "Screen Recording Settings"
        case "full_disk": return "Full Disk Access Settings"
        case "app_management": return "App Management Settings"
        default: return "System Settings"
        }
    }
    private func settingsInstructions(_ entry: PermissionEntry) -> String {
        if entry.id == "post_events" { return "Keyboard and mouse input uses Device Control and Data Access (Accessibility) approval. Turn on Local Workbench there; there is no separate event-posting dialog to wait for." }
        if entry.id == "remote_desktop" { return "This is the separate macOS Remote Desktop category. Workbench currently uses its owned browser and does not provide a Remote Desktop integration." }
        if entry.id == "full_disk" || entry.id == "app_management" {
            return "Open Privacy & Security → \(entry.name). Add Local Workbench with + if it is missing, then turn its switch on. Follow any restart request from macOS. macOS does not expose a public global status check for this category, so this row stays ‘Managed in macOS’."
        }
        if entry.guidedSettings { return "Open Privacy & Security → \(entry.id == "screen" ? "Screen & System Audio Recording" : entry.id == "input_monitoring" ? "Input Monitoring" : entry.settingsLabel). Turn on Local Workbench. If it is missing, use + and select the installed app shown below. Approve authentication if macOS asks." }
        return "Find \(entry.name) in System Settings and manage the relevant app or resource there. This is a system-managed control, not a permission Workbench can switch on itself."
    }
    private func shortDescription(_ entry: PermissionEntry) -> String {
        switch entry.id {
        case "accessibility": return "Allow Workbench to use buttons, menus and controls in other apps."
        case "input_monitoring": return "Allow Workbench to observe keyboard and mouse input for workflows that need it."
        case "screen": return "Allow Workbench to see your Mac’s screen."
        case "full_disk": return "Allow access to files that macOS otherwise protects."
        case "camera": return "Allow camera access."
        case "microphone": return "Allow microphone access."
        default: return entry.description.components(separatedBy: ". ").first ?? entry.description
        }
    }

    private var preparation: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Set up access in advance").font(.title2.bold())
            Text("Choose what to prepare. Each step opens the appropriate macOS prompt, settings pane or target picker. The full reference catalogue is available separately.")
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 10) {
                    ForEach(model.entries.filter { $0.setupEntry }) { entry in
                        Toggle(entry.name, isOn: Binding(get: { model.selectedForPreparation.contains(entry.id) }, set: { value in
                            if value { model.selectedForPreparation.insert(entry.id) } else { model.selectedForPreparation.remove(entry.id) }
                        }))
                    }
                }.padding(4)
            }.frame(height: 330)
            HStack {
                Button("Cancel") { model.showPreparation = false }
                Spacer()
                Button("Begin") { model.beginQueue() }.buttonStyle(.borderedProminent).disabled(model.selectedForPreparation.isEmpty)
            }
        }.padding(24).frame(width: 560)
    }
}
