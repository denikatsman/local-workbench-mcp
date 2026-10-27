import Foundation

struct OAuthDiscoverySettings {
    let mode: String
    init(defaults: UserDefaults) throws {
        let value = defaults.object(forKey: "OAuthDiscoveryMode")
        let mode = value as? String ?? "client_metadata"
        guard (value == nil || value is String), ["client_metadata", "dynamic_registration"].contains(mode) else {
            throw NSError(domain: "LocalWorkbench.OAuthDiscovery", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "The saved OAuth discovery mode is invalid."])
        }
        self.mode = mode
    }
    func arguments() -> [String] {
        mode == "client_metadata" ? [] : ["--oauth-discovery-mode", mode]
    }
}

struct ToolProfileSettings {
    struct Choice: Identifiable {
        let id: String
        let label: String
        let explanation: String
    }
    static let profiles = [
        Choice(id: "source_research", label: "Selected-source research", explanation: "Read configured sources and inspect evidence. General commands, edits and app control are off."),
        Choice(id: "project_development", label: "Project development", explanation: "Use file, command and owned-browser workflows. Native app and shared-tab control are off."),
        Choice(id: "selected_app", label: "Selected-app operation", explanation: "Use apps and tabs you explicitly share. General file tools and commands are off."),
        Choice(id: "full_owner", label: "Broad host execution", explanation: "Use all enabled tools. Commands run as your Mac user and can access files beyond the project.")
    ]
    let profile: String
    let historyAccess: Bool

    init(profile: String, historyAccess: Bool) {
        self.profile = profile; self.historyAccess = historyAccess
    }
    init(defaults: UserDefaults) {
        profile = defaults.string(forKey: "capabilityProfile") ?? "full_owner"
        historyAccess = defaults.object(forKey: "historyAccess") == nil || defaults.bool(forKey: "historyAccess")
    }
    func arguments() throws -> [String] {
        guard Self.profiles.contains(where: { $0.id == profile }) else {
            throw NSError(domain: "LocalWorkbench.ToolProfile", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "The saved tool profile is unknown. Choose a profile in Tool access before starting."])
        }
        return ["--capability-profile", profile] + (historyAccess ? [] : ["--no-history-access"])
    }
    func save(defaults: UserDefaults) {
        defaults.set(profile, forKey: "capabilityProfile")
        defaults.set(historyAccess, forKey: "historyAccess")
    }
}
