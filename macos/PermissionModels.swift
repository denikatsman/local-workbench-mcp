import AppKit
import Foundation
import Security

struct PermissionEntry: Codable, Identifiable {
    let number: Int
    let id, name, group, adapter, settings, description, scope, source: String
    let service: String?
    let search_aliases: [String]?
    let minimum_macos: Int
    let feature_available: Bool
    let restart_policy: String
    let prerequisite: String?
    var available: Bool {
        if ["unavailable", "prerequisite", "build"].contains(adapter) { return false }
        if adapter == "personal_voice" { if #available(macOS 14, *) {} else { return false } }
        if adapter == "audio" { if #available(macOS 14.2, *) {} else { return false } }
        if adapter == "clipboard" { if #available(macOS 15.4, *) {} else { return false } }
        return true
    }
    func matchesSearch(_ query: String) -> Bool {
        query.isEmpty || ([name, description, service ?? ""] + (search_aliases ?? []))
            .joined(separator: " ").localizedCaseInsensitiveContains(query)
    }
    var settingsLabel: String {
        ["accessibility", "post_events"].contains(id) ? "Device Control and Data Access (Accessibility)" : name
    }
    var requiresTarget: Bool { ["automation", "folder"].contains(adapter) }
    var guidedSettings: Bool { ["accessibility", "listen", "post", "screen"].contains(adapter) }
    var setupEntry: Bool {
        available && !["post_events", "remote_desktop", "admin_files", "accessories", "app_extensions",
                       "background", "app_trust", "filesystem", "firewall"].contains(id)
    }
}

struct PermissionCatalogue: Codable {
    let schema_version: Int
    let catalogue_version, reference_macos: String
    let original_entries, protected_resource_count: Int
    let entries: [PermissionEntry]
}

struct PermissionObservation: Codable {
    var approval = "unknown"
    var readiness = "unverified"
    var note = "No current observation."
    var checked_at = Date().timeIntervalSince1970
    var target: String? = nil
    var access_levels: [String: String]? = nil
    var verification = "not_established"
    var condition: String? = nil
    var needsAttention: Bool {
        !["allowed", "limited"].contains(approval) || readiness != "verified" || condition != nil
    }
    var approvalLabel: String {
        switch approval {
        case "allowed": return "Allowed"
        case "limited": return "Limited access"
        case "denied": return "Off"
        case "restricted": return "Blocked by macOS"
        case "not_requested": return "Not requested"
        case "ask_each_time": return "Asks each time"
        case "unavailable": return "Unavailable"
        default: return "Unknown"
        }
    }
    var readinessLabel: String {
        if condition == "audio_cleanup_previous_owner" { return "Previous probe unresolved" }
        if condition == "audio_cleanup_record_unsaved" { return "Cleanup record not saved" }
        if condition?.hasPrefix("audio_cleanup") == true { return "Cleanup incomplete" }
        if readiness == "pending_restart" { return "Restart pending" }
        if readiness == "unavailable" { return "Unavailable" }
        guard readiness == "verified" else { return "Not verified" }
        switch verification {
        case "authorization_api": return "Approval checked; workflow not checked"
        case "selected_path_read_open": return "Selected path read-open checked"
        case "temporary_audio_tap_no_samples": return "Temporary tap cleanup checked"
        case "dedicated_keychain_canary": return "Workbench canary checked"
        default: return "Scoped check completed"
        }
    }
    var summaryLabel: String { "Approval: \(approvalLabel) · Check: \(readinessLabel)" }
}

// The nonce is created once per process, so PID reuse cannot authorize a saved
// numeric audio object. Probe identity also distinguishes successive tap lives.
struct PermissionProbeOwner: Codable, Equatable {
    let pid: Int32
    let generation: String
    static let current = Self(pid: ProcessInfo.processInfo.processIdentifier, generation: UUID().uuidString)
}
struct PermissionAudioProbeRecord: Codable, Equatable {
    let probeID: String
    let owner: PermissionProbeOwner
    var phase: String
    var tapID: UInt32?
    var createStatus: Int32?
    var destroyStatus: Int32?
    var observed_at = Date().timeIntervalSince1970
    var unresolved: Bool { !["released", "create_failed"].contains(phase) }
}
struct PermissionAudioProbeAPI {
    var create: (UUID) -> (status: Int32, tapID: UInt32)
    var destroy: (UInt32) -> Int32
}

struct PermissionPreferences: Codable {
    var targets: [String: String] = [:]
    var bookmarks: [String: Data] = [:]
    var restart_ticket: String? = nil
    var restart_phase = "none"
    var resume_service = false
    var restart_categories: [String] = []
    var previous_approvals: [String: String] = [:]
    var preparation_queue: [String] = []
    var preparation_index = 0
    var audio_probe: PermissionAudioProbeRecord? = nil
    init() {}
    enum CodingKeys: String, CodingKey {
        case targets, bookmarks, restart_ticket, restart_phase, resume_service, restart_categories, previous_approvals, preparation_queue, preparation_index, audio_probe
    }
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        targets = try values.decodeIfPresent([String: String].self, forKey: .targets) ?? [:]
        bookmarks = try values.decodeIfPresent([String: Data].self, forKey: .bookmarks) ?? [:]
        restart_ticket = try values.decodeIfPresent(String.self, forKey: .restart_ticket)
        restart_phase = try values.decodeIfPresent(String.self, forKey: .restart_phase) ?? "none"
        resume_service = try values.decodeIfPresent(Bool.self, forKey: .resume_service) ?? false
        restart_categories = try values.decodeIfPresent([String].self, forKey: .restart_categories) ?? []
        previous_approvals = try values.decodeIfPresent([String: String].self, forKey: .previous_approvals) ?? [:]
        preparation_queue = try values.decodeIfPresent([String].self, forKey: .preparation_queue) ?? []
        preparation_index = try values.decodeIfPresent(Int.self, forKey: .preparation_index) ?? 0
        audio_probe = try values.decodeIfPresent(PermissionAudioProbeRecord.self, forKey: .audio_probe)
        if let record = audio_probe {
            let identityValid = record.owner.pid > 0 && UUID(uuidString: record.owner.generation) != nil
                && UUID(uuidString: record.probeID) != nil && record.observed_at.isFinite && record.observed_at > 0
            let phaseValid: Bool
            switch record.phase {
            case "creating": phaseValid = record.tapID == nil && record.createStatus == nil && record.destroyStatus == nil
            case "owned": phaseValid = (record.tapID ?? 0) != 0 && record.createStatus == 0 && record.destroyStatus == nil
            case "cleanup_pending": phaseValid = (record.tapID ?? 0) != 0 && record.createStatus == 0 && record.destroyStatus != nil && record.destroyStatus != 0
            case "released": phaseValid = (record.tapID ?? 0) != 0 && record.createStatus == 0 && record.destroyStatus == 0
            case "identity_unavailable": phaseValid = record.tapID == 0 && record.createStatus == 0 && record.destroyStatus == nil
            case "creation_unverified": phaseValid = (record.tapID ?? 0) != 0 && record.createStatus != nil && record.createStatus != 0 && record.destroyStatus == nil
            case "create_failed": phaseValid = record.tapID == nil && record.createStatus != nil && record.createStatus != 0 && record.destroyStatus == nil
            default: phaseValid = false
            }
            guard identityValid && phaseValid else {
                throw DecodingError.dataCorrupted(.init(codingPath: values.codingPath, debugDescription: "Invalid saved audio probe state."))
            }
        }
        guard ["none", "queued", "committed", "relaunching", "verifying"].contains(restart_phase),
              preparation_index >= 0, preparation_index <= preparation_queue.count else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Invalid saved permission workflow state."))
        }
    }
}

func writePermissionState(_ data: Data, to url: URL) throws {
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
                                           attributes: [.posixPermissions: 0o700])
    try data.write(to: url, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    let file = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard file >= 0 else { throw CocoaError(.fileWriteUnknown) }
    defer { close(file) }
    guard fsync(file) == 0 else { throw CocoaError(.fileWriteUnknown) }
    let directory = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard directory >= 0 else { throw CocoaError(.fileWriteUnknown) }
    defer { close(directory) }
    guard fsync(directory) == 0 else { throw CocoaError(.fileWriteUnknown) }
}

func permissionOwner() -> [String: Any] {
    var code: SecCode?
    var staticCode: SecStaticCode?
    var info: CFDictionary?
    var result: [String: Any] = ["bundle_id": Bundle.main.bundleIdentifier ?? "unknown",
        "version": Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown",
        "build": Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown",
        "pid": ProcessInfo.processInfo.processIdentifier, "executable": Bundle.main.executablePath ?? "unknown"]
    if SecCodeCopySelf([], &code) == errSecSuccess, let code = code,
       SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode = staticCode,
       SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
       let values = info as? [String: Any] {
        result["team_id"] = values[kSecCodeInfoTeamIdentifier as String] as? String ?? "unsigned"
        result["signing_identifier"] = values[kSecCodeInfoIdentifier as String] as? String ?? "unknown"
    }
    return result
}

func jsonDictionary<T: Encodable>(_ value: T) -> [String: Any] {
    guard let data = try? JSONEncoder().encode(value),
          let result = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
    return result
}
