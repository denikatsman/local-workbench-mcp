import Foundation

struct WorkbenchLaunchPolicy {
    let preview: Bool
    let permissionsOnly: Bool
    let automaticStart: Bool
    let presentsInitialUI: Bool

    init(arguments: [String], defaults: UserDefaults) {
        preview = arguments.contains("--preview")
        permissionsOnly = arguments.contains("--permissions-only")
        presentsInitialUI = preview || permissionsOnly || !arguments.contains("--background")
        // Argument-domain values can be strings, including "NO".
        automaticStart = defaults.object(forKey: "autoStart") == nil
            ? true : defaults.bool(forKey: "autoStart")
    }

    func shouldStart(resumeService: Bool, hasStarted: Bool) -> Bool {
        !preview && !permissionsOnly && (resumeService || (automaticStart && hasStarted))
    }
}

// Main-queue policy only. A prior verified permanent connection retains its
// run intent across transient child failures; retries have a bounded rate.
struct LauncherRecoveryPolicy {
    private var armed = false
    private var failures = 0
    private var readySince: TimeInterval?
    private let delays: [TimeInterval] = [1, 2, 4, 8, 15, 30, 60, 120, 300]

    mutating func ready(permanent: Bool, now: TimeInterval) {
        guard permanent else { cancel(); return }
        armed = true
        readySince = now
    }

    mutating func stopped(intentional: Bool, now: TimeInterval) -> TimeInterval? {
        guard !intentional, armed else { cancel(); return nil }
        if let readySince, now - readySince >= 60 { failures = 0 }
        readySince = nil
        let delay = delays[min(failures, delays.count - 1)]
        failures = min(failures + 1, delays.count - 1)
        return delay
    }

    mutating func cancel() {
        armed = false
        failures = 0
        readySince = nil
    }
}

// Kept only in memory; never log credentials. Snapshot profile configuration,
// not journals, OAuth databases, or native runtime credentials that must rotate.
struct LauncherRecoveryIdentity: Equatable {
    let settings: [String: String]
    let files: [String: Data]
    let fileSecurity: [String: String]

    static func capture(directory: URL, settings: [String: String]) throws -> Self {
        var files: [String: Data] = [:]
        for name in ["named-tunnel.json", "tunnel-token"] {
            files[name] = try Data(contentsOf: directory.appendingPathComponent(name))
        }
        let profiles = directory.appendingPathComponent("profiles", isDirectory: true)
        if FileManager.default.fileExists(atPath: profiles.path) {
            for profile in try FileManager.default.contentsOfDirectory(at: profiles, includingPropertiesForKeys: nil) {
                let config = profile.appendingPathComponent("workbench.json")
                if FileManager.default.fileExists(atPath: config.path) {
                    files["profiles/" + profile.lastPathComponent + "/workbench.json"] = try Data(contentsOf: config)
                }
            }
        }
        var security: [String: String] = [:]
        for name in files.keys {
            let attributes = try FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent(name).path)
            for key in [FileAttributeKey.posixPermissions, .ownerAccountID, .type] {
                security[name + ":" + key.rawValue] = String(describing: attributes[key])
            }
        }
        return Self(settings: settings, files: files, fileSecurity: security)
    }
}
