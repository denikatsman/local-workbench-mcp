import Foundation
import AppKit
import Darwin

struct NativeElectronLaunchSeed {
    let session: String, generation: String
    let sessionRoot: URL, profile: URL
    var initialFile: URL? = nil
    var arguments: [String] {
        ["--user-data-dir=" + profile.path, "--extensions-dir=" + profile.appendingPathComponent("extensions").path,
         "--disable-extensions", "--remote-debugging-port=0", "--new-window", "--skip-welcome"] +
            (initialFile.map { ["--file-uri=" + $0.absoluteString] } ?? [])
    }
}

/// Only the reviewed Code family is eligible. This uses its unchanged vendor
/// executable and an owned profile; it does not expose arbitrary developer ports.
enum NativeElectronManagedLaunch {
    private static func directory(_ url: URL, create: Bool) throws {
        var information = stat()
        if lstat(url.path, &information) != 0 {
            guard create, errno == ENOENT, mkdir(url.path, 0o700) == 0 else {
                throw NativeProviderHostFailure("native_electron_directory_unavailable")
            }
            guard lstat(url.path, &information) == 0 else { throw NativeProviderHostFailure("native_electron_directory_unavailable") }
        }
        guard information.st_mode & S_IFMT == S_IFDIR, information.st_uid == geteuid(),
              information.st_mode & 0o777 == 0o700 else { throw NativeProviderHostFailure("native_electron_directory_unsafe") }
    }

    static func prepare(url: URL, bundleID: String, stateDirectory: URL,
                        initialFile: URL? = nil, initialBounds: NativeRect? = nil) throws -> NativeElectronLaunchSeed? {
        guard bundleID == "com.microsoft.VSCode" else { return nil }
        let target = try NativeProviderAdmissionInspector().inspectTarget(bundlePath: url.path, expectedBundleID: bundleID)
        guard target.signingIdentifier == bundleID, target.teamIdentifier == "UBF8T346G9",
              target.signature == .valid else { throw NativeProviderHostFailure("native_electron_target_unverified") }
        let session = UUID().uuidString, generation = UUID().uuidString
        let sessions = stateDirectory.appendingPathComponent("native-operations/electron-sessions", isDirectory: true)
        try FileManager.default.createDirectory(at: sessions, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try directory(sessions, create: false)
        try NativeProviderRecovery.validatePrivateDirectory(sessions)
        let sessionRoot = sessions.appendingPathComponent(session.lowercased(), isDirectory: true)
        try directory(sessionRoot, create: true)
        // Code's UNIX instance socket has a103byte pathname limit. The profile
        // stays durable and owned outside Applications, with its exact location
        // recorded in this session instead of using a disposable temporary dir.
        let profiles = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local-workbench-code", isDirectory: true)
        try directory(profiles, create: true)
        try NativeProviderRecovery.validatePrivateDirectory(profiles)
        let profile = profiles.appendingPathComponent(session.replacingOccurrences(of: "-", with: ""), isDirectory: true)
        guard profile.path.utf8.count + 20 <= 103 else { throw NativeProviderHostFailure("native_electron_profile_path_limit") }
        try directory(profile, create: true)
        try NativeProviderRecovery.validatePrivateDirectory(profile)
        let user = profile.appendingPathComponent("User", isDirectory: true); try directory(user, create: true)
        if let bounds=initialBounds {
            let storage=user.appendingPathComponent("globalStorage",isDirectory:true);try directory(storage,create:true)
            // This newly created profile has never been launched. Never seed
            // another process's/profile's storage or move a visible window.
            try writePermissionState(JSONSerialization.data(withJSONObject:NativeElectronBootstrap.storageState(bounds:bounds),options:[.sortedKeys]),
                to:storage.appendingPathComponent("storage.json"))
        }
        try directory(profile.appendingPathComponent("extensions", isDirectory: true), create: true)
        let settings: [String: Any] = ["workbench.startupEditor": "none", "window.restoreWindows": "none",
            "workbench.welcomePage.experimentalOnboarding": false,
            // Select Code's supported textarea input route before this owned
            // profile's first launch. Existing profiles and workspace/language
            // overrides are untouched; bindings still verify the real receiver.
            "editor.editContext": false,
            "files.autoSave": "off", "telemetry.telemetryLevel": "off", "update.mode": "none"]
        try writePermissionState(JSONSerialization.data(withJSONObject: settings, options: [.sortedKeys]),
            to: user.appendingPathComponent("settings.json"))
        let seed = NativeElectronLaunchSeed(session: session, generation: generation, sessionRoot: sessionRoot, profile: profile,initialFile:initialFile)
        try writePermissionState(JSONSerialization.data(withJSONObject: ["version": 1, "session_id": session,
            "generation": generation, "profile_path": profile.path, "app_path": url.path, "bundle_id": bundleID,
            "state": "prepared"], options: [.sortedKeys]), to: sessionRoot.appendingPathComponent("launch.json"))
        return seed
    }

    static func endpoint(seed: NativeElectronLaunchSeed) throws -> (port: Int, path: String) {
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        while ProcessInfo.processInfo.systemUptime < deadline {
            if let data = try NativeProviderRecovery.readElectronEndpoint(profileRoot: seed.profile) {
                guard let text = String(data: data, encoding: .utf8) else { throw NativeProviderHostFailure("native_electron_endpoint_invalid") }
                let raw = text.split(separator: "\n").map(String.init)
                guard raw.count == 2, let port = Int(raw[0]), (1025...65535).contains(port),
                      raw[1].range(of: #"^/devtools/browser/[A-Za-z0-9_-]+$"#, options: .regularExpression) != nil else {
                    throw NativeProviderHostFailure("native_electron_endpoint_invalid")
                }
                return (port, raw[1])
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        throw NativeProviderHostFailure("native_electron_endpoint_not_ready")
    }
}
