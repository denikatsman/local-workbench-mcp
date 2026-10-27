import Foundation
import Darwin
import ReceiverProviderFileSecurity

struct NativeTextMatePluginInstallationFailure: Error {
    let code: String
    // Private durable operation directory, never a config/token/content log.
    let recoveryPath: String?
    let publicationUncertain: Bool
    var effectState: String { publicationUncertain ? "unknown" : "none" }
    init(_ code: String, recoveryPath: String? = nil, publicationUncertain: Bool = false) {
        self.code = code; self.recoveryPath = recoveryPath; self.publicationUncertain = publicationUncertain
    }
}

/// Trusted local acquisition of one approved API2 plugin. No app lifecycle or
/// vendor mutations; supportRoot is a local test seam, never a remote field.
enum NativeTextMatePluginInstallation {
    static let identifier = "tools.localworkbench.textmate.receiver"
    static let slot = "WorkbenchTextMateReceiver.tmplugin"
    private static let fileLimit = 16 * 1024 * 1024, totalLimit = 32 * 1024 * 1024

    static func prepare(source: NativeProviderAdmissionMetadata, target: NativeProviderAdmissionMetadata,
                        helper: NativeProviderAdmissionMetadata, durableRoot: URL,
                        supportRoot: URL = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support"),
                        isTargetRunning: () -> Bool) throws -> NativeProviderAdmissionMetadata {
        guard !isTargetRunning() else { throw NativeTextMatePluginInstallationFailure("native_textmate_target_running") }
        let inspector = NativeProviderAdmissionInspector()
        guard let sourcePath = source.bundlePath,
              NativeProviderAdmissionPolicy.evaluateTextMatePlugin(target: target, helper: helper, plugin: source).state == .eligibleForLaunchTrial else {
            throw NativeTextMatePluginInstallationFailure("native_textmate_source_not_eligible")
        }
        try fresh(source, inspector: inspector)
        let support = try directory(supportRoot.path, privateDirectory: false, owned: true)
        defer { close(support) }
        let durable = try directory(durableRoot.path, privateDirectory: true, owned: true)
        defer { close(durable) }
        let sourceFD = try directory(sourcePath, privateDirectory: false, owned: false)
        defer { close(sourceFD) }
        try validateTree(sourceFD, path: sourcePath, owned: false)
        // Recheck all actual participants after read-only filesystem validation.
        try eligible(source, target: target, helper: helper)
        guard !isTargetRunning() else { throw NativeTextMatePluginInstallationFailure("native_textmate_target_running") }

        let textmate = try child(support, name: "TextMate", create: true)
        defer { close(textmate) }
        let plugins = try child(textmate, name: "PlugIns", create: true)
        defer { close(plugins) }
        let pluginsPath = supportRoot.appendingPathComponent("TextMate/PlugIns").path
        try sameDirectory(plugins, path: pluginsPath)
        let destination = URL(fileURLWithPath: pluginsPath).appendingPathComponent(slot)
        var prior: NativeProviderAdmissionMetadata?
        var priorFD: Int32 = -1
        var existing = stat()
        if fstatat(plugins, slot, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            guard existing.st_mode & S_IFMT == S_IFDIR else { throw NativeTextMatePluginInstallationFailure("native_textmate_slot_conflict") }
            do {
                priorFD = try child(plugins, name: slot, create: false)
                try validateTree(priorFD, path: destination.path, owned: true)
                let pin = try inspector.inspectPlugin(bundlePath: destination.path, expectedBundleID: identifier)
                try eligible(pin, target: target, helper: helper)
                prior = pin
            } catch {
                if priorFD >= 0 { close(priorFD) }
                throw NativeTextMatePluginInstallationFailure("native_textmate_slot_conflict")
            }
            if let prior = prior, sameCode(source, prior) {
                defer { close(priorFD) }
                try fresh(prior, inspector: inspector)
                try sameDirectory(plugins, path: pluginsPath)
                try sameDirectory(priorFD, path: destination.path)
                guard !isTargetRunning() else { throw NativeTextMatePluginInstallationFailure("native_textmate_target_running") }
                return prior
            }
        } else if errno != ENOENT { throw NativeTextMatePluginInstallationFailure("native_textmate_slot_unavailable") }
        defer { if priorFD >= 0 { close(priorFD) } }

        // Every later uncertain effect has a private, stable recovery directory.
        let operationName = "textmate-plugin-" + UUID().uuidString.lowercased()
        let operation = try child(durable, name: operationName, create: true, privateRequired: true, exclusive: true)
        defer { close(operation) }
        let operationPath = durableRoot.appendingPathComponent(operationName).path
        var stagePath: String? = nil
        var publicationAttempted = false
        do {
            try sameDirectory(durable, path: durableRoot.path)
            try receipt(operation, name: "started.json", values: ["state": "preparing", "slot": slot])
            let stageName = ".lwb-plugin-stage-" + UUID().uuidString.lowercased()
            let stage = try child(plugins, name: stageName, create: true, privateRequired: true, exclusive: true)
            defer { close(stage) }
            stagePath = URL(fileURLWithPath: pluginsPath).appendingPathComponent(stageName).path
            let copy = try child(stage, name: slot, create: true, privateRequired: true, exclusive: true)
            defer { close(copy) }
            var budget = Budget()
            try copyTree(sourceFD, sourcePath: sourcePath, destination: copy, depth: 0, budget: &budget)
            try sameDirectory(sourceFD, path: sourcePath, owned: false)
            try fresh(source, inspector: inspector)
            let stagedPath = URL(fileURLWithPath: stagePath!).appendingPathComponent(slot).path
            let staged = try inspector.inspectPlugin(bundlePath: stagedPath, expectedBundleID: identifier)
            guard sameCode(staged, source) else { throw NativeTextMatePluginInstallationFailure("native_textmate_staged_identity_changed") }
            try eligible(staged, target: target, helper: helper)
            if let prior = prior {
                // Preserve prior bytes before replacing the own verified slot.
                let archive = try child(operation, name: "prior.tmplugin", create: true, privateRequired: true, exclusive: true)
                defer { close(archive) }
                budget = Budget()
                try copyTree(priorFD, sourcePath: destination.path, destination: archive, depth: 0, budget: &budget)
                let archivePin = try inspector.inspectPlugin(bundlePath: URL(fileURLWithPath: operationPath).appendingPathComponent("prior.tmplugin").path,
                                                           expectedBundleID: identifier)
                guard sameCode(archivePin, prior) else { throw NativeTextMatePluginInstallationFailure("native_textmate_prior_archive_changed") }
                try eligible(archivePin, target: target, helper: helper)
                try fresh(prior, inspector: inspector)
                try sameDirectory(priorFD, path: destination.path)
                try receipt(operation, name: "prior-preserved.json", values: ["state": "prior_preserved", "cdhash": prior.cdHash])
            }
            try fresh(source, inspector: inspector)
            try eligible(staged, target: target, helper: helper)
            try sameDirectory(plugins, path: pluginsPath)
            try sameDirectory(stage, path: stagePath!)
            guard !isTargetRunning() else { throw NativeTextMatePluginInstallationFailure("native_textmate_target_running_before_publication") }
            try receipt(operation, name: "publication-intent.json", values: ["state": "publication_intent", "staging_path": stagePath!,
                "prior_preserved": prior != nil, "new_cdhash": source.cdHash])
            let flags = prior == nil ? UInt32(RENAME_EXCL) : UInt32(RENAME_SWAP)
            publicationAttempted = true
            guard renameatx_np(stage, slot, plugins, slot, flags) == 0 else {
                throw NativeTextMatePluginInstallationFailure("native_textmate_publication_refused")
            }
            guard fsync(plugins) == 0, fsync(stage) == 0 else { throw NativeTextMatePluginInstallationFailure("native_textmate_publication_durability_unknown") }
            try sameDirectory(plugins, path: pluginsPath)
            try sameDirectory(copy, path: destination.path)
            try validateTree(copy, path: destination.path, owned: true)
            let installed = try inspector.inspectPlugin(bundlePath: destination.path, expectedBundleID: identifier)
            guard sameCode(installed, source) else { throw NativeTextMatePluginInstallationFailure("native_textmate_published_identity_unknown") }
            try eligible(installed, target: target, helper: helper)
            if let prior = prior {
                let displaced: NativeProviderAdmissionMetadata
                do { displaced = try inspector.inspectPlugin(bundlePath: stagedPath, expectedBundleID: identifier) }
                catch { throw NativeTextMatePluginInstallationFailure("native_textmate_displaced_slot_unknown") }
                guard sameCode(displaced, prior), displaced.filePin == prior.filePin else {
                    throw NativeTextMatePluginInstallationFailure("native_textmate_displaced_slot_unknown")
                }
            }
            try receipt(operation, name: "complete.json", values: ["state": "verified_installed", "cdhash": installed.cdHash,
                "staging_path": stagePath!, "prior_preserved": prior != nil])
            // Retain ignored staging namespace: after update it also holds the
            // exact displaced prior bundle. Never delete uncertain filesystem effects.
            return installed
        } catch {
            let code = (error as? NativeTextMatePluginInstallationFailure)?.code ?? "native_textmate_installation_verification_failed"
            try? receipt(operation, name: "failure.json", values: ["state": publicationAttempted ? "publication_unknown" : "not_published",
                "code": code, "staging_path": stagePath ?? "", "never_replay_uncertain": publicationAttempted])
            throw NativeTextMatePluginInstallationFailure(code, recoveryPath: operationPath, publicationUncertain: publicationAttempted)
        }
    }

    private static func fresh(_ pin: NativeProviderAdmissionMetadata, inspector: NativeProviderAdmissionInspector) throws {
        do { try inspector.verifyCurrentDeveloperID(pin) }
        catch { throw NativeTextMatePluginInstallationFailure("native_textmate_source_identity_changed") }
    }
    private static func eligible(_ plugin: NativeProviderAdmissionMetadata, target: NativeProviderAdmissionMetadata,
                                 helper: NativeProviderAdmissionMetadata) throws {
        guard NativeProviderAdmissionPolicy.evaluateTextMatePlugin(target: target, helper: helper, plugin: plugin).state == .eligibleForLaunchTrial else {
            throw NativeTextMatePluginInstallationFailure("native_textmate_participant_identity_changed")
        }
    }
    private static func sameCode(_ a: NativeProviderAdmissionMetadata, _ b: NativeProviderAdmissionMetadata) -> Bool {
        a.kind == .plugin && b.kind == .plugin && a.bundleIdentifier == b.bundleIdentifier &&
        a.signingIdentifier == b.signingIdentifier && a.teamIdentifier == b.teamIdentifier && a.cdHash == b.cdHash &&
        a.designatedRequirement == b.designatedRequirement && a.flags == b.flags && a.entitlements == b.entitlements &&
        a.platformIdentifier == b.platformIdentifier && a.signature == b.signature && a.restrictedMachO == b.restrictedMachO
    }
    private static func safe(_ fd: Int32, _ info: stat, directory: Bool, owned: Bool) -> Bool {
        info.st_nlink > 0 && (directory ? info.st_mode & S_IFMT == S_IFDIR : info.st_mode & S_IFMT == S_IFREG && info.st_nlink == 1) &&
        (owned ? info.st_uid == geteuid() : info.st_uid == 0 || info.st_uid == geteuid()) &&
        info.st_mode & 0o7000 == (directory ? info.st_mode & S_ISVTX : 0) &&
        (info.st_mode & 0o022 == 0 || (directory && info.st_uid == 0 && info.st_mode & S_ISVTX != 0)) &&
        LWProviderHasStableAncestorACL(fd)
    }
    private static func directory(_ path: String, privateDirectory: Bool, owned: Bool) throws -> Int32 {
        guard path.hasPrefix("/"), !path.utf8.contains(0), path.utf8.count <= 4096,
              path.split(separator: "/", omittingEmptySubsequences: false).dropFirst().allSatisfy({
                  !$0.isEmpty && $0 != "." && $0 != ".."
              }) else {
            throw NativeTextMatePluginInstallationFailure("native_textmate_path_invalid")
        }
        var fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw NativeTextMatePluginInstallationFailure("native_textmate_directory_unavailable") }
        do {
            for part in path.split(separator: "/") {
                var current = stat()
                guard fstat(fd, &current) == 0, safe(fd, current, directory: true, owned: false) else {
                    throw NativeTextMatePluginInstallationFailure("native_textmate_unsafe_ancestry")
                }
                let next = openat(fd, String(part), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw NativeTextMatePluginInstallationFailure("native_textmate_directory_alias_or_missing") }
                close(fd); fd = next
            }
            var info = stat()
            guard fstat(fd, &info) == 0, safe(fd, info, directory: true, owned: owned),
                  !privateDirectory || (info.st_mode & 0o7777 == 0o700 && LWProviderHasPrivateACL(fd)) else {
                throw NativeTextMatePluginInstallationFailure("native_textmate_directory_rights_refused")
            }
            return fd
        } catch { close(fd); throw error }
    }
    private static func child(_ parent: Int32, name: String, create: Bool, privateRequired: Bool = false, exclusive: Bool = false) throws -> Int32 {
        if create {
            let made = mkdirat(parent, name, 0o700)
            guard made == 0 || (!exclusive && errno == EEXIST) else {
                throw NativeTextMatePluginInstallationFailure("native_textmate_directory_create_failed")
            }
            if made == 0 && fsync(parent) != 0 {
                throw NativeTextMatePluginInstallationFailure("native_textmate_directory_durability_unknown")
            }
        }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        var info = stat()
        guard fd >= 0 else { throw NativeTextMatePluginInstallationFailure("native_textmate_directory_alias_or_missing") }
        guard fstat(fd, &info) == 0, safe(fd, info, directory: true, owned: true),
              !privateRequired || (info.st_mode & 0o7777 == 0o700 && LWProviderHasPrivateACL(fd)) else {
            close(fd); throw NativeTextMatePluginInstallationFailure("native_textmate_directory_rights_refused")
        }
        return fd
    }
    private static func sameDirectory(_ fd: Int32, path: String, owned: Bool = true) throws {
        let observed = try directory(path, privateDirectory: false, owned: owned)
        defer { close(observed) }
        var a = stat(), b = stat()
        guard fstat(fd, &a) == 0, fstat(observed, &b) == 0, a.st_dev == b.st_dev, a.st_ino == b.st_ino else {
            throw NativeTextMatePluginInstallationFailure("native_textmate_directory_replaced")
        }
    }
    private struct Budget { var entries = 0, bytes = 0 }
    private static func names(_ fd: Int32, path: String) throws -> [String] {
        try sameDirectory(fd, path: path, owned: false)
        let values = try FileManager.default.contentsOfDirectory(atPath: path).sorted()
        guard values.count <= 64 else { throw NativeTextMatePluginInstallationFailure("native_textmate_tree_limit") }
        try sameDirectory(fd, path: path, owned: false)
        return values
    }
    private static func validateTree(_ fd: Int32, path: String, owned: Bool) throws {
        var budget = Budget(); try walk(fd, path: path, destination: nil, depth: 0, owned: owned, budget: &budget)
    }
    private static func copyTree(_ fd: Int32, sourcePath: String, destination: Int32, depth: Int, budget: inout Budget) throws {
        try walk(fd, path: sourcePath, destination: destination, depth: depth, owned: false, budget: &budget)
    }
    private static func walk(_ fd: Int32, path: String, destination: Int32?, depth: Int, owned: Bool, budget: inout Budget) throws {
        guard depth <= 8 else { throw NativeTextMatePluginInstallationFailure("native_textmate_tree_limit") }
        for name in try names(fd, path: path) {
            budget.entries += 1
            guard budget.entries <= 64 else { throw NativeTextMatePluginInstallationFailure("native_textmate_tree_limit") }
            var named = stat()
            guard fstatat(fd, name, &named, AT_SYMLINK_NOFOLLOW) == 0 else { throw NativeTextMatePluginInstallationFailure("native_textmate_source_tree_changed") }
            let childPath = URL(fileURLWithPath: path).appendingPathComponent(name).path
            if named.st_mode & S_IFMT == S_IFDIR {
                let input = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard input >= 0 else { throw NativeTextMatePluginInstallationFailure("native_textmate_bundle_alias_refused") }
                defer { close(input) }
                var actual = stat()
                guard fstat(input, &actual) == 0, safe(input, actual, directory: true, owned: owned),
                      actual.st_dev == named.st_dev, actual.st_ino == named.st_ino else { throw NativeTextMatePluginInstallationFailure("native_textmate_bundle_rights_refused") }
                var output: Int32? = nil
                if let destination = destination { output = try child(destination, name: name, create: true, privateRequired: true, exclusive: true) }
                defer { if let output = output { close(output) } }
                try walk(input, path: childPath, destination: output, depth: depth + 1, owned: owned, budget: &budget)
            } else {
                let input = openat(fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                guard input >= 0 else { throw NativeTextMatePluginInstallationFailure("native_textmate_bundle_alias_refused") }
                defer { close(input) }
                var before = stat()
                guard fstat(input, &before) == 0, safe(input, before, directory: false, owned: owned),
                      before.st_dev == named.st_dev, before.st_ino == named.st_ino,
                      before.st_size >= 0, before.st_size <= fileLimit else { throw NativeTextMatePluginInstallationFailure("native_textmate_bundle_rights_refused") }
                budget.bytes += Int(before.st_size)
                guard budget.bytes <= totalLimit else { throw NativeTextMatePluginInstallationFailure("native_textmate_tree_limit") }
                if let destination = destination {
                    var bytes = Data(count: Int(before.st_size))
                    try bytes.withUnsafeMutableBytes { buffer in
                        var offset = 0
                        while offset < buffer.count {
                            let n = read(input, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                            if n < 0 && errno == EINTR { continue }
                            guard n > 0 else { throw NativeTextMatePluginInstallationFailure("native_textmate_source_read_changed") }
                            offset += n
                        }
                    }
                    var extra: UInt8 = 0
                    var after = stat(), stillNamed = stat()
                    guard read(input, &extra, 1) == 0, fstat(input, &after) == 0,
                          fstatat(fd, name, &stillNamed, AT_SYMLINK_NOFOLLOW) == 0,
                          equal(before, after), equal(before, stillNamed) else { throw NativeTextMatePluginInstallationFailure("native_textmate_source_tree_changed") }
                    try write(bytes, parent: destination, name: name, mode: 0o600 | (before.st_mode & 0o100))
                }
            }
        }
        if let destination = destination, fsync(destination) != 0 { throw NativeTextMatePluginInstallationFailure("native_textmate_copy_durability_unknown") }
    }
    private static func equal(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size && a.st_mode == b.st_mode &&
        a.st_uid == b.st_uid && a.st_nlink == b.st_nlink && a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec &&
        a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec && a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec &&
        a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
    }
    private static func write(_ data: Data, parent: Int32, name: String, mode: mode_t = 0o600) throws {
        let fd = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        guard fd >= 0 else { throw NativeTextMatePluginInstallationFailure("native_textmate_copy_create_failed") }
        defer { close(fd) }
        guard LWProviderHasPrivateACL(fd) else { throw NativeTextMatePluginInstallationFailure("native_textmate_private_acl_refused") }
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let n = Darwin.write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw NativeTextMatePluginInstallationFailure("native_textmate_copy_write_unknown") }
                offset += n
            }
        }
        guard fsync(fd) == 0 else { throw NativeTextMatePluginInstallationFailure("native_textmate_copy_durability_unknown") }
    }
    private static func receipt(_ parent: Int32, name: String, values: [String: Any]) throws {
        try write(JSONSerialization.data(withJSONObject: values, options: [.sortedKeys]), parent: parent, name: name)
        guard fsync(parent) == 0 else { throw NativeTextMatePluginInstallationFailure("native_textmate_receipt_durability_unknown") }
    }
}
