import Foundation
import Darwin
import Security
import ReceiverProviderFileSecurity

enum NativeProviderTextClientCompatibility {
    // Keep aligned with ProviderBootstrap.h; a new build requires evidence.
    static let textMateCDHash = "c7f21e7c9c33f4c5b6fc2a7597b38ee192969bf3"
    static func supports(_ target: NativeProviderAdmissionMetadata) -> Bool {
        target.kind == .target && target.bundleIdentifier == "com.macromates.TextMate" &&
            target.signingIdentifier == "com.macromates.TextMate" && target.teamIdentifier == "45TL96F76G" &&
            target.cdHash == textMateCDHash
    }
}

/// Only local adapters choose reviewed classes; remote packets cannot supply a
/// profile. A ready receiver is a mechanism, not verified application behavior.
struct NativeProviderReceiverProfile {
    let textClasses: [String]
    let keyOnlyClasses: [String]
    let keyWindowClasses: [String]

    static func reviewed(target: NativeProviderAdmissionMetadata) -> Self {
        let standard = Self(textClasses: ["NSTextView"], keyOnlyClasses: [], keyWindowClasses: [])
        guard target.bundleIdentifier == "com.adobe.Photoshop",
              target.signingIdentifier == "com.adobe.Photoshop", target.teamIdentifier == "JQ525L2MZD",
              target.signature == .valid, let bundlePath = target.bundlePath else { return standard }
        let inspector = NativeProviderAdmissionInspector()
        guard (try? inspector.inspectTarget(bundlePath: bundlePath, expectedBundleID: target.bundleIdentifier,
                                           expectedExecutable: target.executablePath)) == target else { return standard }
        var code: SecStaticCode?, requirement: SecRequirement?
        let source = "anchor apple generic and identifier \"com.adobe.Photoshop\" and certificate leaf[subject.OU] = \"JQ525L2MZD\""
        guard SecRequirementCreateWithString(source as CFString, [], &requirement) == errSecSuccess,
              let requirement = requirement,
              SecStaticCodeCreateWithPath(URL(fileURLWithPath: bundlePath) as CFURL, [], &code) == errSecSuccess,
              let code = code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else { return standard }
        // Bind the Security object that passed the anchor check, not merely
        // whichever app happens to occupy this path before or after the check.
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              let hash = info[kSecCodeInfoUnique as String] as? Data,
              hash.map({ String(format: "%02x", $0) }).joined() == target.cdHash,
              info[kSecCodeInfoIdentifier as String] as? String == target.signingIdentifier,
              info[kSecCodeInfoTeamIdentifier as String] as? String == target.teamIdentifier,
              (try? inspector.inspectTarget(bundlePath: bundlePath, expectedBundleID: target.bundleIdentifier,
                                            expectedExecutable: target.executablePath)) == target else { return standard }
        return Self(textClasses: ["NSTextView"], keyOnlyClasses: ["PSCocoaContentView"], keyWindowClasses: ["AdobeOwlWindow"])
    }
}

struct NativeProviderPreparationFailure: Error, CustomStringConvertible {
    let code: String
    var privateRecovery: [String: String]? = nil
    var description: String { code }
}

/// Secrets stay in private local files and this internal value. Do not put the
/// preparation or its environment into MCP status, artifacts or ordinary logs.
struct NativeProviderPreparation {
    let configURL: URL
    let socketPath: String
    let journalURL: URL
    let persistentConfigURL: URL
    let token: String
    let session: String
    let generation: String
    let target: NativeProviderAdmissionMetadata
    let helper: NativeProviderAdmissionMetadata
    let plugin: NativeProviderAdmissionMetadata?
    private(set) var allowTextClientInputContextKeys = false
    private(set) var allowTextClientInputContextShift = false
    private(set) var allowTextClientInputContextControlOption = false
    private(set) var allowTextClientInputContextReceiverKeyUp = false

    var environment: [String: String] {
        if plugin != nil { return ["LOCAL_WORKBENCH_PLUGIN_PROVIDER_CONFIG": configURL.path] }
        return ["DYLD_INSERT_LIBRARIES": helper.executablePath,
         "LOCAL_WORKBENCH_PROVIDER_CONFIG": configURL.path]
    }

    /// Each launched process retains its own signed helper file. Updating the
    /// Workbench bundle cannot replace code still mapped into another process.
    static func retainHelper(source: NativeProviderAdmissionMetadata, durableRoot: URL) throws -> NativeProviderAdmissionMetadata {
        guard source.kind == .helper, source.signature == .valid else {
            throw NativeProviderPreparationFailure(code: "native_provider_helper_invalid")
        }
        let root = try canonical(durableRoot), rootFD = try privateDirectory(root.path)
        defer { close(rootFD) }
        let inspector = NativeProviderAdmissionInspector()
        guard try inspector.inspectHelper(executablePath: source.executablePath) == source else {
            throw NativeProviderPreparationFailure(code: "native_provider_helper_changed")
        }
        let sourceFD = open(source.executablePath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard sourceFD >= 0 else { throw NativeProviderPreparationFailure(code: "native_provider_helper_unavailable") }
        defer { close(sourceFD) }
        var before = stat()
        guard fstat(sourceFD, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
              before.st_size > 0, before.st_size <= 8 * 1024 * 1024 else {
            throw NativeProviderPreparationFailure(code: "native_provider_helper_limit")
        }
        var data = Data(count: Int(before.st_size))
        try data.withUnsafeMutableBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = read(sourceFD, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw NativeProviderPreparationFailure(code: "native_provider_helper_read_failed") }
                offset += count
            }
        }
        var after = stat()
        guard fstat(sourceFD, &after) == 0, before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size, before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              try inspector.inspectHelper(executablePath: source.executablePath) == source else {
            throw NativeProviderPreparationFailure(code: "native_provider_helper_changed")
        }
        let name = "receiver-" + UUID().uuidString.lowercased() + ".dylib"
        try exclusiveWrite(data, directory: rootFD, name: name)
        try requireSameDirectory(root.path, descriptor: rootFD)
        let retained = try inspector.inspectHelper(executablePath: root.appendingPathComponent(name).path)
        guard retained.cdHash == source.cdHash, retained.signingIdentifier == source.signingIdentifier,
              retained.teamIdentifier == source.teamIdentifier, retained.designatedRequirement == source.designatedRequirement else {
            throw NativeProviderPreparationFailure(code: "native_provider_retained_helper_changed")
        }
        return retained
    }

    /// Caller supplies reviewed local class policy and a previously approved
    /// private durable root. This method prepares files; it never launches,
    /// injects, signs, changes entitlements, or replaces any existing artifact.
    static func create(target: NativeProviderAdmissionMetadata, helper: NativeProviderAdmissionMetadata,
                       hostAuditToken: Data, receiverClasses: [String], durableRoot: URL,
                       temporaryRoot: URL = URL(fileURLWithPath: "/private/tmp"),
                       keyOnlyReceiverClasses: [String] = [], keyOnlyWindowClasses: [String] = [],
                       plugin: NativeProviderAdmissionMetadata? = nil,
                       textClientReceiverClasses: [String] = [], textClientWindowClasses: [String] = [],
                       textClientDocumentClasses: [String] = [],
                       allowTextClientInputContextKeys: Bool = false,
                       allowTextClientInputContextShift: Bool = false,
                       allowTextClientInputContextControlOption: Bool = false,
                       allowTextClientInputContextReceiverKeyUp: Bool = false) throws -> Self {
        func validClasses(_ names: [String]) -> Bool {
            names.count <= 32 && Set(names).count == names.count && names.allSatisfy {
                $0.range(of: "^[A-Za-z_][A-Za-z0-9_]{0,127}$", options: .regularExpression) != nil
            }
        }
        let textClient = !textClientReceiverClasses.isEmpty || !textClientWindowClasses.isEmpty || !textClientDocumentClasses.isEmpty
        if allowTextClientInputContextReceiverKeyUp && !allowTextClientInputContextControlOption {
            throw NativeProviderPreparationFailure(code: "native_plugin_input_context_receiver_key_up_requires_control_option")
        }
        if allowTextClientInputContextControlOption && !allowTextClientInputContextShift {
            throw NativeProviderPreparationFailure(code: "native_plugin_input_context_control_option_requires_shift")
        }
        if allowTextClientInputContextShift && !allowTextClientInputContextKeys {
            throw NativeProviderPreparationFailure(code: "native_plugin_input_context_shift_requires_keys")
        }
        if allowTextClientInputContextKeys && !textClient {
            throw NativeProviderPreparationFailure(code: "native_plugin_input_context_profile_required")
        }
        if textClient && (plugin == nil || textClientReceiverClasses != ["OakTextView"] ||
            textClientWindowClasses != ["NSWindow"] || textClientDocumentClasses != ["OakDocument"]) {
            throw NativeProviderPreparationFailure(code: "native_plugin_text_client_profile_required")
        }
        if textClient && !NativeProviderTextClientCompatibility.supports(target) {
            throw NativeProviderPreparationFailure(code: "native_plugin_text_client_target_not_reviewed")
        }
        if plugin != nil && (receiverClasses != ["NSTextView"] || !keyOnlyReceiverClasses.isEmpty || !keyOnlyWindowClasses.isEmpty) {
            throw NativeProviderPreparationFailure(code: "native_plugin_standard_receiver_profile_required")
        }
        let decision = plugin.map { NativeProviderAdmissionPolicy.evaluateTextMatePlugin(target: target, helper: helper, plugin: $0) }
            ?? NativeProviderAdmissionPolicy.evaluate(target: target, helper: helper)
        guard decision.state == .eligibleForLaunchTrial, !helper.executablePath.contains(":"),
              hostAuditToken.count == MemoryLayout<audit_token_t>.size,
              !receiverClasses.isEmpty, validClasses(receiverClasses), validClasses(keyOnlyReceiverClasses), validClasses(keyOnlyWindowClasses),
              Set(receiverClasses).isDisjoint(with: Set(keyOnlyReceiverClasses)),
              keyOnlyReceiverClasses.isEmpty == keyOnlyWindowClasses.isEmpty else {
            throw NativeProviderPreparationFailure(code: "native_provider_preparation_not_eligible")
        }
        let durable = try canonical(durableRoot)
        let temporary = try canonical(temporaryRoot)
        let durableFD = try privateDirectory(durable.path)
        defer { close(durableFD) }
        let temporaryFD = try directory(temporary.path, requirePrivate: false)
        defer { close(temporaryFD) }
        var random = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else {
            throw NativeProviderPreparationFailure(code: "native_provider_capability_unavailable")
        }
        let token = random.map { String(format: "%02x", $0) }.joined()
        let session = UUID().uuidString, generation = UUID().uuidString
        let sessionName = session.lowercased()
        let durableSession = durable.appendingPathComponent(sessionName, isDirectory: true)
        let journal = durableSession.appendingPathComponent("journal", isDirectory: true)
        let transientName = "lwb-provider-" + UUID().uuidString.lowercased()
        let transient = temporary.appendingPathComponent(transientName, isDirectory: true)
        let socket = transient.appendingPathComponent("s").path
        guard socket.utf8.count < 104 else { throw NativeProviderPreparationFailure(code: "native_provider_socket_path_limit") }
        let config = transient.appendingPathComponent("bootstrap.json")
        let persistent = durableSession.appendingPathComponent("bootstrap.json")
        var object: [String: Any] = ["version": allowTextClientInputContextReceiverKeyUp ? 8 : allowTextClientInputContextControlOption ? 7 : allowTextClientInputContextShift ? 6 : allowTextClientInputContextKeys ? 5 : textClient ? 4 : plugin != nil ? 3 : keyOnlyReceiverClasses.isEmpty ? 1 : 2, "socket_path": socket, "journal_path": journal.path,
            "token": token, "session": session, "generation": generation,
            "host_audit_token": hostAuditToken.base64EncodedString(), "receiver_classes": receiverClasses,
            "target": ["bundle_identifier": target.bundleIdentifier!, "executable": target.executablePath,
                       "signing_identifier": target.signingIdentifier, "team_identifier": target.teamIdentifier!, "cdhash": target.cdHash],
            "helper": ["path": helper.executablePath, "signing_identifier": helper.signingIdentifier,
                       "team_identifier": helper.teamIdentifier!, "cdhash": helper.cdHash]]
        if let plugin = plugin {
            object["route"] = "textmate_api2_plugin"
            object["plugin"] = ["bundle_path": plugin.bundlePath!, "executable": plugin.executablePath,
                "bundle_identifier": plugin.bundleIdentifier!, "signing_identifier": plugin.signingIdentifier,
                "team_identifier": plugin.teamIdentifier!, "cdhash": plugin.cdHash]
        }
        if !keyOnlyReceiverClasses.isEmpty {
            object["key_only_receiver_classes"] = keyOnlyReceiverClasses
            object["key_only_window_classes"] = keyOnlyWindowClasses
        }
        if textClient {
            object["text_input_client_receiver_classes"] = textClientReceiverClasses
            object["text_input_client_window_classes"] = textClientWindowClasses
            object["text_input_client_document_classes"] = textClientDocumentClasses
        }
        if allowTextClientInputContextKeys { object["text_input_context_keys"] = true }
        if allowTextClientInputContextShift { object["text_input_context_shift"] = true }
        if allowTextClientInputContextControlOption { object["text_input_context_control_option"] = true }
        if allowTextClientInputContextReceiverKeyUp { object["text_input_context_receiver_key_up"] = true }
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard data.count <= 16384 else { throw NativeProviderPreparationFailure(code: "native_provider_configuration_limit") }
        // All predictable validation precedes filesystem allocation. From this
        // point retain uncertain material and a private recovery descriptor.
        do {
            guard mkdirat(durableFD, sessionName, 0o700) == 0 else {
                throw NativeProviderPreparationFailure(code: "native_provider_new_session_failed")
            }
            let sessionFD = try privateChild(durableFD, name: sessionName)
            defer { close(sessionFD) }
            guard mkdirat(sessionFD, "journal", 0o700) == 0 else {
                throw NativeProviderPreparationFailure(code: "native_provider_journal_directory_failed")
            }
            let journalFD = try privateChild(sessionFD, name: "journal")
            defer { close(journalFD) }
            guard mkdirat(temporaryFD, transientName, 0o700) == 0 else {
                throw NativeProviderPreparationFailure(code: "native_provider_socket_directory_failed")
            }
            let transientFD = try privateChild(temporaryFD, name: transientName)
            defer { close(transientFD) }
            try requireSameDirectory(durableSession.path, descriptor: sessionFD)
            try requireSameDirectory(transient.path, descriptor: transientFD)
            // A private durable copy precedes the transient launch file.
            try exclusiveWrite(data, directory: sessionFD, name: "bootstrap.json")
            try exclusiveWrite(data, directory: transientFD, name: "bootstrap.json")
            guard fsync(journalFD) == 0, fsync(durableFD) == 0, fsync(temporaryFD) == 0 else {
                throw NativeProviderPreparationFailure(code: "native_provider_directory_durability_unknown")
            }
            try requireSameDirectory(durableSession.path, descriptor: sessionFD)
            try requireSameDirectory(journal.path, descriptor: journalFD)
            try requireSameDirectory(transient.path, descriptor: transientFD)
        } catch {
            throw NativeProviderPreparationFailure(code: (error as? NativeProviderPreparationFailure)?.code ?? "native_provider_preparation_unknown",
                privateRecovery: ["session_directory": durableSession.path, "temporary_directory": transient.path,
                                  "config_path": config.path, "persistent_config_path": persistent.path,
                                  "journal_path": journal.path])
        }
        return Self(configURL: config, socketPath: socket, journalURL: journal, persistentConfigURL: persistent,
            token: token, session: session, generation: generation, target: target, helper: helper, plugin: plugin,
            allowTextClientInputContextKeys: allowTextClientInputContextKeys, allowTextClientInputContextShift: allowTextClientInputContextShift,
            allowTextClientInputContextControlOption: allowTextClientInputContextControlOption,
            allowTextClientInputContextReceiverKeyUp: allowTextClientInputContextReceiverKeyUp)
    }

    private static func canonical(_ url: URL) throws -> URL {
        guard url.isFileURL, url.path.hasPrefix("/"), !url.path.utf8.contains(0), url.path.utf8.count <= 4096 else {
            throw NativeProviderPreparationFailure(code: "native_provider_directory_invalid")
        }
        // Foundation standardization may rewrite /private/tmp to the /tmp
        // symlink. Preserve lexical canonical paths, then walk with O_NOFOLLOW.
        let pieces = url.path.split(separator: "/", omittingEmptySubsequences: false)
        guard pieces.first == "", pieces.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw NativeProviderPreparationFailure(code: "native_provider_directory_invalid")
        }
        return url
    }
    private static func privateDirectory(_ path: String) throws -> Int32 {
        try directory(path, requirePrivate: true)
    }
    private static func privateChild(_ parent: Int32, name: String) throws -> Int32 {
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        var info = stat()
        guard fd >= 0 else { throw NativeProviderPreparationFailure(code: "native_provider_private_child_unavailable") }
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == geteuid(), info.st_mode & 0o777 == 0o700, LWProviderHasPrivateACL(fd) else {
            close(fd); throw NativeProviderPreparationFailure(code: "native_provider_private_child_changed")
        }
        return fd
    }
    private static func requireSameDirectory(_ path: String, descriptor: Int32) throws {
        let current = try privateDirectory(path)
        defer { close(current) }
        var pinned = stat(), observed = stat()
        guard fstat(descriptor, &pinned) == 0, fstat(current, &observed) == 0,
              pinned.st_dev == observed.st_dev, pinned.st_ino == observed.st_ino else {
            throw NativeProviderPreparationFailure(code: "native_provider_directory_replaced")
        }
    }
    private static func directory(_ path: String, requirePrivate: Bool) throws -> Int32 {
        var fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw NativeProviderPreparationFailure(code: "native_provider_private_directory_unavailable") }
        for piece in path.split(separator: "/") {
            let next = openat(fd, String(piece), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            close(fd)
            guard next >= 0 else { throw NativeProviderPreparationFailure(code: "native_provider_directory_alias_or_missing") }
            fd = next
        }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              !requirePrivate || (info.st_uid == geteuid() && info.st_mode & 0o777 == 0o700 && LWProviderHasPrivateACL(fd)) else {
            close(fd); throw NativeProviderPreparationFailure(code: "native_provider_private_directory_required")
        }
        return fd
    }
    private static func exclusiveWrite(_ data: Data, directory: Int32, name: String) throws {
        let fd = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw NativeProviderPreparationFailure(code: "native_provider_new_configuration_failed") }
        defer { close(fd) }
        guard LWProviderHasPrivateACL(fd) else { throw NativeProviderPreparationFailure(code: "native_provider_configuration_acl_refused") }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let written = write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if written < 0 && errno == EINTR { continue }
                guard written > 0 else { throw NativeProviderPreparationFailure(code: "native_provider_configuration_write_unknown") }
                offset += written
            }
        }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == geteuid(), info.st_nlink == 1,
              info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o777 == 0o600, info.st_size == data.count, LWProviderHasPrivateACL(fd),
              fcntl(fd, F_FULLFSYNC) == 0, fsync(directory) == 0 else {
            throw NativeProviderPreparationFailure(code: "native_provider_configuration_durability_unknown")
        }
    }
}
