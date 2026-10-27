import Foundation
import Darwin
import CryptoKit
import ReceiverProviderProtocol
import ReceiverProviderFileSecurity
import WorkbenchProcessSupport

/// Original kernel snapshot retained after the authenticated receiver hello.
/// These bytes are historical evidence, never current process authority.
struct NativeProviderRegisteredProcess: Codable, Equatable {
    let audit: Data
    let pid: Int32, version: Int32
    let uid: UInt32, realUID: UInt32
    let startSeconds: UInt64, startMicroseconds: UInt64
    let executable: String
}

struct NativeProviderRegistrationRecord: Codable, Equatable {
    let version: Int
    let sessionID: String, generation: String, bootID: String
    let process: NativeProviderRegisteredProcess
    let target: NativeProviderAdmissionMetadata, helper: NativeProviderAdmissionMetadata
    let plugin: NativeProviderAdmissionMetadata?
    let authorityEpoch: String, rebindVersion: Int, bootstrapSHA256: String
    enum CodingKeys: String, CodingKey {
        case version, process, target, helper, plugin
        case bootID = "boot_id"
        case sessionID = "provider_session_id", generation = "provider_generation"
        case authorityEpoch = "initial_authority_epoch", rebindVersion = "rebind_version", bootstrapSHA256 = "bootstrap_sha256"
    }
}

struct NativeProviderRegistrationFailure: Error {
    let code: String
    /// A failed/uncertain create stays intact. Never delete it and replay save.
    let created: Bool
    let durabilityUnknown: Bool
    init(_ code: String, created: Bool = false, durabilityUnknown: Bool = false) {
        self.code = code; self.created = created; self.durabilityUnknown = durabilityUnknown
    }
}
struct NativeProviderRegistrationSaveResult {
    enum Durability { case confirmed, unknown }
    let record: NativeProviderRegistrationRecord
    let durability: Durability
}
struct NativeProviderRegistrationInventory {
    let sessionIDs: [String]
    /// A bounded prefix is not an exhaustive inventory or negative authority.
    let truncated: Bool
}
/// Host-private verified bytes from the same pinned read. Never serialize this
/// bundle into public views, telemetry or diagnostics: bootstrap holds secrets.
struct NativeProviderRegistrationBundle {
    let record: NativeProviderRegistrationRecord
    let bootstrapData: Data
}

/// Private immutable registration only. The caller supplies a fixed local root,
/// saves after live admission, and MUST requalify exact live target/audit/helper
/// identity and signing before restoring an endpoint. No token is duplicated.
enum NativeProviderRegistration {
    static let maximumBytes = 65536
    private static let bootstrapLimit = 16384
    #if NATIVE_PROVIDER_REGISTRATION_TESTING
    // Owned-fixture race/durability seam; absent from normal native builds.
    static var boundaryHook: ((String) -> Void)?
    static var flushHook: ((Int32, Int32) -> Bool)?
    #endif
    private static func boundary(_ name: String) {
        #if NATIVE_PROVIDER_REGISTRATION_TESTING
        boundaryHook?(name)
        #endif
    }

    static func save(providerSessionsRoot: URL, preparation: NativeProviderPreparation,
                     process: NativeProviderRegisteredProcess, bootID: String, authorityEpoch: String,
                     rebindVersion: Int, negotiatedHello: [String: Any]) throws -> NativeProviderRegistrationSaveResult {
        guard uuid(preparation.session), uuid(preparation.generation), uuid(bootID), uuid(authorityEpoch), rebindVersion == 2,
              boolean(negotiatedHello["ready"]) == true, negotiatedHello["status"] as? String == "running",
              integer(negotiatedHello["pid"]) == Int64(process.pid),
              integer(negotiatedHello["host_rebind_version"]) == 2, negotiatedHello["authority_epoch"] as? String == authorityEpoch,
              valid(process, target: preparation.target), valid(preparation.target, preparation.helper, plugin: preparation.plugin) else {
            throw NativeProviderRegistrationFailure("native_provider_registration_invalid")
        }
        let tree = try Tree(providerSessionsRoot)
        let directory = try tree.child(tree.root, preparation.session.lowercased())
        let fixedBootstrap = tree.path + "/" + preparation.session.lowercased() + "/bootstrap.json"
        guard preparation.persistentConfigURL.isFileURL, preparation.persistentConfigURL.path == fixedBootstrap,
              preparation.journalURL.isFileURL,
              preparation.journalURL.path == tree.path + "/" + preparation.session.lowercased() + "/journal" else {
            throw NativeProviderRegistrationFailure("native_provider_registration_preparation_mismatch")
        }
        let bytes = try tree.read(directory, "bootstrap.json", limit: bootstrapLimit)
        guard let bootstrap = decode(bytes, limit: bootstrapLimit),
              validBootstrap(bootstrap, root: tree.path, session: preparation.session, generation: preparation.generation,
                             target: preparation.target, helper: preparation.helper, plugin: preparation.plugin),
              (boolean(bootstrap["text_input_context_keys"]) ?? false) == preparation.allowTextClientInputContextKeys,
              (boolean(bootstrap["text_input_context_shift"]) ?? false) == preparation.allowTextClientInputContextShift,
              (boolean(bootstrap["text_input_context_control_option"]) ?? false) == preparation.allowTextClientInputContextControlOption,
              (boolean(bootstrap["text_input_context_receiver_key_up"]) ?? false) == preparation.allowTextClientInputContextReceiverKeyUp,
              bootstrap["token"] as? String == preparation.token,
              bootstrap["socket_path"] as? String == preparation.socketPath else {
            throw NativeProviderRegistrationFailure("native_provider_registration_bootstrap_mismatch")
        }
        let record = NativeProviderRegistrationRecord(version: 2, sessionID: preparation.session, generation: preparation.generation, bootID: bootID,
            process: process, target: preparation.target, helper: preparation.helper, plugin: preparation.plugin, authorityEpoch: authorityEpoch,
            rebindVersion: rebindVersion, bootstrapSHA256: digest(bytes))
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(record)
        guard encoded.count <= maximumBytes, let checked = decode(encoded, limit: maximumBytes),
              validRecord(checked, session: preparation.session) else {
            throw NativeProviderRegistrationFailure("native_provider_registration_limit_or_schema")
        }
        boundary("bootstrap_read")
        try tree.verify()
        // The deterministic full-record slot is the authoritative admission.
        // Reserve/publish it before the historical session receipt, so a crash
        // never makes a new admission discoverable only through history scans.
        var existing = stat()
        if fstatat(directory, "registration.json", &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            throw NativeProviderRegistrationFailure("native_provider_registration_exists")
        }
        guard errno == ENOENT else { throw NativeProviderRegistrationFailure("native_provider_registration_file_unavailable") }
        let intakeDurable = try ensureIntake(tree: tree, maximumEntries: 128)
        let slotDurable = try publishSlot(tree: tree, record: record, encoded: encoded)
        do {
            guard try tree.read(tree.root, slotName(bootID: record.bootID, process: record.process), limit: maximumBytes) == encoded else {
                throw NativeProviderRegistrationFailure("native_provider_registration_slot_changed")
            }
        } catch {
            throw NativeProviderRegistrationFailure((error as? NativeProviderRegistrationFailure)?.code ?? "native_provider_registration_slot_write_unknown", created: true, durabilityUnknown: true)
        }
        boundary("slot_published")
        let fd = openat(directory, "registration.json", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        guard fd >= 0 else {
            throw NativeProviderRegistrationFailure(errno == EEXIST ? "native_provider_registration_exists" : "native_provider_registration_create_failed", created: true, durabilityUnknown: true)
        }
        defer { close(fd) }
        do {
            boundary("registration_created")
            guard tree.safeFile(fd, size: 0) else { throw NativeProviderRegistrationFailure("native_provider_registration_created_file_unsafe") }
            try tree.verify()
            try encoded.withUnsafeBytes { buffer in
                var at = 0
                while at < buffer.count {
                    let count = Darwin.write(fd, buffer.baseAddress!.advanced(by: at), buffer.count - at)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw NativeProviderRegistrationFailure("native_provider_registration_write_unknown") }
                    at += count
                }
            }
            let written = try tree.fileSnapshot(fd, size: encoded.count)
            var durable: Bool
            #if NATIVE_PROVIDER_REGISTRATION_TESTING
            if let flush = flushHook { durable = flush(fd, directory) }
            else { durable = fcntl(fd, F_FULLFSYNC) == 0 && fsync(directory) == 0 }
            #else
            durable = fcntl(fd, F_FULLFSYNC) == 0 && fsync(directory) == 0
            #endif
            boundary("before_save_verify")
            try tree.verify()
            guard tree.matchesFile(fd, bytes: encoded) else { throw NativeProviderRegistrationFailure("native_provider_registration_written_bytes_changed") }
            try tree.verifyNamedFile(directory, "registration.json", fd: fd, initial: written, size: encoded.count)
            return NativeProviderRegistrationSaveResult(record: record, durability: durable && slotDurable && intakeDurable ? .confirmed : .unknown)
        } catch {
            throw NativeProviderRegistrationFailure((error as? NativeProviderRegistrationFailure)?.code ?? "native_provider_registration_write_unknown",
                created: true, durabilityUnknown: true)
        }
    }

    static func load(providerSessionsRoot: URL, sessionID: String) throws -> NativeProviderRegistrationRecord {
        try loadBundle(providerSessionsRoot: providerSessionsRoot, sessionID: sessionID).record
    }

    /// Reconstruct launcher-private settings only from a validated immutable
    /// registration. This grants no authority: the caller still requalifies
    /// exact live code/process and negotiates the authenticated target socket.
    static func preparation(bundle: NativeProviderRegistrationBundle, providerSessionsRoot: URL) throws -> NativeProviderPreparation {
        let record = bundle.record
        guard let root = path(providerSessionsRoot.path), digest(bundle.bootstrapData) == record.bootstrapSHA256,
              let config = decode(bundle.bootstrapData, limit: bootstrapLimit),
              validBootstrap(config, root: root, session: record.sessionID, generation: record.generation,
                  target: record.target, helper: record.helper, plugin: record.plugin),
              let socket = config["socket_path"] as? String, let token = config["token"] as? String,
              let journal = config["journal_path"] as? String else {
            throw NativeProviderRegistrationFailure("native_provider_registration_bootstrap_mismatch")
        }
        let configURL = providerSessionsRoot.appendingPathComponent(record.sessionID.lowercased()).appendingPathComponent("bootstrap.json")
        return NativeProviderPreparation(configURL: configURL, socketPath: socket,
            journalURL: URL(fileURLWithPath: journal), persistentConfigURL: configURL, token: token,
            session: record.sessionID, generation: record.generation, target: record.target, helper: record.helper, plugin: record.plugin,
            allowTextClientInputContextKeys: boolean(config["text_input_context_keys"]) ?? false,
            allowTextClientInputContextShift: boolean(config["text_input_context_shift"]) ?? false,
            allowTextClientInputContextControlOption: boolean(config["text_input_context_control_option"]) ?? false,
            allowTextClientInputContextReceiverKeyUp: boolean(config["text_input_context_receiver_key_up"]) ?? false)
    }

    static func loadBundle(providerSessionsRoot: URL, sessionID: String) throws -> NativeProviderRegistrationBundle {
        guard uuid(sessionID) else { throw NativeProviderRegistrationFailure("native_provider_registration_session_invalid") }
        let tree = try Tree(providerSessionsRoot)
        let directory = try tree.child(tree.root, sessionID.lowercased())
        return try loadBundle(tree: tree, directory: directory, sessionID: sessionID)
    }

    private static func loadBundle(tree: Tree, directory: Int32, sessionID: String) throws -> NativeProviderRegistrationBundle {
        let recordBytes = try tree.read(directory, "registration.json", limit: maximumBytes)
        return try loadBundle(tree: tree, directory: directory, sessionID: sessionID, recordBytes: recordBytes)
    }

    private static func loadBundle(tree: Tree, directory: Int32, sessionID: String, recordBytes: Data) throws -> NativeProviderRegistrationBundle {
        guard let raw = decode(recordBytes, limit: maximumBytes), validRecord(raw, session: sessionID),
              let record = try? JSONDecoder().decode(NativeProviderRegistrationRecord.self, from: recordBytes) else {
            throw NativeProviderRegistrationFailure("native_provider_registration_record_invalid")
        }
        let bootstrapBytes = try tree.read(directory, "bootstrap.json", limit: bootstrapLimit)
        guard digest(bootstrapBytes) == record.bootstrapSHA256,
              let bootstrap = decode(bootstrapBytes, limit: bootstrapLimit),
              validBootstrap(bootstrap, root: tree.path, session: record.sessionID, generation: record.generation,
                             target: record.target, helper: record.helper, plugin: record.plugin) else {
            throw NativeProviderRegistrationFailure("native_provider_registration_bootstrap_mismatch")
        }
        boundary("before_load_verify")
        try tree.verify()
        return NativeProviderRegistrationBundle(record: record, bootstrapData: bootstrapBytes)
    }

    /// A present deterministic slot is authoritative for this exact identity;
    /// unrelated historical receipts are not an inventory or competing authority.
    /// A validated immutable root marker certifies complete legacy intake;
    /// without it, require complete unique legacy selection before migration.
    /// Malformed/unsafe slots never permit fallback. All bytes remain historical
    /// evidence: the caller must still qualify live process/code/socket authority.
    static func loadMatching(providerSessionsRoot: URL, bootID: String, process: NativeProviderRegisteredProcess,
                             maximumEntries: Int = 128) throws -> NativeProviderRegistrationBundle? {
        guard uuid(bootID) else { throw NativeProviderRegistrationFailure("native_provider_registration_boot_invalid") }
        let pinnedTree = try Tree(providerSessionsRoot)
        _ = try ensureIntake(tree: pinnedTree, maximumEntries: maximumEntries)
        let slot = try slotName(bootID: bootID, process: process)
        var slotInfo = stat()
        if fstatat(pinnedTree.root, slot, &slotInfo, AT_SYMLINK_NOFOLLOW) == 0 {
            let bytes = try pinnedTree.read(pinnedTree.root, slot, limit: maximumBytes)
            guard let raw = decode(bytes, limit: maximumBytes), let session = raw["provider_session_id"] as? String,
                  uuid(session), validRecord(raw, session: session),
                  let record = try? JSONDecoder().decode(NativeProviderRegistrationRecord.self, from: bytes),
                  record.bootID.lowercased() == bootID.lowercased(), record.process == process else {
                throw NativeProviderRegistrationFailure("native_provider_registration_slot_invalid")
            }
            let directory = try pinnedTree.child(pinnedTree.root, session.lowercased())
            let bundle = try loadBundle(tree: pinnedTree, directory: directory, sessionID: session, recordBytes: bytes)
            // A present historical receipt must agree. Missing receipt is the
            // defined interrupted-publication case; the slot remains authority.
            var info = stat()
            if fstatat(directory, "registration.json", &info, AT_SYMLINK_NOFOLLOW) == 0 {
                guard try pinnedTree.read(directory, "registration.json", limit: maximumBytes) == bytes else {
                    throw NativeProviderRegistrationFailure("native_provider_registration_slot_conflict")
                }
            } else if errno != ENOENT { throw NativeProviderRegistrationFailure("native_provider_registration_file_unavailable") }
            boundary("before_matching_verify")
            try pinnedTree.verify()
            return bundle
        }
        guard errno == ENOENT else { throw NativeProviderRegistrationFailure("native_provider_registration_file_unavailable") }
        boundary("before_matching_verify")
        try pinnedTree.verify()
        return nil
    }

    /// Scans at most maximumEntries directory entries, including unrelated
    /// helper files. A caller may load candidates individually; neither list nor
    /// load asserts that an original process remains alive or input-qualified.
    static func list(providerSessionsRoot: URL, maximumEntries: Int = 128) throws -> NativeProviderRegistrationInventory {
        guard (1...256).contains(maximumEntries) else { throw NativeProviderRegistrationFailure("native_provider_registration_inventory_limit") }
        let tree = try Tree(providerSessionsRoot)
        let copy = dup(tree.root)
        guard copy >= 0 else { throw NativeProviderRegistrationFailure("native_provider_registration_inventory_unavailable") }
        guard let stream = fdopendir(copy) else { close(copy); throw NativeProviderRegistrationFailure("native_provider_registration_inventory_unavailable") }
        defer { closedir(stream) }
        var sessions: [String] = [], count = 0, truncated = false
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw NativeProviderRegistrationFailure("native_provider_registration_inventory_unavailable") }
                break
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if name == "." || name == ".." { continue }
            guard count < maximumEntries else { truncated = true; break }
            count += 1
            if uuid(name), name == name.lowercased() {
                _ = try tree.child(tree.root, name)
                sessions.append(name)
            }
        }
        boundary("before_list_verify")
        try tree.verify()
        return NativeProviderRegistrationInventory(sessionIDs: sessions.sorted(), truncated: truncated)
    }

    private static let formatName = "registration-format.json"
    private static let intakeTemporaryPrefix = ".registration-intake-"
    private static let formatBytes = Data("{\"format\":\"exact-process-admissions\",\"version\":1}".utf8)

    /// One-time cutover: complete bounded legacy intake precedes the immutable
    /// marker. Every old record is reserved before future saves can use slots.
    /// Original v2 receipts/bootstrap bytes remain untouched. Partial identical
    /// slot intake can resume; a partial/invalid marker is never overwritten.
    private static func ensureIntake(tree: Tree, maximumEntries: Int) throws -> Bool {
        guard (1...256).contains(maximumEntries) else { throw NativeProviderRegistrationFailure("native_provider_registration_inventory_limit") }
        var marker = stat()
        if fstatat(tree.root, formatName, &marker, AT_SYMLINK_NOFOLLOW) == 0 {
            guard try tree.read(tree.root, formatName, limit: maximumBytes) == formatBytes else {
                throw NativeProviderRegistrationFailure("native_provider_registration_format_invalid")
            }
            return true
        }
        guard errno == ENOENT else { throw NativeProviderRegistrationFailure("native_provider_registration_file_unavailable") }
        let initial = try intakeNames(tree: tree, maximumEntries: maximumEntries)
        var records: [(NativeProviderRegistrationRecord, Data)] = []
        var names: Set<String> = []
        var directories: [(Int32, stat)] = []
        for session in initial.filter({ uuid($0) && $0 == $0.lowercased() }).sorted() {
            let directory = try tree.child(tree.root, session)
            var info = stat()
            guard fstat(directory, &info) == 0 else { throw NativeProviderRegistrationFailure("native_provider_registration_path_unavailable") }
            directories.append((directory, info))
            if fstatat(directory, "registration.json", &info, AT_SYMLINK_NOFOLLOW) != 0 {
                guard errno == ENOENT else { throw NativeProviderRegistrationFailure("native_provider_registration_file_unavailable") }
                continue
            }
            let bytes = try tree.read(directory, "registration.json", limit: maximumBytes)
            let bundle = try loadBundle(tree: tree, directory: directory, sessionID: session, recordBytes: bytes)
            let name = try slotName(bootID: bundle.record.bootID, process: bundle.record.process)
            guard names.insert(name).inserted else { throw NativeProviderRegistrationFailure("native_provider_registration_ambiguous") }
            records.append((bundle.record, bytes))
        }
        // A cutover cannot silently adopt unknown orphan/index files.
        guard initial.filter({ $0.hasPrefix("admission-") }).allSatisfy({ names.contains($0) }) else {
            throw NativeProviderRegistrationFailure("native_provider_registration_slot_invalid")
        }
        var pendingMarker: String?
        func verifyInventory() throws {
            try tree.verify()
            for (fd, before) in directories {
                var after = stat()
                guard fstat(fd, &after) == 0,
                      before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
                      before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
                      before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
                      before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
                    throw NativeProviderRegistrationFailure("native_provider_registration_inventory_changed")
                }
            }
            let current = try intakeNames(tree: tree, maximumEntries: maximumEntries, ignoring: pendingMarker)
            guard current.filter({ $0.hasPrefix("admission-") }).allSatisfy({ names.contains($0) }) else {
                throw NativeProviderRegistrationFailure("native_provider_registration_slot_invalid")
            }
            guard current.filter({ !$0.hasPrefix("admission-") && $0 != formatName && $0 != pendingMarker }) == initial.filter({ !$0.hasPrefix("admission-") && $0 != formatName }) else {
                throw NativeProviderRegistrationFailure("native_provider_registration_inventory_changed")
            }
        }
        boundary("before_matching_verify")
        try verifyInventory()
        var created = false
        do {
            for (record, bytes) in records {
                let durable = try publishSlot(tree: tree, record: record, encoded: bytes, allowIdentical: true)
                created = true
                guard durable else { throw NativeProviderRegistrationFailure("native_provider_registration_intake_durability_unknown", created: true, durabilityUnknown: true) }
                guard try tree.read(tree.root, slotName(bootID: record.bootID, process: record.process), limit: maximumBytes) == bytes else {
                    throw NativeProviderRegistrationFailure("native_provider_registration_slot_changed")
                }
            }
            try verifyInventory()
            let temporary = intakeTemporaryPrefix + UUID().uuidString.lowercased()
            pendingMarker = temporary
            let durable = try publish(tree: tree, name: temporary, encoded: formatBytes, allowIdentical: false,
                commitName: formatName, beforeCommit: { try verifyInventory() })
            created = true
            try tree.verify()
            return durable
        } catch {
            if created {
                throw NativeProviderRegistrationFailure((error as? NativeProviderRegistrationFailure)?.code ?? "native_provider_registration_intake_unknown", created: true, durabilityUnknown: true)
            }
            throw error
        }
    }

    /// Bound original entries, reserved slots and retained intake temporaries
    /// separately, each by maximumEntries. A retained temporary needs an exact
    /// generated UUID name, private regular-file safety and a prefix of the
    /// fixed marker bytes; it never supplies cutover authority. At most three
    /// times maximumEntries plus the current marker temporary are visited.
    private static func intakeNames(tree: Tree, maximumEntries: Int, ignoring: String? = nil) throws -> Set<String> {
        let copy = openat(tree.root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copy >= 0 else { throw NativeProviderRegistrationFailure("native_provider_registration_inventory_unavailable") }
        guard let stream = fdopendir(copy) else { close(copy); throw NativeProviderRegistrationFailure("native_provider_registration_inventory_unavailable") }
        defer { closedir(stream) }
        var names: Set<String> = [], originals = 0, slots = 0, temporaries = 0
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw NativeProviderRegistrationFailure("native_provider_registration_inventory_unavailable") }
                break
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if name == "." || name == ".." || name == formatName || name == ignoring { continue }
            let suffix = String(name.dropFirst(intakeTemporaryPrefix.count))
            let temporary = name.hasPrefix(intakeTemporaryPrefix) && uuid(suffix) && suffix == suffix.lowercased()
            if temporary { temporaries += 1 }
            else if name.hasPrefix("admission-") { slots += 1 }
            else { originals += 1 }
            guard originals <= maximumEntries, slots <= maximumEntries, temporaries <= maximumEntries else {
                throw NativeProviderRegistrationFailure("native_provider_registration_inventory_truncated")
            }
            if temporary {
                let bytes = try tree.read(tree.root, name, limit: formatBytes.count, allowEmpty: true)
                guard formatBytes.starts(with: bytes) else { throw NativeProviderRegistrationFailure("native_provider_registration_format_temporary_invalid") }
            }
            names.insert(name)
        }
        try tree.verify()
        return names
    }

    /// Exact boot plus every immutable process field; JSON key order is fixed.
    private static func slotName(bootID: String, process: NativeProviderRegisteredProcess) throws -> String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        var bytes = Data(bootID.lowercased().utf8); bytes.append(0)
        bytes.append(try encoder.encode(process))
        return "admission-" + digest(bytes) + ".json"
    }

    /// Exclusive immutable publication. Partial/unknown files stay in place and
    /// prohibit fallback/replay. No rename, overwrite, cleanup or secret copy.
    private static func publishSlot(tree: Tree, record: NativeProviderRegistrationRecord, encoded: Data, allowIdentical: Bool = false) throws -> Bool {
        let name = try slotName(bootID: record.bootID, process: record.process)
        return try publish(tree: tree, name: name, encoded: encoded, allowIdentical: allowIdentical)
    }

    private static func publish(tree: Tree, name: String, encoded: Data, allowIdentical: Bool,
                                commitName: String? = nil, beforeCommit: (() throws -> Void)? = nil) throws -> Bool {
        try tree.verify()
        let fd = openat(tree.root, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        guard fd >= 0 else {
            if errno == EEXIST && allowIdentical {
                guard try tree.read(tree.root, name, limit: maximumBytes) == encoded else {
                    throw NativeProviderRegistrationFailure("native_provider_registration_ambiguous")
                }
                // Confirm current persistence without rewriting bytes. This
                // makes identical interrupted legacy intake resumable, while
                // asserting nothing about its earlier flush attempt.
                return try tree.flushLastRead(parent: tree.root)
            }
            throw NativeProviderRegistrationFailure(errno == EEXIST ? "native_provider_registration_ambiguous" : "native_provider_registration_slot_create_failed")
        }
        defer { close(fd) }
        do {
            boundary(commitName == formatName ? "format_created" : "slot_created")
            guard tree.safeFile(fd, size: 0) else { throw NativeProviderRegistrationFailure("native_provider_registration_slot_unsafe") }
            try tree.verify()
            try encoded.withUnsafeBytes { buffer in
                var offset = 0
                while offset < buffer.count {
                    let count = Darwin.write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw NativeProviderRegistrationFailure("native_provider_registration_slot_write_unknown") }
                    offset += count
                }
            }
            let written = try tree.fileSnapshot(fd, size: encoded.count)
            let durable: Bool
            #if NATIVE_PROVIDER_REGISTRATION_TESTING
            if let flush = flushHook { durable = flush(fd, tree.root) }
            else { durable = fcntl(fd, F_FULLFSYNC) == 0 && fsync(tree.root) == 0 }
            #else
            durable = fcntl(fd, F_FULLFSYNC) == 0 && fsync(tree.root) == 0
            #endif
            boundary(commitName == formatName ? "before_format_verify" : "before_slot_verify")
            try tree.verify()
            guard tree.matchesFile(fd, bytes: encoded) else { throw NativeProviderRegistrationFailure("native_provider_registration_slot_changed") }
            try tree.verifyNamedFile(tree.root, name, fd: fd, initial: written, size: encoded.count)
            if let destination = commitName {
                try beforeCommit?()
                guard renameatx_np(tree.root, name, tree.root, destination, UInt32(RENAME_EXCL)) == 0 else {
                    throw NativeProviderRegistrationFailure("native_provider_registration_format_publish_unknown")
                }
                let committed = try tree.fileSnapshot(fd, size: encoded.count)
                guard tree.matchesFile(fd, bytes: encoded) else { throw NativeProviderRegistrationFailure("native_provider_registration_slot_changed") }
                try tree.verifyNamedFile(tree.root, destination, fd: fd, initial: committed, size: encoded.count)
                try tree.verify()
                return fsync(tree.root) == 0 && durable
            }
            return durable
        } catch {
            throw NativeProviderRegistrationFailure((error as? NativeProviderRegistrationFailure)?.code ?? "native_provider_registration_slot_write_unknown",
                created: true, durabilityUnknown: true)
        }
    }

    private static func digest(_ value: Data) -> String { SHA256.hash(data: value).map { String(format: "%02x", $0) }.joined() }
    private static func decode(_ data: Data, limit: Int) -> [String: Any]? {
        guard !data.isEmpty, data.count <= limit else { return nil }
        return LWProviderDecodeJSON(data, nil) as? [String: Any]
    }
    private static func keys(_ object: [String: Any], _ required: Set<String>, optional: Set<String> = []) -> Bool {
        required.isSubset(of: Set(object.keys)) && Set(object.keys).isSubset(of: required.union(optional))
    }
    private static func string(_ value: Any?, _ limit: Int) -> Bool {
        guard let value = value as? String else { return false }
        return !value.isEmpty && value.utf8.count <= limit && !value.utf8.contains(0)
    }
    private static func path(_ value: Any?) -> String? {
        guard let value = value as? String, string(value, 4096), value.hasPrefix("/"),
              value.split(separator: "/", omittingEmptySubsequences: false).dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { return nil }
        return value
    }
    private static func uuid(_ value: Any?) -> Bool {
        guard let value = value as? String else { return false }
        return value.utf8.count == 36 && UUID(uuidString: value) != nil
    }
    private static func integer(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(), !CFNumberIsFloatType(number) else { return nil }
        return number.int64Value
    }
    private static func boolean(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }
    private static func hash(_ value: Any?) -> Bool {
        guard let value = value as? String, value.utf8.count == 64 else { return false }
        return value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    private static func valid(_ process: NativeProviderRegisteredProcess, target: NativeProviderAdmissionMetadata) -> Bool {
        guard process.audit.count == MemoryLayout<audit_token_t>.size, process.pid > 0,
              process.uid == geteuid(), process.realUID == getuid(), process.startSeconds > 0,
              process.startSeconds <= UInt64(Int64.max), process.startMicroseconds < 1_000_000,
              path(process.executable) != nil, process.executable == target.executablePath else { return false }
        var audit = audit_token_t()
        _ = withUnsafeMutableBytes(of: &audit) { process.audit.copyBytes(to: $0) }
        return audit_token_to_pid(audit) == process.pid && audit_token_to_pidversion(audit) == process.version &&
            audit_token_to_euid(audit) == process.uid && audit_token_to_ruid(audit) == process.realUID
    }
    private static func valid(_ target: NativeProviderAdmissionMetadata, _ helper: NativeProviderAdmissionMetadata, plugin: NativeProviderAdmissionMetadata?) -> Bool {
        let decision = NativeProviderAdmissionPolicy.evaluate(target: target, helper: helper)
        if let plugin = plugin {
            // Persistence validates saved shape only. Current plugin admission
            // also performs live Developer ID inspection; the runtime must do
            // that before save and again before restoration, never infer it here.
            guard decision.state == .eligibleForLaunchTrial ||
                    (decision.state == .unsupported && decision.prerequisites == ["target_existing_allow_dyld_environment_variables_required"]),
                  target.bundleIdentifier == "com.macromates.TextMate", target.signingIdentifier == "com.macromates.TextMate",
                  target.teamIdentifier == "45TL96F76G", target.hardenedRuntime,
                  target.entitlements.disableLibraryValidation == .enabled,
                  plugin.kind == .plugin, let bundle = plugin.bundlePath, bundle.hasSuffix(".tmplugin"),
                  plugin.executablePath.hasPrefix(bundle + "/Contents/MacOS/"),
                  plugin.bundleIdentifier == "tools.localworkbench.textmate.receiver",
                  plugin.signingIdentifier == "tools.localworkbench.textmate.receiver", plugin.teamIdentifier == helper.teamIdentifier else { return false }
        } else if decision.state != .eligibleForLaunchTrial { return false }
        for code in [target, helper] + (plugin.map { [$0] } ?? []) {
            let pin = code.filePin
            let fields = [code.entitlements.allowDYLD, code.entitlements.disableLibraryValidation, code.entitlements.sandbox]
            guard code.signature == .valid, code.flags & (NativeProviderSignatureFlags.adHoc | NativeProviderSignatureFlags.linkerSigned | NativeProviderSignatureFlags.restrict) == 0,
                  code.platformIdentifier == nil || code.platformIdentifier == 0,
                  code.restrictedMachO == false, !fields.contains(.malformed), !fields.contains(.unavailable), code.entitlements.sandbox != .enabled,
                  (40...128).contains(code.cdHash.count), code.cdHash.count % 2 == 0,
                  code.cdHash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }), path(code.executablePath) != nil, code.bundlePath.map({ path($0) != nil }) ?? true,
                  string(code.signingIdentifier, 512), string(code.designatedRequirement, 16384), string(code.teamIdentifier, 128),
                  pin.device <= UInt64(UInt32.max), pin.inode > 0, pin.size > 0,
                  pin.modifiedSeconds >= 0, (0..<1_000_000_000).contains(pin.modifiedNanoseconds),
                  pin.mode & UInt32(S_IFMT) == UInt32(S_IFREG), pin.mode & UInt32(S_ISUID | S_ISGID) == 0 else { return false }
        }
        return true
    }
    private static func metadata(_ value: Any?) -> NativeProviderAdmissionMetadata? {
        guard let object = value as? [String: Any], keys(object,
            ["inspectionSource", "kind", "executablePath", "signingIdentifier", "designatedRequirement", "cdHash", "flags", "signature", "entitlements", "filePin"],
            optional: ["bundlePath", "bundleIdentifier", "teamIdentifier", "platformIdentifier", "restrictedMachO"]),
              object["inspectionSource"] as? String == "Security.framework static-code APIs and bounded Mach-O headers; no dynamic admission proof",
              let flags = integer(object["flags"]), (0...Int64(UInt32.max)).contains(flags),
              let restrictions = object["restrictedMachO"], boolean(restrictions) != nil,
              let entitlements = object["entitlements"] as? [String: Any], keys(entitlements, ["allowDYLD", "disableLibraryValidation", "sandbox"]),
              let pin = object["filePin"] as? [String: Any], keys(pin, ["device", "inode", "size", "modifiedSeconds", "modifiedNanoseconds", "mode"]),
              pin.values.allSatisfy({ integer($0) != nil }),
              let data = try? JSONSerialization.data(withJSONObject: object),
              let metadata = try? JSONDecoder().decode(NativeProviderAdmissionMetadata.self, from: data) else { return nil }
        if let platform = object["platformIdentifier"], !(platform is NSNull), integer(platform) == nil { return nil }
        return metadata
    }
    private static func validRecord(_ object: [String: Any], session: String) -> Bool {
        guard keys(object, ["version", "provider_session_id", "provider_generation", "process", "target", "helper", "initial_authority_epoch", "rebind_version", "bootstrap_sha256", "boot_id"], optional: ["plugin"]),
              integer(object["version"]) == 2, integer(object["rebind_version"]) == 2,
              let savedSession = object["provider_session_id"] as? String, uuid(savedSession), savedSession.lowercased() == session.lowercased(),
              uuid(object["provider_generation"]), uuid(object["boot_id"]), uuid(object["initial_authority_epoch"]), hash(object["bootstrap_sha256"]),
              let target = metadata(object["target"]), let helper = metadata(object["helper"]),
              (object["plugin"] == nil || metadata(object["plugin"]) != nil),
              valid(target, helper, plugin: metadata(object["plugin"])),
              let process = object["process"] as? [String: Any], keys(process, ["audit", "pid", "version", "uid", "realUID", "startSeconds", "startMicroseconds", "executable"]),
              ["pid", "version", "uid", "realUID", "startSeconds", "startMicroseconds"].allSatisfy({ integer(process[$0]) != nil }),
              let auditText = process["audit"] as? String, let audit = Data(base64Encoded: auditText), audit.base64EncodedString() == auditText,
              let bytes = try? JSONSerialization.data(withJSONObject: process),
              let snapshot = try? JSONDecoder().decode(NativeProviderRegisteredProcess.self, from: bytes), valid(snapshot, target: target) else { return false }
        return true
    }
    /// Mirrors the current producer's compact pins and version-specific profile.
    /// This parses saved metadata only; it never grants live process authority.
    private static func validBootstrap(_ object: [String: Any], root: String, session: String, generation: String,
                                       target: NativeProviderAdmissionMetadata, helper: NativeProviderAdmissionMetadata,
                                       plugin: NativeProviderAdmissionMetadata?) -> Bool {
        guard let version = integer(object["version"]), (1...8).contains(version), (version >= 3) == (plugin != nil) else { return false }
        var required: Set<String> = ["version", "socket_path", "journal_path", "token", "session", "generation", "host_audit_token", "target", "helper", "receiver_classes"]
        if version == 2 { required.formUnion(["key_only_receiver_classes", "key_only_window_classes"]) }
        if version >= 3 { required.formUnion(["route", "plugin"]) }
        if version >= 4 { required.formUnion(["text_input_client_receiver_classes", "text_input_client_window_classes", "text_input_client_document_classes"]) }
        for (minimum, key) in [(5, "text_input_context_keys"), (6, "text_input_context_shift"), (7, "text_input_context_control_option"), (8, "text_input_context_receiver_key_up")] where version >= minimum {
            required.insert(key)
            guard boolean(object[key]) == true else { return false }
        }
        func classes(_ value: Any?) -> Bool {
            guard let names = value as? [String], (1...32).contains(names.count), Set(names).count == names.count else { return false }
            return names.allSatisfy { $0.range(of: "^[A-Za-z_][A-Za-z0-9_]{0,127}$", options: .regularExpression) != nil }
        }
        guard keys(object, required), object["session"] as? String == session, object["generation"] as? String == generation,
              let socket = path(object["socket_path"]), socket.utf8.count < 104, hash(object["token"]),
              object["journal_path"] as? String == root + "/" + session.lowercased() + "/journal",
              let auditText = object["host_audit_token"] as? String, let audit = Data(base64Encoded: auditText),
              audit.count == MemoryLayout<audit_token_t>.size, audit.base64EncodedString() == auditText,
              classes(object["receiver_classes"]),
              let targetPin = object["target"] as? [String: Any], let helperPin = object["helper"] as? [String: Any] else { return false }
        let expectedTarget: [String: Any] = ["bundle_identifier": target.bundleIdentifier ?? "", "executable": target.executablePath,
            "signing_identifier": target.signingIdentifier, "team_identifier": target.teamIdentifier ?? "", "cdhash": target.cdHash]
        let expectedHelper: [String: Any] = ["path": helper.executablePath, "signing_identifier": helper.signingIdentifier,
            "team_identifier": helper.teamIdentifier ?? "", "cdhash": helper.cdHash]
        guard NSDictionary(dictionary: targetPin).isEqual(to: expectedTarget), NSDictionary(dictionary: helperPin).isEqual(to: expectedHelper) else { return false }
        if version == 2 {
            guard classes(object["key_only_receiver_classes"]), classes(object["key_only_window_classes"]) else { return false }

        }
        if let plugin = plugin {
            let expected: [String: Any] = ["bundle_path": plugin.bundlePath ?? "", "executable": plugin.executablePath,
                "bundle_identifier": plugin.bundleIdentifier ?? "", "signing_identifier": plugin.signingIdentifier,
                "team_identifier": plugin.teamIdentifier ?? "", "cdhash": plugin.cdHash]
            guard object["route"] as? String == "textmate_api2_plugin", object["receiver_classes"] as? [String] == ["NSTextView"],
                  let actual = object["plugin"] as? [String: Any], NSDictionary(dictionary: actual).isEqual(to: expected) else { return false }
        }
        if version >= 4 {
            guard NativeProviderTextClientCompatibility.supports(target),
                  object["text_input_client_receiver_classes"] as? [String] == ["OakTextView"],
                  object["text_input_client_window_classes"] as? [String] == ["NSWindow"],
                  object["text_input_client_document_classes"] as? [String] == ["OakDocument"] else { return false }
        }
        return true
    }

    // Kept local to this new store: the existing recovery/preparation helpers
    // are private. Shared factoring belongs to the lead, not this packet.
    private final class Tree {
        private struct Object { let fd: Int32, parent: Int32?, name: String?, initial: stat, privateDirectory: Bool, file: Bool }
        let path: String
        private(set) var root: Int32 = -1
        private var objects: [Object] = []
        init(_ url: URL) throws {
            guard url.isFileURL, let path = NativeProviderRegistration.path(url.path) else { throw NativeProviderRegistrationFailure("native_provider_registration_root_invalid") }
            self.path = path
            let first = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard first >= 0 else { throw NativeProviderRegistrationFailure("native_provider_registration_path_unavailable") }
            do {
                try retain(first, parent: nil, name: nil, privateDirectory: false, file: false)
                var directory = first
                let pieces = path.split(separator: "/")
                for (index, piece) in pieces.enumerated() { directory = try openDirectory(directory, String(piece), privateDirectory: index == pieces.count - 1) }
                root = directory
            } catch { for item in objects.reversed() { close(item.fd) }; objects.removeAll(); throw error }
        }
        deinit { for item in objects.reversed() { close(item.fd) } }
        func child(_ parent: Int32, _ name: String) throws -> Int32 { try openDirectory(parent, name, privateDirectory: true) }
        private func openDirectory(_ parent: Int32, _ name: String, privateDirectory: Bool) throws -> Int32 {
            let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw NativeProviderRegistrationFailure("native_provider_registration_path_unavailable") }
            try retain(fd, parent: parent, name: name, privateDirectory: privateDirectory, file: false)
            return fd
        }
        private func retain(_ fd: Int32, parent: Int32?, name: String?, privateDirectory: Bool, file: Bool) throws {
            var info = stat()
            guard fstat(fd, &info) == 0, safe(fd, info, privateDirectory: privateDirectory, file: file) else {
                close(fd); throw NativeProviderRegistrationFailure("native_provider_registration_file_unsafe")
            }
            objects.append(Object(fd: fd, parent: parent, name: name, initial: info, privateDirectory: privateDirectory, file: file))
        }
        private func safe(_ fd: Int32, _ info: stat, privateDirectory: Bool, file: Bool) -> Bool {
            guard info.st_nlink > 0, info.st_mode & 0o7000 == (file || privateDirectory ? 0 : info.st_mode & S_ISVTX),
                  (file || privateDirectory ? LWProviderHasPrivateACL(fd) : LWProviderHasStableAncestorACL(fd)) else { return false }
            if file { return info.st_mode & S_IFMT == S_IFREG && info.st_uid == geteuid() && info.st_mode & 0o777 == 0o600 && info.st_nlink == 1 }
            guard info.st_mode & S_IFMT == S_IFDIR else { return false }
            if privateDirectory { return info.st_uid == geteuid() && info.st_mode & 0o777 == 0o700 }
            return (info.st_uid == 0 || info.st_uid == geteuid()) &&
                (info.st_mode & 0o022 == 0 || (info.st_uid == 0 && info.st_mode & S_ISVTX != 0))
        }
        func safeFile(_ fd: Int32, size: Int) -> Bool {
            var info = stat()
            return fstat(fd, &info) == 0 && info.st_size == size && safe(fd, info, privateDirectory: false, file: true)
        }
        func fileSnapshot(_ fd: Int32, size: Int) throws -> stat {
            var info = stat()
            guard safeFile(fd, size: size), fstat(fd, &info) == 0 else { throw NativeProviderRegistrationFailure("native_provider_registration_written_file_unsafe") }
            return info
        }
        func matchesFile(_ fd: Int32, bytes: Data) -> Bool {
            var observed = Data(count: bytes.count)
            let complete = observed.withUnsafeMutableBytes { buffer -> Bool in
                var at = 0
                while at < buffer.count {
                    let count = pread(fd, buffer.baseAddress!.advanced(by: at), buffer.count - at, off_t(at))
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { return false }
                    at += count
                }
                return true
            }
            return complete && observed == bytes
        }
        func read(_ directory: Int32, _ name: String, limit: Int, allowEmpty: Bool = false) throws -> Data {
            let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard fd >= 0 else { throw NativeProviderRegistrationFailure("native_provider_registration_file_unavailable") }
            try retain(fd, parent: directory, name: name, privateDirectory: false, file: true)
            let before = objects.last!.initial
            guard before.st_size >= (allowEmpty ? 0 : 1), before.st_size <= limit else { throw NativeProviderRegistrationFailure("native_provider_registration_file_limit") }
            var data = Data(count: Int(before.st_size))
            try data.withUnsafeMutableBytes { buffer in
                var at = 0
                while at < buffer.count {
                    let count = Darwin.read(fd, buffer.baseAddress!.advanced(by: at), buffer.count - at)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw NativeProviderRegistrationFailure("native_provider_registration_read_unknown") }
                    at += count
                }
            }
            var extra: UInt8 = 0
            guard Darwin.read(fd, &extra, 1) == 0 else { throw NativeProviderRegistrationFailure("native_provider_registration_read_unknown") }
            try verify()
            return data
        }
        func flushLastRead(parent: Int32) throws -> Bool {
            guard let file = objects.last, file.file else { throw NativeProviderRegistrationFailure("native_provider_registration_file_unavailable") }
            let durable: Bool
            #if NATIVE_PROVIDER_REGISTRATION_TESTING
            if let flush = NativeProviderRegistration.flushHook { durable = flush(file.fd, parent) }
            else { durable = fcntl(file.fd, F_FULLFSYNC) == 0 && fsync(parent) == 0 }
            #else
            durable = fcntl(file.fd, F_FULLFSYNC) == 0 && fsync(parent) == 0
            #endif
            try verify()
            return durable
        }
        private func same(_ a: stat, _ b: stat, file: Bool) -> Bool {
            // APFS directory link counts include ordinary entries, so our own
            // exclusive create legitimately changes the containing directory.
            // Identity/permissions stay pinned; regular files require one link.
            guard a.st_dev == b.st_dev, a.st_ino == b.st_ino, a.st_mode == b.st_mode, a.st_uid == b.st_uid, a.st_gid == b.st_gid else { return false }
            return !file || (a.st_nlink == b.st_nlink && a.st_size == b.st_size && a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
                a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec)
        }
        func verifyNamedFile(_ directory: Int32, _ name: String, fd: Int32, initial: stat, size: Int) throws {
            var current = stat(), named = stat()
            guard fstat(fd, &current) == 0, safeFile(fd, size: size), fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
                  same(initial, current, file: true), same(initial, named, file: true) else { throw NativeProviderRegistrationFailure("native_provider_registration_file_changed") }
        }
        func verify() throws {
            for item in objects {
                var current = stat()
                guard fstat(item.fd, &current) == 0, same(item.initial, current, file: item.file),
                      safe(item.fd, current, privateDirectory: item.privateDirectory, file: item.file) else { throw NativeProviderRegistrationFailure("native_provider_registration_file_changed") }
                if let parent = item.parent, let name = item.name {
                    var named = stat()
                    guard fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0, same(item.initial, named, file: item.file) else { throw NativeProviderRegistrationFailure("native_provider_registration_path_changed") }
                }
            }
        }
    }
}
