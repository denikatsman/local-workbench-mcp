import Foundation
import Darwin
import CryptoKit
import ReceiverProviderProtocol
import ReceiverProviderFileSecurity

/// Read-only recovery of the original receiver journal, independent of process
/// lifetime. The root must come from local host setup, never a remote packet.
/// No input, socket, process, configuration write or replay authority is used.
enum NativeProviderRecovery {
    private static let recordLimit = 65536
    private static let configLimit = 16384
    private static let ownerKeys: Set<String> = ["claim_id", "owner_session", "runtime_generation", "target_generation", "window_id"]

    /// Admission for other host-managed journals uses the same no-follow
    /// ancestry/UID/mode/ACL contract as the original receiver storage.
    static func validatePrivateDirectory(_ url: URL) throws {
        do { let tree = try PrivateTree(root: url); try tree.verify() }
        catch { throw NativeProviderHostFailure("native_provider_directory_unsafe") }
    }

    /// One immutable inode is shared by the host and every inherited worker
    /// stderr. Close only: LOCK_UN would release the children's ownership too.
    final class ElectronOwnership {
        private let tree: PrivateTree
        private let descriptor: Int32
        private let contextHash: String
        init(root: URL, managed: [String: Any], create: Bool) throws {
            let tree = try PrivateTree(root: root)
            let saved = decode(try tree.read(directory: tree.root, name: "managed.json", limit: recordLimit), limit: recordLimit)
            guard let saved = saved, try electronContextHash(saved) == electronContextHash(managed) else {
                throw NativeProviderHostFailure("native_electron_registration_changed")
            }
            if !create {
                do { _ = try tree.read(directory: tree.root, name: "ownership.json", limit: 4096) }
                catch let failure as ReadFailure where failure.missing {
                    throw NativeProviderHostFailure("native_electron_legacy_registration_unsupported")
                }
            }
            let descriptor = try tree.lockFile(name: "ownership.lock", create: create)
            var info = stat()
            guard fstat(descriptor, &info) == 0 else { throw NativeProviderHostFailure("native_electron_ownership_unsafe") }
            let expected: [String: Any] = ["version": 1, "context_hash": try electronContextHash(managed),
                "lease_device": String(info.st_dev), "lease_inode": String(info.st_ino)]
            if create { try tree.writeNew(name: "ownership.json", data: JSONSerialization.data(withJSONObject: expected, options: [.sortedKeys])) }
            guard let record = decode(try tree.read(directory: tree.root, name: "ownership.json", limit: 4096), limit: 4096),
                  Set(record.keys) == Set(expected.keys), integer(record["version"]) == 1,
                  record["context_hash"] as? String == expected["context_hash"] as? String,
                  record["lease_device"] as? String == expected["lease_device"] as? String,
                  record["lease_inode"] as? String == expected["lease_inode"] as? String else { throw NativeProviderHostFailure("native_electron_ownership_unsafe") }
            try tree.verify()
            self.tree = tree; self.descriptor = descriptor; self.contextHash = try electronContextHash(managed)
        }
        func verify(_ managed: [String: Any]? = nil) throws {
            try tree.verify()
            if let managed = managed, try electronContextHash(managed) != contextHash {
                throw NativeProviderHostFailure("native_electron_registration_changed")
            }
        }
        func inheritedHandle() throws -> FileHandle {
            try verify()
            let copy = fcntl(descriptor, F_DUPFD_CLOEXEC, 3)
            guard copy >= 0 else { throw NativeProviderHostFailure("native_electron_ownership_unavailable") }
            return FileHandle(fileDescriptor: copy, closeOnDealloc: true)
        }
    }

    /// Only fixed local UUID children are considered; this does not import
    /// claims, renderer bindings, windows or once IDs from the old host.
    static func electronRegistration(sessionsRoot: URL, pid: Int32, boot: String,
                                     liveProcess: [String: Any],
                                     home: URL = FileManager.default.homeDirectoryForCurrentUser) throws -> [String: Any]? {
        do {
            let tree = try PrivateTree(root: sessionsRoot)
            var selected: [String: Any]?
            for name in try tree.children() {
                guard UUID(uuidString: name)?.uuidString.lowercased() == name else { continue }
                let child = try tree.child(directory: tree.root, name: name)
                let data: Data
                do { data = try tree.read(directory: child, name: "managed.json", limit: recordLimit) }
                catch let failure as ReadFailure where failure.missing { continue } // Interrupted launch, not a registration.
                guard let managed = decode(data, limit: recordLimit),
                      let process = managed["process"] as? [String: Any], integer(process["pid"]) == Int64(pid) else { continue }
                guard let session = uuid(managed["session_id"]),
                      validElectronManaged(managed, session: session, root: tree.path + "/" + name),
                      managed["user_home"] as? String == home.path,
                      managed["profile_path"] as? String == home.path + "/.local-workbench-code/" + session.replacingOccurrences(of: "-", with: "") else {
                    throw NativeProviderHostFailure("native_electron_saved_configuration_invalid")
                }
                // Historical PID numbers may recur. Only exact current pins
                // compete for this restore; their original records stay intact.
                guard managed["boot_id"] as? String == boot, equal(process, liveProcess) else { continue }
                guard selected == nil else { throw NativeProviderHostFailure("native_electron_registration_ambiguous") }
                selected = managed
            }
            try tree.verify(); return selected
        } catch let failure as ReadFailure where failure.missing { return nil }
        catch let failure as NativeProviderHostFailure { throw failure }
        catch { throw NativeProviderHostFailure("native_electron_registration_unsafe") }
    }

    static func verifyElectronEndpoint(_ managed: [String: Any]) throws {
        guard let profile = managed["profile_path"] as? String, let port = integer(managed["port"]),
              let path = managed["browser_websocket_path"] as? String,
              let data = try readElectronEndpoint(profileRoot: URL(fileURLWithPath: profile)),
              let text = String(data: data, encoding: .utf8),
              text.split(separator: "\n").map(String.init) == [String(port), path] else {
            throw NativeProviderHostFailure("native_electron_endpoint_changed")
        }
    }

    static func electronContextHash(_ managed: [String: Any]) throws -> String {
        var immutable = managed
        immutable.removeValue(forKey: "windows")
        let bytes = try JSONSerialization.data(withJSONObject: immutable, options: [.sortedKeys, .withoutEscapingSlashes])
        return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    /// Code writes its endpoint metadata with 0644 on some versions. The
    /// surrounding owned0700 profile remains mandatory; only this fixed
    /// producer filename admits owner-written, otherwise read-only0644.
    static func readElectronEndpoint(profileRoot: URL) throws -> Data? {
        do {
            let tree = try PrivateTree(root: profileRoot)
            return try tree.read(directory: tree.root, name: "DevToolsActivePort", limit: 1024, producer: true)
        } catch let failure as ReadFailure where failure.missing { return nil }
        catch { throw NativeProviderHostFailure("native_electron_endpoint_file_unsafe") }
    }

    /// The child cannot query macOS ACLs. Before admitting any effect the host
    /// reads the exact original binding and intent through its private-tree
    /// reader and compares them with its immutable registration and packet.
    static func verifyElectronAdmission(managed: [String: Any], method: String, payload: [String: Any],
                                        message: [String: Any]) throws {
        guard let root = path(managed["session_root"]), let profile = path(managed["profile_path"]),
              let bindingID = uuid(payload["binding_id"]), let onceID = uuid(payload["once_id"]),
              let owner = payload["owner"] as? [String: Any] else {
            throw NativeProviderHostFailure("native_electron_authorisation_invalid")
        }
        do {
            try validatePrivateDirectory(URL(fileURLWithPath: profile))
            let tree = try PrivateTree(root: URL(fileURLWithPath: root))
            let context = try electronContextHash(managed)
            let original = decode(try tree.read(directory: tree.root, name: "managed.json", limit: recordLimit), limit: recordLimit)
            let binding = decode(try tree.read(directory: tree.root, name: bindingID.lowercased() + ".binding.json", limit: 262144), limit: 262144)
            let intent = decode(try tree.read(directory: tree.root, name: onceID.lowercased() + ".intent.json", limit: recordLimit), limit: recordLimit)
            guard let original = original, try electronContextHash(original) == context,
                  let binding = binding, let intent = intent,
                  [binding, intent].allSatisfy({ integer($0["version"]) == 1 && $0["binding_id"] as? String == bindingID &&
                    $0["once_id"] as? String == onceID && $0["context_hash"] as? String == context &&
                    ($0["owner"] as? [String: Any]).map({ equal($0, owner) }) == true }),
                  intent["method"] as? String == method, intent["target_id"] as? String == message["target_id"] as? String,
                  binding["target_id"] as? String == message["target_id"] as? String,
                  let window = binding["window"] as? [String: Any],
                  integer(window["cg_window_id"]) == integer(message["cg_window_id"]), integer(message["cg_window_id"]) != nil,
                  window["document_uri"] as? String == message["document_uri"] as? String else {
                throw NativeProviderHostFailure("native_electron_original_admission_changed")
            }
            try tree.verify()
        } catch let failure as NativeProviderHostFailure { throw failure }
        catch { throw NativeProviderHostFailure("native_electron_original_admission_unsafe") }
    }

    /// Existing native receipts may contain larger bounded AX readbacks than
    /// provider records. Preserve their parser/schema while bounding the file
    /// read and enforcing the same private, descriptor-bound storage rules.
    static func readNativeReceipt(operationReceiptsRoot: URL, operationID: String) throws -> Data? {
        guard operationID.range(of: "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", options: .regularExpression) != nil else {
            throw NativeProviderHostFailure("native_provider_receipt_owner_mismatch", effectState: "unknown")
        }
        do {
            let receipts = try PrivateTree(root: operationReceiptsRoot)
            let name = SHA256.hash(data: Data(operationID.utf8)).map { String(format: "%02x", $0) }.joined() + ".json"
            do { return try receipts.read(directory: receipts.root, name: name, limit: 2 * 1024 * 1024) }
            catch let failure as ReadFailure where failure.missing {
                // Absence is authoritative only while the pinned ancestry
                // still names the original private receipt directory.
                try receipts.verify()
                throw failure
            }
        } catch let failure as ReadFailure where failure.missing { return nil }
        catch { throw NativeProviderHostFailure("native_receipt_unavailable", effectState: "unknown") }
    }

    /// One serializer for the pending and completed native operation context.
    /// Keep the historical payload hash encoding unchanged.
    static func nativeReceiptContext(packet: [String: Any]) throws -> [String: Any] {
        let payload = packet.filter { !["token", "request_id", "app_generation", "launch_id", "runtime_generation"].contains($0.key) }
        let bytes = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        return ["operation_id": packet["operation_id"] as? String ?? "",
            "payload_sha256": SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined(),
            "claim_id": packet["claim_id"] as? String ?? "",
            "owner_session": packet["owner_session"] as? String ?? "",
            "runtime_generation": packet["runtime_generation"] as? String ?? "",
            "native_action": packet["action"] as? String ?? "",
            "parameters": payload.filter { !["version", "method", "action", "operation_id"].contains($0.key) }]
    }

    /// Called before the SDK send. Never upgrade an old sidecar on recovery:
    /// its original native payload digest must have been retained at dispatch.
    static func bindPendingContext(record: [String: Any], pending: [String: Any], operationID: String) throws -> [String: Any] {
        guard integer(record["version"]) == 1,
              Set(record.keys) == ["version", "operation_id", "provider_session_id", "owner", "descriptor"],
              record["operation_id"] as? String == operationID,
              pending["operation_id"] as? String == operationID, pending["state"] as? String == "pending",
              pending["effect_state"] as? String == "unknown", pending["result"] == nil,
              let owner = record["owner"] as? [String: Any], Set(owner.keys) == ownerKeys,
              owner.values.allSatisfy({ string($0, limit: 128) }),
              let parameters = pending["parameters"] as? [String: Any],
              ["claim_id", "owner_session", "runtime_generation"].allSatisfy({ pending[$0] as? String == owner[$0] as? String }),
              ["claim_id", "owner_session", "window_id"].allSatisfy({ parameters[$0] as? String == owner[$0] as? String }),
              hash(pending["payload_sha256"]), let action = pending["native_action"] as? String,
              ["key_pair", "key_chord", "key_sequence", "insert_text"].contains(action) else {
            throw NativeProviderHostFailure("native_provider_receipt_owner_mismatch", effectState: "unknown")
        }
        var bound = record
        bound["version"] = 2
        bound["native_payload_sha256"] = pending["payload_sha256"]
        bound["native_action"] = action
        return bound
    }

    /// Production entrypoint: both roots come from local installation setup.
    /// Read the exact original sidecar without following links or allocating
    /// unbounded bytes before the strict record decoder gets control.
    static func recoverStored(providerSessionsRoot: URL, electronSessionsRoot: URL? = nil, operationReceiptsRoot: URL,
                              ownerSession: String, operationID: String,
                              nativeReceipt: [String: Any]? = nil) throws -> [String: Any] {
        guard operationID.range(of: "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", options: .regularExpression) != nil else {
            throw NativeProviderHostFailure("native_provider_receipt_owner_mismatch", effectState: "unknown")
        }
        do {
            let receipts = try PrivateTree(root: operationReceiptsRoot)
            let name = SHA256.hash(data: Data(operationID.utf8)).map { String(format: "%02x", $0) }.joined() + ".json.provider.json"
            let data = try receipts.read(directory: receipts.root, name: name, limit: recordLimit)
            let result: [String: Any]
            if decode(data, limit: recordLimit)?["backend"] as? String == "electron_pointer", let root = electronSessionsRoot {
                result = try recoverElectronPointer(sessionsRoot: root, recordData: data, ownerSession: ownerSession, operationID: operationID)
            } else if decode(data, limit: recordLimit)?["backend"] as? String == "electron_renderer", let root = electronSessionsRoot {
                result = try recoverElectron(sessionsRoot: root, recordData: data, ownerSession: ownerSession, operationID: operationID)
            } else {
                result = try recover(providerSessionsRoot: providerSessionsRoot, recordData: data,
                    ownerSession: ownerSession, operationID: operationID)
            }
            var view: [String: Any] = ["provider_reconciliation": result]
            if let native = nativeReceipt, let record = decode(data, limit: recordLimit),
               integer(record["version"]) == 2, record["backend"] == nil,
               boolean(result["receipt_recovered"]) == true,
               let owner = record["owner"] as? [String: Any],
               native["operation_id"] as? String == operationID,
               native["owner_session"] as? String == ownerSession,
               native["payload_sha256"] as? String == record["native_payload_sha256"] as? String,
               native["native_action"] as? String == record["native_action"] as? String,
               ["claim_id", "runtime_generation"].allSatisfy({ key in
                   native[key] == nil || native[key] as? String == owner[key] as? String
               }),
               (native["parameters"] == nil || (native["parameters"] as? [String: Any]).map({ parameters in
                   ["claim_id", "owner_session", "window_id"].allSatisfy { parameters[$0] as? String == owner[$0] as? String }
               }) == true) {
                var binding = owner
                binding["version"] = 1; binding["source"] = "verified_provider_receipt"
                binding["operation_id"] = operationID
                binding["payload_sha256"] = record["native_payload_sha256"]
                binding["native_action"] = record["native_action"]
                view["historical_binding"] = binding
            }
            try receipts.verify()
            return nativeReceipt == nil ? result : view
        } catch let failure as NativeProviderHostFailure { throw failure }
        catch {
            let result = unknown("native_provider_original_receipt_unavailable_or_unsafe")
            return nativeReceipt == nil ? result : ["provider_reconciliation": result]
        }
    }

    static func validElectronPointerResult(_ value: [String: Any], binding: String, once: String,
                                           operation: String, action: String? = nil,
                                           expectedWindow: UInt32? = nil, expectedTarget: String? = nil,
                                           inputAdmitted: Bool? = nil) -> Bool {
        let keys: Set<String> = ["ready", "binding_id", "once_id", "operation_id", "receiver_kind", "action", "target_id", "window_id",
            "dispatch_attempted", "down_attempted", "down_returned", "up_attempted", "up_returned", "sent_events", "possibly_sent",
            "release_state", "effect_state", "outcome", "retry_allowed", "receipt_durable", "receipt_recovered", "requested_hold_ms",
            "elapsed_hold_ms", "reason", "session_detached"]
        let booleans = ["ready", "dispatch_attempted", "down_attempted", "down_returned", "up_attempted", "up_returned",
            "possibly_sent", "retry_allowed", "receipt_durable", "receipt_recovered", "session_detached"]
        guard Set(value.keys) == keys, value["binding_id"] as? String == binding, value["once_id"] as? String == once,
              value["operation_id"] as? String == operation, value["receiver_kind"] as? String == "electron_renderer_pointer",
              booleans.allSatisfy({ boolean(value[$0]) != nil }), boolean(value["retry_allowed"]) == false,
              let selected = value["action"] as? String, ["click", "double_click", "right_click", "hold", "right_hold", "drag", "scroll"].contains(selected),
              action == nil || selected == action,
              let sent = integer(value["sent_events"]), (0...40).contains(sent),
              let window = integer(value["window_id"]), (1...Int64(Int32.max)).contains(window),
              expectedWindow == nil || window == Int64(expectedWindow!),
              expectedTarget == nil || value["target_id"] as? String == expectedTarget,
              let release = value["release_state"] as? String,
              ["not_eligible", "eligible", "possibly_sent", "acknowledged", "unverified"].contains(release),
              ["none", "unknown"].contains(value["effect_state"] as? String ?? ""),
              string(value["outcome"], limit: 128),
              value["reason"] is NSNull || (value["reason"] as? String).map({ $0.range(of: "^electron_[a-z0-9_]{1,200}$", options: .regularExpression) != nil }) == true else { return false }
        if value["target_id"] is NSNull {
            guard boolean(value["possibly_sent"]) == false, boolean(value["ready"]) == false else { return false }
        } else if !string(value["target_id"], limit: 128) { return false }
        if value["requested_hold_ms"] is NSNull {
            guard !["hold", "right_hold"].contains(selected) else { return false }
        } else {
            guard ["hold", "right_hold"].contains(selected), let hold = integer(value["requested_hold_ms"]), (1...5000).contains(hold) else { return false }
        }
        if !(value["elapsed_hold_ms"] is NSNull) {
            guard ["hold", "right_hold"].contains(selected), let elapsed = finiteClock(value["elapsed_hold_ms"]), elapsed <= 15000 else { return false }
        }
        if boolean(value["possibly_sent"]) == true {
            guard value["effect_state"] as? String == "unknown", boolean(value["dispatch_attempted"]) == true,
                  inputAdmitted != false else { return false }
        } else {
            guard sent == 0, boolean(value["dispatch_attempted"]) == false,
                  boolean(value["down_attempted"]) == false, boolean(value["up_attempted"]) == false,
                  boolean(value["down_returned"]) == false, boolean(value["up_returned"]) == false,
                  release == "not_eligible", value["outcome"] as? String == "not_dispatched",
                  value["effect_state"] as? String == "none" else { return false }
        }
        if release == "acknowledged" { guard boolean(value["up_returned"]) == true else { return false } }
        if boolean(value["down_returned"]) == true && boolean(value["down_attempted"]) != true { return false }
        if boolean(value["up_returned"]) == true && boolean(value["up_attempted"]) != true { return false }
        if boolean(value["ready"]) == true {
            guard boolean(value["session_detached"]) == true, boolean(value["possibly_sent"]) == true, sent > 0,
                  selected == "scroll" ? release == "not_eligible" : release == "acknowledged" else { return false }
        }
        return true
    }

    /// Pointer recovery reads the original private journal after process or
    /// claim loss. It does not reconnect, reconstruct UP or renew authority.
    static func recoverElectronPointer(sessionsRoot: URL, recordData: Data, ownerSession: String,
                                      operationID: String) throws -> [String: Any] {
        guard let record = decode(recordData, limit: recordLimit),
              Set(record.keys) == ["version", "backend", "operation_id", "provider_session_id", "owner", "descriptor", "capture"],
              integer(record["version"]) == 1, record["backend"] as? String == "electron_pointer",
              record["operation_id"] as? String == operationID, string(operationID, limit: 128), string(ownerSession, limit: 128),
              let owner = record["owner"] as? [String: Any], Set(owner.keys) == ownerKeys,
              owner.values.allSatisfy({ string($0, limit: 128) }), owner["owner_session"] as? String == ownerSession,
              let descriptor = record["descriptor"] as? [String: Any], Set(descriptor.keys) == ["owner", "binding_id", "once_id"],
              let savedOwner = descriptor["owner"] as? [String: Any], equal(owner, savedOwner),
              let bindingID = uuid(descriptor["binding_id"]), let onceID = uuid(descriptor["once_id"]),
              let sessionID = uuid(record["provider_session_id"]), let capture = record["capture"] as? [String: Any] else {
            throw NativeProviderHostFailure("native_provider_receipt_owner_mismatch", effectState: "unknown")
        }
        do {
            let tree = try PrivateTree(root: sessionsRoot), directory = try tree.child(directory: tree.root, name: sessionID.lowercased())
            guard let managed = decode(try tree.read(directory: directory, name: "managed.json", limit: recordLimit), limit: recordLimit),
                  validElectronManaged(managed, session: sessionID, root: tree.path + "/" + sessionID.lowercased()) else {
                return unknown("native_electron_saved_configuration_invalid")
            }
            let context = try electronContextHash(managed)
            let binding = decode(try tree.read(directory: directory, name: bindingID.lowercased() + ".pointer-binding.json", limit: 262144), limit: 262144)
            let intent = decode(try tree.read(directory: directory, name: onceID.lowercased() + ".pointer-intent.json", limit: recordLimit), limit: recordLimit)
            let terminal = decode(try tree.read(directory: directory, name: onceID.lowercased() + ".pointer-terminal.json", limit: recordLimit), limit: recordLimit)
            let base: Set<String> = ["version", "pointer_contract", "owner", "context_hash", "boot_id", "binding_id", "once_id", "operation_id",
                "capture_id", "authority_hash", "gesture_hash", "target_id", "window_id", "action"]
            guard let b = binding, let i = intent, let t = terminal,
                  Set(b.keys) == base.union(["payload", "mapping", "observed_node_ns"]),
                  Set(i.keys) == base.union(["release_required", "contract"]),
                  base.allSatisfy({ equalJSON(b[$0], i[$0]) }), integer(b["version"]) == 1, integer(b["pointer_contract"]) == 1,
                  (b["owner"] as? [String: Any]).map({ equal(owner, $0) }) == true,
                  b["context_hash"] as? String == context, b["boot_id"] as? String == managed["boot_id"] as? String,
                  b["binding_id"] as? String == bindingID, b["once_id"] as? String == onceID,
                  b["operation_id"] as? String == operationID, b["capture_id"] as? String == capture["capture_id"] as? String,
                  b["authority_hash"] as? String == capture["authority_hash"] as? String, hash(b["authority_hash"]), hash(b["gesture_hash"]),
                  decimalClock(b["observed_node_ns"]), string(b["target_id"], limit: 128),
                  let selected = b["action"] as? String,
                  let payload = b["payload"] as? [String: Any],
                  Set(payload.keys) == ["pointer_contract", "owner", "binding_id", "once_id", "operation_id", "capture", "mapping", "gesture"],
                  integer(payload["pointer_contract"]) == 1,
                  (payload["owner"] as? [String: Any]).map({ equal(owner, $0) }) == true,
                  payload["binding_id"] as? String == bindingID, payload["once_id"] as? String == onceID,
                  payload["operation_id"] as? String == operationID,
                  let original = payload["capture"] as? [String: Any], equal(original, capture),
                  let gesture = payload["gesture"] as? [String: Any], gesture["action"] as? String == selected,
                  let gestureBytes = try? JSONSerialization.data(withJSONObject: gesture, options: [.sortedKeys, .withoutEscapingSlashes]),
                  SHA256.hash(data: gestureBytes).map({ String(format: "%02x", $0) }).joined() == b["gesture_hash"] as? String,
                  let originalMapping = payload["mapping"] as? [String: Any], let resolvedMapping = b["mapping"] as? [String: Any],
                  originalMapping.allSatisfy({ equalJSON($0.value, resolvedMapping[$0.key]) }),
                  resolvedMapping["target_id"] as? String == b["target_id"] as? String,
                  integer(originalMapping["cg_window_id"]) == integer(b["window_id"]),
                  boolean(i["release_required"]) == (selected != "scroll"),
                  i["contract"] as? String == "missing_terminal_is_unknown_never_replay",
                  Set(t.keys) == ["version", "pointer_contract", "owner", "context_hash", "result"],
                  integer(t["version"]) == 1, integer(t["pointer_contract"]) == 1, t["context_hash"] as? String == context,
                  (t["owner"] as? [String: Any]).map({ equal(owner, $0) }) == true,
                  let result = t["result"] as? [String: Any],
                  validElectronPointerResult(result, binding: bindingID, once: onceID, operation: operationID, action: selected),
                  ["hold", "right_hold"].contains(selected) ? integer(result["requested_hold_ms"]) == integer(gesture["hold_ms"]) : result["requested_hold_ms"] is NSNull,
                  boolean(result["receipt_durable"]) == false, boolean(result["receipt_recovered"]) == false,
                  result["target_id"] as? String == b["target_id"] as? String, integer(result["window_id"]) == integer(b["window_id"]) else {
                return unknown("native_electron_pointer_receipt_inconsistent")
            }
            if boolean(result["possibly_sent"]) == true {
                guard let dispatch = decode(try tree.read(directory: directory, name: onceID.lowercased() + ".pointer-dispatch.json", limit: recordLimit), limit: recordLimit),
                      Set(dispatch.keys) == base.union(["release_required"]), base.allSatisfy({ equalJSON(dispatch[$0], b[$0]) }),
                      boolean(dispatch["release_required"]) == (selected != "scroll") else { return unknown("native_electron_pointer_receipt_inconsistent") }
            }
            if boolean(result["up_returned"]) == true {
                guard let release = decode(try tree.read(directory: directory, name: onceID.lowercased() + ".pointer-release.json", limit: recordLimit), limit: recordLimit),
                      Set(release.keys) == base.union(["session_id", "up_returned", "original_transport"]),
                      base.allSatisfy({ equalJSON(release[$0], b[$0]) }), string(release["session_id"], limit: 128),
                      boolean(release["up_returned"]) == true, boolean(release["original_transport"]) == true else {
                    return unknown("native_electron_pointer_release_unverified")
                }
            }
            try tree.verify()
            var recovered = result
            recovered["receipt_recovered"] = true; recovered["receipt_durable"] = false
            recovered["receipt_read_verified"] = true; recovered["retry_allowed"] = false
            recovered["recovery_source"] = "original_durable_electron_pointer_journal"
            return recovered
        } catch { return unknown("native_electron_pointer_receipt_unavailable_or_unsafe") }
    }

    private static func equalJSON(_ left: Any?, _ right: Any?) -> Bool {
        guard let a = left, let b = right,
              let x = try? JSONSerialization.data(withJSONObject: a, options: [.sortedKeys, .fragmentsAllowed, .withoutEscapingSlashes]),
              let y = try? JSONSerialization.data(withJSONObject: b, options: [.sortedKeys, .fragmentsAllowed, .withoutEscapingSlashes]) else { return false }
        return x == y
    }

    /// Historical renderer receipts need no live Code/host process, endpoint,
    /// observation or current claim. Read only the original local records;
    /// missing intent/terminal or an unsafe record is unknown, never replay.
    static func recoverElectron(sessionsRoot: URL, recordData: Data, ownerSession: String,
                                operationID: String) throws -> [String: Any] {
        guard let record = decode(recordData, limit: recordLimit),
              Set(record.keys) == ["version", "backend", "operation_id", "provider_session_id", "owner", "descriptor"],
              integer(record["version"]) == 1, record["backend"] as? String == "electron_renderer",
              string(operationID, limit: 128), string(ownerSession, limit: 128), record["operation_id"] as? String == operationID,
              let owner = record["owner"] as? [String: Any], Set(owner.keys) == ownerKeys,
              owner.values.allSatisfy({ string($0, limit: 128) }), owner["owner_session"] as? String == ownerSession,
              let descriptor = record["descriptor"] as? [String: Any], Set(descriptor.keys) == ["owner", "binding_id", "once_id"],
              let savedOwner = descriptor["owner"] as? [String: Any], equal(owner, savedOwner),
              let bindingID = uuid(descriptor["binding_id"]), let onceID = uuid(descriptor["once_id"]),
              let sessionID = uuid(record["provider_session_id"]) else {
            throw NativeProviderHostFailure("native_provider_receipt_owner_mismatch", effectState: "unknown")
        }
        do {
            let tree = try PrivateTree(root: sessionsRoot)
            let directory = try tree.child(directory: tree.root, name: sessionID.lowercased())
            guard let managed = decode(try tree.read(directory: directory, name: "managed.json", limit: recordLimit), limit: recordLimit),
                  validElectronManaged(managed, session: sessionID, root: tree.path + "/" + sessionID.lowercased()) else {
                return unknown("native_electron_saved_configuration_invalid")
            }
            let context = try electronContextHash(managed)
            let binding = decode(try tree.read(directory: directory, name: bindingID.lowercased() + ".binding.json", limit: 262144), limit: 262144)
            let intent = decode(try tree.read(directory: directory, name: onceID.lowercased() + ".intent.json", limit: recordLimit), limit: recordLimit)
            guard let binding = binding, let intent = intent,
                  [binding, intent].allSatisfy({ integer($0["version"]) == 1 && $0["context_hash"] as? String == context &&
                    ($0["owner"] as? [String: Any]).map({ equal(owner, $0) }) == true }),
                  Set(binding.keys) == ["version", "owner", "context_hash", "boot_id", "binding_id", "once_id", "window", "target_id", "marker",
                    "frame_id", "loader_id", "dom", "editor_state_hash", "include_text", "observed_host_uptime", "deadline_monotonic", "observed_node_ns"],
                  binding["binding_id"] as? String == bindingID, binding["once_id"] as? String == onceID,
                  binding["boot_id"] as? String == managed["boot_id"] as? String, uuid(binding["marker"]) != nil,
                  hash(binding["editor_state_hash"]), boolean(binding["include_text"]) != nil,
                  string(binding["frame_id"], limit: 128), string(binding["loader_id"], limit: 128), binding["dom"] is [String: Any],
                  decimalClock(binding["observed_node_ns"]), let observed = finiteClock(binding["observed_host_uptime"]),
                  let deadline = finiteClock(binding["deadline_monotonic"]), deadline > observed, deadline <= observed + 30,
                  let window = binding["window"] as? [String: Any],
                  Set(window.keys).isSuperset(of: ["cg_window_id", "native_title", "document_uri"]),
                  Set(window.keys).isSubset(of: ["cg_window_id", "native_title", "document_uri", "target_id"]),
                  let number = integer(window["cg_window_id"]), (1...Int64(Int32.max)).contains(number),
                  string(window["native_title"], limit: 512), let document = window["document_uri"] as? String,
                  document.hasPrefix("file:///"), string(document, limit: 8192), string(binding["target_id"], limit: 128),
                  Set(intent.keys) == Set(["version", "owner", "context_hash", "binding_id", "once_id", "method", "argument_sha256", "target_id",
                    "window_id", "boot_id", "original_node_ns", "contract"]).union(intent.keys.contains("keyboard_release_contract") ? ["keyboard_release_contract"] : []),
                  intent["binding_id"] as? String == bindingID, intent["once_id"] as? String == onceID,
                  intent["target_id"] as? String == binding["target_id"] as? String, integer(intent["window_id"]) == number,
                  intent["boot_id"] as? String == managed["boot_id"] as? String, decimalClock(intent["original_node_ns"]),
                  hash(intent["argument_sha256"]), intent["contract"] as? String == "missing_terminal_is_unknown_never_replay",
                  let method = intent["method"] as? String, ["key_pair", "key_chord", "consume_plain_text"].contains(method),
                  !intent.keys.contains("keyboard_release_contract") ||
                    (integer(intent["keyboard_release_contract"]) == 1 && method != "consume_plain_text") else {
                return unknown("native_electron_original_receipt_inconsistent")
            }
            let terminalData: Data?
            do { terminalData = try tree.read(directory: directory, name: onceID.lowercased() + ".terminal.json", limit: 262144) }
            catch let failure as ReadFailure where failure.missing { terminalData = nil }
            if terminalData == nil {
                // A surviving guardian can finish the original UP after its
                // validation child dies. That proves release only: never create
                // a terminal receipt or infer that the original input succeeded.
                guard integer(intent["keyboard_release_contract"]) == 1 else {
                    return unknown("native_electron_original_receipt_unavailable_or_unsafe")
                }
                _ = try verifyElectronKeyboardRelease(tree: tree, directory: directory, intent: intent,
                    requireDispatch: true, requireRelease: true)
                try tree.verify()
                var recovered = unknown("native_electron_terminal_receipt_unavailable")
                recovered["release_recovered"] = true; recovered["release_read_verified"] = true
                recovered["release_state"] = "acknowledged"; recovered["up_returned"] = true
                recovered["release_recovery_source"] = "original_durable_electron_keyboard_release"
                return recovered
            }
            guard let terminal = decode(terminalData!, limit: 262144),
                  integer(terminal["version"]) == 1, terminal["context_hash"] as? String == context,
                  (terminal["owner"] as? [String: Any]).map({ equal(owner, $0) }) == true,
                  Set(terminal.keys) == ["version", "owner", "context_hash", "result"], let result = terminal["result"] as? [String: Any],
                  validElectronTerminal(result, binding: bindingID, once: onceID, method: method,
                    includeText: boolean(binding["include_text"]) == true) else {
                return unknown("native_electron_original_receipt_inconsistent")
            }
            if integer(intent["keyboard_release_contract"]) == 1 {
                let attempted = boolean(result["dispatch_attempted"]) == true
                let released = try verifyElectronKeyboardRelease(tree: tree, directory: directory, intent: intent,
                    requireDispatch: attempted, requireRelease: boolean(result["up_returned"]) == true)
                guard attempted || !released else { return unknown("native_electron_original_receipt_inconsistent") }
            }
            try tree.verify()
            var recovered = result
            recovered["receipt_recovered"] = true; recovered["receipt_read_verified"] = true
            recovered["receipt_durable"] = false; recovered["retry_allowed"] = false
            recovered["recovery_source"] = "original_durable_electron_journal"
            return recovered
        } catch { return unknown("native_electron_original_receipt_unavailable_or_unsafe") }
    }

    /// Bind the guardian's immutable records to the validated original intent,
    /// including its managed-process context hash and argument digest. No live
    /// endpoint, replacement process or current claim is recovery authority.
    private static func verifyElectronKeyboardRelease(tree: PrivateTree, directory: Int32,
                                                       intent: [String: Any], requireDispatch: Bool,
                                                       requireRelease: Bool) throws -> Bool {
        let once = intent["once_id"] as! String
        let fields: Set<String> = ["version", "owner", "context_hash", "binding_id", "once_id", "method", "target_id", "window_id", "boot_id"]
        func read(_ stage: String) throws -> [String: Any]? {
            do {
                let bytes = try tree.read(directory: directory, name: once.lowercased() + "." + stage + ".json", limit: recordLimit)
                guard let value = decode(bytes, limit: recordLimit) else { throw ReadFailure() }
                return value
            } catch let failure as ReadFailure where failure.missing { return nil }
        }
        let dispatch = try read("keyboard-dispatch"), release = try read("keyboard-release")
        if let dispatch = dispatch {
            guard Set(dispatch.keys) == fields, integer(dispatch["version"]) == 1, integer(dispatch["window_id"]) != nil,
                  fields.allSatisfy({ equalJSON(dispatch[$0], intent[$0]) }) else { throw ReadFailure() }
        } else if requireDispatch || release != nil { throw ReadFailure() }
        if let release = release {
            guard Set(release.keys) == fields.union(["argument_sha256", "session_id", "up_returned", "original_transport"]),
                  integer(release["version"]) == 1, integer(release["window_id"]) != nil,
                  fields.union(["argument_sha256"]).allSatisfy({ equalJSON(release[$0], intent[$0]) }),
                  let session = release["session_id"] as? String,
                  session.range(of: "^[A-Za-z0-9_-]{1,128}$", options: .regularExpression) != nil,
                  boolean(release["up_returned"]) == true, boolean(release["original_transport"]) == true else { throw ReadFailure() }
        } else if requireRelease { throw ReadFailure() }
        return release != nil
    }

    private static func decimalClock(_ value: Any?) -> Bool {
        guard let value = value as? String else { return false }
        return value.range(of: "^[0-9]{1,30}$", options: .regularExpression) != nil
    }
    private static func finiteClock(_ value: Any?) -> Double? {
        guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(), n.doubleValue.isFinite, n.doubleValue >= 0 else { return nil }
        return n.doubleValue
    }
    private static func validElectronManaged(_ managed: [String: Any], session: String, root: String) -> Bool {
        guard Set(managed.keys) == ["session_id", "generation", "boot_id", "user_home", "session_root", "profile_path", "port", "browser_websocket_path", "process"],
              managed["session_id"] as? String == session, uuid(managed["generation"]) != nil, uuid(managed["boot_id"]) != nil,
              managed["session_root"] as? String == root, path(managed["user_home"]) != nil, path(managed["profile_path"]) != nil,
              let port = integer(managed["port"]), (1025...65535).contains(port),
              let endpoint = managed["browser_websocket_path"] as? String,
              endpoint.range(of: "^/devtools/browser/[A-Za-z0-9_-]{1,128}$", options: .regularExpression) != nil,
              let process = managed["process"] as? [String: Any],
              Set(process.keys) == ["pid", "start_seconds", "start_microseconds", "uid", "real_uid", "pid_version", "audit_token_base64", "executable",
                "bundle_identifier", "signing_identifier", "team_identifier", "cdhash", "designated_requirement"],
              let pid = integer(process["pid"]), (1...Int64(Int32.max)).contains(pid),
              let born = integer(process["start_seconds"]), born > 0,
              let micro = integer(process["start_microseconds"]), (0...999999).contains(micro),
              integer(process["uid"]) == Int64(geteuid()), integer(process["real_uid"]) == Int64(geteuid()),
              let version = integer(process["pid_version"]), (Int64(Int32.min)...Int64(Int32.max)).contains(version),
              let tokenString = process["audit_token_base64"] as? String, let token = Data(base64Encoded: tokenString),
              token.count == 32, token.base64EncodedString() == tokenString,
              process["bundle_identifier"] as? String == "com.microsoft.VSCode", process["signing_identifier"] as? String == "com.microsoft.VSCode",
              process["team_identifier"] as? String == "UBF8T346G9", hash(process["cdhash"], minimum: 40, maximum: 128),
              process["executable"] as? String == "/Applications/Visual Studio Code.app/Contents/MacOS/Code",
              string(process["designated_requirement"], limit: 16384) else { return false }
        let audit = token.withUnsafeBytes { Array($0.bindMemory(to: UInt32.self)) }
        return audit[1] == geteuid() && audit[3] == geteuid() && audit[5] == UInt32(pid) && Int32(bitPattern: audit[7]) == Int32(version)
    }
    private static func electronSnapshot(_ value: Any?, includeText: Bool) -> Bool {
        guard let snapshot = value as? [String: Any],
              Set(snapshot.keys) == (includeText ? ["scope", "complete_document", "visible_sha256", "context_sha256", "visible_utf16_units",
                "context_utf16_units", "selection", "renderer_focus", "visible_text", "context_text"] :
                ["scope", "complete_document", "visible_sha256", "context_sha256", "visible_utf16_units", "context_utf16_units", "selection", "renderer_focus"]),
              snapshot["scope"] as? String == "exact_renderer_visible_lines_and_input_context_not_complete_document",
              boolean(snapshot["complete_document"]) == false, boolean(snapshot["renderer_focus"]) != nil else { return false }
        for prefix in ["visible", "context"] {
            if snapshot[prefix + "_sha256"] is NSNull {
                guard snapshot[prefix + "_utf16_units"] is NSNull else { return false }
            } else {
                guard hash(snapshot[prefix + "_sha256"]), let size = integer(snapshot[prefix + "_utf16_units"]), (0...4096).contains(size) else { return false }
            }
            if includeText, !(snapshot[prefix + "_text"] is NSNull) {
                guard let text = snapshot[prefix + "_text"] as? String, text.utf16.count <= 4096, text.utf8.count <= 16384,
                      integer(snapshot[prefix + "_utf16_units"]) == Int64(text.utf16.count) else { return false }
                let bytes = try? JSONSerialization.data(withJSONObject: text, options: [.fragmentsAllowed, .withoutEscapingSlashes])
                guard let bytes = bytes, SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == snapshot[prefix + "_sha256"] as? String else { return false }
            }
        }
        if snapshot["selection"] is NSNull { return true }
        guard let selection = snapshot["selection"] as? [String: Any], Set(selection.keys) == ["start", "end"],
              let start = integer(selection["start"]), let end = integer(selection["end"]), start >= 0, end >= start, end <= Int32.max else { return false }
        return true
    }
    private static func validElectronTerminal(_ result: [String: Any], binding: String, once: String, method: String, includeText: Bool) -> Bool {
        let required: Set<String> = ["ready", "binding_id", "once_id", "receiver_kind", "action", "dispatch_attempted", "down_attempted", "up_attempted",
            "effect_state", "outcome", "retry_allowed", "before", "receipt_durable"]
        let optional: Set<String> = ["down_returned", "up_returned", "cleanup_unknown", "after", "readback_completed", "complete_document_verified", "visible_changed",
            "input_context_changed", "reason", "cleanup_deferred_unknown", "renderer_binding_released", "session_detached"]
        guard Set(result.keys).isSuperset(of: required), Set(result.keys).isSubset(of: required.union(optional)),
              result["binding_id"] as? String == binding, result["once_id"] as? String == once,
              boolean(result["ready"]) == true, result["receiver_kind"] as? String == "electron_renderer", result["action"] as? String == method,
              boolean(result["retry_allowed"]) == false, boolean(result["receipt_durable"]) == false,
              let attempted = boolean(result["dispatch_attempted"]), let down = boolean(result["down_attempted"]), let up = boolean(result["up_attempted"]),
              let outcome = result["outcome"] as? String, let effect = result["effect_state"] as? String,
              electronSnapshot(result["before"], includeText: includeText) else { return false }
        for key in optional.subtracting(["after", "reason"]) where result[key] != nil { guard boolean(result[key]) != nil else { return false } }
        if result["reason"] != nil && !string(result["reason"], limit: 256) { return false }
        guard boolean(result["down_returned"]) != true || down,
              boolean(result["up_returned"]) != true || up else { return false }
        if !attempted { return !down && !up && effect == "none" && outcome == "not_dispatched" && result["after"] == nil }
        guard (method == "consume_plain_text" ? (!down && !up) : (down && up)),
              ["bounded_readback", "unknown_after_attempt", "dispatched_unverified"].contains(outcome) else { return false }
        if effect == "bounded_renderer_readback" {
            return outcome == "bounded_readback" && boolean(result["readback_completed"]) == true && electronSnapshot(result["after"], includeText: includeText) &&
                boolean(result["complete_document_verified"]) == false && boolean(result["cleanup_unknown"]) != true &&
                (method == "consume_plain_text" || boolean(result["up_returned"]) == true)
        }
        return effect == "unknown"
    }

    static func recover(providerSessionsRoot: URL, recordData: Data, ownerSession: String,
                        operationID: String) throws -> [String: Any] {
        guard let record = decode(recordData, limit: recordLimit),
              ((integer(record["version"]) == 1 && Set(record.keys) == ["version", "operation_id", "provider_session_id", "owner", "descriptor"]) ||
               (integer(record["version"]) == 2 && Set(record.keys) == ["version", "operation_id", "provider_session_id", "owner", "descriptor", "native_payload_sha256", "native_action"] &&
                hash(record["native_payload_sha256"]) && ["key_pair", "key_chord", "key_sequence", "insert_text"].contains(record["native_action"] as? String ?? ""))),
              string(operationID, limit: 128), string(ownerSession, limit: 128),
              record["operation_id"] as? String == operationID,
              let owner = record["owner"] as? [String: Any], Set(owner.keys) == ownerKeys,
              owner.values.allSatisfy({ string($0, limit: 128) }), owner["owner_session"] as? String == ownerSession,
              let descriptor = record["descriptor"] as? [String: Any],
              Set(descriptor.keys) == ["owner", "binding_id", "once_id"],
              let savedOwner = descriptor["owner"] as? [String: Any], equal(owner, savedOwner),
              let binding = uuid(descriptor["binding_id"]), let once = uuid(descriptor["once_id"]),
              let session = uuid(record["provider_session_id"]) else {
            throw NativeProviderHostFailure("native_provider_receipt_owner_mismatch", effectState: "unknown")
        }
        do {
            let tree = try PrivateTree(root: providerSessionsRoot)
            let sessionDirectory = try tree.child(directory: tree.root, name: session.lowercased())
            let bootstrap = try tree.read(directory: sessionDirectory, name: "bootstrap.json", limit: configLimit)
            guard let config = decode(bootstrap, limit: configLimit),
                  validConfig(config, session: session, journalPath: tree.path + "/" + session.lowercased() + "/journal") else {
                return unknown("native_provider_saved_configuration_invalid")
            }
            let pluginRoute = [3, 4, 5, 6, 7, 8].contains(integer(config["version"]) ?? 0)
            if pluginRoute && !currentPluginParticipants(config) {
                return unknown("native_provider_saved_plugin_identity_unverified")
            }
            // The config path is compared, never followed. All actual reads
            // use fixed names under the locally selected descriptor ancestry.
            let journal = try tree.child(directory: sessionDirectory, name: "journal")
            let intentData = try tree.read(directory: journal, name: once.lowercased() + ".intent.json", limit: recordLimit)
            let resultData = try tree.read(directory: journal, name: once.lowercased() + ".result.json", limit: recordLimit)
            guard let intent = envelope(intentData, stage: "intent", owner: owner, binding: binding, once: once),
                  let result = envelope(resultData, stage: "result", owner: owner, binding: binding, once: once),
                  consistent(intent: intent, result: result, configVersion: integer(config["version"])!),
                  integer(record["version"]) != 2 || intent["action"] as? String ==
                    ((record["native_action"] as? String == "insert_text") ? "literal_plaintext_consume" : record["native_action"] as? String) else {
                return unknown("native_provider_original_receipt_inconsistent")
            }
            // Recheck every retained object and its original directory entry
            // after parsing/reconciliation, including the bootstrap and intent.
            try tree.verify()
            if pluginRoute && !currentPluginParticipants(config) {
                return unknown("native_provider_saved_plugin_identity_unverified")
            }
            var recovered = result
            recovered["receipt_recovered"] = true
            recovered["receipt_read_verified"] = true
            recovered["recovery_source"] = "original_durable_provider_journal"
            recovered["retry_allowed"] = false
            // The terminal record intentionally omits its historical flush
            // result. A verified read cannot reconstruct receipt_durable.
            return recovered
        } catch {
            return unknown("native_provider_original_receipt_unavailable_or_unsafe")
        }
    }

    /// For already decoded host-private records. Use recordData when the raw
    /// retained bytes are available so duplicate keys cannot be lost upstream.
    static func recover(providerSessionsRoot: URL, record: [String: Any], ownerSession: String,
                        operationID: String) throws -> [String: Any] {
        guard JSONSerialization.isValidJSONObject(record),
              let bytes = try? JSONSerialization.data(withJSONObject: record), bytes.count <= recordLimit else {
            throw NativeProviderHostFailure("native_provider_receipt_owner_mismatch", effectState: "unknown")
        }
        return try recover(providerSessionsRoot: providerSessionsRoot, recordData: bytes,
                           ownerSession: ownerSession, operationID: operationID)
    }

    private static func unknown(_ reason: String) -> [String: Any] {
        ["receipt_recovered": false, "effect_state": "unknown", "reason": reason, "retry_allowed": false]
    }
    private static func decode(_ data: Data, limit: Int) -> [String: Any]? {
        guard !data.isEmpty, data.count <= limit else { return nil }
        return LWProviderDecodeJSON(data, nil) as? [String: Any]
    }
    private static func string(_ value: Any?, limit: Int) -> Bool {
        guard let value = value as? String else { return false }
        return !value.isEmpty && value.utf8.count <= limit && !value.utf8.contains(0)
    }
    private static func uuid(_ value: Any?) -> String? {
        guard let value = value as? String, value.utf8.count == 36, UUID(uuidString: value) != nil else { return nil }
        return value
    }
    private static func integer(_ value: Any?) -> Int64? {
        guard let value = value as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(), !CFNumberIsFloatType(value) else { return nil }
        return value.int64Value
    }
    private static func boolean(_ value: Any?) -> Bool? {
        guard let value = value as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID() else { return nil }
        return value.boolValue
    }
    private static func producerFlag(_ value: Any?) -> Bool? {
        if let flag = boolean(value) { return flag }
        // ReceiverCore's @(!BOOL) expressions historically serialize as
        // integers. Only known producer diagnostics accept exact integer 0/1;
        // never coerce dispatch, intent durability or readback authority.
        guard let number = integer(value), number == 0 || number == 1 else { return nil }
        return number == 1
    }
    private static func equal(_ first: [String: Any], _ second: [String: Any]) -> Bool {
        NSDictionary(dictionary: first).isEqual(to: second)
    }
    private static func path(_ value: Any?) -> String? {
        guard let value = value as? String, string(value, limit: 4096), value.hasPrefix("/"),
              value.split(separator: "/", omittingEmptySubsequences: false).dropFirst().allSatisfy({
                  !$0.isEmpty && $0 != "." && $0 != ".."
              }) else { return nil }
        return value
    }
    private static func hash(_ value: Any?, minimum: Int = 64, maximum: Int = 64) -> Bool {
        guard let value = value as? String, (minimum...maximum).contains(value.utf8.count), value.utf8.count % 2 == 0 else { return false }
        return value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    private static func pin(_ value: Any?, target: Bool) -> Bool {
        guard let value = value as? [String: Any], Set(value.keys) == (target ?
            ["bundle_identifier", "executable", "signing_identifier", "team_identifier", "cdhash"] :
            ["path", "signing_identifier", "team_identifier", "cdhash"]) else { return false }
        return path(value[target ? "executable" : "path"]) != nil &&
            (!target || string(value["bundle_identifier"], limit: 512)) &&
            string(value["signing_identifier"], limit: 512) && string(value["team_identifier"], limit: 128) &&
            hash(value["cdhash"], minimum: 40, maximum: 128)
    }
    private static func validConfig(_ value: [String: Any], session: String, journalPath: String) -> Bool {
        guard let version = integer(value["version"]), [1, 3, 4, 5, 6, 7, 8].contains(version) else { return false }
        // Retain existing v2 refusal; plugin compatibility is a distinct route.
        var keys: Set<String> = ["version", "socket_path", "journal_path", "token", "session", "generation",
                                "host_audit_token", "target", "helper", "receiver_classes"]
        if version >= 3 { keys.formUnion(["route", "plugin"]) }
        if version >= 4 { keys.formUnion(["text_input_client_receiver_classes", "text_input_client_window_classes", "text_input_client_document_classes"]) }
        if version >= 5 { keys.insert("text_input_context_keys") }
        guard version < 5 || boolean(value["text_input_context_keys"]) == true else { return false }
        if version >= 6 { keys.insert("text_input_context_shift") }
        guard version < 6 || boolean(value["text_input_context_shift"]) == true else { return false }
        if version >= 7 { keys.insert("text_input_context_control_option") }
        guard version < 7 || boolean(value["text_input_context_control_option"]) == true else { return false }
        if version == 8 { keys.insert("text_input_context_receiver_key_up") }
        guard version != 8 || boolean(value["text_input_context_receiver_key_up"]) == true else { return false }
        guard Set(value.keys) == keys, value["session"] as? String == session,
              uuid(value["generation"]) != nil, value["journal_path"] as? String == journalPath,
              let socket = path(value["socket_path"]), socket.utf8.count < 104,
              hash(value["token"]), let auditString = value["host_audit_token"] as? String,
              let audit = Data(base64Encoded: auditString), audit.count == MemoryLayout<audit_token_t>.size,
              audit.base64EncodedString() == auditString, pin(value["target"], target: true), pin(value["helper"], target: false),
              let classes = value["receiver_classes"] as? [String], !classes.isEmpty, classes.count <= 32,
              Set(classes).count == classes.count, classes.allSatisfy({
                  $0.range(of: "^[A-Za-z_][A-Za-z0-9_]{0,127}$", options: .regularExpression) != nil
              }) else { return false }
        if version >= 3 {
            guard value["route"] as? String == "textmate_api2_plugin", classes == ["NSTextView"],
                  let plugin = value["plugin"] as? [String: Any],
                  Set(plugin.keys) == ["bundle_path", "executable", "bundle_identifier", "signing_identifier", "team_identifier", "cdhash"],
                  let bundle = path(plugin["bundle_path"]), bundle.hasSuffix(".tmplugin"),
                  let executable = path(plugin["executable"]), executable.hasPrefix(bundle + "/Contents/MacOS/"),
                  plugin["bundle_identifier"] as? String == "tools.localworkbench.textmate.receiver",
                  plugin["signing_identifier"] as? String == "tools.localworkbench.textmate.receiver",
                  string(plugin["team_identifier"], limit: 128), hash(plugin["cdhash"], minimum: 40, maximum: 128),
                  let target = value["target"] as? [String: Any], let helper = value["helper"] as? [String: Any],
                  target["bundle_identifier"] as? String == "com.macromates.TextMate",
                  target["signing_identifier"] as? String == "com.macromates.TextMate",
                  target["team_identifier"] as? String == "45TL96F76G",
                  plugin["team_identifier"] as? String == helper["team_identifier"] as? String else { return false }
            if version >= 4 {
                guard target["cdhash"] as? String == NativeProviderTextClientCompatibility.textMateCDHash,
                      value["text_input_client_receiver_classes"] as? [String] == ["OakTextView"],
                      value["text_input_client_window_classes"] as? [String] == ["NSWindow"],
                      value["text_input_client_document_classes"] as? [String] == ["OakDocument"] else { return false }
            }
        }
        return true
    }
    // Current static code authenticity qualifies only this saved record. No PID,
    // mapped-image, socket, relaunch/rebind or input authority can be inferred.
    // Live original-host validation remains NativeProviderRuntime's responsibility.
    private static func currentPluginParticipants(_ config: [String: Any]) -> Bool {
        guard let targetPin = config["target"] as? [String: Any], let targetPath = targetPin["executable"] as? String,
              targetPath.hasSuffix("/Contents/MacOS/TextMate"),
              let helperPin = config["helper"] as? [String: Any], let helperPath = helperPin["path"] as? String,
              let pluginPin = config["plugin"] as? [String: Any], let pluginPath = pluginPin["bundle_path"] as? String else { return false }
        do {
            let inspector = NativeProviderAdmissionInspector()
            let bundle = String(targetPath.dropLast("/Contents/MacOS/TextMate".count))
            let target = try inspector.inspectTarget(bundlePath: bundle, expectedBundleID: "com.macromates.TextMate", expectedExecutable: targetPath)
            let helper = try inspector.inspectHelper(executablePath: helperPath)
            let plugin = try inspector.inspectPlugin(bundlePath: pluginPath, expectedBundleID: "tools.localworkbench.textmate.receiver",
                                                      expectedExecutable: pluginPin["executable"] as? String)
            let actualTarget: [String: Any] = ["bundle_identifier": target.bundleIdentifier ?? "", "executable": target.executablePath,
                "signing_identifier": target.signingIdentifier, "team_identifier": target.teamIdentifier ?? "", "cdhash": target.cdHash]
            let actualHelper: [String: Any] = ["path": helper.executablePath, "signing_identifier": helper.signingIdentifier,
                "team_identifier": helper.teamIdentifier ?? "", "cdhash": helper.cdHash]
            let actualPlugin: [String: Any] = ["bundle_path": plugin.bundlePath ?? "", "executable": plugin.executablePath,
                "bundle_identifier": plugin.bundleIdentifier ?? "", "signing_identifier": plugin.signingIdentifier,
                "team_identifier": plugin.teamIdentifier ?? "", "cdhash": plugin.cdHash]
            return equal(targetPin, actualTarget) && equal(helperPin, actualHelper) && equal(pluginPin, actualPlugin) &&
                NativeProviderAdmissionPolicy.evaluateTextMatePlugin(target: target, helper: helper, plugin: plugin).state == .eligibleForLaunchTrial &&
                ((integer(config["version"]) ?? 0) < 4 || NativeProviderTextClientCompatibility.supports(target))
        } catch { return false }
    }
    private static func envelope(_ data: Data, stage: String, owner: [String: Any], binding: String, once: String) -> [String: Any]? {
        guard let value = decode(data, limit: recordLimit),
              Set(value.keys) == ["owner", "binding_id", "once_id", "stage", "result"],
              let savedOwner = value["owner"] as? [String: Any], equal(owner, savedOwner),
              value["binding_id"] as? String == binding, value["once_id"] as? String == once,
              value["stage"] as? String == stage, let result = value["result"] as? [String: Any],
              result["binding_id"] as? String == binding, result["once_id"] as? String == once else { return nil }
        return result
    }
    private static func textSnapshot(_ value: Any?, textClient: Bool = false) -> [String: Any]? {
        var keys: Set<String> = ["length_utf16", "bytes_utf8", "text_sha256", "selection_location", "selection_length", "text_selection_sha256"]
        if textClient { keys.insert("selection_string") }
        guard let value = value as? [String: Any], Set(value.keys) == keys,
              let length = integer(value["length_utf16"]), (0...65536).contains(length),
              let bytes = integer(value["bytes_utf8"]), (0...262144).contains(bytes),
              let location = integer(value["selection_location"]), (0...length).contains(location),
              let selection = integer(value["selection_length"]), (0...(length - location)).contains(selection),
              hash(value["text_sha256"]), hash(value["text_selection_sha256"]) else { return nil }
        if textClient {
            guard length <= 4096, bytes <= 16384, let selectionString = value["selection_string"] as? String,
                  string(selectionString, limit: 128) else { return nil }
            let position = "[1-9][0-9]{0,4}(?::[1-9][0-9]{0,4})?"
            let grammar = selection == 0 ? "^" + position + "$" : "^" + position + "-" + position + "$"
            guard selectionString.range(of: grammar, options: .regularExpression) != nil else { return nil }
            for endpoint in selectionString.split(separator: "-") {
                let parts = endpoint.split(separator: ":")
                guard let line = Int64(parts[0]), line <= length + 1 else { return nil }
                if parts.count == 2 {
                    guard let column = Int64(parts[1]), column >= 2, column <= bytes + 1 else { return nil }
                }
            }
        }
        return value
    }
    private static func consistent(intent: [String: Any], result: [String: Any], configVersion: Int64 = 1) -> Bool {
        // New sequence schema only; legacy receipt parsing/recovery is unchanged.
        if intent["action"] as? String == "key_sequence" {
            return configVersion == 8 && NativeProviderKeySequence.validIntent(intent, result: result) &&
                textSnapshot(intent["before"], textClient: true) != nil &&
                (result["before"] == nil || NSDictionary(dictionary: result["before"] as? [String: Any] ?? [:]).isEqual(to: intent["before"] as? [String: Any] ?? [:])) &&
                (result["after"] == nil || textSnapshot(result["after"], textClient: true) != nil)
        }
        let textClient = configVersion >= 4 && intent["receiver_kind"] as? String == "custom_text_input_client" &&
            result["receiver_kind"] as? String == "custom_text_input_client"
        let keyAction = ["key_pair", "key_chord"].contains(intent["action"] as? String ?? "")
        let chord = intent["action"] as? String == "key_chord"
        let contextKeys = textClient && configVersion >= 5 && keyAction
        let receiverKeyUp = contextKeys && configVersion == 8
        if chord {
            guard textClient, [6, 7, 8].contains(configVersion), let modifiers=intent["modifiers"] as? [String],
                  modifiers.count == 1, (configVersion >= 7 ? ["shift", "control", "option"] : ["shift"]).contains(modifiers[0]),
                  result["modifiers"] as? [String] == modifiers else { return false }
        }
        if configVersion >= 3 && (intent["receiver_kind"] == nil || result["receiver_kind"] == nil) { return false }
        guard let action = intent["action"] as? String, ["key_pair", "key_chord", "literal_plaintext_consume"].contains(action),
              result["action"] as? String == action,
              intent["contract"] as? String == "missing_terminal_result_is_unknown_never_replay",
              let observed = intent["observed_monotonic"] as? NSNumber, CFGetTypeID(observed) != CFBooleanGetTypeID(),
              observed.doubleValue.isFinite, observed.doubleValue >= 0,
              let deadline = intent["deadline_monotonic"] as? NSNumber, CFGetTypeID(deadline) != CFBooleanGetTypeID(),
              deadline.doubleValue.isFinite, deadline.doubleValue > observed.doubleValue,
              let state = intent["state"] as? [String: Any], let window = integer(state["window_id"]), window > 0, window <= Int32.max,
              let before = textSnapshot(intent["before"], textClient: textClient), result["receipt_state"] as? String == "terminal_result",
              boolean(result["intent_durable"]) == true,
              let attempted = boolean(result["dispatch_attempted"]), let readback = boolean(result["readback_completed"]),
              let outcome = result["outcome"] as? String, let effect = result["effect_state"] as? String else { return false }
        let baseIntent: Set<String> = ["binding_id", "once_id", "action", "observed_monotonic", "deadline_monotonic", "state", "before", "contract"]
        var actionIntent: Set<String> = keyAction ? ["key_code", "characters_sha256", "characters_ignoring_modifiers_sha256"] :
            ["payload_bytes", "payload_sha256", "board_name", "board_generation", "board_types"]
        if chord { actionIntent.insert("modifiers") }
        if contextKeys {
            actionIntent.insert("key_pair_route")
            guard intent["key_pair_route"] as? String == "exact_view_input_context",
                  result["key_pair_route"] as? String == "exact_view_input_context" else { return false }
        }
        if receiverKeyUp {
            actionIntent.insert("key_up_route")
            guard intent["key_up_route"] as? String == "original_receiver_key_up",
                  result["key_up_route"] as? String == "original_receiver_key_up" else { return false }
        }
        let receiverKeys: Set<String> = (intent["receiver_kind"] != nil || result["receiver_kind"] != nil) ? ["receiver_kind"] : []
        if !receiverKeys.isEmpty {
            // The current original typed producer added its explicit kind.
            // Preserve legacy records; do not admit custom/unknown kinds as
            // proof of a typed text snapshot.
            if textClient {
                guard (action == "literal_plaintext_consume" || contextKeys), state["receiver_kind"] as? String == "custom_text_input_client",
                      result["consumer_returned_bool"] is NSNull else { return false }
            } else {
                guard intent["receiver_kind"] as? String == "typed_text_view",
                      result["receiver_kind"] as? String == "typed_text_view" else { return false }
            }
        }
        guard Set(intent.keys) == baseIntent.union(actionIntent).union(receiverKeys) else { return false }
        if keyAction {
            guard let code = integer(intent["key_code"]), (0...127).contains(code), !(54...63).contains(code),
                  hash(intent["characters_sha256"]), hash(intent["characters_ignoring_modifiers_sha256"]) else { return false }
        } else {
            guard let bytes = integer(intent["payload_bytes"]), (0...16384).contains(bytes), hash(intent["payload_sha256"]),
                  string(intent["board_name"], limit: 512), let generation = integer(intent["board_generation"]), generation >= 0,
                  intent["board_types"] is [String: Any] else { return false }
        }
        let required: Set<String> = ["binding_id", "once_id", "receipt_state", "action", "outcome", "effect_state", "dispatch_attempted",
            "down_attempted", "up_attempted", "intent_durable", "readback_completed", "consumer_returned_bool", "exact_plaintext_replacement",
            "own_board_release_requested", "cleanup_deferred_unknown_board"]
        var optional: Set<String> = ["reason", "before", "after", "text_changed", "after_observations", "down_returned", "up_returned", "receiver_kind"]
        if textClient { optional.formUnion(["literal_insert_returned", "exact_plaintext_selection", "sampled_focus_unchanged", "focus_evidence"]) }
        if chord { optional.insert("modifiers") }
        if contextKeys { optional.formUnion(["key_pair_route", "input_context_down_consumed",
            "sampled_input_context_unchanged", "input_context_evidence"]) }
        if contextKeys { optional.insert(receiverKeyUp ? "key_up_route" : "input_context_up_consumed") }
        if textClient && result["literal_insert_returned"] != nil && (!attempted || boolean(result["literal_insert_returned"]) != true) { return false }
        guard required.isSubset(of: Set(result.keys)), Set(result.keys).isSubset(of: required.union(optional)),
              ["down_attempted", "up_attempted", "own_board_release_requested"].allSatisfy({ boolean(result[$0]) != nil }),
              producerFlag(result["cleanup_deferred_unknown_board"]) != nil,
              ["consumer_returned_bool", "exact_plaintext_replacement"].allSatisfy({ result[$0] is NSNull || boolean(result[$0]) != nil }) else { return false }
        if let reason = result["reason"] {
            // A journal cannot inject a private path/token as a public reason.
            let reasons = ["bounded_explicit_input_refused", "original_authority_affiliation_or_text_changed",
                "replacement_readback_size_refused", "replacement_encoding_refused", "unique_private_board_unavailable",
                "owned_board_lease_unverified", "paired_event_factory_refused", "intent_journal_unconfirmed_never_replay",
                "last_state_lease_or_atomic_authority_refused", "original_deadline_or_monotonic_clock_refused",
                "bounded_readback_unavailable", "receiver_or_postcheck_exception", "intent_journal_exception_never_replay", "pre_effect_exception"]
            guard let reason = reason as? String, reasons.contains(reason) ||
                (configVersion >= 5 && textClient && reason == "input_context_changed_before_dispatch" &&
                    !attempted && !readback && outcome == "not_dispatched" && effect == "none") else { return false }
        }
        if let saved = result["before"] { guard let saved = textSnapshot(saved, textClient: textClient), equal(before, saved) else { return false } }
        if keyAction {
            guard boolean(result["down_returned"]) != nil, boolean(result["up_returned"]) != nil,
                  boolean(result["down_attempted"]) == attempted, boolean(result["up_attempted"]) == attempted,
                  attempted || (boolean(result["down_returned"]) == false && boolean(result["up_returned"]) == false),
                  result["consumer_returned_bool"] is NSNull, result["exact_plaintext_replacement"] is NSNull else { return false }
            if contextKeys {
                guard result["literal_insert_returned"] == nil, result["exact_plaintext_selection"] == nil else { return false }
                for direction in (receiverKeyUp ? ["down"] : ["down", "up"]) {
                    let consumed = result["input_context_" + direction + "_consumed"]
                    guard boolean(result[direction + "_returned"]) == true ? boolean(consumed) != nil : consumed == nil else { return false }
                }
            }
        } else {
            guard result["down_returned"] == nil, result["up_returned"] == nil,
                  boolean(result["down_attempted"]) == false, boolean(result["up_attempted"]) == false,
                  attempted || result["consumer_returned_bool"] is NSNull else { return false }
        }
        if readback {
            guard attempted, outcome == "bounded_readback", effect == "bounded_text_readback", result["before"] != nil,
                  textSnapshot(result["after"], textClient: textClient) != nil, producerFlag(result["text_changed"]) != nil,
                  let observations = result["after_observations"] as? [String: Any],
                  Set(observations.keys) == ["app_active", "window_key", "window_main"],
                  observations.values.allSatisfy({ boolean($0) != nil }),
                  action != "literal_plaintext_consume" || (boolean(result["exact_plaintext_replacement"]) != nil &&
                      (textClient ? result["consumer_returned_bool"] is NSNull : boolean(result["consumer_returned_bool"]) != nil)) else { return false }
            if textClient {
                guard boolean(result["sampled_focus_unchanged"]) != nil,
                      result["focus_evidence"] as? String == "app_and_window_samples_only" else { return false }
                if contextKeys {
                    guard boolean(result["down_returned"]) == true, boolean(result["up_returned"]) == true,
                          boolean(result["sampled_input_context_unchanged"]) == true,
                          result["input_context_evidence"] as? String == "exact_view_and_current_context_client_samples_only" else { return false }
                } else {
                    guard boolean(result["literal_insert_returned"]) == true,
                          producerFlag(result["exact_plaintext_selection"]) != nil else { return false }
                }
            }
        } else {
            if textClient && ["exact_plaintext_selection", "sampled_focus_unchanged", "focus_evidence",
                "sampled_input_context_unchanged", "input_context_evidence"].contains(where: { result[$0] != nil }) { return false }
            guard result["before"] == nil, result["after"] == nil, result["text_changed"] == nil, result["after_observations"] == nil,
                  result["exact_plaintext_replacement"] is NSNull,
                  attempted ? (outcome == "unknown_after_attempt" && effect == "unknown") : (outcome == "not_dispatched" && effect == "none") else { return false }
        }
        return true
    }

    private struct ReadFailure: Error { var missing = false }
    /// Descriptor-relative ancestry stays open until all records are reconciled.
    /// No realpath/symlink resolution and no path supplied by JSON is opened.
    private final class PrivateTree {
        private struct Object {
            let fd: Int32, parent: Int32?, name: String?, initial: stat, privateDirectory: Bool, file: Bool, producer: Bool
        }
        let path: String
        private(set) var root: Int32 = -1
        private var objects: [Object] = []
        init(root url: URL) throws {
            guard url.isFileURL, let path = NativeProviderRecovery.path(url.path) else { throw ReadFailure() }
            self.path = path
            let first = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard first >= 0 else { throw ReadFailure(missing: errno == ENOENT) }
            do {
                try retain(first, parent: nil, name: nil, privateDirectory: false, file: false)
                var directory = first
                let components = path.split(separator: "/")
                for (index, component) in components.enumerated() {
                    directory = try openDirectory(parent: directory, name: String(component), privateDirectory: index == components.count - 1)
                }
                root = directory
            } catch {
                for item in objects.reversed() { close(item.fd) }
                objects.removeAll()
                throw error
            }
        }
        deinit { for item in objects.reversed() { close(item.fd) } }
        func child(directory: Int32, name: String) throws -> Int32 {
            try openDirectory(parent: directory, name: name, privateDirectory: true)
        }
        private func openDirectory(parent: Int32, name: String, privateDirectory: Bool) throws -> Int32 {
            let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw ReadFailure(missing: errno == ENOENT) }
            try retain(fd, parent: parent, name: name, privateDirectory: privateDirectory, file: false)
            return fd
        }
        private func retain(_ fd: Int32, parent: Int32?, name: String?, privateDirectory: Bool, file: Bool, producer: Bool = false) throws {
            var info = stat()
            guard fstat(fd, &info) == 0, safe(fd, info, privateDirectory: privateDirectory, file: file, producer: producer) else {
                close(fd); throw ReadFailure()
            }
            objects.append(Object(fd: fd, parent: parent, name: name, initial: info, privateDirectory: privateDirectory, file: file, producer: producer))
        }
        private func safe(_ fd: Int32, _ info: stat, privateDirectory: Bool, file: Bool, producer: Bool = false) -> Bool {
            guard info.st_nlink > 0, info.st_mode & 0o7000 == (file || privateDirectory ? 0 : info.st_mode & S_ISVTX),
                  (file || privateDirectory ? LWProviderHasPrivateACL(fd) : LWProviderHasStableAncestorACL(fd)) else { return false }
            if file {
                return info.st_mode & S_IFMT == S_IFREG && info.st_uid == geteuid() &&
                    (info.st_mode & 0o777 == 0o600 || (producer && info.st_mode & 0o777 == 0o644)) && info.st_nlink == 1
            }
            guard info.st_mode & S_IFMT == S_IFDIR else { return false }
            if privateDirectory { return info.st_uid == geteuid() && info.st_mode & 0o777 == 0o700 }
            // System ancestry may be readable, but may not be replaced by
            // another user. Root-owned sticky temporary ancestors are valid.
            return (info.st_uid == 0 || info.st_uid == geteuid()) &&
                (info.st_mode & 0o022 == 0 || (info.st_uid == 0 && info.st_mode & S_ISVTX != 0))
        }
        func children() throws -> [String] {
            let copy = fcntl(root, F_DUPFD_CLOEXEC, 3)
            guard copy >= 0, let directory = fdopendir(copy) else { if copy >= 0 { close(copy) }; throw ReadFailure() }
            defer { closedir(directory) }
            var names: [String] = []
            while true {
                errno = 0
                guard let entry = readdir(directory) else { guard errno == 0 else { throw ReadFailure() }; break }
                let name = withUnsafePointer(to: &entry.pointee.d_name) {
                    $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
                }
                if name == "." || name == ".." { continue }
                guard names.count < 128 else { throw ReadFailure() }
                names.append(name)
            }
            try verify(); return names.sorted()
        }
        func lockFile(name: String, create: Bool) throws -> Int32 {
            let fd = openat(root, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC | (create ? O_CREAT | O_EXCL : 0), 0o600)
            guard fd >= 0 else { throw ReadFailure() }
            try retain(fd, parent: root, name: name, privateDirectory: false, file: true)
            guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw NativeProviderHostFailure("native_electron_owner_active") }
            try verify(); return fd
        }
        func writeNew(name: String, data: Data) throws {
            let fd = openat(root, name, O_WRONLY | O_CREAT | O_EXCL | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw ReadFailure() }
            defer { close(fd) }
            var info = stat()
            guard fstat(fd, &info) == 0, safe(fd, info, privateDirectory: false, file: true) else { throw ReadFailure() }
            try data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw ReadFailure() }; offset += count
                }
            }
            guard fsync(fd) == 0, fsync(root) == 0 else { throw ReadFailure() }
            try verify()
        }
        func read(directory: Int32, name: String, limit: Int, producer: Bool = false) throws -> Data {
            let fd = openat(directory, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw ReadFailure(missing: errno == ENOENT) }
            try retain(fd, parent: directory, name: name, privateDirectory: false, file: true, producer: producer)
            let before = objects.last!.initial
            guard before.st_size > 0, before.st_size <= limit else { throw ReadFailure() }
            var data = Data(count: Int(before.st_size))
            try data.withUnsafeMutableBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let count = Darwin.read(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw ReadFailure() }
                    offset += count
                }
            }
            var extra: UInt8 = 0
            guard Darwin.read(fd, &extra, 1) == 0 else { throw ReadFailure() }
            try verify()
            return data
        }
        private func same(_ first: stat, _ second: stat, file: Bool) -> Bool {
            guard first.st_dev == second.st_dev, first.st_ino == second.st_ino, first.st_mode == second.st_mode,
                  first.st_uid == second.st_uid, first.st_gid == second.st_gid,
                  (!file || first.st_nlink == second.st_nlink) else { return false }
            // Unrelated journal/sibling creation changes directory link counts,
            // not authority over pinned entries. Identity/access checks remain
            // exact; every regular file retains its original single-link pin.
            return !file || (first.st_size == second.st_size && first.st_mtimespec.tv_sec == second.st_mtimespec.tv_sec &&
                first.st_mtimespec.tv_nsec == second.st_mtimespec.tv_nsec && first.st_ctimespec.tv_sec == second.st_ctimespec.tv_sec &&
                first.st_ctimespec.tv_nsec == second.st_ctimespec.tv_nsec)
        }
        func verify() throws {
            for item in objects {
                var current = stat()
                guard fstat(item.fd, &current) == 0, same(item.initial, current, file: item.file),
                      safe(item.fd, current, privateDirectory: item.privateDirectory, file: item.file, producer: item.producer) else { throw ReadFailure() }
                if let parent = item.parent, let name = item.name {
                    var named = stat()
                    guard fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0, same(item.initial, named, file: item.file) else { throw ReadFailure() }
                }
            }
        }
    }
}
