import Foundation

/// Registration is a local managed-launch result, never a remote MCP payload.
/// The common provider host retains claim/freshness/once/recovery semantics.
final class NativeElectronSession {
    private final class ExchangeEntry {
        private let lock = NSLock()
        private var entered = false
        func begin() throws {
            lock.lock(); defer { lock.unlock() }
            guard !entered else { throw NativeProviderHostFailure("native_provider_prepared_consumed") }
            entered = true
        }
    }
    typealias Metadata = (NativeProviderOwner) throws -> [String: Any]
    typealias Authority = (NativeProviderOwner, UInt32, Bool) throws -> Void
    typealias PointerExchange = (@escaping NativeElectronWorker.Authorise, @escaping NativeElectronWorker.PointerProgress) throws -> [String: Any]
    struct PreparedPointer { let sessionID: String; let exchange: PointerExchange }
    private let worker: NativeElectronWorker
    private let ownership: NativeProviderRecovery.ElectronOwnership
    private let metadata: Metadata, authority: Authority, checkCancelled: (String) throws -> Void
    private let saveRecovery: (String, [String: Any]) throws -> Void
    private let managed: [String: Any], validate: () -> Bool
    private var host: NativeProviderHost!
    let id: String, pid: Int32
    var isCurrent: Bool { validate() }

    init(managed: [String: Any], worker: NativeElectronWorker, ownership: NativeProviderRecovery.ElectronOwnership, validate: @escaping () -> Bool,
         metadata: @escaping Metadata, authority: @escaping Authority,
         checkCancelled: @escaping (String) throws -> Void,
         saveRecovery: @escaping (String, [String: Any]) throws -> Void) throws {
        guard let id = managed["session_id"] as? String, UUID(uuidString: id) != nil,
              let process = managed["process"] as? [String: Any], let pid = process["pid"] as? Int32,
              pid > 0, validate() else { throw NativeProviderHostFailure("native_electron_registration_invalid") }
        self.id = id; self.pid = pid; self.managed = managed; self.worker = worker; self.ownership = ownership; self.validate = validate
        self.metadata = metadata; self.authority = authority; self.checkCancelled = checkCancelled; self.saveRecovery = saveRecovery
        host = NativeProviderHost(exchange: { [weak self] requestID, method, payload in
            guard let self = self else { throw NativeProviderHostFailure("native_electron_process_changed") }
            let owner = try self.decodeOwner(payload)
            let context = try self.context(owner: owner)
            return try self.worker.exchange(requestID: requestID, method: method, payload: payload, managed: context,
                operation: "", claim: owner.claim_id, bundle: "", ownership: self.ownership,
                authorise: { _ in throw NativeProviderHostFailure("native_electron_authorisation_invalid") })
        }, authority: { [weak self] owner, number in
            guard let self = self, self.validate() else { throw NativeProviderHostFailure("native_electron_process_changed") }
            try self.authority(owner, number, false)
        })
    }

    private func decodeOwner(_ payload: [String: Any]) throws -> NativeProviderOwner {
        guard let raw = payload["owner"] as? [String: Any],
              let owner = try? JSONDecoder().decode(NativeProviderOwner.self, from: JSONSerialization.data(withJSONObject: raw)),
              owner.valid else { throw NativeProviderHostFailure("native_provider_owner_invalid") }
        return owner
    }

    private func context(owner: NativeProviderOwner) throws -> [String: Any] {
        guard validate(), let root = managed["session_root"] as? String,
              let profile = managed["profile_path"] as? String else {
            throw NativeProviderHostFailure("native_electron_process_changed")
        }
        try NativeProviderRecovery.validatePrivateDirectory(URL(fileURLWithPath: root))
        try NativeProviderRecovery.validatePrivateDirectory(URL(fileURLWithPath: profile))
        try ownership.verify(managed)
        var context = managed; context["windows"] = [try metadata(owner)]
        // Snapshot nested Foundation containers rather than borrowing mutable metadata.
        return try JSONSerialization.jsonObject(with: JSONSerialization.data(withJSONObject: context)) as! [String: Any]
    }

    func observe(owner: NativeProviderOwner, window: UInt32) -> [String: Any] {
        do { return try host.observe(owner: owner, windowNumber: window) }
        catch let e as NativeProviderHostFailure { return ["ready": false, "reason": e.code, "retry_allowed": false] }
        catch { return ["ready": false, "reason": "native_electron_observation_unavailable", "retry_allowed": false] }
    }

    /// A fixed frame request uses separate capture admission. It never passes
    /// through host.observe/input authority or creates a keyboard binding.
    func refreshForCapture(owner: NativeProviderOwner, window: [String: Any], operation: String,
                           bundle: String, deadline: Double,
                           authorise: @escaping NativeElectronWorker.Authorise) throws -> [String: Any] {
        guard owner.valid, !operation.isEmpty, !bundle.isEmpty, validate(),
              let number = window["cg_window_id"] as? UInt32, number > 0,
              let document = window["document_uri"] as? String, !document.isEmpty,
              deadline.isFinite, deadline > ProcessInfo.processInfo.systemUptime else {
            throw NativeProviderHostFailure("native_capture_refresh_target_invalid")
        }
        try checkCancelled(operation); try ownership.verify(managed)
        var context = managed; context["windows"] = [window]
        let response = try worker.exchange(requestID: UUID().uuidString, method: "refresh_for_capture",
            payload: ["owner": owner.wire, "cg_window_id": number, "deadline_monotonic": deadline], managed: context,
            operation: operation, claim: owner.claim_id, bundle: bundle, ownership: ownership) { message in
                guard self.validate(), Set(message.keys) == ["event", "request_id", "nonce", "context_hash", "owner",
                    "cg_window_id", "document_uri", "target_id", "frame_id", "loader_id", "time_origin", "purpose"],
                      message["purpose"] as? String == "capture_refresh",
                      let reportedOwner = message["owner"] as? [String: Any],
                      NSDictionary(dictionary: reportedOwner).isEqual(to: owner.wire),
                      message["cg_window_id"] as? UInt32 == number,
                      message["document_uri"] as? String == document,
                      let target = message["target_id"] as? String, !target.isEmpty,
                      let frame = message["frame_id"] as? String, !frame.isEmpty,
                      let loader = message["loader_id"] as? String, !loader.isEmpty,
                      let origin = message["time_origin"] as? Double, origin.isFinite,
                      ProcessInfo.processInfo.systemUptime < deadline else {
                    throw NativeProviderHostFailure("native_capture_refresh_admission_invalid")
                }
                try self.checkCancelled(operation); try self.ownership.verify(self.managed)
                try authorise(message)
                try self.checkCancelled(operation); try self.ownership.verify(self.managed)
            }
        try checkCancelled(operation)
        guard validate(), response["ok"] as? Bool == true, let result = response["result"] as? [String: Any] else {
            throw NativeProviderHostFailure("native_capture_refresh_reply_unavailable", effectState: "unknown")
        }
        guard result["ready"] as? Bool == true, result["refresh_for_capture"] as? Bool == true,
              result["receiver_kind"] as? String == "electron_renderer",
              result["dispatch_attempted"] as? Bool == true, result["screenshot_acknowledged"] as? Bool == true,
              result["session_detached"] as? Bool == true, result["frame_age_known"] as? Bool == false,
              result["effect_state"] as? String == "renderer_capture_requested" else {
            let code = result["reason"] as? String ?? "native_capture_refresh_unavailable"
            throw NativeProviderHostFailure(code, effectState: result["effect_state"] as? String == "none" ? "none" : "unknown")
        }
        return result
    }

    typealias AdmissionExecutor = (@escaping () throws -> Void) throws -> Void
    typealias PerformExchange = (@escaping AdmissionExecutor) throws -> [String: Any]
    struct PreparedPerform {
        let sessionID: String, operation: String, bundle: String
        let owner: NativeProviderOwner
        let window: UInt32
        let exchange: PerformExchange
        fileprivate let action: NativeProviderHost.PreparedAction
    }

    /// Native lane only. Persist recovery before returning any executable flight.
    func preparePerform(owner: NativeProviderOwner, window: UInt32, observation: String, operation: String,
                        bundle: String, method: String, arguments: [String: Any],
                        settled: @escaping () -> Void = {}) throws -> PreparedPerform {
        guard !operation.isEmpty, !bundle.isEmpty, validate() else {
            throw NativeProviderHostFailure("native_provider_operation_required")
        }
        try checkCancelled(operation); try authority(owner, window, false)
        let action = try host.preparePerform(owner: owner, observationID: observation, method: method, arguments: arguments)
        var preparedContext: [String: Any] = [:], preparationError: Error?
        do {
            try saveRecovery(operation, ["version": 1, "backend": "electron_renderer", "operation_id": operation,
                "provider_session_id": id, "owner": owner.wire, "descriptor": action.recovery])
            preparedContext = try context(owner: owner)
            guard let windows = preparedContext["windows"] as? [[String: Any]], windows.count == 1,
                  windows[0]["cg_window_id"] as? UInt32 == window, action.windowNumber == window else {
                throw NativeProviderHostFailure("native_electron_document_changed")
            }
        } catch { preparationError = error }
        let context = preparedContext, failure = preparationError, requestID = UUID().uuidString
        let payload = action.payload, worker = self.worker, ownership = self.ownership, entry = ExchangeEntry()
        return PreparedPerform(sessionID: id, operation: operation, bundle: bundle, owner: owner, window: window,
            exchange: { onLane in
                // Only the original exchange owns its settlement callback.
                // A rejected second invocation must not retire a live first.
                try entry.begin()
                var enteredWorker = false
                defer { if !enteredWorker { settled() } }
                if let failure = failure { throw failure }
                try onLane {
                    try self.host.beginPrepared(action)
                    try self.checkCancelled(operation)
                }
                enteredWorker = true
                return try worker.exchange(requestID: requestID, method: method, payload: payload, managed: context,
                    operation: operation, claim: owner.claim_id, bundle: bundle, ownership: ownership,
                    settled: settled,
                    authorise: { message in
                        try onLane {
                            guard self.validate(),
                                  Set(message.keys) == ["event", "request_id", "nonce", "context_hash", "binding_id", "once_id",
                                    "owner", "cg_window_id", "document_uri", "target_id", "renderer_state_hash"],
                                  message["binding_id"] as? String == payload["binding_id"] as? String,
                                  message["once_id"] as? String == payload["once_id"] as? String,
                                  let number = message["cg_window_id"] as? UInt32, number == window,
                                  let reportedOwner = message["owner"] as? [String: Any],
                                  NSDictionary(dictionary: reportedOwner).isEqual(to: owner.wire),
                                  let document = message["document_uri"] as? String,
                                  let target = message["target_id"] as? String, !target.isEmpty else {
                                throw NativeProviderHostFailure("native_electron_authorisation_invalid")
                            }
                            try self.checkCancelled(operation)
                            try NativeProviderRecovery.verifyElectronAdmission(managed: context, method: method, payload: payload, message: message)
                            try self.authority(owner, number, false)
                            let fresh = try self.metadata(owner)
                            guard let original = (context["windows"] as? [[String: Any]])?.first,
                                  NSDictionary(dictionary: fresh).isEqual(to: original),
                                  fresh["document_uri"] as? String == document, self.validate() else {
                                throw NativeProviderHostFailure("native_electron_document_changed")
                            }
                            try self.checkCancelled(operation)
                            try self.host.verifyOriginalAdmission(owner: owner, payload: payload)
                            try self.ownership.verify(context)
                            try self.checkCancelled(operation)
                        }
                    })
            }, action: action)
    }

    /// Native lane only. Keep the ticket until the caller stores its durable
    /// native terminal, even when worker I/O or provider cleanup is uncertain.
    func finalizePerform(_ prepared: PreparedPerform, response: Result<[String: Any], Error>) -> [String: Any] {
        host.finalizePrepared(prepared.action, response: response)
    }
    func releasePerform(_ prepared: PreparedPerform) { host.releasePrepared(prepared.action) }

    func perform(owner: NativeProviderOwner, window: UInt32, observation: String, operation: String,
                 bundle: String, method: String, arguments: [String: Any]) throws -> [String: Any] {
        let prepared = try preparePerform(owner: owner, window: window, observation: observation, operation: operation,
            bundle: bundle, method: method, arguments: arguments)
        defer { releasePerform(prepared) }
        let response = Result { try prepared.exchange { work in try work() } }
        return finalizePerform(prepared, response: response)
    }

    func retire(owner: NativeProviderOwner? = nil) { host.retire(owner: owner) }

    /// Prepare on the native lane. The returned immutable request only waits
    /// on worker I/O; its authority/progress callbacks must reenter that lane.
    /// Each exchange retains its own immutable operation tags.
    func preparePointer(owner: NativeProviderOwner, operation: String, bundle: String,
                        payload: [String: Any], settled: @escaping () -> Void = {}) throws -> PreparedPointer {
        guard owner.valid, !operation.isEmpty, !bundle.isEmpty, validate(),
              let suppliedOwner = payload["owner"] as? [String: Any],
              NSDictionary(dictionary: suppliedOwner).isEqual(to: owner.wire),
              payload["operation_id"] as? String == operation,
              let mapping = payload["mapping"] as? [String: Any],
              let number = mapping["cg_window_id"] as? UInt32 else {
            throw NativeProviderHostFailure("native_electron_pointer_preparation_invalid")
        }
        try checkCancelled(operation); try authority(owner, number, false); try ownership.verify(managed)
        let window = try metadata(owner)
        guard window["cg_window_id"] as? UInt32 == number,
              window["document_uri"] as? String == mapping["document_uri"] as? String else {
            throw NativeProviderHostFailure("native_electron_document_changed")
        }
        var context = managed; context["windows"] = [window]
        let requestID = UUID().uuidString, worker = self.worker, ownership = self.ownership, entry = ExchangeEntry()
        return PreparedPointer(sessionID: id) { authorise, progress in
            try entry.begin()
            return try worker.exchange(requestID: requestID, method: "pointer", payload: payload, managed: context,
                operation: operation, claim: owner.claim_id, bundle: bundle, ownership: ownership,
                pointerProgress: progress, settled: settled, authorise: authorise)
        }
    }
}
