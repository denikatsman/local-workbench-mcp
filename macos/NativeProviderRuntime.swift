import Foundation

/// Serial-queue provider ownership. Only the in-flight transport table is shared
/// with the control lane; no AX/claim state is read from that lane.
final class NativeProviderRuntime {
    typealias Transport = (NativeProviderEndpoint, String, String, [String: Any], Double) throws -> [String: Any]
    typealias Authority = (NativeProviderOwner, UInt32, Bool) throws -> Void
    private final class Session {
        let id: String, pid: Int32, endpoint: NativeProviderEndpoint
        let validate: () -> Bool
        let cancellationQueue: DispatchQueue
        var host: NativeProviderHost!
        var operationID: String?
        var beforeInputSend: (() throws -> Void)?
        init(id: String, pid: Int32, endpoint: NativeProviderEndpoint, validate: @escaping () -> Bool) {
            self.id = id; self.pid = pid; self.endpoint = endpoint; self.validate = validate
            self.cancellationQueue = DispatchQueue(label: "workbench-provider-cancel-" + id, qos: .userInitiated)
        }
    }
    private struct InFlight {
        let operationID: String, claimID: String, bundleID: String
        let endpoint: NativeProviderEndpoint, requestID: String
        let cancellationQueue: DispatchQueue
        var cancellationKey: String { endpoint.session + "/" + requestID }
    }
    private var sessions: [String: Session] = [:]
    private let authority: Authority
    private let transport: Transport
    private let checkCancelled: (String) throws -> Void
    private let saveRecovery: (String, [String: Any]) throws -> Void
    private let lock = NSLock()
    private var inFlight: [String: InFlight] = [:]
    private var cancellationSent: Set<String> = []
    private let retirement = DispatchQueue(label: "workbench-native-provider-retirement")
    private var operationOwner: (claim: String, bundle: String)?

    init(authority: @escaping Authority, checkCancelled: @escaping (String) throws -> Void,
         saveRecovery: @escaping (String, [String: Any]) throws -> Void,
         transport: @escaping Transport = { endpoint, id, method, payload, timeout in
             try NativeProviderWire.exchange(endpoint: endpoint, requestID: id, method: method, payload: payload, timeout: timeout)
         }) {
        self.authority = authority; self.checkCancelled = checkCancelled
        self.saveRecovery = saveRecovery; self.transport = transport
    }

    private func boolean(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }

    /// Called only for a launcher-prepared process, with a captured kernel
    /// birth/audit identity. No remote request can register a helper endpoint.
    @discardableResult
    func register(preparation: NativeProviderPreparation, pid: Int32, audit: Data,
                  replacingHost: Bool = false, validate: @escaping () -> Bool) throws -> [String: Any] {
        guard pid > 0, validate() else { throw NativeProviderHostFailure("native_provider_process_changed") }
        sessions = sessions.filter { $0.value.validate() }
        guard sessions.count < 32, sessions.values.allSatisfy({ $0.pid != pid }) else {
            throw NativeProviderHostFailure("native_provider_session_capacity_or_duplicate")
        }
        let endpoint = NativeProviderEndpoint(socketPath: preparation.socketPath, token: preparation.token,
            session: preparation.session, generation: preparation.generation, peerAuditToken: audit)
        // A replacement first authenticates the same exact target socket. It
        // sends only an empty handover control, never an old input envelope.
        // Reply loss is reconciled by current-owner handover status, which the
        // receiver makes idempotent without retiring bindings twice.
        let reply = try transport(endpoint, UUID().uuidString, replacingHost ? "handover" : "hello", [:], 3)
        let expectedTarget: [String: Any] = ["bundle_identifier": preparation.target.bundleIdentifier ?? "",
            "executable": preparation.target.executablePath, "signing_identifier": preparation.target.signingIdentifier,
            "team_identifier": preparation.target.teamIdentifier ?? "", "cdhash": preparation.target.cdHash]
        let expectedHelper: [String: Any] = ["path": preparation.helper.executablePath,
            "signing_identifier": preparation.helper.signingIdentifier, "team_identifier": preparation.helper.teamIdentifier ?? "",
            "cdhash": preparation.helper.cdHash]
        guard boolean(reply["ok"]) == true, let value = reply["result"] as? [String: Any],
              boolean(value["ready"]) == true, value["status"] as? String == "running",
              let reportedPID = value["pid"] as? NSNumber, CFGetTypeID(reportedPID) != CFBooleanGetTypeID(),
              reportedPID.doubleValue == Double(pid),
              let target = value["target"] as? [String: Any], NSDictionary(dictionary: target).isEqual(to: expectedTarget),
              let helper = value["helper"] as? [String: Any], NSDictionary(dictionary: helper).isEqual(to: expectedHelper),
              validate() else { throw NativeProviderHostFailure("native_provider_admission_reply_invalid") }
        if replacingHost || value["host_rebind_version"] != nil || value["authority_epoch"] != nil {
            guard let version = value["host_rebind_version"] as? NSNumber,
                  CFGetTypeID(version) != CFBooleanGetTypeID(), !CFNumberIsFloatType(version), version.int64Value == 2,
                  let epoch = value["authority_epoch"] as? String, epoch.utf8.count == 36, UUID(uuidString: epoch) != nil else {
                throw NativeProviderHostFailure("native_provider_handover_reply_invalid")
            }
        }
        if let plugin = preparation.plugin {
            let expectedPlugin: [String: Any] = ["bundle_path": plugin.bundlePath ?? "", "executable": plugin.executablePath,
                "bundle_identifier": plugin.bundleIdentifier ?? "", "signing_identifier": plugin.signingIdentifier,
                "team_identifier": plugin.teamIdentifier ?? "", "cdhash": plugin.cdHash]
            guard value["route"] as? String == "textmate_api2_plugin",
                  let reported = value["plugin"] as? [String: Any],
                  NSDictionary(dictionary: reported).isEqual(to: expectedPlugin), validate() else {
                throw NativeProviderHostFailure("native_provider_admission_reply_invalid")
            }
        } else if value["route"] != nil || value["plugin"] != nil {
            throw NativeProviderHostFailure("native_provider_admission_reply_invalid")
        }
        if preparation.allowTextClientInputContextKeys {
            guard preparation.plugin != nil, NativeProviderTextClientCompatibility.supports(preparation.target),
                  boolean(value["text_input_context_keys"]) == true else {
                throw NativeProviderHostFailure("native_provider_admission_reply_invalid")
            }
        } else if value["text_input_context_keys"] != nil {
            throw NativeProviderHostFailure("native_provider_admission_reply_invalid")
        }
        if preparation.allowTextClientInputContextShift {
            guard preparation.allowTextClientInputContextKeys, boolean(value["text_input_context_shift"]) == true else {
                throw NativeProviderHostFailure("native_provider_admission_reply_invalid")
            }
        } else if value["text_input_context_shift"] != nil {
            throw NativeProviderHostFailure("native_provider_admission_reply_invalid")
        }
        if preparation.allowTextClientInputContextControlOption {
            guard preparation.allowTextClientInputContextShift, boolean(value["text_input_context_control_option"]) == true else {
                throw NativeProviderHostFailure("native_provider_admission_reply_invalid")
            }
        } else if value["text_input_context_control_option"] != nil {
            throw NativeProviderHostFailure("native_provider_admission_reply_invalid")
        }
        if preparation.allowTextClientInputContextReceiverKeyUp {
            guard preparation.allowTextClientInputContextControlOption, boolean(value["text_input_context_receiver_key_up"]) == true else {
                throw NativeProviderHostFailure("native_provider_admission_reply_invalid")
            }
        } else if value["text_input_context_receiver_key_up"] != nil {
            throw NativeProviderHostFailure("native_provider_admission_reply_invalid")
        }
        let session = Session(id: preparation.session, pid: pid, endpoint: endpoint, validate: validate)
        session.host = NativeProviderHost(exchange: { [weak self, weak session] id, method, payload in
            guard let self = self, let session = session, session.validate() else {
                throw NativeProviderHostFailure("native_provider_process_changed")
            }
            let input = ["key_pair", "key_chord", "key_sequence", "consume_plain_text"].contains(method)
            if input {
                guard let operation = session.operationID, let owner = self.operationOwner else {
                    throw NativeProviderHostFailure("native_provider_operation_required")
                }
                // Publish before checking the ticket. Cancellation arriving
                // between the check and send reaches cancel_request, including
                // the helper's bounded cancel-before-envelope table.
                self.lock.lock()
                let flight = InFlight(operationID: operation, claimID: owner.claim,
                    bundleID: owner.bundle, endpoint: session.endpoint, requestID: id, cancellationQueue: session.cancellationQueue)
                self.inFlight[operation] = flight
                self.lock.unlock()
                defer {
                    self.lock.lock(); self.inFlight.removeValue(forKey: operation)
                    self.cancellationSent.remove(flight.cancellationKey); self.lock.unlock()
                }
                try self.checkCancelled(operation)
                // All process/AX/provider admission above may be slow. This
                // last callback reads retained capture/authority state only.
                try session.beforeInputSend?()
                try self.checkCancelled(operation)
                // Never hold NativeCancellation's lock while waiting on IPC.
                return try self.transport(session.endpoint, id, method, payload, 3)
            }
            return try self.transport(session.endpoint, id, method, payload, 3)
        }, authority: { [weak self, weak session] owner, window in
            guard let self = self, let session = session, session.validate() else {
                throw NativeProviderHostFailure("native_provider_process_changed")
            }
            try self.authority(owner, window, false)
        }, allowTextClientInputContextKeys: preparation.allowTextClientInputContextKeys,
           allowTextClientInputContextShift: preparation.allowTextClientInputContextShift,
           allowTextClientInputContextControlOption: preparation.allowTextClientInputContextControlOption,
           allowTextClientInputContextReceiverKeyUp: preparation.allowTextClientInputContextReceiverKeyUp)
        sessions[session.id] = session
        return value
    }

    func contains(pid: Int32) -> Bool { sessions.values.contains { $0.pid == pid && $0.validate() } }

    private func session(pid: Int32) throws -> Session {
        guard let session = sessions.values.first(where: { $0.pid == pid }), session.validate() else {
            throw NativeProviderHostFailure("native_provider_not_registered")
        }
        return session
    }

    func observe(pid: Int32, owner: NativeProviderOwner, window: UInt32) -> [String: Any] {
        do { return try session(pid: pid).host.observe(owner: owner, windowNumber: window) }
        catch let failure as NativeProviderHostFailure {
            return ["ready": false, "reason": failure.code, "retry_allowed": false]
        } catch { return ["ready": false, "reason": "native_provider_observation_unavailable", "retry_allowed": false] }
    }

    func perform(pid: Int32, bundleID: String, owner: NativeProviderOwner, window: UInt32,
                 observationID: String, operationID: String, method: String, arguments: [String: Any],
                 beforeSendAdmission: @escaping () throws -> Void = {}) throws -> [String: Any] {
        guard !operationID.isEmpty, sessionOperationIdle else { throw NativeProviderHostFailure("native_provider_operation_required") }
        let session = try session(pid: pid)
        try authority(owner, window, method == "consume_plain_text")
        try checkCancelled(operationID)
        session.operationID = operationID; operationOwner = (owner.claim_id, bundleID)
        session.beforeInputSend = beforeSendAdmission
        defer { session.operationID = nil; session.beforeInputSend = nil; operationOwner = nil }
        return try session.host.perform(owner: owner, observationID: observationID, method: method, arguments: arguments,
            prepareRecovery: { descriptor in
                try self.saveRecovery(operationID, ["version": 1, "operation_id": operationID,
                    "provider_session_id": session.id, "owner": owner.wire, "descriptor": descriptor])
            }, guardedSend: { action in
                try self.checkCancelled(operationID)
                try self.authority(owner, window, method == "consume_plain_text")
                try action()
            })
    }

    private var sessionOperationIdle: Bool { operationOwner == nil }

    /// Authenticated read-only recovery. Original receipts are never rewritten.
    func recover(record: [String: Any], ownerSession: String, operationID: String) throws -> [String: Any] {
        guard record["operation_id"] as? String == operationID,
              let raw = record["owner"] as? [String: Any], raw["owner_session"] as? String == ownerSession,
              let owner = try? JSONDecoder().decode(NativeProviderOwner.self, from: JSONSerialization.data(withJSONObject: raw)),
              owner.valid, let descriptor = record["descriptor"] as? [String: Any],
              let id = record["provider_session_id"] as? String else {
            throw NativeProviderHostFailure("native_provider_receipt_owner_mismatch")
        }
        guard let session = sessions[id], session.validate() else {
            return ["receipt_recovered": false, "effect_state": "unknown", "reason": "native_provider_original_process_unavailable",
                    "retry_allowed": false]
        }
        return try session.host.recover(owner: owner, descriptor: descriptor)
    }

    /// Called after local cancellation tickets are revoked. This method is safe
    /// on the control/UI lane and only schedules bounded authenticated IPC.
    @discardableResult
    func cancel(operationID: String? = nil, claimID: String? = nil, bundleID: String? = nil) -> Int {
        lock.lock()
        let requests = inFlight.values.filter {
            (operationID == nil || $0.operationID == operationID) && (claimID == nil || $0.claimID == claimID)
                && (bundleID == nil || $0.bundleID == bundleID)
        }.filter { cancellationSent.insert($0.cancellationKey).inserted }
        lock.unlock()
        for request in requests {
            request.cancellationQueue.async { [transport] in
                _ = try? transport(request.endpoint, UUID().uuidString, "cancel_request",
                    ["target_request_id": request.requestID], 1)
            }
        }
        return requests.count
    }

    /// Serial lane only, after claims have stopped. Endpoint remains available
    /// for original receipts; retiring a binding cannot fabricate no-effect.
    func retire(owner: NativeProviderOwner? = nil) {
        for session in sessions.values {
            session.host.retire(owner: owner)
            let payload: [String: Any] = owner.map { ["owner": $0.wire] } ?? [:]
            let endpoint = session.endpoint
            retirement.async { [transport] in
                _ = try? transport(endpoint, UUID().uuidString, "cancel", payload, 1)
            }
        }
    }
}

/// Raw provider IDs stay in private signed-host journals. Public MCP views keep
/// effect/readback evidence and the host's opaque observation ID only.
enum NativeProviderPublicView {
    static func clean(_ value: [String: Any]) -> [String: Any] {
        func redact(_ item: Any) -> Any {
            if let object = item as? [String: Any] {
                return object.filter { !["binding_id", "once_id", "provider_recovery", "provider_session_id"].contains($0.key) }
                    .mapValues(redact)
            }
            if let array = item as? [Any] { return array.map(redact) }
            return item
        }
        return redact(value) as! [String: Any]
    }
}
