import Foundation

struct NativeProviderOwner: Codable, Equatable {
    let claim_id: String
    let owner_session: String
    let runtime_generation: String
    let target_generation: String
    let window_id: String

    var valid: Bool {
        [claim_id, owner_session, runtime_generation, target_generation, window_id].allSatisfy {
            !$0.isEmpty && $0.utf8.count <= 128 && !$0.utf8.contains(0)
        }
    }
    var wire: [String: Any] {
        ["claim_id": claim_id, "owner_session": owner_session, "runtime_generation": runtime_generation,
         "target_generation": target_generation, "window_id": window_id]
    }
}

struct NativeProviderHostFailure: Error {
    let code: String
    let effectState: String
    let admissionEvidence: [String: Any]?
    init(_ code: String, effectState: String = "none", admissionEvidence: [String: Any]? = nil) {
        self.code = code; self.effectState = effectState; self.admissionEvidence = admissionEvidence
    }
}

/// One authenticated, dynamically admitted target process. Creation/registration
/// belongs to the signed launcher, not to a remote packet or arbitrary path.
/// Use on the native operation serial queue. No automatic retry or relaunch.
final class NativeProviderHost {
    typealias Exchange = (String, String, [String: Any]) throws -> [String: Any]
    typealias Authority = (NativeProviderOwner, UInt32) throws -> Void
    typealias GuardedSend = (() throws -> Void) throws -> Void

    private struct Binding {
        let owner: NativeProviderOwner
        let windowNumber: UInt32
        let bindingID: String
        let onceID: String
        let observed: Double
        let deadline: Double
        let methods: Set<String>
        let contextModifiers: [String]?
        var consumed: Bool
    }
    /// Immutable original request. Only the owning serial lane may use lifecycle APIs.
    final class PreparedAction {
        fileprivate let ticket = UUID()
        let owner: NativeProviderOwner
        let windowNumber: UInt32
        let method: String
        let deadline: Double
        fileprivate let requestID = UUID().uuidString
        private let payloadData: Data
        private let recoveryData: Data
        var payload: [String: Any] { try! JSONSerialization.jsonObject(with: payloadData) as! [String: Any] }
        var recovery: [String: Any] { try! JSONSerialization.jsonObject(with: recoveryData) as! [String: Any] }
        fileprivate init(owner: NativeProviderOwner, window: UInt32, method: String, deadline: Double,
                         payload: [String: Any], recovery: [String: Any]) throws {
            self.owner = owner; self.windowNumber = window; self.method = method; self.deadline = deadline
            payloadData = try JSONSerialization.data(withJSONObject: payload)
            recoveryData = try JSONSerialization.data(withJSONObject: recovery)
        }
    }
    private struct Flight { let action: PreparedAction; var started = false; var admitted = false; var finalized = false }
    private var flights: [UUID: Flight] = [:]
    private let exchange: Exchange
    private let authority: Authority
    private let clock: () -> Double
    private let allowTextClientInputContextKeys: Bool
    private let allowTextClientInputContextShift: Bool
    private let allowTextClientInputContextControlOption: Bool
    private let allowTextClientInputContextReceiverKeyUp: Bool
    private var bindings: [String: Binding] = [:]

    private func boolean(_ value: Any?) -> Bool? {
        guard let value = value as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID() else { return nil }
        return value.boolValue
    }

    init(exchange: @escaping Exchange, authority: @escaping Authority,
         clock: @escaping () -> Double = { ProcessInfo.processInfo.systemUptime },
         allowTextClientInputContextKeys: Bool = false, allowTextClientInputContextShift: Bool = false,
         allowTextClientInputContextControlOption: Bool = false,
         allowTextClientInputContextReceiverKeyUp: Bool = false) {
        self.exchange = exchange; self.authority = authority; self.clock = clock
        self.allowTextClientInputContextKeys = allowTextClientInputContextKeys
        self.allowTextClientInputContextShift = allowTextClientInputContextShift
        self.allowTextClientInputContextControlOption = allowTextClientInputContextControlOption
        self.allowTextClientInputContextReceiverKeyUp = allowTextClientInputContextReceiverKeyUp
    }

    private func result(_ response: [String: Any]) throws -> [String: Any] {
        guard boolean(response["ok"]) == true, let value = response["result"] as? [String: Any] else {
            throw NativeProviderHostFailure("native_provider_reply_unavailable", effectState: "unknown")
        }
        return value
    }

    private func request(_ method: String, _ payload: [String: Any]) throws -> [String: Any] {
        do { return try result(exchange(UUID().uuidString, method, payload)) }
        catch let failure as NativeProviderWireFailure {
            throw NativeProviderHostFailure(failure.code,
                effectState: failure.requestMayHaveBeenReceived ? "unknown" : "none")
        }
    }

    func observe(owner: NativeProviderOwner, windowNumber: UInt32, includeText: Bool = false) throws -> [String: Any] {
        guard owner.valid, windowNumber > 0, windowNumber <= UInt32(Int32.max) else {
            throw NativeProviderHostFailure("native_provider_target_invalid")
        }
        if allowTextClientInputContextReceiverKeyUp && !allowTextClientInputContextControlOption {
            throw NativeProviderHostFailure("native_provider_receiver_capabilities_invalid")
        }
        if allowTextClientInputContextControlOption && (!allowTextClientInputContextKeys || !allowTextClientInputContextShift) {
            throw NativeProviderHostFailure("native_provider_receiver_capabilities_invalid")
        }
        try authority(owner, windowNumber)
        let started = clock()
        guard started.isFinite, started >= 0 else { throw NativeProviderHostFailure("native_provider_clock_unavailable") }
        let retained = Set(flights.values.map { $0.action.payload["once_id"] as! String })
        bindings = bindings.filter { retained.contains($0.value.onceID) || (!$0.value.consumed && $0.value.deadline > started) }
        guard bindings.count < 64 else { throw NativeProviderHostFailure("native_provider_active_binding_limit") }
        var observed = try request("observe", ["owner": owner.wire, "cg_window_id": windowNumber, "include_text": includeText])
        guard let ready = boolean(observed["ready"]) else {
            throw NativeProviderHostFailure("native_provider_observation_protocol")
        }
        guard ready else { return observed }
        if allowTextClientInputContextKeys && (observed["receiver_kind"] == nil || observed["capabilities"] == nil) {
            throw NativeProviderHostFailure("native_provider_receiver_capabilities_invalid")
        }
        let sequence = observed["key_sequence_version"] != nil
        if sequence {
            guard let version = observed["key_sequence_version"] as? NSNumber,
                  CFGetTypeID(version) != CFBooleanGetTypeID(), !CFNumberIsFloatType(version), version.intValue == 1,
                  allowTextClientInputContextReceiverKeyUp,
                  observed["receiver_kind"] as? String == "custom_text_input_client" else {
                throw NativeProviderHostFailure("native_provider_receiver_capabilities_invalid")
            }
        }
        var methods: Set<String> = ["key_pair", "consume_plain_text"]
        var contextModifiers: [String]? = nil
        if observed["receiver_kind"] != nil || observed["capabilities"] != nil {
            guard let kind = observed["receiver_kind"] as? String,
                  ["typed_text_view", "custom_view_key_only", "custom_text_input_client", "electron_renderer"].contains(kind),
                  let capabilities = observed["capabilities"] as? [String: Any],
                  Set(capabilities.keys) == ((kind == "electron_renderer" || (kind == "custom_text_input_client" && allowTextClientInputContextShift))
                    ? Set(["key_pair", "consume_plain_text", "key_chord"]) : Set(["key_pair", "consume_plain_text"])).union(sequence ? ["key_sequence"] : []),
                  boolean(capabilities["key_pair"]) == (kind != "custom_text_input_client" || allowTextClientInputContextKeys),
                  let consume = boolean(capabilities["consume_plain_text"]),
                  consume == (kind != "custom_view_key_only"),
                  kind != "electron_renderer" || boolean(capabilities["key_chord"]) == true else {
                throw NativeProviderHostFailure("native_provider_receiver_capabilities_invalid")
            }
            if kind == "custom_text_input_client" && allowTextClientInputContextShift {
                guard allowTextClientInputContextKeys, boolean(capabilities["key_chord"]) == true,
                      observed["supported_modifiers"] as? [String] == (allowTextClientInputContextControlOption ? ["shift", "control", "option"] : ["shift"]),
                      !allowTextClientInputContextControlOption || (observed["maximum_modifier_count"] as? NSNumber).map({ CFGetTypeID($0) != CFBooleanGetTypeID() && !CFNumberIsFloatType($0) && $0.int64Value == 1 }) == true,
                      allowTextClientInputContextControlOption || observed["maximum_modifier_count"] == nil else {
                    throw NativeProviderHostFailure("native_provider_receiver_capabilities_invalid")
                }
                contextModifiers = allowTextClientInputContextControlOption ? ["shift", "control", "option"] : ["shift"]; methods.insert("key_chord")
            } else if observed["supported_modifiers"] != nil || observed["maximum_modifier_count"] != nil {
                throw NativeProviderHostFailure("native_provider_receiver_capabilities_invalid")
            }
            if kind == "custom_text_input_client" && allowTextClientInputContextReceiverKeyUp {
                guard allowTextClientInputContextKeys, observed["key_up_route"] as? String == "original_receiver_key_up" else {
                    throw NativeProviderHostFailure("native_provider_receiver_capabilities_invalid")
                }
            } else if observed["key_up_route"] != nil {
                throw NativeProviderHostFailure("native_provider_receiver_capabilities_invalid")
            }
            if kind == "custom_text_input_client" {
                if allowTextClientInputContextKeys {
                    guard observed["key_pair_route"] as? String == "exact_view_input_context" else {
                        throw NativeProviderHostFailure("native_provider_receiver_capabilities_invalid")
                    }
                } else {
                    guard observed["key_pair_route"] == nil else {
                        throw NativeProviderHostFailure("native_provider_receiver_capabilities_invalid")
                    }
                    methods = ["consume_plain_text"]
                }
            } else if observed["key_pair_route"] != nil {
                throw NativeProviderHostFailure("native_provider_receiver_capabilities_invalid")
            }
            if !consume {
                guard observed["text"] == nil, observed["text_snapshot"] == nil else {
                    throw NativeProviderHostFailure("native_provider_key_only_text_disclosure_invalid")
                }
                methods = ["key_pair"]
            }
            if kind == "electron_renderer" { methods.insert("key_chord") }
            if sequence {
                guard boolean(capabilities["key_sequence"]) == true,
                      observed["key_up_route"] as? String == "original_receiver_key_up" else {
                    throw NativeProviderHostFailure("native_provider_receiver_capabilities_invalid")
                }
                methods.insert("key_sequence")
            }
        }
        guard let bindingID = observed["binding_id"] as? String, UUID(uuidString: bindingID) != nil,
              observed["freshness_clock"] as? String == "system_uptime_v1",
              let onceID = observed["once_id"] as? String, UUID(uuidString: onceID) != nil,
              let deadline = observed["deadline_monotonic"] as? NSNumber,
              CFGetTypeID(deadline) != CFBooleanGetTypeID(), deadline.doubleValue.isFinite,
              deadline.doubleValue > started,
              let state = observed["state"] as? [String: Any], let remoteWindow = state["window_id"] as? NSNumber,
              CFGetTypeID(remoteWindow) != CFBooleanGetTypeID(), remoteWindow.doubleValue == Double(windowNumber) else {
            throw NativeProviderHostFailure("native_provider_observation_binding_invalid")
        }
        try authority(owner, windowNumber)
        let localDeadline = min(deadline.doubleValue, started + 30)
        let finished = clock()
        guard finished.isFinite, finished >= started, finished < localDeadline else {
            throw NativeProviderHostFailure("native_provider_observation_expired")
        }
        let observationID = UUID().uuidString
        bindings[observationID] = Binding(owner: owner, windowNumber: windowNumber,
            bindingID: bindingID, onceID: onceID, observed: started, deadline: localDeadline, methods: methods, contextModifiers: contextModifiers, consumed: false)
        observed["provider_observation_id"] = observationID
        observed["deadline_monotonic"] = localDeadline
        // Component IDs remain in the native host. Recovery uses an explicit,
        // owner-bound descriptor returned by perform, never a raw remote ID.
        observed.removeValue(forKey: "binding_id"); observed.removeValue(forKey: "once_id")
        return observed
    }

    func preparePerform(owner: NativeProviderOwner, observationID: String, method: String,
                 arguments suppliedArguments: [String: Any]) throws -> PreparedAction {
        guard var binding = bindings[observationID], binding.owner == owner, owner.valid else {
            throw NativeProviderHostFailure("native_provider_observation_owner_mismatch")
        }
        guard !binding.consumed else { throw NativeProviderHostFailure("native_provider_observation_consumed") }
        guard ["key_pair", "key_chord", "key_sequence", "consume_plain_text"].contains(method) else {
            throw NativeProviderHostFailure("native_provider_action_invalid")
        }
        guard binding.methods.contains(method) else {
            throw NativeProviderHostFailure("native_provider_action_not_supported_by_receiver")
        }
        // Freeze only the new sequence route before any reentrant host authority
        // callback. Bound and prevalidate caller containers before serialization,
        // then validate and use the decoded immutable snapshot throughout.
        var arguments = suppliedArguments
        if method == "key_sequence" {
            guard Set(suppliedArguments.keys) == ["keys"],
                  let suppliedKeys = suppliedArguments["keys"] as? [[String: Any]],
                  NativeProviderKeySequence.validKeys(suppliedKeys, supported: binding.contextModifiers ?? []),
                  let bytes = try? JSONSerialization.data(withJSONObject: suppliedArguments), bytes.count <= 8192,
                  let frozen = (try? JSONSerialization.jsonObject(with: bytes)) as? [String: Any] else {
                throw NativeProviderHostFailure("native_provider_key_sequence_invalid")
            }
            arguments = frozen
        }
        let keys = Set(arguments.keys)
        if method == "key_sequence" {
            guard keys == ["keys"], let descriptors = arguments["keys"] as? [[String: Any]],
                  NativeProviderKeySequence.validKeys(descriptors, supported: binding.contextModifiers ?? []) else {
                throw NativeProviderHostFailure("native_provider_key_sequence_invalid")
            }
        } else if ["key_pair", "key_chord"].contains(method) {
            let expected: Set<String> = method == "key_chord"
                ? ["key_code", "characters", "characters_ignoring_modifiers", "modifiers"]
                : ["key_code", "characters", "characters_ignoring_modifiers"]
            guard keys == expected,
                  let code = arguments["key_code"] as? NSNumber, CFGetTypeID(code) != CFBooleanGetTypeID(),
                  code.doubleValue.isFinite, code.doubleValue.rounded() == code.doubleValue,
                  (0.0...127.0).contains(code.doubleValue), !(54...63).contains(code.intValue),
                  ["characters", "characters_ignoring_modifiers"].allSatisfy({
                      guard let text = arguments[$0] as? String else { return false }
                      return !text.isEmpty && text.utf16.count <= 8
                  }) else { throw NativeProviderHostFailure("native_provider_key_invalid") }
            if method == "key_chord" {
                if let supported = binding.contextModifiers, (arguments["modifiers"] as? [String]).map({ $0.count == 1 && supported.contains($0[0]) }) != true {
                    throw NativeProviderHostFailure("native_provider_modifiers_invalid")
                }
                guard let modifiers = arguments["modifiers"] as? [String], (1...4).contains(modifiers.count),
                      Set(modifiers).count == modifiers.count,
                      Set(modifiers).isSubset(of: ["command", "control", "option", "shift"]) else {
                    throw NativeProviderHostFailure("native_provider_modifiers_invalid")
                }
            }
        } else {
            guard keys == ["text"], let text = arguments["text"] as? String,
                  text.utf16.count <= 4096, text.utf8.count <= 16384 else {
                throw NativeProviderHostFailure("native_provider_text_invalid")
            }
        }
        guard !flights.values.contains(where: { $0.action.windowNumber == binding.windowNumber }) else {
            throw NativeProviderHostFailure("native_provider_target_in_flight")
        }
        try authority(owner, binding.windowNumber)
        let now = clock()
        guard now.isFinite, now >= binding.observed, now < binding.deadline else { throw NativeProviderHostFailure("native_provider_observation_expired") }
        // Consume locally before the guarded send. A transport failure cannot
        // turn an original binding into permission to repeat an uncertain key.
        binding.consumed = true; bindings[observationID] = binding
        var payload = arguments
        payload["owner"] = owner.wire; payload["binding_id"] = binding.bindingID; payload["once_id"] = binding.onceID
        let recovery: [String: Any] = ["owner": owner.wire, "once_id": binding.onceID, "binding_id": binding.bindingID]
        let action = try PreparedAction(owner: owner, window: binding.windowNumber, method: method,
            deadline: binding.deadline, payload: payload, recovery: recovery)
        flights[action.ticket] = Flight(action: action)
        return action
    }

    /// One transition into worker I/O. The callback remains on the serial owner;
    /// only the returned immutable operation may subsequently wait off lane.
    func beginPrepared(_ action: PreparedAction) throws {
        guard var flight = flights[action.ticket], flight.action === action, !flight.started, !flight.finalized else {
            throw NativeProviderHostFailure("native_provider_prepared_consumed")
        }
        flight.started = true; flights[action.ticket] = flight
        try verifyOriginalAdmission(owner: action.owner, payload: action.payload)
        flight.admitted = true; flights[action.ticket] = flight
    }

    func finalizePrepared(_ action: PreparedAction, response: Result<[String: Any], Error>) -> [String: Any] {
        guard var flight = flights[action.ticket], flight.action === action, !flight.finalized else {
            return ["ready": false, "effect_state": "unknown", "reason": "native_provider_prepared_consumed",
                    "retry_allowed": false, "provider_recovery": action.recovery]
        }
        flight.finalized = true; flights[action.ticket] = flight
        let value: [String: Any]
        do {
            let raw = try response.get()
            guard flight.admitted else { throw NativeProviderHostFailure("native_provider_prepared_not_admitted") }
            value = try result(raw)
        }
        catch {
            let failure = error as? NativeProviderHostFailure
            let wire = error as? NativeProviderWireFailure
            var failed: [String: Any] = ["ready": false, "outcome": "unknown_or_not_dispatched",
                "effect_state": failure?.effectState ?? wire.map { $0.requestMayHaveBeenReceived ? "unknown" : "none" } ?? "unknown",
                "reason": failure?.code ?? wire?.code ?? "native_provider_guard_or_transport_failed",
                "retry_allowed": false, "provider_recovery": action.recovery]
            if let evidence = failure?.admissionEvidence { failed["admission_failure"] = evidence }
            return failed
        }
        guard value["binding_id"] as? String == action.payload["binding_id"] as? String,
              value["once_id"] as? String == action.payload["once_id"] as? String else {
            return ["ready": false, "outcome": "unknown_after_request", "effect_state": "unknown",
                    "reason": "native_provider_result_binding_invalid", "retry_allowed": false, "provider_recovery": action.recovery]
        }
        if action.method == "key_sequence", !NativeProviderKeySequence.validResult(value, expectedCount: (action.payload["keys"] as? [Any])?.count) {
            return ["ready": false, "outcome": "unknown_after_request", "effect_state": "unknown",
                    "reason": "native_provider_sequence_result_invalid", "retry_allowed": false, "provider_recovery": action.recovery]
        }
        var bound = value; bound["provider_recovery"] = action.recovery
        return bound
    }

    /// Keep the reservation through original cleanup AND the enclosing durable
    /// terminal. Failed terminal storage must leave this ticket retained.
    func releasePrepared(_ action: PreparedAction) {
        guard let flight = flights[action.ticket], flight.action === action else { return }
        flights.removeValue(forKey: action.ticket)
    }

    func perform(owner: NativeProviderOwner, observationID: String, method: String,
                 arguments: [String: Any], prepareRecovery: ([String: Any]) throws -> Void = { _ in },
                 guardedSend: GuardedSend) throws -> [String: Any] {
        let action = try preparePerform(owner: owner, observationID: observationID, method: method, arguments: arguments)
        defer { releasePrepared(action) }
        var response: Result<[String: Any], Error> = .failure(NativeProviderHostFailure("native_provider_guard_or_transport_failed", effectState: "unknown"))
        do {
            try prepareRecovery(action.recovery)
            try guardedSend {
                try self.beginPrepared(action)
                response = Result { try self.exchange(action.requestID, action.method, action.payload) }
            }
        } catch { response = .failure(error) }
        return finalizePrepared(action, response: response)
    }

    func retire(owner: NativeProviderOwner? = nil) {
        if let owner = owner { bindings = bindings.filter { $0.value.owner != owner } }
        else { bindings.removeAll() }
    }

    /// A child may ask for admission after transport setup. Recheck the same
    /// consumed original binding and deadline immediately before its first
    /// possible effect, without creating a second dispatch permission.
    func verifyOriginalAdmission(owner: NativeProviderOwner, payload: [String: Any]) throws {
        guard let bindingID = payload["binding_id"] as? String, let onceID = payload["once_id"] as? String,
              let binding = bindings.values.first(where: { $0.bindingID == bindingID && $0.onceID == onceID }),
              binding.consumed, binding.owner == owner,
              flights.values.contains(where: { $0.started && !$0.finalized && $0.action.owner == owner &&
                  $0.action.payload["binding_id"] as? String == bindingID && $0.action.payload["once_id"] as? String == onceID }) else {
            throw NativeProviderHostFailure("native_provider_observation_owner_mismatch")
        }
        let now = clock()
        guard now.isFinite, now >= binding.observed, now < binding.deadline else {
            throw NativeProviderHostFailure("native_provider_observation_expired")
        }
        try authority(owner, binding.windowNumber)
        let checked = clock()
        guard checked.isFinite, checked >= now, checked < binding.deadline else {
            throw NativeProviderHostFailure("native_provider_observation_expired")
        }
    }

    /// The enclosing native operation receipt binds this descriptor to its
    /// original task; current input authority is not needed for owned recovery.
    func recover(owner: NativeProviderOwner, descriptor: [String: Any]) throws -> [String: Any] {
        guard owner.valid, Set(descriptor.keys) == ["owner", "once_id", "binding_id"],
              let savedOwner = descriptor["owner"] as? [String: Any], NSDictionary(dictionary: savedOwner).isEqual(to: owner.wire),
              let onceID = descriptor["once_id"] as? String, UUID(uuidString: onceID) != nil,
              let bindingID = descriptor["binding_id"] as? String, UUID(uuidString: bindingID) != nil else {
            throw NativeProviderHostFailure("native_provider_receipt_owner_mismatch")
        }
        let value = try request("receipt", ["owner": owner.wire, "once_id": onceID])
        if value["receipt_recovered"] != nil && boolean(value["receipt_recovered"]) == nil {
            throw NativeProviderHostFailure("native_provider_receipt_protocol", effectState: "unknown")
        }
        if boolean(value["receipt_recovered"]) == true {
            guard value["once_id"] as? String == onceID, value["binding_id"] as? String == bindingID else {
                throw NativeProviderHostFailure("native_provider_receipt_binding_invalid", effectState: "unknown")
            }
        }
        return value
    }
}

/// Additive sequence-only wire validation. No OS/layout or atomic-text claim.
enum NativeProviderKeySequence {
    private static func integer(_ value: Any?) -> Int? {
        guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(), !CFNumberIsFloatType(n) else { return nil }
        return n.intValue
    }
    private static func boolean(_ value: Any?) -> Bool? {
        guard let n = value as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else { return nil }
        return n.boolValue
    }
    static func validKeys(_ keys: [[String: Any]], supported: [String]) -> Bool {
        guard (2...8).contains(keys.count) else { return false }
        return keys.allSatisfy { key in
            guard Set(key.keys) == ["key_code", "characters", "characters_ignoring_modifiers", "modifiers"],
                  let code = integer(key["key_code"]), (0...127).contains(code), !(54...63).contains(code),
                  let modifiers = key["modifiers"] as? [String], modifiers.count <= 1,
                  modifiers.allSatisfy({ supported.contains($0) && ["shift", "control", "option"].contains($0) }) else { return false }
            return ["characters", "characters_ignoring_modifiers"].allSatisfy {
                guard let text = key[$0] as? String else { return false }
                return !text.isEmpty && text.utf16.count <= 8
            }
        }
    }
    static func validResult(_ result: [String: Any], expectedCount: Int? = nil) -> Bool {
        if let expected = expectedCount, let count = result["requested_count"], integer(count) != expected { return false }
        guard result["action"] as? String == "key_sequence",
              boolean(result["sequence_atomic"]) == false,
              result["text_causality"] as? String == "not_attributed",
              result["final_state_evidence"] as? String == "bounded_non_atomic_samples",
              let dispatched = boolean(result["dispatch_attempted"]), let readback = boolean(result["readback_completed"]),
              let prefix = integer(result["completed_prefix_count"]), (0...8).contains(prefix),
              let steps = result["steps"] as? [[String: Any]], steps.count <= 8,
              dispatched == !steps.isEmpty,
              ["not_dispatched", "unknown_intent", "unknown_after_attempt", "unknown_receipt", "bounded_readback"].contains(result["outcome"] as? String ?? "") else { return false }
        var completed = 0
        for (index, step) in steps.enumerated() {
            guard Set(step.keys).isSubset(of: ["index", "down_attempted", "down_returned", "up_attempted", "up_returned", "input_context_down_consumed"]),
                  integer(step["index"]) == index, boolean(step["down_attempted"]) == true,
                  boolean(step["up_attempted"]) == true, let down = boolean(step["down_returned"]),
                  let up = boolean(step["up_returned"]),
                  step["input_context_down_consumed"] == nil || boolean(step["input_context_down_consumed"]) != nil else { return false }
            if down && up { completed += 1 }
            else if index != steps.count - 1 { return false }
        }
        guard prefix == completed else { return false }
        if !steps.isEmpty {
            guard let count = integer(result["requested_count"]), (2...8).contains(count), steps.count <= count,
                  result["key_pair_route"] as? String == "exact_view_input_context",
                  result["key_up_route"] as? String == "original_receiver_key_up" else { return false }
        }
        if let mark = result["final_marked_text"], !(mark is NSNull), boolean(mark) == nil { return false }
        if readback {
            guard let count = integer(result["requested_count"]), prefix == count,
                  boolean(result["final_marked_text"]) == false, result["before"] is [String: Any], result["after"] is [String: Any],
                  result["effect_state"] as? String == "bounded_text_readback",
                  ["bounded_readback", "unknown_receipt"].contains(result["outcome"] as? String ?? "") else { return false }
        } else if result["outcome"] as? String == "bounded_readback" ||
            result["effect_state"] as? String != (dispatched ? "unknown" : "none") { return false }
        return true
    }
    static func validIntent(_ intent: [String: Any], result: [String: Any]) -> Bool {
        guard validResult(result), intent["action"] as? String == "key_sequence",
              Set(intent.keys) == ["binding_id", "once_id", "action", "keys", "before", "state", "observed_monotonic", "deadline_monotonic", "contract"],
              intent["contract"] as? String == "missing_terminal_result_is_unknown_never_replay",
              let keys = intent["keys"] as? [[String: Any]], (2...8).contains(keys.count),
              let state = intent["state"] as? [String: Any], state["receiver_kind"] as? String == "custom_text_input_client",
              let observed = intent["observed_monotonic"] as? NSNumber, CFGetTypeID(observed) != CFBooleanGetTypeID(),
              let deadline = intent["deadline_monotonic"] as? NSNumber, CFGetTypeID(deadline) != CFBooleanGetTypeID(),
              observed.doubleValue.isFinite, observed.doubleValue >= 0, deadline.doubleValue.isFinite,
              deadline.doubleValue > observed.doubleValue, deadline.doubleValue <= observed.doubleValue + 30,
              result["requested_count"] == nil || integer(result["requested_count"]) == keys.count else { return false }
        return keys.allSatisfy { key in
            guard Set(key.keys) == ["key_code", "modifiers", "characters_sha256", "characters_ignoring_modifiers_sha256"],
                  let code = integer(key["key_code"]), (0...127).contains(code), !(54...63).contains(code),
                  let modifiers = key["modifiers"] as? [String], modifiers.count <= 1,
                  modifiers.allSatisfy({ ["shift", "control", "option"].contains($0) }) else { return false }
            return ["characters_sha256", "characters_ignoring_modifiers_sha256"].allSatisfy {
                (key[$0] as? String)?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
            }
        }
    }
}
