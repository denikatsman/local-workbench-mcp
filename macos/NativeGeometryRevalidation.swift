import Foundation
import ApplicationServices

private enum NativeCGWindowMetadata {
    static func integer(_ raw: Any?, minimum: Double, maximum: Double) -> Double? {
        guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let value = number.doubleValue
        return value.isFinite && value >= minimum && value <= maximum
            && value.rounded(.towardZero) == value ? value : nil
    }
    static func bounds(_ raw: Any?) -> NativeRect? {
        guard let dictionary = raw as? NSDictionary,
              ["X", "Y", "Width", "Height"].allSatisfy({ key in
                  guard let value = dictionary[key] as? NSNumber,
                        CFGetTypeID(value) != CFBooleanGetTypeID() else { return false }
                  return value.doubleValue.isFinite
                      && (!["Width", "Height"].contains(key) || value.doubleValue > 0)
              }), let rect = CGRect(dictionaryRepresentation: dictionary) else { return nil }
        let frame = NativeRect(x: rect.origin.x, y: rect.origin.y, width: rect.size.width, height: rect.size.height)
        return frame.finite ? frame : nil
    }
}

extension NativeGeometryCGMapping {
    // Decode inventory metadata without OS reads. AX windows can be floating
    // panels at nonzero CG layers; layer is metadata, not window identity.
    static func fromRows(_ rows: [[String: Any]], ownerPID: Int32, bounds: NativeRect,
                         originalWindowID: UInt32? = nil) -> Self {
        let unavailable = Self(state: .metadataUnavailable, windowID: nil)
        guard ownerPID > 0 else { return unavailable }
        var candidates: [NativeGeometryCGCandidate] = []
        for row in rows {
            // Unknown ownership cannot safely be excluded from ambiguity.
            guard let owner = NativeCGWindowMetadata.integer(row[kCGWindowOwnerPID as String], minimum: 1, maximum: Double(Int32.max)) else {
                return unavailable
            }
            if owner != Double(ownerPID) { continue }
            guard NativeCGWindowMetadata.integer(row[kCGWindowLayer as String], minimum: Double(Int32.min), maximum: Double(Int32.max)) != nil,
                  let number = NativeCGWindowMetadata.integer(row[kCGWindowNumber as String], minimum: 1, maximum: Double(UInt32.max)),
                  let frame = NativeCGWindowMetadata.bounds(row[kCGWindowBounds as String]) else { return unavailable }
            candidates.append(NativeGeometryCGCandidate(windowID: UInt32(number), bounds: frame))
        }
        return classify(candidates, bounds: bounds, originalWindowID: originalWindowID)
    }
}

struct NativeWindowIdentityResult {
    var mapping: NativeGeometryCGMapping
    var diagnostic: NativeWindowIdentityDiagnostic
    var windowID: UInt32? { mapping.windowID }
}

// Pure policy with injected OS reads. A failed present getter never selects a
// geometric sibling. The fallback retains the original unique-geometry policy.
enum NativeWindowIdentity {
    static let maximumSeconds = 0.3
    static let maximumCallSeconds = 0.1
    static func messagingTimeout(remaining: Double) -> Float? {
        guard remaining.isFinite else { return nil }
        let milliseconds = floor(min(maximumCallSeconds, remaining) * 1000)
        guard milliseconds >= 1 else { return nil }
        let seconds = Float(milliseconds / 1000)
        // The current platform converts Float seconds to integer milliseconds.
        return seconds.isFinite && seconds * 1000 >= 1 ? seconds : nil
    }
    static func resolve(ownerPID: Int32, bounds: NativeRect, availability: NativeWindowGetterAvailability,
                        deadline outerDeadline: Double, originalWindowID: UInt32? = nil,
                        now: () -> Double, check: () throws -> Void,
                        configure: (Float) -> Int32, getter: () -> (status: Int32, id: UInt32),
                        inventory: () -> [[String: Any]]?) throws -> NativeWindowIdentityResult {
        let started = now(), deadline = min(outerDeadline, started + maximumSeconds)
        var diagnostic = NativeWindowIdentityDiagnostic(state: .unverified, getterAvailability: availability)
        func result(_ state: NativeWindowIdentityState, _ mapping: NativeGeometryCGMapping =
                    NativeGeometryCGMapping(state: .unverified, windowID: nil)) -> NativeWindowIdentityResult {
            var final = diagnostic; final.state = state
            let elapsed = now() - started
            final.elapsedSeconds = elapsed.isFinite && elapsed >= 0 ? elapsed : nil
            return NativeWindowIdentityResult(mapping: mapping, diagnostic: final)
        }
        func inTime() -> Bool {
            let time = now()
            return started.isFinite && outerDeadline.isFinite && deadline.isFinite && time.isFinite
                && time >= started && messagingTimeout(remaining: deadline - time) != nil
        }
        func checked() throws -> Bool {
            guard inTime() else { return false }
            try check()
            return inTime()
        }
        guard bounds.finite, ownerPID > 0 else { return result(.geometryUnavailable) }
        guard try checked() else { return result(.budgetExhausted) }
        var directID: UInt32?
        if availability == .available {
            guard let seconds = messagingTimeout(remaining: deadline - now()) else { return result(.budgetExhausted) }
            diagnostic.timeoutError = configure(seconds)
            guard try checked() else { return result(.budgetExhausted) }
            guard diagnostic.timeoutError == 0 else { return result(.timeoutSetupFailed) }
            // Recompute admission after setup: never inherit a global timeout
            // from a positive sub-millisecond remainder.
            guard messagingTimeout(remaining: deadline - now()) != nil else { return result(.budgetExhausted) }
            let call = getter()
            diagnostic.axError = call.status
            guard try checked() else { return result(.budgetExhausted) }
            guard call.status == 0 else { return result(.getterError) }
            guard call.id != 0 else { return result(.zeroID) }
            if let original = originalWindowID, call.id != original { return result(.identityChanged) }
            directID = call.id
        }
        guard try checked() else { return result(.budgetExhausted) }
        guard let rows = inventory() else {
            return result(.inventoryUnavailable, NativeGeometryCGMapping(state: .inventoryUnavailable, windowID: nil))
        }
        guard try checked() else { return result(.budgetExhausted) }
        if let number = directID {
            var selected: [[String: Any]] = []
            for row in rows {
                guard let id = NativeCGWindowMetadata.integer(row[kCGWindowNumber as String], minimum: 1,
                    maximum: Double(UInt32.max)) else { return result(.metadataUnavailable) }
                if id == Double(number) { selected.append(row) }
            }
            guard selected.count <= 1 else { return result(.ambiguous, NativeGeometryCGMapping(state: .ambiguous, windowID: nil)) }
            guard let row = selected.first else {
                return result(.identityChanged, NativeGeometryCGMapping(state: .originalWindowMissing, windowID: nil))
            }
            guard let owner = NativeCGWindowMetadata.integer(row[kCGWindowOwnerPID as String], minimum: 1,
                    maximum: Double(Int32.max)), let frame = NativeCGWindowMetadata.bounds(row[kCGWindowBounds as String]) else {
                return result(.metadataUnavailable)
            }
            guard owner == Double(ownerPID) else { return result(.ownerMismatch) }
            diagnostic.candidateWindowID = number
            diagnostic.logicalBounds = bounds
            diagnostic.compositorBounds = frame
            diagnostic.provenance = .privateAXWindowID
            guard frame == bounds else {
                return result(.boundsMismatch, NativeGeometryCGMapping(state: .frameNotPublished, windowID: nil))
            }
            guard try checked() else { return result(.budgetExhausted) }
            return result(.mappedDirect, NativeGeometryCGMapping(state: .matched, windowID: number))
        }
        let mapping = NativeGeometryCGMapping.fromRows(rows, ownerPID: ownerPID, bounds: bounds,
            originalWindowID: originalWindowID)
        guard try checked() else { return result(.budgetExhausted) }
        diagnostic.provenance = .uniqueGeometryFallback
        let state: NativeWindowIdentityState = mapping.state == .matched ? .mappedFallback
            : mapping.state == .ambiguous ? .ambiguous
            : mapping.state == .metadataUnavailable ? .metadataUnavailable : .unverified
        return result(state, mapping)
    }
}

// Pure admission policy. The driver supplies fresh AX reads and the SDK's
// cannotComplete value; this code never reads AX or dispatches input itself.
enum NativeGeometryValueState: String {
    case decoded, axError, noValue, wrongType, wrongValueType, conversionFailed
    case nonfinite, invalidDimensions, notRead, timeoutSetupFailed
}

struct NativeGeometryAttributeRead {
    let error: Int32?
    let state: NativeGeometryValueState
    let value: NativePoint?
    let cfType: UInt?
    let axValueType: UInt32?
    let timeoutError: Int32?

    init(error: Int32? = 0, state: NativeGeometryValueState = .decoded, value: NativePoint? = nil,
         cfType: UInt? = nil, axValueType: UInt32? = nil, timeoutError: Int32? = nil) {
        self.error = error; self.state = state; self.value = value
        self.cfType = cfType; self.axValueType = axValueType; self.timeoutError = timeoutError
    }
    var decoded: Bool {
        error == 0 && state == .decoded && value?.x.isFinite == true && value?.y.isFinite == true
    }
    func transient(_ cannotComplete: Int32) -> Bool { state == .axError && error == cannotComplete }
    var diagnostic: [String: Any] {
        ["ax_error": error as Any? ?? NSNull(), "value_state": state.rawValue,
         "returned_cf_type": cfType as Any? ?? NSNull(), "ax_value_type": axValueType as Any? ?? NSNull(),
         "timeout_setup_error": timeoutError as Any? ?? NSNull(),
         "value": value.map { ["x": $0.x.isFinite ? $0.x as Any : NSNull(),
                                "y": $0.y.isFinite ? $0.y as Any : NSNull()] } as Any? ?? NSNull()]
    }
    // CF decoding is separate from AX messaging so malformed/type/nonfinite
    // values can be verified without contacting an application.
    static func decode(_ raw: CFTypeRef?, result: AXError, expected: AXValueType,
                       timeoutResult: AXError = .success) -> Self {
        guard timeoutResult == .success else {
            return Self(error: nil, state: .timeoutSetupFailed, timeoutError: timeoutResult.rawValue)
        }
        guard result == .success else {
            return Self(error: result.rawValue, state: .axError, timeoutError: timeoutResult.rawValue)
        }
        guard let raw = raw else { return Self(state: .noValue, timeoutError: timeoutResult.rawValue) }
        let cfType = CFGetTypeID(raw)
        guard cfType == AXValueGetTypeID() else {
            return Self(state: .wrongType, cfType: cfType, timeoutError: timeoutResult.rawValue)
        }
        let axValue = raw as! AXValue, actualType = AXValueGetType(axValue)
        guard expected == .cgPoint || expected == .cgSize, actualType == expected else {
            return Self(state: .wrongValueType, cfType: cfType, axValueType: actualType.rawValue,
                        timeoutError: timeoutResult.rawValue)
        }
        var value: NativePoint
        if expected == .cgPoint {
            var point = CGPoint.zero
            guard AXValueGetValue(axValue, expected, &point) else {
                return Self(state: .conversionFailed, cfType: cfType, axValueType: actualType.rawValue,
                            timeoutError: timeoutResult.rawValue)
            }
            value = NativePoint(x: point.x, y: point.y)
        } else {
            var size = CGSize.zero
            guard AXValueGetValue(axValue, expected, &size) else {
                return Self(state: .conversionFailed, cfType: cfType, axValueType: actualType.rawValue,
                            timeoutError: timeoutResult.rawValue)
            }
            value = NativePoint(x: size.width, y: size.height)
        }
        let state: NativeGeometryValueState = !value.x.isFinite || !value.y.isFinite ? .nonfinite
            : expected == .cgSize && (value.x <= 0 || value.y <= 0) ? .invalidDimensions : .decoded
        return Self(state: state, value: value, cfType: cfType, axValueType: actualType.rawValue,
                    timeoutError: timeoutResult.rawValue)
    }
}

struct NativeGeometryRead {
    let position: NativeGeometryAttributeRead
    let size: NativeGeometryAttributeRead
    var bounds: NativeRect? {
        guard position.decoded, size.decoded, let p = position.value, let s = size.value else { return nil }
        return NativeRect(x: p.x, y: p.y, width: s.x, height: s.y)
    }
    func transientOnly(_ cannotComplete: Int32) -> Bool {
        let positionValid = position.decoded || position.transient(cannotComplete)
        let sizeValid = (size.decoded && (size.value?.x ?? 0) > 0 && (size.value?.y ?? 0) > 0)
            || size.transient(cannotComplete)
        return positionValid && sizeValid && (position.transient(cannotComplete) || size.transient(cannotComplete))
    }
    var diagnostic: [String: Any] { ["position": position.diagnostic, "size": size.diagnostic] }
}

struct NativeGeometryRevalidationPolicy {
    var maximumAttempts = 3
    var totalSeconds = 0.5
    var maximumAttributeSeconds = 0.1
}

// Failure-only projection of an already computed trace. Never retain geometry,
// identities or the original dictionary; this does not perform an OS read.
struct NativeGeometryFailure {
    static let reasonCodes: [String: String] = [
        "deadline": "native_window_geometry_unavailable",
        "position_changed": "native_window_moved", "size_changed": "native_window_moved",
        "bounds_changed": "native_window_moved",
        "nonfinite_or_invalid_dimensions": "native_window_geometry_unavailable",
        "cg_identity_changed": "native_window_identity_changed",
        "non_retryable_read": "native_window_geometry_unavailable",
        "attempt_limit": "native_window_geometry_unavailable"]
    let value: [String: Any]
    let errorCode: String
    private static func integer(_ raw: Any?, _ range: ClosedRange<Int>) -> Int? {
        guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              !["d", "f"].contains(String(cString: number.objCType)),
              number.doubleValue >= Double(range.lowerBound), number.doubleValue <= Double(range.upperBound),
              number.doubleValue == Double(number.intValue) else { return nil }
        return number.intValue
    }
    private static func seconds(_ raw: Any?, maximum: Double, positive: Bool = false) -> Double? {
        guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite, number.doubleValue <= maximum,
              positive ? number.doubleValue > 0 : number.doubleValue >= 0 else { return nil }
        return number.doubleValue
    }
    private static func attribute(_ raw: Any?) -> [String: Any]? {
        guard let row = raw as? [String: Any], let state = row["value_state"] as? String,
              NativeGeometryValueState(rawValue: state) != nil else { return nil }
        var result: [String: Any] = ["value_state": state]
        for key in ["ax_error", "timeout_setup_error"] {
            guard let raw = row[key] else { return nil }
            if raw is NSNull { result[key] = NSNull() }
            else if let code = integer(raw, Int(Int32.min)...Int(Int32.max)) { result[key] = code }
            else { return nil }
        }
        return result
    }
    init?(_ row: [String: Any]) {
        guard row["kind"] as? String == "window_validation_failure",
              let recovered = row["read_recovered"] as? NSNumber,
              CFGetTypeID(recovered) == CFBooleanGetTypeID(), !recovered.boolValue,
              row["admission"] as? String == "refused", let reason = row["reason"] as? String,
              let code = row["error_code"] as? String,
              NativePointerFailureSummary.permitsFailureReason(code) || code == "native_geometry_guard_failed",
              reason == "guard_refused" || Self.reasonCodes[reason] == code,
              let maximum = Self.integer(row["maximum_attempts"], 1...3),
              let total = Self.seconds(row["total_seconds"], maximum: 0.5, positive: true),
              let limit = Self.seconds(row["maximum_attribute_seconds"], maximum: 0.1, positive: true),
              let rawElapsed = row["elapsed_seconds"], let samples = row["attempts"] as? [[String: Any]],
              samples.count <= maximum else { return nil }
        let elapsed: Any
        if rawElapsed is NSNull { elapsed = NSNull() }
        else if let seconds = Self.seconds(rawElapsed, maximum: 9_007_199_254_740_991) { elapsed = seconds }
        else { return nil }
        var attempts: [[String: Any]] = []
        for (index, sample) in samples.enumerated() {
            guard Self.integer(sample["attempt"], 1...3) == index + 1,
                  let read = sample["read"] as? [String: Any],
                  let position = Self.attribute(read["position"]), let size = Self.attribute(read["size"]) else { return nil }
            attempts.append(["attempt": index + 1, "position": position, "size": size])
        }
        let projected: [String: Any] = ["reason": reason, "error_code": code, "attempt_count": attempts.count,
            "maximum_attempts": maximum, "elapsed_seconds": elapsed, "total_seconds": total,
            "maximum_attribute_seconds": limit, "attempts": attempts]
        guard let encoded = try? JSONSerialization.data(withJSONObject: projected), encoded.count <= 4096 else { return nil }
        value = projected; errorCode = code
    }
}

enum NativeGeometryRevalidation {
    static func validate(expected: NativeRect, expectedCG: UInt32, cannotComplete: Int32,
                         policy: NativeGeometryRevalidationPolicy = NativeGeometryRevalidationPolicy(),
                         now: () -> Double, check: (_ deadline: Double) throws -> Void,
                         read: (_ deadline: Double, _ attributeLimit: Double) -> NativeGeometryRead,
                         mappedCG: (_ bounds: NativeRect, _ deadline: Double) -> UInt32?, trace: ([String: Any]) -> Void) throws {
        guard expected.finite, expectedCG > 0,
              (1...3).contains(policy.maximumAttempts), policy.totalSeconds.isFinite,
              policy.totalSeconds > 0, policy.totalSeconds <= 0.5,
              policy.maximumAttributeSeconds.isFinite, policy.maximumAttributeSeconds > 0,
              policy.maximumAttributeSeconds <= 0.1 else { throw NativeFailure("native_geometry_policy_invalid", "unknown") }
        let started = now(), deadline = started + policy.totalSeconds
        guard started.isFinite, deadline.isFinite else { throw NativeFailure("native_geometry_clock_invalid", "unknown") }
        var samples: [[String: Any]] = [], current: NativeRect?, currentCG: UInt32?, cgLookup = "not_read"
        func inTime() -> Bool {
            let time = now()
            return time.isFinite && time >= started
                && NativeWindowIdentity.messagingTimeout(remaining: deadline - time) != nil
        }
        func diagnostic(_ reason: String, code: String?, recovered: Bool = false) {
            let elapsed = now() - started
            trace(["kind": recovered ? "window_geometry_revalidated" : "window_validation_failure",
                "reason": reason, "error_code": code as Any? ?? NSNull(), "read_recovered": recovered,
                "admission": recovered ? "pending_final_guard" : "refused",
                "expected_bounds": nativeDictionary(expected),
                "current_bounds": current.map(nativeDictionary) as Any? ?? NSNull(),
                "expected_cg_window_id": expectedCG, "current_cg_window_id": currentCG as Any? ?? NSNull(),
                "cg_lookup_state": cgLookup,
                "elapsed_seconds": elapsed.isFinite ? elapsed as Any : NSNull(),
                "maximum_attempts": policy.maximumAttempts, "total_seconds": policy.totalSeconds,
                "maximum_attribute_seconds": policy.maximumAttributeSeconds, "attempts": samples])
        }
        func fail(_ reason: String, _ code: String = "native_window_geometry_unavailable") throws -> Never {
            diagnostic(reason, code: code)
            throw NativeFailure(code, "unknown")
        }
        func checked(recordFailure: Bool = true) throws {
            guard inTime() else {
                if recordFailure { try fail("deadline") }
                throw NativeFailure("native_window_geometry_unavailable", "unknown")
            }
            do { try check(deadline) }
            catch {
                if recordFailure { diagnostic("guard_refused", code: (error as? NativeFailure)?.code ?? "native_geometry_guard_failed") }
                throw error
            }
            guard inTime() else {
                if recordFailure { try fail("deadline") }
                throw NativeFailure("native_window_geometry_unavailable", "unknown")
            }
        }
        for attempt in 1...policy.maximumAttempts {
            try checked()
            let observation = read(deadline, policy.maximumAttributeSeconds)
            current = observation.bounds; currentCG = nil; cgLookup = "not_read"
            samples.append(["attempt": attempt, "read": observation.diagnostic])
            guard inTime() else { try fail("deadline") }
            // Cancellation/identity/permission can change during a blocking read.
            try checked()
            // One fresh decoded component can already prove movement, even if
            // the other attribute is temporarily unavailable. Never retry it.
            if observation.position.decoded, let position = observation.position.value,
               position.x != expected.x || position.y != expected.y {
                cgLookup = "not_read_position_changed"
                try fail("position_changed", "native_window_moved")
            }
            if observation.size.decoded, let size = observation.size.value, size.x > 0, size.y > 0,
               size.x != expected.width || size.y != expected.height {
                cgLookup = "not_read_size_changed"
                try fail("size_changed", "native_window_moved")
            }
            if let bounds = current {
                guard bounds.finite else { try fail("nonfinite_or_invalid_dimensions") }
                guard bounds == expected else {
                    cgLookup = "not_read_bounds_changed"
                    try fail("bounds_changed", "native_window_moved")
                }
                currentCG = mappedCG(bounds, deadline)
                cgLookup = currentCG == nil ? "unresolved" : "mapped"
                guard inTime() else { try fail("deadline") }
                guard currentCG == expectedCG else { try fail("cg_identity_changed", "native_window_identity_changed") }
                try checked()
                if samples.count > 1 { diagnostic("transient_read_recovered", code: nil, recovered: true) }
                // Logging/observer work is inside the same admission budget.
                // A recovery summary is read evidence, not final authority;
                // keep one summary row if the final guard now refuses.
                try checked(recordFailure: samples.count == 1)
                return
            }
            guard observation.transientOnly(cannotComplete) else { try fail("non_retryable_read") }
            if attempt == policy.maximumAttempts { try fail("attempt_limit") }
        }
    }
}
