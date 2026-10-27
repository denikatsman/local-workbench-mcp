import Foundation
import ApplicationServices

enum NativeAttachedSheetPolicy {
    static func retainedWindows(_ windows: Set<String>, parents: [String: String]) -> Set<String> {
        windows.union(windows.compactMap { parents[$0] })
    }
    // A sheet cannot inherit a root's CG identity, nor be admitted through the
    // ordinary unique-geometry fallback on unsupported getter platforms.
    static func independentIdentity(parentID: UInt32?, parent: NativeWindowIdentityDiagnostic,
                                    sheetID: UInt32?, sheet: NativeWindowIdentityDiagnostic) -> Bool {
        parentID != nil && sheetID != nil && parentID != sheetID
            && parent.state == .mappedDirect && sheet.state == .mappedDirect
            && parent.provenance == .privateAXWindowID && sheet.provenance == .privateAXWindowID
    }
    static func captureLayout(bounds: NativeRect, frame: NativeRect, content: NativeRect,
                              scale: Double, candidates: Int, included: [UInt32], number: UInt32) -> Bool {
        bounds.finite && frame == bounds && content.finite && candidates == 1 && included == [number]
            && content.width == bounds.width && content.height == bounds.height
            && ((content.x == 0 && content.y == 0) || (content.x == bounds.x && content.y == bounds.y))
            && scale.isFinite && scale > 0 && scale <= 8
    }
}

struct NativeWindowInventoryRead<Element> {
    let elements: [Element]?
    let error: Int32
    let timeoutError: Int32
    let state: String
    let cfType: UInt?
    var diagnostic: [String: Any] {
        ["error": error, "timeout_error": timeoutError, "state": state,
         "count": elements?.count as Any? ?? NSNull(), "cf_type": cfType as Any? ?? NSNull()]
    }
}
enum NativeWindowInventory {
    // Preserve already enumerated ordinary windows before spending any time
    // on supplemental sheets. All phases share the original total deadline;
    // supplemental AX calls have only this small cooperative admission budget.
    static func materializeThenSupplement<Element>(elements: [Element], deadline: Double,
        now: () -> Double, same: (Element, Element) -> Bool,
        materialize: (Element, Int) throws -> Bool,
        supplement: ([Element], Double) throws -> (elements: [Element], complete: Bool)) rethrows
        -> (elements: [Element], supplementComplete: Bool, budgetExhausted: Bool) {
        var produced: [Element] = [], result = elements, attempts = 0
        for element in elements.prefix(30) {
            guard now() < deadline else { return (result, false, true) }
            if try materialize(element, attempts) { produced.append(element) }
            attempts += 1
        }
        guard now() < deadline else { return (result, false, true) }
        let extra = try supplement(Array(elements.prefix(30)), min(deadline, now() + 0.3))
        var complete = extra.complete && elements.count <= 30
        for element in extra.elements {
            if !result.contains(where: { same($0, element) }) {
                guard result.count < 30 else { complete = false; continue }
                result.append(element)
            }
            if produced.contains(where: { same($0, element) }) { continue }
            guard attempts < 30, now() < deadline else { complete = false; break }
            if try materialize(element, attempts) { produced.append(element) }
            attempts += 1
        }
        return (result, complete, now() >= deadline)
    }

    static func suppressAmbiguousMappings(_ windows: [NativeWindow], previouslyBlocked: Set<String> = []) -> (windows: [NativeWindow], blocked: Set<String>) {
        let groups = Dictionary(grouping: windows.filter { $0.cgWindowID != nil }, by: { $0.cgWindowID! })
        let ambiguous = Set(groups.filter { Set($0.value.map(\.id)).count > 1 }.keys)
        let blocked = previouslyBlocked.union(windows.filter { $0.cgWindowID.map(ambiguous.contains) == true }.map(\.id))
        return (windows.map { window in
            var result = window
            if blocked.contains(result.id) { result.cgWindowID = nil }
            return result
        }, blocked)
    }
    static func anchorCandidates<Element>(deadline: Double, maximumSeconds: Double, now: () -> Double,
        check: () throws -> Void, read: (String, Float) -> (element: Element?, diagnostic: [String: Any]),
        validate: (Element, Float) -> (valid: Bool, diagnostic: [String: Any]),
        same: (Element, Element) -> Bool) throws -> (elements: [Element], diagnostics: [[String: Any]]) {
        let start = now()
        guard start.isFinite, deadline.isFinite, maximumSeconds.isFinite, maximumSeconds > 0 else {
            throw NativeFailure("native_window_anchor_deadline")
        }
        func remaining() throws -> Float {
            let time = now(), seconds = min(maximumSeconds, deadline - time), converted = Float(seconds)
            guard time.isFinite, time >= start, seconds.isFinite, seconds > 0, converted.isFinite, converted > 0 else {
                throw NativeFailure("native_window_anchor_deadline")
            }
            return converted
        }
        var elements: [Element] = [], diagnostics: [[String: Any]] = []
        for name in [kAXMainWindowAttribute, kAXFocusedWindowAttribute] {
            try check()
            let sample = read(name, try remaining())
            try check(); _ = try remaining()
            var diagnostic = sample.diagnostic
            if let element = sample.element {
                let validation = validate(element, try remaining())
                try check(); _ = try remaining()
                diagnostic.merge(validation.diagnostic) { _, new in new }
                if validation.valid { elements = appendUnique(elements, element, same: same) }
            }
            diagnostics.append(diagnostic)
        }
        return (elements, diagnostics)
    }
    static func appendUnique<Element>(_ existing: [Element], _ candidate: Element,
                                      same: (Element, Element) -> Bool) -> [Element] {
        existing.contains(where: { same($0, candidate) }) ? existing : existing + [candidate]
    }
    static func anchors(application: AXUIElement, pid: Int32, deadline: Double, maximumSeconds: Double,
                        check: () throws -> Void) throws -> (elements: [AXUIElement], diagnostics: [[String: Any]]) {
        try anchorCandidates(deadline: deadline, maximumSeconds: maximumSeconds,
            now: { ProcessInfo.processInfo.systemUptime }, check: check, read: { name, seconds in
            let configured = AXUIElementSetMessagingTimeout(application, seconds)
            var raw: CFTypeRef?
            let status = configured == .success ? AXUIElementCopyAttributeValue(application, name as CFString, &raw) : configured
            var diagnostic: [String: Any] = ["attribute": name, "error": status.rawValue, "timeout_error": configured.rawValue]
            guard status == .success, let raw = raw else {
                diagnostic["state"] = status == .attributeUnsupported || status == .noValue ? "absent" : "unavailable"
                return (nil, diagnostic)
            }
            guard CFGetTypeID(raw) == AXUIElementGetTypeID() else {
                diagnostic["state"] = "wrong_type"; return (nil, diagnostic)
            }
            return ((raw as! AXUIElement), diagnostic)
        }, validate: { element, seconds in
            validateReference(element, pid: pid, seconds: seconds)
        }, same: CFEqual)
    }
    static func validateReference(_ element: AXUIElement, pid: Int32, seconds: Float) -> (valid: Bool, diagnostic: [String: Any]) {
        guard seconds.isFinite, seconds > 0, seconds * 1000 >= 1 else {
            return (false, ["state": "reference_budget_exhausted"])
        }
        var owner: pid_t = 0
        let ownerStatus = AXUIElementGetPid(element, &owner)
        let timeout = AXUIElementSetMessagingTimeout(element, seconds)
        var role: CFTypeRef?
        let roleStatus = timeout == .success ? AXUIElementCopyAttributeValue(element, kAXRoleAttribute as CFString, &role) : timeout
        let valid = ownerStatus == .success && owner == pid && roleStatus == .success && role as? String == kAXWindowRole
        return (valid, ["pid_error": ownerStatus.rawValue, "role_error": roleStatus.rawValue,
            "timeout_error": timeout.rawValue, "state": valid ? "validated_window_reference" : "owner_or_role_unverified"])
    }
    static func read<Element>(cannotComplete: Int32, now: () -> Double,
        check: () throws -> Void, read: (Double) -> NativeWindowInventoryRead<Element>,
        trace: ([String: Any]) -> Void) throws -> [Element] {
        let start = now(), deadline = start + 0.6
        guard start.isFinite, deadline.isFinite else { throw NativeFailure("native_window_inventory_clock_invalid") }
        var attempts: [[String: Any]] = []
        func inTime() -> Bool { let time = now(); return time.isFinite && time >= start && time < deadline }
        func report(_ state: String) {
            let elapsed = now() - start
            trace(["state": state, "attempts": attempts, "maximum_attempts": 3,
                   "maximum_seconds": 0.6, "elapsed_seconds": elapsed.isFinite ? elapsed as Any : NSNull(),
                   "scope": "fresh_accessibility_window_inventory", "cached_windows_used": false])
        }
        for _ in 0..<3 {
            guard inTime() else { report("deadline"); throw NativeFailure("native_windows_unavailable") }
            do { try check() } catch { report("guard_refused"); throw error }
            guard inTime() else { report("deadline"); throw NativeFailure("native_windows_unavailable") }
            let readAt = now(), remaining = deadline - readAt
            guard readAt.isFinite, readAt >= start, remaining.isFinite, remaining > 0 else {
                report("deadline"); throw NativeFailure("native_windows_unavailable")
            }
            let sample = read(min(0.2, remaining))
            attempts.append(sample.diagnostic)
            guard inTime() else { report("deadline"); throw NativeFailure("native_windows_unavailable") }
            do { try check() } catch { report("guard_refused"); throw error }
            guard inTime() else { report("deadline"); throw NativeFailure("native_windows_unavailable") }
            if sample.error == 0, sample.timeoutError == 0, sample.state == "decoded", let elements = sample.elements {
                report(attempts.count == 1 ? "read" : "transient_read_recovered")
                return elements
            }
            // Only a messaging failure may be retried. Absence, access denial,
            // bad type/elements or a timeout-setup failure remain unavailable.
            guard sample.timeoutError == 0, sample.error == cannotComplete, sample.state == "ax_error" else {
                report("unavailable"); throw NativeFailure("native_windows_unavailable")
            }
        }
        report("attempt_limit"); throw NativeFailure("native_windows_unavailable")
    }
    static func decode(_ raw: CFTypeRef?, error: AXError, timeoutError: AXError) -> NativeWindowInventoryRead<AXUIElement> {
        func value(_ state: String, _ type: UInt? = nil, _ elements: [AXUIElement]? = nil) -> NativeWindowInventoryRead<AXUIElement> {
            NativeWindowInventoryRead(elements: elements, error: error.rawValue, timeoutError: timeoutError.rawValue, state: state, cfType: type)
        }
        guard timeoutError == .success else { return value("timeout_setup_failed") }
        guard error == .success else { return value("ax_error") }
        guard let raw = raw else { return value("no_value") }
        let type = CFGetTypeID(raw)
        guard type == CFArrayGetTypeID(), let array = raw as? [Any], array.count <= 100 else { return value("wrong_type_or_limit", type) }
        var elements: [AXUIElement] = []
        for entry in array {
            let object = entry as CFTypeRef
            guard CFGetTypeID(object) == AXUIElementGetTypeID() else { return value("wrong_element_type", type) }
            elements.append(object as! AXUIElement)
        }
        return value("decoded", type, elements)
    }
}
