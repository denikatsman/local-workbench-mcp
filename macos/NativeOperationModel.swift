import Foundation
import CoreFoundation
import CryptoKit

/// A finite operation suspended on its existing serial lane. Starting and every
/// completion run on that lane; timers may only enqueue the retained step.
/// Internal control flow, never a public protocol result or retry instruction.
final class NativeDeferred<Value>: Error {
    typealias Completion = (Result<Value, Error>) -> Void
    private var body: ((@escaping Completion) -> Void)?
    init(_ body: @escaping (@escaping Completion) -> Void) { self.body = body }
    func start(_ completion: @escaping Completion) {
        guard let body = body else { return }
        self.body = nil
        var completed = false
        body { result in
            guard !completed else { return }
            completed = true
            completion(result)
        }
    }
    func mapResult<Next>(_ transform: @escaping (Result<Value, Error>) throws -> Next) -> NativeDeferred<Next> {
        NativeDeferred<Next> { completion in
            self.start { result in completion(Result { try transform(result) }) }
        }
    }
}

struct NativeRect: Codable, Equatable {
    var x: Double, y: Double, width: Double, height: Double
    func contains(_ point: NativePoint) -> Bool {
        point.x >= x && point.y >= y && point.x < x + width && point.y < y + height
    }
    var finite: Bool { [x, y, width, height].allSatisfy(\.isFinite) && width > 0 && height > 0 }
}
enum NativePointerClickModifiers {
    static let allowed: Set<String> = ["command", "control", "option", "shift"]
    static func validate(_ modifiers: [String]) throws {
        guard modifiers.count <= 4, Set(modifiers).count == modifiers.count,
              Set(modifiers).isSubset(of: allowed) else {
            throw NativeFailure("native_pointer_modifiers_invalid")
        }
    }
}

struct NativePoint: Codable, Equatable { var x: Double, y: Double }
struct NativeDrag: Equatable {
    let end: NativePoint
    let steps: Int
    func path(from start: NativePoint) throws -> [NativePoint] {
        guard (2...16).contains(steps), start != end,
              [start.x, start.y, end.x, end.y].allSatisfy(\.isFinite) else {
            throw NativeFailure("native_drag_invalid")
        }
        let points = (1...steps).map { step -> NativePoint in
            if step == steps { return end }
            let fraction = Double(step) / Double(steps)
            return NativePoint(x: (1 - fraction) * start.x + fraction * end.x,
                               y: (1 - fraction) * start.y + fraction * end.y)
        }
        guard points.allSatisfy({ $0.x.isFinite && $0.y.isFinite }) else { throw NativeFailure("native_drag_invalid") }
        return points
    }
}
struct NativeSize: Codable, Equatable {
    var width: Double, height: Double
    var valid: Bool { width.isFinite && height.isFinite && width > 0 && height > 0 }
}
enum NativeWindowGeometryMutation {
    case move(NativePoint), resize(NativeSize)
    var action: String { if case .move = self { return "move" }; return "resize" }
    var attribute: String { if case .move = self { return "AXPosition" }; return "AXSize" }
    func requested(_ before: NativeRect) -> NativeRect {
        switch self {
        case .move(let p): return NativeRect(x: p.x, y: p.y, width: before.width, height: before.height)
        case .resize(let s): return NativeRect(x: before.x, y: before.y, width: s.width, height: s.height)
        }
    }
}
struct NativeWindowGeometrySnapshot: Codable, Equatable {
    var windowID: String, bounds: NativeRect, cgWindowID: UInt32?
    func requireMatch(_ current: NativeWindowGeometrySnapshot) throws {
        guard windowID == current.windowID, cgWindowID != nil, cgWindowID == current.cgWindowID else {
            throw NativeFailure("native_window_identity_changed")
        }
        guard bounds == current.bounds else { throw NativeFailure("native_window_moved") }
    }
}
struct NativeGeometrySetterResult {
    var attempted: Bool, dispatchResult: Int32?, capabilityResult: Int32?, settable: Bool?
}
enum NativeGeometryMappingState: String {
    case matched = "matched"
    case frameNotPublished = "frame_not_published"
    case ambiguous = "ambiguous"
    case inventoryUnavailable = "inventory_unavailable"
    case metadataUnavailable = "metadata_unavailable"
    case originalWindowMissing = "original_window_missing"
    case unverified = "unverified"
}
struct NativeGeometryCGCandidate {
    var windowID: UInt32, bounds: NativeRect
}
struct NativeGeometryCGMapping {
    var state: NativeGeometryMappingState, windowID: UInt32?
    static func classify(_ candidates: [NativeGeometryCGCandidate], bounds: NativeRect,
                         originalWindowID: UInt32?) -> NativeGeometryCGMapping {
        guard bounds.finite, candidates.allSatisfy({ $0.windowID != 0 && $0.bounds.finite }) else {
            return NativeGeometryCGMapping(state: .metadataUnavailable, windowID: nil)
        }
        let ids = candidates.map { $0.windowID }
        guard Set(ids).count == ids.count else { return NativeGeometryCGMapping(state: .ambiguous, windowID: nil) }
        let matches = candidates.filter {
            abs($0.bounds.x - bounds.x) < 1 && abs($0.bounds.y - bounds.y) < 1
                && abs($0.bounds.width - bounds.width) < 1 && abs($0.bounds.height - bounds.height) < 1
        }
        if matches.count > 1 { return NativeGeometryCGMapping(state: .ambiguous, windowID: nil) }
        if let original = originalWindowID, !ids.contains(original) {
            return NativeGeometryCGMapping(state: .originalWindowMissing, windowID: nil)
        }
        if let match = matches.first { return NativeGeometryCGMapping(state: .matched, windowID: match.windowID) }
        // Only a still-present original window with unmatched geometry may
        // settle. Missing/ambiguous metadata is never turned into authority.
        return NativeGeometryCGMapping(state: originalWindowID == nil ? .unverified : .frameNotPublished, windowID: nil)
    }
}
struct NativeWindowGeometryReadback {
    var snapshot: NativeWindowGeometrySnapshot, mappingState: NativeGeometryMappingState
    var attempts: Int = 1, snapshotAttempt: Int = 1, elapsedSeconds: Double = 0, budgetExhausted: Bool = false
    var terminalErrorCode: String? = nil
}
enum NativeGeometryReadbackPoll {
    static let maximumSeconds = 0.5
    static let maximumAttempts = 12
    static func read(now: () -> Double, check: () throws -> Void,
                     sample: (Double) throws -> (NativeWindowGeometrySnapshot, NativeGeometryMappingState),
                     wait: (Double) -> Void) throws -> NativeWindowGeometryReadback {
        let started = now(), deadline = started + maximumSeconds
        var last: NativeWindowGeometryReadback?, sampleAttempts = 0
        for attempt in 1...maximumAttempts {
            do {
                try check()
                guard now() < deadline else {
                    guard var result = last else { throw NativeFailure("native_geometry_readback_unavailable") }
                    result.elapsedSeconds = max(0, now() - started); result.budgetExhausted = true; return result
                }
                sampleAttempts += 1
                let (snapshot, state) = try sample(deadline)
                last = NativeWindowGeometryReadback(snapshot: snapshot, mappingState: state,
                    attempts: sampleAttempts, snapshotAttempt: sampleAttempts,
                    elapsedSeconds: max(0, now() - started), budgetExhausted: now() >= deadline)
                try check()
                var result = last!
                result.elapsedSeconds = max(0, now() - started)
                result.budgetExhausted = now() >= deadline
                last = result
                if state != .frameNotPublished || result.budgetExhausted { return result }
                if attempt == maximumAttempts { result.budgetExhausted = true; return result }
                wait(min(0.01, max(0, deadline - now())))
            } catch {
                guard var result = last else { throw error }
                result.attempts = sampleAttempts
                result.elapsedSeconds = max(0, now() - started)
                result.budgetExhausted = now() >= deadline
                result.terminalErrorCode = (error as? NativeFailure)?.code ?? "native_geometry_readback_unavailable"
                return result
            }
        }
        throw NativeFailure("native_geometry_readback_unavailable")
    }
}
struct NativeWheelDelta: Codable, Equatable {
    var x: Int32, y: Int32
    var valid: Bool { abs(Int64(x)) <= 2000 && abs(Int64(y)) <= 2000 && (x != 0 || y != 0) }
}
struct NativeAppIdentity: Codable, Equatable {
    var bundleID: String, bundlePath: String, executable: String
    var pid: Int32, launchedAt: Double
    var signingIdentifier: String?, teamID: String?, designatedRequirement: String?
    var processGeneration: String? = nil
}
struct NativeIdentityDiagnostic: Codable, Equatable {
    var stage: String
    var status: Int32? = nil
    var fields: [String] = []
    var checkedAt: Double? = nil
    var processProbeJSON: String? = nil
    static func differences(_ expected: NativeAppIdentity, _ actual: NativeAppIdentity) -> [String] {
        var fields: [String] = []
        if expected.bundleID != actual.bundleID { fields.append("bundle_id") }
        if expected.bundlePath != actual.bundlePath { fields.append("bundle_path") }
        if expected.executable != actual.executable { fields.append("executable") }
        if expected.pid != actual.pid { fields.append("pid") }
        if expected.launchedAt != actual.launchedAt { fields.append("launched_at") }
        if expected.signingIdentifier != actual.signingIdentifier { fields.append("signing_identifier") }
        if expected.teamID != actual.teamID { fields.append("team_id") }
        if expected.designatedRequirement != actual.designatedRequirement { fields.append("designated_requirement") }
        if expected.processGeneration != actual.processGeneration { fields.append("process_generation") }
        return fields
    }
}
/// Read-only public AXURL metadata, never a filesystem or destination authority.
struct NativeFileURLMetadata: Codable, Equatable {
    static let maximumBytes = 4096
    var state: String
    var original: String? = nil
    var axError: Int32? = nil
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.state == rhs.state && lhs.axError == rhs.axError
            && NativeTextRange.sameText(lhs.original, rhs.original)
    }
}
struct NativeControl: Codable, Equatable {
    var id: String, role: String?, label: String
    var value: String?, valueType: String?, secure: Bool, valueTruncated: Bool
    var enabled: Bool, focused: Bool, bounds: NativeRect?, actions: [String], valueSettable: Bool
    var selectedRange: NativeTextRange? = nil
    var selectedRangeSettable: Bool = false
    var selectedTextSettable: Bool = false
    // Opaque identity of the exact AX ancestry used by semantic text editing.
    // A same-window shared editor moving between containers gets a new token.
    var textRouteID: String? = nil
    // Verified AXWindow attribute provenance, separate from the app's label.
    var windowAttribute: String? = nil
    var fileURL: NativeFileURLMetadata? = nil
    var hasTextSelectionCapability: Bool {
        !secure && !valueTruncated && valueType == "text"
            && (selectedRangeSettable || selectedTextSettable && selectedRange != nil)
    }
}
struct NativeTextRange: Codable, Equatable {
    var location: Int, length: Int
    static func sameText(_ left: String?, _ right: String?) -> Bool {
        switch (left, right) {
        case let (a?, b?): return a.utf16.elementsEqual(b.utf16)
        case (nil, nil): return true
        default: return false
        }
    }
    func valid(in text: String) -> Bool {
        guard location >= 0, length >= 0, location <= 32768, length <= 32768 else { return false }
        let units = Array(text.utf16)
        guard location <= units.count, length <= units.count - location else { return false }
        func boundary(_ offset: Int) -> Bool {
            offset == 0 || offset == units.count || !(0xDC00...0xDFFF).contains(units[offset])
                || !(0xD800...0xDBFF).contains(units[offset - 1])
        }
        return boundary(location) && boundary(location + length)
    }
}
struct NativeTreeNode: Codable, Equatable {
    var id: String, parentID: String?, childIndex: Int, depth: Int
    var element: NativeControl
    var childrenState: String
}
struct NativeTreeObservation: Codable, Equatable {
    var nodes: [NativeTreeNode], complete: Bool
    var omissions: [String]
    var startedAt: Double, finishedAt: Double
    var maximumNodes: Int, maximumDepth: Int, maximumSeconds: Double
    var maximumBytes: Int = 196608
}
struct NativeObservationScope: Codable, Equatable {
    let kind: String, root_control_id: String, source_observation_id: String
    let scoped_hops: Int
    let whole_window_complete: Bool
    let predecessor_must_be_current: Bool
    let maximum_ancestry_nodes: Int
}
struct NativeWindow: Codable, Equatable {
    var id: String, title: String, bounds: NativeRect, focused: Bool
    var controls: [NativeControl], nodesVisited: Int, incomplete: Bool
    var cgWindowID: UInt32?
    var routeRevision: String? = nil
    var observationScope: NativeObservationScope? = nil
    var tree: NativeTreeObservation? = nil
    var positionSettable: Bool? = nil, sizeSettable: Bool? = nil
    var minimized: Bool? = nil, minimizedSettable: Bool? = nil
    var identityDiagnostic: NativeWindowIdentityDiagnostic? = nil
    // AX-reported state; unavailable is unknown, never inferred from geometry.
    var fullscreen: Bool? = nil
    // Observation-only relationship; never input authority or a focus requirement.
    var keyboardRecipient: NativeKeyboardRecipientDiagnostic? = nil
    // Server-validated direct attachment. This does not transfer parent input
    // authority or focus; the sheet keeps its own opaque window/CG identity.
    var attachedSheetParentID: String? = nil

    static func == (lhs: Self, rhs: Self) -> Bool {
        // Sampling time and focus diagnostics do not change the guarded window
        // snapshot. Keep every pre-existing field in its original equality.
        lhs.id == rhs.id && lhs.title == rhs.title && lhs.bounds == rhs.bounds
            && lhs.focused == rhs.focused && lhs.controls == rhs.controls
            && lhs.nodesVisited == rhs.nodesVisited && lhs.incomplete == rhs.incomplete
            && lhs.cgWindowID == rhs.cgWindowID && lhs.routeRevision == rhs.routeRevision
            && lhs.observationScope == rhs.observationScope && lhs.tree == rhs.tree
            && lhs.positionSettable == rhs.positionSettable && lhs.sizeSettable == rhs.sizeSettable
            && lhs.minimized == rhs.minimized && lhs.minimizedSettable == rhs.minimizedSettable
            && lhs.identityDiagnostic == rhs.identityDiagnostic && lhs.fullscreen == rhs.fullscreen
            && lhs.attachedSheetParentID == rhs.attachedSheetParentID
    }
}
struct NativeKeyboardRecipientDiagnostic: Codable, Equatable {
    var relation: String
    var controlID: String? = nil
    var sampledAt: Double? = nil
    var elapsedSeconds: Double? = nil
    // Cooperative admission budget, not a hard bound on an OS call's latency.
    var budgetSeconds: Double = 0.05
    var atomicSnapshot: Bool = false
    var inputReady: Bool = false
}
// Fixed-size metadata about a read, never proof of atomicity or unchanged content.
enum NativeWindowGetterAvailability: String, Codable { case available, getterUnavailable, unsupportedPlatform }
enum NativeWindowIdentityState: String, Codable {
    case mappedDirect, mappedFallback, ambiguous, getterError, zeroID, timeoutSetupFailed
    case budgetExhausted, geometryUnavailable, inventoryUnavailable, metadataUnavailable
    case ownerMismatch, boundsMismatch, identityChanged, unverified, aliasBlocked
}
enum NativeWindowIdentityProvenance: String, Codable {
    case privateAXWindowID = "private_ax_window_id", uniqueGeometryFallback = "unique_geometry_fallback"
}
struct NativeCaptureLayoutDiagnostic: Codable, Equatable {
    var state: String
    var maximumSeconds: Double = 2
    var elapsedSeconds: Double
    var capturedPixels: Bool = false
    var atomicSnapshot: Bool = false
    var scWindowID: UInt32? = nil
    var scOwnerPID: Int32? = nil
    var scFrame: NativeRect? = nil
    var scIsActive: Bool? = nil
    var scIsOnScreen: Bool? = nil
    var filterContentRect: NativeRect? = nil
    var filterPointPixelScale: Double? = nil
    var filterWindowCount: Int? = nil
    var filterHasOnlyCandidateWindow: Bool? = nil
}
struct NativeWindowIdentityDiagnostic: Codable, Equatable {
    var state: NativeWindowIdentityState
    var getterAvailability: NativeWindowGetterAvailability
    var provenance: NativeWindowIdentityProvenance? = nil
    var axError: Int32? = nil, timeoutError: Int32? = nil
    var maximumSeconds: Double = 0.3, elapsedSeconds: Double? = nil
    // Candidate metadata does not qualify capture or input. The original
    // state and refusal remain authoritative when compositor geometry differs.
    var candidateWindowID: UInt32? = nil
    var logicalBounds: NativeRect? = nil
    var compositorBounds: NativeRect? = nil
    var captureLayout: NativeCaptureLayoutDiagnostic? = nil
    var failure: NativeFailure {
        let code: String
        switch state {
        case .ambiguous, .aliasBlocked: code = "native_window_capture_ambiguous"
        case .budgetExhausted: code = "native_window_identity_budget_exhausted"
        case .ownerMismatch, .identityChanged: code = "native_window_identity_changed"
        case .boundsMismatch: code = "native_window_moved"
        case .geometryUnavailable: code = "native_window_geometry_unavailable"
        default: code = "native_window_identity_unavailable"
        }
        var result = NativeFailure(code)
        result.windowIdentity = self
        return result
    }
}
struct NativeWindowMinimizedState: Codable, Equatable {
    var windowID: String, minimized: Bool?, minimizedSettable: Bool?
}
struct NativeWindowRestoreSetterResult {
    var attempted: Bool, dispatchResult: Int32?, before: NativeWindowMinimizedState
}
struct NativeWindowRestoreReadback {
    var state: NativeWindowMinimizedState?, attempts: Int, elapsedSeconds: Double
    var budgetExhausted: Bool, terminalErrorCode: String?
}
enum NativeMinimizedAttribute {
    static func value(_ raw: CFTypeRef?, success: Bool) -> Bool? {
        guard success, let raw = raw, CFGetTypeID(raw) == CFBooleanGetTypeID() else { return nil }
        return CFBooleanGetValue((raw as! CFBoolean))
    }
    static func requireInputAvailable(_ minimized: Bool?, releasing: Bool = false) throws {
        if !releasing && minimized == true { throw NativeFailure("native_window_minimized") }
    }
}
enum NativeWindowRestorePoll {
    static let maximumSeconds = 0.5, maximumAttempts = 8
    static func read(now: () -> Double, check: () throws -> Void,
                     sample: (Double) throws -> NativeWindowMinimizedState, wait: (Double) -> Void) -> NativeWindowRestoreReadback {
        let start = now(), deadline = start + maximumSeconds
        var actual: NativeWindowMinimizedState?, attempts = 0, terminal: String?
        while attempts < maximumAttempts && now() < deadline {
            do {
                try check(); attempts += 1; actual = try sample(deadline); try check()
                if now() < deadline && actual?.minimized == false { break }
            } catch { terminal = (error as? NativeFailure)?.code ?? "native_restore_readback_unavailable"; break }
            let remaining = deadline - now()
            if remaining > 0 { wait(min(0.04, remaining)) }
        }
        let elapsed = now() - start
        return NativeWindowRestoreReadback(state: actual, attempts: attempts, elapsedSeconds: elapsed,
            budgetExhausted: !elapsed.isFinite || elapsed < 0 || now() >= deadline, terminalErrorCode: terminal)
    }
}
struct NativeDisplay: Codable, Equatable {
    var id: UInt32, bounds: NativeRect, scale: Double
}
struct NativeClipboard: Equatable {
    var changeCount: Int, items: [[String: Data]]
}
struct NativeClipboardPayload {
    // One immutable pasteboard item, with only documented textual representations.
    // Data(utf8) preserves the supplied bytes; no fallback, rendering or normalization.
    static let maximumBytes = 32768
    static let types = ["plain_text": "public.utf8-plain-text",
                        "markdown": "net.daringfireball.markdown", "html": "public.html"]
    let items: [[String: Data]]
    let metadata: [[String: Any]]

    init(text: String? = nil, representations: Any? = nil) throws {
        let entries: [[String: Any]]
        if let supplied = representations {
            guard text == nil, let rows = supplied as? [[String: Any]], (1...3).contains(rows.count) else {
                throw NativeFailure("invalid_native_clipboard_payload")
            }
            entries = rows
        } else {
            guard let text = text else { throw NativeFailure("invalid_native_clipboard_payload") }
            entries = [["format": "plain_text", "text": text]]
        }
        var fields: [String: Data] = [:], descriptions: [[String: Any]] = []
        var bytes = 0
        for entry in entries {
            guard Set(entry.keys) == Set(["format", "text"]), let format = entry["format"] as? String,
                  let type = Self.types[format], let text = entry["text"] as? String, fields[type] == nil else {
                throw NativeFailure("invalid_native_clipboard_payload")
            }
            let data = Data(text.utf8)
            guard data.count <= Self.maximumBytes - bytes else { throw NativeFailure("native_clipboard_payload_limit") }
            bytes += data.count; fields[type] = data
            descriptions.append(["format": format, "type": type, "bytes": data.count,
                "sha256": SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()])
        }
        items = [fields]; metadata = descriptions
    }
}
enum NativeClipboardReceiptPolicy {
    static func verify(_ receipt: [String: Any], ownerSession: String) throws {
        let action = receipt["native_action"] as? String ?? ""
        let result = receipt["result"] as? [String: Any] ?? [:]
        guard ["clipboard_temporary", "clipboard_restore", "clipboard_release"].contains(action)
            || result["clipboard_lease_id"] != nil || result["clipboard_recovery"] != nil else { return }
        // A supplied legacy alias is only request data: even a refused trusted
        // recovery can retain it. Ownership comes from the signed original receipt.
        // Current legacy receipts also retain this owner; absent attribution never
        // permits returning private recovery metadata or token-bearing parameters.
        guard let originalOwner = receipt["owner_session"] as? String, !originalOwner.isEmpty else {
            throw NativeFailure("native_clipboard_receipt_owner_unavailable", "unknown")
        }
        guard originalOwner == ownerSession else { throw NativeFailure("native_clipboard_owner_mismatch") }
    }
}
enum NativeClipboardMutation {
    // These remain separate platform calls, not an atomic conditional replace.
    static func write(_ items: [[String: Data]], expectedChangeCount: Int,
                      currentCount: () -> Int, clear: () -> Int, write: () -> Bool,
                      readback: () throws -> NativeClipboard) throws -> NativeClipboard {
        guard currentCount() == expectedChangeCount else { throw NativeFailure("clipboard_changed") }
        let next = expectedChangeCount.addingReportingOverflow(1)
        guard !next.overflow else { throw NativeFailure("clipboard_count_invalid") }
        let cleared = clear()
        guard cleared == next.partialValue else { throw NativeFailure("clipboard_clear_unverified", "unknown") }
        guard items.isEmpty || write() else { throw NativeFailure("clipboard_write_failed", "unknown") }
        let observed: NativeClipboard
        do { observed = try readback() }
        catch let failure as NativeFailure { throw NativeFailure(failure.code, "unknown") }
        catch { throw NativeFailure("clipboard_readback_failed", "unknown") }
        guard observed.changeCount == cleared, observed.items == items else {
            throw NativeFailure("clipboard_write_unverified", "unknown")
        }
        return observed
    }
}
// Inspection records identity and capture scope, never a point-coordinate mapping.
struct NativeCaptureInspection: Codable, Equatable {
    var windowID: UInt32, ownerPID: Int32
    var logicalBounds: NativeRect, compositorBounds: NativeRect, scFrame: NativeRect, filterContentRect: NativeRect
    var filterPointPixelScale: Double, filterWindowCount: Int
    var filterHasOnlyCandidateWindow: Bool, ignoreGlobalClipSingleWindow: Bool, ignoreShadowsSingleWindow: Bool
    var contentMappingVerified: Bool = false, frameAgeKnown: Bool = false
}
struct NativeCapture {
    var data: Data, width: Int, height: Int, displayScale: Double
    var cgWindowID: UInt32
    var inspection: NativeCaptureInspection? = nil
}
enum NativeCapturePurpose {
    static func decode(_ packet: [String: Any]) throws -> String {
        guard let raw = packet["capture_purpose"], !(raw is NSNull) else { return "input" }
        guard packet["method"] as? String == "operation", packet["action"] as? String == "capture", let purpose = raw as? String,
              ["input", "inspection"].contains(purpose) else { throw NativeFailure("invalid_native_capture_purpose") }
        return purpose
    }
}
struct NativeFailure: Error {
    let code: String, effectState: String
    var clipboardRecovery: [String: Any]?
    var visualValidity: [String: Any]?
    var windowIdentity: NativeWindowIdentityDiagnostic?
    init(_ code: String, _ effectState: String = "none", clipboardRecovery: [String: Any]? = nil) {
        self.code = code; self.effectState = effectState; self.clipboardRecovery = clipboardRecovery
    }
    var response: [String: Any] {
        var detail: [String: Any] = ["code": code, "effect_state": effectState]
        if let validity = visualValidity { detail.merge(validity) { _, new in new } }
        if let identity = windowIdentity { detail["window_identity"] = nativeDictionary(identity) }
        var value: [String: Any] = ["ok": false, "error": detail]
        if let validity = visualValidity { value.merge(validity) { _, new in new } }
        if let recovery = clipboardRecovery { value["clipboard_recovery"] = recovery }
        return value
    }
}
struct NativePointerAdmission {
    let validateAuthority: () throws -> Void
    let beforeSend: () throws -> Void
    func guardedSend(_ guardSend: ((() throws -> Void) throws -> Void)?) -> (() throws -> Void) throws -> Void {
        { dispatch in
            if let guardSend = guardSend { try guardSend { try self.beforeSend(); try dispatch() } }
            else { try self.beforeSend(); try dispatch() }
        }
    }
    func validating(_ geometry: @escaping (Bool) throws -> Void) -> (Bool) throws -> Void {
        { releasing in
            if !releasing { try self.validateAuthority() }
            try geometry(releasing)
            if !releasing { try self.validateAuthority() }
        }
    }
}
// Bounded preparation/sender decisions, never recipient effect evidence.
struct NativeActivationContext {
    private static let modes: Set<String> = ["activation_point", "code_context_only", "window_context_only"]
    private static let dispositions: Set<String> = ["not_read", "available", "unsupported", "no_value", "read_failed", "malformed", "outside_bounds"]
    private(set) var value: [String: Any]?
    private var invalid = false
    private func boolean(_ raw: Any?) -> Bool? {
        guard let number = raw as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }
    mutating func record(_ row: [String: Any]) {
        guard !invalid else { return }
        if row["kind"] as? String == "activation_context" {
            guard value == nil, Set(row.keys) == Set(["kind", "read_attempted", "disposition", "selected_mode"]),
                  let attempted = boolean(row["read_attempted"]), let disposition = row["disposition"] as? String,
                  Self.dispositions.contains(disposition), let mode = row["selected_mode"] as? String,
                  Self.modes.contains(mode),
                  (disposition == "not_read") == (mode == "code_context_only"),
                  disposition != "not_read" || !attempted,
                  !["available", "unsupported", "no_value", "malformed", "outside_bounds"].contains(disposition) || attempted,
                  mode != "window_context_only" || ["unsupported", "no_value", "outside_bounds"].contains(disposition) else {
                value = nil; invalid = true; return
            }
            value = ["read_attempted": attempted, "disposition": disposition, "selected_mode": mode]
        } else if row["kind"] as? String == "activation_mode", value != nil {
            guard let mode = row["mode"] as? String, mode == value?["selected_mode"] as? String,
                  let background = boolean(row["background_prelude"]), value?["background_prelude"] == nil else {
                value = nil; invalid = true; return
            }
            value?["background_prelude"] = background
        }
    }
}
// Failure-only evidence from the existing sender trace. Counts include focus
// events and never certify recipient delivery or successful cleanup.
struct NativePointerFailureSummary {
    private static let phases: Set<String> = [
        "initial_validation", "release_validation", "event_validation", "release_permission", "event_permission",
        "release_send", "event_send", "release_admission", "event_admission", "mouse_up_creation", "mouse_down_creation",
        "hold_wait_validation", "hold_wait_permission", "hold_wait_clock", "hold_wait_sleep", "press_validation",
        "press_permission", "press_send", "press_admission", "drag_down_validation", "drag_down_send",
        "drag_down_admission", "wheel_creation"]
    private static let reasons: Set<String> = [
        "native_input_failure", "accessibility_required", "screen_recording_required", "human_input_interrupted",
        "native_activation_point_unavailable", "native_drag_invalid", "native_event_creation_failed",
        "native_event_source_unavailable", "native_focus_cleanup_unverified", "native_focus_event_unavailable",
        "native_hold_clock_invalid", "native_hold_duration_outside_scope", "native_hold_wait_limit",
        "native_input_permission_revoked", "native_point_outside_scope", "native_release_unverified",
        "native_scroll_delta_outside_scope", "native_targeted_input_partial", "native_targeted_pointer_unavailable",
        "native_window_geometry_unavailable", "native_window_identity_changed", "native_window_moved",
        "native_process_identity_changed", "native_element_process_mismatch", "native_element_identity_unavailable",
        "native_attribute_timeout_unavailable", "native_same_process_window_isolation_unavailable",
        "native_capture_required", "native_capture_not_granted", "native_freshness_clock_invalid", "native_claim_target_mismatch",
        "native_lease_ended", "native_trusted_setup_required", "native_capability_not_trusted",
        "native_claim_capabilities_changed", "native_control_not_granted", "native_operation_cancelled",
        "native_access_stopped", "native_cancellation_finished", "unknown_native_window", "native_window_minimized"]
    let value: [String: Any]
    static func permitsFailureReason(_ reason: String) -> Bool { reasons.contains(reason) }
    init?(_ row: [String: Any]) {
        guard row["kind"] as? String == "failure", let phase = row["phase"] as? String,
              Self.phases.contains(phase), let count = row["sent_events"] as? NSNumber,
              CFGetTypeID(count) != CFBooleanGetTypeID(), String(cString: count.objCType) != "d",
              String(cString: count.objCType) != "f", count.doubleValue >= 0, count.doubleValue <= 64,
              count.doubleValue == Double(count.intValue), let possible = row["possibly_sent"] as? NSNumber,
              CFGetTypeID(possible) == CFBooleanGetTypeID() else { return nil }
        let cause = row["cause"] as? String ?? ""
        value = ["reason": Self.reasons.contains(cause) ? cause : "native_input_failure",
                 "phase": phase, "sent_events": count.intValue, "possibly_sent": possible.boolValue]
    }
}
enum NativeAttributePolicy {
    // AX unsupported/no-value are absence; messaging/type failures are unknown.
    static func securityTextUnavailable(success: Bool, absent: Bool, validText: Bool, required: Bool) -> Bool {
        success ? !validText : required || !absent
    }
    enum SecurityTextRead: Equatable {
        case text(String), unsupported, noValue, failed(Int32), notRead(Int32), malformed
        var value: String? { if case .text(let value) = self { return value }; return nil }
        func unavailable(required: Bool = false) -> Bool {
            let success: Bool
            switch self {
            case .text, .malformed: success = true
            default: success = false
            }
            return NativeAttributePolicy.securityTextUnavailable(success: success,
                absent: self == .unsupported || self == .noValue, validText: value != nil, required: required)
        }
    }
    struct SecurityTextMetadata {
        let role, subrole, title: SecurityTextRead
        let description: SecurityTextRead?
        var label: String {
            if let value = title.value, !value.isEmpty { return value }
            return description?.value ?? ""
        }
        // Exact tuple observed in the pinned Apple TextEdit document editor.
        // This is only a candidate; code identity and complete document ancestry
        // must be independently verified before the optional failure is excused.
        var textEditDescriptionFailure: Bool {
            role == .text("AXTextArea") && subrole == .unsupported && title == .unsupported
                && description == .failed(-25200)
        }
        var protected: Bool {
            role.unavailable(required: true) || subrole.unavailable() || title.unavailable()
                || description?.unavailable() == true || subrole.value == "AXSecureTextField"
                || label.localizedCaseInsensitiveContains("password")
                || description?.value?.localizedCaseInsensitiveContains("password") == true
        }
    }
    static func protects(_ metadata: SecurityTextMetadata, inheritedSecure: Bool,
                         textEditCodeVerified: Bool = false, textEditDocumentAncestorsVerified: Bool = false) -> Bool {
        if inheritedSecure { return true }
        let knownOptionalFailure = metadata.textEditDescriptionFailure && textEditCodeVerified
            && textEditDocumentAncestorsVerified
        return metadata.protected && !knownOptionalFailure
    }
    static func enabled(success: Bool, absent: Bool, value: Bool?) -> Bool {
        success ? value ?? false : absent
    }
}

protocol NativeOperationDriver: AnyObject {
    var accessibilityAllowed: Bool { get }
    var screenAllowed: Bool { get }
    var inputMonitorAvailable: Bool { get }
    var inputEpoch: UInt64 { get }
    var frontmostPID: Int32? { get }
    var clipboardChangeCount: Int? { get }
    var backgroundPointInputAvailable: Bool { get }
    var backgroundDragInputAvailable: Bool { get }
    func matches(_ app: NativeAppIdentity) -> Bool
    var identityFailureDiagnostic: NativeIdentityDiagnostic? { get }
    var windowInventoryDiagnostic: [String: Any]? { get }
    func windows(_ app: NativeAppIdentity) throws -> [NativeWindow]
    func window(_ app: NativeAppIdentity, id: String) throws -> NativeWindow
    func observedWindow(_ app: NativeAppIdentity, id: String) throws -> NativeWindow
    func subtreeWindow(_ app: NativeAppIdentity, id: String, rootControlID: String,
                       sourceRevision: String, sourceHops: Int) throws -> NativeWindow
    func requireRouteRevision(_ app: NativeAppIdentity, windowID: String, revision: String) throws
    func scopedWindowState(_ app: NativeAppIdentity, id: String) throws -> NativeWindow
    func captureWindowState(_ app: NativeAppIdentity, source: NativeWindow) throws -> NativeWindow
    func control(_ app: NativeAppIdentity, windowID: String, id: String) throws -> NativeControl
    func windowAvailable(_ app: NativeAppIdentity, id: String) -> Bool?
    func retainBindings(windows: Set<String>, controls: Set<String>)
    func retainProcessIdentities(_ apps: [NativeAppIdentity])
    func beginWindowDiscovery() -> UUID?
    func endWindowDiscovery(_ batch: UUID)
    func perform(_ app: NativeAppIdentity, windowID: String, controlID: String, action: String, text: String?) throws -> Int32
    func selectTextRange(_ app: NativeAppIdentity, windowID: String, controlID: String, range: NativeTextRange) throws -> Int32
    func performTextAction(_ app: NativeAppIdentity, windowID: String, expectedWindow: NativeWindowGeometrySnapshot,
        expected: NativeControl, action: String, text: String?, selection: NativeTextRange?, beforeSetter: () throws -> Void) throws -> Int32
    func windowGeometry(_ app: NativeAppIdentity, windowID: String) throws -> NativeWindowGeometrySnapshot
    func windowGeometryReadback(_ app: NativeAppIdentity, windowID: String, originalWindowID: UInt32) throws -> NativeWindowGeometryReadback
    func setWindowGeometry(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot,
                           mutation: NativeWindowGeometryMutation, beforeSetter: () throws -> Void) throws -> NativeGeometrySetterResult
    func windowMinimizedState(_ app: NativeAppIdentity, windowID: String) throws -> NativeWindowMinimizedState
    func setWindowRestored(_ app: NativeAppIdentity, windowID: String,
                           beforeSetter: () throws -> Void) throws -> NativeWindowRestoreSetterResult
    func windowRestoreReadback(_ app: NativeAppIdentity, windowID: String) throws -> NativeWindowRestoreReadback
    func pointInput(_ app: NativeAppIdentity, windowID: String, point: NativePoint, action: String, marker: Int64) throws
    func withTargetedFocus<Value>(_ app: NativeAppIdentity, windowID: String,
        expected: NativeWindowGeometrySnapshot, point: NativePoint, marker: Int64,
        admission: NativePointerAdmission, body: @escaping (@escaping () throws -> Void) throws -> Value) throws -> Value
    func targetedPointInput(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot, point: NativePoint, action: String, modifiers: [String], marker: Int64, admission: NativePointerAdmission) throws
    func targetedScrollInput(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot, point: NativePoint, delta: NativeWheelDelta, marker: Int64, admission: NativePointerAdmission) throws
    func targetedHoldInput(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot, point: NativePoint, action: String, holdMS: Int, marker: Int64, admission: NativePointerAdmission) throws
    func targetedDragInput(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot,
                           point: NativePoint, drag: NativeDrag, marker: Int64, admission: @escaping () throws -> Void,
                           sendCheck: @escaping () throws -> Void) throws
    var cancellationCheck: (() throws -> Void)? { get set }
    var guardedInputSend: (((() throws -> Void)) throws -> Void)? { get set }
    func pointIsVisible(_ app: NativeAppIdentity, windowID: String, point: NativePoint) -> Bool
    func capture(_ app: NativeAppIdentity, windowID: String) throws -> NativeCapture
    func capture(_ app: NativeAppIdentity, windowID: String, source: NativeWindow) throws -> NativeCapture
    func captureInspection(_ app: NativeAppIdentity, windowID: String) throws -> NativeCapture
    func displays() -> [NativeDisplay]
    func clipboard() throws -> NativeClipboard
    func writeClipboard(_ items: [[String: Data]], expectedChangeCount: Int) throws -> NativeClipboard
}

extension NativeOperationDriver {
    func observedWindow(_ app: NativeAppIdentity, id: String) throws -> NativeWindow {
        try window(app, id: id)
    }
    func subtreeWindow(_ app: NativeAppIdentity, id: String, rootControlID: String,
                       sourceRevision: String, sourceHops: Int) throws -> NativeWindow {
        throw NativeFailure("native_subtree_observation_unsupported")
    }
    func requireRouteRevision(_ app: NativeAppIdentity, windowID: String, revision: String) throws {
        throw NativeFailure("native_subtree_observation_unsupported")
    }
    func scopedWindowState(_ app: NativeAppIdentity, id: String) throws -> NativeWindow {
        throw NativeFailure("native_subtree_observation_unsupported")
    }
    func captureWindowState(_ app: NativeAppIdentity, source: NativeWindow) throws -> NativeWindow {
        try window(app, id: source.id)
    }
    func capture(_ app: NativeAppIdentity, windowID: String, source: NativeWindow) throws -> NativeCapture {
        try capture(app, windowID: windowID)
    }
    func withTargetedFocus<Value>(_ app: NativeAppIdentity, windowID: String,
        expected: NativeWindowGeometrySnapshot, point: NativePoint, marker: Int64,
        admission: NativePointerAdmission, body: @escaping (@escaping () throws -> Void) throws -> Value) throws -> Value {
        throw NativeFailure("native_focused_key_provider_unavailable")
    }
    var windowInventoryDiagnostic: [String: Any]? { nil }
    func captureInspection(_ app: NativeAppIdentity, windowID: String) throws -> NativeCapture {
        throw NativeFailure("native_capture_inspection_unsupported")
    }
    var clipboardChangeCount: Int? { nil }
    func windowMinimizedState(_ app: NativeAppIdentity, windowID: String) throws -> NativeWindowMinimizedState {
        let observed = try window(app, id: windowID)
        return NativeWindowMinimizedState(windowID: observed.id, minimized: observed.minimized, minimizedSettable: observed.minimizedSettable)
    }
    func setWindowRestored(_ app: NativeAppIdentity, windowID: String,
                           beforeSetter: () throws -> Void) throws -> NativeWindowRestoreSetterResult {
        throw NativeFailure("native_restore_unavailable")
    }
    func windowRestoreReadback(_ app: NativeAppIdentity, windowID: String) throws -> NativeWindowRestoreReadback {
        throw NativeFailure("native_restore_readback_unavailable")
    }
    func windowGeometry(_ app: NativeAppIdentity, windowID: String) throws -> NativeWindowGeometrySnapshot {
        throw NativeFailure("native_window_geometry_unavailable")
    }
    func windowGeometryReadback(_ app: NativeAppIdentity, windowID: String, originalWindowID: UInt32) throws -> NativeWindowGeometryReadback {
        let snapshot = try windowGeometry(app, windowID: windowID)
        return NativeWindowGeometryReadback(snapshot: snapshot, mappingState: snapshot.cgWindowID == nil ? .unverified : .matched)
    }
    func setWindowGeometry(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot,
                           mutation: NativeWindowGeometryMutation, beforeSetter: () throws -> Void) throws -> NativeGeometrySetterResult {
        throw NativeFailure("native_window_geometry_unavailable")
    }
    var identityFailureDiagnostic: NativeIdentityDiagnostic? { nil }
    func retainProcessIdentities(_ apps: [NativeAppIdentity]) {}
    func selectTextRange(_ app: NativeAppIdentity, windowID: String, controlID: String, range: NativeTextRange) throws -> Int32 {
        throw NativeFailure("native_text_range_unavailable")
    }
    func performTextAction(_ app: NativeAppIdentity, windowID: String, expectedWindow: NativeWindowGeometrySnapshot,
        expected: NativeControl, action: String, text: String?, selection: NativeTextRange?, beforeSetter: () throws -> Void) throws -> Int32 {
        // A driver must explicitly implement the final snapshot/authority
        // boundary; old perform/select implementations cannot inherit it.
        throw NativeFailure("native_text_range_unavailable")
    }
    func retainBindings(windows: Set<String>, controls: Set<String>) {}
    func beginWindowDiscovery() -> UUID? { nil }
    func endWindowDiscovery(_ batch: UUID) {}
    // A legacy global-HID path must never become background input by removing
    // its foreground guard. A targeted dispatcher is integrated separately.
    var backgroundPointInputAvailable: Bool { false }
    var backgroundDragInputAvailable: Bool { false }
    func targetedDragInput(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot,
                           point: NativePoint, drag: NativeDrag, marker: Int64, admission: @escaping () throws -> Void,
                           sendCheck: @escaping () throws -> Void) throws {
        throw NativeFailure("native_targeted_drag_unavailable")
    }
    var cancellationCheck: (() throws -> Void)? { get { nil } set {} }
    var guardedInputSend: (((() throws -> Void)) throws -> Void)? { get { nil } set {} }
    func targetedPointInput(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot, point: NativePoint, action: String, modifiers: [String], marker: Int64, admission: NativePointerAdmission) throws {
        throw NativeFailure("native_targeted_pointer_unavailable")
    }
    func targetedHoldInput(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot, point: NativePoint, action: String, holdMS: Int, marker: Int64, admission: NativePointerAdmission) throws {
        throw NativeFailure("native_targeted_hold_unavailable")
    }
    func targetedScrollInput(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot, point: NativePoint, delta: NativeWheelDelta, marker: Int64, admission: NativePointerAdmission) throws {
        throw NativeFailure("native_targeted_scroll_unavailable")
    }
    func windowAvailable(_ app: NativeAppIdentity, id: String) -> Bool? { (try? window(app, id: id)) != nil }
}

final class NativeOperationEngine {
    struct Lease {
        var id: String, app: NativeAppIdentity, expires: Double
        var control: Bool, capture: Bool, clipboard: Bool, inputEpoch: UInt64
        var state = "active", reason: String?
        var identityFailure: NativeIdentityDiagnostic?
        var trustRevision: Int?, ownerSession: String?, runtimeGeneration: String?
        var targetID: String?, targetGeneration: String?, windowID: String?
        var windowFamilyID: String? = nil
        var windowFamilyResource: String? {
            windowFamilyID ?? windowID.map { nativeTargetResource(app, windowID: $0) }
        }
    }
    struct Observation {
        let leaseID: String, window: NativeWindow, inputEpoch: UInt64, created: Double, freshnessStarted: Double
        let clockGeneration: UInt64
    }
    struct NativeCaptureProof {
        let captureID: String, observationID: String
        let lease: Lease
        let observationStarted: Double, windowID: String, bounds: NativeRect
        let clockGeneration: UInt64
        let captureStarted: Double, captureFinished: Double, deadline: Double, budget: Double
        let cgWindowID: UInt32, width: Int, height: Int, displayScale: Double
    }
    // Local backend selection only; never deserialized from a tool request.
    // The original visual intent is consumed by pointDispatch before this
    // closure runs. A backend must retain the admission for every send and
    // return an original cleanup outcome, including through NativeDeferred.
    typealias ManagedPointerDispatch = (Lease, Observation, NativeCaptureProof, NativePointerAdmission) throws -> [String: Any]
    struct ClipboardLease {
        let leaseID: String, original: NativeClipboard
        let ownerSession: String?
        var temporary: NativeClipboard?
        var state: String
    }
    let driver: NativeOperationDriver
    let now: () -> Double
    let freshnessNow: () -> Double
    private var lastFreshnessTime: Double?
    private var freshnessGeneration: UInt64 = 0
    private(set) var leases: [String: Lease] = [:]
    private var observations: [String: Observation] = [:]
    // Original cleanup references survive action-authority retirement. They
    // pin proof caches and reserve the family; cleanup still verifies identity.
    private var heldCleanupBindings: [String: (app: NativeAppIdentity, windowID: String, familyID: String)] = [:]
    private var treeRevisions: [String: Observation] = [:]
    private var treeRevisionBytes: [String: Int] = [:]
    private var observationTreeBytes: [String: Int] = [:]
    private var captures: [String: (Data, Double)] = [:]
    private var resultPayloadIDs: Set<String> = []
    private var captureProofs: [String: NativeCaptureProof] = [:]
    // Retired metadata never arms input. Keep at most 100 small records so an
    // expired/consumed intent can explain its original capture without pixels.
    private var retiredCaptureProofs: [String: (NativeCaptureProof, String)] = [:]
    private var retiredCaptureOrder: [String] = []
    private var clipboardLeases: [String: ClipboardLease] = [:]
    private let marker = Int64.random(in: 1...Int64.max)
    var installationTrust: NativeInstallationTrust?

    init(driver: NativeOperationDriver, now: @escaping () -> Double = { Date().timeIntervalSince1970 },
         freshnessNow: @escaping () -> Double = { ProcessInfo.processInfo.systemUptime }) {
        self.driver = driver; self.now = now; self.freshnessNow = freshnessNow
    }
    private func freshnessTime() throws -> Double {
        let time = freshnessNow()
        guard time.isFinite, time >= 0, lastFreshnessTime.map({ time >= $0 }) ?? true else {
            freshnessGeneration &+= 1
            for key in Array(captureProofs.keys) { retireCaptureProof(key, reason: "clock_invalid") }
            throw NativeFailure("native_freshness_clock_invalid")
        }
        lastFreshnessTime = time
        return time
    }
    private func fresh(_ observation: Observation, at time: Double) -> Bool {
        observation.clockGeneration == freshnessGeneration && time >= observation.freshnessStarted && time - observation.freshnessStarted < 30
    }
    private func retireCaptureProof(_ observationID: String, reason: String) {
        guard let proof = captureProofs.removeValue(forKey: observationID) else { return }
        // The host already owns transferred pixels. Retired metadata explains
        // the original intent; its bytes must not occupy another transfer slot.
        captures.removeValue(forKey: proof.captureID)
        retiredCaptureProofs[observationID] = (proof, reason)
        retiredCaptureOrder.removeAll { $0 == observationID }
        retiredCaptureOrder.append(observationID)
        while retiredCaptureOrder.count > 100 {
            retiredCaptureProofs.removeValue(forKey: retiredCaptureOrder.removeFirst())
        }
    }
    private func captureProvenance(_ proof: NativeCaptureProof, at time: Double?) -> [String: Any] {
        let validTime = time.flatMap { proof.clockGeneration == freshnessGeneration && $0.isFinite && $0 >= proof.captureFinished && $0 >= proof.observationStarted ? $0 : nil }
        return ["visual_validity_policy": proof.lease.trustRevision == nil ? "legacy_capture_5s_observation_30s" : "trusted_capture_and_observation_30s",
            "visual_validity_budget_seconds": proof.budget, "original_capture_id": proof.captureID,
            "source_observation_id": proof.observationID,
            "capture_call_age_seconds": validTime.map { $0 - proof.captureStarted } as Any? ?? NSNull(),
            "observation_age_seconds": validTime.map { $0 - proof.observationStarted } as Any? ?? NSNull(),
            "remaining_validity_seconds": validTime.map { max(0, proof.deadline - $0) } as Any? ?? NSNull(),
            "freshness_clock": "system_uptime_monotonic", "capture_age_anchor": "signed_app_capture_call_start",
            "frame_age_known": false, "atomic_with_dispatch": false,
            "content_unchanged": "not_established"]
    }
    private func refreshFailure(_ proof: NativeCaptureProof, at time: Double?, reason: String,
                                code: String = "native_capture_required") -> NativeFailure {
        var failure = NativeFailure(code)
        var provenance = captureProvenance(proof, at: time)
        provenance["refresh_required"] = true; provenance["visual_validity_state"] = reason
        provenance["refresh_action"] = "observe_and_explicitly_capture_then_select_coordinates_for_new_intent"
        failure.visualValidity = provenance
        return failure
    }
    private func requireCaptureFresh(_ proof: NativeCaptureProof, at time: Double) throws {
        guard proof.clockGeneration == freshnessGeneration else {
            throw refreshFailure(proof, at: nil, reason: "clock_invalid", code: "native_freshness_clock_invalid")
        }
        guard time >= proof.captureFinished, time >= proof.observationStarted, time < proof.deadline else {
            throw refreshFailure(proof, at: time, reason: "expired")
        }
    }
    private func sameCaptureAuthority(_ proof: NativeCaptureProof, _ current: Lease) -> Bool {
        sameCaptureAuthority(proof.lease, current)
    }
    private func sameCaptureAuthority(_ original: Lease, _ current: Lease) -> Bool {
        return current.id == original.id && current.app == original.app && current.windowID == original.windowID
            && current.ownerSession == original.ownerSession && current.runtimeGeneration == original.runtimeGeneration
            && current.targetID == original.targetID && current.targetGeneration == original.targetGeneration
            && current.trustRevision == original.trustRevision && current.control == original.control
            && current.capture == original.capture && current.clipboard == original.clipboard
    }
    private func boundTreeStorage() {
        treeRevisionBytes = treeRevisionBytes.filter { treeRevisions[$0.key] != nil }
        observationTreeBytes = observationTreeBytes.filter { observations[$0.key] != nil }
        // Count each retained tree conservatively even where Swift shares value storage.
        while treeRevisionBytes.values.reduce(0, +) + observationTreeBytes.values.reduce(0, +) > 8388608 {
            let oldestRevision = treeRevisions.min { $0.value.created < $1.value.created }
            let oldestObservation = observations.min { $0.value.created < $1.value.created }
            if let revision = oldestRevision, oldestObservation == nil || revision.value.created <= oldestObservation!.value.created {
                treeRevisions.removeValue(forKey: revision.key); treeRevisionBytes.removeValue(forKey: revision.key)
            } else if let observation = oldestObservation {
                observations.removeValue(forKey: observation.key); observationTreeBytes.removeValue(forKey: observation.key)
            } else { break }
        }
    }

    func grantLocally(app: NativeAppIdentity, seconds: Int, control: Bool, capture: Bool, clipboard: Bool) throws -> String {
        guard (30...300).contains(seconds), app.launchedAt > 0, driver.matches(app) else { throw NativeFailure("invalid_app_target") }
        guard driver.accessibilityAllowed else { throw NativeFailure("accessibility_required") }
        if control {
            guard driver.inputMonitorAvailable else { throw NativeFailure("input_monitoring_required") }
            guard driver.frontmostPID == app.pid else { throw NativeFailure("selected_app_not_frontmost") }
        }
        if capture && !driver.screenAllowed { throw NativeFailure("screen_recording_required") }
        if clipboard { _ = try driver.clipboard() } // Only reached from the local grant action.
        expire()
        if leases.count >= 100 { leases = leases.filter { $0.value.state == "active" } }
        guard leases.count < 100 else { throw NativeFailure("native_lease_limit") }
        let id = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        leases[id] = Lease(id: id, app: app, expires: now() + Double(seconds), control: control, capture: capture,
                           clipboard: clipboard, inputEpoch: driver.inputEpoch)
        return id
    }

    func acquireTrusted(app: NativeAppIdentity, windowID: String, ownerSession: String, runtimeGeneration: String,
                        control: Bool, capture: Bool, clipboard: Bool) throws -> [String: Any] {
        guard let trust = installationTrust, trust.valid, trust.permits("native.observe", app: app) else {
            throw NativeFailure("native_trusted_setup_required")
        }
        guard !ownerSession.isEmpty, ownerSession.utf8.count <= 128,
              runtimeGeneration.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
              driver.matches(app) else { throw NativeFailure("invalid_app_target") }
        for (needed, capability) in [(control,"native.control"),(capture,"native.capture"),(clipboard,"native.clipboard")] {
            if needed && !trust.permits(capability, app: app) { throw NativeFailure("native_capability_not_trusted") }
        }
        guard driver.accessibilityAllowed else { throw NativeFailure("accessibility_required") }
        if capture && !driver.screenAllowed { throw NativeFailure("screen_recording_required") }
        let window = try driver.window(app, id: windowID)
        guard window.bounds.finite else { throw NativeFailure("window_geometry_unavailable") }
        expire()
        let resource = nativeTargetResource(app, windowID: windowID)
        let family = nativeTargetResource(app, windowID: window.attachedSheetParentID ?? windowID)
        // Original cleanup remains eligible independently of lease lifetime.
        // Only durable settlement releases this family reservation.
        guard !heldCleanupBindings.values.contains(where: { $0.app == app && $0.familyID == family }) else {
            throw NativeFailure("native_target_claimed")
        }
        // Active parent/sheet ownership is exclusive. A prior transport's
        // suspended claim has no action authority and may be replaced in a new
        // runtime; its exact recovery records remain. Original cleanup above
        // reserves the family independently of every lease/transport state.
        for old in leases.values where (old.state == "active"
            || (old.state == "suspended_transport" && old.runtimeGeneration == runtimeGeneration))
            && (old.windowFamilyID ?? old.targetID) == family {
            guard old.ownerSession == ownerSession, old.runtimeGeneration == runtimeGeneration else {
                throw NativeFailure("native_target_claimed")
            }
        }
        for old in leases.values where old.state == "active" && old.targetID == resource {
            guard old.ownerSession == ownerSession, old.runtimeGeneration == runtimeGeneration else {
                throw NativeFailure("native_target_claimed")
            }
            guard old.control == control, old.capture == capture, old.clipboard == clipboard else {
                throw NativeFailure("native_claim_capabilities_changed")
            }
            return claim(old)
        }
        guard leases.values.filter({ $0.state == "active" }).count < 100 else { throw NativeFailure("native_lease_limit") }
        let id = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let lease = Lease(id: id, app: app, expires: Double.greatestFiniteMagnitude, control: control, capture: capture,
            clipboard: clipboard, inputEpoch: driver.inputEpoch, trustRevision: trust.policyRevision,
            ownerSession: ownerSession, runtimeGeneration: runtimeGeneration, targetID: resource,
            targetGeneration: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(), windowID: windowID,
            windowFamilyID: family)
        leases[id] = lease
        refreshBindingRetention()
        return claim(lease)
    }

    private func claim(_ lease: Lease) -> [String: Any] {
        ["ok": true, "interaction_version": 1, "claim_id": lease.id, "lease_id": lease.id,
         "claim_epoch": lease.trustRevision as Any? ?? NSNull(), "owner_session": lease.ownerSession as Any? ?? NSNull(),
         "runtime_generation": lease.runtimeGeneration as Any? ?? NSNull(), "state": lease.state,
         "reason": lease.reason as Any? ?? NSNull(),
         "identity_diagnostic": lease.identityFailure.map(nativeDictionary) as Any? ?? NSNull(),
         "target": ["backend": "native", "target_id": lease.targetID as Any? ?? NSNull(),
                    "target_generation": lease.targetGeneration as Any? ?? NSNull(), "window_id": lease.windowID as Any? ?? NSNull(),
                    "app": nativeDictionary(lease.app)],
         "installation_id": installationTrust?.installationID as Any? ?? NSNull(),
         "expires_at": NSNull(), "input_backend": "semantic_ax", "background_pointer_available": driver.backgroundPointInputAvailable,
         "background_drag_available": driver.backgroundDragInputAvailable,
         "control": lease.control, "capture": lease.capture, "clipboard": lease.clipboard,
         "prompts_triggered": false]
    }

    func releaseClaim(_ id: String, ownerSession: String, runtimeGeneration: String,
                      releaseBinding: [String: Any]? = nil) throws -> [String: Any] {
        // Cross-runtime retirement requires the exact original binding returned
        // by the private preflight. Never treat it as current input authority.
        if let binding = releaseBinding {
            guard let retained = leases[id] else { throw NativeFailure("native_lease_ended") }
            let current = claim(retained)
            for key in ["interaction_version", "installation_id", "claim_id", "owner_session", "runtime_generation", "claim_epoch", "target"] {
                guard let a = binding[key], let b = current[key],
                      let supplied = try? JSONSerialization.data(withJSONObject: [key: a], options: [.sortedKeys]),
                      let retained = try? JSONSerialization.data(withJSONObject: [key: b], options: [.sortedKeys]),
                      supplied == retained else {
                    throw NativeFailure("native_claim_owner_mismatch")
                }
            }
        }
        let owned = try retainedOwnedClaim(id, ownerSession: ownerSession, runtimeGeneration: runtimeGeneration,
                                          retirement: releaseBinding != nil)
        let changed = ["active", "suspended_transport"].contains(owned.state)
        if changed {
            // A suspended claim retains resources but cannot send input. Keep
            // its recorded cause when cleanup ends that retained authority.
            revoke(id, reason: owned.state == "active" ? "claim_released" : owned.reason ?? "claim_released")
        }
        let ended = leases[id] ?? owned
        return ["ok": true, "claim_id": id, "released": true, "trust_revoked": false,
                "authority_changed": changed, "already_ended": !changed, "effect_state": "none",
                "state": ended.state, "reason": ended.reason as Any? ?? NSNull()]
    }
    func claimStatus(_ id: String, ownerSession: String, runtimeGeneration: String) throws -> [String: Any] {
        claim(try retainedOwnedClaim(id, ownerSession: ownerSession, runtimeGeneration: runtimeGeneration))
    }
    func claimReleaseStatus(_ id: String, ownerSession: String, runtimeGeneration: String) throws -> [String: Any] {
        ["ok": true, "release_claim": claim(try retainedOwnedClaim(id, ownerSession: ownerSession,
                                                               runtimeGeneration: runtimeGeneration, retirement: true))]
    }
    private func retainedOwnedClaim(_ id: String, ownerSession: String, runtimeGeneration: String,
                                    retirement: Bool = false) throws -> Lease {
        guard let retained = leases[id] else { throw NativeFailure("native_lease_ended") }
        guard retained.trustRevision != nil, !ownerSession.isEmpty, retained.ownerSession == ownerSession,
              runtimeGeneration.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
              let originalRuntime = retained.runtimeGeneration,
              originalRuntime.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
              originalRuntime == runtimeGeneration || (retirement && ["suspended_transport", "revoked"].contains(retained.state)) else {
            throw NativeFailure("native_claim_owner_mismatch")
        }
        expire()
        if !driver.accessibilityAllowed { revoke(id, reason: "accessibility_revoked") }
        return leases[id] ?? retained
    }
    func verifyOwner(_ id: String, ownerSession: String, runtimeGeneration: String, legacyAlias: Bool = false) throws {
        let granted = try lease(id)
        if legacyAlias && granted.trustRevision != nil { throw NativeFailure("native_claim_id_required") }
        if granted.trustRevision != nil && (granted.ownerSession != ownerSession || granted.runtimeGeneration != runtimeGeneration) {
            throw NativeFailure("native_claim_owner_mismatch")
        }
    }
    func suspendTrustedClaimsForNewRuntime() {
        for var lease in leases.values where lease.trustRevision != nil && lease.state == "active" {
            lease.state = "suspended_transport"; lease.reason = "runtime_generation_changed"; leases[lease.id] = lease
            observations = observations.filter { $0.value.leaseID != lease.id }
            treeRevisions = treeRevisions.filter { $0.value.leaseID != lease.id }
            treeRevisionBytes = treeRevisionBytes.filter { treeRevisions[$0.key] != nil }
        }
        // Trust, immutable receipts and pending clipboard restoration survive.
        refreshBindingRetention()
    }

    func revoke(_ id: String, reason: String = "local_revoke") {
        guard var lease = leases[id], ["active", "suspended_transport"].contains(lease.state) else { return }
        lease.state = "revoked"; lease.reason = reason; leases[id] = lease
        observations = observations.filter { $0.value.leaseID != id }
        treeRevisions = treeRevisions.filter { $0.value.leaseID != id }
        treeRevisionBytes = treeRevisionBytes.filter { treeRevisions[$0.key] != nil }
        refreshBindingRetention()
    }
    func retainHeldCleanupBindings(_ operationID: String, lease: Lease) {
        guard let windowID = lease.windowID, let family = lease.windowFamilyResource else { return }
        heldCleanupBindings[operationID] = (lease.app, windowID, family)
        refreshBindingRetention()
    }
    func releaseHeldCleanupBindings(_ operationID: String) {
        heldCleanupBindings.removeValue(forKey: operationID)
        refreshBindingRetention()
    }
    private func refreshBindingRetention() {
        boundTreeStorage()
        for (key, proof) in captureProofs where observations[key] == nil || captures[proof.captureID] == nil {
            retireCaptureProof(key, reason: "source_unavailable")
        }
        let time = try? freshnessTime()
        var windows = Set(leases.values.filter { ["active", "suspended_transport"].contains($0.state) }.compactMap { $0.windowID })
        windows.formUnion(heldCleanupBindings.values.map(\.windowID))
        var controls: Set<String> = []
        for observation in observations.values where time.map({ fresh(observation, at: $0) }) == true {
            windows.insert(observation.window.id)
            controls.formUnion(observation.window.controls.map { $0.id })
            controls.formUnion(observation.window.tree?.nodes.map { $0.id } ?? [])
        }
        for revision in treeRevisions.values where time.map({ fresh(revision, at: $0) }) == true {
            windows.insert(revision.window.id)
            controls.formUnion(revision.window.tree?.nodes.map { $0.id } ?? [])
        }
        driver.retainBindings(windows: windows, controls: controls)
        let retainedLeaseIDs = Set(leases.values.filter { ["active", "suspended_transport"].contains($0.state) }.map(\.id))
            .union(observations.values.filter { observation in time.map({ fresh(observation, at: $0) }) == true }.map(\.leaseID))
            .union(treeRevisions.values.filter { observation in time.map({ fresh(observation, at: $0) }) == true }.map(\.leaseID))
        driver.retainProcessIdentities(retainedLeaseIDs.compactMap { leases[$0]?.app }
            + heldCleanupBindings.values.map(\.app))
    }
    func expire() {
        defer { refreshBindingRetention() }
        for lease in leases.values where ["active", "suspended_transport"].contains(lease.state) {
            if lease.expires <= now() { revoke(lease.id, reason: "expired") }
            else if !driver.matches(lease.app) {
                // Capture the same failed check before revocation touches bindings.
                let diagnostic = driver.identityFailureDiagnostic
                revoke(lease.id, reason: "app_process_changed")
                if var revoked = leases[lease.id] {
                    revoked.identityFailure = diagnostic; leases[lease.id] = revoked
                }
            }
            else if let revision = lease.trustRevision {
                guard let trust = installationTrust, trust.policyRevision >= revision, trust.permits("native.observe", app: lease.app),
                      !lease.control || trust.permits("native.control", app: lease.app),
                      !lease.capture || trust.permits("native.capture", app: lease.app),
                      !lease.clipboard || trust.permits("native.clipboard", app: lease.app) else {
                    revoke(lease.id, reason: "trust_revoked_or_changed"); continue
                }
                if let windowID = lease.windowID, driver.windowAvailable(lease.app, id: windowID) == false {
                    revoke(lease.id, reason: "target_closed")
                }
            }
            else if lease.control && !driver.inputMonitorAvailable { revoke(lease.id, reason: "input_monitor_unavailable") }
            else if lease.control && (driver.inputEpoch != lease.inputEpoch || driver.frontmostPID != lease.app.pid) {
                revoke(lease.id, reason: "human_input_or_focus_change")
            }
        }
        captures = captures.filter { now() - $0.value.1 < 120 }
        resultPayloadIDs = resultPayloadIDs.filter { captures[$0] != nil }
        let time = try? freshnessTime()
        for (key, proof) in captureProofs {
            if time.map({ $0 >= proof.captureFinished && $0 < proof.deadline }) != true {
                retireCaptureProof(key, reason: time == nil ? "clock_invalid" : "expired")
            }
        }
        observations = observations.filter { observation in time.map({ fresh(observation.value, at: $0) }) == true }
        treeRevisions = treeRevisions.filter { observation in time.map({ fresh(observation.value, at: $0) }) == true }
        treeRevisionBytes = treeRevisionBytes.filter { treeRevisions[$0.key] != nil }
    }
    func activeIDs() -> [String] {
        expire()
        return leases.values.filter { $0.state == "active" }.map(\.id) + clipboardLeases.keys.map { "clipboard:" + $0 }
    }

    func status(ownerSession: String? = nil) -> [String: Any] {
        expire()
        return ["ok": true, "checked_at": now(), "accessibility_allowed": driver.accessibilityAllowed,
                "screen_allowed": driver.screenAllowed, "input_monitor_available": driver.inputMonitorAvailable,
                "subtree_observation_version": 1, "interaction_version": 1, "installation_trust": installationTrust?.wire as Any? ?? NSNull(),
                "claims": leases.values.filter { $0.trustRevision != nil }.map(claim),
                "leases": leases.values.map { l in ["lease_id": l.id, "app": nativeDictionary(l.app), "expires_at": l.trustRevision == nil ? l.expires as Any : NSNull(),
                    "state": l.state, "reason": l.reason as Any? ?? NSNull(),
                    "identity_diagnostic": l.identityFailure.map(nativeDictionary) as Any? ?? NSNull(), "control": l.control,
                    "capture": l.capture, "clipboard": l.clipboard] as [String: Any] },
                "clipboard_change_count": driver.clipboardChangeCount as Any? ?? NSNull(),
                "clipboard_leases": clipboardLeases.filter { ownerSession == nil || $0.value.ownerSession == nil || $0.value.ownerSession == ownerSession }
                    .map { token, saved in ["clipboard_lease_id": token,
                    "lease_id": saved.leaseID, "owned_change_count": saved.temporary?.changeCount as Any? ?? NSNull(),
                    "state": saved.state, "preimage_retained": true,
                    "restoration_pending": true] as [String: Any] },
                "coordinate_space": "macOS global top-left points", "displays": driver.displays().map(nativeDictionary)]
    }

    private func lease(_ id: String, control: Bool = false) throws -> Lease {
        expire()
        guard let lease = leases[id], lease.state == "active", lease.expires > now() else { throw NativeFailure("native_lease_ended") }
        guard driver.accessibilityAllowed else { revoke(id, reason: "accessibility_revoked"); throw NativeFailure("accessibility_required") }
        if control && !lease.control { throw NativeFailure("native_control_not_granted") }
        return lease
    }

    func observe(_ id: String, windowID: String? = nil, treeBaseID: String? = nil,
                 sourceObservationID: String? = nil, rootControlID: String? = nil) throws -> [String: Any] {
        let granted = try lease(id)
        guard (sourceObservationID == nil) == (rootControlID == nil),
              sourceObservationID == nil || windowID != nil else { throw NativeFailure("native_subtree_selection_required") }
        if let selected = windowID {
            if let pinned = granted.windowID, pinned != selected { throw NativeFailure("native_claim_target_mismatch") }
            let freshnessStarted = try freshnessTime()
            let clockGeneration = freshnessGeneration
            var scope: NativeObservationScope?
            let observedWindow: NativeWindow
            if let sourceID = sourceObservationID, let rootID = rootControlID {
                guard let prior = observations[sourceID], prior.leaseID == id, prior.window.id == selected,
                      fresh(prior, at: try freshnessTime()) else { throw NativeFailure("stale_native_observation") }
                let anchor = prior.window.tree?.nodes.first(where: { $0.id == rootID })?.element
                    ?? prior.window.controls.first(where: { $0.id == rootID })
                guard let anchor = anchor, !anchor.secure, let revision = prior.window.routeRevision else {
                    throw NativeFailure("native_subtree_anchor_unavailable")
                }
                let hops = prior.window.observationScope?.scoped_hops ?? 0
                guard hops < 2 else { throw NativeFailure("native_subtree_hop_limit") }
                observedWindow = try driver.subtreeWindow(granted.app, id: selected, rootControlID: rootID,
                    sourceRevision: revision, sourceHops: hops)
                guard observedWindow.bounds == prior.window.bounds, observedWindow.cgWindowID == prior.window.cgWindowID else {
                    throw NativeFailure("native_window_identity_changed")
                }
                scope = NativeObservationScope(kind: "subtree", root_control_id: rootID,
                    source_observation_id: sourceID, scoped_hops: hops + 1, whole_window_complete: false,
                    predecessor_must_be_current: true, maximum_ancestry_nodes: 64)
            } else { observedWindow = try driver.observedWindow(granted.app, id: selected) }
            var window = observedWindow
            window.observationScope = scope
            if scope != nil { window.incomplete = true }
            guard window.bounds.finite else { throw NativeFailure("window_geometry_unavailable") }
            let observationID = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            let observed = Observation(leaseID: id, window: window, inputEpoch: driver.inputEpoch, created: now(), freshnessStarted: freshnessStarted,
                clockGeneration: clockGeneration)
            guard fresh(observed, at: try freshnessTime()) else { throw NativeFailure("stale_native_observation") }
            observations[observationID] = observed
            observationTreeBytes[observationID] = try JSONEncoder().encode(window.tree).count
            if observations.count > 100 { observations.removeValue(forKey: observations.min(by: { $0.value.created < $1.value.created })!.key) }
            let base = treeBaseID.flatMap { treeRevisions[$0] }
            if treeBaseID != nil {
                guard let base = base, base.leaseID == id, base.window.id == selected,
                      base.window.observationScope?.root_control_id == scope?.root_control_id,
                      (base.window.observationScope == nil) == (scope == nil),
                      fresh(base, at: try freshnessTime()) else {
                    observations.removeValue(forKey: observationID)
                    observationTreeBytes.removeValue(forKey: observationID)
                    refreshBindingRetention()
                    throw NativeFailure("stale_native_tree_revision")
                }
            }
            treeRevisions[observationID] = observed
            treeRevisionBytes[observationID] = try JSONEncoder().encode(window.tree).count
            while treeRevisions.count > 100 || treeRevisionBytes.values.reduce(0, +) > 8388608 {
                guard let oldest = treeRevisions.min(by: { $0.value.created < $1.value.created })?.key else { break }
                treeRevisions.removeValue(forKey: oldest); treeRevisionBytes.removeValue(forKey: oldest)
            }
            refreshBindingRetention()
            var reply: [String: Any] = ["ok": true, "lease_id": id, "observation_id": observationID, "window": nativeDictionary(window),
                    "app": nativeDictionary(granted.app), "input_epoch": driver.inputEpoch, "checked_at": now(),
                    "coordinate_space": "macOS global top-left points", "potentially_sensitive": true]
            if let scope = scope {
                reply["subtree_observation_version"] = 1
                reply["observation_scope"] = nativeDictionary(scope)
            }
            if let tree = window.tree {
                var descriptor = nativeDictionary(window); descriptor.removeValue(forKey: "tree"); reply["window"] = descriptor
                var update: [String: Any] = ["revision_id": observationID, "mode": "full", "tree": nativeDictionary(tree)]
                if let prior = base?.window.tree, let treeBaseID = treeBaseID {
                    let old = Dictionary(uniqueKeysWithValues: prior.nodes.map { ($0.id, $0) })
                    let current = Dictionary(uniqueKeysWithValues: tree.nodes.map { ($0.id, $0) })
                    update = ["revision_id": observationID, "base_revision_id": treeBaseID, "mode": "diff",
                        "removed_ids": old.keys.filter { current[$0] == nil }.sorted(),
                        "upsert_nodes": tree.nodes.filter { old[$0.id] != $0 }.map(nativeDictionary),
                        "node_order": tree.nodes.map { $0.id },
                        "metadata": ["complete": tree.complete, "omissions": tree.omissions,
                            "startedAt": tree.startedAt, "finishedAt": tree.finishedAt,
                            "maximumNodes": tree.maximumNodes, "maximumDepth": tree.maximumDepth,
                            "maximumSeconds": tree.maximumSeconds, "maximumBytes": tree.maximumBytes]]
                }
                reply["tree_update"] = update
            }
            return reply
        }
        guard treeBaseID == nil else { throw NativeFailure("native_tree_window_required") }
        let windows = try granted.windowID.map { [try driver.window(granted.app, id: $0)] } ?? driver.windows(granted.app)
        var reply: [String: Any] = ["ok": true, "lease_id": id, "app": nativeDictionary(granted.app), "windows": windows.map(nativeDictionary),
                "checked_at": now(), "potentially_sensitive": true,
                "incomplete": windows.contains(where: { $0.incomplete })]
        if granted.windowID == nil, let diagnostic = driver.windowInventoryDiagnostic {
            reply["window_inventory"] = diagnostic
            if diagnostic["scope_complete"] as? Bool == false { reply["incomplete"] = true }
        }
        return reply
    }

    private func checkedObservation(_ id: String, observationID: String, control: Bool) throws -> (Lease, Observation) {
        let granted = try lease(id, control: control)
        let time = try freshnessTime()
        guard let observation = observations[observationID], observation.leaseID == id, fresh(observation, at: time) else {
            throw NativeFailure("stale_native_observation")
        }
        let current: NativeWindow
        if observation.window.observationScope != nil {
            guard let revision = observation.window.routeRevision else { throw NativeFailure("native_subtree_anchor_unavailable") }
            try driver.requireRouteRevision(granted.app, windowID: observation.window.id, revision: revision)
            current = try driver.scopedWindowState(granted.app, id: observation.window.id)
        } else { current = try driver.window(granted.app, id: observation.window.id) }
        guard current.bounds == observation.window.bounds else {
            retireCaptureProof(observationID, reason: "geometry_changed"); throw NativeFailure("native_window_moved")
        }
        guard current.cgWindowID == observation.window.cgWindowID else {
            retireCaptureProof(observationID, reason: "window_replaced"); throw NativeFailure("native_window_identity_changed")
        }
        if control && granted.trustRevision == nil {
            guard current.focused && driver.frontmostPID == granted.app.pid else { throw NativeFailure("native_focus_changed") }
            guard driver.inputEpoch == observation.inputEpoch else { revoke(id, reason: "human_input"); throw NativeFailure("human_input_interrupted") }
        }
        return (granted, observation)
    }

    func action(_ id: String, observationID: String, controlID: String, action: String, text: String?, selection: NativeTextRange? = nil) throws -> [String: Any] {
        let aliases = ["press": "AXPress", "increment": "AXIncrement", "decrement": "AXDecrement",
                       "show_menu": "AXShowMenu", "confirm": "AXConfirm", "cancel": "AXCancel", "raise": "AXRaise"]
        let dispatchedAction = aliases[action] ?? action
        let (granted, observation) = try checkedObservation(id, observationID: observationID, control: true)
        guard let original = observation.window.controls.first(where: { $0.id == controlID }) else { throw NativeFailure("unknown_native_control") }
        let before = try driver.control(granted.app, windowID: observation.window.id, id: controlID)
        guard original == before, before.enabled else { throw NativeFailure("native_control_changed") }
        guard before.role != nil else { throw NativeFailure("native_role_unavailable") }
        guard !before.secure else { throw NativeFailure("local_sensitive_input_required") }
        guard !before.valueTruncated else { throw NativeFailure("native_value_guard_limit") }
        let textAction = ["select_text", "replace_selection"].contains(dispatchedAction)
        let textValueAction = dispatchedAction == "set_value" && before.valueType == "text"
        if (textAction || textValueAction) && !NativeTextRange.sameText(original.value, before.value) { throw NativeFailure("native_control_changed") }
        guard dispatchedAction == "select_text" || selection == nil else { throw NativeFailure("native_text_range_invalid") }
        var expectedText: String?
        if textAction {
            guard before.valueType == "text", let value = before.value,
                  value.utf8.count <= 32768 else {
                throw NativeFailure("native_text_range_unavailable")
            }
            if dispatchedAction == "select_text" {
                guard before.selectedRangeSettable, let range = selection, range.valid(in: value), text == nil else {
                    throw NativeFailure("native_text_range_invalid")
                }
            } else {
                guard before.selectedTextSettable, let range = before.selectedRange, range.valid(in: value),
                      let text = text, text.utf8.count <= 32768 else { throw NativeFailure("native_text_selection_unavailable") }
                expectedText = (value as NSString).replacingCharacters(in: NSRange(location: range.location, length: range.length), with: text)
                guard expectedText!.utf8.count <= 32768 else { throw NativeFailure("native_text_value_limit") }
            }
        } else if dispatchedAction == "set_value" {
            guard before.valueSettable, let text = text, text.utf8.count <= 32768 else { throw NativeFailure("native_value_not_settable") }
            if textValueAction { expectedText = text }
        } else if !before.actions.contains(dispatchedAction) { throw NativeFailure("native_action_unsupported") }
        _ = try checkedObservation(id, observationID: observationID, control: true)
        var result: Int32 = -1, dispatchEntered = false, textSetterAttempted = false
        let expectedWindow = NativeWindowGeometrySnapshot(windowID: observation.window.id,
            bounds: observation.window.bounds, cgWindowID: observation.window.cgWindowID)
        // Keep binding retention tidy after either outcome. Old observations
        // are consumed at the actual setter boundary, including unknown writes.
        defer {
            if textSetterAttempted { refreshBindingRetention() }
        }
        let send = {
            dispatchEntered = true
            if textAction {
                result = try self.driver.performTextAction(granted.app, windowID: observation.window.id,
                    expectedWindow: expectedWindow, expected: before, action: dispatchedAction, text: text, selection: selection,
                    beforeSetter: {
                        // This callback follows the driver's final AX reads.
                        // Recheck cached authority without expiry/AX callbacks
                        // while the Stop/send gate is held.
                        guard let current = self.leases[id], current.state == "active", current.control,
                              current.app == granted.app, current.expires > self.now(),
                              current.windowID == granted.windowID,
                              current.ownerSession == granted.ownerSession, current.runtimeGeneration == granted.runtimeGeneration,
                              current.targetID == granted.targetID, current.targetGeneration == granted.targetGeneration,
                              current.trustRevision == granted.trustRevision,
                              self.observations[observationID]?.leaseID == id,
                              self.fresh(observation, at: try self.freshnessTime()) else {
                            throw NativeFailure("stale_native_observation")
                        }
                        guard self.driver.accessibilityAllowed else { throw NativeFailure("accessibility_required") }
                        if let revision = current.trustRevision {
                            guard let trust = self.installationTrust, trust.policyRevision >= revision,
                                  trust.permits("native.observe", app: current.app),
                                  trust.permits("native.control", app: current.app) else {
                                throw NativeFailure("native_capability_not_trusted")
                            }
                        } else {
                            guard self.driver.inputMonitorAvailable, self.driver.inputEpoch == observation.inputEpoch,
                                  self.driver.frontmostPID == granted.app.pid else { throw NativeFailure("human_input_interrupted") }
                        }
                        self.invalidateWindowObservations(observation.window.id, reason: "text_changed", refreshBindings: false)
                        textSetterAttempted = true
                    })
            } else {
                result = try self.driver.perform(granted.app, windowID: observation.window.id,
                    controlID: controlID, action: dispatchedAction, text: text)
            }
        }
        do {
            // The text driver owns the gate around its final bounded read batch
            // and setter. Slow window/ancestry preparation stays cancellable.
            if textAction { try send() }
            else if let guardedSend = driver.guardedInputSend { try guardedSend(send) }
            else { try send() }
        } catch let failure as NativeFailure {
            if textSetterAttempted {
                var uncertain = NativeFailure(failure.code, "unknown", clipboardRecovery: failure.clipboardRecovery)
                uncertain.visualValidity = failure.visualValidity; uncertain.windowIdentity = failure.windowIdentity
                throw uncertain
            }
            // A rejected send gate cannot have called AX. Once the closure
            // begins, preserve possible-effect uncertainty and never replay.
            if failure.code == "native_operation_cancelled", !dispatchEntered || textAction && !textSetterAttempted {
                throw NativeFailure(failure.code, "none")
            }
            throw failure
        } catch {
            if textSetterAttempted { throw NativeFailure("native_text_dispatch_uncertain", "unknown") }
            throw error
        }
        observations.removeValue(forKey: observationID)
        refreshBindingRetention()
        var reply: [String: Any] = ["ok": result == 0, "lease_id": id, "dispatch_result": result,
            "requested_action": action, "dispatched_action": dispatchedAction,
            "before": nativeDictionary(before), "effect_state": result == 0 ? "applied" : "unknown",
            "task_completion": "not_established", "potentially_sensitive": true, "checked_at": now()]
        if textValueAction { reply["exact_requested_state"] = false }
        if textAction {
            reply["input_backend"] = "semantic_ax"
            reply["text_state_atomic"] = false
            reply["exact_requested_state"] = false
        }
        do {
            if textAction { try driver.cancellationCheck?(); _ = try lease(id, control: true) }
            let after = try driver.control(granted.app, windowID: observation.window.id, id: controlID)
            reply["readback"] = nativeDictionary(after); reply["observed_change"] = after != before
            reply["verification_state"] = "target_readback_received"
            if textAction || textValueAction {
                let exact = dispatchedAction == "select_text"
                    ? after.selectedRange == selection && NativeTextRange.sameText(after.value, before.value)
                    : NativeTextRange.sameText(after.value, expectedText)
                if textAction { reply["range_units"] = "UTF-16 code units" }
                reply["exact_requested_state"] = result == 0 && exact && !after.secure && !after.valueTruncated
                    && after.id == before.id && after.role == before.role && after.valueType == "text"
                    && (!textAction || after.textRouteID == before.textRouteID && after.bounds == before.bounds)
                reply["verification_state"] = reply["exact_requested_state"] as? Bool == true ? "exact_text_state_verified" : "text_state_not_verified"
                reply["effect_state"] = reply["exact_requested_state"] as? Bool == true ? "applied" : "unknown"
                if let selection = selection { reply["requested_range"] = nativeDictionary(selection) }
            }
            if textAction { try driver.cancellationCheck?(); _ = try lease(id, control: true) }
        } catch {
            reply["verification_state"] = "readback_unavailable"; reply["effect_state"] = "unknown"
            if textAction { reply["exact_requested_state"] = false }
        }
        if granted.trustRevision == nil && (driver.inputEpoch != observation.inputEpoch || driver.frontmostPID != granted.app.pid) {
            revoke(id, reason: "human_input_or_focus_change"); reply["lease_ended_during_action"] = true
            reply["effect_state"] = "unknown"
        }
        return reply
    }

    func geometry(_ id: String, windowID: String, observationID: String, mutation: NativeWindowGeometryMutation) throws -> [String: Any] {
        let (granted, observation) = try checkedObservation(id, observationID: observationID, control: true)
        guard granted.trustRevision != nil, granted.windowID == windowID, observation.window.id == windowID else {
            throw NativeFailure("native_claim_target_mismatch")
        }
        let capability = mutation.action == "move" ? observation.window.positionSettable : observation.window.sizeSettable
        guard capability == true else { throw NativeFailure(capability == false ? "native_geometry_not_settable" : "native_geometry_capability_unavailable") }
        let expected = NativeWindowGeometrySnapshot(windowID: windowID, bounds: observation.window.bounds, cgWindowID: observation.window.cgWindowID)
        guard let originalWindowID = expected.cgWindowID else { throw NativeFailure("native_geometry_identity_unavailable") }
        let requested = mutation.requested(expected.bounds)
        guard requested.finite, (requested.x + requested.width).isFinite, (requested.y + requested.height).isFinite else {
            throw NativeFailure("invalid_native_geometry")
        }
        var result: [String: Any] = ["action": mutation.action, "input_backend": "semantic_ax", "source_observation_id": observationID,
            "window_id": windowID, "coordinate_space": "macOS global top-left points", "requested_attribute": mutation.attribute,
            "requested_frame": nativeDictionary(requested), "before_frame": nativeDictionary(expected.bounds),
            "before_cg_window_id": expected.cgWindowID as Any? ?? NSNull(), "dispatch_state": "not_dispatched",
            "dispatch_result": NSNull(), "frame_readback_atomic": false, "after_frame": NSNull(),
            "position_postcondition": "unavailable", "size_postcondition": "unavailable", "identity_postcondition": "unavailable",
            "exact_requested_state": false, "verification_state": "not_dispatched", "observations_invalidated": false]
        var attempted = false, successful = false, errorCode: String?
        do {
            try driver.cancellationCheck?()
            let send = {
                guard let current = self.leases[id], current.state == "active", current.control,
                      current.app == granted.app, let revision = current.trustRevision,
                      let trust = self.installationTrust, trust.policyRevision >= revision,
                      trust.permits("native.observe", app: current.app), trust.permits("native.control", app: current.app),
                      current.windowID == windowID,
                      let fresh = self.observations[observationID], fresh.leaseID == id,
                      self.fresh(fresh, at: try self.freshnessTime()) else { throw NativeFailure("stale_native_observation") }
                let obsolete = Set(self.observations.filter { $0.value.window.id == windowID }.map { $0.key })
                self.observations = self.observations.filter { $0.value.window.id != windowID }
                self.treeRevisions = self.treeRevisions.filter { $0.value.window.id != windowID }
                self.observationTreeBytes = self.observationTreeBytes.filter { !obsolete.contains($0.key) }
                self.treeRevisionBytes = self.treeRevisionBytes.filter { self.treeRevisions[$0.key] != nil }
                for key in obsolete { self.retireCaptureProof(key, reason: "geometry_changed") }
                self.refreshBindingRetention(); result["observations_invalidated"] = true
                let dispatched = try self.driver.setWindowGeometry(granted.app, windowID: windowID, expected: expected, mutation: mutation, beforeSetter: {
                    // No AX/global expiry under the Stop/send lock after the
                    // driver's final frame guard. Public expiry ran above.
                    guard let current = self.leases[id], current.state == "active", current.control,
                          current.app == granted.app, let revision = current.trustRevision,
                          let trust = self.installationTrust, trust.policyRevision >= revision,
                          trust.permits("native.observe", app: current.app), trust.permits("native.control", app: current.app),
                          current.windowID == windowID,
                          self.fresh(observation, at: try self.freshnessTime()) else {
                        throw NativeFailure("stale_native_observation")
                    }
                })
                attempted = dispatched.attempted; successful = dispatched.dispatchResult == 0 && attempted
                result["dispatch_state"] = attempted ? "dispatched" : "not_dispatched"
                result["dispatch_result"] = dispatched.dispatchResult as Any? ?? NSNull()
                result["capability_result"] = dispatched.capabilityResult as Any? ?? NSNull()
                result["settable"] = dispatched.settable as Any? ?? NSNull()
                if !successful {
                    errorCode = attempted ? "native_geometry_dispatch_failed"
                        : dispatched.capabilityResult == 0 && dispatched.settable == false ? "native_geometry_not_settable" : "native_geometry_capability_unavailable"
                }
            }
            if let guarded = driver.guardedInputSend { try guarded(send) } else { try send() }
            if attempted {
                let readback = try driver.windowGeometryReadback(granted.app, windowID: windowID, originalWindowID: originalWindowID)
                let after = readback.snapshot
                let position = after.bounds.x == requested.x && after.bounds.y == requested.y
                let size = after.bounds.width == requested.width && after.bounds.height == requested.height
                let identityUnavailable = after.cgWindowID == nil || readback.mappingState != .matched || readback.budgetExhausted || readback.terminalErrorCode != nil
                let identity = !identityUnavailable && after.cgWindowID == originalWindowID && after.windowID == windowID
                result["after_frame"] = nativeDictionary(after.bounds); result["after_cg_window_id"] = after.cgWindowID as Any? ?? NSNull()
                result["position_postcondition"] = position ? "passed" : "failed"
                result["size_postcondition"] = size ? "passed" : "failed"
                result["identity_postcondition"] = identity ? "passed" : identityUnavailable ? "unavailable" : "failed"
                result["cg_mapping_state"] = readback.mappingState.rawValue
                result["readback_attempts"] = readback.attempts
                result["readback_snapshot_attempt"] = readback.snapshotAttempt
                result["readback_elapsed_ms"] = readback.elapsedSeconds * 1000
                result["readback_maximum_ms"] = NativeGeometryReadbackPoll.maximumSeconds * 1000
                result["readback_budget_exhausted"] = readback.budgetExhausted
                if let terminal = readback.terminalErrorCode {
                    result["terminal_readback_error"] = terminal
                    result["interrupted_after_dispatch"] = true
                    errorCode = terminal
                }
                result["observed_change"] = after.bounds != expected.bounds
                try driver.cancellationCheck?()
                let exact = successful && position && size && identity
                result["exact_requested_state"] = exact
                result["verification_state"] = readback.terminalErrorCode != nil ? "readback_unavailable" : exact ? "exact_frame_verified" : !identity ? (identityUnavailable ? "identity_unavailable" : "identity_mismatch") : "frame_mismatch"
                if !exact { errorCode = errorCode ?? "native_geometry_postcondition_failed" }
            }
        } catch {
            errorCode = (error as? NativeFailure)?.code ?? "native_geometry_readback_unavailable"
            result["verification_state"] = attempted ? "readback_unavailable" : "not_dispatched"
            result["interrupted_after_dispatch"] = attempted
        }
        let exact = result["exact_requested_state"] as? Bool == true
        let effect = exact ? "applied" : attempted ? "unknown" : "none"
        var reply: [String: Any] = ["ok": exact, "geometry_result": result, "effect_state": effect,
            "task_completion": "not_established", "checked_at": now(), "potentially_sensitive": true]
        if !exact { reply["error"] = ["code": errorCode ?? "native_geometry_not_verified", "effect_state": effect] }
        return reply
    }

    /// Capability selection only, never input authority. Unsupported renderer
    /// mapping leaves existing raw routes available under their own guards.
    func hasUnitWebAreaCapture(_ id: String, observationID: String) -> Bool {
        guard let proof = captureProofs[observationID], proof.lease.id == id,
              let observed = observations[observationID], observed.leaseID == id,
              Double(proof.width) == proof.bounds.width, Double(proof.height) == proof.bounds.height, proof.displayScale == 1 else { return false }
        return observed.window.controls.filter { $0.role == "AXWebArea" && !$0.secure && $0.bounds == proof.bounds }.count == 1
    }

    func point(_ id: String, observationID: String, point: NativePoint, action: String, modifiers: [String] = [], wheel: NativeWheelDelta? = nil,
               holdMS: Int? = nil, drag: NativeDrag? = nil, windowID: String? = nil,
               managedDispatch: ManagedPointerDispatch? = nil) throws -> [String: Any] {
        func enrich(_ original: NativeFailure) -> NativeFailure {
            var failure = original
            if failure.visualValidity == nil, let retired = retiredCaptureProofs[observationID],
               let current = leases[id], sameCaptureAuthority(retired.0, current) {
                let time = try? freshnessTime()
                let reason = time.map({ $0 >= retired.0.deadline }) == true ? "expired" : retired.1
                if reason == "expired" && failure.code == "stale_native_observation" {
                    failure = refreshFailure(retired.0, at: time, reason: reason)
                } else { failure.visualValidity = refreshFailure(retired.0, at: time, reason: reason).visualValidity }
            }
            return failure
        }
        do {
            return try pointDispatch(id, observationID: observationID, point: point, action: action, modifiers: modifiers, wheel: wheel, holdMS: holdMS, drag: drag, windowID: windowID,
                managedDispatch: managedDispatch)
        } catch let deferred as NativeDeferred<[String: Any]> {
            throw deferred.mapResult { result in
                do { return try result.get() }
                catch let failure as NativeFailure { throw enrich(failure) }
            }
        } catch let failure as NativeFailure { throw enrich(failure) }
    }

    // Internal compound operation, not a remotely selectable pointer action.
    // Reuse the exact capture consumption, authority and first-send fences.
    func capturedFocus(_ id: String, observationID: String, windowID: String,
                       dispatch: @escaping ManagedPointerDispatch) throws -> [String: Any] {
        let (granted, observed) = try checkedObservation(id, observationID: observationID, control: true)
        guard granted.trustRevision != nil, granted.windowID == windowID, observed.window.id == windowID else {
            throw NativeFailure("native_claim_target_mismatch")
        }
        let bounds = observed.window.bounds
        return try point(id, observationID: observationID,
            point: NativePoint(x: bounds.x + bounds.width / 2, y: bounds.y + bounds.height / 2),
            action: "focus_context", windowID: windowID, managedDispatch: dispatch)
    }

    private func invalidateWindowObservations(_ windowID: String, reason: String = "geometry_changed", refreshBindings: Bool = true) {
        let obsolete = Set(observations.filter { $0.value.window.id == windowID }.map { $0.key })
        observations = observations.filter { $0.value.window.id != windowID }
        treeRevisions = treeRevisions.filter { $0.value.window.id != windowID }
        observationTreeBytes = observationTreeBytes.filter { !obsolete.contains($0.key) }
        treeRevisionBytes = treeRevisionBytes.filter { treeRevisions[$0.key] != nil }
        for key in obsolete { retireCaptureProof(key, reason: reason) }
        if refreshBindings { refreshBindingRetention() }
    }
    func restoreWindow(_ id: String, windowID: String) throws -> [String: Any] {
        let granted = try lease(id, control: true)
        guard granted.trustRevision != nil, granted.windowID == windowID else { throw NativeFailure("native_claim_target_mismatch") }
        func authority() throws {
            guard let current = leases[id], current.state == "active", current.control, current.expires > now(),
                  current.app == granted.app, current.windowID == windowID,
                  current.ownerSession == granted.ownerSession, current.runtimeGeneration == granted.runtimeGeneration,
                  current.targetID == granted.targetID, current.targetGeneration == granted.targetGeneration,
                  current.trustRevision == granted.trustRevision,
                  let revision = current.trustRevision, let trust = installationTrust, trust.policyRevision >= revision,
                  trust.permits("native.observe", app: current.app), trust.permits("native.control", app: current.app) else {
                throw NativeFailure("native_lease_ended")
            }
        }
        try driver.cancellationCheck?(); try authority()
        let before = try driver.windowMinimizedState(granted.app, windowID: windowID)
        guard before.windowID == windowID else { throw NativeFailure("native_claim_target_mismatch") }
        var result: [String: Any] = ["action": "restore_window", "window_id": windowID, "input_backend": "semantic_ax",
            "before": nativeDictionary(before), "after": NSNull(), "dispatch_state": "not_dispatched",
            "dispatch_result": NSNull(), "exact_requested_state": false, "observations_invalidated": false,
            "verification_state": "not_dispatched"]
        var attempted = false, exact = false, errorCode: String?
        do {
            try driver.cancellationCheck?(); try authority()
            guard let minimized = before.minimized else { throw NativeFailure("native_minimized_state_unavailable") }
            if !minimized {
                exact = true; result["after"] = nativeDictionary(before); result["verification_state"] = "already_restored"
            } else {
                guard before.minimizedSettable == true else {
                    throw NativeFailure(before.minimizedSettable == false ? "native_minimized_not_settable" : "native_minimized_capability_unavailable")
                }
                var dispatched: NativeWindowRestoreSetterResult?
                let send = {
                    try authority()
                    dispatched = try self.driver.setWindowRestored(granted.app, windowID: windowID, beforeSetter: {
                        try authority()
                        // Mark immediately before the sole setter; no later failure can hide this attempt.
                        attempted = true; self.invalidateWindowObservations(windowID)
                        result["observations_invalidated"] = true
                    })
                }
                if let guarded = driver.guardedInputSend { try guarded(send) } else { try send() }
                guard let dispatch = dispatched, dispatch.before.windowID == windowID else { throw NativeFailure("native_restore_unavailable") }
                attempted = attempted || dispatch.attempted
                result["before"] = nativeDictionary(dispatch.before)
                result["dispatch_state"] = attempted ? "dispatched" : "not_dispatched"
                result["dispatch_result"] = dispatch.dispatchResult as Any? ?? NSNull()
                if attempted {
                    let readback = try driver.windowRestoreReadback(granted.app, windowID: windowID)
                    result["after"] = readback.state.map(nativeDictionary) as Any? ?? NSNull()
                    result["readback_attempts"] = readback.attempts; result["readback_elapsed_ms"] = readback.elapsedSeconds * 1000
                    result["readback_maximum_ms"] = NativeWindowRestorePoll.maximumSeconds * 1000
                    result["readback_budget_exhausted"] = readback.budgetExhausted
                    if let terminal = readback.terminalErrorCode { result["terminal_readback_error"] = terminal }
                    try driver.cancellationCheck?(); try authority()
                    exact = dispatch.dispatchResult == 0 && readback.state?.windowID == windowID
                        && readback.state?.minimized == false && !readback.budgetExhausted && readback.terminalErrorCode == nil
                    result["verification_state"] = exact ? "minimized_false_verified" : "minimized_false_not_verified"
                    errorCode = readback.terminalErrorCode ?? (dispatch.dispatchResult == 0 ? "native_restore_postcondition_failed" : "native_restore_dispatch_failed")
                } else if dispatch.before.minimized == false {
                    exact = true; result["after"] = nativeDictionary(dispatch.before); result["verification_state"] = "already_restored"
                } else { throw NativeFailure(dispatch.before.minimizedSettable == false ? "native_minimized_not_settable" : "native_minimized_state_unavailable") }
            }
        } catch {
            errorCode = (error as? NativeFailure)?.code ?? "native_restore_readback_unavailable"
            result["verification_state"] = attempted ? "readback_unavailable" : "not_dispatched"
        }
        result["dispatch_state"] = attempted ? "dispatched" : "not_dispatched"
        result["exact_requested_state"] = exact
        let effect = attempted ? (exact ? "applied" : "unknown") : "none"
        var reply: [String: Any] = ["ok": exact, "restore_result": result, "effect_state": effect,
            "task_completion": "not_established", "checked_at": now(), "potentially_sensitive": true]
        if !exact { reply["error"] = ["code": errorCode ?? "native_restore_unverified", "effect_state": effect] }
        return reply
    }
    #if LOCAL_WORKBENCH_POINTER_ACCEPTANCE
    func fixtureProbePoint(_ id: String, observationID: String, permit: NativeFixtureProbePermit,
                           consume: @escaping () throws -> Void, context: @escaping (Int64) -> Void) throws -> [String: Any] {
        try pointDispatch(id, observationID: observationID, point: permit.point, action: permit.action, wheel: permit.wheel, holdMS: permit.holdMS,
            drag: permit.drag, windowID: permit.windowID,
            admission: { granted, observed in
                guard granted.trustRevision != nil, granted.control, granted.capture,
                      permit.claimID == id, permit.app == granted.app, permit.windowID == granted.windowID,
                      permit.runtime.ownerSession == granted.ownerSession,
                      permit.runtime.runtimeGeneration == granted.runtimeGeneration,
                      permit.targetGeneration == granted.targetGeneration,
                      permit.windowID == observed.window.id, permit.cgWindowID == observed.window.cgWindowID,
                      permit.bounds == observed.window.bounds else { throw NativeFailure("native_probe_target_mismatch") }
            }, prepareSend: consume, sendContext: context)
    }
    #endif
    private func pointDispatch(_ id: String, observationID: String, point: NativePoint, action: String, modifiers: [String] = [], wheel: NativeWheelDelta? = nil,
                               holdMS: Int? = nil, drag: NativeDrag? = nil, windowID: String? = nil,
                               admission: ((Lease, Observation) throws -> Void)? = nil,
                               prepareSend: (() throws -> Void)? = nil, sendContext: ((Int64) -> Void)? = nil,
                               managedDispatch: ManagedPointerDispatch? = nil) throws -> [String: Any] {
        try NativePointerClickModifiers.validate(modifiers)
        let (granted, observation) = try checkedObservation(id, observationID: observationID, control: true)
        // Modifier metadata belongs only to this exact trusted single click.
        // Never drop it into a legacy, managed/receiver or fixture route.
        if !modifiers.isEmpty {
            guard action == "click", wheel == nil, holdMS == nil, drag == nil,
                  managedDispatch == nil, admission == nil, granted.trustRevision != nil,
                  windowID == granted.windowID, windowID == observation.window.id else {
                throw NativeFailure("native_pointer_modifiers_outside_scope")
            }
        }
        if managedDispatch != nil {
            guard granted.trustRevision != nil, windowID == granted.windowID, windowID == observation.window.id else {
                throw NativeFailure("native_claim_target_mismatch")
            }
        }
        if action == "drag" {
            guard granted.trustRevision != nil, windowID == granted.windowID, windowID == observation.window.id,
                  let drag = drag, wheel == nil, holdMS == nil else { throw NativeFailure("native_drag_invalid") }
            let path = try drag.path(from: point)
            guard path.allSatisfy({ location in observation.window.bounds.contains(location)
                && driver.displays().contains(where: { $0.bounds.contains(location) }) }) else { throw NativeFailure("native_point_outside_scope") }
        } else if drag != nil { throw NativeFailure("native_drag_invalid") }
        if let admission = admission { try admission(granted, observation) }
        else if managedDispatch == nil && granted.trustRevision != nil && !(action == "drag" ? driver.backgroundDragInputAvailable : driver.backgroundPointInputAvailable) {
            throw NativeFailure(action == "drag" ? "native_targeted_drag_unavailable" : "native_targeted_pointer_unavailable")
        }
        guard point.x.isFinite && point.y.isFinite, observation.window.bounds.contains(point),
              driver.displays().contains(where: { $0.bounds.contains(point) }),
              ["click", "double_click", "right_click", "scroll", "hold", "right_hold", "drag"].contains(action)
                || (action == "focus_context" && managedDispatch != nil && granted.trustRevision != nil) else {
            throw NativeFailure("native_point_outside_scope")
        }
        guard action == "scroll" ? wheel?.valid == true : wheel == nil else { throw NativeFailure("native_scroll_delta_invalid") }
        let holding = ["hold", "right_hold"].contains(action)
        guard holding ? holdMS.map({ (1...5000).contains($0) }) == true : holdMS == nil else { throw NativeFailure("native_hold_duration_invalid") }
        if holding && granted.trustRevision == nil { throw NativeFailure("native_targeted_hold_unavailable") }
        if action == "scroll" && granted.trustRevision == nil { throw NativeFailure("native_targeted_scroll_unavailable") }
        if action == "right_click" && granted.trustRevision == nil { throw NativeFailure("native_targeted_pointer_unavailable") }
        let visible = try driver.captureWindowState(granted.app, source: observation.window)
        try NativeMinimizedAttribute.requireInputAvailable(visible.minimized)
        guard visible.cgWindowID != nil, let proof = captureProofs[observationID], sameCaptureAuthority(proof, granted),
              proof.observationID == observationID, proof.windowID == observation.window.id,
              proof.bounds == observation.window.bounds, proof.cgWindowID == visible.cgWindowID,
              captures[proof.captureID] != nil else { throw NativeFailure("native_capture_required") }
        if granted.trustRevision == nil && !driver.pointIsVisible(granted.app, windowID: observation.window.id, point: point) { throw NativeFailure("native_point_obstructed") }
        _ = try checkedObservation(id, observationID: observationID, control: true)
        try prepareSend?()
        // Driver/fixture validation can be slow. Age the exact capture again
        // at the final boundary, without another traversal moving that boundary.
        let dispatchAt = try freshnessTime()
        try requireCaptureFresh(proof, at: dispatchAt)
        guard observations[observationID] != nil, captureProofs[observationID]?.captureID == proof.captureID else {
            throw refreshFailure(proof, at: dispatchAt, reason: "source_unavailable")
        }
        observations.removeValue(forKey: observationID)
        retireCaptureProof(observationID, reason: "consumed")
        refreshBindingRetention()
        sendContext?(marker)
        let expectedGeometry = NativeWindowGeometrySnapshot(windowID: observation.window.id,
            bounds: observation.window.bounds, cgWindowID: observation.window.cgWindowID)
        var firstSendAt: Double?
        var managedResult: [String: Any]?
        func finishPoint() throws -> [String: Any] {
            var result: [String: Any] = ["ok": true, "lease_id": id, "effect_state": granted.trustRevision == nil ? "applied" : "unknown",
                "dispatch_state": "sent", "task_completion": "not_established",
                "checked_at": now(), "potentially_sensitive": true]
            result.merge(captureProvenance(proof, at: firstSendAt ?? dispatchAt)) { _, new in new }
            result["validity_timing_scope"] = granted.trustRevision == nil ? "final_model_admission" : "first_nonrelease_send_admission"
            if let holdMS = holdMS { result["requested_hold_ms"] = holdMS; result["hold_timing_scope"] = "sender dispatch; receiver duration requires independent callback evidence" }
            if let drag = drag { result["drag_steps"] = drag.steps; result["drag_end"] = nativeDictionary(drag.end) }
            if let managedResult = managedResult {
                result[action == "focus_context" ? "focus_context_result" : "managed_pointer_result"] = managedResult
                if managedResult["ready"] as? Bool != true {
                    let effect = managedResult["effect_state"] as? String == "none" ? "none" : "unknown"
                    result["ok"] = false; result["effect_state"] = effect
                    result["error"] = ["code": managedResult["reason"] as? String ?? "native_managed_pointer_unverified", "effect_state": effect]
                }
            }
            do { result["readback"] = nativeDictionary(try driver.window(granted.app, id: observation.window.id)); result["verification_state"] = "window_readback_received" }
            catch { result["verification_state"] = "readback_unavailable"; result["effect_state"] = "unknown" }
            if granted.trustRevision == nil && (driver.inputEpoch != observation.inputEpoch || driver.frontmostPID != granted.app.pid) {
                revoke(id, reason: "human_input_or_focus_change"); result["effect_state"] = "unknown"
            }
            return result
        }
        if granted.trustRevision != nil {
            // Only retained state and the original clock belong at the
            // cancellation-locked send boundary; no AX/display reads.
            let authorityCheck: (Bool) throws -> Void = { [weak self] freshCapture in
                guard let self = self else { throw NativeFailure("native_lease_ended") }
                let time = try self.freshnessTime()
                guard proof.clockGeneration == self.freshnessGeneration else {
                    throw self.refreshFailure(proof, at: nil, reason: "clock_invalid", code: "native_freshness_clock_invalid")
                }
                guard let current = self.leases[id], current.state == "active", current.expires > self.now() else {
                    throw NativeFailure("native_lease_ended")
                }
                guard current.control else { throw NativeFailure("native_control_not_granted") }
                guard self.sameCaptureAuthority(proof, current) else { throw NativeFailure("native_claim_target_mismatch") }
                guard current.capture else { throw NativeFailure("native_capture_not_granted") }
                guard let revision = current.trustRevision, let trust = self.installationTrust,
                      trust.policyRevision >= revision, trust.permits("native.observe", app: current.app),
                      trust.permits("native.control", app: current.app), trust.permits("native.capture", app: current.app) else {
                    throw NativeFailure("native_lease_ended")
                }
                guard time >= proof.captureFinished else { throw NativeFailure("native_freshness_clock_invalid") }
                if freshCapture {
                    try self.requireCaptureFresh(proof, at: time)
                    if firstSendAt == nil { firstSendAt = time }
                }
            }
            let admission = NativePointerAdmission(validateAuthority: { [weak self] in
                    guard let self = self else { throw NativeFailure("native_lease_ended") }
                    let current = try self.lease(id, control: true)
                    guard current.capture, self.driver.screenAllowed else { throw NativeFailure("native_capture_not_granted") }
                    // Waiting inside an admitted hold may outlive capture
                    // age. It still requires this exact live claim/trust.
                    try authorityCheck(false)
                }, beforeSend: { try authorityCheck(true) })
            do {
                if let managedDispatch = managedDispatch {
                    managedResult = try managedDispatch(granted, observation, proof, admission)
                }
                else if let drag = drag {
                    try driver.targetedDragInput(granted.app, windowID: observation.window.id, expected: expectedGeometry,
                        point: point, drag: drag, marker: marker, admission: {
                            try admission.validateAuthority()
                            try self.requireCaptureFresh(proof, at: try self.freshnessTime())
                        }, sendCheck: admission.beforeSend)
                }
                else if let wheel = wheel { try driver.targetedScrollInput(granted.app, windowID: observation.window.id, expected: expectedGeometry, point: point, delta: wheel, marker: marker, admission: admission) }
                else if holding { try driver.targetedHoldInput(granted.app, windowID: observation.window.id, expected: expectedGeometry, point: point, action: action, holdMS: holdMS!, marker: marker, admission: admission) }
                else { try driver.targetedPointInput(granted.app, windowID: observation.window.id, expected: expectedGeometry, point: point, action: action, modifiers: modifiers, marker: marker, admission: admission) }
            } catch let deferred as NativeDeferred<[String: Any]> {
                throw deferred.mapResult { outcome in
                    managedResult = try outcome.get()
                    return try finishPoint()
                }
            } catch let deferred as NativeDeferred<Void> {
                throw deferred.mapResult { result in
                    try result.get()
                    return try finishPoint()
                }
            } catch let failure as NativeFailure {
                // The existing cancellation lane conservatively reports unknown.
                // In this route every possible non-release send must first reach
                // beforeSend under its guard. No reached boundary means no event;
                // any admitted/possibly sent event keeps its original uncertainty.
                if firstSendAt == nil && failure.code == "native_operation_cancelled" && failure.effectState == "unknown" {
                    var refused = NativeFailure(failure.code)
                    refused.visualValidity = failure.visualValidity
                    throw refused
                }
                throw failure
            }
        } else { try driver.pointInput(granted.app, windowID: observation.window.id, point: point, action: action, marker: marker) }
        return try finishPoint()
    }

    // Capture preparation has capture authority only. This reusable check lets
    // the host revalidate the ORIGINAL observation immediately before a
    // renderer frame request; it neither renews it nor creates an input proof.
    func captureObservation(_ id: String, observationID: String) throws -> (Lease, Observation) {
        let (granted, observation) = try checkedObservation(id, observationID: observationID, control: false)
        guard granted.capture, driver.screenAllowed else { throw NativeFailure("native_capture_not_granted") }
        return (granted, observation)
    }

    func capture(_ id: String, observationID: String, purpose: String = "input",
                 prepare: ((Lease, Observation) throws -> [String: Any]?)? = nil) throws -> [String: Any] {
        guard ["input", "inspection"].contains(purpose) else { throw NativeFailure("invalid_native_capture_purpose") }
        _ = try lease(id)
        guard let selected = observations[observationID], selected.leaseID == id else {
            throw NativeFailure("stale_native_observation")
        }
        // Inspection also retires older arms for this exact claim/window. A
        // foreign observation cannot retire another task's proof.
        if purpose == "inspection" {
            let prior = captureProofs.filter { $0.value.lease.id == id && $0.value.windowID == selected.window.id }.map(\.key)
            for key in prior { retireCaptureProof(key, reason: "inspection_capture") }
        } else {
            // A failed refresh cannot leave the prior image authorizing input.
            retireCaptureProof(observationID, reason: "capture_refresh_failed")
        }
        let (granted, observation) = try captureObservation(id, observationID: observationID)
        try driver.cancellationCheck?()
        let preparation = try prepare?(granted, observation)
        let (prepared, _) = try captureObservation(id, observationID: observationID)
        guard sameCaptureAuthority(granted, prepared) else { throw NativeFailure("native_claim_target_mismatch") }
        try driver.cancellationCheck?()
        if purpose == "inspection" {
            var result = try inspectionCapture(id, observationID: observationID, granted: granted, observation: observation)
            if let preparation = preparation { result["renderer_preparation"] = preparation }
            return result
        }
        let captureStarted = try freshnessTime()
        let captureStartedAt = now()
        let image = try driver.capture(granted.app, windowID: observation.window.id, source: observation.window)
        try driver.cancellationCheck?()
        let captureFinishedAt = now()
        let captureFinished = try freshnessTime()
        guard captureFinished >= captureStarted, (captureFinished - captureStarted).isFinite else {
            throw NativeFailure("native_freshness_clock_invalid")
        }
        guard image.cgWindowID == observation.window.cgWindowID else { throw NativeFailure("native_window_identity_changed") }
        guard image.width > 0, image.height > 0, image.width <= 16777216 / image.height,
              !image.data.isEmpty, image.data.count <= 8388608, image.displayScale.isFinite, image.displayScale > 0 else {
            throw NativeFailure("native_image_limit")
        }
        let after = try driver.captureWindowState(granted.app, source: observation.window)
        guard after.bounds == observation.window.bounds else { throw NativeFailure("native_window_moved") }
        guard after.cgWindowID == observation.window.cgWindowID else { throw NativeFailure("native_window_identity_changed") }
        let imageScaleX = Double(image.width) / after.bounds.width, imageScaleY = Double(image.height) / after.bounds.height
        guard imageScaleX.isFinite, imageScaleY.isFinite, imageScaleX > 0, imageScaleY > 0 else {
            throw NativeFailure("native_image_limit")
        }
        let (current, _) = try checkedObservation(id, observationID: observationID, control: false)
        guard current.app == granted.app, current.targetGeneration == granted.targetGeneration,
              current.capture, driver.screenAllowed else { throw NativeFailure("native_capture_not_granted") }
        let total = captures.values.reduce(0) { $0 + $1.0.count }
        guard captures.count < 4, total + image.data.count <= 33554432 else { throw NativeFailure("native_capture_storage_limit") }
        let captureID = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let budget = granted.trustRevision == nil ? 5.0 : 30.0
        let proof = NativeCaptureProof(captureID: captureID, observationID: observationID, lease: granted,
            observationStarted: observation.freshnessStarted, windowID: observation.window.id, bounds: observation.window.bounds,
            clockGeneration: observation.clockGeneration,
            captureStarted: captureStarted, captureFinished: captureFinished,
            deadline: min(observation.freshnessStarted + 30, captureStarted + budget), budget: budget,
            cgWindowID: image.cgWindowID, width: image.width, height: image.height, displayScale: image.displayScale)
        let armedAt = try freshnessTime()
        try requireCaptureFresh(proof, at: armedAt)
        try driver.cancellationCheck?()
        captures[captureID] = (image.data, now())
        captureProofs[observationID] = proof
        retiredCaptureProofs.removeValue(forKey: observationID)
        retiredCaptureOrder.removeAll { $0 == observationID }
        // These bracket the signed app's capture call, not a compositor frame
        // timestamp. AX and pixels are separate observations even on success.
        let elapsed = captureFinishedAt - captureStartedAt
        let validInterval = captureStartedAt.isFinite && captureFinishedAt.isFinite && elapsed.isFinite && elapsed >= 0
        func timestamp(_ value: Double?) -> Any { value.flatMap { $0.isFinite ? $0 : nil } as Any? ?? NSNull() }
        var result: [String: Any] = ["ok": true, "lease_id": id, "capture_id": captureID, "bytes": image.data.count,
                "sha256": SHA256.hash(data: image.data).map { String(format: "%02x", $0) }.joined(),
                "width": image.width, "height": image.height, "display_scale": image.displayScale,
                "image_scale_x": imageScaleX, "image_scale_y": imageScaleY,
                "full_display_resolution": Double(image.width) >= after.bounds.width * image.displayScale
                    && Double(image.height) >= after.bounds.height * image.displayScale,
                "source_observation_id": observationID,
                "observation_timing": ["observed_at": timestamp(observation.created),
                    "tree_present": observation.window.tree != nil,
                    "tree_started_at": timestamp(observation.window.tree?.startedAt),
                    "tree_finished_at": timestamp(observation.window.tree?.finishedAt),
                    "atomic_with_capture": false],
                "capture_timing": ["started_at": timestamp(captureStartedAt), "finished_at": timestamp(captureFinishedAt),
                    "wall_elapsed_seconds": validInterval ? elapsed as Any : NSNull(),
                    "clock": "unix_seconds_wall_clock", "scope": "signed_app_capture_call",
                    "interval_state": validInterval ? "recorded" : "clock_discontinuity"],
                "window_bounds": nativeDictionary(after.bounds), "checked_at": now(), "potentially_sensitive": true]
        result.merge(captureProvenance(proof, at: armedAt)) { _, new in new }
        result["capture_call_elapsed_seconds"] = captureFinished - captureStarted
        result["validity_timing_scope"] = "capture_arm"
        if let preparation = preparation { result["renderer_preparation"] = preparation }
        return result
    }

    private func inspectionIdentity(_ window: NativeWindow) throws -> NativeWindowIdentityDiagnostic {
        guard let identity = window.identityDiagnostic, identity.getterAvailability == .available,
              identity.provenance == .privateAXWindowID, [.mappedDirect, .boundsMismatch].contains(identity.state),
              let candidate = identity.candidateWindowID, candidate > 0,
              window.cgWindowID == nil || window.cgWindowID == candidate,
              let logical = identity.logicalBounds, logical.finite, logical == window.bounds,
              let compositor = identity.compositorBounds, compositor.finite else {
            throw NativeFailure("native_capture_inspection_requires_exact_identity")
        }
        return identity
    }
    private func inspectionCapture(_ id: String, observationID: String, granted: Lease, observation: Observation) throws -> [String: Any] {
        let original = try inspectionIdentity(observation.window)
        let before = try driver.captureWindowState(granted.app, source: observation.window)
        let beforeIdentity = try inspectionIdentity(before)
        guard before.id == observation.window.id, beforeIdentity.candidateWindowID == original.candidateWindowID else {
            throw NativeFailure("native_window_identity_changed")
        }
        guard before.bounds == observation.window.bounds, beforeIdentity.logicalBounds == original.logicalBounds,
              beforeIdentity.compositorBounds == original.compositorBounds else { throw NativeFailure("native_window_moved") }
        let (admitted, _) = try checkedObservation(id, observationID: observationID, control: false)
        guard sameCaptureAuthority(granted, admitted) else { throw NativeFailure("native_claim_target_mismatch") }
        guard admitted.capture, driver.screenAllowed else { throw NativeFailure("native_capture_not_granted") }
        let captureStarted = try freshnessTime(), captureStartedAt = now()
        let image = try driver.captureInspection(granted.app, windowID: observation.window.id)
        try driver.cancellationCheck?()
        let captureFinishedAt = now(), captureFinished = try freshnessTime()
        guard captureFinished >= captureStarted, (captureFinished - captureStarted).isFinite else {
            throw NativeFailure("native_freshness_clock_invalid")
        }
        guard let inspection = image.inspection, inspection.windowID == image.cgWindowID,
              inspection.windowID == original.candidateWindowID, inspection.ownerPID == granted.app.pid else {
            throw NativeFailure("native_window_identity_changed")
        }
        guard inspection.logicalBounds == original.logicalBounds, inspection.compositorBounds == original.compositorBounds else {
            throw NativeFailure("native_window_moved")
        }
        guard image.width > 0, image.height > 0, image.width <= 16777216 / image.height,
              !image.data.isEmpty, image.data.count <= 8388608, image.displayScale.isFinite, image.displayScale > 0 else {
            throw NativeFailure("native_image_limit")
        }
        guard inspection.scFrame.finite, inspection.filterContentRect.finite,
              inspection.filterPointPixelScale.isFinite, inspection.filterPointPixelScale > 0, inspection.filterPointPixelScale <= 8,
              inspection.filterWindowCount == 1, inspection.filterHasOnlyCandidateWindow,
              inspection.ignoreGlobalClipSingleWindow, inspection.ignoreShadowsSingleWindow,
              !inspection.contentMappingVerified, !inspection.frameAgeKnown else {
            throw NativeFailure("native_capture_inspection_scope_unverified")
        }
        let after = try driver.captureWindowState(granted.app, source: observation.window)
        let afterIdentity = try inspectionIdentity(after)
        guard after.id == before.id, afterIdentity.candidateWindowID == original.candidateWindowID else {
            throw NativeFailure("native_window_identity_changed")
        }
        guard after.bounds == observation.window.bounds, afterIdentity.logicalBounds == original.logicalBounds,
              afterIdentity.compositorBounds == original.compositorBounds else { throw NativeFailure("native_window_moved") }
        let (current, _) = try checkedObservation(id, observationID: observationID, control: false)
        guard sameCaptureAuthority(granted, current) else { throw NativeFailure("native_claim_target_mismatch") }
        guard current.capture, driver.screenAllowed else { throw NativeFailure("native_capture_not_granted") }
        guard fresh(observation, at: try freshnessTime()) else { throw NativeFailure("stale_native_observation") }
        let total = captures.values.reduce(0) { $0 + $1.0.count }
        guard captures.count < 4, total + image.data.count <= 33554432 else { throw NativeFailure("native_capture_storage_limit") }
        let captureID = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        try driver.cancellationCheck?()
        captures[captureID] = (image.data, now())
        // No NativeCaptureProof exists for these pixels. SCK layout and the AX
        // frame remain separate observations even when identity is exact.
        let elapsed = captureFinishedAt - captureStartedAt
        let validInterval = captureStartedAt.isFinite && captureFinishedAt.isFinite && elapsed.isFinite && elapsed >= 0
        func timestamp(_ value: Double?) -> Any { value.flatMap { $0.isFinite ? $0 : nil } as Any? ?? NSNull() }
        return ["ok": true, "lease_id": id, "capture_id": captureID, "bytes": image.data.count,
            "sha256": SHA256.hash(data: image.data).map { String(format: "%02x", $0) }.joined(),
            "width": image.width, "height": image.height, "capture_purpose": "inspection", "input_armed": false,
            "inspection": nativeDictionary(inspection), "content_mapping_verified": false, "frame_age_known": false,
            "source_observation_id": observationID,
            "observation_timing": ["observed_at": timestamp(observation.created),
                "tree_present": observation.window.tree != nil, "tree_started_at": timestamp(observation.window.tree?.startedAt),
                "tree_finished_at": timestamp(observation.window.tree?.finishedAt), "atomic_with_capture": false],
            "capture_timing": ["started_at": timestamp(captureStartedAt), "finished_at": timestamp(captureFinishedAt),
                "wall_elapsed_seconds": validInterval ? elapsed as Any : NSNull(), "clock": "unix_seconds_wall_clock",
                "scope": "signed_app_capture_call", "interval_state": validInterval ? "recorded" : "clock_discontinuity"],
            "capture_call_elapsed_seconds": captureFinished - captureStarted,
            "window_bounds": nativeDictionary(after.bounds), "checked_at": now(), "potentially_sensitive": true]
    }

    func capturePage(_ id: String, offset: Int, count: Int) throws -> [String: Any] {
        expire()
        guard let image = captures[id], (0...image.0.count).contains(offset), (1...32768).contains(count) else {
            throw NativeFailure("native_capture_unavailable")
        }
        let end = min(image.0.count, offset + count)
        return ["ok": true, "capture_id": id, "offset": offset, "total_bytes": image.0.count,
                "data": image.0.subdata(in: offset..<end).base64EncodedString(), "eof": end == image.0.count]
    }

    func temporaryClipboard(_ id: String, expectedChangeCount: Int, text: String) throws -> [String: Any] {
        try temporaryClipboard(id, expectedChangeCount: expectedChangeCount, payload: NativeClipboardPayload(text: text))
    }
    func temporaryClipboard(_ id: String, expectedChangeCount: Int, payload: NativeClipboardPayload) throws -> [String: Any] {
        guard expectedChangeCount >= 0 else { throw NativeFailure("invalid_native_clipboard_count") }
        let granted = try lease(id, control: true)
        guard granted.clipboard else { throw NativeFailure("native_clipboard_not_granted") }
        // The centre's serial operation queue owns this model. A global pasteboard
        // preimage cannot be nested by another claim, even after Stop or human Copy.
        if let pending = clipboardLeases.first {
            let failure = NativeFailure("clipboard_lease_active")
            guard pending.value.leaseID == id else { throw failure }
            throw clipboardFailure(failure, token: pending.key)
        }
        let original = try driver.clipboard()
        guard original.changeCount == expectedChangeCount else { throw NativeFailure("clipboard_changed") }
        let token = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        clipboardLeases[token] = ClipboardLease(leaseID: id, original: original, ownerSession: granted.ownerSession,
            temporary: nil, state: "write_pending")
        let requested = payload.items
        let temporary: NativeClipboard
        do {
            temporary = try driver.writeClipboard(requested, expectedChangeCount: original.changeCount)
            let next = original.changeCount.addingReportingOverflow(1)
            guard !next.overflow, temporary.changeCount == next.partialValue, temporary.items == requested else {
                throw NativeFailure("clipboard_write_unverified", "unknown")
            }
        } catch {
            clipboardLeases[token]?.state = "recovery_only"
            throw clipboardFailure(error, token: token)
        }
        clipboardLeases[token]?.temporary = temporary
        clipboardLeases[token]?.state = "temporary_verified"
        return ["ok": true, "lease_id": id, "clipboard_lease_id": token, "change_count": temporary.changeCount,
                "effect_state": "applied", "representations": payload.metadata,
                "effect_scope": "clipboard_write_readback", "consumer_effect_verified": false,
                "restoration": "Explicit restore compares the current clipboard; expiry never overwrites it."]
    }
    func restoreClipboard(_ token: String, ownerSession: String? = nil) throws -> [String: Any] {
        guard let saved = clipboardLeases[token] else { throw NativeFailure("unknown_clipboard_lease") }
        try verifyClipboardOwner(saved, ownerSession: ownerSession)
        guard saved.state == "temporary_verified", let temporary = saved.temporary else {
            throw clipboardFailure(NativeFailure("clipboard_recovery_unverified"), token: token)
        }
        do { guard try driver.clipboard() == temporary else { throw NativeFailure("clipboard_changed") } }
        catch { throw clipboardFailure(error, token: token) }
        clipboardLeases[token]?.state = "restore_pending"
        let restored: NativeClipboard
        do {
            restored = try driver.writeClipboard(saved.original.items, expectedChangeCount: temporary.changeCount)
            let next = temporary.changeCount.addingReportingOverflow(1)
            guard !next.overflow, restored.changeCount == next.partialValue, restored.items == saved.original.items else {
                throw NativeFailure("clipboard_restore_unverified", "unknown")
            }
        } catch {
            clipboardLeases[token]?.state = "recovery_only"
            throw clipboardFailure(error, token: token)
        }
        clipboardLeases.removeValue(forKey: token)
        return ["ok": true, "clipboard_lease_id": token, "restored": true,
                "change_count": restored.changeCount, "effect_state": "applied"]
    }
    private func clipboardFailure(_ error: Error, token: String) -> NativeFailure {
        let failure = error as? NativeFailure ?? NativeFailure("clipboard_operation_failed", "unknown")
        return NativeFailure(failure.code, failure.effectState, clipboardRecovery: [
            "clipboard_lease_id": token, "preimage_retained": clipboardLeases[token] != nil,
            "state": clipboardLeases[token]?.state ?? "unavailable", "automatic_restoration": false,
            "durability": "app_process_memory"])
    }
    private func verifyClipboardOwner(_ saved: ClipboardLease, ownerSession: String?) throws {
        // This captured owner outlives active claim authority. Local UI may make an
        // explicit choice; authenticated channel calls always supply their owner.
        if let owner = saved.ownerSession, ownerSession != nil, ownerSession != owner {
            throw NativeFailure("native_clipboard_owner_mismatch")
        }
    }
    func releaseClipboard(_ token: String, ownerSession: String? = nil) throws -> [String: Any] {
        guard let saved = clipboardLeases[token] else { throw NativeFailure("unknown_clipboard_lease") }
        try verifyClipboardOwner(saved, ownerSession: ownerSession)
        clipboardLeases.removeValue(forKey: token)
        return ["ok": true, "clipboard_lease_id": token, "released": true, "clipboard_modified": false]
    }
    func storePayload(_ data: Data) throws -> [String: Any] {
        expire()
        guard data.count <= 8388608, captures.count < 4, captures.values.reduce(0, { $0 + $1.0.count }) + data.count <= 33554432 else {
            throw NativeFailure("native_result_storage_limit")
        }
        let id = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        captures[id] = (data, now())
        resultPayloadIDs.insert(id)
        return ["capture_id": id, "bytes": data.count, "payload_kind": "result",
                "sha256": SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()]
    }
    func releaseResultPayload(_ id: String, bytes: Int, sha256: String) throws -> [String: Any] {
        expire()
        // Image permits cannot be deleted through result-transfer cleanup.
        guard resultPayloadIDs.contains(id), let stored = captures[id], stored.0.count == bytes,
              SHA256.hash(data: stored.0).map({ String(format: "%02x", $0) }).joined() == sha256 else {
            throw NativeFailure("native_result_release_mismatch")
        }
        captures.removeValue(forKey: id)
        resultPayloadIDs.remove(id)
        return ["ok": true, "capture_id": id, "released": true, "bytes": bytes,
                "sha256": sha256, "input_authority_changed": false]
    }
}

func nativeDictionary<T: Encodable>(_ value: T) -> [String: Any] {
    guard let data = try? JSONEncoder().encode(value), let result = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
    return result
}
