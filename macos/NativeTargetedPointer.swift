import AppKit
import ApplicationServices
import Darwin

/// Internal policy only; no remote mode parameter or retry between preludes.
enum NativePointerActivationMode: String {
    case activationPoint = "activation_point"
    case codeContextOnly = "code_context_only"
    case windowContextOnly = "window_context_only"

    static func forVerifiedApp(_ app: NativeAppIdentity, verifyCurrentSignature: () -> Bool) throws -> Self {
        guard app.bundleID == "com.microsoft.VSCode", app.signingIdentifier == "com.microsoft.VSCode",
              app.teamID == "UBF8T346G9", let requirement = app.designatedRequirement, !requirement.isEmpty else {
            return .activationPoint
        }
        guard verifyCurrentSignature() else { throw NativeFailure("native_process_identity_changed") }
        return .codeContextOnly
    }

    /// A successful, finite AX point outside fresh verified window geometry is
    /// unusable metadata. Select the existing scoped prelude before dispatch;
    /// failed reads, malformed values and geometry never gain eligibility.
    static func outsideActivationPoint(_ app: NativeAppIdentity, point: NativePoint?, bounds: NativeRect,
        attributeResult: AXError, attributeReadAttempted: Bool,
        verifyCurrentSignature: () -> Bool) throws -> Self {
        guard attributeReadAttempted, attributeResult == .success,
              let point = point, point.x.isFinite, point.y.isFinite,
              bounds.finite, (bounds.x + bounds.width).isFinite, (bounds.y + bounds.height).isFinite,
              !bounds.contains(point),
              let signingIdentifier = app.signingIdentifier, !signingIdentifier.isEmpty,
              let requirement = app.designatedRequirement, !requirement.isEmpty else {
            return .activationPoint
        }
        guard verifyCurrentSignature() else { throw NativeFailure("native_process_identity_changed") }
        return .windowContextOnly
    }

    /// Missing optional AX metadata can use the same scoped private-source
    /// prelude. This selects a candidate mechanism, not receiver qualification.
    /// A timeout, failed read or malformed value must retain the strict path.
    static func withoutActivationPoint(_ app: NativeAppIdentity, attributeResult: AXError,
        attributeReadAttempted: Bool, verifyCurrentSignature: () -> Bool) throws -> Self {
        guard attributeReadAttempted,
              attributeResult == .attributeUnsupported || attributeResult == .noValue,
              let signingIdentifier = app.signingIdentifier, !signingIdentifier.isEmpty,
              let requirement = app.designatedRequirement, !requirement.isEmpty else {
            return .activationPoint
        }
        guard verifyCurrentSignature() else { throw NativeFailure("native_process_identity_changed") }
        return .windowContextOnly
    }
}

/// PID/window input with private source state; no global-HID or pointer warping.
/// Delivery is still unverified until the target's effect is observed.
struct NativeTargetedPointerPresentation {
    let app: NativeAppIdentity
    let windowNumber: UInt32
    let bounds: NativeRect
    let point: NativePoint
    let marker: Int64
    let eventType: UInt32
}

/// A validated hold refresh is metadata, not an input dispatch receipt.
struct NativeTargetedPointerHoldPresentation {
    let app: NativeAppIdentity
    let windowNumber: UInt32
    let bounds: NativeRect
    let point: NativePoint
    let marker: Int64
    let action: String
    let requestedHoldMS: Int
    let elapsedWaitMS: Double
}

final class NativeTargetedPointer {
    typealias WindowLocation = @convention(c) (CGEvent, CGPoint) -> Void
    private let library: UnsafeMutableRawPointer?
    private let windowLocation: WindowLocation?
    private let permissions: () -> Bool
    private let foreground: () -> Int32?
    private let send: (CGEvent, Int32) throws -> Void
    private let trace: ([String: Any]) -> Void
    private let presentation: (NativeTargetedPointerPresentation) -> Void
    private let holdPresentation: (NativeTargetedPointerHoldPresentation) -> Void
    private let monotonic: () -> UInt64
    private let holdSleep: (UInt64) -> Void
    private let clickSleep: (TimeInterval) -> Void
    init(permissions: @escaping () -> Bool = { CGPreflightPostEventAccess() && AXIsProcessTrusted() },
         foreground: @escaping () -> Int32? = { NSWorkspace.shared.frontmostApplication?.processIdentifier },
         send: @escaping (CGEvent, Int32) throws -> Void = { event, pid in event.postToPid(pid) },
         trace: @escaping ([String: Any]) -> Void = { _ in },
         presentation: @escaping (NativeTargetedPointerPresentation) -> Void = { _ in },
         holdPresentation: @escaping (NativeTargetedPointerHoldPresentation) -> Void = { _ in },
         monotonic: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds },
         holdSleep: @escaping (UInt64) -> Void = { nanoseconds in
             // nanosleep may finish early on a signal. The hold loop checks the
             // monotonic clock and validation again before any remaining wait.
             var interval = timespec(tv_sec: 0, tv_nsec: Int(nanoseconds))
             _ = nanosleep(&interval, nil)
         },
         clickSleep: @escaping (TimeInterval) -> Void = { Thread.sleep(forTimeInterval: $0) }) {
        self.permissions = permissions; self.foreground = foreground; self.send = send; self.trace = trace
        self.presentation = presentation; self.holdPresentation = holdPresentation; self.monotonic = monotonic
        self.holdSleep = holdSleep; self.clickSleep = clickSleep
        library = dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", RTLD_LAZY | RTLD_LOCAL)
        if let library = library, let symbol = dlsym(library, "CGEventSetWindowLocation") {
            windowLocation = unsafeBitCast(symbol, to: WindowLocation.self)
        } else { windowLocation = nil }
    }
    deinit { if let library = library { dlclose(library) } }
    var available: Bool { windowLocation != nil && permissions() }

    static func cursorPoint(_ row: [String: Any]) -> NativePoint? {
        guard let type = row["event_type"] as? UInt32,
              [CGEventType.leftMouseDown.rawValue, CGEventType.leftMouseUp.rawValue,
               CGEventType.leftMouseDragged.rawValue,
               CGEventType.rightMouseDown.rawValue, CGEventType.rightMouseUp.rawValue].contains(type),
              let x = row["x"] as? NSNumber, let y = row["y"] as? NSNumber,
              CFGetTypeID(x) != CFBooleanGetTypeID(), CFGetTypeID(y) != CFBooleanGetTypeID(),
              x.doubleValue.isFinite, y.doubleValue.isFinite else { return nil }
        return NativePoint(x: x.doubleValue, y: y.doubleValue)
    }

    func drag(app: NativeAppIdentity, windowNumber: UInt32, bounds: NativeRect, point: NativePoint,
              drag: NativeDrag, activationPoint: NativePoint?, marker: Int64,
              activationMode: NativePointerActivationMode = .activationPoint,
              guardedSend: (((() throws -> Void)) throws -> Void)? = nil,
              validate: @escaping (_ releasing: Bool) throws -> Void) throws {
        try perform(app: app, windowNumber: windowNumber, bounds: bounds, point: point,
                    action: "drag", wheel: nil, holdMS: nil, drag: drag, activationPoint: activationPoint,
                    marker: marker, activationMode: activationMode, guardedSend: guardedSend, validate: validate)
    }
    func click(app: NativeAppIdentity, windowNumber: UInt32, bounds: NativeRect, point: NativePoint,
               action: String, modifiers: [String] = [], activationPoint: NativePoint?, marker: Int64,
               activationMode: NativePointerActivationMode = .activationPoint,
              guardedSend: (((() throws -> Void)) throws -> Void)? = nil,
               validate: @escaping (_ releasing: Bool) throws -> Void) throws {
        try perform(app: app, windowNumber: windowNumber, bounds: bounds, point: point,
                    action: action, wheel: nil, holdMS: nil, clickModifiers: modifiers, activationPoint: activationPoint, marker: marker,
                    activationMode: activationMode, guardedSend: guardedSend, validate: validate)
    }

    /// Explicit finite holds only. The public caller must reject untyped JSON
    /// numbers before reaching this Int boundary; no Boolean/NSNumber coercion.
    func hold(app: NativeAppIdentity, windowNumber: UInt32, bounds: NativeRect, point: NativePoint,
              action: String, holdMS: Int, activationPoint: NativePoint?, marker: Int64,
              schedule: ((UInt64, @escaping () -> Void) -> Void)? = nil,
              activationMode: NativePointerActivationMode = .activationPoint,
              guardedSend: (((() throws -> Void)) throws -> Void)? = nil,
              validate: @escaping (_ releasing: Bool) throws -> Void) throws {
        guard ["hold", "right_hold"].contains(action), (1...5000).contains(holdMS) else {
            throw NativeFailure("native_hold_duration_outside_scope")
        }
        try perform(app: app, windowNumber: windowNumber, bounds: bounds, point: point,
                    action: action, wheel: nil, holdMS: holdMS, activationPoint: activationPoint, marker: marker,
                    schedule: schedule,
                    activationMode: activationMode, guardedSend: guardedSend, validate: validate)
    }

    /// Deltas use CG pixel units, exposed by AppKit as precise scrolling points.
    /// Positive X/Y means right/down content offset in top-left coordinates;
    /// Quartz wheel axes have the opposite sign. No backing-scale conversion.
    func scroll(app: NativeAppIdentity, windowNumber: UInt32, bounds: NativeRect, point: NativePoint,
                deltaX: Int32, deltaY: Int32, activationPoint: NativePoint?, marker: Int64,
                activationMode: NativePointerActivationMode = .activationPoint,
              guardedSend: (((() throws -> Void)) throws -> Void)? = nil,
                validate: @escaping (_ releasing: Bool) throws -> Void) throws {
        try perform(app: app, windowNumber: windowNumber, bounds: bounds, point: point,
                    action: "scroll", wheel: (deltaX, deltaY), holdMS: nil, activationPoint: activationPoint, marker: marker,
                    activationMode: activationMode, guardedSend: guardedSend, validate: validate)
    }

    private func perform(app: NativeAppIdentity, windowNumber: UInt32, bounds: NativeRect, point: NativePoint,
                         action: String, wheel: (x: Int32, y: Int32)?, holdMS: Int?, drag: NativeDrag? = nil,
                         clickModifiers: [String] = [], activationPoint: NativePoint?, marker: Int64,
                         schedule: ((UInt64, @escaping () -> Void) -> Void)? = nil,
                         activationMode: NativePointerActivationMode,
                         guardedSend: (((() throws -> Void)) throws -> Void)?,
                         validate: @escaping (_ releasing: Bool) throws -> Void) throws {
        try performWithFocus(app: app, windowNumber: windowNumber, bounds: bounds, point: point,
            action: action, wheel: wheel, holdMS: holdMS, drag: drag, clickModifiers: clickModifiers, activationPoint: activationPoint,
            marker: marker, schedule: schedule, activationMode: activationMode,
            guardedSend: guardedSend, validate: validate, body: {})
    }

    /// Keeps this exact target's synthetic focus alive through an internal body.
    /// A deferred body retains the same cleanup state until its terminal callback.
    /// Callers still own recipient qualification, atomic admission of body input,
    /// effect readback, deadlines/cancellation completion and the serial lane.
    func withFocusContext<Value>(app: NativeAppIdentity, windowNumber: UInt32, bounds: NativeRect,
        point: NativePoint, activationPoint: NativePoint?, marker: Int64,
        activationMode: NativePointerActivationMode = .activationPoint,
        guardedSend: (((() throws -> Void)) throws -> Void)? = nil,
        validate: @escaping (_ releasing: Bool) throws -> Void,
        body: @escaping () throws -> Value) throws -> Value {
        try performWithFocus(app: app, windowNumber: windowNumber, bounds: bounds, point: point,
            action: "click", wheel: nil, holdMS: nil, focusOnly: true, activationPoint: activationPoint,
            marker: marker, activationMode: activationMode, guardedSend: guardedSend,
            validate: validate, body: body)
    }

    private func performWithFocus<Value>(app: NativeAppIdentity, windowNumber: UInt32, bounds: NativeRect, point: NativePoint,
                         action: String, wheel: (x: Int32, y: Int32)?, holdMS: Int?, drag: NativeDrag? = nil,
                         focusOnly: Bool = false, clickModifiers: [String] = [], activationPoint: NativePoint?, marker: Int64,
                         schedule: ((UInt64, @escaping () -> Void) -> Void)? = nil,
                         activationMode: NativePointerActivationMode,
                         guardedSend: (((() throws -> Void)) throws -> Void)?,
                         validate: @escaping (_ releasing: Bool) throws -> Void,
                         body: @escaping () throws -> Value) throws -> Value {
        try NativePointerClickModifiers.validate(clickModifiers)
        guard clickModifiers.isEmpty || (action == "click" && wheel == nil && holdMS == nil && drag == nil && !focusOnly) else {
            throw NativeFailure("native_pointer_modifiers_outside_scope")
        }
        var modifierFlags: NSEvent.ModifierFlags = []
        for modifier in clickModifiers {
            switch modifier {
            case "command": modifierFlags.insert(.command)
            case "control": modifierFlags.insert(.control)
            case "option": modifierFlags.insert(.option)
            case "shift": modifierFlags.insert(.shift)
            default: throw NativeFailure("native_pointer_modifiers_invalid")
            }
        }
        guard available else { throw NativeFailure("native_targeted_pointer_unavailable") }
        if focusOnly {
            guard app.pid > 0, windowNumber > 0, bounds.finite, bounds.contains(point),
                  drag == nil, wheel == nil, holdMS == nil else {
                throw NativeFailure("native_point_outside_scope")
            }
        }
        var dragPath: [NativePoint]?
        if let drag = drag {
            let path = try drag.path(from: point)
            guard action == "drag", wheel == nil, holdMS == nil, app.pid > 0, windowNumber > 0,
                  bounds.finite, bounds.contains(point), path.allSatisfy({ bounds.contains($0) }) else {
                throw NativeFailure("native_drag_invalid")
            }
            dragPath = path
        } else if let wheel = wheel {
            guard app.pid > 0, windowNumber > 0, bounds.finite,
                  point.x.isFinite, point.y.isFinite, bounds.contains(point) else {
                throw NativeFailure("native_point_outside_scope")
            }
            guard (-2000...2000).contains(wheel.x), (-2000...2000).contains(wheel.y),
                  wheel.x != 0 || wheel.y != 0 else { throw NativeFailure("native_scroll_delta_outside_scope") }
        } else {
            let actions = holdMS == nil ? ["click", "double_click", "right_click"] : ["hold", "right_hold"]
            guard actions.contains(action), bounds.finite, bounds.contains(point),
                  holdMS == nil || (app.pid > 0 && windowNumber > 0) else {
                throw NativeFailure("native_point_outside_scope")
            }
        }
        guard let source = CGEventSource(stateID: .privateState) else { throw NativeFailure("native_event_source_unavailable") }
        var held: CGEvent?, sent = 0, possiblySent = false, syntheticFocusSent = false
        var releaseUnconfirmed = false
        var focusCleanupAttempted = Set<UInt>(), focusCleanupConfirmed = Set<UInt>()
        var phase = "initial_validation"
        var holdStarted: UInt64?, lastHoldClock: UInt64?, holdClockInvalid = false
        var holdTimingEmitted = false, holdWaitChecks = 0
        func readHoldClock() throws -> UInt64 {
            let now = monotonic()
            guard lastHoldClock == nil || now >= lastHoldClock! else {
                holdClockInvalid = true
                throw NativeFailure("native_hold_clock_invalid", "unknown")
            }
            lastHoldClock = now
            return now
        }
        func holdTiming(releaseDispatched: Bool) {
            guard let requested = holdMS, let started = holdStarted, !holdTimingEmitted else { return }
            holdTimingEmitted = true
            let now = monotonic()
            let valid = !holdClockInvalid && now >= started && (lastHoldClock == nil || now >= lastHoldClock!)
            let elapsed: Any = valid ? Double(now - started) / 1_000_000 : NSNull()
            trace(["kind": "hold_timing", "requested_hold_ms": requested,
                   "elapsed_hold_ms": releaseDispatched ? elapsed : NSNull(),
                   "elapsed_until_cleanup_ms": elapsed, "wait_checks": holdWaitChecks,
                   "clock_valid": valid, "release_dispatch_state": releaseDispatched ? "possibly_sent" : "not_dispatched",
                   "elapsed_basis": releaseDispatched ? "down_dispatch_to_release_dispatch" : "down_dispatch_to_cleanup_end",
                   "pid": app.pid, "window_number": windowNumber, "x": point.x, "y": point.y,
                   "effect_state": "unknown_until_target_readback"])
        }
        func present(_ event: CGEvent) {
            guard [CGEventType.leftMouseDown, .leftMouseUp, .leftMouseDragged, .rightMouseDown, .rightMouseUp, .scrollWheel].contains(event.type) else { return }
            presentation(NativeTargetedPointerPresentation(app: app, windowNumber: windowNumber, bounds: bounds,
                point: NativePoint(x: event.location.x, y: event.location.y), marker: marker, eventType: event.type.rawValue))
        }
        func post(_ event: CGEvent, releasing: Bool = false, activating: Bool = false,
                  ownedRelease: Bool = false, moveRelease: CGEvent? = nil, focusCleanupType: UInt? = nil) throws {
            phase = releasing ? "release_validation" : "event_validation"
            try validate(releasing)
            phase = releasing ? "release_permission" : "event_permission"
            guard permissions() else { throw NativeFailure("native_input_permission_revoked", sent == 0 ? "none" : "unknown") }
            event.setIntegerValueField(.eventSourceUserData, value: marker)
            event.setIntegerValueField(.eventTargetUnixProcessID, value: Int64(app.pid))
            event.timestamp = DispatchTime.now().uptimeNanoseconds
            let dispatch = {
                phase = releasing ? "release_send" : "event_send"
                possiblySent = true
                if let moveRelease = moveRelease { held = moveRelease }
                if activating { syntheticFocusSent = true }
                // A possible send consumes this exact owned release. Refusal
                // before this boundary leaves it eligible for guarded cleanup.
                if ownedRelease { held = nil; releaseUnconfirmed = true; holdTiming(releaseDispatched: true) }
                if let type = focusCleanupType { focusCleanupAttempted.insert(type) }
                try self.send(event, app.pid)
                if ownedRelease { releaseUnconfirmed = false }
                if let type = focusCleanupType { focusCleanupConfirmed.insert(type) }
            }
            phase = releasing ? "release_admission" : "event_admission"
            if !releasing, let guardedSend = guardedSend { try guardedSend(dispatch) }
            else { try dispatch() }
            sent += 1
            var row: [String: Any] = ["sequence": sent, "kind": releasing ? "release" : "event", "event_type": event.type.rawValue,
                   "category": event.type == .scrollWheel ? "wheel" : ([UInt32(13), UInt32(21)].contains(event.type.rawValue) ? "focus_context" : "mouse"),
                   "pid": app.pid, "window_number": windowNumber, "x": event.location.x, "y": event.location.y,
                   "effect_state": "unknown_until_target_readback"]
            if event.type == .scrollWheel, let wheel = wheel {
                row["delta_x"] = wheel.x; row["delta_y"] = wheel.y; row["units"] = "pixel"
                row["window_x"] = point.x - bounds.x; row["window_y"] = point.y - bounds.y
                row["cg_point_delta_axis1"] = event.getIntegerValueField(.scrollWheelEventPointDeltaAxis1)
                row["cg_point_delta_axis2"] = event.getIntegerValueField(.scrollWheelEventPointDeltaAxis2)
            }
            trace(row)
            present(event)
        }
        func mouse(_ type: NSEvent.EventType, _ location: NativePoint, count: Int, flags: NSEvent.ModifierFlags = []) throws -> CGEvent {
            phase = (type == .leftMouseUp || type == .rightMouseUp) ? "mouse_up_creation" : "mouse_down_creation"
            let global = CGPoint(x: location.x, y: location.y)
            guard let ns = NSEvent.mouseEvent(with: type, location: global, modifierFlags: flags, timestamp: 0,
                windowNumber: Int(windowNumber), context: nil, eventNumber: sent + 1, clickCount: count, pressure: 1),
                  let event = ns.cgEvent else { throw NativeFailure("native_event_creation_failed", sent == 0 ? "none" : "unknown") }
            event.location = global
            event.setSource(source)
            // Source attachment must not replace this event-local metadata.
            event.flags = CGEventFlags(rawValue: UInt64(flags.rawValue))
            event.setIntegerValueField(.mouseEventButtonNumber, value: (type == .rightMouseDown || type == .rightMouseUp) ? 1 : 0)
            event.setIntegerValueField(.mouseEventSubtype, value: 3)
            event.setIntegerValueField(.mouseEventWindowUnderMousePointer, value: Int64(windowNumber))
            event.setIntegerValueField(.mouseEventWindowUnderMousePointerThatCanHandleThisEvent, value: Int64(windowNumber))
            // The independently verified variant uses window-local top-left Y.
            windowLocation?(event, CGPoint(x: location.x - bounds.x, y: location.y - bounds.y))
            return event
        }
        func waitForHold(milliseconds: Int) throws {
            guard let started = holdStarted else { throw NativeFailure("native_hold_clock_invalid", "unknown") }
            let duration = UInt64(milliseconds) * 1_000_000
            var refreshAt = started
            // A clock/sleeper dependency that never advances sufficiently must
            // fail with cleanup, even if it returns tiny positive increments.
            for _ in 0..<1024 {
                phase = "hold_wait_validation"
                try validate(false)
                phase = "hold_wait_permission"
                guard permissions() else { throw NativeFailure("native_input_permission_revoked", "unknown") }
                phase = "hold_wait_clock"
                let now = try readHoldClock()
                let elapsed = now - started
                holdWaitChecks += 1
                if elapsed >= duration { return }
                if now - refreshAt >= 100_000_000 {
                    holdPresentation(NativeTargetedPointerHoldPresentation(app: app, windowNumber: windowNumber,
                        bounds: bounds, point: point, marker: marker, action: action,
                        requestedHoldMS: milliseconds, elapsedWaitMS: Double(elapsed) / 1_000_000))
                    refreshAt = now
                }
                phase = "hold_wait_sleep"
                holdSleep(min(20_000_000, duration - elapsed))
                let after = try readHoldClock()
                guard after > now else {
                    holdClockInvalid = true
                    throw NativeFailure("native_hold_clock_invalid", "unknown")
                }
            }
            throw NativeFailure("native_hold_wait_limit", "unknown")
        }
        func pair(_ location: NativePoint, count: Int, right: Bool = false, durationMS: Int? = nil, flags: NSEvent.ModifierFlags = []) throws {
            let up = try mouse(right ? .rightMouseUp : .leftMouseUp, location, count: count, flags: flags)
            let down = try mouse(right ? .rightMouseDown : .leftMouseDown, location, count: count, flags: flags)
            phase = "press_validation"
            try validate(false)
            phase = "press_permission"
            guard permissions() else { throw NativeFailure("native_input_permission_revoked", sent == 0 ? "none" : "unknown") }
            // Only a validated send boundary makes a matching release eligible.
            down.setIntegerValueField(.eventSourceUserData, value: marker)
            down.setIntegerValueField(.eventTargetUnixProcessID, value: Int64(app.pid))
            down.timestamp = DispatchTime.now().uptimeNanoseconds
            let dispatch = {
                phase = "press_send"
                if durationMS != nil { holdStarted = self.monotonic(); lastHoldClock = holdStarted }
                held = up; possiblySent = true
                try self.send(down, app.pid)
            }
            phase = "press_admission"
            if let guardedSend = guardedSend { try guardedSend(dispatch) }
            else { try dispatch() }
            sent += 1
            trace(["sequence": sent, "kind": "press", "event_type": down.type.rawValue, "pid": app.pid,
                   "category": "mouse",
                   "window_number": windowNumber, "x": down.location.x, "y": down.location.y,
                   "effect_state": "unknown_until_target_readback"])
            present(down)
            if let durationMS = durationMS, let schedule = schedule {
                // Retain these original event objects and all local cleanup state.
                // The timer owns no engine state; its callback only enqueues tick.
                throw NativeDeferred<Void> { completion in
                    var refreshAt = holdStarted!, previousWaitClock: UInt64?
                    var tick: (() -> Void)?
                    tick = {
                        do {
                            phase = "hold_wait_validation"; try validate(false)
                            phase = "hold_wait_permission"
                            guard self.permissions() else { throw NativeFailure("native_input_permission_revoked", "unknown") }
                            phase = "hold_wait_clock"
                            let now = try readHoldClock()
                            if let previous = previousWaitClock, now <= previous {
                                holdClockInvalid = true
                                throw NativeFailure("native_hold_clock_invalid", "unknown")
                            }
                            let elapsed = now - holdStarted!
                            holdWaitChecks += 1
                            if elapsed >= UInt64(durationMS) * 1_000_000 {
                                try post(up, releasing: true, ownedRelease: true)
                                tick = nil; completion(.success(())); return
                            }
                            guard holdWaitChecks <= 1024 else { throw NativeFailure("native_hold_wait_limit", "unknown") }
                            if now - refreshAt >= 100_000_000 {
                                self.holdPresentation(NativeTargetedPointerHoldPresentation(app: app, windowNumber: windowNumber,
                                    bounds: bounds, point: point, marker: marker, action: action,
                                    requestedHoldMS: durationMS, elapsedWaitMS: Double(elapsed) / 1_000_000))
                                refreshAt = now
                            }
                            phase = "hold_wait_sleep"; previousWaitClock = now
                            let delay = min(20_000_000, UInt64(durationMS) * 1_000_000 - elapsed)
                            schedule(delay) { tick?() }
                        } catch { tick = nil; completion(.failure(error)) }
                    }
                    schedule(0) { tick?() }
                }
            }
            if let durationMS = durationMS { try waitForHold(milliseconds: durationMS) }
            else { clickSleep(0.04) }
            try post(up, releasing: true, ownedRelease: true)
        }
        func focusEvent(type: UInt, subtype: Int16, cleanup: Bool = false) throws {
            guard let eventType = NSEvent.EventType(rawValue: type),
                  let ns = NSEvent.otherEvent(with: eventType, location: .zero,
                    modifierFlags: type == 13 && subtype == 1 ? NSEvent.ModifierFlags(rawValue: 0xc0000) : [],
                    timestamp: 0, windowNumber: Int(windowNumber), context: nil, subtype: subtype, data1: 0, data2: 0),
                  let event = ns.cgEvent else { throw NativeFailure("native_focus_event_unavailable", sent == 0 ? "none" : "unknown") }
            event.setSource(source)
            try post(event, releasing: cleanup, activating: type == 13 && subtype == 1,
                     focusCleanupType: cleanup ? type : nil)
        }
        func finishFocus() throws {
            guard syntheticFocusSent else { return }
            if foreground() == app.pid {
                if !focusCleanupAttempted.subtracting(focusCleanupConfirmed).isEmpty {
                    throw NativeFailure("native_focus_cleanup_unverified", "unknown")
                }
                return
            }
            // Each cleanup event is independent: continue the unsent remainder,
            // but never replay an acknowledged or possibly executed event.
            if !focusCleanupAttempted.contains(21) { try? focusEvent(type: 21, subtype: 0x4000, cleanup: true) }
            if !focusCleanupAttempted.contains(13) { try? focusEvent(type: 13, subtype: 2, cleanup: true) }
            guard focusCleanupConfirmed == Set([UInt(21), UInt(13)]) else {
                throw NativeFailure("native_focus_cleanup_unverified", "unknown")
            }
            syntheticFocusSent = false
        }
        func fail(_ error: Error, preservingTypedFailure: Bool = false) throws -> Never {
            // Keep the original partial-effect classification while retaining
            // its bounded cause before cleanup changes the current phase.
            trace(["kind": "failure", "phase": phase,
                   "cause": (error as? NativeFailure)?.code ?? "native_input_failure",
                   "sent_events": sent, "possibly_sent": possiblySent,
                   "effect_state": possiblySent ? "unknown" : "none"])
            var releaseFailed = releaseUnconfirmed, focusFailed = false
            if let up = held { do { try post(up, releasing: true, ownedRelease: true) } catch { releaseFailed = true } }
            do { try finishFocus() } catch { focusFailed = true }
            holdTiming(releaseDispatched: false)
            if preservingTypedFailure, let original = error as? NativeFailure {
                // Body recovery metadata remains authoritative even when focus
                // preparation widened the possible effect or cleanup failed.
                let code = releaseFailed ? "native_release_unverified" :
                    focusFailed ? "native_focus_cleanup_unverified" : original.code
                var failure = NativeFailure(code,
                    possiblySent || releaseFailed || focusFailed ? "unknown" : original.effectState,
                    clipboardRecovery: original.clipboardRecovery)
                failure.visualValidity = original.visualValidity
                failure.windowIdentity = original.windowIdentity
                throw failure
            }
            if releaseFailed { throw NativeFailure("native_release_unverified", "unknown") }
            if focusFailed { throw NativeFailure("native_focus_cleanup_unverified", "unknown") }
            if possiblySent { throw NativeFailure("native_targeted_input_partial", "unknown") }
            throw error
        }
        func runBody() throws -> Value {
            do {
                // The prelude itself may have changed authority or recipient state.
                if focusOnly {
                    try validate(false)
                    guard permissions() else { throw NativeFailure("native_input_permission_revoked", possiblySent ? "unknown" : "none") }
                }
                let value = try body()
                try finishFocus()
                return value
            } catch let deferred as NativeDeferred<Value> {
                throw deferred.mapResult { result in
                    do { let value = try result.get(); try finishFocus(); return value }
                    catch { try fail(error, preservingTypedFailure: focusOnly) }
                }
            } catch { try fail(error, preservingTypedFailure: focusOnly) }
        }
        // Build the complete finite gesture before its first possible input.
        // A cancelled move releases at the last possibly sent point, never at
        // a future endpoint that the recipient has not received.
        var dragDown: CGEvent?, dragUps: [CGEvent] = [], dragMoves: [CGEvent] = []
        if let path = dragPath {
            dragDown = try mouse(.leftMouseDown, point, count: 1)
            dragUps = try ([point] + path).map { try mouse(.leftMouseUp, $0, count: 1) }
            dragMoves = try path.map { try mouse(.leftMouseDragged, $0, count: 1) }
        }
        do {
            try validate(false)
            let needsPrelude = foreground() != app.pid
            trace(["kind": "activation_mode", "mode": activationMode.rawValue, "background_prelude": needsPrelude,
                   "pid": app.pid, "window_number": windowNumber, "effect_state": "not_established"])
            if needsPrelude {
                if activationMode == .activationPoint {
                    guard let activationPoint = activationPoint, bounds.contains(activationPoint) else {
                        throw NativeFailure("native_activation_point_unavailable")
                    }
                }
                try focusEvent(type: 13, subtype: 1)
                if activationMode == .activationPoint, let activationPoint = activationPoint {
                    try pair(activationPoint, count: 1)
                }
                try focusEvent(type: 21, subtype: Int16(bitPattern: 0x8000))
            }
            if let down = dragDown {
                phase = "drag_down_validation"; try validate(false)
                guard permissions() else { throw NativeFailure("native_input_permission_revoked", sent == 0 ? "none" : "unknown") }
                down.setIntegerValueField(.eventSourceUserData, value: marker)
                down.setIntegerValueField(.eventTargetUnixProcessID, value: Int64(app.pid))
                down.timestamp = DispatchTime.now().uptimeNanoseconds
                let dispatch = {
                    phase = "drag_down_send"; held = dragUps[0]; possiblySent = true
                    try self.send(down, app.pid)
                }
                phase = "drag_down_admission"
                if let guardedSend = guardedSend { try guardedSend(dispatch) } else { try dispatch() }
                sent += 1
                trace(["sequence": sent, "kind": "press", "category": "mouse", "event_type": down.type.rawValue,
                    "pid": app.pid, "window_number": windowNumber, "x": point.x, "y": point.y,
                    "effect_state": "unknown_until_target_readback"])
                present(down)
                for (index, move) in dragMoves.enumerated() {
                    try post(move, moveRelease: dragUps[index + 1])
                }
                try post(dragUps.last!, releasing: true, ownedRelease: true)
            } else if let wheel = wheel {
                phase = "wheel_creation"
                guard let windowField = CGEventField(rawValue: 51),
                      let event = CGEvent(scrollWheelEvent2Source: source, units: .pixel, wheelCount: 2,
                    wheel1: -wheel.y, wheel2: -wheel.x, wheel3: 0) else {
                    throw NativeFailure("native_event_creation_failed", sent == 0 ? "none" : "unknown")
                }
                event.location = CGPoint(x: point.x, y: point.y)
                // The pixel-wheel constructor ignores mouse window fields 91/92.
                // Field 51 preserves the exact NSEvent windowNumber (factory proof).
                event.setIntegerValueField(windowField, value: Int64(windowNumber))
                event.setIntegerValueField(.mouseEventWindowUnderMousePointer, value: Int64(windowNumber))
                event.setIntegerValueField(.mouseEventWindowUnderMousePointerThatCanHandleThisEvent, value: Int64(windowNumber))
                windowLocation?(event, CGPoint(x: point.x - bounds.x, y: point.y - bounds.y))
                try post(event)
            } else if !focusOnly {
                for count in 1...(action == "double_click" ? 2 : 1) {
                    try pair(point, count: count, right: action == "right_click" || action == "right_hold", durationMS: holdMS, flags: modifierFlags)
                }
            }
        } catch let deferred as NativeDeferred<Void> {
            throw deferred.mapResult { result in
                do { try result.get() }
                catch { try fail(error) }
                return try runBody()
            }
        } catch {
            try fail(error)
        }
        return try runBody()
    }
}
