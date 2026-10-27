import AppKit
import ApplicationServices

protocol NativeCursorSurface: AnyObject {
    var windowID: UInt32? { get }
    func show(_ plan: NativeCursorPlan)
    func hide()
}

final class NativeCursorScheduledWork {
    private let cancellation: () -> Void
    init(_ cancellation: @escaping () -> Void) { self.cancellation = cancellation }
    func cancel() { cancellation() }
}

/// A bounded, target-bound presentation of sent events; never app-effect proof.
/// Metadata queries run off the UI queue and cannot delay the independent hide.
final class NativeAgentCursor {
    typealias Reader = (NativeCursorTarget, UInt32?, @escaping (NativeCursorSnapshot) -> Void) -> Void
    typealias Enqueue = (@escaping () -> Void) -> Void
    typealias Schedule = (Double, @escaping () -> Void) -> NativeCursorScheduledWork
    private let lock = NSLock()
    private var lifecycle = NativeCursorLifecycle()
    private let now: () -> Double
    private let read: (NativeCursorTarget, UInt32?, @escaping (NativeCursorTracePhase) -> Void,
                       @escaping (NativeCursorSnapshot) -> Void) -> Void
    private let enqueue: Enqueue
    private let schedule: Schedule
    private let factory: () -> NativeCursorSurface
    private let disposition: (String) -> Void
    private let diagnostic: (NativeCursorTraceSignal) -> Void
    // UI-queue state only.
    private var surface: NativeCursorSurface?
    private var shown: NativeCursorTicket?
    private var shownExpiryWork: NativeCursorScheduledWork?
    private var refreshWork: NativeCursorScheduledWork?
    private var refreshTicket: NativeCursorTicket?
    private var expiryWork: NativeCursorScheduledWork?
    private var expiryTicket: NativeCursorTicket?
    private var lookupWork: NativeCursorScheduledWork?
    private var pendingLookup: UUID?
    private var lookupInFlight: UUID?
    private var lookupTicket: NativeCursorTicket?
    private static let refreshSeconds = 0.05
    private static let lookupSeconds = 0.1

    init(bindingCheck: ((NativeCursorTarget) -> Bool?)? = nil,
         now: @escaping () -> Double = { ProcessInfo.processInfo.systemUptime },
         reader: Reader? = nil,
         enqueue: @escaping Enqueue = { DispatchQueue.main.async(execute: $0) },
         schedule: @escaping Schedule = { delay, callback in
             let work = DispatchWorkItem(block: callback)
             DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: work)
             return NativeCursorScheduledWork { work.cancel() }
         }, factory: @escaping () -> NativeCursorSurface = { NativeCursorPanelSurface() },
         disposition: @escaping (String) -> Void = { _ in },
         diagnostic: @escaping (NativeCursorTraceSignal) -> Void = { _ in }) {
        self.now = now; self.enqueue = enqueue; self.schedule = schedule
        self.factory = factory; self.disposition = disposition
        self.diagnostic = diagnostic
        if let reader = reader { self.read = { target, overlay, _, completion in reader(target, overlay, completion) } }
        else {
            let queue = DispatchQueue(label: "tools.localworkbench.cursor-metadata")
            self.read = { target, overlay, trace, completion in
                let top = NativeCursorSystemSnapshot.screenTop()
                queue.async {
                    trace(.metadataQueueStart)
                    let snapshot = NativeCursorSystemSnapshot.read(target, overlay: overlay, top: top,
                        bindingCheck: bindingCheck, trace: trace)
                    trace(.metadataReadEnd)
                    completion(snapshot)
                }
            }
        }
    }
    private func state<T>(_ work: (inout NativeCursorLifecycle) -> T) -> T {
        lock.lock(); defer { lock.unlock() }; return work(&lifecycle)
    }
    func begin(operationID: String) -> NativeCursorGeneration {
        let generation = state { $0.begin(operationID: operationID) }
        enqueue { [weak self] in
            guard let self = self, self.state({ $0.generation == generation }) else { return }
            if self.shown?.presentation.generation != generation {
                let prior = self.shown
                if let prior = prior { self.trace(.hideRequest, prior) }
                self.surface?.hide(); self.shown = nil
                if let prior = prior { self.trace(.hideReturn, prior) }
            }
        }
        return generation
    }
    private func trace(_ phase: NativeCursorTracePhase, _ ticket: NativeCursorTicket, lookup: UUID? = nil,
                       reason: NativeCursorRefusal? = nil) {
        diagnostic(NativeCursorTraceSignal(generation: ticket.presentation.generation, ticketSerial: ticket.serial,
            lookup: lookup, phase: phase, requestedPoint: ticket.presentation.requestedPoint, reason: reason?.rawValue))
    }
    func sent(target: NativeCursorTarget, point: NativePoint, generation: NativeCursorGeneration, requestedPoint: Bool? = nil) {
        let presentation = NativeCursorPresentation(target: target, point: point, generation: generation, requestedPoint: requestedPoint)
        guard let ticket = state({ $0.enqueue(presentation, now: now()) }) else { return }
        trace(.enqueue, ticket)
        enqueue { [weak self] in self?.start(ticket) }
    }
    // Source-compatible fail-closed shim. A point alone never creates a panel.
    func sent(point: NativePoint) { disposition("cursor_target_required") }
    func invalidate(_ generation: NativeCursorGeneration) {
        guard state({ $0.invalidate(generation) }) else { return }
        diagnostic(NativeCursorTraceSignal(generation: generation, ticketSerial: nil, lookup: nil,
            phase: .invalidate, requestedPoint: nil, reason: nil))
        // Retirement may release the driver's last reference immediately.
        // Keep this one cleanup alive until its surface/timers are retired.
        enqueue { [self] in
            if self.shown?.presentation.generation == generation {
                let prior = self.shown
                if let prior = prior { self.trace(.hideRequest, prior) }
                self.shownExpiryWork?.cancel(); self.shownExpiryWork = nil
                self.surface?.hide(); self.shown = nil
                if let prior = prior { self.trace(.hideReturn, prior) }
            }
            if self.expiryTicket?.presentation.generation == generation {
                self.expiryWork?.cancel(); self.expiryTicket = nil
            }
            if self.lookupTicket?.presentation.generation == generation {
                self.lookupWork?.cancel(); self.pendingLookup = nil
            }
            if self.refreshTicket?.presentation.generation == generation {
                self.refreshWork?.cancel(); self.refreshTicket = nil
            }
        }
    }
    private func hide(_ ticket: NativeCursorTicket, reason: NativeCursorRefusal) {
        trace(.hideRequest, ticket, reason: reason)
        let current = state { $0.finish(ticket) }
        // An old timer may remove its own old pixels, but never newer pixels.
        // A failed current refresh also retires retained pixels from the same
        // operation, without touching a newer generation.
        if shown == ticket || (current && shown?.presentation.generation == ticket.presentation.generation) {
            shownExpiryWork?.cancel(); shownExpiryWork = nil
            surface?.hide(); shown = nil
        }
        if expiryTicket == ticket { expiryWork?.cancel(); expiryTicket = nil }
        if refreshTicket == ticket { refreshWork?.cancel(); refreshTicket = nil }
        if current { disposition(reason.rawValue) }
        trace(.hideReturn, ticket, reason: reason)
    }
    private func start(_ ticket: NativeCursorTicket) {
        trace(.uiStart, ticket)
        guard state({ $0.isCurrent(ticket) }) else { return }
        guard state({ $0.live(ticket, now: now()) }) else { hide(ticket, reason: .expired); return }
        refreshWork?.cancel(); expiryWork?.cancel()
        if shown != ticket {
            shownExpiryWork?.cancel(); shownExpiryWork = nil
            if let previous = shown, previous.presentation == ticket.presentation,
               now() >= previous.createdAt, now() < previous.expiresAt {
                // No validation or lifetime extension: retain exactly these
                // unchanged pixels only until their original ticket expires.
                shownExpiryWork = schedule(max(0, previous.expiresAt - now())) { [weak self] in
                    guard let self = self, self.shown == previous else { return }
                    self.trace(.hideRequest, previous, reason: .expired)
                    self.surface?.hide(); self.shown = nil; self.shownExpiryWork = nil
                    self.trace(.hideReturn, previous, reason: .expired)
                }
            } else {
                let prior = shown
                if let prior = prior { trace(.hideRequest, prior) }
                surface?.hide(); shown = nil
                if let prior = prior { trace(.hideReturn, prior) }
            }
        }
        expiryTicket = ticket
        expiryWork = schedule(max(0, ticket.expiresAt - now())) { [weak self] in self?.hide(ticket, reason: .expired) }
        lookup(ticket)
    }
    private func lookup(_ ticket: NativeCursorTicket) {
        guard state({ $0.live(ticket, now: now()) }) else {
            if state({ $0.isCurrent(ticket) }) { hide(ticket, reason: .expired) }; return
        }
        // One outstanding OS query at most. A newer ticket waits for that query
        // to finish, while its independent expiry still runs on the UI queue.
        guard lookupInFlight == nil else { return }
        let nonce = UUID(), deadline = min(ticket.expiresAt, now() + Self.lookupSeconds)
        lookupInFlight = nonce
        trace(.lookupStart, ticket, lookup: nonce)
        pendingLookup = nonce; lookupTicket = ticket
        lookupWork = schedule(max(0, deadline - now())) { [weak self] in
            guard let self = self, self.pendingLookup == nonce else { return }
            self.trace(.timeout, ticket, lookup: nonce, reason: .lookupTimeout)
            self.pendingLookup = nil; self.hide(ticket, reason: .lookupTimeout)
        }
        read(ticket.presentation.target, surface?.windowID, { [weak self] phase in
            self?.trace(phase, ticket, lookup: nonce)
        }) { [weak self] snapshot in
            self?.enqueue { [weak self] in self?.complete(ticket, nonce: nonce, deadline: deadline, snapshot: snapshot) }
        }
    }
    private func complete(_ ticket: NativeCursorTicket, nonce: UUID, deadline: Double, snapshot: NativeCursorSnapshot) {
        trace(.completionStart, ticket, lookup: nonce)
        guard lookupInFlight == nonce else { return }
        lookupInFlight = nil
        let expected = pendingLookup == nonce
        if expected { lookupWork?.cancel(); pendingLookup = nil }
        guard expected, state({ $0.live(ticket, now: now()) }), now() < deadline else {
            trace(.superseded, ticket, lookup: nonce)
            if expected, state({ $0.isCurrent(ticket) }) { hide(ticket, reason: .lookupTimeout) }
            if let latest = state({ $0.ticket }), latest != ticket, state({ $0.live(latest, now: now()) }) { lookup(latest) }
            return
        }
        let plan: NativeCursorPlan
        do { plan = try NativeCursorEligibility.plan(ticket.presentation, snapshot) }
        catch {
            let reason = error as? NativeCursorRefusal ?? .stackUnknown
            trace(.refusal, ticket, lookup: nonce, reason: reason)
            hide(ticket, reason: reason); return
        }
        guard state({ $0.live(ticket, now: now()) }) else { hide(ticket, reason: .expired); return }
        if surface == nil { surface = factory() }
        guard state({ $0.live(ticket, now: now()) }) else { hide(ticket, reason: .expired); return }
        shownExpiryWork?.cancel(); shownExpiryWork = nil
        trace(.showRequest, ticket, lookup: nonce)
        shown = ticket; surface?.show(plan)
        trace(.showReturn, ticket, lookup: nonce)
        guard state({ $0.live(ticket, now: now()) }) else {
            if shown == ticket {
                trace(.hideRequest, ticket, reason: .expired)
                surface?.hide(); shown = nil
                trace(.hideReturn, ticket, reason: .expired)
            }
            hide(ticket, reason: .expired); return
        }
        refreshTicket = ticket
        refreshWork = schedule(min(Self.refreshSeconds, max(0, ticket.expiresAt - now()))) { [weak self] in self?.lookup(ticket) }
    }
}

enum NativeCursorSystemSnapshot {
    static func screenTop() -> Double? {
        guard let screen = NSScreen.screens.first(where: {
            ($0.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber)?.uint32Value == CGMainDisplayID()
        }), screen.frame.maxY.isFinite else { return nil }
        return Double(screen.frame.maxY)
    }
    static func read(_ target: NativeCursorTarget, overlay: UInt32?, top: Double?,
                     bindingCheck: ((NativeCursorTarget) -> Bool?)?,
                     trace: (NativeCursorTracePhase) -> Void = { _ in }) -> NativeCursorSnapshot {
        func refused(_ reason: NativeCursorRefusal) -> NativeCursorSnapshot {
            NativeCursorSnapshot(app: nil, bindingMatches: nil, target: nil, stack: [], screenTop: top, failure: reason)
        }
        guard let check = bindingCheck else { return refused(.bindingUnknown) }
        trace(.bindingStart)
        let firstBinding = check(target)
        trace(.bindingEnd)
        guard let binding = firstBinding else { return refused(.bindingUnknown) }
        guard binding else { return refused(.bindingChanged) }
        // The production binding check freshly validates the host-issued audit
        // generation and dynamic code; a nullable AppKit lookup is not liveness.
        let app = target.app
        trace(.stackReadStart)
        let exactValue = CGWindowListCopyWindowInfo(.optionIncludingWindow, target.cgWindowID)
        trace(.stackReadEnd)
        guard let exact = exactValue as? [[String: Any]] else {
            return refused(.windowListUnavailable)
        }
        let exactRows = exact.filter {
            integer($0[kCGWindowNumber as String], minimum: 1, maximum: Int64(UInt32.max)) == Int64(target.cgWindowID)
        }
        guard exactRows.count == 1, let current = exactRows.first else {
            return refused(.targetMissing)
        }
        trace(.stackReadStart)
        let rowsValue = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID)
        trace(.stackReadEnd)
        guard let rows = rowsValue as? [[String: Any]] else {
            return refused(.windowListUnavailable)
        }
        guard rows.count <= NativeCursorEligibility.maximumStackWindows else { return refused(.stackLimit) }
        trace(.bindingStart)
        let secondBinding = check(target)
        trace(.bindingEnd)
        guard secondBinding == true else { return refused(.bindingChanged) }
        // This caps processing, not the WindowServer API's allocation/time.
        return NativeCursorSnapshot(app: app, bindingMatches: true, target: metadata(current), stack: rows.map(metadata),
            screenTop: top, ownOverlayID: overlay, ownOverlayPID: ProcessInfo.processInfo.processIdentifier)
    }
    private static func integer(_ raw: Any?, minimum: Int64 = Int64(Int32.min), maximum: Int64 = Int64(Int32.max)) -> Int64? {
        guard let n = raw as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(), n.doubleValue.isFinite,
              n.doubleValue.rounded() == n.doubleValue,
              n.doubleValue >= Double(minimum), n.doubleValue <= Double(maximum) else { return nil }
        return n.int64Value
    }
    private static func metadata(_ raw: [String: Any]) -> NativeCursorWindowMetadata {
        let id = integer(raw[kCGWindowNumber as String], minimum: 1, maximum: Int64(UInt32.max)).flatMap(UInt32.init(exactly:))
        let pid = integer(raw[kCGWindowOwnerPID as String]).flatMap { $0 >= 0 ? Int32(exactly: $0) : nil }
        let level = integer(raw[kCGWindowLayer as String]).map(Int.init)
        let alpha: Double? = (raw[kCGWindowAlpha as String] as? NSNumber).flatMap {
            CFGetTypeID($0) != CFBooleanGetTypeID() && $0.doubleValue.isFinite ? $0.doubleValue : nil
        }
        let onScreen: Bool? = (raw[kCGWindowIsOnscreen as String] as? NSNumber).flatMap {
            CFGetTypeID($0) == CFBooleanGetTypeID() ? $0.boolValue : nil
        }
        let bounds = (raw[kCGWindowBounds as String] as? NSDictionary).flatMap { CGRect(dictionaryRepresentation: $0) }.map {
            NativeRect(x: $0.minX, y: $0.minY, width: $0.width, height: $0.height)
        }
        return NativeCursorWindowMetadata(id: id, ownerPID: pid, bounds: bounds, level: level, alpha: alpha, onScreen: onScreen)
    }
}

private final class NativeCursorPanel: NSPanel {
    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }
}

private final class NativeCursorPanelSurface: NativeCursorSurface {
    private let panel: NativeCursorPanel
    private let clip: NSView
    private let glyph: CursorView
    var windowID: UInt32? { panel.windowNumber > 0 ? UInt32(exactly: panel.windowNumber) : nil }
    init() {
        panel = NativeCursorPanel(contentRect: NSRect(x: 0, y: 0, width: 28, height: 28),
            styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.isOpaque = false; panel.backgroundColor = .clear; panel.hasShadow = false
        panel.ignoresMouseEvents = true; panel.isFloatingPanel = false; panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.transient, .ignoresCycle]
        clip = NSView(frame: .zero); clip.wantsLayer = true; clip.layer?.masksToBounds = true
        clip.setAccessibilityElement(false)
        glyph = CursorView(frame: NSRect(x: 0, y: 0, width: 28, height: 28)); glyph.setAccessibilityElement(false)
        clip.addSubview(glyph); panel.contentView = clip
    }
    func show(_ plan: NativeCursorPlan) {
        let frame = plan.panelAppKit, inner = plan.glyphInPanel
        panel.level = NSWindow.Level(rawValue: plan.windowLevel)
        panel.setFrame(NSRect(x: frame.x, y: frame.y, width: frame.width, height: frame.height), display: true)
        clip.frame = NSRect(x: 0, y: 0, width: frame.width, height: frame.height)
        glyph.frame = NSRect(x: inner.x, y: inner.y, width: inner.width, height: inner.height)
        panel.order(.above, relativeTo: Int(plan.relativeWindowID))
    }
    func hide() { panel.orderOut(nil) }
    private final class CursorView: NSView {
        override func draw(_ dirtyRect: NSRect) {
            let path=NSBezierPath();path.move(to:NSPoint(x:4,y:24));path.line(to:NSPoint(x:4,y:5))
            path.line(to:NSPoint(x:10,y:10));path.line(to:NSPoint(x:15,y:2));path.line(to:NSPoint(x:19,y:5))
            path.line(to:NSPoint(x:14,y:13));path.line(to:NSPoint(x:22,y:14));path.close()
            NSColor.systemBlue.setFill();path.fill();NSColor.white.setStroke();path.lineWidth=1.5;path.stroke()
        }
    }
}
