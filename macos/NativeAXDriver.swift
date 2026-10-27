import AppKit
import ApplicationServices
import ScreenCaptureKit
import CryptoKit
import Security
import Darwin
import MachO

// Capture callbacks publish only into their own mailbox. A timed-out operation
// closes it, so late callbacks cannot touch the next operation's driver state.
private final class NativeCaptureMailbox<Value> {
    private let lock = NSLock()
    private let ready = DispatchSemaphore(value: 0)
    private var completed = false, closed = false
    private var value: Value?
    private let deadline: DispatchTime
    init(deadline: DispatchTime) { self.deadline = deadline }
    func publish(_ value: Value?) {
        lock.lock()
        guard !closed, !completed, DispatchTime.now() < deadline else { lock.unlock(); return }
        self.value = value; completed = true
        lock.unlock(); ready.signal()
    }
    func wait(until deadline: DispatchTime) -> Value? {
        let received = ready.wait(timeout: deadline) == .success
        lock.lock(); defer { lock.unlock() }
        closed = true
        defer { value = nil }
        return received && completed && DispatchTime.now() < self.deadline ? value : nil
    }
}

// The private ABI is qualified only for the current, inspected platform/image.
// Resolution does not contact AX. Keep this owner and its framework handle alive
// throughout each call; other OS builds retain the honest geometry fallback.
private final class NativeExactWindowGetter {
    typealias Getter = @convention(c) (AXUIElement, UnsafeMutablePointer<UInt32>) -> Int32
    static let shared = NativeExactWindowGetter()
    private let library: UnsafeMutableRawPointer?
    private let getter: Getter?
    let availability: NativeWindowGetterAvailability
    private static func build() -> String? {
        var count = 0
        guard sysctlbyname("kern.osversion", nil, &count, nil, 0) == 0, count > 0, count <= 128 else { return nil }
        var bytes = [CChar](repeating: 0, count: count)
        guard sysctlbyname("kern.osversion", &bytes, &count, nil, 0) == 0 else { return nil }
        return String(cString: bytes)
    }
    private static func imageQualified() -> Bool {
        let path = "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/Frameworks/HIServices.framework/Versions/A/HIServices"
        for index in 0..<_dyld_image_count() {
            guard let name = _dyld_get_image_name(index), String(cString: name) == path,
                  let header = _dyld_get_image_header(index), header.pointee.magic == MH_MAGIC_64 else { continue }
            let base = UnsafeRawPointer(header), size = MemoryLayout<mach_header_64>.size
            let image = base.load(as: mach_header_64.self)
            guard image.ncmds <= 1000, image.sizeofcmds <= 16_777_216 else { return false }
            var offset = size
            let end = size + Int(image.sizeofcmds)
            for _ in 0..<image.ncmds {
                guard offset + MemoryLayout<load_command>.size <= end else { return false }
                let command = base.advanced(by: offset).load(as: load_command.self)
                guard command.cmdsize >= MemoryLayout<load_command>.size,
                      Int(command.cmdsize) <= end - offset else { return false }
                if command.cmd == LC_UUID {
                    guard command.cmdsize >= MemoryLayout<uuid_command>.size else { return false }
                    let uuid = base.advanced(by: offset).load(as: uuid_command.self).uuid
                    return UUID(uuid: uuid).uuidString.lowercased() == "185a502d-7e89-344d-9718-11ffb39205ff"
                }
                offset += Int(command.cmdsize)
            }
        }
        return false
    }
    private init() {
        #if arch(arm64)
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let platform = version.majorVersion == 27 && version.minorVersion == 0 && version.patchVersion == 1
            && Self.build() == "26A434"
        #else
        let platform = false
        #endif
        guard platform else { library = nil; getter = nil; availability = .unsupportedPlatform; return }
        library = dlopen("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices", RTLD_NOW | RTLD_LOCAL)
        guard let library = library, let symbol = dlsym(library, "_AXUIElementGetWindow") else {
            getter = nil; availability = .getterUnavailable; return
        }
        guard Self.imageQualified() else { getter = nil; availability = .unsupportedPlatform; return }
        getter = unsafeBitCast(symbol, to: Getter.self); availability = .available
    }
    deinit { if let library = library { dlclose(library) } }
    func read(_ element: AXUIElement) -> (status: Int32, id: UInt32) {
        guard let getter = getter else { return (AXError.notImplemented.rawValue, 0) }
        var number: UInt32 = 0
        let status = getter(element, &number)
        return (status, status == AXError.success.rawValue ? number : 0)
    }
}

final class NativeInputMonitor {
    private let lock = NSLock()
    private var epoch: UInt64 = 0
    private var tap: CFMachPort?
    private var source: CFRunLoopSource?
    private let ownPID = ProcessInfo.processInfo.processIdentifier
    var ownMarkers: Set<Int64> = []
    var available: Bool {
        guard let tap = tap, let source = source else { return false }
        return CGPreflightListenEventAccess() && CFMachPortIsValid(tap)
            && CGEvent.tapIsEnabled(tap: tap) && CFRunLoopSourceIsValid(source)
            && CFRunLoopContainsSource(CFRunLoopGetMain(), source, .commonModes)
    }
    var currentEpoch: UInt64 { lock.lock(); defer { lock.unlock() }; return epoch }
    init() {
        guard CGPreflightListenEventAccess() else { return }
        let types: [CGEventType] = [.keyDown, .keyUp, .flagsChanged,
            .leftMouseDown, .rightMouseDown, .otherMouseDown, .leftMouseUp, .rightMouseUp, .otherMouseUp,
            .leftMouseDragged, .rightMouseDragged, .otherMouseDragged, .scrollWheel, .mouseMoved]
        let mask = types.reduce(CGEventMask(0)) { $0 | (CGEventMask(1) << $1.rawValue) }
        let callback: CGEventTapCallBack = { _, type, event, info in
            guard let info = info else { return Unmanaged.passUnretained(event) }
            let monitor = Unmanaged<NativeInputMonitor>.fromOpaque(info).takeUnretainedValue()
            if type == .tapDisabledByTimeout || type == .tapDisabledByUserInput {
                monitor.lock.lock(); monitor.epoch &+= 1; monitor.lock.unlock()
                if let tap = monitor.tap { CGEvent.tapEnable(tap: tap, enable: true) }
            } else {
                let pid = event.getIntegerValueField(.eventSourceUnixProcessID)
                let marker = event.getIntegerValueField(.eventSourceUserData)
                monitor.lock.lock()
                if pid != Int64(monitor.ownPID) || !monitor.ownMarkers.contains(marker) { monitor.epoch &+= 1 }
                monitor.lock.unlock()
            }
            return Unmanaged.passUnretained(event)
        }
        tap = CGEvent.tapCreate(tap: .cgSessionEventTap, place: .headInsertEventTap, options: .listenOnly,
                               eventsOfInterest: mask, callback: callback, userInfo: Unmanaged.passUnretained(self).toOpaque())
        if let tap = tap {
            source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0)
            if let source = source { CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes) }
            CGEvent.tapEnable(tap: tap, enable: true)
        }
    }
    func addMarker(_ value: Int64) { lock.lock(); ownMarkers.insert(value); lock.unlock() }
    deinit {
        if let source = source { CFRunLoopRemoveSource(CFRunLoopGetMain(), source, .commonModes) }
        if let tap = tap { CFMachPortInvalidate(tap) }
    }
}

final class NativeAXDriver: NativeOperationDriver {
    let monitor: NativeInputMonitor
    let processDiagnostics = NativeProcessDiagnostics()
    private let processIdentities: NativeProcessIdentityStore
    private var processDiscoveryBatches: [UUID: UUID] = [:]
    private let cursorDiagnostics = NativeCursorDiagnostics()
    private var cursorRuntime: String?
    private let cursorLock = NSLock()
    private let mappingLock = NSLock()
    private var ambiguousWindowMappings = Set<String>()
    private var mappingRevision: UInt64 = 0
    private var attachedSheetParents: [String: String] = [:]
    private func mappingVersion(_ windowID: String) -> UInt64? {
        mappingLock.lock(); defer { mappingLock.unlock() }
        return ambiguousWindowMappings.contains(windowID) ? nil : mappingRevision
    }
    private typealias CursorContext = (target: NativeCursorTarget, generation: NativeCursorGeneration, marker: Int64, requestedPoint: NativePoint)
    private var cursorContexts: [String: CursorContext] = [:]
    private var agentCursors: [String: NativeAgentCursor] = [:]
    private var activeCursorOperations = Set<String>()
    private var cursorOperationID: String?
    var pointerTraceObserver: (([String: Any]) -> Void)?
    // Configured by the centre with its existing serial lane. The callback must
    // only enqueue; retained state is installed immediately around each step.
    var holdSchedule: ((UInt64, @escaping () -> Void) -> Void)?
    private func retainedHoldSchedule() -> ((UInt64, @escaping () -> Void) -> Void)? {
        guard let schedule = holdSchedule else { return nil }
        let check = cancellationCheck, send = guardedInputSend, observer = pointerTraceObserver
        cursorLock.lock(); let operation = cursorOperationID; cursorLock.unlock()
        return { delay, step in
            schedule(delay) {
                let previousCheck = self.cancellationCheck, previousSend = self.guardedInputSend
                let previousObserver = self.pointerTraceObserver
                self.cursorLock.lock(); let previousOperation = self.cursorOperationID
                self.cursorOperationID = operation; self.cursorLock.unlock()
                self.cancellationCheck = check; self.guardedInputSend = send; self.pointerTraceObserver = observer
                defer {
                    self.cancellationCheck = previousCheck; self.guardedInputSend = previousSend
                    self.pointerTraceObserver = previousObserver
                    self.cursorLock.lock()
                    self.cursorOperationID = previousOperation.flatMap { self.activeCursorOperations.contains($0) ? $0 : nil }
                    self.cursorLock.unlock()
                }
                step()
            }
        }
    }

    func retainingPointerFailure(_ action: () throws -> [String: Any]) throws -> [String: Any] {
        let previous = pointerTraceObserver
        var summary: NativePointerFailureSummary?
        var geometry: NativeGeometryFailure?
        var activation = NativeActivationContext()
        var malformedSummary = false
        pointerTraceObserver = { row in
            previous?(row)
            activation.record(row)
            if summary == nil {
                if geometry == nil { geometry = NativeGeometryFailure(row) }
                summary = NativePointerFailureSummary(row)
                if row["kind"] as? String == "failure", summary == nil { malformedSummary = true }
            }
        }
        defer { pointerTraceObserver = previous }
        func enriched(_ result: [String: Any]) -> [String: Any] {
            var result = result
            if let context = activation.value { result["activation_context"] = context }
            return result
        }
        func failureReply(_ failure: NativeFailure) -> [String: Any] {
            var result: [String: Any] = ["ok": false,
                "error": ["code": failure.code, "effect_state": failure.effectState]]
            if let summary = summary { result["failure_summary"] = summary.value }
            if !malformedSummary, let geometry = geometry,
               geometry.errorCode == (summary?.value["reason"] as? String ?? failure.code) {
                result["geometry_failure"] = geometry.value
            }
            return enriched(result)
        }
        do { return enriched(try action()) }
        catch let deferred as NativeDeferred<[String: Any]> {
            throw deferred.mapResult { result in
                do { return enriched(try result.get()) }
                catch let failure as NativeFailure { return failureReply(failure) }
            }
        }
        catch let failure as NativeFailure {
            return failureReply(failure)
        }
    }
    private lazy var targetedPointer = NativeTargetedPointer(trace: { [weak self] row in
        self?.pointerTraceObserver?(row)
    }, presentation: { [weak self] sent in self?.presentCursor(sent) },
       holdPresentation: { [weak self] holding in self?.presentHeldCursor(holding) })
    private let windowBindings = NativeBindingCache<NativeAppIdentity, AXUIElement>(
        limit: 100, failure: "native_window_identity_capacity", same: { CFEqual($0, $1) })
    private let controlBindings = NativeBindingCache<String, AXUIElement>(
        limit: 5000, failure: "native_control_identity_capacity", same: { CFEqual($0, $1) })
    init(monitor: NativeInputMonitor) {
        self.monitor = monitor
        processIdentities = NativeProcessIdentityStore(provider: NativeSystemProcessIdentity(metadata: { pid in
            guard let running = NSRunningApplication(processIdentifier: pid), !running.isTerminated else { return nil }
            return try? NativeAXDriver.identity(running)
        }))
    }
    private func makeAgentCursor() -> NativeAgentCursor {
        return NativeAgentCursor(bindingCheck: { [weak self] target in self?.cursorBindingMatches(target) },
            diagnostic: { [weak self] signal in
                self?.cursorDiagnostics.append(operationID: signal.generation.operationID, generation: signal.generation.nonce,
                    ticketSerial: signal.ticketSerial, lookup: signal.lookup, phase: signal.phase,
                    requestedPoint: signal.requestedPoint, reason: signal.reason)
            })
    }
    var accessibilityAllowed: Bool { AXIsProcessTrusted() }
    var clipboardChangeCount: Int? { NSPasteboard.general.changeCount }
    var screenAllowed: Bool { CGPreflightScreenCaptureAccess() }
    var inputMonitorAvailable: Bool { monitor.available }
    var inputEpoch: UInt64 { monitor.currentEpoch }
    var frontmostPID: Int32? { NSWorkspace.shared.frontmostApplication?.processIdentifier }
    var cancellationCheck: (() throws -> Void)?
    var guardedInputSend: (((() throws -> Void)) throws -> Void)?
    private var treeFieldReadFailures: Set<String>?
    private var lastAttributeResult: AXError = .success
    private var lastAttributeValueReadAttempted = false
    private var textEditDocumentPrivacyControls = Set<String>()
    private var windowChromeControls: [String: (windowID: String, attribute: String)] = [:]
    // Observed references select a bounded proof route, never current authority.
    // Upward references may be virtual aliases outside the downward AX tree.
    private var controlPaths: [String: (nodes: [AXUIElement], parents: [AXUIElement])] = [:]
    private var textControlRoutes: [String: (nodes: [AXUIElement], parents: [AXUIElement], token: String)] = [:]
    private var controlScopedHops: [String: Int] = [:]
    private var windowRouteRevisions: [String: String] = [:]
    private(set) var windowInventoryDiagnostic: [String: Any]?
    // Backend eligibility with OS approval; ordinary effects/cursor/client
    // qualification and same-process coexistence remain separate gates.
    var backgroundPointInputAvailable: Bool { targetedPointer.available }
    // The drag primitive has owned receiver/Stop qualification. Availability
    // still requires its native backend and OS approval; exact target/freshness
    // guards remain at dispatch. Broader window/cursor/client parity is separate.
    var backgroundDragInputAvailable: Bool { targetedPointer.available }

    func beginCursorOperation(_ operationID: String, owner: NativeCursorTraceOwner? = nil) {
        if let owner = owner, owner.operationID == operationID {
            if cursorRuntime != owner.runtimeGeneration {
                cursorDiagnostics.reset(runtimeGeneration: owner.runtimeGeneration); cursorRuntime = owner.runtimeGeneration
            }
            cursorDiagnostics.register(owner)
        }
        cursorLock.lock()
        // Finished cursors retire at the next admission; held owners retain
        // independent surfaces/generations until their own Stop or terminal.
        let retired = cursorContexts.filter { !activeCursorOperations.contains($0.key) }
        for (id, context) in retired {
            agentCursors[id]?.invalidate(context.generation)
            cursorContexts.removeValue(forKey: id); agentCursors.removeValue(forKey: id)
        }
        activeCursorOperations.insert(operationID)
        cursorOperationID = operationID
        cursorLock.unlock()
    }
    func resetCursorDiagnostics() {
        cursorRuntime = nil; cursorDiagnostics.reset(runtimeGeneration: "")
    }
    func cursorDiagnosticSnapshot(_ owner: NativeCursorTraceOwner) -> NativeCursorTraceSnapshot? {
        cursorDiagnostics.snapshot(owner)
    }
    func finishCursorOperation(_ operationID: String) {
        cursorLock.lock()
        activeCursorOperations.remove(operationID)
        if cursorOperationID == operationID { cursorOperationID = nil }
        let context = cursorContexts[operationID]
        cursorLock.unlock()
        // Keep the existing final-send lifetime, then dispose the exact owner's
        // surface/timers. Undurable operations retain resource pins separately.
        DispatchQueue.main.asyncAfter(deadline: .now() + NativeCursorLifecycle.lifetime) { [weak self] in
            guard let self = self, let context = context else { return }
            self.cursorLock.lock()
            guard !self.activeCursorOperations.contains(operationID),
                  self.cursorContexts[operationID]?.generation == context.generation else { self.cursorLock.unlock(); return }
            self.cursorContexts.removeValue(forKey: operationID)
            let cursor = self.agentCursors.removeValue(forKey: operationID)
            self.cursorLock.unlock()
            cursor?.invalidate(context.generation)
        }
    }
    func invalidateCursor(operationID: String? = nil, bundleID: String? = nil, windowID: String? = nil) {
        cursorLock.lock()
        let contexts = cursorContexts.filter { id, context in
            (operationID == nil || id == operationID)
                && (bundleID == nil || context.target.app.bundleID == bundleID)
                && (windowID == nil || context.target.windowBindingID == windowID)
        }
        for (id, context) in contexts {
            agentCursors[id]?.invalidate(context.generation)
            cursorContexts.removeValue(forKey: id); agentCursors.removeValue(forKey: id)
        }
        cursorLock.unlock()
    }
    private func cursorBindingMatches(_ target: NativeCursorTarget) -> Bool? {
        guard let revision = mappingVersion(target.windowBindingID) else { return nil }
        guard let binding = windowBindings.entry(target.windowBindingID) else { return nil }
        guard binding.owner == target.app, (try? processIdentities.verify(target.app)) != nil, accessibilityAllowed else { return false }
        var pid: pid_t = 0
        guard AXUIElementGetPid(binding.element, &pid) == .success, pid == target.app.pid else { return false }
        // Use an independent AX reference: cursor metadata must not change the
        // input driver's messaging timeout or tree-read diagnostics.
        let element = AXUIElementCreateApplication(target.app.pid)
        let deadline = ProcessInfo.processInfo.systemUptime + 0.06
        guard AXUIElementSetMessagingTimeout(element, 0.02) == .success else { return nil }
        var raw: CFTypeRef?
        let status = AXUIElementCopyAttributeValue(element, kAXWindowsAttribute as CFString, &raw)
        let decoded = NativeWindowInventory.decode(raw, error: status, timeoutError: .success)
        guard var windows = decoded.elements else { return nil }
        if windows.isEmpty {
            guard let anchors = try? NativeWindowInventory.anchors(application: element, pid: target.app.pid,
                deadline: deadline, maximumSeconds: 0.02, check: {
                    guard (try? self.processIdentities.verify(target.app)) != nil, self.accessibilityAllowed else {
                        throw NativeFailure("native_cursor_identity_unavailable")
                    }
                }) else { return nil }
            windows = anchors.elements
            guard windows.contains(where: { CFEqual($0, binding.element) }) else { return nil }
        }
        guard let current = windows.first(where: { CFEqual($0, binding.element) }) else { return false }
        let geometry = inputGeometry(current, deadline: deadline, attributeLimit: 0.02)
        guard let bounds = geometry.bounds else { return nil }
        let number = cgID(target.app, bounds: bounds)
        guard mappingVersion(target.windowBindingID) == revision else { return nil }
        return bounds == target.bounds && number == target.cgWindowID
    }
    private func prepareCursor(_ app: NativeAppIdentity, windowID: String, number: UInt32, bounds: NativeRect, marker: Int64, point: NativePoint) {
        cursorLock.lock(); let operationID = cursorOperationID; cursorLock.unlock()
        guard let operationID = operationID else { return }
        let cursor = makeAgentCursor()
        let generation = cursor.begin(operationID: operationID)
        cursorDiagnostics.bind(operationID: operationID, generation: generation.nonce)
        let target = NativeCursorTarget(app: app, windowBindingID: windowID, cgWindowID: number, bounds: bounds)
        cursorLock.lock()
        if let prior = cursorContexts[operationID] { agentCursors[operationID]?.invalidate(prior.generation) }
        cursorContexts[operationID] = (target, generation, marker, point)
        agentCursors[operationID] = cursor; cursorLock.unlock()
    }
    private func presentCursor(_ sent: NativeTargetedPointerPresentation) {
        cursorLock.lock(); let context = cursorContexts.values.first { $0.marker == sent.marker }
        let cursor = context.flatMap { agentCursors[$0.generation.operationID] }; cursorLock.unlock()
        guard let context = context, context.marker == sent.marker, context.target.app == sent.app,
              context.target.cgWindowID == sent.windowNumber, context.target.bounds == sent.bounds else { return }
        cursor?.sent(target: context.target, point: sent.point, generation: context.generation,
            requestedPoint: sent.point == context.requestedPoint)
    }

    private func presentHeldCursor(_ holding: NativeTargetedPointerHoldPresentation) {
        cursorLock.lock(); let context = cursorContexts.values.first { $0.marker == holding.marker }
        let cursor = context.flatMap { agentCursors[$0.generation.operationID] }; cursorLock.unlock()
        guard let context = context, context.marker == holding.marker,
              context.target.app == holding.app, context.target.cgWindowID == holding.windowNumber,
              context.target.bounds == holding.bounds else { return }
        // This is a validated visual refresh during an existing hold, not an
        // extra event dispatch. Stop invalidates the same operation generation.
        cursor?.sent(target: context.target, point: holding.point, generation: context.generation,
            requestedPoint: holding.point == context.requestedPoint)
    }

    static func identity(_ application: NSRunningApplication) throws -> NativeAppIdentity {
        var diagnostic: NativeIdentityDiagnostic?
        return try identity(application, diagnostic: &diagnostic)
    }
    func identify(_ application: NSRunningApplication) throws -> NativeAppIdentity {
        let before = try processIdentities.initialSnapshot(application.processIdentifier)
        guard !application.isTerminated else { throw NativeProcessIdentityFailure("running_application_terminated") }
        var diagnostic: NativeIdentityDiagnostic?
        let observed = try Self.identity(application, before: before, diagnostic: &diagnostic)
        return try processIdentities.issue(observed, before: before)
    }
    private static func identity(_ application: NSRunningApplication,
                                 before: NativeProcessSnapshot? = nil,
                                 diagnostic: inout NativeIdentityDiagnostic?) throws -> NativeAppIdentity {
        var missing: [String] = []
        let observedBundle = application.bundleIdentifier, observedPath = application.bundleURL?.path
        let observedExecutable = application.executableURL?.path, observedLaunch = application.launchDate
        if observedBundle == nil { missing.append("bundle_id") }
        if observedPath == nil { missing.append("bundle_path") }
        if observedExecutable == nil { missing.append("executable") }
        if observedLaunch == nil && before == nil { missing.append("launched_at") }
        guard let bundle = observedBundle, let path = observedPath,
              let executable = observedExecutable, observedLaunch != nil || before != nil else {
            diagnostic = NativeIdentityDiagnostic(stage: "required_metadata_unavailable", fields: missing)
            throw NativeFailure("native_app_identity_unavailable")
        }
        var signingIdentifier: String?, teamID: String?, requirementText: String?
        var code: SecStaticCode?, info: CFDictionary?, requirement: SecRequirement?, text: CFString?
        let createStatus = SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code)
        if createStatus == errSecSuccess, let code = code {
            let infoStatus = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
            if infoStatus == errSecSuccess, let values = info as? [String: Any] {
                signingIdentifier = values[kSecCodeInfoIdentifier as String] as? String
                teamID = values[kSecCodeInfoTeamIdentifier as String] as? String
                let requirementStatus = SecCodeCopyDesignatedRequirement(code, [], &requirement)
                if requirementStatus == errSecSuccess, let requirement = requirement {
                    let textStatus = SecRequirementCopyString(requirement, [], &text)
                    if textStatus == errSecSuccess { requirementText = text as String? }
                    if textStatus != errSecSuccess || requirementText == nil {
                        diagnostic = NativeIdentityDiagnostic(stage: "requirement_text_unavailable", status: textStatus)
                    }
                } else {
                    diagnostic = NativeIdentityDiagnostic(stage: "designated_requirement_unavailable", status: requirementStatus)
                }
            } else {
                diagnostic = NativeIdentityDiagnostic(stage: "signing_information_unavailable", status: infoStatus)
            }
        } else {
            diagnostic = NativeIdentityDiagnostic(stage: "static_code_unavailable", status: createStatus)
        }
        // A signed running alias can use the exact kernel birth metadata. The
        // subsequent issue() still requires the complete dual-path signature
        // proof before this observation gains authority. Unsigned stays strict.
        let timestampExecutable = signingIdentifier != nil && requirementText != nil ? before?.executable ?? executable : executable
        let launchedAt = try NativeProcessLaunchTimestamp.resolve(observed: observedLaunch?.timeIntervalSince1970,
            pid: application.processIdentifier, executable: timestampExecutable, before: before)
        return NativeAppIdentity(bundleID: bundle, bundlePath: path, executable: executable,
            pid: application.processIdentifier, launchedAt: launchedAt,
            signingIdentifier: signingIdentifier, teamID: teamID, designatedRequirement: requirementText)
    }
    private(set) var identityFailureDiagnostic: NativeIdentityDiagnostic?
    func matches(_ app: NativeAppIdentity) -> Bool {
        identityFailureDiagnostic = nil
        do { try processIdentities.verify(app); return true }
        catch {
            var failed = (error as? NativeProcessIdentityFailure)?.diagnostic
                ?? NativeIdentityDiagnostic(stage: "process_identity_unavailable")
            failed.checkedAt = Date().timeIntervalSince1970
            failed.processProbeJSON = processDiagnostics.firstFailure(app)
            identityFailureDiagnostic = failed
            return false
        }
    }
    private func sameProcess(_ app: NativeAppIdentity) -> Bool {
        (try? processIdentities.verify(app, full: false)) != nil
    }
    private func attribute(_ element: AXUIElement, _ name: String, deadline: Double? = nil) -> CFTypeRef? {
        lastAttributeValueReadAttempted = false
        let remaining = deadline.map { $0 - ProcessInfo.processInfo.systemUptime } ?? 0.1
        guard let timeout = NativeWindowIdentity.messagingTimeout(remaining: remaining) else {
            lastAttributeResult = .cannotComplete; treeFieldReadFailures?.insert("time_limit"); return nil
        }
        let timeoutResult = AXUIElementSetMessagingTimeout(element, timeout)
        guard timeoutResult == .success else {
            lastAttributeResult = timeoutResult; treeFieldReadFailures?.insert("timeout_setup_failed"); return nil
        }
        guard deadline.map({ NativeWindowIdentity.messagingTimeout(remaining: $0 - ProcessInfo.processInfo.systemUptime) != nil }) ?? true else {
            lastAttributeResult = .cannotComplete; treeFieldReadFailures?.insert("time_limit"); return nil
        }
        var value: CFTypeRef?
        lastAttributeValueReadAttempted = true
        let result = AXUIElementCopyAttributeValue(element, name as CFString, &value)
        lastAttributeResult = result
        guard result == .success else {
            if result != .attributeUnsupported && result != .noValue { treeFieldReadFailures?.insert("attribute_read_failed") }
            return nil
        }
        return value
    }
    private func geometry(_ element: AXUIElement, deadline: Double? = nil) -> NativeRect? {
        guard let position = attribute(element, kAXPositionAttribute, deadline: deadline),
              let size = attribute(element, kAXSizeAttribute, deadline: deadline) else { return nil }
        guard CFGetTypeID(position) == AXValueGetTypeID(), CFGetTypeID(size) == AXValueGetTypeID(),
              AXValueGetType(position as! AXValue) == .cgPoint, AXValueGetType(size as! AXValue) == .cgSize else {
            treeFieldReadFailures?.insert("geometry_type_failed"); return nil
        }
        var point = CGPoint.zero, dimensions = CGSize.zero
        guard AXValueGetValue(position as! AXValue, .cgPoint, &point), AXValueGetValue(size as! AXValue, .cgSize, &dimensions) else {
            treeFieldReadFailures?.insert("geometry_conversion_failed"); return nil
        }
        return NativeRect(x: point.x, y: point.y, width: dimensions.width, height: dimensions.height)
    }
    private func inputGeometry(_ element: AXUIElement, deadline: Double,
                               attributeLimit: Double) -> NativeGeometryRead {
        func read(_ name: String, type: AXValueType) -> NativeGeometryAttributeRead {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard let timeout = NativeWindowIdentity.messagingTimeout(remaining: min(attributeLimit, remaining)) else {
                return NativeGeometryAttributeRead(error: nil, state: .notRead)
            }
            let configured = AXUIElementSetMessagingTimeout(element, timeout)
            guard configured == .success else {
                return NativeGeometryAttributeRead.decode(nil, result: .success, expected: type, timeoutResult: configured)
            }
            guard NativeWindowIdentity.messagingTimeout(remaining: deadline - ProcessInfo.processInfo.systemUptime) != nil else {
                return NativeGeometryAttributeRead(error: nil, state: .notRead)
            }
            var raw: CFTypeRef?
            let result = AXUIElementCopyAttributeValue(element, name as CFString, &raw)
            return NativeGeometryAttributeRead.decode(raw, result: result, expected: type, timeoutResult: configured)
        }
        let position = read(kAXPositionAttribute, type: .cgPoint)
        let size = read(kAXSizeAttribute, type: .cgSize)
        return NativeGeometryRead(position: position, size: size)
    }
    private func requireGeometryReadBudget(_ deadline: Double?) throws {
        if let deadline = deadline,
           NativeWindowIdentity.messagingTimeout(remaining: deadline - ProcessInfo.processInfo.systemUptime) == nil {
            throw NativeFailure("native_window_geometry_unavailable", "unknown")
        }
    }
    private func check(_ app: NativeAppIdentity, _ element: AXUIElement, deadline: Double? = nil) throws {
        var pid: pid_t = 0
        try requireGeometryReadBudget(deadline)
        guard accessibilityAllowed else { throw NativeFailure("accessibility_required") }
        // Full code identity is checked once at each public operation boundary.
        // Each traversed node still checks process launch identity and AX PID.
        try requireGeometryReadBudget(deadline)
        guard sameProcess(app) else { throw NativeFailure("native_process_identity_changed") }
        try requireGeometryReadBudget(deadline)
        guard AXUIElementGetPid(element, &pid) == .success else { throw NativeFailure("native_element_identity_unavailable") }
        guard pid == app.pid else { throw NativeFailure("native_element_process_mismatch") }
    }
    private func focused(_ app: NativeAppIdentity, window: AXUIElement, deadline: Double? = nil) -> Bool {
        let application = AXUIElementCreateApplication(app.pid)
        guard let selected = attribute(application, kAXFocusedWindowAttribute, deadline: deadline) else { return false }
        guard CFGetTypeID(selected) == AXUIElementGetTypeID() else {
            treeFieldReadFailures?.insert("focused_window_type_failed"); return false
        }
        return CFEqual(selected, window)
    }
    func retainBindings(windows: Set<String>, controls: Set<String>) {
        // An active sheet depends on the original opaque parent reference,
        // including while its own observation/control caches are retired.
        windowBindings.retain(NativeAttachedSheetPolicy.retainedWindows(windows, parents: attachedSheetParents))
        controlBindings.retain(controls)
        attachedSheetParents = attachedSheetParents.filter {
            windowBindings.entry($0.key) != nil && windowBindings.entry($0.value) != nil
        }
        // Unpinning does not retire a cached binding or its privacy provenance.
        textEditDocumentPrivacyControls = Set(textEditDocumentPrivacyControls.filter { controlBindings.entry($0) != nil })
        windowChromeControls = windowChromeControls.filter { controlBindings.entry($0.key)?.owner == $0.value.windowID }
        controlPaths = controlPaths.filter { controlBindings.entry($0.key) != nil }
        textControlRoutes = textControlRoutes.filter { controlBindings.entry($0.key) != nil }
        controlScopedHops = controlScopedHops.filter { controlPaths[$0.key] != nil }
        windowRouteRevisions = windowRouteRevisions.filter { windowBindings.entry($0.key) != nil }
    }
    func retainProcessIdentities(_ apps: [NativeAppIdentity]) { processIdentities.retain(apps) }
    func beginWindowDiscovery() -> UUID? {
        let batch = windowBindings.beginBatch()
        processDiscoveryBatches[batch] = processIdentities.beginBatch()
        return batch
    }
    func endWindowDiscovery(_ batch: UUID) {
        windowBindings.endBatch(batch)
        if let processes = processDiscoveryBatches.removeValue(forKey: batch) { processIdentities.endBatch(processes) }
    }
    private func windowID(_ element: AXUIElement, app: NativeAppIdentity) throws -> String {
        try windowBindings.identifier(element, owner: app)
    }
    private func controlID(_ element: AXUIElement, windowID: String) throws -> String {
        try controlBindings.identifier(element, owner: windowID)
    }
    private func cgID(_ app: NativeAppIdentity, bounds: NativeRect) -> UInt32? {
        // A claimed AX window can belong to another desktop. Match its exact
        // owner and geometry across all windows; visibility remains a separate
        // requirement for the legacy global-pointer route.
        guard let rows = CGWindowListCopyWindowInfo(.optionAll, kCGNullWindowID) as? [[String: Any]] else { return nil }
        return NativeGeometryCGMapping.fromRows(rows, ownerPID: app.pid, bounds: bounds).windowID
    }
    private func mappedCGID(_ app: NativeAppIdentity, windowID: String, bounds: NativeRect,
                            deadline: Double? = nil) -> UInt32? {
        guard let revision = mappingVersion(windowID) else { return nil }
        let number = try? windowCGMapping(app, windowID: windowID, bounds: bounds,
            deadline: deadline ?? ProcessInfo.processInfo.systemUptime + NativeWindowIdentity.maximumSeconds).windowID
        return mappingVersion(windowID) == revision ? number : nil
    }
    private func windowCGMapping(_ app: NativeAppIdentity, windowID: String, bounds: NativeRect,
                                 deadline: Double, originalWindowID: UInt32? = nil) throws -> NativeWindowIdentityResult {
        let getter = NativeExactWindowGetter.shared
        guard let revision = mappingVersion(windowID) else {
            return NativeWindowIdentityResult(mapping: NativeGeometryCGMapping(state: .ambiguous, windowID: nil),
                diagnostic: NativeWindowIdentityDiagnostic(state: .aliasBlocked, getterAvailability: getter.availability))
        }
        guard let binding = windowBindings.entry(windowID), binding.owner == app else { throw NativeFailure("unknown_native_window") }
        let element = binding.element
        let parent = try attachedSheetParent(app, windowID: windowID, deadline: deadline)
        let result = try NativeWindowIdentity.resolve(ownerPID: app.pid, bounds: bounds, availability: getter.availability,
            deadline: deadline, originalWindowID: originalWindowID, now: { ProcessInfo.processInfo.systemUptime }, check: {
                guard self.mappingVersion(windowID) == revision, let current = self.windowBindings.entry(windowID),
                      current.owner == app, CFEqual(current.element, element) else { throw NativeFailure("native_window_identity_changed") }
                try self.check(app, element, deadline: deadline)
            }, configure: { AXUIElementSetMessagingTimeout(element, $0).rawValue }, getter: { getter.read(element) },
            inventory: { CGWindowListCopyWindowInfo(.optionAll, kCGNullWindowID) as? [[String: Any]] })
        if let parent = parent {
            let parentSnapshot = try windowIdentitySnapshot(app, windowID: parent, outerDeadline: deadline)
            guard NativeAttachedSheetPolicy.independentIdentity(parentID: parentSnapshot.identity.windowID,
                parent: parentSnapshot.identity.diagnostic, sheetID: result.windowID, sheet: result.diagnostic),
                try attachedSheetParent(app, windowID: windowID, deadline: deadline) == parent else {
                throw NativeFailure("native_attached_sheet_identity_unverified")
            }
        }
        return result
    }
    // This relation is checked on every mapping path, including final pointer
    // revalidation. A cached association only selects references to re-read.
    private func attachedSheetParent(_ app: NativeAppIdentity, windowID: String, deadline: Double) throws -> String? {
        guard let sheet = windowBindings.entry(windowID), sheet.owner == app else { throw NativeFailure("unknown_native_window") }
        guard let parentID = attachedSheetParents[windowID] else {
            guard securityText(sheet.element, kAXRoleAttribute, deadline: deadline) != .text(kAXSheetRole) else {
                throw NativeFailure("native_attached_sheet_relation_unverified")
            }
            return nil
        }
        guard parentID != windowID, let parent = windowBindings.entry(parentID), parent.owner == app,
              attachedSheetParents[parentID] == nil else { throw NativeFailure("native_attached_sheet_relation_unverified") }
        try check(app, parent.element, deadline: deadline); try check(app, sheet.element, deadline: deadline)
        let metadata = securityMetadata(sheet.element, deadline: deadline)
        let parentMetadata = securityMetadata(parent.element, deadline: deadline)
        guard metadata.role == .text(kAXSheetRole), !metadata.protected,
              parentMetadata.role == .text(kAXWindowRole), !parentMetadata.protected,
              let rawParent = attribute(sheet.element, kAXParentAttribute, deadline: deadline),
              CFGetTypeID(rawParent) == AXUIElementGetTypeID(), CFEqual(rawParent, parent.element),
              let rawChildren = attribute(parent.element, kAXChildrenAttribute, deadline: deadline),
              let children = rawChildren as? [AXUIElement], children.count <= 1000,
              children.filter({ CFEqual($0, sheet.element) }).count == 1,
              ProcessInfo.processInfo.systemUptime < deadline else {
            throw NativeFailure("native_attached_sheet_relation_unverified")
        }
        try check(app, parent.element, deadline: deadline); try check(app, sheet.element, deadline: deadline)
        return parentID
    }

    private func discoverAttachedSheets(_ app: NativeAppIdentity, elements: [AXUIElement],
                                        deadline: Double) throws -> (elements: [AXUIElement], complete: Bool) {
        var sheets: [AXUIElement] = [], complete = elements.count <= 30
        for parent in elements.prefix(30) {
            guard ProcessInfo.processInfo.systemUptime < deadline else { complete = false; break }
            try cancellationCheck?(); try check(app, parent, deadline: deadline)
            let metadata = securityMetadata(parent, deadline: deadline)
            guard case .text(let parentRole) = metadata.role, !parentRole.isEmpty else { complete = false; continue }
            guard parentRole == kAXWindowRole else { continue }
            guard !metadata.protected,
                  let raw = attribute(parent, kAXChildrenAttribute, deadline: deadline),
                  let children = raw as? [AXUIElement], children.count <= 1000 else { complete = false; continue }
            let parentID = try windowID(parent, app: app)
            for child in children {
                guard ProcessInfo.processInfo.systemUptime < deadline else { complete = false; break }
                try cancellationCheck?()
                var pid: pid_t = 0
                // Foreign helpers are excluded before even their role is read.
                guard AXUIElementGetPid(child, &pid) == .success, pid > 0 else { complete = false; continue }
                guard pid == app.pid else { continue }
                // Most direct children are ordinary content; do not spend a
                // full security tuple on them during supplemental discovery.
                guard case .text(let childRole) = securityText(child, kAXRoleAttribute, deadline: deadline),
                      !childRole.isEmpty else { complete = false; continue }
                guard childRole == kAXSheetRole else { continue }
                let childMetadata = securityMetadata(child, deadline: deadline)
                guard childMetadata.role == .text(kAXSheetRole), !childMetadata.protected else { complete = false; continue }
                if !elements.contains(where: { CFEqual($0, child) }),
                   elements.count + sheets.filter({ sheet in !elements.contains(where: { CFEqual($0, sheet) }) }).count >= 30 {
                    complete = false; continue
                }
                let id = try windowID(child, app: app)
                guard attachedSheetParents[id] == nil || attachedSheetParents[id] == parentID else {
                    throw NativeFailure("native_attached_sheet_relation_unverified")
                }
                attachedSheetParents[id] = parentID
                guard (try? attachedSheetParent(app, windowID: id, deadline: deadline)) == parentID else { complete = false; continue }
                sheets = NativeWindowInventory.appendUnique(sheets, child, same: CFEqual)
            }
        }
        return (sheets, complete && ProcessInfo.processInfo.systemUptime < deadline)
    }
    private func windowIdentitySnapshot(_ app: NativeAppIdentity, windowID: String,
                                        outerDeadline: Double? = nil,
                                        geometryUnavailable: (([String: Any]) -> Void)? = nil) throws -> (bounds: NativeRect, identity: NativeWindowIdentityResult) {
        // Essential geometry/identity reads have an admission budget separate
        // from the full tree. Synchronous AX calls are not a hard wall deadline.
        let started = ProcessInfo.processInfo.systemUptime
        let deadline = min(started + 0.5, outerDeadline ?? started + 0.5)
        guard started.isFinite, deadline.isFinite, started < deadline else {
            throw NativeWindowIdentityDiagnostic(state: .budgetExhausted,
                getterAvailability: NativeExactWindowGetter.shared.availability).failure
        }
        guard let binding = windowBindings.entry(windowID), binding.owner == app else { throw NativeFailure("unknown_native_window") }
        let revision = mappingVersion(windowID)
        try check(app, binding.element)
        let geometry = inputGeometry(binding.element, deadline: deadline, attributeLimit: 0.1)
        if [geometry.position.error, geometry.size.error, geometry.position.timeoutError, geometry.size.timeoutError]
            .contains(AXError.apiDisabled.rawValue) { throw NativeFailure("accessibility_required") }
        guard let bounds = geometry.bounds else {
            geometryUnavailable?(geometry.diagnostic)
            throw NativeFailure("native_window_geometry_unavailable")
        }
        let identity = try windowCGMapping(app, windowID: windowID, bounds: bounds, deadline: deadline)
        guard mappingVersion(windowID) == revision,
              let current = windowBindings.entry(windowID), current.owner == app,
              CFEqual(current.element, binding.element) else { throw NativeFailure("native_window_identity_changed") }
        try check(app, binding.element)
        guard ProcessInfo.processInfo.systemUptime < deadline else {
            throw NativeWindowIdentityDiagnostic(state: .budgetExhausted,
                getterAvailability: NativeExactWindowGetter.shared.availability).failure
        }
        return (bounds, identity)
    }
    func windows(_ app: NativeAppIdentity) throws -> [NativeWindow] {
        windowInventoryDiagnostic = nil
        // One per-app budget includes ordinary inventory, anchors, known
        // references and materialization. Synchronous AX is not a hard timeout.
        let inventoryDeadline = ProcessInfo.processInfo.systemUptime + 3.0
        let application = AXUIElementCreateApplication(app.pid)
        var elements: [AXUIElement] = try NativeWindowInventory.read(cannotComplete: AXError.cannotComplete.rawValue,
            now: { ProcessInfo.processInfo.systemUptime }, check: {
                guard self.accessibilityAllowed else { throw NativeFailure("accessibility_required") }
                guard self.matches(app) else { throw NativeFailure("native_process_identity_changed") }
                try self.cancellationCheck?()
            }, read: { limit in
                let seconds = Float(limit)
                guard seconds.isFinite, seconds > 0, seconds <= 0.2 else {
                    return NativeWindowInventoryRead(elements: nil, error: AXError.cannotComplete.rawValue,
                        timeoutError: AXError.cannotComplete.rawValue, state: "deadline", cfType: nil)
                }
                let timeout = AXUIElementSetMessagingTimeout(application, seconds)
                var raw: CFTypeRef?
                let result = timeout == .success
                    ? AXUIElementCopyAttributeValue(application, kAXWindowsAttribute as CFString, &raw) : timeout
                return NativeWindowInventory.decode(raw, error: result, timeoutError: timeout)
            }, trace: { self.windowInventoryDiagnostic = $0 })
        if elements.isEmpty {
            let anchors = try NativeWindowInventory.anchors(application: application, pid: app.pid,
                deadline: min(inventoryDeadline, ProcessInfo.processInfo.systemUptime + 0.3), maximumSeconds: 0.1, check: {
                    guard self.accessibilityAllowed, self.matches(app) else { throw NativeFailure("native_process_identity_changed") }
                    try self.cancellationCheck?()
                })
            elements = anchors.elements
            windowInventoryDiagnostic?["supplementary_references"] = anchors.diagnostics
            windowInventoryDiagnostic?["enumeration_scope"] = "main_and_focused_window_references"
            windowInventoryDiagnostic?["scope_complete"] = false
        } else {
            windowInventoryDiagnostic?["enumeration_scope"] = "accessibility_windows"
            windowInventoryDiagnostic?["scope_complete"] = true
        }
        var enumerationComplete = windowInventoryDiagnostic?["scope_complete"] as? Bool == true
        windowInventoryDiagnostic?["enumeration_complete"] = enumerationComplete
        windowInventoryDiagnostic?["scope_complete"] = false
        windowInventoryDiagnostic?["materialization_state"] = "in_progress"
        var unavailable: [[String: Any]] = []
        var attempted = 0, budgetExhausted = false, attachedSheetsComplete = false
        let observed = try windowBindings.withBatch {
            let known = windowBindings.candidates(owner: app, limit: 30)
            var knownOnly: Set<String> = [], knownDiagnostics: [[String: Any]] = []
            for candidate in known.entries {
                if elements.contains(where: { CFEqual($0, candidate.entry.element) }) { continue }
                elements.append(candidate.entry.element); knownOnly.insert(candidate.id)
            }
            windowInventoryDiagnostic?["known_reference_candidates_truncated"] = known.truncated
            windowInventoryDiagnostic?["cached_window_metadata_used"] = false
            if !knownOnly.isEmpty {
                enumerationComplete = false
                windowInventoryDiagnostic?["enumeration_scope"] = "accessibility_and_freshly_revalidated_known_references"
                windowInventoryDiagnostic?["enumeration_complete"] = false
            }
            var rows: [NativeWindow] = []
            let materialized = try NativeWindowInventory.materializeThenSupplement(elements: elements, deadline: inventoryDeadline,
                now: { ProcessInfo.processInfo.systemUptime }, same: CFEqual, materialize: { element, index in
                guard accessibilityAllowed else { throw NativeFailure("accessibility_required") }
                guard matches(app) else { throw NativeFailure("native_process_identity_changed") }
                try cancellationCheck?()
                guard ProcessInfo.processInfo.systemUptime < inventoryDeadline else { budgetExhausted = true; return false }
                attempted += 1
                let id: String
                if let seed = known.entries.first(where: { knownOnly.contains($0.id) && CFEqual($0.entry.element, element) }) {
                    // Never re-register an invalidated remembered reference as
                    // a new ordinary candidate, losing its validation policy.
                    guard let current = windowBindings.entry(seed.id), current.owner == app,
                          CFEqual(current.element, element) else {
                        unavailable.append(["index": index, "window_id": seed.id,
                            "reason": "known_reference_invalidated", "incomplete": true]); return false
                    }
                    id = seed.id
                    let validation: (valid: Bool, diagnostic: [String: Any]) = attachedSheetParents[id] == nil
                        ? validateKnownReference(element, pid: app.pid,
                            seconds: Float(min(0.1, inventoryDeadline - ProcessInfo.processInfo.systemUptime)))
                        : ((try? attachedSheetParent(app, windowID: id, deadline: inventoryDeadline)) != nil,
                            ["state": "attached_sheet_reference_revalidated"])
                    guard accessibilityAllowed else { throw NativeFailure("accessibility_required") }
                    guard matches(app) else { throw NativeFailure("native_process_identity_changed") }
                    try cancellationCheck?()
                    var diagnostic = validation.diagnostic; diagnostic["window_id"] = id
                    knownDiagnostics.append(diagnostic)
                    guard validation.valid else { return false }
                    guard let current = windowBindings.entry(id), current.owner == app,
                          CFEqual(current.element, element) else {
                        unavailable.append(["index": index, "window_id": id,
                            "reason": "known_reference_invalidated", "incomplete": true]); return false
                    }
                } else { id = try windowID(element, app: app) }
                try check(app, element)
                var geometryFailure: [String: Any]?
                let snapshot: (bounds: NativeRect, identity: NativeWindowIdentityResult)
                do {
                    snapshot = try windowIdentitySnapshot(app, windowID: id, outerDeadline: inventoryDeadline,
                        geometryUnavailable: { geometryFailure = $0 })
                } catch let failure as NativeFailure where
                    ["native_attached_sheet_identity_unverified", "native_attached_sheet_relation_unverified"].contains(failure.code) {
                    unavailable.append(["index": index, "window_id": id, "reason": failure.code,
                        "phase": "attached_sheet_identity", "incomplete": true])
                    return false
                } catch let failure as NativeFailure where
                    failure.code == "native_window_identity_budget_exhausted" ||
                    failure.code == "native_window_geometry_unavailable" && geometryFailure != nil {
                    // Only recorded geometry absence or explicit budget expiry
                    // may fail locally; never swallow an identity change.
                    // Identity, access, cancellation and mapping failures remain fatal.
                    guard accessibilityAllowed else { throw NativeFailure("accessibility_required") }
                    guard matches(app) else { throw NativeFailure("native_process_identity_changed") }
                    try cancellationCheck?()
                    try check(app, element)
                    unavailable.append(["index": index, "window_id": id, "reason": failure.code,
                        "phase": "identity_snapshot", "incomplete": true,
                        "geometry_read": geometryFailure as Any? ?? NSNull()])
                    if ProcessInfo.processInfo.systemUptime >= inventoryDeadline { budgetExhausted = true }
                    return false
                }
                // A remembered AX reference cannot supply an observation from
                // old geometry or an unverified CG association.
                if knownOnly.contains(id), snapshot.identity.windowID == nil {
                    unavailable.append(["index": index, "window_id": id,
                        "reason": "known_window_identity_unverified", "incomplete": true,
                        "identity_diagnostic": nativeDictionary(snapshot.identity.diagnostic)])
                    return false
                }
                guard accessibilityAllowed else { throw NativeFailure("accessibility_required") }
                guard matches(app) else { throw NativeFailure("native_process_identity_changed") }
                try cancellationCheck?()
                let minimizedDeadline = min(inventoryDeadline, ProcessInfo.processInfo.systemUptime + 0.2)
                rows.append(NativeWindow(id: id, title: String((attribute(element, kAXTitleAttribute, deadline: minimizedDeadline) as? String ?? "").prefix(300)),
                    bounds: snapshot.bounds, focused: focused(app, window: element, deadline: minimizedDeadline),
                    controls: [], nodesVisited: 0, incomplete: snapshot.identity.windowID == nil, cgWindowID: snapshot.identity.windowID,
                    minimized: minimizedValue(element, deadline: minimizedDeadline),
                    minimizedSettable: geometrySettable(element, attribute: kAXMinimizedAttribute, deadline: minimizedDeadline),
                    identityDiagnostic: snapshot.identity.diagnostic,
                    fullscreen: fullscreenValue(element, deadline: minimizedDeadline), attachedSheetParentID: attachedSheetParents[id]))
                if ProcessInfo.processInfo.systemUptime >= inventoryDeadline { budgetExhausted = true }
                return true
            }, supplement: { candidates, deadline in
                try self.discoverAttachedSheets(app, elements: candidates, deadline: deadline)
            })
            elements = materialized.elements
            attachedSheetsComplete = materialized.supplementComplete
            budgetExhausted = budgetExhausted || materialized.budgetExhausted
            windowInventoryDiagnostic?["known_reference_candidates"] = knownDiagnostics
            guard accessibilityAllowed else { throw NativeFailure("accessibility_required") }
            guard matches(app) else { throw NativeFailure("native_process_identity_changed") }
            try cancellationCheck?()
            return rows
        }
        windowInventoryDiagnostic?["enumerated_count"] = elements.count
        windowInventoryDiagnostic?["attempted_count"] = attempted
        windowInventoryDiagnostic?["returned_count"] = observed.count
        windowInventoryDiagnostic?["omitted_count"] = max(0, elements.count - attempted)
        windowInventoryDiagnostic?["materialization_limit"] = 30
        windowInventoryDiagnostic?["maximum_discovery_seconds"] = 3.0
        windowInventoryDiagnostic?["materialization_budget_exhausted"] = budgetExhausted
        windowInventoryDiagnostic?["unavailable_windows"] = unavailable
        windowInventoryDiagnostic?["controls_observed"] = false
        windowInventoryDiagnostic?["attached_sheet_discovery_complete"] = attachedSheetsComplete
        windowInventoryDiagnostic?["attached_sheet_maximum_seconds"] = 0.3
        mappingLock.lock()
        // Partial main/focused rediscovery cannot prove a prior alias closed.
        // Keep a known ambiguity for each retained opaque AX binding.
        let retainedBlocks = Set(ambiguousWindowMappings.filter { windowBindings.entry($0) != nil })
        let mapped = NativeWindowInventory.suppressAmbiguousMappings(observed, previouslyBlocked: retainedBlocks)
        if ambiguousWindowMappings != mapped.blocked { mappingRevision &+= 1 }
        ambiguousWindowMappings = mapped.blocked
        mappingLock.unlock()
        windowInventoryDiagnostic?["ambiguous_mapping_count"] = observed.filter { mapped.blocked.contains($0.id) }.count
        windowInventoryDiagnostic?["materialization_state"] = "read"
        windowInventoryDiagnostic?["scope_complete"] = enumerationComplete && attachedSheetsComplete && !budgetExhausted && unavailable.isEmpty && elements.count <= 30
            && !observed.contains(where: { $0.incomplete }) && !observed.contains(where: { mapped.blocked.contains($0.id) })
        return mapped.windows.map { window in
            var result = window
            if mapped.blocked.contains(result.id) {
                result.identityDiagnostic?.state = .aliasBlocked; result.incomplete = true
            }
            return result
        }
    }
    private func validateKnownReference(_ element: AXUIElement, pid: Int32, seconds: Float) -> (valid: Bool, diagnostic: [String: Any]) {
        NativeWindowInventory.validateReference(element, pid: pid, seconds: seconds)
    }
    private func securityText(_ element: AXUIElement, _ name: String,
                              deadline: Double?) -> NativeAttributePolicy.SecurityTextRead {
        let raw = attribute(element, name, deadline: deadline)
        guard lastAttributeValueReadAttempted else { return .notRead(lastAttributeResult.rawValue) }
        switch lastAttributeResult {
        case .success:
            guard let value = raw as? String else {
                treeFieldReadFailures?.insert("attribute_type_failed"); return .malformed
            }
            return .text(value)
        case .attributeUnsupported: return .unsupported
        case .noValue: return .noValue
        default: return .failed(lastAttributeResult.rawValue)
        }
    }
    private func securityMetadata(_ element: AXUIElement,
                                  deadline: Double?) -> NativeAttributePolicy.SecurityTextMetadata {
        let role = securityText(element, kAXRoleAttribute, deadline: deadline)
        let subrole = securityText(element, kAXSubroleAttribute, deadline: deadline)
        let title = securityText(element, kAXTitleAttribute, deadline: deadline)
        // Display-title precedence is not a privacy boundary: an ordinary title
        // can accompany a password description on custom controls/ancestors.
        let description = securityText(element, kAXDescriptionAttribute, deadline: deadline)
        return NativeAttributePolicy.SecurityTextMetadata(role: role, subrole: subrole, title: title,
            description: description)
    }
    private func trustedSystemTextEdit(_ app: NativeAppIdentity) -> Bool {
        // Qualify the running guest, not an app name or a static on-disk bundle.
        // An OS/app update returns to default redaction until requalified.
        let version = ProcessInfo.processInfo.operatingSystemVersion
        guard version.majorVersion == 27, version.minorVersion == 0, version.patchVersion == 1,
              app.bundleID == "com.apple.TextEdit", app.signingIdentifier == "com.apple.TextEdit",
              app.bundlePath == "/System/Applications/TextEdit.app",
              app.executable == "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit",
              app.processGeneration != nil, sameProcess(app) else { return false }
        var count = 0
        guard sysctlbyname("kern.osversion", nil, &count, nil, 0) == 0, count > 0, count <= 128 else { return false }
        var build = [CChar](repeating: 0, count: count)
        guard sysctlbyname("kern.osversion", &build, &count, nil, 0) == 0,
              String(cString: build) == "26A434",
              let before = try? processIdentities.initialSnapshot(app.pid), before.executable == app.executable else { return false }
        var requirement: SecRequirement?, code: SecCode?
        let source = "anchor apple and identifier \"com.apple.TextEdit\" and cdhash H\"07f33932b9952fa33fb86a8231f5436dbeb20e1c\""
        guard SecRequirementCreateWithString(source as CFString, [], &requirement) == errSecSuccess,
              let requirement = requirement,
              SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit as String: before.audit] as CFDictionary, [], &code) == errSecSuccess,
              let code = code, SecCodeCheckValidity(code, [], requirement) == errSecSuccess,
              sameProcess(app), let after = try? processIdentities.initialSnapshot(app.pid), after == before else { return false }
        return true
    }
    private func textEditDocumentAncestors(_ element: AXUIElement, app: NativeAppIdentity,
                                          window: AXUIElement, deadline: Double?) throws -> Bool {
        // Only the demonstrated document topology is supported. Each ancestor
        // must remain in the exact owner process and have readable, nonsecure
        // metadata. Direct control rediscovery repeats these reads as well.
        guard let rawWindow = attribute(element, kAXWindowAttribute, deadline: deadline),
              lastAttributeResult == .success, CFGetTypeID(rawWindow) == AXUIElementGetTypeID(),
              CFEqual(rawWindow, window) else { return false }
        var child = element, ancestry = [element]
        for expectedRole in [kAXScrollAreaRole, kAXWindowRole] {
            guard let rawParent = attribute(child, kAXParentAttribute, deadline: deadline),
                  lastAttributeResult == .success, CFGetTypeID(rawParent) == AXUIElementGetTypeID() else { return false }
            let parent = rawParent as! AXUIElement
            try check(app, parent)
            let metadata = securityMetadata(parent, deadline: deadline)
            guard metadata.role == .text(expectedRole), !metadata.protected,
                  let rawChildren = attribute(parent, kAXChildrenAttribute, deadline: deadline),
                  lastAttributeResult == .success, let children = rawChildren as? [AXUIElement],
                  children.contains(where: { CFEqual($0, child) }) else { return false }
            child = parent; ancestry.append(parent)
        }
        guard CFEqual(child, window) else { return false }
        // Repeat the exact links and security metadata; a control can be moved
        // into a protected container while the first ancestry sample is read.
        for index in 0..<2 {
            let child = ancestry[index], parent = ancestry[index + 1]
            try check(app, child); try check(app, parent)
            guard let rawParent = attribute(child, kAXParentAttribute, deadline: deadline),
                  lastAttributeResult == .success, CFGetTypeID(rawParent) == AXUIElementGetTypeID(),
                  CFEqual(rawParent, parent) else { return false }
            let metadata = securityMetadata(parent, deadline: deadline)
            guard metadata.role == .text(index == 0 ? kAXScrollAreaRole : kAXWindowRole), !metadata.protected,
                  let rawChildren = attribute(parent, kAXChildrenAttribute, deadline: deadline),
                  lastAttributeResult == .success, let children = rawChildren as? [AXUIElement],
                  children.contains(where: { CFEqual($0, child) }) else { return false }
        }
        guard let rawWindowAgain = attribute(element, kAXWindowAttribute, deadline: deadline),
              lastAttributeResult == .success, CFGetTypeID(rawWindowAgain) == AXUIElementGetTypeID(),
              CFEqual(rawWindowAgain, window) else { return false }
        try check(app, element)
        return true
    }
    private func fileURLMetadata(_ element: AXUIElement, secure: Bool,
                                 deadline: Double?) -> NativeFileURLMetadata {
        guard !secure else { return NativeFileURLMetadata(state: "suppressed") }
        let raw = attribute(element, kAXURLAttribute, deadline: deadline)
        let result = lastAttributeResult
        guard lastAttributeValueReadAttempted else {
            return NativeFileURLMetadata(state: "not_read", axError: result.rawValue)
        }
        if result == .attributeUnsupported { return NativeFileURLMetadata(state: "unsupported") }
        if result == .noValue { return NativeFileURLMetadata(state: "no_value") }
        guard result == .success else { return NativeFileURLMetadata(state: "read_failed", axError: result.rawValue) }
        guard let raw = raw, CFGetTypeID(raw) == CFURLGetTypeID() else {
            return NativeFileURLMetadata(state: "wrong_type")
        }
        let url = raw as! CFURL
        guard CFURLGetBaseURL(url) == nil else { return NativeFileURLMetadata(state: "relative") }
        guard let text = CFURLGetString(url) else { return NativeFileURLMetadata(state: "wrong_type") }
        // Bound the original CF string before allocating a Swift copy. No
        // URL resolution/resource lookup/standardization or unsafe echo occurs.
        guard CFStringGetLength(text) <= NativeFileURLMetadata.maximumBytes else {
            return NativeFileURLMetadata(state: "oversize")
        }
        let original = text as String
        guard original.utf8.count <= NativeFileURLMetadata.maximumBytes else {
            return NativeFileURLMetadata(state: "oversize")
        }
        guard let parsed = URLComponents(string: original) else { return NativeFileURLMetadata(state: "unsafe") }
        guard let scheme = parsed.scheme else { return NativeFileURLMetadata(state: "relative") }
        guard scheme.lowercased() == "file" else { return NativeFileURLMetadata(state: "non_file") }
        guard parsed.percentEncodedPath.hasPrefix("/") else { return NativeFileURLMetadata(state: "relative") }
        // Foundation accessors may hide encoded controls. Decode the original
        // URI once for validation, including the host, without changing its echo.
        guard let decodedOriginal = original.removingPercentEncoding,
              parsed.user == nil, parsed.password == nil, parsed.query == nil, parsed.fragment == nil,
              !original.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }),
              !decodedOriginal.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else {
            return NativeFileURLMetadata(state: "unsafe")
        }
        return NativeFileURLMetadata(state: "available", original: original)
    }
    private func describe(_ element: AXUIElement, windowID: String, inheritedSecure: Bool = false,
                          deadline: Double? = nil) throws -> NativeControl {
        let id = try controlID(element, windowID: windowID)
        // Cache eviction can precede the engine's next retention update.
        textEditDocumentPrivacyControls = Set(textEditDocumentPrivacyControls.filter { controlBindings.entry($0) != nil })
        let previouslyAdapted = textEditDocumentPrivacyControls.contains(id)
        var metadata = securityMetadata(element, deadline: deadline)
        var codeVerified = false, ancestorsVerified = false
        if !inheritedSecure, metadata.textEditDescriptionFailure || previouslyAdapted,
           let binding = windowBindings.entry(windowID) {
            codeVerified = trustedSystemTextEdit(binding.owner)
            if codeVerified {
                let adapterDeadline = deadline ?? ProcessInfo.processInfo.systemUptime + 0.3
                ancestorsVerified = try textEditDocumentAncestors(element, app: binding.owner,
                    window: binding.element, deadline: adapterDeadline)
                if ancestorsVerified { metadata = securityMetadata(element, deadline: adapterDeadline) }
            }
        }
        let role = metadata.role.value, label = metadata.label
        // Keep this provenance until the opaque control binding is retired.
        // A later readable description must not drop the ancestry requirement
        // for a control that was exposed through this document-only adapter.
        let documentVerified = codeVerified && ancestorsVerified && metadata.role == .text(kAXTextAreaRole)
        var secure = previouslyAdapted && !documentVerified || NativeAttributePolicy.protects(metadata,
            inheritedSecure: inheritedSecure, textEditCodeVerified: codeVerified,
            textEditDocumentAncestorsVerified: ancestorsVerified)
        func configureRead() throws {
            let remaining = deadline.map { $0 - ProcessInfo.processInfo.systemUptime } ?? 0.1
            guard remaining > 0 else { throw NativeFailure("native_tree_read_deadline") }
            guard AXUIElementSetMessagingTimeout(element, Float(min(0.1, remaining))) == .success else {
                throw NativeFailure("native_attribute_timeout_unavailable")
            }
        }
        var rangeSettable = false, selectedTextSettable = false
        if !secure {
            for name in [kAXSelectedTextRangeAttribute, kAXSelectedTextAttribute] {
                try configureRead()
                var writable = DarwinBoolean(false)
                let result = AXUIElementIsAttributeSettable(element, name as CFString, &writable)
                if result == .success {
                    if name == kAXSelectedTextRangeAttribute { rangeSettable = writable.boolValue }
                    else { selectedTextSettable = writable.boolValue }
                } else if result != .attributeUnsupported && result != .noValue { treeFieldReadFailures?.insert("text_range_settable_failed") }
            }
        }
        if !secure, documentVerified { textEditDocumentPrivacyControls.insert(id) }
        var raw = secure ? nil : attribute(element, kAXValueAttribute, deadline: deadline)
        var value: String?, valueType: String?
        if let text = raw as? String { value = String(text.prefix(4096)); valueType = "text" }
        else if let number = raw as? NSNumber { value = number.stringValue; valueType = "number" }
        else if raw != nil { valueType = "unsupported" }
        var actions: CFArray?
        try configureRead()
        let actionResult = AXUIElementCopyActionNames(element, &actions)
        if actionResult != .success && actionResult != .attributeUnsupported {
            treeFieldReadFailures?.insert("actions_read_failed"); actions = nil
        }
        if actionResult == .success && actions as? [String] == nil { treeFieldReadFailures?.insert("actions_type_failed") }
        var settable: DarwinBoolean = false
        try configureRead()
        let settableResult = AXUIElementIsAttributeSettable(element, kAXValueAttribute as CFString, &settable)
        if settableResult != .success {
            settable = false
            if settableResult != .attributeUnsupported && settableResult != .noValue { treeFieldReadFailures?.insert("settable_read_failed") }
        }
        var selectedRange: NativeTextRange?
        // Public text capabilities belong to the exact observed element, not
        // an app/role whitelist. Nontext, protected and truncated values never
        // gain a selection contract from a successful settable query alone.
        if !secure, let text = raw as? String, text.count <= 4096, text.utf8.count <= 32768 {
            if let rawRange = attribute(element, kAXSelectedTextRangeAttribute, deadline: deadline) {
                if CFGetTypeID(rawRange) == AXValueGetTypeID() {
                    let ax = rawRange as! AXValue
                    var range = CFRange()
                    if AXValueGetType(ax) == .cfRange, AXValueGetValue(ax, .cfRange, &range) {
                        let candidate = NativeTextRange(location: range.location, length: range.length)
                        if candidate.valid(in: text) { selectedRange = candidate }
                        else { treeFieldReadFailures?.insert("text_range_invalid") }
                    } else { treeFieldReadFailures?.insert("text_range_type_failed") }
                } else { treeFieldReadFailures?.insert("text_range_type_failed") }
            }
        } else { rangeSettable = false; selectedTextSettable = false }
        let enabledRaw = attribute(element, kAXEnabledAttribute, deadline: deadline)
        let enabledResult = lastAttributeResult
        let enabled = NativeAttributePolicy.enabled(success: enabledResult == .success,
            absent: enabledResult == .attributeUnsupported || enabledResult == .noValue,
            value: (enabledRaw as? NSNumber)?.boolValue)
        if enabledResult == .success && enabledRaw as? NSNumber == nil { treeFieldReadFailures?.insert("enabled_type_failed") }
        let focusedRaw = attribute(element, kAXFocusedAttribute, deadline: deadline)
        if lastAttributeResult == .success && focusedRaw as? NSNumber == nil { treeFieldReadFailures?.insert("focused_type_failed") }
        var fileURL = fileURLMetadata(element, secure: secure, deadline: deadline)
        let bounds = geometry(element, deadline: deadline)
        if !secure, valueType == "text" {
            // AX getters can reenter the recipient. Run privacy last, after
            // focused/fileURL/geometry reads too. No remote getter follows it.
            let after = securityMetadata(element, deadline: deadline)
            if after.role != metadata.role || after.subrole != metadata.subrole
                || NativeAttributePolicy.protects(after, inheritedSecure: inheritedSecure,
                    textEditCodeVerified: codeVerified, textEditDocumentAncestorsVerified: ancestorsVerified) {
                secure = true; raw = nil; value = nil; valueType = nil; selectedRange = nil
                rangeSettable = false; selectedTextSettable = false; fileURL = NativeFileURLMetadata(state: "suppressed")
                treeFieldReadFailures?.insert("text_privacy_changed")
            }
        }
        return NativeControl(id: id, role: role, label: secure ? "[protected]" : String(label.prefix(300)),
            value: value, valueType: valueType, secure: secure, valueTruncated: ((raw as? String)?.count ?? 0) > 4096,
            enabled: enabled,
            focused: (focusedRaw as? NSNumber)?.boolValue ?? false,
            bounds: bounds, actions: (actions as? [String]) ?? [], valueSettable: settable.boolValue,
            selectedRange: selectedRange, selectedRangeSettable: rangeSettable, selectedTextSettable: selectedTextSettable, fileURL: fileURL)
    }
    /// Host-only metadata for a reviewed renderer mapping. A document label is
    /// never a process/window proof; both are independently revalidated here.
    func electronWindowMetadata(_ app: NativeAppIdentity, windowID: String) throws -> [String: Any] {
        guard let binding = windowBindings.entry(windowID), binding.owner == app, matches(app) else {
            throw NativeFailure("native_process_identity_changed")
        }
        try check(app, binding.element)
        let before = try windowIdentitySnapshot(app, windowID: windowID)
        let deadline = ProcessInfo.processInfo.systemUptime + 0.3
        let title = attribute(binding.element, kAXTitleAttribute, deadline: deadline) as? String ?? ""
        let raw = attribute(binding.element, kAXDocumentAttribute, deadline: deadline)
        let document = (raw as? URL)?.absoluteString ?? (raw as? String)
        let after = try windowIdentitySnapshot(app, windowID: windowID)
        guard let number = before.identity.windowID, number == after.identity.windowID,
              before.bounds == after.bounds, matches(app), ProcessInfo.processInfo.systemUptime < deadline,
              let current = windowBindings.entry(windowID), current.owner == app,
              CFEqual(current.element, binding.element) else { throw NativeFailure("native_window_identity_changed") }
        var value: [String: Any] = ["cg_window_id": number, "native_title": title]
        if let document = document, !document.isEmpty, document.utf8.count <= 4096 { value["document_uri"] = document }
        return value
    }

    /// Geometry-only native half of managed renderer pointer admission. This
    /// does not enter or relax the generic raw same-process input guard.
    func verifyManagedPointerGeometry(_ app: NativeAppIdentity, expected: NativeWindowGeometrySnapshot) throws {
        let current = try windowIdentitySnapshot(app, windowID: expected.windowID)
        try expected.requireMatch(NativeWindowGeometrySnapshot(windowID: expected.windowID,
            bounds: current.bounds, cgWindowID: current.identity.windowID))
        try NativeMinimizedAttribute.requireInputAvailable(try windowMinimizedState(app, windowID: expected.windowID).minimized)
    }

    func prepareManagedPointerCursor(_ app: NativeAppIdentity, expected: NativeWindowGeometrySnapshot,
                                     point: NativePoint, marker: Int64) throws {
        try verifyManagedPointerGeometry(app, expected: expected)
        guard let number = expected.cgWindowID else { throw NativeFailure("native_window_identity_changed") }
        prepareCursor(app, windowID: expected.windowID, number: number, bounds: expected.bounds, marker: marker, point: point)
    }

    func presentManagedPointer(_ app: NativeAppIdentity, expected: NativeWindowGeometrySnapshot,
                               point: NativePoint, marker: Int64) {
        guard let number = expected.cgWindowID else { return }
        // Presentation reports an acknowledged renderer event, not a CGEvent.
        presentCursor(NativeTargetedPointerPresentation(app: app, windowNumber: number,
            bounds: expected.bounds, point: point, marker: marker, eventType: 0))
    }

    private func validateWindowChrome(_ element: AXUIElement, window: AXUIElement,
                                      attribute name: String, owner app: NativeAppIdentity,
                                      deadline: Double?) throws -> Bool {
        do { try check(app, window); try check(app, element) }
        catch let error as NativeFailure where error.code == "native_element_process_mismatch" { return false }
        let rootMetadata = securityMetadata(window, deadline: deadline)
        guard rootMetadata.role == .text(kAXWindowRole), !rootMetadata.protected else { return false }
        guard let current = attribute(window, name, deadline: deadline),
              CFGetTypeID(current) == AXUIElementGetTypeID(), CFEqual(current, element),
              let linked = attribute(element, kAXWindowAttribute, deadline: deadline),
              CFGetTypeID(linked) == AXUIElementGetTypeID(), CFEqual(linked, window) else { return false }
        let metadata = securityMetadata(element, deadline: deadline)
        return metadata.role == .text(kAXButtonRole) && !metadata.protected
    }

    private func windowChromeCandidates(_ window: AXUIElement, owner: NativeAppIdentity,
                                        deadline: Double?) throws -> [(attribute: String, element: AXUIElement)] {
        var result: [(attribute: String, element: AXUIElement)] = []
        let rootMetadata = securityMetadata(window, deadline: deadline)
        guard rootMetadata.role == .text(kAXWindowRole), !rootMetadata.protected else { return result }
        for name in [kAXCloseButtonAttribute, kAXMinimizeButtonAttribute, kAXZoomButtonAttribute, kAXFullScreenButtonAttribute] {
            guard let raw = attribute(window, name, deadline: deadline),
                  CFGetTypeID(raw) == AXUIElementGetTypeID() else { continue }
            let element = raw as! AXUIElement
            guard !result.contains(where: { CFEqual($0.element, element) }),
                  try validateWindowChrome(element, window: window, attribute: name, owner: owner, deadline: deadline) else { continue }
            result.append((name, element))
        }
        return result
    }

    private func modalFirstWindowChildren(_ children: [(offset: Int, element: AXUIElement)],
                                          owner app: NativeAppIdentity,
                                          deadline: Double) throws -> [(offset: Int, element: AXUIElement, modal: Bool)] {
        var sheets: [(offset: Int, element: AXUIElement, modal: Bool)] = []
        var others: [(offset: Int, element: AXUIElement, modal: Bool)] = []
        for child in children {
            // Only the already admitted direct AXChildren are considered. A role
            // hint changes visit order, never edges, identity or control authority.
            guard ProcessInfo.processInfo.systemUptime < deadline else {
                treeFieldReadFailures?.insert("time_limit")
                return children.map { ($0.offset, $0.element, false) }
            }
            do { try check(app, child.element) }
            catch let failure as NativeFailure where failure.code == "native_element_process_mismatch" {
                // The normal traversal records this omitted branch without
                // reading any foreign metadata, values or descendants.
                others.append((child.offset, child.element, false)); continue
            }
            guard ProcessInfo.processInfo.systemUptime < deadline else {
                treeFieldReadFailures?.insert("time_limit")
                return children.map { ($0.offset, $0.element, false) }
            }
            if securityText(child.element, kAXRoleAttribute, deadline: deadline) == .text(kAXSheetRole) {
                sheets.append((child.offset, child.element, true))
            } else { others.append((child.offset, child.element, false)) }
        }
        return sheets + others
    }

    func window(_ app: NativeAppIdentity, id: String) throws -> NativeWindow {
        do { return try readWindow(app, id: id) }
        catch { retireWindowRoutes(id); throw error }
    }
    func observedWindow(_ app: NativeAppIdentity, id: String) throws -> NativeWindow {
        do { return try readWindow(app, id: id, includeKeyboardRecipient: true) }
        catch { retireWindowRoutes(id); throw error }
    }
    private func retireWindowRoutes(_ id: String) {
        windowRouteRevisions.removeValue(forKey: id)
        controlPaths = controlPaths.filter {
            guard let owner = controlBindings.entry($0.key)?.owner else { return false }
            return owner != id && windowBindings.entry(owner) != nil
        }
        controlScopedHops = controlScopedHops.filter { controlPaths[$0.key] != nil }
    }
    func requireRouteRevision(_ app: NativeAppIdentity, windowID: String, revision: String) throws {
        guard matches(app), let binding = windowBindings.entry(windowID), binding.owner == app,
              windowRouteRevisions[windowID] == revision else { throw NativeFailure("native_subtree_source_superseded") }
        try check(app, binding.element)
    }
    func subtreeWindow(_ app: NativeAppIdentity, id: String, rootControlID: String,
                       sourceRevision: String, sourceHops: Int) throws -> NativeWindow {
        do {
            try requireRouteRevision(app, windowID: id, revision: sourceRevision)
            guard (0..<2).contains(sourceHops), controlScopedHops[rootControlID] == sourceHops else {
                throw NativeFailure("native_subtree_hop_limit")
            }
            return try readWindow(app, id: id, rootControlID: rootControlID, scopedHops: sourceHops + 1)
        } catch { retireWindowRoutes(id); throw error }
    }
    func scopedWindowState(_ app: NativeAppIdentity, id: String) throws -> NativeWindow {
        guard let binding = windowBindings.entry(id), binding.owner == app, matches(app) else {
            throw NativeFailure("native_process_identity_changed")
        }
        let deadline = ProcessInfo.processInfo.systemUptime + 0.3
        try check(app, binding.element)
        let before = try windowIdentitySnapshot(app, windowID: id, outerDeadline: deadline)
        let isFocused = focused(app, window: binding.element, deadline: deadline)
        let after = try windowIdentitySnapshot(app, windowID: id, outerDeadline: deadline)
        guard before.bounds == after.bounds, before.identity.windowID == after.identity.windowID,
              ProcessInfo.processInfo.systemUptime < deadline, matches(app) else { throw NativeFailure("native_window_identity_changed") }
        return NativeWindow(id: id, title: "", bounds: before.bounds, focused: isFocused,
            controls: [], nodesVisited: 0, incomplete: true, cgWindowID: before.identity.windowID,
            attachedSheetParentID: attachedSheetParents[id])
    }
    func captureWindowState(_ app: NativeAppIdentity, source: NativeWindow) throws -> NativeWindow {
        let id = source.id
        guard screenAllowed, matches(app), let binding = windowBindings.entry(id), binding.owner == app,
              source.attachedSheetParentID == attachedSheetParents[id] else {
            throw NativeFailure("native_window_identity_changed")
        }
        // Same admission budget as scoped state. Read metadata/identity and
        // retained ancestry only: no value/descendant traversal or route minting.
        let deadline = ProcessInfo.processInfo.systemUptime + 0.3
        func privacy() throws {
            try cancellationCheck?(); try check(app, binding.element, deadline: deadline)
            let metadata = securityMetadata(binding.element, deadline: deadline)
            let role = attachedSheetParents[id] == nil ? kAXWindowRole : kAXSheetRole
            guard metadata.role == .text(role), !metadata.protected else {
                throw NativeFailure("native_capture_privacy_unverified")
            }
            if let scope = source.observationScope {
                guard let revision = source.routeRevision else { throw NativeFailure("native_subtree_anchor_unavailable") }
                try requireRouteRevision(app, windowID: id, revision: revision)
                guard controlScopedHops[scope.root_control_id] == scope.scoped_hops,
                      let anchor = controlBindings.entry(scope.root_control_id), anchor.owner == id,
                      try validateControlAncestry(anchor.element, window: binding.element, owner: app,
                        controlID: scope.root_control_id, deadline: deadline) else {
                    throw NativeFailure("native_subtree_anchor_unavailable")
                }
                try requireRouteRevision(app, windowID: id, revision: revision)
            }
        }
        try privacy()
        let before = try windowIdentitySnapshot(app, windowID: id, outerDeadline: deadline)
        let isFocused = focused(app, window: binding.element, deadline: deadline)
        let minimized = minimizedValue(binding.element, deadline: deadline)
        let after = try windowIdentitySnapshot(app, windowID: id, outerDeadline: deadline)
        try privacy()
        guard before.bounds == after.bounds, before.identity.windowID == after.identity.windowID,
              screenAllowed, matches(app), let current = windowBindings.entry(id), current.owner == app,
              CFEqual(current.element, binding.element), ProcessInfo.processInfo.systemUptime < deadline else {
            throw NativeFailure("native_window_identity_changed")
        }
        guard source.bounds == after.bounds else { throw NativeFailure("native_window_moved") }
        guard source.cgWindowID == after.identity.windowID else { throw NativeFailure("native_window_identity_changed") }
        return NativeWindow(id: id, title: "", bounds: after.bounds, focused: isFocused,
            controls: [], nodesVisited: 0, incomplete: true, cgWindowID: after.identity.windowID,
            minimized: minimized, identityDiagnostic: after.identity.diagnostic, attachedSheetParentID: attachedSheetParents[id])
    }
    private func readWindow(_ app: NativeAppIdentity, id: String, rootControlID: String? = nil,
                            scopedHops: Int = 0, includeKeyboardRecipient: Bool = false) throws -> NativeWindow {
        guard let binding = windowBindings.entry(id), binding.owner == app else { throw NativeFailure("unknown_native_window") }
        let prefix = rootControlID.flatMap { controlPaths[$0] }
        let anchor = rootControlID.flatMap { controlBindings.entry($0) }
        let element = binding.element
        guard matches(app) else { throw NativeFailure("native_process_identity_changed") }
        try check(app, element)
        let initial = try windowIdentitySnapshot(app, windowID: id)
        let bounds = initial.bounds
        let started = Date().timeIntervalSince1970
        let observationDeadline = ProcessInfo.processInfo.systemUptime + 1
        // Reserve final prefix validation inside the same observation budget.
        let deadline = observationDeadline - (rootControlID == nil ? 0 : 0.3)
        if let rootID = rootControlID {
            guard let prefix = prefix, let anchor = anchor, anchor.owner == id,
                  prefix.nodes.count <= 64, !prefix.nodes.isEmpty,
                  try validateControlAncestry(anchor.element, window: element, owner: app, controlID: rootID,
                    deadline: min(deadline, ProcessInfo.processInfo.systemUptime + 0.3)) else {
                throw NativeFailure("native_subtree_anchor_unavailable")
            }
        }
        retireWindowRoutes(id)
        let routeRevision = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let traversalRoot = anchor?.element ?? element
        let localDepth = rootControlID == nil ? 30 : min(30, 64 - (prefix?.nodes.count ?? 0))
        let minimized = minimizedValue(element, deadline: deadline)
        let minimizedSettable = geometrySettable(element, attribute: kAXMinimizedAttribute, deadline: deadline)
        let fullscreen = fullscreenValue(element, deadline: deadline)
        return try controlBindings.withBatch {
        treeFieldReadFailures = []
        defer { treeFieldReadFailures = nil }
        var controls: [NativeControl] = [], nodes: [NativeTreeNode] = []
        var observedPaths: [String: (nodes: [AXUIElement], parents: [AXUIElement])] = [:]
        // FIFO prevents deep early branches from starving shallow siblings.
        // Retain the existing direct-sheet priority across its descendants;
        // both lanes share the original 1000 admitted-node/storage bound.
        var pending: [(AXUIElement, Int, String?, Int, Bool)] = [(traversalRoot, 0, nil, 0, false)]
        var modalPending: [(AXUIElement, Int, String?, Int, Bool)] = []
        var nextPending = 0, nextModal = 0
        var interruptedParent: String?
        var visited = 0, incomplete = false, omissions = Set<String>(), seen = Set<String>()
        var descriptionBytes = 0
        let descriptionBudget = 196608
        windowChromeControls = windowChromeControls.filter { controlBindings.entry($0.key)?.owner == $0.value.windowID }
        // Window buttons can be attribute-only or follow a large content tree.
        // Observe their actual references first, sharing the existing budgets.
        // They remain flat controls: an AXWindow attribute is not an AXChildren edge.
        for candidate in try (rootControlID == nil ? windowChromeCandidates(element, owner: app, deadline: deadline) : []) {
            guard ProcessInfo.processInfo.systemUptime < deadline else {
                incomplete = true; omissions.insert("time_limit"); break
            }
            visited += 1
            var control: NativeControl
            do { control = try describe(candidate.element, windowID: id, deadline: deadline) }
            catch let error as NativeFailure where error.code == "native_tree_read_deadline" {
                incomplete = true; omissions.insert("time_limit"); break
            }
            guard !control.secure else { incomplete = true; omissions.insert("protected_window_control_omitted"); continue }
            control.windowAttribute = candidate.attribute
            let bytes = (try JSONEncoder().encode(control)).count + 128
            guard descriptionBytes + bytes <= descriptionBudget else {
                incomplete = true; omissions.insert("byte_limit"); break
            }
            descriptionBytes += bytes
            controls.append(control)
            windowChromeControls[control.id] = (id, candidate.attribute)
        }
        var flatControlIDs = Set(controls.map { $0.id })
        while nextPending < pending.count || nextModal < modalPending.count {
            if visited >= 1000 { incomplete = true; omissions.insert("node_limit"); break }
            if ProcessInfo.processInfo.systemUptime >= deadline { incomplete = true; omissions.insert("time_limit"); break }
            let prioritized = nextModal < modalPending.count
            let (node, depth, parent, childIndex, modal) = prioritized ? modalPending[nextModal] : pending[nextPending]
            if prioritized { nextModal += 1 } else { nextPending += 1 }
            if depth > localDepth { incomplete = true; omissions.insert("depth_limit"); continue }
            visited += 1
            if rootControlID != nil, depth > 0, prefix?.nodes.dropLast().contains(where: { CFEqual($0, node) }) == true {
                incomplete = true; omissions.insert("ancestor_cycle_omitted"); continue
            }
            do { try check(app, node) }
            catch let failure as NativeFailure where failure.code == "native_element_process_mismatch" && parent != nil {
                // A system-hosted descendant is not authority to inspect or control its process.
                // Keep same-process controls usable, with the skipped branch explicitly incomplete.
                incomplete = true; omissions.insert("foreign_process_subtree_omitted")
                if let index = nodes.firstIndex(where: { $0.id == parent }) {
                    nodes[index].childrenState = "foreign_process_child_omitted"
                }
                continue
            }
            var actions: NativeControl
            do { actions = try describe(node, windowID: id, deadline: deadline) }
            catch let error as NativeFailure where error.code == "native_tree_read_deadline" {
                interruptedParent = parent
                incomplete = true; omissions.insert("time_limit"); break
            }
            guard seen.insert(actions.id).inserted else {
                incomplete = true; omissions.insert("repeated_element"); continue
            }
            if !actions.secure {
                if parent == nil {
                    observedPaths[actions.id] = prefix ?? ([node], [])
                } else if let parent = parent, let route = observedPaths[parent],
                          let rawParent = attribute(node, kAXParentAttribute, deadline: deadline),
                          lastAttributeResult == .success, CFGetTypeID(rawParent) == AXUIElementGetTypeID() {
                    let reference = rawParent as! AXUIElement
                    do {
                        try check(app, reference)
                        observedPaths[actions.id] = (route.nodes + [node], route.parents + [reference])
                    } catch let failure as NativeFailure where failure.code == "native_element_process_mismatch"
                        || failure.code == "native_element_identity_unavailable" { }
                }
            }
            let textCapable = actions.hasTextSelectionCapability
            if textCapable, let route = observedPaths[actions.id] {
                actions.textRouteID = textRouteID(actions.id, nodes: route.nodes, parents: route.parents)
            }
            let actionable = textCapable || !actions.actions.isEmpty || [kAXTextFieldRole, kAXTextAreaRole, kAXCheckBoxRole, kAXButtonRole, kAXPopUpButtonRole].contains(actions.role ?? "")
            // Reserve both node and legacy-control descriptions; JSON byte size
            // includes Unicode encoding, quotes and escaping, not character count.
            let row = NativeTreeNode(id: actions.id, parentID: parent, childIndex: childIndex,
                                     depth: depth, element: actions, childrenState: "protected_subtree_omitted")
            let nodeBytes = (try JSONEncoder().encode(row)).count
            let newControl = actionable && !flatControlIDs.contains(actions.id)
            let controlBytes = newControl && controls.count < 200 ? (try JSONEncoder().encode(actions)).count : 0
            guard descriptionBytes + nodeBytes + controlBytes + 128 <= descriptionBudget else {
                interruptedParent = parent
                incomplete = true; omissions.insert("byte_limit"); break
            }
            descriptionBytes += nodeBytes + controlBytes + 128
            if newControl {
                if controls.count < 200 { controls.append(actions); flatControlIDs.insert(actions.id) }
                else { incomplete = true; omissions.insert("control_limit") }
            }
            var childrenState = "complete"
            if actions.secure {
                childrenState = "protected_subtree_omitted"; incomplete = true; omissions.insert(childrenState)
            } else if depth == localDepth {
                childrenState = "depth_limit"; incomplete = true; omissions.insert(childrenState)
            } else if ProcessInfo.processInfo.systemUptime >= deadline {
                childrenState = "time_limit"; incomplete = true; omissions.insert(childrenState)
            } else {
                var raw: CFTypeRef?
                let remaining = deadline - ProcessInfo.processInfo.systemUptime
                guard remaining > 0 else { interruptedParent = parent; incomplete = true; omissions.insert("time_limit"); break }
                let configured = AXUIElementSetMessagingTimeout(node, Float(min(0.1, remaining)))
                let result = configured == .success ? AXUIElementCopyAttributeValue(node, kAXChildrenAttribute as CFString, &raw) : configured
                if configured != .success { treeFieldReadFailures?.insert("children_timeout_setup_failed") }
                if result == .attributeUnsupported || result == .noValue { childrenState = "no_children_attribute" }
                else if result != .success {
                    childrenState = "ax_error_\(result.rawValue)"; incomplete = true; omissions.insert("children_read_failed")
                } else if let children = raw as? [AXUIElement] {
                    let remainingCapacity = max(0, 1000 - visited - (pending.count - nextPending) - (modalPending.count - nextModal))
                    if children.count > remainingCapacity {
                        childrenState = "node_limit"; incomplete = true; omissions.insert(childrenState)
                    }
                    let admitted = Array(children.prefix(remainingCapacity).enumerated())
                    let ordered = depth == 0
                        ? try modalFirstWindowChildren(admitted, owner: app, deadline: deadline)
                        : admitted.map { (offset: $0.offset, element: $0.element, modal: false) }
                    for child in ordered {
                        let entry = (child.element, depth + 1, Optional(actions.id), child.offset, modal || child.modal)
                        if entry.4 { modalPending.append(entry) } else { pending.append(entry) }
                    }
                } else { childrenState = "invalid_children_type"; incomplete = true; omissions.insert(childrenState) }
            }
            nodes.append(NativeTreeNode(id: actions.id, parentID: parent, childIndex: childIndex,
                depth: depth, element: actions, childrenState: childrenState))
        }
        // AXChildren enumeration is not descendant coverage. Mark admitted
        // edges whose queued child was never published when any budget ended.
        if nextPending < pending.count || nextModal < modalPending.count || interruptedParent != nil {
            incomplete = true; omissions.insert("queued_children_omitted")
            var parents = Set(pending[nextPending...].compactMap { $0.2 })
            parents.formUnion(modalPending[nextModal...].compactMap { $0.2 })
            if let parent = interruptedParent { parents.insert(parent) }
            for index in nodes.indices where parents.contains(nodes[index].id)
                && nodes[index].childrenState == "complete" {
                nodes[index].childrenState = "queued_children_omitted"
            }
        }
        let title = String((attribute(element, kAXTitleAttribute, deadline: deadline) as? String ?? "").prefix(300))
        let isFocused = focused(app, window: element, deadline: deadline)
        if ProcessInfo.processInfo.systemUptime >= deadline { incomplete = true; omissions.insert("time_limit") }
        if let failures = treeFieldReadFailures, !failures.isEmpty { incomplete = true; omissions.formUnion(failures) }
        let tree = NativeTreeObservation(nodes: nodes, complete: !incomplete, omissions: omissions.sorted(),
            startedAt: started, finishedAt: Date().timeIntervalSince1970,
            maximumNodes: 1000, maximumDepth: localDepth, maximumSeconds: 1)
        let current = try windowIdentitySnapshot(app, windowID: id)
        guard current.bounds == bounds else { throw NativeFailure("native_window_moved") }
        if let original = initial.identity.windowID, let latest = current.identity.windowID, original != latest {
            throw NativeFailure("native_window_identity_changed")
        }
        for (controlID, route) in observedPaths where controlBindings.entry(controlID)?.owner == id {
            controlPaths[controlID] = route
            controlScopedHops[controlID] = scopedHops
        }
        // The retained prefix is rechecked after traversal before publication.
        if let rootID = rootControlID, let anchor = anchor {
            guard try validateControlAncestry(anchor.element, window: element, owner: app, controlID: rootID,
                deadline: min(observationDeadline, ProcessInfo.processInfo.systemUptime + 0.3)) else {
                throw NativeFailure("native_subtree_anchor_unavailable")
            }
        }
        windowRouteRevisions[id] = routeRevision
        controlPaths = controlPaths.filter { controlBindings.entry($0.key) != nil }
        let positionSettable = geometrySettable(element, attribute: kAXPositionAttribute, deadline: deadline)
        let sizeSettable = geometrySettable(element, attribute: kAXSizeAttribute, deadline: deadline)
        var keyboardRecipient: NativeKeyboardRecipientDiagnostic?
        if includeKeyboardRecipient {
            let application = AXUIElementCreateApplication(app.pid)
            let candidates = controls.filter { !$0.secure }.compactMap { control -> (id: String, element: AXUIElement)? in
                guard let binding = controlBindings.entry(control.id), binding.owner == id else { return nil }
                return (control.id, binding.element)
            }
            keyboardRecipient = NativeKeyboardRecipientObservation.sample(window: element, controls: candidates,
                deadline: deadline, now: { ProcessInfo.processInfo.systemUptime },
                wallNow: { Date().timeIntervalSince1970 },
                authorized: {
                    do { try self.cancellationCheck?(); try self.check(app, element); return true }
                    catch { return false }
                }, same: { CFEqual($0, $1) },
                read: { name, sampleDeadline in
                    guard let raw = self.attribute(application, name, deadline: sampleDeadline),
                          self.lastAttributeResult == .success, CFGetTypeID(raw) == AXUIElementGetTypeID() else { return nil }
                    return (raw as! AXUIElement)
                })
        }
        return NativeWindow(id: id, title: title, bounds: bounds, focused: isFocused,
            controls: controls, nodesVisited: visited, incomplete: incomplete, cgWindowID: current.identity.windowID,
            routeRevision: routeRevision, tree: tree,
            positionSettable: positionSettable, sizeSettable: sizeSettable,
            minimized: minimized, minimizedSettable: minimizedSettable, identityDiagnostic: current.identity.diagnostic,
            fullscreen: fullscreen, keyboardRecipient: keyboardRecipient, attachedSheetParentID: attachedSheetParents[id])
        }
    }
    private func textRouteID(_ controlID: String, nodes: [AXUIElement], parents: [AXUIElement]) -> String {
        if let prior = textControlRoutes[controlID], prior.nodes.count == nodes.count, prior.parents.count == parents.count,
           zip(prior.nodes, nodes).allSatisfy({ CFEqual($0.0, $0.1) }),
           zip(prior.parents, parents).allSatisfy({ CFEqual($0.0, $0.1) }) { return prior.token }
        let token = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        textControlRoutes[controlID] = (nodes, parents, token)
        return token
    }
    private func validateControlAncestry(_ element: AXUIElement, window: AXUIElement,
                                         owner app: NativeAppIdentity, controlID: String,
                                         deadline: Double) throws -> Bool {
        // Fresh downward AXChildren edges prove exact-root containment. Cached
        // paths merely select edges to check. AXParent need not equal the visible
        // parent (Electron virtualizes it), but its observed same-PID reference
        // must remain stable; unavailable or contradictory evidence fails closed.
        let hops = controlScopedHops[controlID] ?? 0
        guard (0...2).contains(hops), let route = controlPaths[controlID], !route.nodes.isEmpty,
              route.nodes.count <= (hops == 0 ? 31 : 64),
              route.parents.count == route.nodes.count - 1,
              CFEqual(route.nodes[0], window), CFEqual(route.nodes.last!, element) else { return false }
        let chain = route.nodes
        let rootRole = attachedSheetParents[controlBindings.entry(controlID)?.owner ?? ""] == nil ? kAXWindowRole : kAXSheetRole
        for index in chain.indices {
            guard !chain.prefix(index).contains(where: { CFEqual($0, chain[index]) }) else { return false }
        }
        for _ in 0..<2 {
            for index in chain.indices {
                guard ProcessInfo.processInfo.systemUptime < deadline else { return false }
                let node = chain[index]
                try check(app, node)
                let metadata = securityMetadata(node, deadline: deadline)
                var adapted = false
                if index == chain.count - 1, metadata.textEditDescriptionFailure || textEditDocumentPrivacyControls.contains(controlID) {
                    adapted = try trustedSystemTextEdit(app)
                        && textEditDocumentAncestors(node, app: app, window: window, deadline: deadline)
                    guard adapted, metadata.role == .text(kAXTextAreaRole) else { return false }
                }
                guard !NativeAttributePolicy.protects(metadata, inheritedSecure: false,
                    textEditCodeVerified: adapted, textEditDocumentAncestorsVerified: adapted),
                    index != 0 || metadata.role == .text(rootRole),
                    index == 0 || metadata.role != .text(kAXWindowRole) else { return false }
                if index > 0 {
                    guard let rawParent = attribute(node, kAXParentAttribute, deadline: deadline),
                          lastAttributeResult == .success, CFGetTypeID(rawParent) == AXUIElementGetTypeID() else { return false }
                    let reference = rawParent as! AXUIElement
                    try check(app, reference)
                    guard CFEqual(reference, route.parents[index - 1]) else { return false }
                }
                if index + 1 < chain.count {
                    guard let rawChildren = attribute(node, kAXChildrenAttribute, deadline: deadline),
                          lastAttributeResult == .success, let children = rawChildren as? [AXUIElement],
                          children.prefix(1000).contains(where: { CFEqual($0, chain[index + 1]) }) else { return false }
                }
            }
        }
        try check(app, element); try check(app, window)
        return ProcessInfo.processInfo.systemUptime < deadline
    }

    private func validateControlTarget(_ app: NativeAppIdentity, windowID: String,
                                       controlID: String, element: AXUIElement) throws {
        guard let window = windowBindings.entry(windowID), window.owner == app else {
            throw NativeFailure("native_window_control_changed")
        }
        let deadline = ProcessInfo.processInfo.systemUptime + 0.3
        if attachedSheetParents[windowID] != nil {
            _ = try attachedSheetParent(app, windowID: windowID, deadline: deadline)
        }
        let valid: Bool
        do {
            try check(app, element); try check(app, window.element)
            if let origin = windowChromeControls[controlID] {
                valid = try origin.windowID == windowID && validateWindowChrome(element,
                    window: window.element, attribute: origin.attribute, owner: app, deadline: deadline)
            } else {
                valid = try validateControlAncestry(element, window: window.element,
                    owner: app, controlID: controlID, deadline: deadline)
            }
        } catch let error as NativeFailure where error.code == "native_element_process_mismatch" {
            throw NativeFailure("native_window_control_changed")
        }
        guard valid, ProcessInfo.processInfo.systemUptime < deadline,
              let current = windowBindings.entry(windowID), current.owner == app,
              CFEqual(current.element, window.element) else { throw NativeFailure("native_window_control_changed") }
        if attachedSheetParents[windowID] != nil {
            _ = try attachedSheetParent(app, windowID: windowID, deadline: deadline)
        }
    }

    func control(_ app: NativeAppIdentity, windowID: String, id: String) throws -> NativeControl {
        guard let binding = controlBindings.entry(id), binding.owner == windowID else { throw NativeFailure("unknown_native_control") }
        let element = binding.element
        guard matches(app) else { throw NativeFailure("native_process_identity_changed") }
        try validateControlTarget(app, windowID: windowID, controlID: id, element: element)
        try check(app, element)
        guard geometry(element) != nil else { throw NativeFailure("native_control_unavailable") }
        var control = try describe(element, windowID: windowID)
        control.windowAttribute = windowChromeControls[id]?.attribute
        if let route = controlPaths[id], control.hasTextSelectionCapability {
            control.textRouteID = textRouteID(id, nodes: route.nodes, parents: route.parents)
        }
        return control
    }
    func windowAvailable(_ app: NativeAppIdentity, id: String) -> Bool? {
        guard let binding = windowBindings.entry(id), binding.owner == app else { return nil }
        let element = binding.element
        var value: CFTypeRef?
        let result = AXUIElementCopyAttributeValue(element, kAXPositionAttribute as CFString, &value)
        if result == .invalidUIElement { return false }
        guard result == .success else { return nil } // Temporary AX gaps do not prove closure.
        if attachedSheetParents[id] != nil,
           (try? attachedSheetParent(app, windowID: id, deadline: ProcessInfo.processInfo.systemUptime + 0.3)) == nil { return nil }
        return true
    }
    func perform(_ app: NativeAppIdentity, windowID: String, controlID: String, action: String, text: String?) throws -> Int32 {
        guard let binding = controlBindings.entry(controlID), binding.owner == windowID else { throw NativeFailure("unknown_native_control") }
        let element = binding.element
        guard matches(app) else { throw NativeFailure("native_process_identity_changed") }
        try validateControlTarget(app, windowID: windowID, controlID: controlID, element: element)
        try check(app, element)
        let result: AXError
        if action == "set_value", let text = text { result = AXUIElementSetAttributeValue(element, kAXValueAttribute as CFString, text as CFString) }
        else if action == "replace_selection", let text = text { result = AXUIElementSetAttributeValue(element, kAXSelectedTextAttribute as CFString, text as CFString) }
        else { result = AXUIElementPerformAction(element, action as CFString) }
        return result.rawValue
    }
    func selectTextRange(_ app: NativeAppIdentity, windowID: String, controlID: String, range: NativeTextRange) throws -> Int32 {
        guard let binding = controlBindings.entry(controlID), binding.owner == windowID else { throw NativeFailure("unknown_native_control") }
        guard matches(app) else { throw NativeFailure("native_process_identity_changed") }
        let element = binding.element
        var selected = CFRange(location: range.location, length: range.length)
        guard let value = AXValueCreate(.cfRange, &selected) else { throw NativeFailure("native_text_range_invalid") }
        try validateControlTarget(app, windowID: windowID, controlID: controlID, element: element)
        return AXUIElementSetAttributeValue(element, kAXSelectedTextRangeAttribute as CFString, value).rawValue
    }
    func performTextAction(_ app: NativeAppIdentity, windowID: String, expectedWindow: NativeWindowGeometrySnapshot,
        expected: NativeControl, action: String, text: String?, selection: NativeTextRange?, beforeSetter: () throws -> Void) throws -> Int32 {
        guard let binding = controlBindings.entry(expected.id), binding.owner == windowID,
              expectedWindow.windowID == windowID, expected.textRouteID != nil else { throw NativeFailure("unknown_native_control") }
        // Prepare the setter argument before the last recipient/authority
        // checks. Neither branch focuses, raises, sends keys, or uses a board.
        let attributeName: String, setterValue: CFTypeRef
        if action == "select_text", text == nil, let range = selection,
           expected.selectedRangeSettable, let original = expected.value, range.valid(in: original) {
            var raw = CFRange(location: range.location, length: range.length)
            guard let value = AXValueCreate(.cfRange, &raw) else { throw NativeFailure("native_text_range_invalid") }
            attributeName = kAXSelectedTextRangeAttribute; setterValue = value
        } else if action == "replace_selection", selection == nil, expected.selectedTextSettable,
                  let original = expected.value, let range = expected.selectedRange, range.valid(in: original),
                  let text = text, text.utf8.count <= 32768 {
            attributeName = kAXSelectedTextAttribute; setterValue = text as CFString
        } else { throw NativeFailure("native_text_selection_unavailable") }
        let currentWindow = try windowGeometry(app, windowID: windowID)
        guard currentWindow.windowID == expectedWindow.windowID,
              currentWindow.cgWindowID == expectedWindow.cgWindowID else { throw NativeFailure("native_window_identity_changed") }
        guard currentWindow.bounds == expectedWindow.bounds else { throw NativeFailure("native_window_moved") }
        // control repeats exact-root ancestry/privacy and process identity, then
        // reads the actual value, selection, role and setter capabilities.
        let current = try control(app, windowID: windowID, id: expected.id)
        guard current == expected, NativeTextRange.sameText(current.value, expected.value),
              !current.secure, !current.valueTruncated, current.enabled, current.valueType == "text",
              let fresh = controlBindings.entry(expected.id), fresh.owner == windowID,
              CFEqual(fresh.element, binding.element) else { throw NativeFailure("native_control_changed") }
        var result: Int32 = -1
        func send() throws {
            // A later focused/URL/geometry getter in describe can cause a one-way
            // recipient change. Resample the exact text tuple after those getters;
            // then finish with privacy. AX still provides no atomic compare-and-set.
            let deadline = ProcessInfo.processInfo.systemUptime + 0.3
            let finalText = attribute(binding.element, kAXValueAttribute, deadline: deadline) as? String
            guard lastAttributeResult == .success, NativeTextRange.sameText(finalText, expected.value) else {
                throw NativeFailure("native_control_changed")
            }
            var finalRange: NativeTextRange?
            if let rawRange = attribute(binding.element, kAXSelectedTextRangeAttribute, deadline: deadline) {
                guard CFGetTypeID(rawRange) == AXValueGetTypeID() else { throw NativeFailure("native_control_changed") }
                let value = rawRange as! AXValue
                var range = CFRange()
                guard AXValueGetType(value) == .cfRange, AXValueGetValue(value, .cfRange, &range) else {
                    throw NativeFailure("native_control_changed")
                }
                finalRange = NativeTextRange(location: range.location, length: range.length)
            } else if lastAttributeResult != .attributeUnsupported && lastAttributeResult != .noValue {
                throw NativeFailure("native_control_changed")
            }
            guard finalRange == expected.selectedRange else { throw NativeFailure("native_control_changed") }
            let finalPrivacy = securityMetadata(binding.element, deadline: deadline)
            let adaptedDocument = textEditDocumentPrivacyControls.contains(expected.id) && expected.role == kAXTextAreaRole
            guard finalPrivacy.role.value == expected.role,
                  !NativeAttributePolicy.protects(finalPrivacy, inheritedSecure: false,
                    textEditCodeVerified: adaptedDocument, textEditDocumentAncestorsVerified: adaptedDocument),
                  ProcessInfo.processInfo.systemUptime < deadline else { throw NativeFailure("local_sensitive_input_required") }
            try beforeSetter()
            // AX has no compare-and-set: a target can still change after this final
            // snapshot. Exact sampled readback is reported separately from dispatch.
            result = AXUIElementSetAttributeValue(binding.element, attributeName as CFString, setterValue).rawValue
        }
        // No cancellation callback or whole-window traversal is permitted
        // inside the nonrecursive send gate. Preparation above remains freely
        // cancellable; this final admitted batch is deliberately bounded.
        if let guarded = guardedInputSend { try guarded(send) } else { try send() }
        return result
    }
    private func geometrySettable(_ element: AXUIElement, attribute: String, deadline: Double) -> Bool? {
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        guard remaining > 0, AXUIElementSetMessagingTimeout(element, Float(min(0.1, remaining))) == .success else { return nil }
        var value = DarwinBoolean(false)
        guard AXUIElementIsAttributeSettable(element, attribute as CFString, &value) == .success else { return nil }
        return value.boolValue
    }
    private func minimizedValue(_ element: AXUIElement, deadline: Double) -> Bool? {
        let raw = attribute(element, kAXMinimizedAttribute, deadline: deadline)
        return NativeMinimizedAttribute.value(raw, success: lastAttributeResult == .success)
    }
    private func fullscreenValue(_ element: AXUIElement, deadline: Double) -> Bool? {
        let readDeadline = min(deadline, ProcessInfo.processInfo.systemUptime + 0.1)
        let raw = attribute(element, "AXFullScreen", deadline: readDeadline)
        guard ProcessInfo.processInfo.systemUptime < readDeadline else { return nil }
        // Reuse the strict CFBoolean decoder, without minimized input policy.
        return NativeMinimizedAttribute.value(raw, success: lastAttributeResult == .success)
    }
    func windowMinimizedState(_ app: NativeAppIdentity, windowID: String) throws -> NativeWindowMinimizedState {
        guard let binding = windowBindings.entry(windowID), binding.owner == app else { throw NativeFailure("unknown_native_window") }
        guard matches(app) else { throw NativeFailure("native_process_identity_changed") }
        try check(app, binding.element)
        let deadline = ProcessInfo.processInfo.systemUptime + 0.2
        if attachedSheetParents[windowID] != nil {
            _ = try attachedSheetParent(app, windowID: windowID, deadline: deadline)
        }
        let state = NativeWindowMinimizedState(windowID: windowID,
            minimized: minimizedValue(binding.element, deadline: deadline),
            minimizedSettable: geometrySettable(binding.element, attribute: kAXMinimizedAttribute, deadline: deadline))
        // The engine checks cancellation outside the Stop/send lock; this
        // read is also used by the final setter guard under that lock.
        try check(app, binding.element)
        return state
    }
    func setWindowRestored(_ app: NativeAppIdentity, windowID: String,
                           beforeSetter: () throws -> Void) throws -> NativeWindowRestoreSetterResult {
        guard let binding = windowBindings.entry(windowID), binding.owner == app else { throw NativeFailure("unknown_native_window") }
        let before = try windowMinimizedState(app, windowID: windowID)
        guard before.minimized != nil else { throw NativeFailure("native_minimized_state_unavailable") }
        guard before.minimized == true else { return NativeWindowRestoreSetterResult(attempted: false, dispatchResult: nil, before: before) }
        guard before.minimizedSettable == true else {
            return NativeWindowRestoreSetterResult(attempted: false, dispatchResult: nil, before: before)
        }
        guard let current = windowBindings.entry(windowID), current.owner == app, CFEqual(current.element, binding.element),
              matches(app) else { throw NativeFailure("native_process_identity_changed") }
        try check(app, binding.element)
        guard AXUIElementSetMessagingTimeout(binding.element, 0.1) == .success else { throw NativeFailure("native_minimized_capability_unavailable") }
        invalidateCursor(windowID: windowID)
        try beforeSetter()
        let sent = AXUIElementSetAttributeValue(binding.element, kAXMinimizedAttribute as CFString, kCFBooleanFalse)
        return NativeWindowRestoreSetterResult(attempted: true, dispatchResult: sent.rawValue, before: before)
    }
    func windowRestoreReadback(_ app: NativeAppIdentity, windowID: String) throws -> NativeWindowRestoreReadback {
        guard let binding = windowBindings.entry(windowID), binding.owner == app else { throw NativeFailure("unknown_native_window") }
        return NativeWindowRestorePoll.read(now: { ProcessInfo.processInfo.systemUptime }, check: {
            try self.cancellationCheck?()
            guard self.matches(app), let current = self.windowBindings.entry(windowID),
                  current.owner == app, CFEqual(current.element, binding.element) else { throw NativeFailure("native_process_identity_changed") }
            try self.check(app, binding.element)
        }, sample: { deadline in
            NativeWindowMinimizedState(windowID: windowID,
                minimized: self.minimizedValue(binding.element, deadline: deadline), minimizedSettable: nil)
        }, wait: { Thread.sleep(forTimeInterval: $0) })
    }
    func windowGeometry(_ app: NativeAppIdentity, windowID: String) throws -> NativeWindowGeometrySnapshot {
        let deadline = ProcessInfo.processInfo.systemUptime + 0.5
        guard let binding = windowBindings.entry(windowID), binding.owner == app else { throw NativeFailure("unknown_native_window") }
        guard matches(app) else { throw NativeFailure("native_process_identity_changed") }
        try check(app, binding.element)
        guard let bounds = inputGeometry(binding.element, deadline: deadline, attributeLimit: 0.1).bounds else {
            throw NativeFailure("native_window_geometry_unavailable")
        }
        let mapped = try windowCGMapping(app, windowID: windowID, bounds: bounds, deadline: deadline).windowID
        guard ProcessInfo.processInfo.systemUptime < deadline, matches(app) else { throw NativeFailure("native_window_geometry_unavailable") }
        try check(app, binding.element)
        return NativeWindowGeometrySnapshot(windowID: windowID, bounds: bounds, cgWindowID: mapped)
    }
    func windowGeometryReadback(_ app: NativeAppIdentity, windowID: String, originalWindowID: UInt32) throws -> NativeWindowGeometryReadback {
        guard let binding = windowBindings.entry(windowID), binding.owner == app else { throw NativeFailure("unknown_native_window") }
        guard let revision = mappingVersion(windowID) else { throw NativeFailure("native_geometry_identity_unavailable") }
        // AX setters may return before WindowServer publishes the new frame.
        // Poll only reads; a missing/changed/ambiguous original fails closed.
        return try NativeGeometryReadbackPoll.read(now: { ProcessInfo.processInfo.systemUptime }, check: {
            try self.cancellationCheck?()
            guard self.matches(app), let current = self.windowBindings.entry(windowID),
                  current.owner == app, CFEqual(current.element, binding.element),
                  self.mappingVersion(windowID) == revision else { throw NativeFailure("native_geometry_identity_changed") }
            try self.check(app, binding.element)
        }, sample: { deadline in
            guard let bounds = self.inputGeometry(binding.element, deadline: deadline, attributeLimit: 0.1).bounds else {
                throw NativeFailure("native_window_geometry_unavailable")
            }
            let mapping = try self.windowCGMapping(app, windowID: windowID, bounds: bounds,
                deadline: deadline, originalWindowID: originalWindowID).mapping
            return (NativeWindowGeometrySnapshot(windowID: windowID, bounds: bounds, cgWindowID: mapping.windowID), mapping.state)
        }, wait: { Thread.sleep(forTimeInterval: $0) })
    }
    func setWindowGeometry(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot,
                           mutation: NativeWindowGeometryMutation, beforeSetter: () throws -> Void) throws -> NativeGeometrySetterResult {
        let deadline = ProcessInfo.processInfo.systemUptime + 0.5
        guard let binding = windowBindings.entry(windowID), binding.owner == app else { throw NativeFailure("unknown_native_window") }
        guard matches(app) else { throw NativeFailure("native_process_identity_changed") }
        try check(app, binding.element)
        let attribute = mutation.action == "move" ? kAXPositionAttribute : kAXSizeAttribute
        guard AXUIElementSetMessagingTimeout(binding.element, 0.1) == .success else { throw NativeFailure("native_geometry_capability_unavailable") }
        var settable = DarwinBoolean(false)
        let capability = AXUIElementIsAttributeSettable(binding.element, attribute as CFString, &settable)
        guard capability == .success, settable.boolValue else {
            return NativeGeometrySetterResult(attempted: false, dispatchResult: nil, capabilityResult: capability.rawValue,
                settable: capability == .success ? settable.boolValue : nil)
        }
        let value: AXValue?
        switch mutation {
        case .move(let point):
            var position = CGPoint(x: point.x, y: point.y); value = AXValueCreate(.cgPoint, &position)
        case .resize(let requested):
            var size = CGSize(width: requested.width, height: requested.height); value = AXValueCreate(.cgSize, &size)
        }
        guard let value = value else { throw NativeFailure("invalid_native_geometry") }
        let actual = try windowGeometry(app, windowID: windowID)
        guard actual == expected else { throw NativeFailure("native_window_moved") }
        guard ProcessInfo.processInfo.systemUptime < deadline, matches(app) else { throw NativeFailure("native_process_identity_changed") }
        try check(app, binding.element)
        invalidateCursor(windowID: windowID)
        try beforeSetter()
        // The caller owns Stop/send linearization. No nested cancellation or
        // fallible post-send work occurs before the raw setter result returns.
        let sent = AXUIElementSetAttributeValue(binding.element, attribute as CFString, value)
        return NativeGeometrySetterResult(attempted: true, dispatchResult: sent.rawValue, capabilityResult: capability.rawValue, settable: true)
    }
    func pointInput(_ app: NativeAppIdentity, windowID: String, point: NativePoint, action: String, marker: Int64) throws {
        guard frontmostPID == app.pid, matches(app), inputMonitorAvailable else { throw NativeFailure("native_focus_changed") }
        monitor.addMarker(marker)
        let source = CGEventSource(stateID: .privateState)
        let location = CGPoint(x: point.x, y: point.y)
        let epoch = inputEpoch
        for click in 1...(action == "double_click" ? 2 : 1) {
            guard frontmostPID == app.pid, matches(app), inputEpoch == epoch else { throw NativeFailure("human_input_interrupted", "unknown") }
            for type in [CGEventType.leftMouseDown, .leftMouseUp] {
                if type == .leftMouseDown {
                    try NativeMinimizedAttribute.requireInputAvailable(try windowMinimizedState(app, windowID: windowID).minimized)
                }
                guard frontmostPID == app.pid, inputEpoch == epoch, pointIsVisible(app, windowID: windowID, point: point) else {
                    throw NativeFailure("human_input_interrupted", "unknown")
                }
                guard let event = CGEvent(mouseEventSource: source, mouseType: type, mouseCursorPosition: location, mouseButton: .left) else {
                    throw NativeFailure("native_event_creation_failed", "unknown")
                }
                event.setIntegerValueField(.eventSourceUserData, value: marker)
                event.setIntegerValueField(.mouseEventClickState, value: Int64(click))
                event.post(tap: .cghidEventTap)
            }
        }
    }
    private func targetedInputContext(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot, point: NativePoint, marker: Int64) throws -> (NativeWindow, UInt32, NativePoint?, NativePointerActivationMode, (Bool) throws -> Void) {
        guard let binding = windowBindings.entry(windowID), binding.owner == app else { throw NativeFailure("unknown_native_window") }
        let element = binding.element
        let window = try self.window(app, id: windowID)
        try NativeMinimizedAttribute.requireInputAvailable(window.minimized)
        try expected.requireMatch(NativeWindowGeometrySnapshot(windowID: window.id, bounds: window.bounds, cgWindowID: window.cgWindowID))
        if frontmostPID == app.pid && !window.focused {
            throw NativeFailure("native_same_process_window_isolation_unavailable")
        }
        guard let number = window.cgWindowID, window.bounds.contains(point), targetedPointer.available else {
            throw NativeFailure("native_targeted_pointer_unavailable")
        }
        var activationMode = try NativePointerActivationMode.forVerifiedApp(app, verifyCurrentSignature: { self.matches(app) })
        var activationPoint: NativePoint?
        var activationReadAttempted = false, activationDisposition = "not_read"
        if activationMode == .activationPoint {
            if let raw = attribute(element, "AXActivationPoint") {
                activationReadAttempted = lastAttributeValueReadAttempted
                activationDisposition = "malformed"
                if CFGetTypeID(raw) == AXValueGetTypeID(), AXValueGetType(raw as! AXValue) == .cgPoint {
                    var location = CGPoint.zero
                    if AXValueGetValue(raw as! AXValue, .cgPoint, &location) {
                        activationPoint = NativePoint(x: location.x, y: location.y)
                        let saneBounds = window.bounds.finite && (window.bounds.x + window.bounds.width).isFinite
                            && (window.bounds.y + window.bounds.height).isFinite
                        activationDisposition = location.x.isFinite && location.y.isFinite && saneBounds
                            ? (window.bounds.contains(activationPoint!) ? "available" : "outside_bounds") : "malformed"
                        activationMode = try NativePointerActivationMode.outsideActivationPoint(app,
                            point: activationPoint, bounds: window.bounds, attributeResult: lastAttributeResult,
                            attributeReadAttempted: activationReadAttempted, verifyCurrentSignature: { self.matches(app) })
                        // Shared with captured custom-key focus preparation: never
                        // retain unusable coordinates for its cursor preparation.
                        if activationMode == .windowContextOnly { activationPoint = nil }
                    }
                }
            } else {
                activationReadAttempted = lastAttributeValueReadAttempted
                activationDisposition = !activationReadAttempted ? "read_failed" :
                    lastAttributeResult == .attributeUnsupported ? "unsupported" :
                    lastAttributeResult == .noValue ? "no_value" :
                    lastAttributeResult == .success ? "malformed" : "read_failed"
                activationMode = try NativePointerActivationMode.withoutActivationPoint(app,
                    attributeResult: lastAttributeResult, attributeReadAttempted: lastAttributeValueReadAttempted,
                    verifyCurrentSignature: { self.matches(app) })
            }
        }
        pointerTraceObserver?(["kind": "activation_context", "read_attempted": activationReadAttempted,
            "disposition": activationDisposition, "selected_mode": activationMode.rawValue])
        monitor.addMarker(marker)
        let validate: (Bool) throws -> Void = { releasing in
            if !releasing {
                try NativeGeometryRevalidation.validate(expected: window.bounds, expectedCG: number,
                    cannotComplete: AXError.cannotComplete.rawValue,
                    now: { ProcessInfo.processInfo.systemUptime }, check: { deadline in
                        try self.cancellationCheck?()
                        try self.requireGeometryReadBudget(deadline)
                        guard self.matches(app) else { throw NativeFailure("native_process_identity_changed", "unknown") }
                        try self.requireGeometryReadBudget(deadline)
                        guard self.accessibilityAllowed, CGPreflightPostEventAccess() else {
                            throw NativeFailure("native_input_permission_revoked", "unknown")
                        }
                        try self.check(app, element, deadline: deadline)
                        try NativeMinimizedAttribute.requireInputAvailable(self.minimizedValue(element,
                            deadline: deadline))
                        try self.requireGeometryReadBudget(deadline)
                        if self.frontmostPID == app.pid, !self.focused(app, window: element, deadline: deadline) {
                            throw NativeFailure("native_same_process_window_isolation_unavailable", "unknown")
                        }
                        try self.requireGeometryReadBudget(deadline)
                        guard let rows = CGWindowListCopyWindowInfo(.optionAll, kCGNullWindowID) as? [[String: Any]],
                              rows.contains(where: { ($0[kCGWindowNumber as String] as? UInt32) == number
                                  && ($0[kCGWindowOwnerPID as String] as? Int32) == app.pid }) else {
                            throw NativeFailure("native_window_identity_changed", "unknown")
                        }
                    }, read: { deadline, limit in
                        self.inputGeometry(element, deadline: deadline, attributeLimit: limit)
                    }, mappedCG: { bounds, deadline in
                        self.mappedCGID(app, windowID: windowID, bounds: bounds, deadline: deadline)
                    }, trace: { self.pointerTraceObserver?($0) })
            } else {
                // Release/focus cleanup keeps its original one-pass guard.
                guard self.matches(app), self.accessibilityAllowed else { throw NativeFailure("native_process_identity_changed", "unknown") }
                guard let rows = CGWindowListCopyWindowInfo(.optionAll, kCGNullWindowID) as? [[String: Any]],
                      rows.contains(where: { ($0[kCGWindowNumber as String] as? UInt32) == number
                          && ($0[kCGWindowOwnerPID as String] as? Int32) == app.pid }) else {
                    throw NativeFailure("native_window_identity_changed", "unknown")
                }
            }
        }
        return (window, number, activationPoint, activationMode, validate)
    }
    func targetedDragInput(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot,
                           point: NativePoint, drag: NativeDrag, marker: Int64, admission: @escaping () throws -> Void,
                           sendCheck: @escaping () throws -> Void) throws {
        try admission()
        let path = try drag.path(from: point)
        guard path.allSatisfy({ expected.bounds.contains($0) }) else { throw NativeFailure("native_point_outside_scope") }
        let (window, number, activationPoint, activationMode, validate) = try targetedInputContext(app, windowID: windowID, expected: expected, point: point, marker: marker)
        prepareCursor(app, windowID: windowID, number: number, bounds: window.bounds, marker: marker, point: point)
        let guarded = guardedInputSend
        let finalSend: ((() throws -> Void) throws -> Void) = { dispatch in
            if let guarded = guarded { try guarded { try sendCheck(); try dispatch() } }
            else { try sendCheck(); try dispatch() }
        }
        try targetedPointer.drag(app: app, windowNumber: number, bounds: window.bounds, point: point, drag: drag,
            activationPoint: activationPoint, marker: marker, activationMode: activationMode, guardedSend: finalSend, validate: { releasing in
                if !releasing { try admission() }
                try validate(releasing)
                if !releasing {
                    guard path.allSatisfy({ location in self.displays().contains(where: { $0.bounds.contains(location) }) }) else {
                        throw NativeFailure("native_point_outside_scope", "unknown")
                    }
                    try admission()
                }
            })
    }
    func withTargetedFocus<Value>(_ app: NativeAppIdentity, windowID: String,
        expected: NativeWindowGeometrySnapshot, point: NativePoint, marker: Int64,
        admission: NativePointerAdmission, body: @escaping (@escaping () throws -> Void) throws -> Value) throws -> Value {
        try admission.validateAuthority()
        let (window, number, activationPoint, activationMode, validate) = try targetedInputContext(app,
            windowID: windowID, expected: expected, point: point, marker: marker)
        let revalidate = admission.validating(validate)
        prepareCursor(app, windowID: windowID, number: number, bounds: window.bounds,
            marker: marker, point: activationPoint ?? point)
        return try targetedPointer.withFocusContext(app: app, windowNumber: number, bounds: window.bounds,
            point: point, activationPoint: activationPoint, marker: marker, activationMode: activationMode,
            guardedSend: admission.guardedSend(guardedInputSend), validate: revalidate, body: {
                try body {
                    try revalidate(false)
                    try admission.beforeSend()
                }
            })
    }

    func targetedPointInput(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot, point: NativePoint, action: String, modifiers: [String], marker: Int64, admission: NativePointerAdmission) throws {
        try NativePointerClickModifiers.validate(modifiers)
        guard modifiers.isEmpty || action == "click" else { throw NativeFailure("native_pointer_modifiers_outside_scope") }
        try admission.validateAuthority()
        let (window, number, activationPoint, activationMode, validate) = try targetedInputContext(app, windowID: windowID, expected: expected, point: point, marker: marker)
        prepareCursor(app, windowID: windowID, number: number, bounds: window.bounds, marker: marker, point: point)
        try targetedPointer.click(app: app, windowNumber: number, bounds: window.bounds, point: point, action: action, modifiers: modifiers,
            activationPoint: activationPoint, marker: marker, activationMode: activationMode, guardedSend: admission.guardedSend(guardedInputSend), validate: admission.validating(validate))
    }
    func targetedHoldInput(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot, point: NativePoint, action: String, holdMS: Int, marker: Int64, admission: NativePointerAdmission) throws {
        try admission.validateAuthority()
        guard ["hold", "right_hold"].contains(action), (1...5000).contains(holdMS) else { throw NativeFailure("native_hold_duration_invalid") }
        let (window, number, activationPoint, activationMode, validate) = try targetedInputContext(app, windowID: windowID, expected: expected, point: point, marker: marker)
        prepareCursor(app, windowID: windowID, number: number, bounds: window.bounds, marker: marker, point: point)
        try targetedPointer.hold(app: app, windowNumber: number, bounds: window.bounds, point: point, action: action,
            holdMS: holdMS, activationPoint: activationPoint, marker: marker, schedule: retainedHoldSchedule(), activationMode: activationMode, guardedSend: admission.guardedSend(guardedInputSend), validate: admission.validating(validate))
    }
    func targetedScrollInput(_ app: NativeAppIdentity, windowID: String, expected: NativeWindowGeometrySnapshot, point: NativePoint, delta: NativeWheelDelta, marker: Int64, admission: NativePointerAdmission) throws {
        try admission.validateAuthority()
        guard delta.valid else { throw NativeFailure("native_scroll_delta_invalid") }
        let (window, number, activationPoint, activationMode, validate) = try targetedInputContext(app, windowID: windowID, expected: expected, point: point, marker: marker)
        prepareCursor(app, windowID: windowID, number: number, bounds: window.bounds, marker: marker, point: point)
        try targetedPointer.scroll(app: app, windowNumber: number, bounds: window.bounds, point: point,
            deltaX: delta.x, deltaY: delta.y, activationPoint: activationPoint, marker: marker, activationMode: activationMode,
            guardedSend: admission.guardedSend(guardedInputSend), validate: admission.validating(validate))
    }
    func pointIsVisible(_ app: NativeAppIdentity, windowID: String, point: NativePoint) -> Bool {
        guard let selected = try? window(app, id: windowID), let expected = selected.cgWindowID,
              let rows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] else { return false }
        for row in rows {
            guard (row[kCGWindowAlpha as String] as? NSNumber)?.doubleValue ?? 1 > 0,
                  let bounds = row[kCGWindowBounds as String] as? NSDictionary,
                  let rectangle = CGRect(dictionaryRepresentation: bounds), rectangle.contains(CGPoint(x: point.x, y: point.y)) else { continue }
            return (row[kCGWindowOwnerPID as String] as? NSNumber)?.int32Value == app.pid
                && (row[kCGWindowNumber as String] as? NSNumber)?.uint32Value == expected
        }
        return false
    }
    @available(macOS 14, *)
    private func captureLayoutDiagnostic(_ app: NativeAppIdentity, windowID: String,
                                         original: NativeWindowIdentityDiagnostic) -> NativeCaptureLayoutDiagnostic? {
        guard original.state == .boundsMismatch, let number = original.candidateWindowID,
              let logical = original.logicalBounds, let compositor = original.compositorBounds,
              logical.finite, compositor.finite, screenAllowed, matches(app),
              let binding = windowBindings.entry(windowID), binding.owner == app,
              let revision = mappingVersion(windowID) else { return nil }
        let started = ProcessInfo.processInfo.systemUptime
        let outerDeadline = started + 2
        let deadline = DispatchTime.now() + 2
        let reply = NativeCaptureMailbox<SCShareableContent>(deadline: deadline)
        SCShareableContent.getExcludingDesktopWindows(true, onScreenWindowsOnly: false) { content, error in
            reply.publish(error == nil ? content : nil)
        }
        func diagnostic(_ state: String) -> NativeCaptureLayoutDiagnostic {
            NativeCaptureLayoutDiagnostic(state: state, elapsedSeconds: max(0, ProcessInfo.processInfo.systemUptime - started))
        }
        guard let content = reply.wait(until: deadline) else { return diagnostic("unavailable") }
        let candidates = content.windows.filter { $0.windowID == number }
        guard candidates.count == 1, let window = candidates.first,
              window.owningApplication?.processID == app.pid else { return diagnostic("identityChanged") }
        let filter = SCContentFilter(desktopIndependentWindow: window)
        func rectangle(_ frame: CGRect) -> NativeRect {
            NativeRect(x: frame.minX, y: frame.minY, width: frame.width, height: frame.height)
        }
        let frame = rectangle(window.frame), contentRect = rectangle(filter.contentRect)
        let scale = Double(filter.pointPixelScale)
        guard frame.finite, contentRect.finite, scale.isFinite, scale > 0, scale <= 8 else {
            return diagnostic("unavailable")
        }
        // These are metadata reads, not an atomic compositor snapshot. A
        // changed binding/process/frame cannot become a positive observation.
        guard screenAllowed, matches(app), mappingVersion(windowID) == revision,
              let current = windowBindings.entry(windowID), current.owner == app,
              CFEqual(current.element, binding.element),
              ProcessInfo.processInfo.systemUptime < outerDeadline,
              let fresh = try? windowIdentitySnapshot(app, windowID: windowID, outerDeadline: outerDeadline),
              fresh.identity.diagnostic.state == .boundsMismatch,
              fresh.identity.diagnostic.candidateWindowID == number,
              fresh.bounds == logical, fresh.identity.diagnostic.compositorBounds == compositor,
              ProcessInfo.processInfo.systemUptime - started < 2 else { return diagnostic("identityChanged") }
        var result = diagnostic("observed")
        result.scWindowID = number; result.scOwnerPID = app.pid; result.scFrame = frame
        result.scIsActive = window.isActive; result.scIsOnScreen = window.isOnScreen
        result.filterContentRect = contentRect; result.filterPointPixelScale = scale
        if #available(macOS 15.2, *) {
            result.filterWindowCount = filter.includedWindows.count
            result.filterHasOnlyCandidateWindow = filter.includedWindows.count == 1
                && filter.includedWindows[0].windowID == number
                && filter.includedWindows[0].owningApplication?.processID == app.pid
        }
        return result
    }
    func captureInspection(_ app: NativeAppIdentity, windowID: String) throws -> NativeCapture {
        guard screenAllowed, matches(app) else { throw NativeFailure("screen_recording_required") }
        guard #available(macOS 15.2, *) else { throw NativeFailure("native_capture_inspection_unsupported") }
        let started = ProcessInfo.processInfo.systemUptime, outerDeadline = ProcessInfo.processInfo.systemUptime + 5
        guard let binding = windowBindings.entry(windowID), binding.owner == app,
              let revision = mappingVersion(windowID) else { throw NativeFailure("native_window_identity_changed") }
        let initial = try windowIdentitySnapshot(app, windowID: windowID, outerDeadline: outerDeadline)
        let identity = initial.identity.diagnostic
        guard identity.provenance == .privateAXWindowID,
              [.mappedDirect, .boundsMismatch].contains(identity.state),
              let number = identity.candidateWindowID, let compositor = identity.compositorBounds,
              identity.logicalBounds == initial.bounds else { throw NativeFailure("native_capture_inspection_requires_exact_identity") }
        func validate() throws {
            guard screenAllowed, matches(app), mappingVersion(windowID) == revision,
                  let current = windowBindings.entry(windowID), current.owner == app,
                  CFEqual(current.element, binding.element), ProcessInfo.processInfo.systemUptime < outerDeadline else {
                throw NativeFailure("native_window_identity_changed")
            }
            let fresh = try windowIdentitySnapshot(app, windowID: windowID, outerDeadline: outerDeadline)
            guard fresh.identity.diagnostic.provenance == .privateAXWindowID,
                  [.mappedDirect, .boundsMismatch].contains(fresh.identity.diagnostic.state),
                  fresh.identity.diagnostic.candidateWindowID == number,
                  fresh.bounds == initial.bounds,
                  fresh.identity.diagnostic.compositorBounds == compositor else { throw NativeFailure("native_window_identity_changed") }
        }
        let remaining = outerDeadline - ProcessInfo.processInfo.systemUptime
        guard remaining > 0 else { throw NativeFailure("native_capture_unavailable") }
        let deadline = DispatchTime.now() + remaining
        let contentReply = NativeCaptureMailbox<SCShareableContent>(deadline: deadline)
        SCShareableContent.getExcludingDesktopWindows(true, onScreenWindowsOnly: false) { content, error in
            contentReply.publish(error == nil ? content : nil)
        }
        guard let content = contentReply.wait(until: deadline) else { throw NativeFailure("native_capture_unavailable") }
        let candidates = content.windows.filter { $0.windowID == number }
        guard candidates.count == 1, let window = candidates.first,
              window.owningApplication?.processID == app.pid else { throw NativeFailure("native_capture_inspection_scope_unverified") }
        let filter = SCContentFilter(desktopIndependentWindow: window)
        guard filter.includedWindows.count == 1, filter.includedWindows[0].windowID == number,
              filter.includedWindows[0].owningApplication?.processID == app.pid else {
            throw NativeFailure("native_capture_inspection_scope_unverified")
        }
        func rectangle(_ r: CGRect) -> NativeRect {
            NativeRect(x: r.minX, y: r.minY, width: r.width, height: r.height)
        }
        let frame = rectangle(window.frame), contentRect = rectangle(filter.contentRect)
        let scale = Double(filter.pointPixelScale)
        guard frame.finite, contentRect.finite, scale.isFinite, scale > 0, scale <= 8 else {
            throw NativeFailure("native_capture_inspection_scope_unverified")
        }
        let originalWidth = initial.bounds.width * scale, originalHeight = initial.bounds.height * scale
        guard originalWidth.isFinite, originalHeight.isFinite, originalWidth > 0, originalHeight > 0 else {
            throw NativeFailure("native_capture_inspection_scope_unverified")
        }
        let reduction = min(1, 4096 / max(originalWidth, originalHeight))
        let config = SCStreamConfiguration()
        config.width = max(1, Int(originalWidth * reduction)); config.height = max(1, Int(originalHeight * reduction))
        config.showsCursor = false; config.includeChildWindows = false
        config.ignoreGlobalClipSingleWindow = true; config.ignoreShadowsSingleWindow = true
        // No source crop is supplied. Requested output size is not a verified
        // content transform; this image cannot authorize pointer input.
        try validate()
        guard DispatchTime.now() < deadline else { throw NativeFailure("native_capture_unavailable") }
        let imageReply = NativeCaptureMailbox<CGImage>(deadline: deadline)
        SCScreenshotManager.captureImage(contentFilter: filter, configuration: config) { image, error in
            imageReply.publish(error == nil ? image : nil)
        }
        guard let image = imageReply.wait(until: deadline) else { throw NativeFailure("native_capture_unavailable") }
        guard image.width > 0, image.height > 0, image.width <= 16777216 / image.height else {
            throw NativeFailure("native_image_limit")
        }
        guard let data = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:]) else {
            throw NativeFailure("native_capture_unavailable")
        }
        guard data.count <= 8388608 else { throw NativeFailure("native_image_limit") }
        try validate()
        guard ProcessInfo.processInfo.systemUptime - started < 5 else { throw NativeFailure("native_capture_unavailable") }
        var result = NativeCapture(data: data, width: image.width, height: image.height, displayScale: scale, cgWindowID: number)
        result.inspection = NativeCaptureInspection(windowID: number, ownerPID: app.pid,
            logicalBounds: initial.bounds, compositorBounds: compositor, scFrame: frame,
            filterContentRect: contentRect, filterPointPixelScale: scale, filterWindowCount: 1,
            filterHasOnlyCandidateWindow: true, ignoreGlobalClipSingleWindow: true, ignoreShadowsSingleWindow: true)
        return result
    }
    func capture(_ app: NativeAppIdentity, windowID: String, source: NativeWindow) throws -> NativeCapture {
        guard screenAllowed, matches(app) else { throw NativeFailure("screen_recording_required") }
        guard #available(macOS 14, *) else { throw NativeFailure("native_capture_requires_macos_14") }
        guard source.id == windowID else { throw NativeFailure("native_claim_target_mismatch") }
        let observed = try captureWindowState(app, source: source)
        guard let identifier = observed.cgWindowID else {
            if var diagnostic = observed.identityDiagnostic {
                diagnostic.captureLayout = captureLayoutDiagnostic(app, windowID: windowID, original: diagnostic)
                throw diagnostic.failure
            }
            throw NativeFailure("native_window_identity_unavailable")
        }
        guard let binding = windowBindings.entry(windowID), binding.owner == app,
              let revision = mappingVersion(windowID) else { throw NativeFailure("native_window_identity_changed") }
        func validateCaptureIdentity() throws {
            guard self.screenAllowed, self.matches(app), self.mappingVersion(windowID) == revision,
                  let current = self.windowBindings.entry(windowID), current.owner == app,
                  CFEqual(current.element, binding.element) else { throw NativeFailure("native_window_identity_changed") }
            let fresh = try self.windowIdentitySnapshot(app, windowID: windowID)
            guard let freshID = fresh.identity.windowID else { throw fresh.identity.diagnostic.failure }
            try NativeWindowGeometrySnapshot(windowID: windowID, bounds: observed.bounds, cgWindowID: identifier).requireMatch(
                NativeWindowGeometrySnapshot(windowID: windowID, bounds: fresh.bounds, cgWindowID: freshID))
            let privacy = try self.captureWindowState(app, source: source)
            try NativeWindowGeometrySnapshot(windowID: windowID, bounds: observed.bounds, cgWindowID: identifier).requireMatch(
                NativeWindowGeometrySnapshot(windowID: windowID, bounds: privacy.bounds, cgWindowID: privacy.cgWindowID))
            guard self.screenAllowed, self.mappingVersion(windowID) == revision else { throw NativeFailure("native_window_identity_changed") }
        }
        let deadline = DispatchTime.now() + 5
        let contentReply = NativeCaptureMailbox<SCShareableContent>(deadline: deadline)
        SCShareableContent.getExcludingDesktopWindows(true, onScreenWindowsOnly: false) { content, error in
            contentReply.publish(error == nil ? content : nil)
        }
        guard let content = contentReply.wait(until: deadline),
              let window = content.windows.first(where: { $0.windowID == identifier && $0.owningApplication?.processID == app.pid }) else {
            throw NativeFailure("native_capture_unavailable")
        }
        let filter = SCContentFilter(desktopIndependentWindow: window)
        let sheet = observed.attachedSheetParentID != nil
        var scale = displays().first(where: { $0.bounds.contains(NativePoint(x: window.frame.midX, y: window.frame.midY)) })?.scale ?? 1
        if sheet {
            guard #available(macOS 15.2, *) else { throw NativeFailure("native_attached_sheet_capture_unverified") }
            let frame = NativeRect(x: window.frame.minX, y: window.frame.minY, width: window.frame.width, height: window.frame.height)
            let rect = filter.contentRect
            let contentRect = NativeRect(x: rect.minX, y: rect.minY, width: rect.width, height: rect.height)
            scale = Double(filter.pointPixelScale)
            let included = filter.includedWindows
            guard included.allSatisfy({ $0.owningApplication?.processID == app.pid }),
                  NativeAttachedSheetPolicy.captureLayout(bounds: observed.bounds, frame: frame, content: contentRect,
                    scale: scale, candidates: content.windows.filter({ $0.windowID == identifier }).count,
                    included: included.map(\.windowID), number: identifier) else {
                throw NativeFailure("native_attached_sheet_capture_unverified")
            }
        }
        let originalWidth = max(1, window.frame.width * scale), originalHeight = max(1, window.frame.height * scale)
        let reduction = min(1, 4096 / max(originalWidth, originalHeight))
        let width = max(1, Int(originalWidth * reduction)), height = max(1, Int(originalHeight * reduction))
        // Both validations run on the waiting operation's serialized executor.
        try validateCaptureIdentity()
        guard DispatchTime.now() < deadline else { throw NativeFailure("native_capture_unavailable") }
        let imageReply = NativeCaptureMailbox<CGImage>(deadline: deadline)
        if #available(macOS 26.0, *) {
            let config = SCScreenshotConfiguration()
            config.width = width; config.height = height
            config.showsCursor = false; config.includeChildWindows = false
            if sheet { config.ignoreShadows = true; config.ignoreClipping = true }
            config.dynamicRange = .sdr; config.fileURL = nil
            SCScreenshotManager.captureScreenshot(contentFilter: filter, configuration: config) { output, error in
                imageReply.publish(error == nil ? output?.sdrImage : nil)
            }
        } else {
            let config = SCStreamConfiguration()
            config.width = width; config.height = height; config.showsCursor = false
            if sheet {
                if #available(macOS 14.2, *) { config.includeChildWindows = false }
                config.ignoreShadowsSingleWindow = true; config.ignoreGlobalClipSingleWindow = true
            }
            SCScreenshotManager.captureImage(contentFilter: filter, configuration: config) { image, error in
                imageReply.publish(error == nil ? image : nil)
            }
        }
        guard let image = imageReply.wait(until: deadline),
              let data = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:]) else { throw NativeFailure("native_capture_unavailable") }
        if sheet, image.width != width || image.height != height { throw NativeFailure("native_attached_sheet_capture_unverified") }
        try validateCaptureIdentity()
        return NativeCapture(data: data, width: image.width, height: image.height, displayScale: scale, cgWindowID: identifier)
    }
    func capture(_ app: NativeAppIdentity, windowID: String) throws -> NativeCapture {
        let source = try scopedWindowState(app, id: windowID)
        return try capture(app, windowID: windowID, source: source)
    }
    func displays() -> [NativeDisplay] {
        NSScreen.screens.compactMap { screen in
            guard let number = screen.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber else { return nil }
            let id = number.uint32Value, bounds = CGDisplayBounds(id)
            return NativeDisplay(id: id, bounds: NativeRect(x: bounds.minX, y: bounds.minY, width: bounds.width, height: bounds.height), scale: screen.backingScaleFactor)
        }
    }
    func clipboard() throws -> NativeClipboard {
        if #available(macOS 15.4, *), NSPasteboard.general.accessBehavior != .alwaysAllow { throw NativeFailure("clipboard_local_approval_required") }
        let pasteboard = NSPasteboard.general, before = pasteboard.changeCount
        var bytes = 0, items: [[String: Data]] = []
        guard let sourceItems = pasteboard.pasteboardItems else { throw NativeFailure("clipboard_snapshot_unavailable") }
        for item in sourceItems {
            var entry: [String: Data] = [:]
            for type in item.types {
                guard let data = item.data(forType: type) else { throw NativeFailure("clipboard_representation_unavailable") }
                bytes += data.count
                guard bytes <= 8388608, items.count < 100, entry.count < 100 else { throw NativeFailure("clipboard_snapshot_limit") }
                entry[type.rawValue] = data
            }
            items.append(entry)
        }
        guard pasteboard.changeCount == before else { throw NativeFailure("clipboard_changed") }
        return NativeClipboard(changeCount: before, items: items)
    }
    func writeClipboard(_ items: [[String: Data]], expectedChangeCount: Int) throws -> NativeClipboard {
        if #available(macOS 15.4, *), NSPasteboard.general.accessBehavior != .alwaysAllow {
            throw NativeFailure("clipboard_local_approval_required")
        }
        let objects: [NSPasteboardItem] = try items.map { fields in
            let item = NSPasteboardItem()
            for (type, data) in fields {
                guard item.setData(data, forType: NSPasteboard.PasteboardType(type)) else {
                    throw NativeFailure("clipboard_preparation_failed")
                }
            }
            return item
        }
        return try NativeClipboardMutation.write(items, expectedChangeCount: expectedChangeCount,
            currentCount: { NSPasteboard.general.changeCount }, clear: { NSPasteboard.general.clearContents() },
            write: { NSPasteboard.general.writeObjects(objects) }, readback: { try self.clipboard() })
    }
}
