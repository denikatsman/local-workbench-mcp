import AppKit
import SwiftUI
import UniformTypeIdentifiers
import CryptoKit
import Darwin

/// Only verified absence may admit a new journaled operation. Retained but
/// unreadable or malformed history preserves the original outcome uncertainty.
enum NativeReceiptAdmission {
    static func replay(url: URL, requestID: String, payloadHash: String) throws -> [String: Any]? {
        let retained: Data?
        do {
            retained = try NativeProviderRecovery.readNativeReceipt(
                operationReceiptsRoot: url.deletingLastPathComponent(), operationID: requestID)
        } catch { throw NativeFailure("native_receipt_unavailable", "unknown") }
        guard let data = retained else { return nil }
        guard let old = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let savedHash = old["payload_sha256"] as? String,
              savedHash.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else {
            throw NativeFailure("native_receipt_unavailable", "unknown")
        }
        guard savedHash == payloadHash else { throw NativeFailure("native_request_id_conflict") }
        guard old["state"] as? String == "completed", var reply = old["result"] as? [String: Any] else {
            throw NativeFailure("native_outcome_unknown", "unknown")
        }
        reply["replayed"] = true
        return reply
    }
}

final class NativeOperationCentre: ObservableObject {
    #if LOCAL_WORKBENCH_POINTER_ACCEPTANCE
    private var fixturePointerProbe: NativeFixturePointerProbe?
    #endif
    @Published var selectedPath = ""
    @Published var message = "Choose access above, then enable app access."
    @Published var allowControl = false
    @Published var allowCapture = false
    @Published var allowClipboard = false
    @Published var seconds = 120
    @Published var rows: [[String: Any]] = []
    @Published var clipboardRows: [[String: Any]] = []
    @Published var trustedControl = true
    @Published var trustedCapture = true
    @Published var trustedClipboard = false
    @Published var trustState = "not_configured"
    @Published var stoppedApps: [String] = []
    let queue = DispatchQueue(label: "workbench-native-operations")
    let engine: NativeOperationEngine
    let directory: URL
    let trustStore: NativeInteractionTrustStore
    let terminalInput = NativeTerminalInput()
    var bridge: PermissionSocket?
    var controlBridge: PermissionSocket?
    let cancellation = NativeCancellation()
    private let controlQueue = DispatchQueue(label:"workbench-native-control")
    var restartPending: (() -> Bool)?
    private var timer: Timer?
    private let activityLock = NSLock()
    private var cachedActiveIDs: [String] = []
    private var claimBundles: [String: String] = [:]
    private var grantBlocked = false
    private var grantRevision = UUID()
    private var pendingGrantAdmissions = 0
    // All accesses on queue. Suspended holds keep cancellation, claim/session
    // activity and server-drain pins until original cleanup + durable terminal.
    private var heldOperations = Set<String>()
    private var heldClaims = Set<String>()
    private var heldTargets: [String: (app: NativeAppIdentity, windowID: String, familyID: String)] = [:]
    private var durableHeldTerminals = Set<String>()
    private var settledProviderReleases: [String: () -> Void] = [:]
    private var unsettledProviderOperations = Set<String>()
    private var settledHeldWaiters: [String: () -> Void] = [:]
    private var allowsDeferredProviderIO = false
    private var heldResourceWaiters: [() -> Void] = []
    private var heldDrainWaiters: [() -> Void] = []
    private var draining = false
    private var providerPending: [Int32: (NativeProviderPreparation, NativeProcessSnapshot)] = [:]
    private let providerProcess = NativeSystemProcessIdentity(metadata: { _ in nil })
    private lazy var provider = NativeProviderRuntime(authority: { [weak self] owner, window, clipboard in
        guard let self = self else { throw NativeProviderHostFailure("native_controller_unavailable") }
        try self.verifyProviderOwner(owner, cgWindow: window, clipboard: clipboard)
    }, checkCancelled: { [weak self] id in
        guard let self = self else { throw NativeProviderHostFailure("native_controller_unavailable") }
        try self.cancellation.check(id)
    }, saveRecovery: { [weak self] id, record in
        guard let self = self else { throw NativeProviderHostFailure("native_controller_unavailable") }
        let url = try self.receiptURL(id)
        guard let data = try NativeProviderRecovery.readNativeReceipt(operationReceiptsRoot: url.deletingLastPathComponent(), operationID: id),
              let pending = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw NativeProviderHostFailure("native_provider_receipt_owner_mismatch", effectState: "unknown")
        }
        let bound = try NativeProviderRecovery.bindPendingContext(record: record, pending: pending, operationID: id)
        try writePermissionState(JSONSerialization.data(withJSONObject: bound, options: [.sortedKeys]),
            to: url.appendingPathExtension("provider.json"))
    })

    private lazy var electron = NativeElectronController(directory: directory, metadata: { [weak self] app, owner in
        guard let self = self, let driver = self.engine.driver as? NativeAXDriver else {
            throw NativeProviderHostFailure("native_controller_unavailable")
        }
        let metadata = try driver.electronWindowMetadata(app, windowID: owner.window_id)
        guard let number = metadata["cg_window_id"] as? UInt32 else { throw NativeFailure("native_provider_window_changed") }
        try self.verifyProviderOwner(owner, cgWindow: number, clipboard: false)
        return metadata
    }, authority: { [weak self] owner, number, clipboard in
        guard let self = self else { throw NativeProviderHostFailure("native_controller_unavailable") }
        try self.verifyProviderOwner(owner, cgWindow: number, clipboard: clipboard)
    }, cancelled: { [weak self] id in
        guard let self = self else { throw NativeProviderHostFailure("native_controller_unavailable") }
        try self.cancellation.check(id)
    }, recovery: { [weak self] id, record in
        guard let self = self else { throw NativeProviderHostFailure("native_controller_unavailable") }
        try writePermissionState(JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]),
            to: self.receiptURL(id).appendingPathExtension("provider.json"))
    })

    init(directory: URL, operationEngine: NativeOperationEngine? = nil) {
        self.directory = directory
        let owner = permissionOwner()
        trustStore = NativeInteractionTrustStore(url: directory.appendingPathComponent("native-operations/installation-trust.json"),
            signingIdentifier: owner["signing_identifier"] as? String ?? "unknown",
            teamID: owner["team_id"] as? String ?? "unsigned", write: writePermissionState)
        engine = operationEngine ?? NativeOperationEngine(driver: NativeAXDriver(monitor: NativeInputMonitor()))
        engine.installationTrust = trustStore.policy
        trustState = trustStore.failure ?? trustStore.policy?.state ?? "not_configured"
        if let policy = trustStore.policy {
            trustedControl = policy.capabilities.contains("native.control")
            trustedCapture = policy.capabilities.contains("native.capture")
            trustedClipboard = policy.capabilities.contains("native.clipboard")
            stoppedApps = policy.blockedApps.sorted()
            message = policy.state == "valid" ? "App access enabled. Agents acquire a fresh window for each task." : "App access is stopped. Enable it here to resume."
        }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.refresh() }
    }
    func start() {
        // Initialize on the app's startup lane, before any control callbacks.
        _ = provider; _ = electron
        do {
            let channel = try PermissionSocket(methods: ["operation", "capture_page", "release_result_payload", "terminal_prompt", "terminal_prompt_status"], queue: queue,
                                               environmentPrefix: "LOCAL_WORKBENCH_AUTOMATION")
            channel.deferredHandler = { [weak self] packet, completion in
                guard let self = self else { completion(["ok": false]); return }
                self.handleDeferred(packet, completion: completion)
            }
            channel.start(); bridge = channel
            let controls = try PermissionSocket(methods:["cancel_operation"],queue:controlQueue,environmentPrefix:"LOCAL_WORKBENCH_AUTOMATION_CONTROL")
            controls.handler = { [weak self] packet in
                guard let self = self else { return ["ok":false] }
                do {
                    let operationID = packet["operation_id"] as? String ?? ""
                    let result = try self.cancellation.cancel(requestID: operationID,
                        claimID:packet["claim_id"] as? String ?? "",ownerSession:packet["owner_session"] as? String ?? "",
                        runtimeGeneration:packet["runtime_generation"] as? String ?? "")
                    self.provider.cancel(operationID: operationID)
                    self.electron.cancel(operation: operationID)
                    (self.engine.driver as? NativeAXDriver)?.invalidateCursor(operationID: operationID)
                    return result
                }
                catch let error as NativeFailure { return ["ok":false,"error":["code":error.code,"effect_state":error.effectState]] }
                catch { return ["ok":false,"error":["code":"native_cancel_failed","effect_state":"unknown"]] }
            }
            controls.start(); controlBridge = controls
        } catch { message = "Native app access is unavailable: \(error.localizedDescription)" }
    }
    func newRuntimeEnvironment() -> [String: String] {
        queue.sync {
            guard heldOperations.isEmpty else { return [:] }
            draining = false
            (engine.driver as? NativeAXDriver)?.invalidateCursor()
            (engine.driver as? NativeAXDriver)?.resetCursorDiagnostics()
            engine.suspendTrustedClaimsForNewRuntime(); cancellation.newRuntime(); publishActivity()
            provider.retire(); electron.retire()
            var environment = bridge?.newLaunch() ?? [:]
            let controls = controlQueue.sync { controlBridge?.newLaunch() ?? [:] }
            environment.merge(controls) { _, new in new }
            return environment
        }
    }
    func refresh() {
        queue.async { [weak self] in
            guard let self = self else { return }
            let snapshot = self.engine.status()
            let rows = snapshot["leases"] as? [[String: Any]] ?? []
            let clipboardRows = snapshot["clipboard_leases"] as? [[String: Any]] ?? []
            self.publishActivity()
            let stopped = self.trustStore.policy?.blockedApps.sorted() ?? []
            DispatchQueue.main.async { self.rows = rows; self.clipboardRows = clipboardRows; self.stoppedApps = stopped }
        }
    }
    private func publishActivity() {
        let ids = Array(Set(engine.activeIDs()).union(heldOperations))
        let bundles = Dictionary(uniqueKeysWithValues:engine.leases.values.filter { $0.trustRevision != nil }.map { ($0.id,$0.app.bundleID) })
        activityLock.lock(); cachedActiveIDs = ids; claimBundles = bundles; activityLock.unlock()
    }
    func activeIDs() -> [String] {
        // Acquisition may hold this lock while AX calls wait for the app's
        // main thread. A poll must stay responsive and conservatively busy.
        guard activityLock.try() else { return ["native-admission-busy"] }
        let ids = cachedActiveIDs, pending = pendingGrantAdmissions > 0
        activityLock.unlock()
        if pending { return ["native-admission-busy"] }
        return ids + terminalInput.activeIDs() + electron.activeIDs
    }
    // Global diagnostic sample of the existing conservative activity accounting.
    // Claim state and terminal receipts alone do not settle held cleanup pins.
    private func activitySnapshot() -> [String: Any] {
        let started = ProcessInfo.processInfo.systemUptime
        let ids = Array(Set(activeIDs())).sorted()
        let unknown = ids.contains("native-admission-busy")
        return ["version": 1, "scope": "global_native_activity", "atomic": false,
                "state": unknown ? "unknown_busy" : (ids.isEmpty ? "sampled_empty" : "busy"),
                "busy": !ids.isEmpty, "active_ids": ids, "reported_id_count": ids.count,
                "ids_complete": !unknown, "ids_truncated": false,
                "sample_started_uptime": started,
                "sample_finished_uptime": ProcessInfo.processInfo.systemUptime,
                "authority": "diagnostic_only"]
    }
    func finishServer(_ completion: @escaping () -> Void) {
        // Reject even old sockets whose packet reaches this queue after the
        // barrier. Already admitted work gets its normal identity-bound cleanup.
        bridge?.suspend()
        controlBridge?.suspend()
        controlQueue.async { [weak self] in
            guard let self = self else { return }
            self.cancellation.beginDrain()
            self.provider.cancel(); self.electron.cancel()
            self.queue.async {
                self.draining = true
                let finish = {
                    self.provider.retire(); self.electron.retire()
                    self.controlQueue.async { DispatchQueue.main.async(execute: completion) }
                }
                if self.heldOperations.isEmpty { finish() }
                else { self.heldDrainWaiters.append(finish) }
            }
        }
    }
    func blockGrants(_ blocked: Bool) {
        activityLock.lock(); defer { activityLock.unlock() }
        if grantBlocked != blocked { grantBlocked = blocked; grantRevision = UUID() }
    }
    private func beginGrantAdmission() throws -> UUID {
        activityLock.lock(); defer { activityLock.unlock() }
        guard !grantBlocked else { throw NativeFailure("native_restart_pending") }
        pendingGrantAdmissions += 1
        return grantRevision
    }
    private func validateGrantAdmission(_ revision: UUID) throws {
        activityLock.lock(); defer { activityLock.unlock() }
        guard !grantBlocked, grantRevision == revision else { throw NativeFailure("native_restart_pending") }
    }
    private func finishGrantAdmission() {
        // Publish the resulting ownership before removing the pending fence;
        // otherwise a restart poll could briefly mistake a new claim for idle.
        publishActivity()
        activityLock.lock(); pendingGrantAdmissions -= 1; activityLock.unlock()
    }
    private func withGrantAdmission<T>(_ body: (UUID) throws -> T) throws -> T {
        let revision = try beginGrantAdmission()
        defer { finishGrantAdmission() }
        return try body(revision)
    }
    private func validateGrantedLease(_ result: [String: Any], existing: Set<String>,
                                      revision: UUID, bundle: String? = nil) throws {
        do {
            try validateGrantAdmission(revision)
            if let bundle = bundle {
                try cancellation.admitBundle(bundle)
                if let id = result["lease_id"] as? String { try cancellation.admit(id) }
            }
        } catch {
            // A repeated same-owner acquire can return an older claim. Reject
            // this admission without revoking unrelated pre-existing work.
            if let id = result["lease_id"] as? String, !existing.contains(id) {
                engine.revoke(id, reason: "native_admission_changed")
            }
            throw error
        }
    }
    func configureTrust() {
        guard restartPending?() != true else { message = "Finish or cancel the pending restart first."; return }
        var scopes: Set<String> = ["native.discover", "native.launch", "native.observe"]
        if trustedControl { scopes.insert("native.control") }
        if trustedCapture { scopes.insert("native.capture") }
        if trustedClipboard { scopes.insert("native.clipboard") }
        let enableRevision = cancellation.localEnableRevision()
        queue.async { [weak self] in
            guard let self = self else { return }
            do {
                // An already admitted local configuration may finish; its
                // pending fence keeps restart waiting until publication.
                try self.withGrantAdmission { _ in
                    try self.trustStore.configureLocally(capabilities: scopes)
                    self.engine.installationTrust = self.trustStore.policy
                    self.engine.expire()
                    guard self.cancellation.enableLocally(ifUnchanged: enableRevision) else {
                        throw NativeFailure("native_access_stopped")
                    }
                }
                DispatchQueue.main.async { self.trustState = "valid"; self.message = "App access enabled. Agents can find and claim windows without sharing each app again."; self.refresh() }
            } catch let failure as NativeFailure where failure.code == "native_access_stopped" {
                DispatchQueue.main.async { self.message = "A newer Stop or shutdown kept app access stopped." }
            } catch { DispatchQueue.main.async { self.message = "App access could not be saved. Existing trust and receipts were preserved." } }
        }
    }
    func stopTrustedAccess() {
        cancellation.cancelAll()
        provider.cancel(); electron.cancel()
        (engine.driver as? NativeAXDriver)?.invalidateCursor()
        queue.async { [weak self] in
            guard let self = self else { return }
            self.provider.retire(); self.electron.retire()
            do {
                try self.trustStore.stopLocally(); self.engine.installationTrust = self.trustStore.policy; self.engine.expire()
                DispatchQueue.main.async { self.trustState = "revoked"; self.message = "App access stopped. It stays stopped after reconnect or restart until you enable it here."; self.refresh() }
            } catch {
                self.engine.installationTrust = self.trustStore.policy; self.engine.expire()
                DispatchQueue.main.async { self.trustState = "revoked"; self.message = "App access is stopped now. Stop could not be saved for restart; keep Workbench running and check available storage."; self.refresh() }
            }
        }
    }
    func resumeStoppedApp(_ bundleID: String) {
        queue.async { [weak self] in
            guard let self = self else { return }
            do {
                try self.trustStore.resumeAppLocally(bundleID); self.engine.installationTrust = self.trustStore.policy
                self.cancellation.resumeBundleLocally(bundleID)
                DispatchQueue.main.async { self.message = "App access resumed for this app. A fresh target claim is required."; self.refresh() }
            } catch { DispatchQueue.main.async { self.message = "App access could not be resumed." } }
        }
    }
    func choose() {
        let panel = NSOpenPanel()
        panel.title = "Choose the app Workbench may inspect"; panel.prompt = "Use this app"
        panel.allowedContentTypes = [.application]; panel.canChooseFiles = true; panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url { selectedPath = url.path; message = "Choose access, then share the selected app." }
    }
    func grant() {
        guard restartPending?() != true else { message = "Finish or cancel the pending restart before sharing another app."; return }
        guard let bundle = Bundle(path: selectedPath), let identifier = bundle.bundleIdentifier,
              let running = NSRunningApplication.runningApplications(withBundleIdentifier: identifier).first(where: { $0.bundleURL?.path == selectedPath }),
              let driver = engine.driver as? NativeAXDriver, let app = try? driver.identify(running) else {
            message = "Open the selected app, then share it here."; return
        }
        if allowControl { running.activate(options: []) }
        let control = allowControl, capture = allowCapture, clipboard = allowClipboard, lifetime = seconds
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            guard let self = self, self.restartPending?() != true else { return }
            self.queue.async {
                do {
                    try self.withGrantAdmission { revision in
                        let existing = Set(self.engine.leases.keys)
                        let result = try self.engine.grantLocally(app: app, seconds: lifetime, control: control, capture: capture, clipboard: clipboard)
                        try self.validateGrantedLease(["lease_id": result], existing: existing, revision: revision)
                    }
                    DispatchQueue.main.async { self.message = "App shared. Human input or a focus change ends control access."; self.refresh() }
                } catch let failure as NativeFailure {
                    let instructions: [String: String] = ["accessibility_required": "Enable Accessibility in Permissions & Readiness first.",
                        "input_monitoring_required": "Enable Input Monitoring, then reopen Workbench before sharing control access.",
                        "screen_recording_required": "Enable Screen Recording in Permissions & Readiness first.",
                        "selected_app_not_frontmost": "Bring the selected app to the front and share control again.",
                        "clipboard_local_approval_required": "Prepare clipboard access in Permissions & Readiness first."]
                    DispatchQueue.main.async { self.message = instructions[failure.code] ?? "The selected app could not be shared. Check that it is running and try again." }
                } catch { DispatchQueue.main.async { self.message = "The selected app could not be shared." } }
            }
        }
    }
    func revoke(_ id: String) {
        activityLock.lock()
        let bundle = claimBundles[id]
        let claims = claimBundles.filter { $0.value == bundle }.map(\.key)
        activityLock.unlock()
        if let bundle = bundle { cancellation.stopBundle(bundle); for claim in claims { cancellation.cancelClaim(claim) } }
        else { cancellation.cancelClaim(id) }
        if let bundle = bundle { provider.cancel(bundleID: bundle); electron.cancel(bundle: bundle) }
        else { provider.cancel(claimID: id); electron.cancel(claim: id) }
        if let bundle = bundle { (engine.driver as? NativeAXDriver)?.invalidateCursor(bundleID: bundle) }
        queue.async { [weak self] in
            guard let self = self else { return }
            for claim in claims + [id] { self.retireProviderClaim(claim) }
            do {
                if let lease = self.engine.leases[id], lease.trustRevision != nil {
                    try self.trustStore.stopLocally(appBundleID: lease.app.bundleID)
                    self.engine.installationTrust = self.trustStore.policy
                }
                self.engine.revoke(id); self.engine.expire()
                DispatchQueue.main.async { self.refresh() }
            } catch {
                self.engine.installationTrust = self.trustStore.policy; self.engine.revoke(id); self.engine.expire()
                DispatchQueue.main.async { self.message = "This app is stopped now. Stop could not be saved for restart; check available storage."; self.refresh() }
            }
        }
    }
    func finishClipboard(_ id: String, restore: Bool) {
        queue.async { [weak self] in
            guard let self = self else { return }
            do {
                let result = restore ? try self.engine.restoreClipboard(id) : try self.engine.releaseClipboard(id)
                self.publishActivity()
                DispatchQueue.main.async {
                    self.message = restore ? (result["restored"] as? Bool == true ? "Clipboard restored." : "Restoration could not be verified. The saved clipboard is retained.") : "Current clipboard kept."
                    self.refresh()
                }
            } catch {
                self.publishActivity()
                DispatchQueue.main.async {
                    self.message = "The clipboard choice could not be verified. Review the current recovery state before deciding; no automatic retry was attempted."
                    self.refresh()
                }
            }
        }
    }

    private func wheelDelta(_ packet: [String: Any]) throws -> NativeWheelDelta? {
        guard packet["control_action"] as? String == "scroll" else {
            guard packet["delta_x"] == nil, packet["delta_y"] == nil else { throw NativeFailure("native_scroll_delta_invalid") }
            return nil
        }
        func axis(_ key: String) throws -> Int32 {
            guard let raw = packet[key] else { return 0 }
            guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                  number.doubleValue.isFinite, number.doubleValue.rounded() == number.doubleValue,
                  abs(number.doubleValue) <= 2000 else { throw NativeFailure("native_scroll_delta_invalid") }
            return Int32(number.intValue)
        }
        let delta = try NativeWheelDelta(x: axis("delta_x"), y: axis("delta_y"))
        guard delta.valid else { throw NativeFailure("native_scroll_delta_invalid") }
        return delta
    }
    private func holdDuration(_ packet: [String: Any]) throws -> Int? {
        let holding = ["hold", "right_hold"].contains(packet["control_action"] as? String ?? "")
        guard holding else {
            guard packet["hold_ms"] == nil else { throw NativeFailure("native_hold_duration_invalid") }
            return nil
        }
        guard let raw = packet["hold_ms"] as? NSNumber, CFGetTypeID(raw) != CFBooleanGetTypeID(),
              raw.doubleValue.isFinite, raw.doubleValue.rounded() == raw.doubleValue,
              (1.0...5000.0).contains(raw.doubleValue) else { throw NativeFailure("native_hold_duration_invalid") }
        return raw.intValue
    }
    private func dragRequest(_ packet: [String: Any]) throws -> NativeDrag? {
        let dragging = packet["control_action"] as? String == "drag"
        guard dragging else {
            guard !["end_x", "end_y", "steps"].contains(where: { packet[$0] != nil && !(packet[$0] is NSNull) }) else {
                throw NativeFailure("native_drag_invalid")
            }
            return nil
        }
        var fixtureDrag = false
        #if LOCAL_WORKBENCH_POINTER_ACCEPTANCE
        fixtureDrag = packet["action"] as? String == "fixture_probe_point"
        #endif
        guard packet["action"] as? String == "point" || fixtureDrag,
              ["claim_id", "window_id", "observation_id"].allSatisfy({ (packet[$0] as? String)?.isEmpty == false }),
              !["lease_id", "hold_ms", "delta_x", "delta_y", "text", "selection_start", "selection_length",
                "control_id", "width", "height", "tree_base_revision", "app_identity", "app_path", "bundle_id",
                "clipboard_lease_id", "expected_change_count", "allow_control", "allow_capture", "allow_clipboard"]
                .contains(where: { packet[$0] != nil && !(packet[$0] is NSNull) }) else { throw NativeFailure("native_drag_invalid") }
        if fixtureDrag {
            guard let session = packet["fixture_session"] as? String, UUID(uuidString: session) != nil else {
                throw NativeFailure("native_drag_invalid")
            }
        } else if packet["fixture_session"] != nil && !(packet["fixture_session"] is NSNull) {
            throw NativeFailure("native_drag_invalid")
        }
        func coordinate(_ key: String) throws -> Double {
            guard let raw = packet[key] as? NSNumber, CFGetTypeID(raw) != CFBooleanGetTypeID(), raw.doubleValue.isFinite else {
                throw NativeFailure("native_drag_invalid")
            }
            return raw.doubleValue
        }
        guard let steps = packet["steps"] as? NSNumber, CFGetTypeID(steps) != CFBooleanGetTypeID(),
              ["c", "s", "i", "l", "q", "C", "S", "I", "L", "Q"].contains(String(cString: steps.objCType)),
              steps.doubleValue.isFinite, steps.doubleValue.rounded() == steps.doubleValue,
              (2...16).contains(steps.doubleValue) else { throw NativeFailure("native_drag_invalid") }
        let start = try NativePoint(x: coordinate("x"), y: coordinate("y"))
        let drag = try NativeDrag(end: NativePoint(x: coordinate("end_x"), y: coordinate("end_y")), steps: steps.intValue)
        _ = try drag.path(from: start)
        return drag
    }
    private func integer(_ packet: [String: Any], _ key: String) throws -> Int {
        guard let value = packet[key] as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(),
              value.doubleValue.isFinite, value.doubleValue == Double(value.intValue) else { throw NativeFailure("native_integer_required") }
        return value.intValue
    }
    private func receiptURL(_ requestID: String) throws -> URL {
        guard requestID.range(of: "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", options: .regularExpression) != nil else {
            throw NativeFailure("invalid_native_request_id")
        }
        let name = SHA256.hash(data: Data(requestID.utf8)).map { String(format: "%02x", $0) }.joined()
        return directory.appendingPathComponent("native-operations/receipts/" + name + ".json")
    }
    private func providerOwner(_ claimID: String, windowID: String) throws -> NativeProviderOwner {
        guard let lease = engine.leases[claimID], lease.trustRevision != nil,
              let session = lease.ownerSession, let runtime = lease.runtimeGeneration,
              let target = lease.targetGeneration, lease.windowID == windowID else {
            throw NativeFailure("native_provider_claim_required")
        }
        return NativeProviderOwner(claim_id: claimID, owner_session: session,
            runtime_generation: runtime, target_generation: target, window_id: windowID)
    }
    private func verifyProviderOwner(_ owner: NativeProviderOwner, cgWindow: UInt32, clipboard: Bool) throws {
        try engine.verifyOwner(owner.claim_id, ownerSession: owner.owner_session, runtimeGeneration: owner.runtime_generation)
        guard let lease = engine.leases[owner.claim_id], lease.state == "active", lease.trustRevision != nil,
              lease.targetGeneration == owner.target_generation, lease.windowID == owner.window_id,
              lease.control, engine.installationTrust?.permits("native.control", app: lease.app) == true,
              !clipboard || (lease.clipboard && engine.installationTrust?.permits("native.clipboard", app: lease.app) == true) else {
            throw NativeFailure("native_provider_capability_required")
        }
        try cancellation.admit(owner.claim_id); try cancellation.admitBundle(lease.app.bundleID)
        guard engine.driver.matches(lease.app), try engine.driver.window(lease.app, id: owner.window_id).cgWindowID == cgWindow else {
            throw NativeFailure("native_provider_window_changed")
        }
    }

    private func prepareRendererCapture(_ id: String, observationID: String, operationID: String) throws -> [String: Any]? {
        let (granted, observation) = try engine.captureObservation(id, observationID: observationID)
        // Legacy/unmanaged apps retain native capture. A remote capture cannot
        // create a managed registration, launch an app or obtain input rights.
        guard granted.trustRevision != nil, granted.app.bundleID == "com.microsoft.VSCode" else { return nil }
        let owner = try providerOwner(id, windowID: observation.window.id)
        func metadata() throws -> [String: Any] {
            try engine.verifyOwner(id, ownerSession: owner.owner_session, runtimeGeneration: owner.runtime_generation)
            let (current, observed) = try engine.captureObservation(id, observationID: observationID)
            guard current.windowID == owner.window_id, current.targetGeneration == owner.target_generation,
                  current.app == granted.app,
                  engine.installationTrust?.permits("native.capture", app: current.app) == true,
                  let driver = engine.driver as? NativeAXDriver else { throw NativeFailure("native_capture_not_granted") }
            try cancellation.check(operationID); try cancellation.admit(id); try cancellation.admitBundle(current.app.bundleID)
            let value = try driver.electronWindowMetadata(current.app, windowID: owner.window_id)
            guard value["cg_window_id"] as? UInt32 == observed.window.cgWindowID else {
                throw NativeFailure("native_window_identity_changed")
            }
            return value
        }
        guard engine.installationTrust?.permits("native.capture", app: granted.app) == true else {
            throw NativeFailure("native_capture_not_granted")
        }
        try cancellation.check(operationID); try cancellation.admit(id); try cancellation.admitBundle(granted.app.bundleID)
        do {
            guard try electron.restore(app: granted.app, matches: { self.engine.driver.matches(granted.app) }) else { return nil }
            let window = try metadata()
            guard let document = window["document_uri"] as? String, !document.isEmpty else {
                return ["status": "not_applicable", "reason": "renderer_document_mapping_unavailable", "frame_age_known": false]
            }
            return try electron.refreshForCapture(pid: granted.app.pid, owner: owner, window: window,
                operation: operationID, bundle: granted.app.bundleID, deadline: observation.freshnessStarted + 30) { message in
                    let current = try metadata()
                    guard current["cg_window_id"] as? UInt32 == message["cg_window_id"] as? UInt32,
                          current["native_title"] as? String == window["native_title"] as? String,
                          current["document_uri"] as? String == message["document_uri"] as? String else {
                        throw NativeFailure("native_capture_refresh_target_changed")
                    }
                }
        } catch let failure as NativeProviderHostFailure {
            throw NativeFailure(failure.code, failure.effectState)
        }
    }
    private func retireProviderClaim(_ id: String) {
        if let window = engine.leases[id]?.windowID, let owner = try? providerOwner(id, windowID: window) {
            provider.retire(owner: owner); electron.retire(owner: owner)
        }
    }
    private func prepareProvider(url: URL, bundleID: String) throws -> NativeProviderPreparation? {
        guard engine.installationTrust?.permits("native.control") == true,
              !NSWorkspace.shared.runningApplications.contains(where: { $0.bundleURL?.standardizedFileURL == url.standardizedFileURL }),
              let source = Bundle.main.privateFrameworksURL?.appendingPathComponent("WorkbenchReceiverProvider.dylib") else { return nil }
        let inspector = NativeProviderAdmissionInspector()
        let target = try inspector.inspectTarget(bundlePath: url.path, expectedBundleID: bundleID)
        let helper = try inspector.inspectHelper(executablePath: source.path)
        let root = directory.appendingPathComponent("native-operations/provider-sessions", isDirectory: true)
        var pluginSource: NativeProviderAdmissionMetadata?
        if bundleID == "com.macromates.TextMate" {
            guard NativeProviderTextClientCompatibility.supports(target) else { return nil }
            guard let pluginURL = Bundle.main.builtInPlugInsURL?.appendingPathComponent("WorkbenchTextMateReceiver.tmplugin") else { return nil }
            pluginSource = try inspector.inspectPlugin(bundlePath: pluginURL.path,
                expectedBundleID: "tools.localworkbench.textmate.receiver")
            guard let pluginSource = pluginSource,
                  NativeProviderAdmissionPolicy.evaluateTextMatePlugin(target: target, helper: helper, plugin: pluginSource).state == .eligibleForLaunchTrial else { return nil }
        } else {
            guard NativeProviderAdmissionPolicy.evaluate(target: target, helper: helper).state == .eligibleForLaunchTrial else { return nil }
        }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let retained = try NativeProviderPreparation.retainHelper(source: helper, durableRoot: root)
        if let pluginSource = pluginSource {
            let plugin: NativeProviderAdmissionMetadata
            do {
                plugin = try NativeTextMatePluginInstallation.prepare(source: pluginSource, target: target,
                    helper: retained, durableRoot: root, isTargetRunning: {
                        NSWorkspace.shared.runningApplications.contains { $0.bundleIdentifier == bundleID }
                    })
            } catch let failure as NativeTextMatePluginInstallationFailure {
                // Recovery material stays in the helper's private durable
                // operation directory; expose only its fixed classification.
                throw NativeFailure(failure.code, failure.effectState)
            }
            return try NativeProviderPreparation.create(target: target, helper: retained,
                hostAuditToken: providerProcess.snapshot(getpid()).audit, receiverClasses: ["NSTextView"],
                durableRoot: root, plugin: plugin, textClientReceiverClasses: ["OakTextView"],
                textClientWindowClasses: ["NSWindow"], textClientDocumentClasses: ["OakDocument"],
                allowTextClientInputContextKeys: true, allowTextClientInputContextShift: true,
                allowTextClientInputContextControlOption: true, allowTextClientInputContextReceiverKeyUp: true)
        }
        let profile = NativeProviderReceiverProfile.reviewed(target: target)
        return try NativeProviderPreparation.create(target: target, helper: retained,
            hostAuditToken: providerProcess.snapshot(getpid()).audit, receiverClasses: profile.textClasses, durableRoot: root,
            keyOnlyReceiverClasses: profile.keyOnlyClasses, keyOnlyWindowClasses: profile.keyWindowClasses)
    }
    private func registerPendingProvider(_ app: NativeAppIdentity) -> [String: Any]? {
        guard let (preparation, before) = providerPending[app.pid] else { return nil }
        do {
            let inspector = NativeProviderAdmissionInspector()
            guard engine.driver.matches(app), try providerProcess.snapshot(app.pid) == before,
                  try inspector.inspectTarget(bundlePath: app.bundlePath, expectedBundleID: app.bundleID,
                    expectedExecutable: app.executable) == preparation.target,
                  try inspector.inspectHelper(executablePath: preparation.helper.executablePath) == preparation.helper else {
                providerPending.removeValue(forKey: app.pid)
                throw NativeProviderHostFailure("native_provider_launch_identity_changed")
            }
            let hello = try provider.register(preparation: preparation, pid: app.pid, audit: before.audit, validate: { [providerProcess] in
                (try? providerProcess.snapshot(app.pid)) == before
            })
            providerPending.removeValue(forKey: app.pid)
            // Persist only the original successful live admission. Exclusive
            // create failures/unknown durability are retained, never rewritten
            // or retried; current-session input remains independently qualified.
            if let epoch = hello["authority_epoch"] as? String {
                do {
                    let saved = try NativeProviderRegistration.save(providerSessionsRoot: providerSessionsRoot,
                        preparation: preparation, process: registeredProcess(before), bootID: providerBootID(),
                        authorityEpoch: epoch, rebindVersion: 2, negotiatedHello: hello)
                    return ["ready": false, "reason": "native_provider_fresh_window_observation_required", "registered": true,
                        "continuity_registration": saved.durability == .confirmed ? "confirmed" : "durability_unknown"]
                } catch let failure as NativeProviderRegistrationFailure {
                    return ["ready": false, "registered": true, "reason": failure.code,
                        "continuity_registration": failure.durabilityUnknown ? "durability_unknown" : "unavailable"]
                } catch { return ["ready": false, "registered": true, "reason": "native_provider_registration_unavailable"] }
            }
            return ["ready": false, "reason": "native_provider_fresh_window_observation_required", "registered": true]
        } catch let failure as NativeProviderHostFailure { return ["ready": false, "reason": failure.code] }
        catch let failure as NativeProviderWireFailure { return ["ready": false, "reason": failure.code] }
        catch { return ["ready": false, "reason": "native_provider_startup_unavailable"] }
    }
    private var providerSessionsRoot: URL { directory.appendingPathComponent("native-operations/provider-sessions", isDirectory: true) }
    private func registeredProcess(_ snapshot: NativeProcessSnapshot) -> NativeProviderRegisteredProcess {
        NativeProviderRegisteredProcess(audit: snapshot.audit, pid: snapshot.pid, version: snapshot.version,
            uid: snapshot.uid, realUID: snapshot.realUID, startSeconds: snapshot.startSeconds,
            startMicroseconds: snapshot.startMicroseconds, executable: snapshot.executable)
    }
    private func providerBootID() throws -> String {
        var count = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &count, nil, 0) == 0, count > 0, count < 128 else {
            throw NativeProviderHostFailure("native_provider_boot_identity_unavailable")
        }
        var bytes = [CChar](repeating: 0, count: count)
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &count, nil, 0) == 0,
              let value = UUID(uuidString: String(cString: bytes)) else {
            throw NativeProviderHostFailure("native_provider_boot_identity_unavailable")
        }
        return value.uuidString
    }
    private func restoreProvider(_ app: NativeAppIdentity, owner: NativeProviderOwner, window: UInt32) throws {
        guard !provider.contains(pid: app.pid), providerPending[app.pid] == nil else { return }
        var rootInfo = stat()
        if lstat(providerSessionsRoot.path, &rootInfo) != 0 {
            if errno == ENOENT { return }
            throw NativeProviderHostFailure("native_provider_registration_root_unavailable")
        }
        let before = try providerProcess.snapshot(app.pid)
        do {
            guard let bundle = try NativeProviderRegistration.loadMatching(providerSessionsRoot: providerSessionsRoot,
                bootID: providerBootID(), process: registeredProcess(before)) else { return }
            let preparation = try NativeProviderRegistration.preparation(bundle: bundle, providerSessionsRoot: providerSessionsRoot)
            let inspector = NativeProviderAdmissionInspector()
            guard engine.driver.matches(app), before.executable == app.executable,
                  try inspector.inspectTarget(bundlePath: app.bundlePath, expectedBundleID: app.bundleID,
                    expectedExecutable: app.executable) == preparation.target,
                  try inspector.inspectHelper(executablePath: preparation.helper.executablePath) == preparation.helper else {
                throw NativeProviderHostFailure("native_provider_restore_identity_changed")
            }
            if let plugin = preparation.plugin {
                guard let path = plugin.bundlePath,
                      try inspector.inspectPlugin(bundlePath: path, expectedBundleID: plugin.bundleIdentifier,
                        expectedExecutable: plugin.executablePath) == plugin,
                      NativeProviderAdmissionPolicy.evaluateTextMatePlugin(target: preparation.target,
                        helper: preparation.helper, plugin: plugin).state == .eligibleForLaunchTrial else {
                    throw NativeProviderHostFailure("native_provider_restore_identity_changed")
                }
            } else if NativeProviderAdmissionPolicy.evaluate(target: preparation.target, helper: preparation.helper).state != .eligibleForLaunchTrial {
                throw NativeProviderHostFailure("native_provider_restore_identity_changed")
            }
            try verifyProviderOwner(owner, cgWindow: window, clipboard: false)
            try provider.register(preparation: preparation, pid: app.pid, audit: before.audit, replacingHost: true,
                validate: { [providerProcess] in (try? providerProcess.snapshot(app.pid)) == before })
        } catch let failure as NativeProviderRegistrationFailure { throw NativeProviderHostFailure(failure.code) }
    }
    private func providerFlightSettled(_ operation: String) {
        queue.async {
            guard self.unsettledProviderOperations.remove(operation) != nil else { return }
            self.settledHeldWaiters.removeValue(forKey: operation)?()
        }
    }
    private func capturedProviderKey(_ packet: [String: Any], fields: Set<String>) throws -> [String: Any] {
        guard packet["action"] as? String == "key_pair",
              packet["provider_observation_id"] == nil || packet["provider_observation_id"] is NSNull,
              let claim = packet["claim_id"] as? String, let windowID = packet["window_id"] as? String,
              let observation = packet["observation_id"] as? String, !observation.isEmpty,
              let operation = packet["operation_id"] as? String, !operation.isEmpty,
              let characters = packet["characters"] as? String, (1...8).contains(characters.utf16.count),
              let ignoring = packet["characters_ignoring_modifiers"] as? String, (1...8).contains(ignoring.utf16.count) else {
            throw NativeFailure("invalid_native_provider_action")
        }
        let code = try integer(packet, "key_code")
        guard (0...127).contains(code), !(54...63).contains(code) else { throw NativeFailure("invalid_native_key_code") }
        let owner = try providerOwner(claim, windowID: windowID)
        let (lease, source) = try engine.captureObservation(claim, observationID: observation)
        guard lease.trustRevision != nil, lease.control, source.window.id == windowID,
              let driver = engine.driver as? NativeAXDriver, !electron.contains(lease.app.pid),
              provider.contains(pid: lease.app.pid) else { throw NativeFailure("native_focused_key_provider_unavailable") }
        // Only the existing locally reviewed custom-key profile is eligible.
        // Remote packets cannot nominate receiver classes or routing policies.
        let identity = try NativeProviderAdmissionInspector().inspectTarget(bundlePath: lease.app.bundlePath,
            expectedBundleID: lease.app.bundleID, expectedExecutable: lease.app.executable)
        guard !NativeProviderReceiverProfile.reviewed(target: identity).keyOnlyClasses.isEmpty else {
            throw NativeFailure("native_focused_key_profile_unavailable")
        }
        let arguments = packet.filter { fields.contains($0.key) }
        var providerResult: [String: Any]?
        do {
            var result = try engine.capturedFocus(claim, observationID: observation, windowID: windowID) { granted, observed, proof, admission in
                let expected = NativeWindowGeometrySnapshot(windowID: windowID, bounds: proof.bounds, cgWindowID: proof.cgWindowID)
                let point = NativePoint(x: proof.bounds.x + proof.bounds.width / 2, y: proof.bounds.y + proof.bounds.height / 2)
                return try driver.withTargetedFocus(granted.app, windowID: windowID, expected: expected,
                    point: point, marker: Int64.random(in: 1...Int64.max), admission: admission) { revalidate in
                    try revalidate()
                    let fresh = self.provider.observe(pid: granted.app.pid, owner: owner, window: proof.cgWindowID)
                    guard fresh["ready"] as? Bool == true,
                          fresh["receiver_kind"] as? String == "custom_view_key_only",
                          let binding = fresh["provider_observation_id"] as? String else {
                        return ["ready": false, "reason": "native_focused_key_receiver_unavailable",
                            "preparation": fresh, "dispatch_attempted": false, "effect_state": "unknown", "retry_allowed": false]
                    }
                    do {
                        try revalidate()
                        let body = try self.provider.perform(pid: granted.app.pid, bundleID: granted.app.bundleID,
                            owner: owner, window: proof.cgWindowID, observationID: binding,
                            operationID: operation, method: "key_pair", arguments: arguments, beforeSendAdmission: {
                                do { try admission.beforeSend() }
                                catch let failure as NativeFailure {
                                    throw NativeProviderHostFailure(failure.code, effectState: failure.effectState,
                                        admissionEvidence: failure.response)
                                }
                            })
                        providerResult = body
                        return ["ready": body["dispatch_attempted"] as? Bool == true,
                            "reason": body["reason"] as? String ?? "native_focused_key_not_dispatched", "provider_result": body,
                            "effect_state": "unknown", "retry_allowed": false]
                    } catch let failure as NativeProviderHostFailure { throw NativeFailure(failure.code, failure.effectState) }
                }
            }
            if let body = providerResult { result["provider_result"] = body }
            result["input_backend"] = "captured_focus_custom_receiver"
            result["retry_allowed"] = false
            return result
        } catch let failure as NativeFailure {
            // The provider's original result/recovery survives a later focus
            // cleanup failure. Never replace it with another key attempt.
            guard let body = providerResult else { throw failure }
            var result = failure.response
            result["provider_result"] = body; result["retry_allowed"] = false
            return result
        }
    }

    private func providerAction(_ packet: [String: Any], action: String) throws -> [String: Any] {
        let common: Set<String> = ["version", "method", "action", "token", "request_id", "operation_id", "app_generation", "launch_id",
            "runtime_generation", "owner_session", "claim_id", "window_id", "provider_observation_id", "observation_id"]
        let fields: Set<String> = action == "key_sequence" ? ["keys"] : action == "key_chord"
            ? ["key_code", "characters", "characters_ignoring_modifiers", "modifiers"]
            : action == "key_pair" ? ["key_code", "characters", "characters_ignoring_modifiers"] : ["text"]
        guard !packet.contains(where: { !common.union(fields).contains($0.key) && !($0.value is NSNull) }) else {
            throw NativeFailure("invalid_native_provider_action")
        }
        if packet["observation_id"] != nil && !(packet["observation_id"] is NSNull) {
            guard action == "key_pair" else { throw NativeFailure("invalid_native_provider_action") }
            return try capturedProviderKey(packet, fields: fields)
        }
        guard !packet.contains(where: { !common.union(fields).contains($0.key) && !($0.value is NSNull) }),
              let claim = packet["claim_id"] as? String, let windowID = packet["window_id"] as? String,
              let observation = packet["provider_observation_id"] as? String, UUID(uuidString: observation) != nil,
              let operationID = packet["operation_id"] as? String, !operationID.isEmpty else {
            throw NativeFailure("invalid_native_provider_action")
        }
        let owner = try providerOwner(claim, windowID: windowID)
        guard let app = engine.leases[claim]?.app,
              let window = try engine.driver.window(app, id: windowID).cgWindowID else {
            throw NativeFailure("native_provider_window_changed")
        }
        do {
            let arguments = packet.filter { fields.contains($0.key) }
            let method = action == "insert_text" ? "consume_plain_text" : action
            func reply(_ result: [String: Any]) -> [String: Any] {
                ["ok": true, "provider_result": result, "effect_state": result["effect_state"] as? String ?? "unknown",
                 "retry_allowed": false, "task_completion": "not_established"]
            }
            if allowsDeferredProviderIO, electron.contains(app.pid) {
                let prepared = try electron.preparePerform(pid: app.pid, owner: owner, window: window,
                    observation: observation, operation: operationID, bundle: app.bundleID, method: method, arguments: arguments,
                    settled: { self.providerFlightSettled(operationID) })
                // The original target ticket survives I/O, retirement and even
                // a failed native-terminal write. Do not release it on defer.
                settledProviderReleases[operationID] = prepared.release
                unsettledProviderOperations.insert(operationID)
                throw NativeDeferred<[String: Any]> { completion in
                    DispatchQueue.global(qos: .userInitiated).async {
                        let response = Result {
                            try prepared.exchange { work in try self.queue.sync { try work() } }
                        }
                        self.queue.async { completion(.success(reply(prepared.finalize(response)))) }
                    }
                }
            }
            let result = try electron.contains(app.pid)
                ? electron.perform(pid: app.pid, owner: owner, window: window, observation: observation,
                    operation: operationID, bundle: app.bundleID, method: method, arguments: arguments)
                : provider.perform(pid: app.pid, bundleID: app.bundleID, owner: owner, window: window,
                    observationID: observation, operationID: operationID, method: method, arguments: arguments)
            return reply(result)
        } catch let failure as NativeProviderHostFailure { throw NativeFailure(failure.code, failure.effectState) }
    }

    private func managedPointerDispatch(_ packet: [String: Any], point: NativePoint,
                                        action: String, wheel: NativeWheelDelta?, holdMS: Int?, drag: NativeDrag?) -> NativeOperationEngine.ManagedPointerDispatch? {
        guard let claimID = packet["claim_id"] as? String, let lease = engine.leases[claimID],
              let observationID = packet["observation_id"] as? String, engine.hasUnitWebAreaCapture(claimID, observationID: observationID),
              lease.trustRevision != nil, lease.app.bundleID == "com.microsoft.VSCode",
              lease.app.signingIdentifier == "com.microsoft.VSCode", lease.app.teamID == "UBF8T346G9",
              electron.contains(lease.app.pid) else { return nil }
        return { granted, observed, proof, admission in
            guard let driver = self.engine.driver as? NativeAXDriver,
                  let operation = packet["operation_id"] as? String, !operation.isEmpty,
                  packet["window_id"] as? String == observed.window.id,
                  Double(proof.width) == proof.bounds.width, Double(proof.height) == proof.bounds.height,
                  proof.displayScale == 1,
                  observed.window.controls.filter({ $0.role == "AXWebArea" && !$0.secure && $0.bounds == proof.bounds }).count == 1 else {
                throw NativeFailure("native_managed_pointer_mapping_unavailable")
            }
            let owner = try self.providerOwner(claimID, windowID: observed.window.id)
            let expected = NativeWindowGeometrySnapshot(windowID: observed.window.id, bounds: proof.bounds, cgWindowID: proof.cgWindowID)
            let metadata = try driver.electronWindowMetadata(granted.app, windowID: observed.window.id)
            guard metadata["cg_window_id"] as? UInt32 == proof.cgWindowID,
                  let document = metadata["document_uri"] as? String, !document.isEmpty else {
                throw NativeFailure("native_managed_pointer_mapping_unavailable")
            }
            func digest(_ value: Any) throws -> String {
                let bytes = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
                return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            }
            func rect(_ value: NativeRect) -> [String: Double] {
                ["x": value.x, "y": value.y, "width": value.width, "height": value.height]
            }
            let bounds = rect(proof.bounds), binding = UUID().uuidString, once = UUID().uuidString
            let capture: [String: Any] = ["capture_id": proof.captureID, "observation_id": proof.observationID,
                "authority_hash": try digest(["owner": owner.wire, "capture": proof.captureID, "observation": proof.observationID,
                    "clock_generation": String(proof.clockGeneration), "bounds": bounds, "cg_window_id": proof.cgWindowID]),
                "deadline_host_monotonic": proof.deadline, "clock_generation": String(proof.clockGeneration)]
            let mapping: [String: Any] = ["native_bounds": bounds, "webarea_bounds": bounds,
                "cg_window_id": proof.cgWindowID, "document_uri": document]
            var gesture: [String: Any] = ["action": action, "point": ["x": point.x, "y": point.y]]
            if let wheel = wheel { gesture["wheel"] = ["x": wheel.x, "y": wheel.y] }
            if let holdMS = holdMS { gesture["hold_ms"] = holdMS }
            if let drag = drag { gesture["drag"] = ["end": ["x": drag.end.x, "y": drag.end.y], "steps": drag.steps] }
            let gestureHash = try digest(gesture)
            let payload: [String: Any] = ["pointer_contract": 1, "owner": owner.wire, "binding_id": binding,
                "once_id": once, "operation_id": operation, "capture": capture, "mapping": mapping, "gesture": gesture]
            let prepared: NativeElectronSession.PreparedPointer
            do { prepared = try self.electron.preparePointer(pid: granted.app.pid, owner: owner,
                operation: operation, bundle: granted.app.bundleID, payload: payload,
                settled: { self.providerFlightSettled(operation) }) }
            catch let failure as NativeProviderHostFailure { throw NativeFailure(failure.code, failure.effectState) }
            let marker = Int64.random(in: 1...Int64.max)
            try driver.prepareManagedPointerCursor(granted.app, expected: expected, point: point, marker: marker)
            let trace = driver.pointerTraceObserver
            // Save the original recovery identity before any worker can send.
            let recovery: [String: Any] = ["version": 1, "backend": "electron_pointer", "operation_id": operation,
                "provider_session_id": prepared.sessionID,
                "owner": owner.wire, "descriptor": ["owner": owner.wire, "binding_id": binding, "once_id": once],
                "capture": capture]
            try writePermissionState(JSONSerialization.data(withJSONObject: recovery, options: [.sortedKeys]),
                to: self.receiptURL(operation).appendingPathExtension("provider.json"))
            var resolvedMapping: NSDictionary?
            var inputAdmitted = false
            func sameOwner(_ message: [String: Any]) -> Bool {
                guard let supplied = message["owner"] as? [String: Any],
                      let contract = message["pointer_contract"] as? NSNumber,
                      CFGetTypeID(contract) != CFBooleanGetTypeID(), !CFNumberIsFloatType(contract) else { return false }
                return NSDictionary(dictionary: supplied).isEqual(to: owner.wire)
                    && message["binding_id"] as? String == binding && message["once_id"] as? String == once
                    && contract.int64Value == 1
            }
            func numericTree(_ value: Any) -> Bool {
                if let dictionary = value as? [String: Any] { return dictionary.values.allSatisfy(numericTree) }
                guard let number = value as? NSNumber else { return false }
                return CFGetTypeID(number) != CFBooleanGetTypeID() && number.doubleValue.isFinite
            }
            func validMapping(_ value: [String: Any]) -> Bool {
                let keys: Set<String> = ["native_bounds", "webarea_bounds", "cg_window_id", "document_uri", "target_id", "frame_id", "loader_id", "time_origin", "metrics"]
                guard Set(value.keys) == keys, value["cg_window_id"] as? UInt32 == proof.cgWindowID,
                      value["document_uri"] as? String == document,
                      let native = value["native_bounds"] as? [String: Any], NSDictionary(dictionary: native).isEqual(to: bounds),
                      let web = value["webarea_bounds"] as? [String: Any], NSDictionary(dictionary: web).isEqual(to: bounds),
                      ["target_id", "frame_id", "loader_id"].allSatisfy({ key in
                          guard let text = value[key] as? String else { return false }
                          return !text.isEmpty && text.utf8.count <= 128 && text.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil
                      }), let origin = value["time_origin"] as? NSNumber,
                      CFGetTypeID(origin) != CFBooleanGetTypeID(), origin.doubleValue.isFinite, origin.doubleValue > 0,
                      let metrics = value["metrics"] as? [String: Any] else { return false }
                let expectedMetrics: [String: Any] = ["screen_origin": ["x": proof.bounds.x, "y": proof.bounds.y],
                    "inner_size": ["width": proof.bounds.width, "height": proof.bounds.height],
                    "outer_size": ["width": proof.bounds.width, "height": proof.bounds.height], "device_pixel_ratio": 1,
                    "visual_viewport": ["width": proof.bounds.width, "height": proof.bounds.height, "scale": 1, "offset_x": 0, "offset_y": 0],
                    "css_viewport": ["width": proof.bounds.width, "height": proof.bounds.height, "offset_x": 0, "offset_y": 0,
                        "page_x": 0, "page_y": 0, "scale": 1, "zoom": 1]]
                return numericTree(metrics) && numericTree(native) && numericTree(web)
                    && NSDictionary(dictionary: metrics).isEqual(to: expectedMetrics)
            }
            let authorise: NativeElectronWorker.Authorise = { message in
                try self.queue.sync {
                    let keys: Set<String> = ["event", "request_id", "nonce", "context_hash", "pointer_contract", "owner", "binding_id", "once_id",
                        "operation_id", "purpose", "sequence", "capture", "gesture_hash", "mapping"]
                    guard Set(message.keys) == keys, sameOwner(message), message["operation_id"] as? String == operation,
                          let originalCapture = message["capture"] as? [String: Any], NSDictionary(dictionary: originalCapture).isEqual(to: capture),
                          message["gesture_hash"] as? String == gestureHash,
                          let reportedMapping = message["mapping"] as? [String: Any], validMapping(reportedMapping) else {
                        throw NativeFailure("native_managed_pointer_authorisation_invalid")
                    }
                    if let resolved = resolvedMapping {
                        guard resolved.isEqual(to: reportedMapping) else { throw NativeFailure("native_managed_pointer_mapping_changed") }
                    } else { resolvedMapping = NSDictionary(dictionary: reportedMapping) }
                    try self.cancellation.check(operation)
                    try self.verifyProviderOwner(owner, cgWindow: proof.cgWindowID, clipboard: false)
                    try admission.validateAuthority()
                    try driver.verifyManagedPointerGeometry(granted.app, expected: expected)
                    let current = try driver.electronWindowMetadata(granted.app, windowID: observed.window.id)
                    guard current["cg_window_id"] as? UInt32 == proof.cgWindowID,
                          current["native_title"] as? String == metadata["native_title"] as? String,
                          current["document_uri"] as? String == document else { throw NativeFailure("native_electron_document_changed") }
                    if message["purpose"] as? String == "pointer_hold" {
                        guard inputAdmitted else { throw NativeFailure("native_managed_pointer_authorisation_invalid") }
                    } else { try admission.beforeSend() }
                    try self.cancellation.check(operation)
                    if message["purpose"] as? String != "pointer_hold" { inputAdmitted = true }
                }
            }
            let originalPoints = [point] + (try drag?.path(from: point) ?? [])
            // Match the renderer's viewport conversion and inverse exactly;
            // fractional global coordinates can round at that subtraction.
            // These are presentation checks, never a coordinate rebase/send.
            let allowedPoints = originalPoints + originalPoints.map {
                NativePoint(x: ($0.x - proof.bounds.x) + proof.bounds.x, y: ($0.y - proof.bounds.y) + proof.bounds.y)
            }
            let progress: NativeElectronWorker.PointerProgress = { message in
                try self.queue.sync {
                    let keys: Set<String> = ["event", "request_id", "pointer_contract", "owner", "binding_id", "once_id", "sequence", "phase", "point",
                        "event_type", "button", "sent_events", "possibly_sent", "release_state", "elapsed_ms", "reason"]
                    guard Set(message.keys) == keys, sameOwner(message),
                          let position = message["point"] as? [String: Any], Set(position.keys) == ["x", "y"],
                          let x = position["x"] as? Double, let y = position["y"] as? Double,
                          allowedPoints.contains(NativePoint(x: x, y: y)),
                          let phase = message["phase"] as? String, ["press", "move", "release", "wheel", "hold", "failure", "timing"].contains(phase),
                          let event = message["event_type"] as? String, ["mousePressed", "mouseMoved", "mouseReleased", "mouseWheel", "none"].contains(event),
                          numericTree(position),
                          let count = message["sent_events"] as? NSNumber, CFGetTypeID(count) != CFBooleanGetTypeID(),
                          !CFNumberIsFloatType(count), (0...40).contains(count.int64Value),
                          let possibly = message["possibly_sent"] as? NSNumber, CFGetTypeID(possibly) == CFBooleanGetTypeID(),
                          let button = message["button"] as? String, ["left", "right", "none"].contains(button),
                          message["elapsed_ms"] is NSNull || (message["elapsed_ms"].map(numericTree) == true && (message["elapsed_ms"] as? Double ?? -1) >= 0),
                          message["reason"] is NSNull || (message["reason"] as? String).map({ $0.range(of: "^electron_[a-z0-9_]{1,200}$", options: .regularExpression) != nil }) == true,
                          let release = message["release_state"] as? String,
                          ["not_eligible", "eligible", "possibly_sent", "acknowledged", "unverified"].contains(release) else {
                        throw NativeFailure("native_managed_pointer_progress_invalid", "unknown")
                    }
                    trace?(message)
                    if count.int64Value > 0 && ["press", "move", "release", "wheel", "hold"].contains(phase) {
                        driver.presentManagedPointer(granted.app, expected: expected, point: NativePoint(x: x, y: y), marker: marker)
                    }
                }
            }
            self.unsettledProviderOperations.insert(operation)
            throw NativeDeferred<[String: Any]> { completion in
                DispatchQueue.global(qos: .userInitiated).async {
                    let result: Result<[String: Any], Error> = Result {
                        let response: [String: Any]
                        do { response = try prepared.exchange(authorise, progress) }
                        catch let failure as NativeProviderHostFailure { throw NativeFailure(failure.code, failure.effectState) }
                        return try self.queue.sync {
                            guard response["ok"] as? Bool == true, let value = response["result"] as? [String: Any],
                                  NativeProviderRecovery.validElectronPointerResult(value, binding: binding, once: once,
                                    operation: operation, action: action, expectedWindow: proof.cgWindowID,
                                    expectedTarget: resolvedMapping?["target_id"] as? String, inputAdmitted: inputAdmitted),
                                  value["possibly_sent"] as? Bool != true || (inputAdmitted && resolvedMapping != nil) else {
                                throw NativeFailure("native_managed_pointer_result_unavailable", "unknown")
                            }
                            return value
                        }
                    }
                    self.queue.async { completion(result) }
                }
            }
        }
    }
    private func pointerClickModifiers(_ packet: [String: Any]) throws -> [String] {
        // The existing provider action owns chord validation and dispatch.
        if packet["action"] as? String == "key_chord" { return [] }
        guard let raw = packet["modifiers"] else { return [] }
        guard packet["action"] as? String == "point", packet["control_action"] as? String == "click" else {
            throw NativeFailure("native_pointer_modifiers_outside_scope")
        }
        guard let names = raw as? [String], !names.isEmpty else {
            throw NativeFailure("native_pointer_modifiers_invalid")
        }
        try NativePointerClickModifiers.validate(names)
        return names
    }
    private func operation(_ packet: [String: Any], capturePurpose: String) throws -> [String: Any] {
        let action = packet["action"] as? String ?? ""
        let clickModifiers = try pointerClickModifiers(packet)
        let requestedDrag = try dragRequest(packet)
        if ["launch", "acquire"].contains(action) { try cancellation.admit("") }
        if ["control", "point", "fixture_probe_point", "clipboard_temporary", "move", "resize", "restore_window", "capture"].contains(action), let claim = packet["claim_id"] as? String {
            try cancellation.admit(claim)
            if let bundle = engine.leases[claim]?.app.bundleID { try cancellation.admitBundle(bundle) }
        }
        if action == "status" {
            var result = engine.status(ownerSession: packet["owner_session"] as? String ?? "")
            result["identity_diagnostics"] = (engine.driver as? NativeAXDriver)?.processDiagnostics.reports() ?? []
            result["native_activity"] = activitySnapshot()
            return result
        }
        if action == "discover" {
            guard engine.installationTrust?.permits("native.discover") == true else { throw NativeFailure("native_trusted_setup_required") }
            engine.expire()
            let discoveryBatch = engine.driver.beginWindowDiscovery()
            defer { if let batch = discoveryBatch { engine.driver.endWindowDiscovery(batch) } }
            let bundleID = packet["bundle_id"] as? String, appPath = packet["app_path"] as? String
            let normalizedPath = appPath.map { URL(fileURLWithPath: $0).standardizedFileURL.path }
            let applications = NSWorkspace.shared.runningApplications.filter {
                $0.activationPolicy != .prohibited
                    && (bundleID == nil || $0.bundleIdentifier == bundleID)
                    && (normalizedPath == nil || $0.bundleURL?.standardizedFileURL.path == normalizedPath)
            }
            var unavailable: [[String: Any]] = []
            let records = applications.prefix(100).compactMap { application -> [String: Any]? in
                let identity: NativeAppIdentity
                do {
                    guard let driver = engine.driver as? NativeAXDriver else { throw NativeFailure("native_driver_unavailable") }
                    identity = try driver.identify(application)
                } catch {
                    let reason = (error as? NativeFailure)?.code
                        ?? (error as? NativeProcessIdentityFailure)?.diagnostic.stage
                        ?? "native_app_identity_unavailable"
                    var unavailableApp: [String: Any] = ["pid": application.processIdentifier,
                        "bundle_id": application.bundleIdentifier as Any? ?? NSNull(),
                        "reason": reason, "identity_verified": false]
                    if let diagnostic = (error as? NativeProcessIdentityFailure)?.diagnostic {
                        // Discovery exposes fixed metadata field names only, never
                        // raw signing dictionaries, paths or process-probe values.
                        let publicFields: Set<String> = ["designated_requirement", "signing_identifier", "executable",
                            "secured_info_plist", "secured_bundle_id", "code_unique", "signature_flags"]
                        var detail: [String: Any] = ["stage": diagnostic.stage,
                            "fields": diagnostic.fields.filter { publicFields.contains($0) }]
                        if let status = diagnostic.status { detail["status"] = status }
                        unavailableApp["identity_diagnostic"] = detail
                    }
                    unavailable.append(unavailableApp)
                    return nil
                }
                var record = nativeDictionary(identity); record["name"] = application.localizedName ?? identity.bundleID
                if engine.installationTrust?.permits("native.observe", app: identity) == true {
                    do { record["windows"] = try engine.driver.windows(identity).map(nativeDictionary) }
                    catch let failure as NativeFailure { record["windows_unavailable"] = failure.code }
                    catch { record["windows_unavailable"] = "native_windows_unavailable" }
                    if let diagnostic = engine.driver.windowInventoryDiagnostic {
                        record["window_inventory"] = diagnostic
                    }
                } else { record["access"] = "stopped_locally" }
                return record
            }
            return ["ok": true, "interaction_version": 1, "apps": records, "scope": "running graphical applications",
                    "incomplete": applications.count > 100 || !unavailable.isEmpty || records.contains(where: {
                        $0["windows_unavailable"] != nil || ($0["window_inventory"] as? [String: Any])?["scope_complete"] as? Bool == false
                    }),
                    "unavailable_apps": unavailable, "installed": NativeAppRegistry.installed(bundleID: bundleID, appPath: normalizedPath),
                    "launch_lookup": "exact bundle_id or app_path; use app_path for multiple installed versions",
                    "discovery_lookup": "optional exact bundle_id or app_path filters before the inventory bound", "prompts_triggered": false]
        }
        if action == "launch" {
            guard engine.installationTrust?.permits("native.launch") == true else { throw NativeFailure("native_trusted_setup_required") }
            let path = packet["app_path"] as? String, identifier = packet["bundle_id"] as? String
            guard (path == nil) != (identifier == nil) else { throw NativeFailure("native_exact_app_required") }
            let url = path.map { URL(fileURLWithPath: $0).standardizedFileURL } ?? identifier.flatMap { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) }
            guard let url = url, let bundle = Bundle(url: url), let bundleID = bundle.bundleIdentifier,
                  engine.installationTrust?.blockedApps.contains(bundleID) != true else { throw NativeFailure("native_app_unavailable_or_stopped") }
            try cancellation.admitBundle(bundleID)
            let configuration = NSWorkspace.OpenConfiguration(); configuration.activates = false
            // Unsupported loader policies leave normal launch/semantic access
            // available. Never change the target's signature or entitlements.
            let wantsBootstrap = packet["launch_file_authority"] != nil || packet["initial_bounds"] != nil || packet["initial_display_id"] != nil
            if wantsBootstrap {
                guard engine.installationTrust?.permits("native.control") == true,
                    packet["launch_file_authority"] is [String:Any],
                    bundleID == "com.microsoft.VSCode"
                        ? packet["initial_bounds"] != nil && packet["initial_display_id"] != nil
                        : packet["initial_bounds"] == nil && packet["initial_display_id"] == nil else {
                    throw NativeProviderHostFailure("native_electron_bootstrap_authority_invalid")
                }
            }
            let initialFile = try (packet["launch_file_authority"] as? [String:Any]).map {try NativeElectronBootstrap.fileURL($0)}
            let documentOpen = initialFile != nil && bundleID != "com.microsoft.VSCode"
            if documentOpen, let identifier = identifier, identifier != bundleID {
                throw NativeFailure("native_launch_target_changed")
            }
            let documentTarget = documentOpen
                ? try NativeProviderAdmissionInspector().inspectTarget(bundlePath: url.path, expectedBundleID: bundleID) : nil
            if documentOpen {
                configuration.promptsUserIfNeeded = false
                configuration.addsToRecentItems = false
                configuration.allowsRunningApplicationSubstitution = false
            }
            let initialBounds = try NativeElectronBootstrap.bounds(packet)
            let electronSeed = engine.installationTrust?.permits("native.control") == true
                ? try NativeElectronManagedLaunch.prepare(url: url, bundleID: bundleID, stateDirectory: directory,
                    initialFile: initialFile, initialBounds: initialBounds) : nil
            if let seed = electronSeed { configuration.createsNewApplicationInstance = true; configuration.arguments = seed.arguments }
            let preparation: NativeProviderPreparation?
            if electronSeed == nil && bundleID == "com.macromates.TextMate" {
                // A failed/uncertain plugin publication must not be followed by
                // a fallback launch that could load the uncertain slot.
                preparation = try prepareProvider(url: url, bundleID: bundleID)
            } else {
                preparation = electronSeed == nil ? try? prepareProvider(url: url, bundleID: bundleID) : nil
            }
            if let preparation = preparation { configuration.environment = preparation.environment }
            if let authority=packet["launch_file_authority"] as? [String:Any] {
                // Close profile/signature preparation time before the OS launch.
                _ = try NativeElectronBootstrap.fileURL(authority)
            }
            // A display can disconnect or move while profile preparation runs.
            // Refuse changed containment; never let Code relocate into user work.
            _ = try NativeElectronBootstrap.bounds(packet)
            if let target = documentTarget {
                guard target.signature == .valid, target.bundlePath == url.standardizedFileURL.path,
                      try NativeProviderAdmissionInspector().inspectTarget(bundlePath: url.path,
                        expectedBundleID: bundleID, expectedExecutable: target.executablePath) == target else {
                    throw NativeFailure("native_launch_target_changed")
                }
                // Final file recheck follows potentially expensive signing and
                // provider preparation. Opening by URL is still not atomic.
                if let authority = packet["launch_file_authority"] as? [String: Any] {
                    _ = try NativeElectronBootstrap.fileURL(authority)
                }
                guard !draining else { throw NativeFailure("native_executor_stopping") }
                try cancellation.admit(""); try cancellation.admitBundle(bundleID)
                guard engine.installationTrust?.permits("native.launch") == true,
                      engine.installationTrust?.permits("native.control") == true,
                      engine.installationTrust?.blockedApps.contains(bundleID) != true else {
                    throw NativeFailure("native_trusted_setup_required")
                }
            }
            let done = DispatchSemaphore(value: 0)
            let resultLock = NSLock()
            var launched: NSRunningApplication?, failure: Error?
            let completed: (NSRunningApplication?, Error?) -> Void = { app, error in
                resultLock.lock(); launched = app; failure = error; resultLock.unlock(); done.signal()
            }
            if documentOpen, let file = initialFile {
                try cancellation.admitLaunch(bundleID: bundleID) {
                    NSWorkspace.shared.open([file], withApplicationAt: url, configuration: configuration, completionHandler: completed)
                }
            } else {
                NSWorkspace.shared.openApplication(at: url, configuration: configuration, completionHandler: completed)
            }
            guard done.wait(timeout: .now() + 20) == .success else { throw NativeFailure("native_launch_outcome_unknown", "unknown") }
            resultLock.lock(); defer { resultLock.unlock() }
            guard failure == nil, let app = launched else { throw NativeFailure("native_launch_failed", "unknown") }
            guard app.bundleURL?.standardizedFileURL.path == url.standardizedFileURL.path else {
                throw NativeFailure("native_launch_target_changed", "unknown")
            }
            guard let driver = engine.driver as? NativeAXDriver else {
                throw NativeFailure("native_driver_unavailable", documentOpen ? "unknown" : "none")
            }
            let identity: NativeAppIdentity
            do { identity = try driver.identify(app) }
            catch let original as NativeFailure {
                guard documentOpen else { throw original }
                // The OS open already ran; failed identity readback cannot
                // establish that the original document request had no effect.
                var widened = NativeFailure(original.code, "unknown", clipboardRecovery: original.clipboardRecovery)
                widened.visualValidity = original.visualValidity; widened.windowIdentity = original.windowIdentity
                throw widened
            }
            if let target = documentTarget {
                guard identity.bundleID == bundleID, identity.bundlePath == target.bundlePath,
                      identity.executable == target.executablePath, identity.signingIdentifier == target.signingIdentifier,
                      identity.teamID == target.teamIdentifier, identity.designatedRequirement == target.designatedRequirement else {
                    throw NativeFailure("native_launch_target_changed", "unknown")
                }
            }
            var reply: [String: Any] = ["ok": true, "app": nativeDictionary(identity), "activation_requested": false,
                    "effect_state": "applied", "task_completion": "not_established", "prompts_triggered": false]
            if documentOpen {
                reply["file_open"] = ["requested": true, "os_acknowledged": true]
                reply["effect_state"] = "unknown"
            }
            if let seed = electronSeed {
                do {
                    try electron.register(seed: seed, app: identity, matches: { [weak driver] in driver?.matches(identity) == true })
                    reply["keyboard"] = ["ready": false, "registered": true, "reason": "native_provider_fresh_window_observation_required"]
                } catch let failure as NativeProviderHostFailure {
                    reply["keyboard"] = ["ready": false, "reason": failure.code]
                } catch { reply["keyboard"] = ["ready": false, "reason": "native_electron_registration_unavailable"] }
            }
            if let preparation = preparation, let snapshot = try? providerProcess.snapshot(identity.pid) {
                providerPending = providerPending.filter { (try? providerProcess.snapshot($0.key)) == $0.value.1 }
                if providerPending.count < 32 { providerPending[identity.pid] = (preparation, snapshot) }
                reply["keyboard"] = registerPendingProvider(identity)
            }
            return reply
        }
        if action == "acquire" {
            return try withGrantAdmission { revision in
                guard let raw = packet["app_identity"] as? [String: Any],
                      let requested = try? JSONDecoder().decode(NativeAppIdentity.self, from: JSONSerialization.data(withJSONObject: raw)) else {
                    throw NativeFailure("invalid_app_target")
                }
                let app = requested
                // The engine checks retained original cleanup families after
                // freshly resolving the requested exact window and relation.
                guard engine.driver.matches(app) else { throw NativeFailure("native_process_identity_changed") }
                try cancellation.admitBundle(app.bundleID)
                let existing = Set(engine.leases.keys)
                let result = try engine.acquireTrusted(app: app, windowID: packet["window_id"] as? String ?? "",
                    ownerSession: packet["owner_session"] as? String ?? "", runtimeGeneration: packet["runtime_generation"] as? String ?? "",
                    control: packet["allow_control"] as? Bool ?? false, capture: packet["allow_capture"] as? Bool ?? false,
                    clipboard: packet["allow_clipboard"] as? Bool ?? false)
                try validateGrantedLease(result, existing: existing, revision: revision, bundle: app.bundleID)
                (engine.driver as? NativeAXDriver)?.processDiagnostics.arm(app)
                return result
            }
        }
        if action == "release" {
            guard packet["lease_id"] == nil else { throw NativeFailure("native_claim_id_required") }
            guard packet["release_binding"] == nil || packet["release_binding"] is [String: Any] else {
                throw NativeFailure("native_claim_owner_mismatch")
            }
            let claimID = packet["claim_id"] as? String ?? ""
            let result = try engine.releaseClaim(claimID, ownerSession: packet["owner_session"] as? String ?? "",
                                                runtimeGeneration: packet["runtime_generation"] as? String ?? "",
                                                releaseBinding: packet["release_binding"] as? [String: Any])
            if result["authority_changed"] as? Bool == true { retireProviderClaim(claimID) }
            if result["authority_changed"] as? Bool == true, let windowID = engine.leases[claimID]?.windowID,
               !engine.leases.values.contains(where: { $0.id != claimID && $0.windowID == windowID
                   && ["active", "suspended_transport"].contains($0.state) }) {
                (engine.driver as? NativeAXDriver)?.invalidateCursor(windowID: windowID)
            }
            return result
        }
        if action == "claim_release_status" {
            guard packet["lease_id"] == nil else { throw NativeFailure("native_claim_id_required") }
            return try engine.claimReleaseStatus(packet["claim_id"] as? String ?? "", ownerSession: packet["owner_session"] as? String ?? "",
                                                 runtimeGeneration: packet["runtime_generation"] as? String ?? "")
        }
        if action == "claim_status" {
            guard packet["lease_id"] == nil else { throw NativeFailure("native_claim_id_required") }
            return try engine.claimStatus(packet["claim_id"] as? String ?? "", ownerSession: packet["owner_session"] as? String ?? "",
                                          runtimeGeneration: packet["runtime_generation"] as? String ?? "")
        }
        if action == "receipt" {
            if let view = packet["receipt_view"] as? String {
                guard view == "cursor_diagnostics" else { throw NativeFailure("invalid_native_receipt_view") }
                let owner = NativeCursorTraceOwner(operationID: packet["operation_id"] as? String ?? "",
                    claimID: packet["claim_id"] as? String ?? "", ownerSession: packet["owner_session"] as? String ?? "",
                    runtimeGeneration: packet["runtime_generation"] as? String ?? "")
                guard owner.valid else { throw NativeFailure("invalid_native_cursor_owner") }
                guard let snapshot = (engine.driver as? NativeAXDriver)?.cursorDiagnosticSnapshot(owner) else {
                    return ["ok": true, "receipt_view": view, "state": "unavailable", "diagnostics_only": true]
                }
                let data = try JSONEncoder().encode(snapshot)
                guard data.count <= NativeCursorDiagnostics.maximumBytes,
                      let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    throw NativeFailure("native_cursor_diagnostics_limit")
                }
                return ["ok": true, "receipt_view": view, "state": "available", "diagnostics_only": true, "cursor_diagnostics": value]
            }
            let url = try receiptURL(packet["operation_id"] as? String ?? "")
            let retained: Data?
            do { retained = try NativeProviderRecovery.readNativeReceipt(operationReceiptsRoot: url.deletingLastPathComponent(),
                operationID: packet["operation_id"] as? String ?? "") }
            catch { throw NativeFailure("native_receipt_unavailable", "unknown") }
            guard let data = retained else { return ["ok": true, "state": "not_found"] }
            guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw NativeFailure("native_receipt_unavailable", "unknown")
            }
            try NativeClipboardReceiptPolicy.verify(value, ownerSession: packet["owner_session"] as? String ?? "")
            var reply: [String: Any] = ["ok": true, "receipt": value]
            if ["key_pair", "key_chord", "key_sequence", "insert_text", "point"].contains(value["native_action"] as? String ?? "") {
                let owner = packet["owner_session"] as? String ?? ""
                guard !owner.isEmpty, value["owner_session"] as? String == owner else { throw NativeFailure("native_claim_owner_mismatch") }
                do { let recovered = try NativeProviderRecovery.recoverStored(
                    providerSessionsRoot: directory.appendingPathComponent("native-operations/provider-sessions", isDirectory: true),
                    electronSessionsRoot: directory.appendingPathComponent("native-operations/electron-sessions", isDirectory: true),
                    operationReceiptsRoot: url.deletingLastPathComponent(), ownerSession: owner,
                    operationID: packet["operation_id"] as? String ?? "", nativeReceipt: value)
                    reply["provider_reconciliation"] = recovered["provider_reconciliation"]
                    if let binding = recovered["historical_binding"] { reply["historical_binding"] = binding }
                }
                catch { reply["provider_reconciliation"] = ["receipt_recovered": false, "effect_state": "unknown", "retry_allowed": false] }
            }
            return reply
        }
        let lease = packet["claim_id"] as? String ?? packet["lease_id"] as? String ?? ""
        if !lease.isEmpty {
            try engine.verifyOwner(lease, ownerSession: packet["owner_session"] as? String ?? "", runtimeGeneration: packet["runtime_generation"] as? String ?? "",
                                   legacyAlias: packet["lease_id"] != nil)
        }
        if action == "observe" {
            var result = try engine.observe(lease, windowID: packet["window_id"] as? String, treeBaseID: packet["tree_base_revision"] as? String,
                sourceObservationID: packet["observation_id"] as? String, rootControlID: packet["control_id"] as? String)
            if result["observation_scope"] != nil {
                result["keyboard"] = ["ready": false, "reason": "subtree_observation_semantic_only", "retry_allowed": false]
                return result
            }
            if let windowID = packet["window_id"] as? String, let granted = engine.leases[lease],
               let owner = try? providerOwner(lease, windowID: windowID),
               let descriptor = result["window"] as? [String: Any], let cgWindow = descriptor["cgWindowID"] as? UInt32,
               let current = try? engine.driver.windowGeometry(granted.app, windowID: windowID), current.cgWindowID == cgWindow,
               let observedBounds = descriptor["bounds"] as? [String: Double],
               observedBounds["x"] == current.bounds.x, observedBounds["y"] == current.bounds.y,
               observedBounds["width"] == current.bounds.width, observedBounds["height"] == current.bounds.height {
                _ = registerPendingProvider(granted.app)
                do {
                    _ = try electron.restore(app: granted.app, matches: { self.engine.driver.matches(granted.app) })
                    if !electron.contains(granted.app.pid) { try restoreProvider(granted.app, owner: owner, window: cgWindow) }
                }
                catch let failure as NativeProviderHostFailure {
                    result["keyboard"] = ["ready": false, "reason": failure.code, "retry_allowed": false]; return result
                }
                catch { result["keyboard"] = ["ready": false, "reason": "native_provider_restore_unavailable", "retry_allowed": false]; return result }
                result["keyboard"] = electron.observe(pid: granted.app.pid, owner: owner, window: cgWindow)
                    ?? provider.observe(pid: granted.app.pid, owner: owner, window: cgWindow)
            }
            return result
        }
        if ["key_pair", "key_chord", "key_sequence", "insert_text"].contains(action) { return try providerAction(packet, action: action) }
        if action == "clipboard_restore" { return try engine.restoreClipboard(packet["clipboard_lease_id"] as? String ?? "", ownerSession: packet["owner_session"] as? String ?? "") }
        if action == "clipboard_release" { return try engine.releaseClipboard(packet["clipboard_lease_id"] as? String ?? "", ownerSession: packet["owner_session"] as? String ?? "") }
        if action == "revoke" {
            retireProviderClaim(lease)
            if let active = engine.leases[lease], active.trustRevision != nil {
                do { try trustStore.stopLocally(appBundleID: active.app.bundleID) }
                catch { engine.installationTrust = trustStore.policy; engine.revoke(lease, reason: "mcp_revoke"); engine.expire(); throw error }
                engine.installationTrust = trustStore.policy
            }
            engine.revoke(lease, reason: "mcp_revoke"); engine.expire()
            return ["ok": true, "lease_id": lease, "revoked": true]
        }
        let observation = packet["observation_id"] as? String ?? ""
        if action == "capture" {
            return try engine.capture(lease, observationID: observation, purpose: capturePurpose) { _, _ in
                try self.prepareRendererCapture(lease, observationID: observation,
                    operationID: packet["operation_id"] as? String ?? packet["request_id"] as? String ?? "")
            }
        }
        if action == "restore_window" {
            guard packet["claim_id"] as? String != nil, let windowID = packet["window_id"] as? String, !windowID.isEmpty else {
                throw NativeFailure("native_claim_id_required")
            }
            let allowed: Set<String> = ["version", "method", "action", "token", "request_id", "operation_id", "app_generation", "launch_id", "runtime_generation", "owner_session", "claim_id", "window_id"]
            guard !packet.contains(where: { !allowed.contains($0.key) && !($0.value is NSNull) }) else { throw NativeFailure("invalid_native_restore") }
            return try engine.restoreWindow(lease, windowID: windowID)
        }
        if action == "move" || action == "resize" {
            guard packet["claim_id"] as? String != nil else { throw NativeFailure("native_claim_id_required") }
            let names = action == "move" ? ["x", "y"] : ["width", "height"]
            func number(_ name: String) throws -> Double {
                guard let raw = packet[name] as? NSNumber, CFGetTypeID(raw) != CFBooleanGetTypeID(), raw.doubleValue.isFinite else {
                    throw NativeFailure("invalid_native_geometry")
                }
                return raw.doubleValue
            }
            let first = try number(names[0]), second = try number(names[1])
            if action == "resize" && (first <= 0 || second <= 0) { throw NativeFailure("invalid_native_geometry") }
            let forbidden = ["lease_id", "control_id", "control_action", "text", "selection_start", "selection_length",
                "delta_x", "delta_y", "hold_ms", "wait_ms", "fixture_session", "tree_base_revision", "app_identity", "app_path", "bundle_id",
                "clipboard_lease_id", "expected_change_count", "allow_control", "allow_capture", "allow_clipboard"]
                + (action == "move" ? ["width", "height"] : ["x", "y"])
            guard !forbidden.contains(where: { packet[$0] != nil && !(packet[$0] is NSNull) }) else { throw NativeFailure("invalid_native_geometry") }
            return try engine.geometry(lease, windowID: packet["window_id"] as? String ?? "", observationID: observation,
                mutation: action == "move" ? .move(NativePoint(x: first, y: second)) : .resize(NativeSize(width: first, height: second)))
        }
        if action == "control" {
            var selection: NativeTextRange?
            if packet["selection_start"] != nil || packet["selection_length"] != nil {
                guard packet["control_action"] as? String == "select_text" else { throw NativeFailure("native_text_range_invalid") }
                selection = NativeTextRange(location: try integer(packet, "selection_start"), length: try integer(packet, "selection_length"))
            }
            return try engine.action(lease, observationID: observation, controlID: packet["control_id"] as? String ?? "",
                                     action: packet["control_action"] as? String ?? "", text: packet["text"] as? String, selection: selection)
        }
        if action == "point" {
            guard let rawX = packet["x"] as? NSNumber, let rawY = packet["y"] as? NSNumber,
                  CFGetTypeID(rawX) != CFBooleanGetTypeID(), CFGetTypeID(rawY) != CFBooleanGetTypeID(),
                  rawX.doubleValue.isFinite, rawY.doubleValue.isFinite else { throw NativeFailure("native_point_required") }
            let x = rawX.doubleValue, y = rawY.doubleValue
            let point = NativePoint(x: x, y: y), pointerAction = packet["control_action"] as? String ?? ""
            let wheel = try wheelDelta(packet), duration = try holdDuration(packet)
            let managed = managedPointerDispatch(packet, point: point, action: pointerAction, wheel: wheel, holdMS: duration, drag: requestedDrag)
            let perform = { try self.engine.point(lease, observationID: observation, point: NativePoint(x: x, y: y),
                action: pointerAction, modifiers: clickModifiers, wheel: wheel, holdMS: duration,
                drag: requestedDrag, windowID: packet["window_id"] as? String, managedDispatch: managed) }
            if let driver = engine.driver as? NativeAXDriver { return try driver.retainingPointerFailure(perform) }
            return try perform()
        }
        #if LOCAL_WORKBENCH_POINTER_ACCEPTANCE
        if action == "fixture_probe_point" { return try runFixturePointProbe(packet, lease: lease, observation: observation) }
        #endif
        if action == "clipboard_temporary" {
            let payload = try NativeClipboardPayload(text: packet["text"] as? String, representations: packet["representations"])
            if let text = packet["text"], !(text is String) { throw NativeFailure("invalid_native_clipboard_payload") }
            return try engine.temporaryClipboard(lease, expectedChangeCount: integer(packet, "expected_change_count"), payload: payload)
        }
        throw NativeFailure("native_operation_unsupported")
    }
    #if LOCAL_WORKBENCH_POINTER_ACCEPTANCE
    private func runFixturePointProbe(_ packet: [String: Any], lease: String, observation: String) throws -> [String: Any] {
        let now = Date().timeIntervalSince1970
        if fixturePointerProbe == nil {
            let url = directory.appendingPathComponent("native-operations/fixture-pointer-probe.json")
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            guard attributes[.type] as? FileAttributeType == .typeRegular,
                  (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
                  let mode = attributes[.posixPermissions] as? NSNumber, mode.intValue & 0o077 == 0,
                  (attributes[.size] as? NSNumber)?.intValue ?? 16385 <= 16384 else {
                throw NativeFailure("native_probe_profile_invalid")
            }
            fixturePointerProbe = NativeFixturePointerProbe(profile: try NativeFixtureProbeProfile.load(localURL: url, now: now))
        }
        guard let probe = fixturePointerProbe, let driver = engine.driver as? NativeAXDriver,
              let x = packet["x"] as? NSNumber, let y = packet["y"] as? NSNumber,
              CFGetTypeID(x) != CFBooleanGetTypeID(), CFGetTypeID(y) != CFBooleanGetTypeID() else {
            throw NativeFailure("native_point_required")
        }
        let owner = packet["owner_session"] as? String ?? "", runtime = packet["runtime_generation"] as? String ?? ""
        func currentRequest() throws -> NativeFixtureProbeRequest {
            let claim = try engine.claimStatus(lease, ownerSession: owner, runtimeGeneration: runtime)
            guard let target = claim["target"] as? [String: Any], let appData = target["app"] as? [String: Any],
                  let app = try? JSONDecoder().decode(NativeAppIdentity.self, from: JSONSerialization.data(withJSONObject: appData)),
                  let windowID = target["window_id"] as? String, let generation = target["target_generation"] as? String,
                  driver.matches(app) else { throw NativeFailure("native_probe_target_mismatch") }
            let drag = try dragRequest(packet)
            if drag != nil && packet["window_id"] as? String != windowID { throw NativeFailure("native_probe_target_mismatch") }
            let window = try driver.window(app, id: windowID)
            let stateURL = URL(fileURLWithPath: probe.profile.fixture.bundlePath).deletingLastPathComponent()
                .appendingPathComponent("receipts/state.json")
            let stateData = try Data(contentsOf: stateURL)
            let checkedAt = Date().timeIntervalSince1970
            guard stateData.count <= 65536, let state = try JSONSerialization.jsonObject(with: stateData) as? [String: Any],
                  let session = state["session"] as? String, session == packet["fixture_session"] as? String,
                  let stamp = state["unixSeconds"] as? Double, checkedAt >= stamp, checkedAt - stamp <= 3,
                  (state["pid"] as? NSNumber)?.int32Value == app.pid,
                  let windows = state["windows"] as? [[String: Any]],
                  windows.contains(where: { $0["title"] as? String == window.title && ($0["windowNumber"] as? NSNumber)?.uint32Value == window.cgWindowID }) else {
                throw NativeFailure("native_probe_fixture_state_stale")
            }
            return try NativeFixtureProbeRequest(operationID: packet["operation_id"] as? String ?? "",
                requestedTargetGeneration: packet["target_generation"] as? String ?? "",
                runtime: NativeFixtureProbeRuntime(appGeneration: packet["app_generation"] as? String ?? "",
                    launchID: packet["launch_id"] as? String ?? "", runtimeGeneration: runtime, ownerSession: owner),
                claim: NativeFixtureProbeClaim(id: lease, ownerSession: owner, runtimeGeneration: runtime,
                    targetGeneration: generation, app: app, windowID: windowID, active: claim["state"] as? String == "active",
                    control: claim["control"] as? Bool == true, capture: claim["capture"] as? Bool == true,
                    trusted: claim["claim_epoch"] is NSNumber),
                observedApp: app, observedWindow: window, fixtureSession: session,
                point: NativePoint(x: x.doubleValue, y: y.doubleValue), action: packet["control_action"] as? String ?? "",
                wheel: wheelDelta(packet), holdMS: holdDuration(packet), drag: drag)
        }
        let request = try currentRequest()
        let app = request.observedApp, window = request.observedWindow
        let windowID = window.id, session = request.fixtureSession
        let permit = try probe.authorize(request, now: Date().timeIntervalSince1970)
        var rows: [[String: Any]] = [], marker: Int64?
        let pointerBefore = CGEvent(source: nil)?.location
        let foregroundBefore = NSWorkspace.shared.frontmostApplication?.processIdentifier
        driver.pointerTraceObserver = { row in if rows.count < 32 { rows.append(row) } }
        defer { driver.pointerTraceObserver = nil }
        func finish(_ original: [String: Any]) -> [String: Any] {
            var result = original
            let pointerAfter = CGEvent(source: nil)?.location
            result["diagnostic"] = ["run_id": probe.profile.runID, "profile_sha256": probe.profile.profileSHA256,
                "production_method": request.action == "drag" ? "NativeAXDriver.targetedDragInput" : request.action == "scroll" ? "NativeAXDriver.targetedScrollInput" : ["hold", "right_hold"].contains(request.action) ? "NativeAXDriver.targetedHoldInput" : "NativeAXDriver.targetedPointInput", "fixture_session": session,
                "app": nativeDictionary(app), "window_id": windowID, "cg_window_id": window.cgWindowID as Any,
                "event_marker": marker as Any? ?? NSNull(),
                "event_marker_decimal": marker.map { String($0) } as Any? ?? NSNull(), "trace": rows,
                "pointer_before": pointerBefore.map { [Double($0.x), Double($0.y)] } as Any? ?? NSNull(),
                "pointer_after": pointerAfter.map { [Double($0.x), Double($0.y)] } as Any? ?? NSNull(),
                "foreground_before": foregroundBefore as Any? ?? NSNull(),
                "foreground_after": NSWorkspace.shared.frontmostApplication?.processIdentifier as Any? ?? NSNull(),
                "normal_pointer_enabled": false]
            if let drag = request.drag, var diagnostic = result["diagnostic"] as? [String: Any] {
                diagnostic["drag_start"] = nativeDictionary(request.point)
                diagnostic["drag_end"] = nativeDictionary(drag.end)
                diagnostic["drag_steps"] = drag.steps
                diagnostic["normal_drag_enabled"] = false
                result["diagnostic"] = diagnostic
            }
            return result
        }
        var result: [String: Any]
        do {
            result = try engine.fixtureProbePoint(lease, observationID: observation, permit: permit,
                consume: {
                    let current = try currentRequest()
                    try probe.consume(permit, current: current, now: Date().timeIntervalSince1970)
                },
                context: { marker = $0 })
        } catch let deferred as NativeDeferred<[String: Any]> {
            throw deferred.mapResult { outcome in
                do { return finish(try outcome.get()) }
                catch let failure as NativeFailure { return finish(failure.response) }
            }
        } catch let error as NativeFailure {
            result = ["ok": false, "error": ["code": error.code, "effect_state": error.effectState]]
        }
        return finish(result)
    }
    #endif
    func handle(_ packet: [String: Any]) -> [String: Any] {
        // Existing direct synchronous consumers retain their original behavior.
        let deferredIO = allowsDeferredProviderIO; allowsDeferredProviderIO = false
        let driver = engine.driver as? NativeAXDriver
        let old = driver?.holdSchedule; driver?.holdSchedule = nil
        defer { driver?.holdSchedule = old; allowsDeferredProviderIO = deferredIO }
        do { return try handleOperation(packet) }
        catch { return ["ok": false, "error": ["code": "native_operation_failed", "effect_state": "unknown"]] }
    }

    private func handleDeferred(_ packet: [String: Any], completion: @escaping ([String: Any]) -> Void) {
        if draining { completion(NativeFailure("native_executor_stopping").response); return }
        let action = packet["action"] as? String ?? ""
        // Preserve serialization for shared pointer/focus resources. The exact
        // original packet/capture deadline is checked when it can enter; no
        // refresh, recapture or arbitrary pointer parallelism is introduced.
        let currentClaim = engine.leases[packet["claim_id"] as? String ?? ""]
        let sharesHeldTarget = currentClaim.map { claim in
            heldTargets.values.contains { $0.app == claim.app && $0.familyID == claim.windowFamilyResource }
        } ?? false
        let managedCandidate = ["key_pair", "key_chord", "key_sequence", "insert_text", "point"].contains(action)
        let managed = !heldOperations.isEmpty && managedCandidate && (currentClaim.map { claim in
            claim.trustRevision != nil && claim.app.bundleID == "com.microsoft.VSCode"
                && claim.app.signingIdentifier == "com.microsoft.VSCode" && claim.app.teamID == "UBF8T346G9"
                && electron.contains(claim.app.pid)
        } ?? false)
        let independentManaged = managed && !sharesHeldTarget
            && !heldClaims.contains(packet["claim_id"] as? String ?? "")
            && (["key_pair", "key_chord", "key_sequence", "insert_text"].contains(action)
                || (action == "point" && engine.hasUnitWebAreaCapture(packet["claim_id"] as? String ?? "",
                    observationID: packet["observation_id"] as? String ?? "")))
        // Targeted pointer invocations own private event-source state and exact
        // recipient guards. Their synthetic focus context is process-scoped:
        // never overlap the same PID, even if a new identity reused that PID.
        // Missing/legacy claims retain the conservative shared-resource gate.
        let independentPointer = ["point", "fixture_probe_point"].contains(action)
            && (currentClaim.map { claim in
                claim.trustRevision != nil && claim.windowID != nil
                    && !heldClaims.contains(claim.id)
                    && heldTargets.count == heldOperations.count
                    && heldTargets.values.allSatisfy { $0.app.pid != claim.app.pid }
            } ?? false)
        let sharesHeldResource = (!independentManaged && !independentPointer && ["point", "fixture_probe_point", "move", "resize", "restore_window",
                                  "key_pair", "key_chord", "key_sequence", "insert_text", "launch"].contains(action))
            || (action == "control" && ["raise", "AXRaise", "show_menu", "AXShowMenu"].contains(packet["control_action"] as? String ?? ""))
        if !heldOperations.isEmpty && (sharesHeldResource || (action == "control" && (sharesHeldTarget || heldClaims.contains(packet["claim_id"] as? String ?? "")))) {
            heldResourceWaiters.append { self.handleDeferred(packet, completion: completion) }
            return
        }
        let driver = engine.driver as? NativeAXDriver
        let deferredIO = allowsDeferredProviderIO; allowsDeferredProviderIO = true
        let old = driver?.holdSchedule
        driver?.holdSchedule = { delay, step in
            self.queue.asyncAfter(deadline: .now() + .nanoseconds(Int(delay)), execute: step)
        }
        defer { driver?.holdSchedule = old; allowsDeferredProviderIO = deferredIO }
        do { completion(try handleOperation(packet)) }
        catch let deferred as NativeDeferred<[String: Any]> {
            let id = packet["operation_id"] as? String ?? ""
            let claim = packet["claim_id"] as? String ?? ""
            if let retained = engine.leases[claim], let window = retained.windowID, let family = retained.windowFamilyResource {
                heldTargets[id] = (retained.app, window, family)
                engine.retainHeldCleanupBindings(id, lease: retained)
            }
            heldOperations.insert(id); heldClaims.insert(claim); publishActivity()
            deferred.start { result in
                let reply: [String: Any]
                do { reply = try result.get() }
                catch let failure as NativeFailure { reply = failure.response }
                catch { reply = ["ok": false, "error": ["code": "native_operation_failed", "effect_state": "unknown"]] }
                // Completion includes durable receipt creation before releasing
                // pins and admitting a conflicting original packet.
                // If terminal storage fails, the original events are already
                // consumed. Keep a conservative activity/drain/resource pin;
                // never replay cleanup or certify an undurable operation idle.
                guard self.durableHeldTerminals.remove(id) != nil else { completion(reply); return }
                completion(reply)
                let retire = {
                    self.settledProviderReleases.removeValue(forKey: id)?()
                    if ["point", "fixture_probe_point"].contains(action) { driver?.finishCursorOperation(id) }
                    self.cancellation.finish(id)
                    self.heldOperations.remove(id); self.heldClaims.remove(claim); self.heldTargets.removeValue(forKey: id)
                    self.engine.releaseHeldCleanupBindings(id); self.publishActivity()
                    let waiters = self.heldResourceWaiters; self.heldResourceWaiters.removeAll()
                    for waiter in waiters { waiter() }
                    if self.heldOperations.isEmpty {
                        let drains = self.heldDrainWaiters; self.heldDrainWaiters.removeAll()
                        for finish in drains { finish() }
                    }
                }
                // A timeout/UNKNOWN response does not establish that the
                // original child has stopped sending its immutable cleanup.
                if self.unsettledProviderOperations.contains(id) { self.settledHeldWaiters[id] = retire }
                else { retire() }
            }
        }
        catch let failure as NativeFailure { completion(failure.response) }
        catch { completion(["ok": false, "error": ["code": "native_operation_failed", "effect_state": "unknown"]]) }
    }

    private func handleOperation(_ packet: [String: Any]) throws -> [String: Any] {
        defer { publishActivity() }
        func finalize(_ original: [String: Any]) throws -> [String: Any] {
            var result = original
            let action = packet["action"] as? String ?? ""
            if ["key_pair", "key_chord", "key_sequence", "insert_text", "point", "receipt"].contains(action) {
                result = NativeProviderPublicView.clean(result)
            }
            if action != "receipt" || packet["receipt_view"] as? String != "cursor_diagnostics" {
                result["owner"] = permissionOwner()
            }
            let encoded = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
            if encoded.count > 65536 {
                return ["ok": true, "result_capture": try engine.storePayload(encoded), "potentially_sensitive": true]
            }
            return result
        }
        do {
            // Validate this field before any journal or input admission.
            let capturePurpose = try NativeCapturePurpose.decode(packet)
            if packet["method"] as? String == "terminal_prompt" { return try terminalInput.request(packet) }
            if packet["method"] as? String == "terminal_prompt_status" { return try terminalInput.status(packet["prompt_id"] as? String ?? "") }
            if packet["method"] as? String == "capture_page" {
                return try engine.capturePage(packet["capture_id"] as? String ?? "", offset: integer(packet, "offset"), count: integer(packet, "count"))
            }
            if packet["method"] as? String == "release_result_payload" {
                return try engine.releaseResultPayload(packet["capture_id"] as? String ?? "",
                    bytes: integer(packet, "bytes"), sha256: packet["sha256"] as? String ?? "")
            }
            let action = packet["action"] as? String ?? ""
            func dispatchNew() throws -> [String: Any] {
                // Nonjournaled capture still owns a bounded cancellation
                // ticket; the anonymous host request UUID is its internal ID.
                let requestID = packet["operation_id"] as? String ?? (action == "capture" ? packet["request_id"] as? String ?? "" : "")
                let pointer = ["point", "fixture_probe_point"].contains(action)
                let semanticControl = action == "control"
                let eligible = (pointer || semanticControl || ["move", "resize", "restore_window", "key_pair", "key_chord", "key_sequence", "insert_text", "capture"].contains(action)) && packet["claim_id"] as? String != nil
                if eligible {
                    try engine.verifyOwner(packet["claim_id"] as? String ?? "",ownerSession:packet["owner_session"] as? String ?? "",runtimeGeneration:packet["runtime_generation"] as? String ?? "")
                    try cancellation.begin(requestID:requestID,claimID:packet["claim_id"] as? String ?? "",
                        ownerSession:packet["owner_session"] as? String ?? "",runtimeGeneration:packet["runtime_generation"] as? String ?? "",
                        bundleID:engine.leases[packet["claim_id"] as? String ?? ""]?.app.bundleID ?? "")
                    if pointer { (engine.driver as? NativeAXDriver)?.beginCursorOperation(requestID,
                        owner: NativeCursorTraceOwner(operationID: requestID, claimID: packet["claim_id"] as? String ?? "",
                            ownerSession: packet["owner_session"] as? String ?? "", runtimeGeneration: packet["runtime_generation"] as? String ?? "")) }
                    engine.driver.cancellationCheck = { [weak self] in try self?.cancellation.check(requestID) }
                    engine.driver.guardedInputSend = { [weak self] action in
                        guard let self = self else { throw NativeFailure("native_controller_unavailable") }
                        try self.cancellation.send(requestID,action:action)
                    }
                }
                var suspended = false
                func finish() {
                    if eligible {
                        if pointer { (engine.driver as? NativeAXDriver)?.finishCursorOperation(requestID) }
                        self.cancellation.finish(requestID)
                    }
                }
                defer {
                    if eligible { engine.driver.cancellationCheck = nil; engine.driver.guardedInputSend = nil }
                    if !suspended { finish() }
                }
                do { return try operation(packet, capturePurpose: capturePurpose) }
                catch let deferred as NativeDeferred<[String: Any]> {
                    suspended = true
                    // The outer retained request releases its cancellation/
                    // cursor pins only after the durable terminal is written.
                    throw deferred
                }
            }
            let mutating = ["launch", "acquire", "release", "control", "point", "fixture_probe_point", "clipboard_temporary", "clipboard_restore", "clipboard_release", "revoke", "move", "resize", "restore_window", "key_pair", "key_chord", "key_sequence", "insert_text"].contains(action)
            var result: [String: Any]
            if mutating {
                let requestID = packet["operation_id"] as? String ?? ""
                let url = try receiptURL(requestID)
                let context = try NativeProviderRecovery.nativeReceiptContext(packet: packet)
                let payloadHash = context["payload_sha256"] as! String
                if let replay = try NativeReceiptAdmission.replay(url: url, requestID: requestID, payloadHash: payloadHash) {
                    result = replay
                } else {
                    var pending = context
                    pending["state"] = "pending"; pending["effect_state"] = "unknown"
                    pending["lease_id"] = packet["lease_id"] as Any? ?? NSNull()
                    try writePermissionState(JSONSerialization.data(withJSONObject: pending), to: url)
                    func persist(_ result: [String: Any]) throws -> [String: Any] {
                        var completed = context
                        completed["state"] = "completed"; completed["result"] = result
                        try writePermissionState(JSONSerialization.data(withJSONObject: completed), to: url)
                        if self.heldOperations.contains(requestID) { self.durableHeldTerminals.insert(requestID) }
                        return result
                    }
                    do { result = try persist(dispatchNew()) }
                    catch let deferred as NativeDeferred<[String: Any]> {
                        throw deferred.mapResult { outcome in
                            let terminal: [String: Any]
                            do { terminal = try outcome.get() }
                            catch let failure as NativeFailure { terminal = failure.response }
                            catch { terminal = ["ok": false, "error": ["code": "native_operation_failed", "effect_state": "unknown"]] }
                            return try persist(terminal)
                        }
                    }
                    catch let error as NativeFailure { result = try persist(error.response) }
                }
            } else { result = try dispatchNew() }
            return try finalize(result)
        } catch let deferred as NativeDeferred<[String: Any]> {
            throw deferred.mapResult { result in try finalize(result.get()) }
        } catch let error as NativeFailure { return error.response }
        catch { return ["ok": false, "error": ["code": "native_operation_failed", "effect_state": "unknown"]] }
    }
}

struct NativeOperationView: View {
    @ObservedObject var model: NativeOperationCentre
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("App access").font(.title2.bold())
            Text("Enable app access once. Agents can then find, open and claim windows for their tasks.").foregroundStyle(.secondary)
            Toggle("Allow app control", isOn: $model.trustedControl)
            Toggle("Allow window captures", isOn: $model.trustedCapture)
            Toggle("Allow temporary clipboard use", isOn: $model.trustedClipboard)
            HStack {
                Button(model.trustState == "valid" ? "Update app access" : "Enable app access") { model.configureTrust() }
                if model.trustState == "valid" { Button("Stop app access") { model.stopTrustedAccess() } }
                Text(model.trustState == "valid" ? "Enabled" : model.trustState == "revoked" ? "Stopped" : "Setup needed").foregroundStyle(.secondary)
            }
            ForEach(model.stoppedApps, id: \.self) { bundleID in
                HStack { Text(bundleID); Spacer(); Text("Stopped").foregroundStyle(.secondary)
                    Button("Resume app") { model.resumeStoppedApp(bundleID) }.disabled(model.trustState != "valid") }
            }
            Text("macOS approvals remain separate. Stop stays in effect after reconnect or restart. Available controls depend on the app and its supported input path.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Text(model.message).font(.callout).fixedSize(horizontal: false, vertical: true)
            Divider()
            DisclosureGroup("Older short-session controls") {
            Text("Existing short grants keep their original behavior during migration.").font(.caption).foregroundStyle(.secondary)
            HStack { Text(model.selectedPath.isEmpty ? "No app selected" : URL(fileURLWithPath: model.selectedPath).deletingPathExtension().lastPathComponent); Spacer(); Button("Choose app…") { model.choose() } }
            Toggle("Allow control while this app is in front", isOn: $model.allowControl)
            Toggle("Allow captures of this app’s selected window", isOn: $model.allowCapture)
            Toggle("Allow temporary clipboard use with checked restoration", isOn: $model.allowClipboard)
            Picker("Access lasts", selection: $model.seconds) { Text("1 minute").tag(60); Text("2 minutes").tag(120); Text("5 minutes").tag(300) }
            Button("Share selected app") { model.grant() }.disabled(model.selectedPath.isEmpty)
            Text("These older control grants end on pointer, keyboard or focus changes.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal:false,vertical:true)
            }
            Divider()
            ForEach(model.rows.indices, id: \.self) { index in
                let row = model.rows[index]
                HStack {
                    Text((row["app"] as? [String: Any])?["bundleID"] as? String ?? "Selected app")
                    Spacer(); Text(row["state"] as? String ?? "Unknown").foregroundStyle(.secondary)
                    if row["state"] as? String == "active", let id = row["lease_id"] as? String { Button("Stop sharing") { model.revoke(id) } }
                }
            }
            ForEach(model.clipboardRows.indices, id: \.self) { index in
                if let id = model.clipboardRows[index]["clipboard_lease_id"] as? String {
                    HStack {
                        Text(model.clipboardRows[index]["state"] as? String == "recovery_only"
                             ? "Saved clipboard retained; ownership unverified"
                             : "Temporary clipboard awaiting your choice")
                        Button("Restore") { model.finishClipboard(id, restore: true) }
                            .disabled(model.clipboardRows[index]["state"] as? String != "temporary_verified")
                        Button("Keep current") { model.finishClipboard(id, restore: false) }
                    }
                }
            }
            Text("Readback reports what changed; a sent action alone does not mean the task succeeded.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }.padding(24).frame(minWidth: 540, minHeight: 360)
    }
}
