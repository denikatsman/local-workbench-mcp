import Foundation
import CryptoKit
import CoreFoundation

// Acceptance builds only. Load the profile from lead-selected local startup data,
// never from an operation packet. This helper neither grants access nor sends input.
#if LOCAL_WORKBENCH_POINTER_ACCEPTANCE
struct NativeFixtureProbeProfile {
    struct DragOperation: Equatable {
        let operationID: String, point: NativePoint, drag: NativeDrag
    }
    struct Fixture {
        let bundleID: String, bundlePath: String, executable: String
        let executableSHA256: String, windowTitle: String
    }
    let runID: String, ownerSession: String, expiresAt: Double
    let fixture: Fixture
    let operationIDs: Set<String>
    let dragOperation: DragOperation?
    let profileSHA256: String

    private init(runID: String, ownerSession: String, expiresAt: Double, fixture: Fixture,
                 operationIDs: Set<String>, dragOperation: DragOperation?, profileSHA256: String) {
        self.runID = runID; self.ownerSession = ownerSession; self.expiresAt = expiresAt
        self.fixture = fixture; self.operationIDs = operationIDs; self.dragOperation = dragOperation; self.profileSHA256 = profileSHA256
    }

    static func load(localURL: URL, now: Double) throws -> Self {
        let data: Data
        do { data = try Data(contentsOf: localURL) }
        catch { throw NativeFailure("native_probe_profile_unavailable") }
        guard data.count <= 16384,
              let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(raw.keys) == Set(["schema", "run_id", "expires_at", "owner_session", "fixture", "operation_ids"])
                .union(raw["drag_operation"] == nil ? [] : ["drag_operation"]),
              let schema = number(raw["schema"]), schema == 1,
              let run = raw["run_id"] as? String, identifier(run),
              let owner = raw["owner_session"] as? String, identifier(owner),
              let expiry = number(raw["expires_at"]), now.isFinite,
              let f = raw["fixture"] as? [String: Any],
              Set(f.keys) == ["bundle_id", "bundle_path", "executable", "executable_sha256", "window_title"],
              let bundleID = f["bundle_id"] as? String,
              fullMatch(bundleID, "^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$"),
              let bundlePath = f["bundle_path"] as? String, canonicalAbsolute(bundlePath), bundlePath.hasSuffix(".app"),
              let executable = f["executable"] as? String, canonicalAbsolute(executable),
              executable.hasPrefix(bundlePath + "/Contents/MacOS/"),
              URL(fileURLWithPath: executable).deletingLastPathComponent().path == bundlePath + "/Contents/MacOS",
              let hash = f["executable_sha256"] as? String,
              fullMatch(hash, "^[0-9a-f]{64}$"),
              let title = f["window_title"] as? String, !title.isEmpty, title.utf8.count <= 300,
              let operations = raw["operation_ids"] as? [String], (1...8).contains(operations.count),
              operations.allSatisfy(identifier), Set(operations).count == operations.count else {
            throw NativeFailure("native_probe_profile_invalid")
        }
        guard expiry > now else { throw NativeFailure("native_probe_profile_expired") }
        guard expiry <= now + 900 else { throw NativeFailure("native_probe_profile_invalid") }
        var dragOperation: DragOperation?
        if let value = raw["drag_operation"] {
            guard let packet = value as? [String: Any],
                  Set(packet.keys) == ["operation_id", "x", "y", "end_x", "end_y", "steps"],
                  let operationID = packet["operation_id"] as? String, operations.contains(operationID),
                  let x = number(packet["x"]), let y = number(packet["y"]),
                  let endX = number(packet["end_x"]), let endY = number(packet["end_y"]),
                  let steps = packet["steps"] as? NSNumber, CFGetTypeID(steps) != CFBooleanGetTypeID(),
                  ["c", "s", "i", "l", "q", "C", "S", "I", "L", "Q"].contains(String(cString: steps.objCType)),
                  steps.doubleValue.isFinite, steps.doubleValue.rounded() == steps.doubleValue,
                  (2...16).contains(steps.doubleValue) else { throw NativeFailure("native_probe_profile_invalid") }
            let point = NativePoint(x: x, y: y), drag = NativeDrag(end: NativePoint(x: endX, y: endY), steps: steps.intValue)
            do { _ = try drag.path(from: point) }
            catch { throw NativeFailure("native_probe_profile_invalid") }
            dragOperation = DragOperation(operationID: operationID, point: point, drag: drag)
        }
        return Self(runID: run, ownerSession: owner, expiresAt: expiry,
                    fixture: Fixture(bundleID: bundleID, bundlePath: bundlePath, executable: executable,
                                     executableSHA256: hash, windowTitle: title),
                    operationIDs: Set(operations), dragOperation: dragOperation, profileSHA256: digest(data))
    }
    private static func number(_ raw: Any?) -> Double? {
        guard let n = raw as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(), n.doubleValue.isFinite else { return nil }
        return n.doubleValue
    }
    fileprivate static func identifier(_ value: String) -> Bool {
        fullMatch(value, "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    }
    // Foundation's $ can match before a trailing line terminator. Require the
    // entire UTF-16 range so a matching prefix never admits a malformed identifier.
    fileprivate static func fullMatch(_ value: String, _ pattern: String) -> Bool {
        let full = NSRange(value.startIndex..<value.endIndex, in: value)
        guard let expression = try? NSRegularExpression(pattern: pattern),
              let match = expression.firstMatch(in: value, range: full) else { return false }
        return match.range == full
    }
    private static func canonicalAbsolute(_ path: String) -> Bool {
        path.hasPrefix("/") && URL(fileURLWithPath: path).standardizedFileURL.path == path
    }
    fileprivate static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

// Derive these from the authenticated channel/current engine claim and driver
// observation. They deliberately have no request-JSON decoder.
struct NativeFixtureProbeRuntime: Equatable {
    let appGeneration: String, launchID: String, runtimeGeneration: String, ownerSession: String
}
struct NativeFixtureProbeClaim {
    let id: String, ownerSession: String, runtimeGeneration: String, targetGeneration: String
    let app: NativeAppIdentity
    let windowID: String
    let active: Bool, control: Bool, capture: Bool, trusted: Bool
}
struct NativeFixtureProbeRequest {
    let operationID: String, requestedTargetGeneration: String
    let runtime: NativeFixtureProbeRuntime
    let claim: NativeFixtureProbeClaim
    let observedApp: NativeAppIdentity
    let observedWindow: NativeWindow
    let fixtureSession: String
    let point: NativePoint
    let action: String
    var wheel: NativeWheelDelta? = nil
    var holdMS: Int? = nil
    var drag: NativeDrag? = nil
}

struct NativeFixtureProbePermit {
    fileprivate let authority: UUID, id: UUID, scope: NativeFixtureProbeScope
    let runID: String, operationID: String, point: NativePoint, action: String
    let wheel: NativeWheelDelta?
    let holdMS: Int?
    let drag: NativeDrag?
    var app: NativeAppIdentity { scope.app }
    var windowID: String { scope.windowID }
    var cgWindowID: UInt32 { scope.cgWindowID }
    var bounds: NativeRect { scope.bounds }
    var claimID: String { scope.claimID }
    var targetGeneration: String { scope.targetGeneration }
    var runtime: NativeFixtureProbeRuntime { scope.runtime }
    var fixtureSession: String { scope.fixtureSession }
    // No externally accessible initializer can mint a permit.
    fileprivate init(authority: UUID, scope: NativeFixtureProbeScope, runID: String,
                     operationID: String, point: NativePoint, action: String, wheel: NativeWheelDelta?, holdMS: Int?, drag: NativeDrag?) {
        self.authority = authority; id = UUID(); self.scope = scope; self.runID = runID
        self.operationID = operationID; self.point = point; self.action = action
        self.wheel = wheel; self.holdMS = holdMS; self.drag = drag
    }
}

fileprivate struct NativeFixtureProbeScope: Equatable {
    let runtime: NativeFixtureProbeRuntime
    let app: NativeAppIdentity
    let claimID: String, targetGeneration: String, windowID: String, fixtureSession: String
    let cgWindowID: UInt32
    let bounds: NativeRect
}

// All calls belong on NativeOperationCentre's existing serial native queue.
// A new app/runtime/window needs a fresh locally configured diagnostic instance;
// this instance never rebinds and never resets consumed operations.
final class NativeFixturePointerProbe {
    let profile: NativeFixtureProbeProfile
    private let authority = UUID()
    private var binding: NativeFixtureProbeScope?
    private var permits: [String: NativeFixtureProbePermit] = [:]
    private var consumed: Set<String> = []
    init(profile: NativeFixtureProbeProfile) { self.profile = profile }

    func authorize(_ request: NativeFixtureProbeRequest, now: Double) throws -> NativeFixtureProbePermit {
        let scope = try checkedScope(request, now: now)
        if let binding = binding, binding != scope { throw NativeFailure("native_probe_binding_changed") }
        guard !consumed.contains(request.operationID) else { throw NativeFailure("native_probe_operation_consumed") }
        if let old = permits[request.operationID] {
            guard old.scope == scope, old.point == request.point, old.action == request.action,
                  old.wheel == request.wheel, old.holdMS == request.holdMS, old.drag == request.drag else {
                throw NativeFailure("native_probe_operation_conflict")
            }
            return old
        }
        let permit = NativeFixtureProbePermit(authority: authority, scope: scope, runID: profile.runID,
            operationID: request.operationID, point: request.point, action: request.action, wheel: request.wheel, holdMS: request.holdMS, drag: request.drag)
        binding = scope; permits[request.operationID] = permit
        return permit
    }

    // Call after ordinary observation/capture checks, immediately before possible
    // input. A failed/partial send does not restore this one-use admission.
    func consume(_ permit: NativeFixtureProbePermit, current: NativeFixtureProbeRequest, now: Double) throws {
        guard permit.authority == authority, let issued = permits[permit.operationID], issued.id == permit.id,
              current.operationID == permit.operationID else { throw NativeFailure("native_probe_permit_invalid") }
        guard !consumed.contains(permit.operationID) else { throw NativeFailure("native_probe_operation_consumed") }
        let scope = try checkedScope(current, now: now)
        guard binding == scope, permit.scope == scope, permit.point == current.point, permit.action == current.action,
              permit.wheel == current.wheel, permit.holdMS == current.holdMS, permit.drag == current.drag else {
            throw NativeFailure("native_probe_binding_changed")
        }
        consumed.insert(permit.operationID)
    }

    private func checkedScope(_ request: NativeFixtureProbeRequest, now: Double) throws -> NativeFixtureProbeScope {
        guard now.isFinite, now < profile.expiresAt else { throw NativeFailure("native_probe_profile_expired") }
        guard profile.operationIDs.contains(request.operationID) else { throw NativeFailure("native_probe_operation_not_allowed") }
        let runtime = request.runtime, claim = request.claim, app = request.observedApp, window = request.observedWindow
        guard runtime.ownerSession == profile.ownerSession, claim.ownerSession == profile.ownerSession else {
            throw NativeFailure("native_probe_owner_mismatch")
        }
        guard UUID(uuidString: runtime.appGeneration) != nil, UUID(uuidString: runtime.launchID) != nil,
              NativeFixtureProbeProfile.fullMatch(runtime.runtimeGeneration, "^[0-9a-f]{32}$"),
              claim.runtimeGeneration == runtime.runtimeGeneration else { throw NativeFailure("native_probe_runtime_mismatch") }
        guard claim.active, claim.control, claim.capture, claim.trusted,
              NativeFixtureProbeProfile.fullMatch(claim.id, "^[0-9a-f]{32}$"),
              NativeFixtureProbeProfile.fullMatch(claim.targetGeneration, "^[0-9a-f]{32}$"),
              request.requestedTargetGeneration == claim.targetGeneration,
              claim.app == app, claim.windowID == window.id,
              NativeFixtureProbeProfile.identifier(window.id),
              let number = window.cgWindowID, number > 0, window.bounds.finite,
              window.title == profile.fixture.windowTitle, UUID(uuidString: request.fixtureSession) != nil,
              request.point.x.isFinite, request.point.y.isFinite, window.bounds.contains(request.point),
              ["click", "double_click", "right_click", "scroll", "hold", "right_hold", "drag"].contains(request.action),
              request.action == "scroll" ? request.wheel?.valid == true : request.wheel == nil else { throw NativeFailure("native_probe_target_mismatch") }
        let holding = ["hold", "right_hold"].contains(request.action)
        guard holding ? request.holdMS.map({ (1...5000).contains($0) }) == true : request.holdMS == nil else {
            throw NativeFailure("native_probe_target_mismatch")
        }
        if request.action == "drag" {
            guard let configured = profile.dragOperation, configured.operationID == request.operationID,
                  configured.point == request.point, configured.drag == request.drag,
                  let drag = request.drag,
                  try drag.path(from: request.point).allSatisfy({ window.bounds.contains($0) }) else {
                throw NativeFailure("native_probe_target_mismatch")
            }
        } else {
            guard request.drag == nil, profile.dragOperation?.operationID != request.operationID else {
                throw NativeFailure("native_probe_target_mismatch")
            }
        }
        guard app.pid > 0, app.launchedAt.isFinite, app.launchedAt > 0,
              app.bundleID == profile.fixture.bundleID, app.bundlePath == profile.fixture.bundlePath,
              app.executable == profile.fixture.executable else { throw NativeFailure("native_probe_fixture_mismatch") }
        let executable: Data
        do { executable = try Data(contentsOf: URL(fileURLWithPath: app.executable), options: .mappedIfSafe) }
        catch { throw NativeFailure("native_probe_fixture_unavailable") }
        guard NativeFixtureProbeProfile.digest(executable) == profile.fixture.executableSHA256 else {
            throw NativeFailure("native_probe_fixture_mismatch")
        }
        return NativeFixtureProbeScope(runtime: runtime, app: app, claimID: claim.id,
            targetGeneration: claim.targetGeneration, windowID: window.id, fixtureSession: request.fixtureSession,
            cgWindowID: number, bounds: window.bounds)
    }
}
#endif
