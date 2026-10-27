import Foundation
import AppKit
import Darwin
import WorkbenchProcessSupport

final class NativeElectronController {
    private let directory: URL
    private let process = NativeSystemProcessIdentity(metadata: { _ in nil })
    private let metadata: (NativeAppIdentity, NativeProviderOwner) throws -> [String: Any]
    private let authority: NativeElectronSession.Authority, cancelled: (String) throws -> Void
    private let recovery: (String, [String: Any]) throws -> Void
    private var sessions: [Int32: NativeElectronSession] = [:]
    private var worker: NativeElectronWorker?
    private let workerLock = NSLock()

    init(directory: URL, metadata: @escaping (NativeAppIdentity, NativeProviderOwner) throws -> [String: Any],
         authority: @escaping NativeElectronSession.Authority, cancelled: @escaping (String) throws -> Void,
         recovery: @escaping (String, [String: Any]) throws -> Void) {
        self.directory = directory; self.metadata = metadata; self.authority = authority
        self.cancelled = cancelled; self.recovery = recovery
    }
    private var currentWorker: NativeElectronWorker? {
        workerLock.lock(); defer { workerLock.unlock() }; return worker
    }
    var activeIDs: [String] { currentWorker?.activeIDs ?? [] }
    func cancel(operation: String? = nil, claim: String? = nil, bundle: String? = nil) {
        currentWorker?.cancel(operation: operation, claim: claim, bundle: bundle)
    }
    func retire(owner: NativeProviderOwner? = nil) { sessions.values.forEach { $0.retire(owner: owner) } }
    private func currentSession(_ pid: Int32) -> NativeElectronSession? {
        guard let session = sessions[pid] else { return nil }
        guard session.isCurrent else {
            session.retire(); sessions.removeValue(forKey: pid)
            // Historical records remain available for read-only recovery.
            // A dead registration must not mask a new process's provider.
            return nil
        }
        return session
    }
    func contains(_ pid: Int32) -> Bool { currentSession(pid) != nil }

    private func bootID() throws -> String {
        var count = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &count, nil, 0) == 0, count > 0, count < 128 else {
            throw NativeProviderHostFailure("native_electron_boot_identity_unavailable")
        }
        var buffer = [CChar](repeating: 0, count: count)
        guard sysctlbyname("kern.bootsessionuuid", &buffer, &count, nil, 0) == 0,
              let value = UUID(uuidString: String(cString: buffer)) else {
            throw NativeProviderHostFailure("native_electron_boot_identity_unavailable")
        }
        return value.uuidString
    }

    private func resolveWorker() throws -> NativeElectronWorker {
        if let worker = currentWorker { return worker }
        guard let resources = Bundle.main.resourceURL,
              let data = try? Data(contentsOf: resources.appendingPathComponent("runtime.json")),
              let settings = try? JSONSerialization.jsonObject(with: data) as? [String: String] else {
            throw NativeProviderHostFailure("native_electron_runtime_unavailable")
        }
        let runtime = try WorkbenchRuntimeSettings.load(settings, resources: resources, fixture: false)
        let libraries = runtime.python.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("lib")
        let versions = try FileManager.default.contentsOfDirectory(at: libraries, includingPropertiesForKeys: nil)
        let candidates = versions.filter { $0.lastPathComponent.hasPrefix("python3.") }.map {
            $0.appendingPathComponent("site-packages/playwright/driver/node")
        }.filter { FileManager.default.isExecutableFile(atPath: $0.path) }
        guard candidates.count == 1 else { throw NativeProviderHostFailure("native_electron_node_unavailable") }
        let node = candidates[0].resolvingSymlinksInPath()
        let script = runtime.repository.appendingPathComponent("src/local_workbench/electron_provider/runner.mjs").resolvingSymlinksInPath()
        let keyScript = script.deletingLastPathComponent().appendingPathComponent("guardian.mjs").resolvingSymlinksInPath()
        let pointerBroker = script.deletingLastPathComponent().appendingPathComponent("pointer-broker.mjs").resolvingSymlinksInPath()
        let sealedRoot = resources.resolvingSymlinksInPath().path + "/"
        guard node.path.hasPrefix(sealedRoot), script.path.hasPrefix(sealedRoot), keyScript.path.hasPrefix(sealedRoot), pointerBroker.path.hasPrefix(sealedRoot),
              FileManager.default.fileExists(atPath: script.path), FileManager.default.fileExists(atPath: keyScript.path),
              FileManager.default.fileExists(atPath: pointerBroker.path) else { throw NativeProviderHostFailure("native_electron_runtime_unverified") }
        let result = NativeElectronWorker(node: node, script: script, keyScript: keyScript, pointerBrokerScript: pointerBroker)
        workerLock.lock(); worker = result; workerLock.unlock(); return result
    }

    func register(seed: NativeElectronLaunchSeed, app: NativeAppIdentity, matches: @escaping () -> Bool) throws {
        guard app.bundleID == "com.microsoft.VSCode", app.signingIdentifier == app.bundleID,
              app.teamID == "UBF8T346G9", matches() else { throw NativeProviderHostFailure("native_electron_target_unverified") }
        let before = try process.snapshot(app.pid)
        guard let signature = try process.signature(app, snapshot: before) else {
            throw NativeProviderHostFailure("native_electron_signature_unavailable")
        }
        let endpoint = try NativeElectronManagedLaunch.endpoint(seed: seed)
        try NativeProviderRecovery.validatePrivateDirectory(seed.sessionRoot)
        try NativeProviderRecovery.validatePrivateDirectory(seed.profile)
        guard try process.snapshot(app.pid) == before, matches(),
              WB_ProcessOwnsLoopbackListener(app.pid, UInt16(endpoint.port)) != 0 else {
            throw NativeProviderHostFailure("native_electron_process_changed")
        }
        let context: [String: Any] = ["session_id": seed.session, "generation": seed.generation,
            "boot_id": try bootID(), "user_home": FileManager.default.homeDirectoryForCurrentUser.path,
            "session_root": seed.sessionRoot.path, "profile_path": seed.profile.path, "port": endpoint.port,
            "browser_websocket_path": endpoint.path, "process": ["pid": app.pid,
                "start_seconds": before.startSeconds, "start_microseconds": before.startMicroseconds,
                "uid": before.uid, "real_uid": before.realUID, "pid_version": before.version,
                "audit_token_base64": before.audit.base64EncodedString(), "executable": app.executable,
                "bundle_identifier": app.bundleID, "signing_identifier": signature.identifier,
                "team_identifier": signature.team ?? "", "cdhash": signature.unique.map { String(format: "%02x", $0) }.joined(),
                "designated_requirement": signature.requirement]]
        try writePermissionState(JSONSerialization.data(withJSONObject: context, options: [.sortedKeys, .withoutEscapingSlashes]),
            to: seed.sessionRoot.appendingPathComponent("managed.json"))
        let ownership = try NativeProviderRecovery.ElectronOwnership(root: seed.sessionRoot, managed: context, create: true)
        try install(context: context, app: app, before: before, ownership: ownership, matches: matches)
    }

    private func install(context: [String: Any], app: NativeAppIdentity, before: NativeProcessSnapshot,
                         ownership: NativeProviderRecovery.ElectronOwnership, matches: @escaping () -> Bool) throws {
        let port = context["port"] as! Int
        let runtime = try resolveWorker()
        let session = try NativeElectronSession(managed: context, worker: runtime, ownership: ownership, validate: { [process] in
            do {
                try ownership.verify(context)
                try NativeProviderRecovery.verifyElectronEndpoint(context)
                guard matches(), try process.snapshot(app.pid) == before,
                      WB_ProcessOwnsLoopbackListener(app.pid, UInt16(port)) != 0 else { return false }
                return try process.snapshot(app.pid) == before
            } catch { return false }
        }, metadata: { [metadata] owner in try metadata(app, owner) }, authority: authority,
            checkCancelled: cancelled, saveRecovery: recovery)
        sessions[app.pid] = session
    }

    /// Re-admit only a local immutable registration. Neither claims nor the
    /// previous host's in-memory bindings are imported or written back.
    func restore(app: NativeAppIdentity, matches: @escaping () -> Bool) throws -> Bool {
        if contains(app.pid) { return true }
        guard app.bundleID == "com.microsoft.VSCode", app.signingIdentifier == app.bundleID,
              app.teamID == "UBF8T346G9", matches() else { return false }
        let before = try process.snapshot(app.pid)
        guard let signature = try process.signature(app, snapshot: before) else {
            throw NativeProviderHostFailure("native_electron_signature_unavailable")
        }
        let live: [String: Any] = ["pid": app.pid, "start_seconds": before.startSeconds, "start_microseconds": before.startMicroseconds,
            "uid": before.uid, "real_uid": before.realUID, "pid_version": before.version,
            "audit_token_base64": before.audit.base64EncodedString(), "executable": app.executable,
            "bundle_identifier": app.bundleID, "signing_identifier": signature.identifier,
            "team_identifier": signature.team ?? "", "cdhash": signature.unique.map { String(format: "%02x", $0) }.joined(),
            "designated_requirement": signature.requirement]
        guard let context = try NativeProviderRecovery.electronRegistration(
            sessionsRoot: directory.appendingPathComponent("native-operations/electron-sessions"), pid: app.pid,
            boot: bootID(), liveProcess: live), let root = context["session_root"] as? String else { return false }
        let ownership = try NativeProviderRecovery.ElectronOwnership(root: URL(fileURLWithPath: root), managed: context, create: false)
        try NativeProviderRecovery.verifyElectronEndpoint(context)
        guard try process.snapshot(app.pid) == before, matches() else { throw NativeProviderHostFailure("native_electron_process_changed") }
        try install(context: context, app: app, before: before, ownership: ownership, matches: matches)
        return true
    }

    func observe(pid: Int32, owner: NativeProviderOwner, window: UInt32) -> [String: Any]? {
        currentSession(pid)?.observe(owner: owner, window: window)
    }
    func preparePointer(pid: Int32, owner: NativeProviderOwner, operation: String, bundle: String,
                        payload: [String: Any], settled: @escaping () -> Void = {}) throws -> NativeElectronSession.PreparedPointer {
        guard let session = currentSession(pid) else { throw NativeProviderHostFailure("native_electron_registration_required") }
        return try session.preparePointer(owner: owner, operation: operation, bundle: bundle, payload: payload, settled: settled)
    }
    func refreshForCapture(pid: Int32, owner: NativeProviderOwner, window: [String: Any], operation: String,
                           bundle: String, deadline: Double,
                           authorise: @escaping NativeElectronWorker.Authorise) throws -> [String: Any] {
        guard let session = currentSession(pid) else { throw NativeProviderHostFailure("native_electron_not_registered") }
        return try session.refreshForCapture(owner: owner, window: window, operation: operation,
            bundle: bundle, deadline: deadline, authorise: authorise)
    }
    func perform(pid: Int32, owner: NativeProviderOwner, window: UInt32, observation: String,
                 operation: String, bundle: String, method: String, arguments: [String: Any]) throws -> [String: Any] {
        guard let session = currentSession(pid) else { throw NativeProviderHostFailure("native_electron_not_registered") }
        return try session.perform(owner: owner, window: window, observation: observation, operation: operation,
            bundle: bundle, method: method, arguments: arguments)
    }

    struct PreparedKeyboard {
        let exchange: NativeElectronSession.PerformExchange
        let finalize: (Result<[String: Any], Error>) -> [String: Any]
        let release: () -> Void
    }
    /// Native lane only. Closures retain the original session even if its live
    /// registration is retired while the worker settles the original action.
    func preparePerform(pid: Int32, owner: NativeProviderOwner, window: UInt32, observation: String,
                        operation: String, bundle: String, method: String, arguments: [String: Any],
                        settled: @escaping () -> Void = {}) throws -> PreparedKeyboard {
        guard let session = currentSession(pid) else { throw NativeProviderHostFailure("native_electron_not_registered") }
        let prepared = try session.preparePerform(owner: owner, window: window, observation: observation,
            operation: operation, bundle: bundle, method: method, arguments: arguments, settled: settled)
        return PreparedKeyboard(exchange: prepared.exchange,
            finalize: { session.finalizePerform(prepared, response: $0) },
            release: { session.releasePerform(prepared) })
    }
}
