import Foundation
import AppKit
import Darwin
import Security

// Observations only: no sample can authorize an app, extend a claim or retry input.
final class NativeProcessDiagnostics {
    private struct Baseline {
        let id = UUID().uuidString
        let app: NativeAppIdentity
        let armedAt = Date().timeIntervalSince1970
        var sample: [String: Any] = ["sample_state": "pending"]
        var failureAt: Double?
        var failureSample: [String: Any] = ["sample_state": "pending"]
    }
    static let maximumTargets = 16
    static let maximumBytes = 32768
    private var baselines: [Baseline] = []
    private let collect: (NativeAppIdentity) -> [String: Any]
    private let lock = NSLock()
    private let queue = DispatchQueue(label: "workbench-native-identity-diagnostics")
    private let scheduler: ((@escaping () -> Void) -> Void)?
    init(collect: @escaping (NativeAppIdentity) -> [String: Any] = NativeProcessDiagnostics.sample,
         scheduler: ((@escaping () -> Void) -> Void)? = nil) {
        self.collect = collect
        self.scheduler = scheduler
    }
    // Called only after the host has successfully admitted an exact-window claim.
    func arm(_ app: NativeAppIdentity) {
        lock.lock()
        guard !baselines.contains(where: { $0.app == app }), baselines.count < Self.maximumTargets else { lock.unlock(); return }
        let index = baselines.count
        baselines.append(Baseline(app: app))
        lock.unlock()
        schedule { [self] in
            let sample = boundedSample(collect(app))
            lock.lock(); baselines[index].sample = sample; lock.unlock()
        }
    }
    private func schedule(_ action: @escaping () -> Void) {
        if let scheduler = scheduler { scheduler(action) }
        else { queue.async(execute: action) }
    }
    private func boundedSample(_ raw: [String: Any]) -> [String: Any] {
        // Preflight prevents Foundation from raising an Objective-C exception
        // for non-finite or unsupported values; Swift try? cannot catch that.
        let valid = JSONSerialization.isValidJSONObject(raw)
        let data = valid ? try? JSONSerialization.data(withJSONObject: raw) : nil
        let bounded = data.map { $0.count <= Self.maximumBytes / 4 } == true
        return bounded ? raw : ["sample_state": "unavailable_or_byte_limit"]
    }
    func firstFailure(_ app: NativeAppIdentity) -> String? {
        lock.lock()
        guard let index = baselines.firstIndex(where: { $0.app == app }), baselines[index].failureAt == nil else { lock.unlock(); return nil }
        // Retire before collecting; errors cannot cause another probe or effect replay.
        baselines[index].failureAt = Date().timeIntervalSince1970
        let id = baselines[index].id
        lock.unlock()
        schedule { [self] in
            let sample = boundedSample(collect(app))
            lock.lock(); baselines[index].failureSample = sample; lock.unlock()
        }
        // No OS or signing calls occur on this failure-return path. The later
        // sample timestamps must never be described as the failure instant.
        return "{\"scope\":\"diagnostic_only_not_authorization\",\"probe_id\":\"\(id)\",\"sample_state\":\"scheduled\"}"
    }
    func reports() -> [[String: Any]] {
        lock.lock(); let rows = baselines.filter { $0.failureAt != nil }; lock.unlock()
        return rows.map { entry in
            let row: [String: Any] = ["scope": "diagnostic_only_not_authorization", "probe_id": entry.id,
                "caller_pid": ProcessInfo.processInfo.processIdentifier, "armed_at": entry.armedAt,
                "failure_detected_at": entry.failureAt!, "expected_app": nativeDictionary(entry.app),
                "baseline": entry.sample, "later_failure_sample": entry.failureSample, "atomic_snapshot": false]
            guard let text = boundedReport(row) else {
                return ["probe_id": entry.id, "sample_state": "unavailable_or_byte_limit", "scope": "diagnostic_only_not_authorization"]
            }
            return ["probe_id": entry.id, "process_probe_json": text]
        }
    }
    private func boundedReport(_ row: [String: Any]) -> String? {
        guard JSONSerialization.isValidJSONObject(row),
              let data = try? JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]),
              data.count <= Self.maximumBytes, let text = String(data: data, encoding: .utf8) else {
            return nil
        }
        return text
    }
    static func kernel(_ pid: pid_t) -> [String: Any] {
        var info = proc_bsdinfo()
        errno = 0
        let count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        let infoError = errno
        // The SDK expression macro is 4*MAXPATHLEN; Swift does not import it.
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        errno = 0
        let pathCount = proc_pidpath(pid, &path, UInt32(path.count))
        let pathError = errno
        var row: [String: Any] = ["pid": pid, "at": Date().timeIntervalSince1970,
            "uptime": ProcessInfo.processInfo.systemUptime,
            "info_bytes": count, "expected_info_bytes": MemoryLayout<proc_bsdinfo>.size,
            "info_errno": infoError, "path_bytes": pathCount, "path_errno": pathError]
        if count == MemoryLayout<proc_bsdinfo>.size {
            row["returned_pid"] = info.pbi_pid; row["uid"] = info.pbi_uid; row["real_uid"] = info.pbi_ruid
            row["status"] = info.pbi_status; row["start_seconds"] = info.pbi_start_tvsec
            row["start_microseconds"] = info.pbi_start_tvusec
        }
        if pathCount > 0, let end = path.firstIndex(of: 0),
           let text = String(bytes: path[..<end].map { UInt8(bitPattern: $0) }, encoding: .utf8) { row["path"] = text }
        return row
    }
    static func sample(_ app: NativeAppIdentity) -> [String: Any] {
        var row: [String: Any] = ["at": Date().timeIntervalSince1970, "kernel_before": kernel(app.pid),
            "sample_main_thread": Thread.isMainThread]
        let running = NSRunningApplication(processIdentifier: app.pid)
        row["appkit_lookup_available"] = running != nil
        row["appkit_launch_date"] = running?.launchDate?.timeIntervalSince1970
        row["workspace_exact_pid_present"] = NSWorkspace.shared.runningApplications.contains { $0.processIdentifier == app.pid }
        var code: SecCode?
        let guest = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: NSNumber(value: app.pid)] as CFDictionary, [], &code)
        row["guest_status"] = guest
        if guest == errSecSuccess, let code = code {
            row["dynamic_validity_status"] = SecCodeCheckValidity(code, [], nil)
            if let expected = app.designatedRequirement {
                var requirement: SecRequirement?
                let parsed = SecRequirementCreateWithString(expected as CFString, [], &requirement)
                row["expected_requirement_parse_status"] = parsed
                if parsed == errSecSuccess, let requirement = requirement {
                    row["dynamic_expected_requirement_status"] = SecCodeCheckValidity(code, [], requirement)
                }
            }
            var origin: SecStaticCode?
            let originStatus = SecCodeCopyStaticCode(code, [], &origin)
            row["origin_status"] = originStatus
            // SecCodeCopyStaticCode is not a secure link by itself. These disk-origin
            // observations remain diagnostic, independently of dynamic validity.
            if originStatus == errSecSuccess, let origin = origin {
                var raw: CFDictionary?
                let infoStatus = SecCodeCopySigningInformation(origin, SecCSFlags(rawValue: kSecCSSigningInformation), &raw)
                row["signing_info_status"] = infoStatus
                if infoStatus == errSecSuccess, let info = raw as? [String: Any] {
                    row["signing_identifier"] = info[kSecCodeInfoIdentifier as String] as? String
                    row["team_id"] = info[kSecCodeInfoTeamIdentifier as String] as? String
                    row["signing_main_executable"] = (info[kSecCodeInfoMainExecutable as String] as? URL)?.path
                    row["code_unique"] = (info[kSecCodeInfoUnique as String] as? Data)?.map { String(format: "%02x", $0) }.joined()
                    row["sealed_bundle_id"] = (info[kSecCodeInfoPList as String] as? [String: Any])?["CFBundleIdentifier"] as? String
                }
            }
        }
        row["kernel_after"] = kernel(app.pid)
        return row
    }
}
