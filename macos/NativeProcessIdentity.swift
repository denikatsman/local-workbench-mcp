import Foundation
import Darwin
import Security
import WorkbenchProcessSupport

struct NativeProcessSnapshot: Equatable {
    let audit: Data
    let pid: Int32, version: Int32
    let uid: UInt32, realUID: UInt32
    let startSeconds: UInt64, startMicroseconds: UInt64
    let executable: String
}
// launchDate is optional presentation metadata. Only host identification with
// an already acquired authoritative snapshot may use a kernel birth fallback.
// This Double never replaces the exact audit/version/UInt64 birth in the proof.
enum NativeProcessLaunchTimestamp {
    static func resolve(observed: Double?, pid: Int32, executable: String,
                        before: NativeProcessSnapshot?) throws -> Double {
        if let observed = observed {
            guard observed.isFinite, observed > 0 else {
                throw NativeProcessIdentityFailure("process_launch_timestamp_invalid")
            }
            return observed // Preserve ordinary AppKit dates exactly.
        }
        guard let before = before else {
            throw NativeProcessIdentityFailure("process_launch_kernel_metadata_unavailable")
        }
        guard pid > 0, before.pid == pid, before.executable == executable, executable.hasPrefix("/"),
              before.startSeconds > 0, before.startMicroseconds < 1000000,
              UInt64(exactly: Double(before.startSeconds)) != nil,
              before.uid == geteuid(), before.realUID == getuid(),
              before.audit.count == MemoryLayout<audit_token_t>.size else {
            throw NativeProcessIdentityFailure("process_launch_kernel_metadata_invalid")
        }
        var token = audit_token_t()
        _ = withUnsafeMutableBytes(of: &token) { before.audit.copyBytes(to: $0) }
        guard audit_token_to_pid(token) == pid, audit_token_to_pidversion(token) == before.version,
              audit_token_to_euid(token) == before.uid, audit_token_to_ruid(token) == before.realUID else {
            throw NativeProcessIdentityFailure("process_launch_kernel_metadata_invalid")
        }
        return Double(before.startSeconds) + Double(before.startMicroseconds) / 1000000
    }
}
struct NativeProcessRegistration: Equatable {
    let unique: Data, flags: UInt32
}
struct NativeProcessSignature: Equatable {
    let identifier: String, team: String?, requirement: String
    let unique: Data, flags: UInt32
    let bundlePath: String, executable: String, bundleID: String
    var registration: NativeProcessRegistration? = nil
}
struct NativeProcessIdentityFailure: Error {
    let diagnostic: NativeIdentityDiagnostic
    init(_ stage: String, status: Int32? = nil, fields: [String] = []) {
        diagnostic = NativeIdentityDiagnostic(stage: stage, status: status, fields: fields)
    }
}
protocol NativeProcessIdentityProvider {
    func snapshot(_ pid: Int32) throws -> NativeProcessSnapshot
    func signature(_ app: NativeAppIdentity, snapshot: NativeProcessSnapshot) throws -> NativeProcessSignature?
    func legacyMetadata(_ pid: Int32) -> NativeAppIdentity?
}

final class NativeProcessIdentityStore {
    struct Proof {
        let snapshot: NativeProcessSnapshot
        let signature: NativeProcessSignature?
    }
    private let provider: NativeProcessIdentityProvider
    private let cache: NativeBindingCache<NativeAppIdentity, Proof>
    init(provider: NativeProcessIdentityProvider, limit: Int = 100) {
        self.provider = provider
        cache = NativeBindingCache(limit: limit, failure: "native_process_identity_capacity",
            same: { $0.snapshot == $1.snapshot && $0.signature == $1.signature })
    }
    func initialSnapshot(_ pid: Int32) throws -> NativeProcessSnapshot { try provider.snapshot(pid) }
    // Only the host's identify(NSRunningApplication) path calls issue. Neither
    // matches nor an opaque ID supplied by a client can create/replace a proof.
    func issue(_ observed: NativeAppIdentity, before: NativeProcessSnapshot) throws -> NativeAppIdentity {
        guard observed.processGeneration == nil, observed.pid == before.pid else {
            throw NativeProcessIdentityFailure("process_initial_identity_changed")
        }
        let signature = try provider.signature(observed, snapshot: before)
        if let signature = signature {
            guard signature.executable == before.executable,
                  observed.executable == before.executable || signature.registration != nil else {
                throw NativeProcessIdentityFailure("process_initial_identity_changed")
            }
        } else {
            guard observed.executable == before.executable else {
                throw NativeProcessIdentityFailure("process_initial_identity_changed")
            }
            guard provider.legacyMetadata(observed.pid) == observed else { throw NativeProcessIdentityFailure("legacy_app_identity_unavailable") }
        }
        guard try provider.snapshot(observed.pid) == before else { throw NativeProcessIdentityFailure("process_changed_during_identity") }
        var issued = observed
        issued.processGeneration = try cache.identifier(Proof(snapshot: before, signature: signature), owner: observed)
        return issued
    }
    func verify(_ app: NativeAppIdentity, full: Bool = true) throws {
        guard let id = app.processGeneration, let entry = cache.entry(id) else {
            throw NativeProcessIdentityFailure("process_proof_unavailable")
        }
        var metadata = app; metadata.processGeneration = nil
        guard metadata == entry.owner else { throw NativeProcessIdentityFailure("process_proof_owner_mismatch") }
        do {
            guard try provider.snapshot(app.pid) == entry.element.snapshot else {
                throw NativeProcessIdentityFailure("process_generation_changed")
            }
            if full {
                if let expected = entry.element.signature {
                    guard try provider.signature(metadata, snapshot: entry.element.snapshot) == expected else {
                        throw NativeProcessIdentityFailure("dynamic_code_identity_changed")
                    }
                } else {
                    // Preserve the original unsigned/unknown-signature route,
                    // but require fresh AppKit metadata as well as audit binding.
                    guard provider.legacyMetadata(app.pid) == metadata else {
                        throw NativeProcessIdentityFailure("legacy_app_identity_unavailable")
                    }
                }
                guard try provider.snapshot(app.pid) == entry.element.snapshot else {
                    throw NativeProcessIdentityFailure("process_changed_during_identity")
                }
            }
            guard let current = cache.entry(id), current.owner == entry.owner,
                  current.element.snapshot == entry.element.snapshot,
                  current.element.signature == entry.element.signature else {
                throw NativeProcessIdentityFailure("process_proof_retired_during_check")
            }
        } catch {
            // A later successful read cannot resurrect this generation. Fresh
            // host discovery must issue another proof and different window owner.
            cache.invalidate(id)
            throw error
        }
    }
    func retain(_ apps: [NativeAppIdentity]) { cache.retain(Set(apps.compactMap(\.processGeneration))) }
    func beginBatch() -> UUID { cache.beginBatch() }
    func endBatch(_ id: UUID) { cache.endBatch(id) }
}

final class NativeSystemProcessIdentity: NativeProcessIdentityProvider {
    let metadata: (Int32) -> NativeAppIdentity?
    init(metadata: @escaping (Int32) -> NativeAppIdentity?) { self.metadata = metadata }
    func legacyMetadata(_ pid: Int32) -> NativeAppIdentity? { metadata(pid) }
    private func token(_ pid: Int32) throws -> audit_token_t {
        var port: mach_port_name_t = 0
        let lookup = task_name_for_pid(mach_task_self_, pid, &port)
        guard lookup == KERN_SUCCESS, port != 0 else { throw NativeProcessIdentityFailure("process_audit_port_unavailable", status: lookup) }
        defer { mach_port_deallocate(mach_task_self_, port) }
        var value = audit_token_t()
        let expected = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        var count = expected
        let status = withUnsafeMutablePointer(to: &value) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(expected)) {
                task_info(port, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        guard status == KERN_SUCCESS, count == expected, audit_token_to_pid(value) == pid else {
            throw NativeProcessIdentityFailure("process_audit_unavailable", status: status)
        }
        return value
    }
    private func bytes(_ value: audit_token_t) -> Data {
        var value = value; return withUnsafeBytes(of: &value) { Data($0) }
    }
    func snapshot(_ pid: Int32) throws -> NativeProcessSnapshot {
        guard pid > 0 else { throw NativeProcessIdentityFailure("process_pid_invalid") }
        var first = try token(pid)
        var info = proc_bsdinfo()
        errno = 0
        let count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        guard count == MemoryLayout<proc_bsdinfo>.size else { throw NativeProcessIdentityFailure("process_kernel_unavailable", status: errno) }
        // Public sys/proc.h: running, sleeping and stopped are live; creation
        // and zombie states never become a positive identity observation.
        guard [UInt32(SRUN), UInt32(SSLEEP), UInt32(SSTOP)].contains(info.pbi_status),
              info.pbi_pid == UInt32(pid), info.pbi_start_tvsec > 0, info.pbi_start_tvusec < 1000000,
              info.pbi_uid == geteuid(), info.pbi_ruid == getuid(),
              audit_token_to_euid(first) == info.pbi_uid, audit_token_to_ruid(first) == info.pbi_ruid else {
            throw NativeProcessIdentityFailure("process_kernel_identity_invalid")
        }
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        errno = 0
        let length = proc_pidpath_audittoken(&first, &path, UInt32(path.count))
        guard length > 0, length < path.count, let end = path.firstIndex(of: 0), end == Int(length),
              let executable = String(bytes: path[..<end].map { UInt8(bitPattern: $0) }, encoding: .utf8) else {
            throw NativeProcessIdentityFailure("process_path_unavailable", status: errno)
        }
        let last = try token(pid)
        guard bytes(first) == bytes(last) else { throw NativeProcessIdentityFailure("process_changed_during_snapshot") }
        return NativeProcessSnapshot(audit: bytes(first), pid: pid, version: audit_token_to_pidversion(first),
            uid: info.pbi_uid, realUID: info.pbi_ruid, startSeconds: info.pbi_start_tvsec,
            startMicroseconds: info.pbi_start_tvusec, executable: executable)
    }
    func signature(_ app: NativeAppIdentity, snapshot: NativeProcessSnapshot) throws -> NativeProcessSignature? {
        if app.signingIdentifier == nil && app.designatedRequirement == nil { return nil }
        guard let expectedID = app.signingIdentifier, let expectedRequirement = app.designatedRequirement,
              !expectedID.isEmpty, !expectedRequirement.isEmpty else { throw NativeProcessIdentityFailure("signing_identity_incomplete") }
        var code: SecCode?
        let guestStatus = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit as String: snapshot.audit] as CFDictionary, [], &code)
        guard guestStatus == errSecSuccess, let code = code else { throw NativeProcessIdentityFailure("dynamic_code_unavailable", status: guestStatus) }
        var requirement: SecRequirement?
        let requirementStatus = SecRequirementCreateWithString(expectedRequirement as CFString, [], &requirement)
        guard requirementStatus == errSecSuccess, let requirement = requirement else { throw NativeProcessIdentityFailure("dynamic_requirement_unavailable", status: requirementStatus) }
        let validity = SecCodeCheckValidity(code, [], requirement)
        guard validity == errSecSuccess else { throw NativeProcessIdentityFailure("dynamic_code_invalid", status: validity) }
        var raw: CFDictionary?, path: CFURL?, canonical: SecRequirement?
        let infoStatus = WB_CopyDynamicSigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &raw)
        let pathStatus = WB_CopyDynamicPath(code, [], &path)
        let canonicalStatus = WB_CopyDynamicRequirement(code, [], &canonical)
        guard infoStatus == errSecSuccess, let info = raw as? [String: Any], pathStatus == errSecSuccess,
              let bundlePath = (path as URL?)?.path, canonicalStatus == errSecSuccess, let canonical = canonical else {
            throw NativeProcessIdentityFailure("dynamic_metadata_unavailable", status: infoStatus != 0 ? infoStatus : pathStatus != 0 ? pathStatus : canonicalStatus)
        }
        let live = try Self.signingMetadata(info, bundlePath: bundlePath, canonical: canonical)
        var registration: NativeProcessSignature?
        var publisherQualified = false
        if live.bundlePath != app.bundlePath || live.executable != app.executable {
            // A path alias is accepted only for valid Apple-rooted code on both
            // sides. A self-signed/ad-hoc lookalike cannot nominate a registration.
            var publisher: SecRequirement?
            let publisherStatus = SecRequirementCreateWithString("anchor apple generic" as CFString, [], &publisher)
            guard publisherStatus == errSecSuccess, let publisher = publisher,
                  SecCodeCheckValidity(code, [], publisher) == errSecSuccess else {
                throw NativeProcessIdentityFailure("dynamic_alias_publisher_unqualified", status: publisherStatus)
            }
            registration = try canonicalMetadata(app, requirement: requirement, publisher: publisher)
            publisherQualified = true
        }
        let qualified = try Self.qualify(live, app: app, snapshot: snapshot,
                                         canonical: registration, publisherQualified: publisherQualified)
        let afterValidity = SecCodeCheckValidity(code, [], requirement)
        guard afterValidity == errSecSuccess else { throw NativeProcessIdentityFailure("dynamic_code_changed_during_metadata", status: afterValidity) }
        if let registration = registration {
            // Recreate the static object: checking a previously acquired object
            // alone can miss replacement at the canonical registration path.
            var publisher: SecRequirement?
            let status = SecRequirementCreateWithString("anchor apple generic" as CFString, [], &publisher)
            guard status == errSecSuccess, let publisher = publisher,
                  try canonicalMetadata(app, requirement: requirement, publisher: publisher) == registration else {
                throw NativeProcessIdentityFailure("canonical_code_changed_during_metadata")
            }
        }
        return qualified
    }
    private func canonicalMetadata(_ app: NativeAppIdentity, requirement: SecRequirement,
                                   publisher: SecRequirement) throws -> NativeProcessSignature {
        var registered: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(URL(fileURLWithPath: app.bundlePath) as CFURL, [], &registered)
        guard createStatus == errSecSuccess, let registered = registered,
              SecStaticCodeCheckValidity(registered, [], requirement) == errSecSuccess,
              SecStaticCodeCheckValidity(registered, [], publisher) == errSecSuccess else {
            throw NativeProcessIdentityFailure("canonical_code_invalid", status: createStatus)
        }
        var registeredInfo: CFDictionary?, registeredPath: CFURL?, registeredRequirement: SecRequirement?
        let registeredInfoStatus = SecCodeCopySigningInformation(registered, SecCSFlags(rawValue: kSecCSSigningInformation), &registeredInfo)
        let registeredPathStatus = SecCodeCopyPath(registered, [], &registeredPath)
        let registeredRequirementStatus = SecCodeCopyDesignatedRequirement(registered, [], &registeredRequirement)
        guard registeredInfoStatus == errSecSuccess, let registeredInfo = registeredInfo as? [String: Any],
              registeredPathStatus == errSecSuccess, let registeredPath = (registeredPath as URL?)?.path,
              registeredRequirementStatus == errSecSuccess, let registeredRequirement = registeredRequirement else {
            throw NativeProcessIdentityFailure("canonical_metadata_unavailable")
        }
        let registration = try Self.signingMetadata(registeredInfo, bundlePath: registeredPath, canonical: registeredRequirement)
        guard SecStaticCodeCheckValidity(registered, [], requirement) == errSecSuccess,
              SecStaticCodeCheckValidity(registered, [], publisher) == errSecSuccess else {
            throw NativeProcessIdentityFailure("canonical_code_changed_during_metadata")
        }
        return registration
    }
    // This compares trusted host observations only. Client metadata never enters
    // issuance. The live path is kernel/audit-bound; the canonical path is the
    // independent AppKit registration, freshly read as valid signed static code.
    static func qualify(_ live: NativeProcessSignature, app: NativeAppIdentity,
                        snapshot: NativeProcessSnapshot, canonical: NativeProcessSignature? = nil,
                        publisherQualified: Bool = false) throws -> NativeProcessSignature {
        func sameIdentity(_ value: NativeProcessSignature) -> Bool {
            value.identifier == app.signingIdentifier && value.team == app.teamID &&
            value.requirement == app.designatedRequirement && value.bundleID == app.bundleID
        }
        guard sameIdentity(live), live.executable == snapshot.executable else {
            throw NativeProcessIdentityFailure("dynamic_metadata_changed")
        }
        if live.bundlePath == app.bundlePath && live.executable == app.executable { return live }
        guard publisherQualified, let canonical = canonical, sameIdentity(canonical),
              canonical.bundlePath == app.bundlePath, canonical.executable == app.executable,
              app.executable.hasPrefix(app.bundlePath + "/"), live.bundlePath.hasPrefix("/"),
              live.executable == live.bundlePath + String(app.executable.dropFirst(app.bundlePath.count)) else {
            throw NativeProcessIdentityFailure("dynamic_registration_unqualified")
        }
        var qualified = live
        qualified.registration = NativeProcessRegistration(unique: canonical.unique, flags: canonical.flags)
        return qualified
    }
    // Require signing-subsystem metadata; an ordinary bundle Info.plist is not
    // an authenticated replacement when the secured plist is absent.
    static func signingMetadata(_ info: [String: Any], bundlePath: String,
                                canonical: SecRequirement) throws -> NativeProcessSignature {
        var text: CFString?
        let textStatus = SecRequirementCopyString(canonical, [], &text)
        let requirementText = text as String?
        let identifier = info[kSecCodeInfoIdentifier as String] as? String
        let executable = (info[kSecCodeInfoMainExecutable as String] as? URL)?.path
        let plist = info[kSecCodeInfoPList as String] as? [String: Any]
        let bundleID = plist?["CFBundleIdentifier"] as? String
        let unique = info[kSecCodeInfoUnique as String] as? Data
        let flags = info[kSecCodeInfoFlags as String] as? NSNumber
        let validUnique = unique.map { !$0.isEmpty && $0.count <= 256 } == true
        let validFlags = flags.map {
            CFGetTypeID($0) != CFBooleanGetTypeID() && $0.doubleValue.isFinite &&
            $0.doubleValue >= 0 && $0.doubleValue <= Double(UInt32.max) &&
            $0.doubleValue.rounded() == $0.doubleValue
        } == true
        var fields: [String] = []
        if textStatus != errSecSuccess || requirementText == nil { fields.append("designated_requirement") }
        if identifier == nil { fields.append("signing_identifier") }
        if executable == nil { fields.append("executable") }
        if plist == nil { fields.append("secured_info_plist") }
        else if bundleID == nil { fields.append("secured_bundle_id") }
        if !validUnique { fields.append("code_unique") }
        if !validFlags { fields.append("signature_flags") }
        guard fields.isEmpty, let requirementText = requirementText, let identifier = identifier,
              let executable = executable, let bundleID = bundleID, let unique = unique,
              let flags = flags else {
            throw NativeProcessIdentityFailure("dynamic_metadata_incomplete", status: textStatus, fields: fields)
        }
        let team = info[kSecCodeInfoTeamIdentifier as String] as? String
        return NativeProcessSignature(identifier: identifier, team: team, requirement: requirementText,
            unique: unique, flags: flags.uint32Value, bundlePath: bundlePath, executable: executable, bundleID: bundleID)
    }
}
