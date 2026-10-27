import Foundation
import Security
import Darwin

// Security/CSCommon.h SecCodeSignatureFlags values. These are static signing
// flags, not the dynamic kernel CS_* status word.
enum NativeProviderSignatureFlags {
    static let adHoc: UInt32 = 0x0002
    static let restrict: UInt32 = 0x0800
    static let libraryValidation: UInt32 = 0x2000
    static let runtime: UInt32 = 0x10000
    static let linkerSigned: UInt32 = 0x20000
}

// Static eligibility is a launch prerequisite, never proof that a bridge loaded.
// Reinspect both paths and compare the full pins immediately before launch. The
// resulting process still needs the authenticated PID/birth/helper handshake.
enum NativeProviderAdmissionState: String, Codable {
    case eligibleForLaunchTrial = "eligible_for_launch_trial"
    case unsupported, unverified
}
struct NativeProviderAdmissionDecision: Codable, Equatable {
    let state: NativeProviderAdmissionState
    let prerequisites: [String]
    let authenticatedHandshakeRequired: Bool
    init(_ state: NativeProviderAdmissionState, _ prerequisites: [String]) {
        self.state = state; self.prerequisites = prerequisites
        authenticatedHandshakeRequired = true
    }
}
enum NativeProviderBoolean: String, Codable {
    case absent, enabled, disabled, malformed, unavailable
    static func read(_ dictionary: [String: Any], _ key: String) -> Self {
        guard let value = dictionary[key] else { return .absent }
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return .malformed }
        return number.boolValue ? .enabled : .disabled
    }
}
struct NativeProviderEntitlements: Codable, Equatable {
    let allowDYLD: NativeProviderBoolean
    let disableLibraryValidation: NativeProviderBoolean
    let sandbox: NativeProviderBoolean
    static func read(_ information: [String: Any]) -> Self {
        let key = kSecCodeInfoEntitlementsDict as String
        let blobKey = kSecCodeInfoEntitlements as String
        let values: [String: Any]
        if let raw = information[key] {
            guard let dictionary = raw as? [String: Any] else {
                return Self(allowDYLD: .malformed, disableLibraryValidation: .malformed, sandbox: .malformed)
            }
            values = dictionary
        } else {
            // A blob without a standard dictionary is unknown, not absent.
            if information[blobKey] != nil {
                return Self(allowDYLD: .unavailable, disableLibraryValidation: .unavailable, sandbox: .unavailable)
            }
            values = [:]
        }
        return Self(allowDYLD: .read(values, "com.apple.security.cs.allow-dyld-environment-variables"),
                    disableLibraryValidation: .read(values, "com.apple.security.cs.disable-library-validation"),
                    sandbox: .read(values, "com.apple.security.app-sandbox"))
    }
}
struct NativeProviderFilePin: Codable, Equatable {
    let device: UInt64, inode: UInt64, size: Int64
    let modifiedSeconds: Int64, modifiedNanoseconds: Int64
    let mode: UInt32
}
struct NativeProviderAdmissionMetadata: Codable, Equatable {
    enum Kind: String, Codable { case target, helper, plugin }
    enum Signature: String, Codable { case valid, invalid, unsigned, unavailable }
    let inspectionSource = "Security.framework static-code APIs and bounded Mach-O headers; no dynamic admission proof"
    let kind: Kind
    let bundlePath: String?
    let executablePath: String
    let bundleIdentifier: String?
    let signingIdentifier: String
    let teamIdentifier: String?
    let designatedRequirement: String
    let cdHash: String
    let flags: UInt32
    let platformIdentifier: UInt32?
    let signature: Signature
    let entitlements: NativeProviderEntitlements
    let filePin: NativeProviderFilePin
    // Restriction segments and privilege bits also constrain DYLD loading.
    let restrictedMachO: Bool?
    var hardenedRuntime: Bool { flags & NativeProviderSignatureFlags.runtime != 0 }
    var requiresLibraryValidation: Bool { hardenedRuntime || flags & NativeProviderSignatureFlags.libraryValidation != 0 }
}
struct NativeProviderInspectionFailure: Error {
    let reason: String
    let status: OSStatus?
    let state: NativeProviderAdmissionState
    init(_ reason: String, status: OSStatus? = nil, state: NativeProviderAdmissionState = .unverified) {
        self.reason = reason; self.status = status; self.state = state
    }
    var decision: NativeProviderAdmissionDecision { NativeProviderAdmissionDecision(state, [reason]) }
}

enum NativeProviderAdmissionPolicy {
    static func evaluate(target: NativeProviderAdmissionMetadata, helper: NativeProviderAdmissionMetadata,
                         pinnedTarget: NativeProviderAdmissionMetadata? = nil,
                         pinnedHelper: NativeProviderAdmissionMetadata? = nil) -> NativeProviderAdmissionDecision {
        guard target.kind == .target, helper.kind == .helper else { return .init(.unverified, ["identity_kind_mismatch"]) }
        if let pin = pinnedTarget, pin != target { return .init(.unverified, ["target_identity_changed"]) }
        if let pin = pinnedHelper, pin != helper { return .init(.unverified, ["helper_identity_changed"]) }
        for (name, code) in [("target", target), ("helper", helper)] {
            guard code.signature == .valid else {
                return .init(code.signature == .unsigned || code.signature == .invalid ? .unsupported : .unverified,
                             ["\(name)_signature_\(code.signature.rawValue)"])
            }
            func normalizedPath(_ path: String) -> Bool {
                path.hasPrefix("/") && !path.utf8.contains(0) && path.utf8.count <= 4096 &&
                    URL(fileURLWithPath: path).standardizedFileURL.path == path
            }
            guard normalizedPath(code.executablePath), code.bundlePath.map(normalizedPath) ?? true,
                  !code.signingIdentifier.isEmpty, code.signingIdentifier.utf8.count <= 512,
                  !code.designatedRequirement.isEmpty, code.designatedRequirement.utf8.count <= 16384,
                  code.cdHash.count >= 40, code.cdHash.count <= 128, code.cdHash.count % 2 == 0,
                  code.cdHash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                return .init(.unverified, ["\(name)_identity_incomplete"])
            }
            guard code.flags & (NativeProviderSignatureFlags.adHoc | NativeProviderSignatureFlags.linkerSigned) == 0 else {
                return .init(.unsupported, ["\(name)_ad_hoc_or_linker_signature"])
            }
            guard let team = code.teamIdentifier, !team.isEmpty else { return .init(.unverified, ["\(name)_team_unavailable"]) }
            guard code.platformIdentifier == nil || code.platformIdentifier == 0 else { return .init(.unsupported, ["\(name)_platform_code"]) }
            guard let restricted = code.restrictedMachO else { return .init(.unverified, ["\(name)_restriction_metadata_unavailable"]) }
            guard !restricted, code.flags & NativeProviderSignatureFlags.restrict == 0,
                  code.filePin.mode & UInt32(S_ISUID | S_ISGID) == 0 else { return .init(.unsupported, ["\(name)_restricted_code"]) }
            let fields = [code.entitlements.allowDYLD, code.entitlements.disableLibraryValidation, code.entitlements.sandbox]
            guard !fields.contains(.malformed), !fields.contains(.unavailable) else { return .init(.unverified, ["\(name)_entitlements_unverified"]) }
            guard code.entitlements.sandbox != .enabled else { return .init(.unsupported, ["\(name)_sandbox_loading_path_required"]) }
        }
        guard let bundlePath = target.bundlePath, bundlePath.hasSuffix(".app"),
              target.executablePath.hasPrefix(bundlePath + "/Contents/MacOS/"),
              let bundleID = target.bundleIdentifier, !bundleID.isEmpty, bundleID.utf8.count <= 512,
              helper.bundlePath == nil, helper.bundleIdentifier == nil else {
            return .init(.unverified, ["target_or_helper_bundle_identity_incomplete"])
        }
        var missing: [String] = []
        if target.hardenedRuntime && target.entitlements.allowDYLD != .enabled {
            missing.append("target_existing_allow_dyld_environment_variables_required")
        }
        // This bounded provider supports same-Team code or an explicit existing
        // cross-Team exception. It does not infer foreign-library permission from
        // a non-hardened executable or from absent library-validation flags.
        if target.teamIdentifier != helper.teamIdentifier && target.entitlements.disableLibraryValidation != .enabled {
            missing.append("target_existing_disable_library_validation_required_for_foreign_team")
        }
        return missing.isEmpty ? .init(.eligibleForLaunchTrial, []) : .init(.unsupported, missing)
    }

    // A separate, bounded vendor route. The legacy evaluator above retains all
    // DYLD requirements. Metadata alone can never approve this plugin route.
    static func evaluateTextMatePlugin(target: NativeProviderAdmissionMetadata,
                                       helper: NativeProviderAdmissionMetadata,
                                       plugin: NativeProviderAdmissionMetadata) -> NativeProviderAdmissionDecision {
        guard target.kind == .target, helper.kind == .helper, plugin.kind == .plugin else {
            return .init(.unverified, ["identity_kind_mismatch"])
        }
        guard target.bundleIdentifier == "com.macromates.TextMate",
              target.signingIdentifier == "com.macromates.TextMate", target.teamIdentifier == "45TL96F76G" else {
            return .init(.unsupported, ["textmate_exact_vendor_identity_required"])
        }
        guard target.hardenedRuntime, target.entitlements.disableLibraryValidation == .enabled else {
            return .init(.unsupported, ["textmate_existing_hardened_library_validation_exception_required"])
        }
        let legacy = evaluate(target: target, helper: helper)
        // Reuse every existing target/helper refusal except the one prerequisite
        // specific to the different loader. Do not synthesize altered metadata.
        guard legacy.state == .eligibleForLaunchTrial ||
              (legacy.state == .unsupported && legacy.prerequisites == ["target_existing_allow_dyld_environment_variables_required"]) else {
            return legacy
        }
        guard plugin.signature == .valid else {
            return .init(plugin.signature == .invalid || plugin.signature == .unsigned ? .unsupported : .unverified,
                         ["plugin_signature_\(plugin.signature.rawValue)"])
        }
        guard let bundle = plugin.bundlePath, bundle.hasSuffix(".tmplugin"),
              plugin.executablePath.hasPrefix(bundle + "/Contents/MacOS/"),
              [bundle, plugin.executablePath].allSatisfy({
                  $0.hasPrefix("/") && !$0.utf8.contains(0) && $0.utf8.count <= 4096 &&
                      URL(fileURLWithPath: $0).standardizedFileURL.path == $0
              }), !plugin.designatedRequirement.isEmpty, plugin.designatedRequirement.utf8.count <= 16384,
              plugin.cdHash.count >= 40, plugin.cdHash.count <= 128, plugin.cdHash.count % 2 == 0,
              plugin.cdHash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            return .init(.unverified, ["plugin_identity_incomplete"])
        }
        guard plugin.bundleIdentifier == "tools.localworkbench.textmate.receiver",
              plugin.signingIdentifier == "tools.localworkbench.textmate.receiver",
              plugin.teamIdentifier == helper.teamIdentifier else {
            return .init(.unsupported, ["plugin_approved_identity_and_helper_team_required"])
        }
        guard plugin.flags & (NativeProviderSignatureFlags.adHoc | NativeProviderSignatureFlags.linkerSigned) == 0 else {
            return .init(.unsupported, ["plugin_ad_hoc_or_linker_signature"])
        }
        guard plugin.platformIdentifier == nil || plugin.platformIdentifier == 0 else {
            return .init(.unsupported, ["plugin_platform_code"])
        }
        guard let restricted = plugin.restrictedMachO else {
            return .init(.unverified, ["plugin_restriction_metadata_unavailable"])
        }
        guard !restricted, plugin.flags & NativeProviderSignatureFlags.restrict == 0,
              plugin.filePin.mode & UInt32(S_ISUID | S_ISGID) == 0 else {
            return .init(.unsupported, ["plugin_restricted_code"])
        }
        let fields = [plugin.entitlements.allowDYLD, plugin.entitlements.disableLibraryValidation, plugin.entitlements.sandbox]
        guard !fields.contains(.malformed), !fields.contains(.unavailable) else {
            return .init(.unverified, ["plugin_entitlements_unverified"])
        }
        guard plugin.entitlements.sandbox != .enabled else {
            return .init(.unsupported, ["plugin_sandbox_loading_path_required"])
        }
        let inspector = NativeProviderAdmissionInspector()
        for (name, code) in [("target", target), ("helper", helper), ("plugin", plugin)] {
            do { try inspector.verifyCurrentDeveloperID(code) }
            catch let error as NativeProviderInspectionFailure {
                return .init(error.state, ["\(name)_\(error.reason)"])
            } catch { return .init(.unverified, ["\(name)_developer_id_verification_unavailable"]) }
        }
        return .init(.eligibleForLaunchTrial, [])
    }
}

final class NativeProviderAdmissionInspector {
    func inspectTarget(bundlePath: String, expectedBundleID: String? = nil,
                       expectedExecutable: String? = nil) throws -> NativeProviderAdmissionMetadata {
        try inspect(path: bundlePath, kind: .target, expectedBundleID: expectedBundleID, expectedExecutable: expectedExecutable)
    }
    func inspectHelper(executablePath: String) throws -> NativeProviderAdmissionMetadata {
        try inspect(path: executablePath, kind: .helper, expectedBundleID: nil, expectedExecutable: executablePath)
    }
    func inspectPlugin(bundlePath: String, expectedBundleID: String? = nil,
                       expectedExecutable: String? = nil) throws -> NativeProviderAdmissionMetadata {
        try inspect(path: bundlePath, kind: .plugin, expectedBundleID: expectedBundleID, expectedExecutable: expectedExecutable)
    }
    // Check an actual Security object against Apple's Developer ID certificate
    // chain, bind that object's identity to the pin, then repeat fresh inspection.
    // A designated-requirement string or claimed Team is never anchor proof.
    func verifyCurrentDeveloperID(_ pin: NativeProviderAdmissionMetadata) throws {
        func current() throws -> NativeProviderAdmissionMetadata {
            switch pin.kind {
            case .target:
                guard let path = pin.bundlePath else { throw NativeProviderInspectionFailure("bundle_identity_unavailable") }
                return try inspectTarget(bundlePath: path, expectedBundleID: pin.bundleIdentifier, expectedExecutable: pin.executablePath)
            case .plugin:
                guard let path = pin.bundlePath else { throw NativeProviderInspectionFailure("bundle_identity_unavailable") }
                return try inspectPlugin(bundlePath: path, expectedBundleID: pin.bundleIdentifier, expectedExecutable: pin.executablePath)
            case .helper: return try inspectHelper(executablePath: pin.executablePath)
            }
        }
        guard try current() == pin else { throw NativeProviderInspectionFailure("identity_changed") }
        func quoted(_ value: String) -> String {
            "\"" + value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        guard let team = pin.teamIdentifier, !team.isEmpty else { throw NativeProviderInspectionFailure("team_unavailable") }
        let source = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and identifier " + quoted(pin.signingIdentifier) + " and certificate leaf[subject.OU] = " + quoted(team)
        var requirement: SecRequirement?, code: SecStaticCode?
        guard SecRequirementCreateWithString(source as CFString, [], &requirement) == errSecSuccess,
              let requirement = requirement,
              SecStaticCodeCreateWithPath(URL(fileURLWithPath: pin.bundlePath ?? pin.executablePath) as CFURL, [], &code) == errSecSuccess,
              let code = code else { throw NativeProviderInspectionFailure("developer_id_verification_unavailable") }
        let status = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), requirement)
        guard status == errSecSuccess else {
            throw NativeProviderInspectionFailure("developer_id_anchor_refused", status: status, state: .unsupported)
        }
        var raw: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation), &raw) == errSecSuccess,
              let info = raw as? [String: Any], let hash = info[kSecCodeInfoUnique as String] as? Data,
              hash.map({ String(format: "%02x", $0) }).joined() == pin.cdHash,
              info[kSecCodeInfoIdentifier as String] as? String == pin.signingIdentifier,
              info[kSecCodeInfoTeamIdentifier as String] as? String == pin.teamIdentifier,
              let executable = info[kSecCodeInfoMainExecutable as String] as? URL,
              try canonical(executable.path) == pin.executablePath,
              try current() == pin else { throw NativeProviderInspectionFailure("identity_changed_during_anchor_verification") }
    }
    private func canonical(_ path: String) throws -> String {
        guard path.hasPrefix("/"), !path.utf8.contains(0), path.utf8.count <= 4096 else { throw NativeProviderInspectionFailure("path_invalid") }
        return URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath().path
    }
    private func bounded(_ raw: Any?, _ limit: Int = 4096) -> String? {
        guard let value = raw as? String, !value.isEmpty, !value.utf8.contains(0), value.utf8.count <= limit else { return nil }
        return value
    }
    private func unsignedNumber(_ raw: Any?) -> UInt32? {
        guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite, number.doubleValue >= 0, number.doubleValue <= Double(UInt32.max),
              number.doubleValue.rounded() == number.doubleValue else { return nil }
        return number.uint32Value
    }
    private func pin(_ path: String) throws -> NativeProviderFilePin {
        var value = stat()
        guard lstat(path, &value) == 0, value.st_mode & S_IFMT == S_IFREG else { throw NativeProviderInspectionFailure("executable_file_unavailable") }
        return NativeProviderFilePin(device: UInt64(UInt32(bitPattern: value.st_dev)), inode: value.st_ino,
            size: value.st_size, modifiedSeconds: Int64(value.st_mtimespec.tv_sec),
            modifiedNanoseconds: Int64(value.st_mtimespec.tv_nsec), mode: UInt32(value.st_mode))
    }
    private func inspect(path: String, kind: NativeProviderAdmissionMetadata.Kind, expectedBundleID: String?,
                         expectedExecutable: String?) throws -> NativeProviderAdmissionMetadata {
        let path = try canonical(path)
        var code: SecStaticCode?
        let create = SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code)
        guard create == errSecSuccess, let code = code else { throw NativeProviderInspectionFailure("static_code_unavailable", status: create) }
        let validationFlags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate)
        let validity = SecStaticCodeCheckValidity(code, validationFlags, nil)
        guard validity == errSecSuccess else {
            throw NativeProviderInspectionFailure(validity == errSecCSUnsigned ? "signature_unsigned" : "signature_invalid",
                status: validity, state: .unsupported)
        }
        var raw: CFDictionary?, codePath: CFURL?, requirement: SecRequirement?, requirementText: CFString?
        let infoStatus = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation), &raw)
        let pathStatus = SecCodeCopyPath(code, [], &codePath)
        let requirementStatus = SecCodeCopyDesignatedRequirement(code, [], &requirement)
        guard infoStatus == errSecSuccess, let info = raw as? [String: Any], pathStatus == errSecSuccess,
              let actualPath = (codePath as URL?)?.path, try canonical(actualPath) == path,
              requirementStatus == errSecSuccess, let requirement = requirement else {
            throw NativeProviderInspectionFailure("static_metadata_unavailable", status: infoStatus != 0 ? infoStatus : pathStatus != 0 ? pathStatus : requirementStatus)
        }
        let textStatus = SecRequirementCopyString(requirement, [], &requirementText)
        guard textStatus == errSecSuccess, let requirementString = bounded(requirementText, 16384),
              let identifier = bounded(info[kSecCodeInfoIdentifier as String], 512),
              let unique = info[kSecCodeInfoUnique as String] as? Data, !unique.isEmpty, unique.count <= 64,
              let flags = unsignedNumber(info[kSecCodeInfoFlags as String]),
              let executableURL = info[kSecCodeInfoMainExecutable as String] as? URL else {
            throw NativeProviderInspectionFailure("static_identity_incomplete", status: textStatus)
        }
        let executable = try canonical(executableURL.path)
        if let expectedExecutable = expectedExecutable, try canonical(expectedExecutable) != executable {
            throw NativeProviderInspectionFailure("executable_identity_mismatch")
        }
        var bundleID: String?
        if kind != .helper {
            guard path.hasSuffix(kind == .target ? ".app" : ".tmplugin"), executable.hasPrefix(path + "/Contents/MacOS/"),
                  let plist = info[kSecCodeInfoPList as String] as? [String: Any],
                  let id = bounded(plist["CFBundleIdentifier"], 512) else { throw NativeProviderInspectionFailure("bundle_identity_unavailable") }
            guard expectedBundleID == nil || expectedBundleID == id else { throw NativeProviderInspectionFailure("bundle_identity_mismatch") }
            bundleID = id
        } else if path != executable { throw NativeProviderInspectionFailure("helper_executable_identity_mismatch") }
        let teamRaw = info[kSecCodeInfoTeamIdentifier as String]
        let team = bounded(teamRaw, 128)
        if teamRaw != nil && team == nil { throw NativeProviderInspectionFailure("team_metadata_malformed") }
        let platformRaw = info[kSecCodeInfoPlatformIdentifier as String]
        let platform = unsignedNumber(platformRaw)
        if platformRaw != nil && platform == nil { throw NativeProviderInspectionFailure("platform_metadata_malformed") }
        let before = try pin(executable)
        let restricted = try machORestrictions(executable, kind: kind)
        let result = NativeProviderAdmissionMetadata(kind: kind, bundlePath: kind != .helper ? path : nil,
            executablePath: executable, bundleIdentifier: bundleID, signingIdentifier: identifier,
            teamIdentifier: team, designatedRequirement: requirementString,
            cdHash: unique.map { String(format: "%02x", $0) }.joined(), flags: flags,
            platformIdentifier: platform, signature: .valid, entitlements: .read(info), filePin: before,
            restrictedMachO: restricted)
        // Reopen after header inspection: the original Security object may cache
        // signing information. Compare fresh identity fields as well as validity
        // under the pinned requirement; a same-Team update still changes the pin.
        var freshCode: SecStaticCode?, freshRaw: CFDictionary?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &freshCode) == errSecSuccess,
              let freshCode = freshCode,
              SecStaticCodeCheckValidity(freshCode, validationFlags, requirement) == errSecSuccess,
              SecCodeCopySigningInformation(freshCode, SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation), &freshRaw) == errSecSuccess,
              let fresh = freshRaw as? [String: Any], try pin(executable) == before else {
            throw NativeProviderInspectionFailure("code_changed_during_inspection")
        }
        let stableKeys = [kSecCodeInfoIdentifier, kSecCodeInfoUnique, kSecCodeInfoFlags,
                          kSecCodeInfoTeamIdentifier, kSecCodeInfoPlatformIdentifier,
                          kSecCodeInfoMainExecutable, kSecCodeInfoPList, kSecCodeInfoEntitlementsDict,
                          kSecCodeInfoEntitlements]
        for key in stableKeys {
            let key = key as String
            let left = info[key] as? NSObject, right = fresh[key] as? NSObject
            guard (left == nil && right == nil) || (left != nil && right != nil && left!.isEqual(right!)) else {
                throw NativeProviderInspectionFailure("signing_metadata_changed_during_inspection")
            }
        }
        var freshRequirement: SecRequirement?, freshText: CFString?
        guard SecCodeCopyDesignatedRequirement(freshCode, [], &freshRequirement) == errSecSuccess,
              let freshRequirement = freshRequirement,
              SecRequirementCopyString(freshRequirement, [], &freshText) == errSecSuccess,
              bounded(freshText, 16384) == requirementString else {
            throw NativeProviderInspectionFailure("requirement_changed_during_inspection")
        }
        return result
    }
    // Bounded header/load-command reads only; all fat slices must agree on file
    // kind. Unknown formats or malformed command tables never become approval.
    private func machORestrictions(_ path: String, kind: NativeProviderAdmissionMetadata.Kind) throws -> Bool {
        let file: FileHandle
        do { file = try FileHandle(forReadingFrom: URL(fileURLWithPath: path)) }
        catch { throw NativeProviderInspectionFailure("executable_header_unavailable") }
        defer { try? file.close() }
        let size = try pin(path).size
        func read(_ offset: UInt64, _ count: Int) throws -> Data {
            guard count >= 0, count <= 4 * 1024 * 1024, offset <= UInt64(max(size, 0)),
                  UInt64(count) <= UInt64(max(size, 0)) - offset else { throw NativeProviderInspectionFailure("mach_o_bounds_invalid") }
            do {
                try file.seek(toOffset: offset)
                guard let data = try file.read(upToCount: count), data.count == count else {
                    throw NativeProviderInspectionFailure("mach_o_read_unavailable")
                }
                return data
            } catch { throw NativeProviderInspectionFailure("mach_o_read_unavailable") }
        }
        func word(_ data: Data, _ at: Int, _ big: Bool = false) -> UInt32 {
            let bytes = Array(data[at..<(at + 4)])
            return big ? bytes.reduce(0) { ($0 << 8) | UInt32($1) } : bytes.reversed().reduce(0) { ($0 << 8) | UInt32($1) }
        }
        let header = try read(0, 8)
        let magic = word(header, 0, true)
        var slices: [(UInt64, UInt64)] = [(0, UInt64(max(size, 0)))]
        if magic == 0xcafebabe || magic == 0xcafebabf {
            let count = word(header, 4, true)
            guard count > 0, count <= 16 else { throw NativeProviderInspectionFailure("mach_o_architectures_ambiguous") }
            let wide = magic == 0xcafebabf, stride = wide ? 32 : 20
            let table = try read(8, Int(count) * stride)
            slices = []
            for i in 0..<Int(count) {
                let at = i * stride
                let offset = wide ? UInt64(word(table, at + 8, true)) << 32 | UInt64(word(table, at + 12, true)) : UInt64(word(table, at + 8, true))
                let length = wide ? UInt64(word(table, at + 16, true)) << 32 | UInt64(word(table, at + 20, true)) : UInt64(word(table, at + 12, true))
                guard offset <= UInt64(max(size, 0)), length <= UInt64(max(size, 0)) - offset, length >= 32 else { throw NativeProviderInspectionFailure("mach_o_slice_invalid") }
                slices.append((offset, length))
            }
        }
        var restricted = false
        for (offset, length) in slices {
            let header = try read(offset, 32)
            let magic = word(header, 0)
            guard magic == 0xfeedfacf || magic == 0xfeedface else { throw NativeProviderInspectionFailure("mach_o_format_unsupported") }
            let wide = magic == 0xfeedfacf, headerSize = wide ? 32 : 28
            let expectedKind: UInt32 = kind == .target ? 2 : kind == .helper ? 6 : 8
            guard word(header, 12) == expectedKind else { throw NativeProviderInspectionFailure("mach_o_kind_mismatch") }
            let count = word(header, 16), bytes = word(header, 20)
            guard count <= 8192, UInt64(bytes) <= length - UInt64(headerSize), bytes <= 4 * 1024 * 1024 else { throw NativeProviderInspectionFailure("mach_o_commands_invalid") }
            let commands = try read(offset + UInt64(headerSize), Int(bytes)); var at = 0
            for _ in 0..<count {
                guard at <= commands.count - 8 else { throw NativeProviderInspectionFailure("mach_o_commands_invalid") }
                let cmd = word(commands, at), length = Int(word(commands, at + 4))
                guard length >= 8, length <= commands.count - at else { throw NativeProviderInspectionFailure("mach_o_commands_invalid") }
                if cmd == 1 || cmd == 0x19 {
                    guard length >= (cmd == 1 ? 56 : 72) else { throw NativeProviderInspectionFailure("mach_o_segment_invalid") }
                    let name = commands[(at + 8)..<(at + 24)].prefix { $0 != 0 }
                    if String(bytes: name, encoding: .utf8) == "__RESTRICT" { restricted = true }
                }
                at += length
            }
            guard at == commands.count else { throw NativeProviderInspectionFailure("mach_o_commands_ambiguous") }
        }
        return restricted
    }
}
