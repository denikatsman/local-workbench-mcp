import Foundation
import CryptoKit

/// Durable local authority is independent of OS approval and task ownership.
struct NativeInstallationTrust: Codable, Equatable {
    static let version = 1
    static let supportedCapabilities: Set<String> = ["native.discover", "native.launch", "native.observe", "native.capture", "native.control", "native.clipboard"]
    var schemaVersion: Int = version
    var installationID: String
    var principalID = "host_owner"
    var policyRevision: Int
    var signingIdentifier: String
    var teamID: String
    var state: String
    var capabilities: Set<String>
    var blockedApps: Set<String>
    var updatedAt: Double

    func permits(_ capability: String, app: NativeAppIdentity? = nil) -> Bool {
        state == "valid" && capabilities.contains(capability) && (app.map { !blockedApps.contains($0.bundleID) } ?? true)
    }
    var valid: Bool {
        schemaVersion == Self.version && installationID.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil
        && principalID == "host_owner" && policyRevision > 0 && ["valid", "revoked"].contains(state)
        && !signingIdentifier.isEmpty && !teamID.isEmpty && capabilities.isSubset(of: Self.supportedCapabilities)
        && updatedAt.isFinite && updatedAt > 0
    }
    var wire: [String: Any] {
        ["schema_version": schemaVersion, "installation_id": installationID, "principal_id": principalID,
         "policy_revision": policyRevision, "signing_identifier": signingIdentifier, "team_id": teamID,
         "state": state, "capabilities": capabilities.sorted(), "blocked_apps": blockedApps.sorted(),
         "updated_at": updatedAt, "authority_origin": "local_user_setup", "legacy_grants_promoted": false]
    }
}

/// This store is written only by the signed app's local setup/Stop actions.
/// Unknown record fields survive updates; unsupported schemas fail closed.
final class NativeInteractionTrustStore {
    private let url: URL
    private let component: (String, String)
    private let write: (Data, URL) throws -> Void
    private var original: [String: Any] = [:]
    private(set) var policy: NativeInstallationTrust?
    private(set) var failure: String?

    init(url: URL, signingIdentifier: String, teamID: String, write: @escaping (Data, URL) throws -> Void) {
        self.url = url; component = (signingIdentifier, teamID); self.write = write
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        do {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true, (values.fileSize ?? Int.max) <= 65536 else {
                throw NativeFailure("native_trust_record_invalid")
            }
            let data = try Data(contentsOf: url)
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw NativeFailure("native_trust_record_invalid") }
            original = object
            let decoded = try JSONDecoder().decode(NativeInstallationTrust.self, from: data)
            guard decoded.valid else { throw NativeFailure("native_trust_record_invalid") }
            guard decoded.signingIdentifier == component.0, decoded.teamID == component.1 else {
                throw NativeFailure("native_trust_identity_review_required")
            }
            policy = decoded
        } catch let error as NativeFailure { failure = error.code }
        catch { failure = "native_trust_record_invalid" }
    }

    private func save(_ next: NativeInstallationTrust) throws {
        guard failure == nil, next.valid else { throw NativeFailure(failure ?? "native_trust_record_invalid") }
        let data = try JSONEncoder().encode(next)
        let encoded = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let preserved = original.merging(encoded) { _, current in current }
        let bytes = try JSONSerialization.data(withJSONObject: preserved, options: [.sortedKeys])
        guard bytes.count <= 65536 else { throw NativeFailure("native_trust_record_limit") }
        try write(bytes, url)
        policy = next; original = preserved
    }

    func configureLocally(capabilities: Set<String>) throws {
        guard !capabilities.isEmpty, capabilities.isSubset(of: NativeInstallationTrust.supportedCapabilities) else {
            throw NativeFailure("native_trust_capabilities_invalid")
        }
        let next = NativeInstallationTrust(installationID: policy?.installationID ?? UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
            policyRevision: (policy?.policyRevision ?? 0) + 1, signingIdentifier: component.0, teamID: component.1,
            state: "valid", capabilities: capabilities, blockedApps: policy?.blockedApps ?? [], updatedAt: Date().timeIntervalSince1970)
        try save(next)
    }
    func resumeAppLocally(_ bundleID: String) throws {
        guard var next = policy, next.state == "valid", next.blockedApps.contains(bundleID) else {
            throw NativeFailure("native_app_not_stopped")
        }
        next.policyRevision += 1; next.updatedAt = Date().timeIntervalSince1970; next.blockedApps.remove(bundleID)
        try save(next)
    }
    func stopLocally(appBundleID: String? = nil) throws {
        guard var next = policy else { throw NativeFailure("native_trusted_setup_required") }
        next.policyRevision += 1; next.updatedAt = Date().timeIntervalSince1970
        if let bundle = appBundleID { next.blockedApps.insert(bundle) } else { next.state = "revoked" }
        do { try save(next) }
        catch {
            // Stop takes effect in this process even when durable storage is
            // unavailable or a replacement succeeded but fsync did not.
            policy = next
            throw NativeFailure("native_stop_persistence_failed", "applied")
        }
    }
}

func nativeTargetResource(_ app: NativeAppIdentity, windowID: String) -> String {
    let fields = [app.bundleID, app.bundlePath, app.executable, String(app.pid), String(app.launchedAt),
                  app.signingIdentifier ?? "", app.teamID ?? "", app.designatedRequirement ?? "", windowID]
    // Length-delimited JSON prevents ambiguous concatenation of resource fields.
    let data = try! JSONEncoder().encode(fields)
    return "native-window:" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
