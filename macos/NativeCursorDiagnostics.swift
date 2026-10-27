import Foundation

struct NativeCursorTraceOwner: Equatable, Codable {
    let operationID: String
    let claimID: String
    let ownerSession: String
    let runtimeGeneration: String
    var valid: Bool {
        operationID.range(of: "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", options: .regularExpression) != nil
            && [claimID, ownerSession, runtimeGeneration].allSatisfy {
                $0.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil
            }
    }
}

enum NativeCursorTracePhase: String, Codable {
    case enqueue, uiStart, lookupStart, metadataQueueStart, bindingStart, bindingEnd
    case stackReadStart, stackReadEnd, metadataReadEnd, completionStart
    case superseded, timeout, refusal, showRequest, showReturn, hideRequest, hideReturn, invalidate
    var terminal: Bool { [.timeout, .refusal, .hideRequest, .hideReturn, .invalidate].contains(self) }
}

struct NativeCursorTraceEvent: Codable {
    let sequence: UInt64
    let uptime: Double
    let phase: NativeCursorTracePhase
    let generation: UUID
    let ticketSerial: UInt64?
    let lookup: UUID?
    let requestedPoint: Bool?
    let reason: String?
}

struct NativeCursorTraceSnapshot: Codable {
    let schemaVersion: Int
    let clock: String
    let owner: NativeCursorTraceOwner
    let startedAt: Double
    let checkedAt: Double
    let collecting: Bool
    let detailed: Bool
    let droppedEvents: UInt64
    let events: [NativeCursorTraceEvent]
}

// A diagnostics-only, in-memory view. It does not change or certify the input
// receipt, cursor visibility, claim authority, permissions or event dispatch.
final class NativeCursorDiagnostics {
    static let maximumOperations = 4
    static let maximumEvents = 128
    static let detailedEvents = 112
    static let maximumBytes = 24 * 1024
    static let collectionSeconds = 10.0
    static let retentionSeconds = 60.0
    private static let reasons: Set<String> = [
        "cursor_request_invalid", "cursor_app_identity_unknown", "cursor_app_identity_changed",
        "cursor_window_binding_unknown", "cursor_window_binding_changed", "cursor_target_missing",
        "cursor_target_changed", "cursor_target_moved", "cursor_target_offscreen", "cursor_target_visibility_unknown",
        "cursor_target_transparent", "cursor_window_list_unavailable", "cursor_window_stack_limit",
        "cursor_window_stack_unknown", "cursor_window_stack_changed", "cursor_occlusion_metadata_unknown",
        "cursor_target_occluded", "cursor_screen_coordinates_unknown", "cursor_presentation_expired",
        "cursor_metadata_timeout", "cursor_target_required"]
    private struct Record {
        let owner: NativeCursorTraceOwner
        let startedAt: Double
        var detailed = true
        var sequence: UInt64 = 0
        var dropped: UInt64 = 0
        var generation: UUID?
        var lastUptime: Double?
        var eventBytes = 0
        var events: [NativeCursorTraceEvent] = []
    }
    private let lock = NSLock()
    private var records: [String: Record] = [:]
    private var runtime: String?
    private let now: () -> Double
    init(now: @escaping () -> Double = { ProcessInfo.processInfo.systemUptime }) { self.now = now }
    private func prune(_ time: Double) {
        records = records.filter { time >= $0.value.startedAt && time - $0.value.startedAt < Self.retentionSeconds }
    }
    func reset(runtimeGeneration: String) {
        lock.lock(); defer { lock.unlock() }
        records.removeAll(); runtime = runtimeGeneration
    }
    @discardableResult func register(_ owner: NativeCursorTraceOwner) -> Bool {
        guard owner.valid else { return false }
        let time = now(); guard time.isFinite, time >= 0 else { return false }
        lock.lock(); defer { lock.unlock() }
        guard runtime == owner.runtimeGeneration else { return false }
        prune(time)
        if let existing = records[owner.operationID] { return existing.owner == owner }
        if records.count >= Self.maximumOperations,
           let oldest = records.min(by: { $0.value.startedAt < $1.value.startedAt })?.key { records.removeValue(forKey: oldest) }
        records[owner.operationID] = Record(owner: owner, startedAt: time)
        return true
    }
    func bind(operationID: String, generation: UUID) {
        lock.lock(); defer { lock.unlock() }
        guard var record = records[operationID], record.generation == nil else { return }
        record.generation = generation; records[operationID] = record
    }
    func append(operationID: String, generation: UUID, ticketSerial: UInt64? = nil,
                lookup: UUID? = nil, phase: NativeCursorTracePhase, requestedPoint: Bool? = nil, reason: String? = nil) {
        lock.lock()
        let record = records[operationID]
        let owner = record?.generation == generation ? record?.owner : nil
        lock.unlock()
        guard let owner = owner else { return }
        append(owner: owner, generation: generation, ticketSerial: ticketSerial,
               lookup: lookup, phase: phase, requestedPoint: requestedPoint, reason: reason)
    }
    func append(owner: NativeCursorTraceOwner, generation: UUID, ticketSerial: UInt64? = nil,
                lookup: UUID? = nil, phase: NativeCursorTracePhase, requestedPoint: Bool? = nil, reason: String? = nil) {
        let time = now(); guard time.isFinite, time >= 0 else { return }
        guard reason == nil || Self.reasons.contains(reason!) else { return }
        lock.lock(); defer { lock.unlock() }
        guard runtime == owner.runtimeGeneration, var record = records[owner.operationID], record.owner == owner,
              time >= record.startedAt, time - record.startedAt < Self.collectionSeconds else { return }
        guard record.generation == nil || record.generation == generation else { return }
        guard record.lastUptime == nil || time >= record.lastUptime! else { return }
        guard record.sequence < UInt64.max else { return }
        record.sequence += 1
        record.generation = generation; record.lastUptime = time
        let event = NativeCursorTraceEvent(sequence: record.sequence, uptime: time, phase: phase,
            generation: generation, ticketSerial: ticketSerial, lookup: lookup, requestedPoint: requestedPoint, reason: reason)
        let bytes = (try? JSONEncoder().encode(event).count).map { $0 + 1 }
        let retain = record.events.count < Self.maximumEvents
            && (phase.terminal || (record.detailed && record.events.count < Self.detailedEvents))
            && bytes.map { record.eventBytes + $0 <= Self.maximumBytes - 1024 } == true
        if retain {
            record.events.append(event); record.eventBytes += bytes!
        } else if record.dropped < UInt64.max { record.dropped += 1 }
        if phase == .showReturn && requestedPoint == true { record.detailed = false }
        records[owner.operationID] = record
    }
    func snapshot(_ owner: NativeCursorTraceOwner) -> NativeCursorTraceSnapshot? {
        guard owner.valid else { return nil }
        lock.lock(); defer { lock.unlock() }
        let time = now(); guard time.isFinite, time >= 0 else { return nil }
        guard runtime == owner.runtimeGeneration else { return nil }
        prune(time)
        guard let record = records[owner.operationID], record.owner == owner else { return nil }
        guard record.lastUptime == nil || time >= record.lastUptime! else { return nil }
        return NativeCursorTraceSnapshot(schemaVersion: 1, clock: "ProcessInfo.systemUptime", owner: owner,
            startedAt: record.startedAt, checkedAt: time, collecting: time - record.startedAt < Self.collectionSeconds,
            detailed: record.detailed, droppedEvents: record.dropped, events: record.events)
    }
}
