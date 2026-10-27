import Foundation

// Used on the launcher's main queue. A delayed callback from an earlier child
// must not mutate the new child's status, credentials or process ownership.
final class LauncherCallbackGate {
    private var current: UUID?

    func begin() -> UUID {
        let generation = UUID()
        current = generation
        return generation
    }

    func invalidate() { current = nil }

    @discardableResult
    func perform(for generation: UUID, _ action: () -> Void) -> Bool {
        guard current == generation else { return false }
        action()
        return true
    }
}

// Main-queue join for two independently delivered completion notifications.
// EOF is submitted after the stream's decoded batches, so cleanup proof is
// consumed before termination invalidates this launch's callback generation.
final class LauncherTerminationJoin {
    private var exitStatus: Int32?
    private var outputEnded = false
    private var delivered = false
    private var handoffEnded: Bool
    private var drainEnded: Bool

    init(requireHandoff: Bool = false, requireDrain: Bool = false) {
        handoffEnded = !requireHandoff
        drainEnded = !requireDrain
    }

    func receiveHandoff() -> Int32? { handoffEnded = true; return completion() }
    func receiveDrain() -> Int32? { drainEnded = true; return completion() }

    func receiveExit(_ status: Int32) -> Int32? {
        exitStatus = status
        return completion()
    }

    func receiveEOF() -> Int32? {
        outputEnded = true
        return completion()
    }

    private func completion() -> Int32? {
        guard !delivered, outputEnded, handoffEnded, drainEnded, let exitStatus else { return nil }
        delivered = true
        return exitStatus
    }
}

// Ordered atomic registration precedes payload creation. Stream EOF bounds
// the set: no guardian/payload can retain or fabricate a later event writer.
final class LauncherChildTickets {
    private var tickets: [String: (role: String, finished: Bool)] = [:]
    private(set) var valid = true
    func invalidate() { valid = false }
    func receive(_ event: LauncherEvent) {
        guard let ticket = event.ticket, let role = event.role else { invalidate(); return }
        if event.status == "child_started" {
            guard tickets[ticket] == nil else { invalidate(); return }
            tickets[ticket] = (role, false)
        } else {
            guard let previous = tickets[ticket], previous.role == role, !previous.finished else { invalidate(); return }
            tickets[ticket] = (role, true)
        }
    }
    var cleanupConfirmed: Bool { valid && !tickets.isEmpty && tickets.values.allSatisfy { $0.finished } }
    var emptyAndValid: Bool { valid && tickets.isEmpty }
    var readyCoverage: Bool {
        valid && ["service", "tunnel"].allSatisfy { role in tickets.values.contains { $0.role == role && !$0.finished } }
    }
}

struct LauncherEvent {
    let status: String
    let message: String?
    let url: String?
    let connection: String?
    let ticket: String?
    let role: String?

    init?(line: Data) {
        guard let values = try? JSONSerialization.jsonObject(with: line) as? [String: String],
              Set(values.keys).isSubset(of: ["status", "message", "url", "connection", "ticket", "role"]),
              let status = values["status"],
              ["starting", "ready", "stopping", "stopped", "error", "children_stopped", "child_started", "child_stopped"].contains(status) else { return nil }
        if ["child_started", "child_stopped"].contains(status) {
            guard Set(values.keys) == ["status", "ticket", "role"],
                  let ticket = values["ticket"], ticket.count == 32,
                  ticket.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                  ["service", "tunnel"].contains(values["role"] ?? "") else { return nil }
        } else if values["ticket"] != nil || values["role"] != nil { return nil }
        if status == "children_stopped" && Set(values.keys) != ["status"] { return nil }
        if status == "ready" {
            guard let address = values["url"], let url = URLComponents(string: address),
                  let host = url.host, !host.isEmpty, url.user == nil, url.password == nil,
                  url.query == nil, url.fragment == nil, url.path == "/mcp",
                  url.scheme == "https" || (url.scheme == "http" && ["localhost", "127.0.0.1", "::1", "[::1]"].contains(host.lowercased())),
                  ["stable", "temporary"].contains(values["connection"] ?? "") else { return nil }
        } else if values["url"] != nil || values["connection"] != nil { return nil }
        self.status = status
        message = values["message"]
        url = values["url"]
        connection = values["connection"]
        ticket = values["ticket"]
        role = values["role"]
    }
}

struct LauncherEventBatch {
    var events: [LauncherEvent] = []
    var rejectedFrames = 0
    var oversizedFrames = 0
    var omittedEvents = 0
}

struct LauncherEventDecoder {
    private var pending = Data()
    private var discarding = false
    static let maximumFrameBytes = 65_536
    static let maximumBatchEvents = 64

    mutating func append(_ bytes: Data) -> LauncherEventBatch {
        var batch = LauncherEventBatch()
        for byte in bytes {
            if byte == 10 {
                if discarding {
                    discarding = false
                } else if let event = LauncherEvent(line: pending) {
                    if batch.events.count < Self.maximumBatchEvents { batch.events.append(event) }
                    else { batch.omittedEvents += 1 }
                } else { batch.rejectedFrames += 1 }
                pending.removeAll(keepingCapacity: true)
            } else if !discarding {
                if pending.count == Self.maximumFrameBytes {
                    pending.removeAll(keepingCapacity: true)
                    discarding = true
                    batch.oversizedFrames += 1
                } else { pending.append(byte) }
            }
        }
        return batch
    }

    mutating func finish() -> Bool {
        let incomplete = discarding || !pending.isEmpty
        pending.removeAll(keepingCapacity: false)
        discarding = false
        return incomplete
    }
}
