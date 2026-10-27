import Foundation

/// Control-lane state never touches the serial AX engine.
final class NativeCancellation {
    struct Ticket {
        let requestID: String, claimID: String, ownerSession: String, runtimeGeneration: String
        var bundleID: String
        var cancelled: Bool
    }
    private let lock = NSLock()
    private var tickets: [String: Ticket] = [:]
    private var stopped = false
    private var draining = false
    private var localEnableGeneration = UUID()
    private var stoppedClaims: Set<String> = []
    private var stoppedBundles: Set<String> = []
    private var pendingCancels: [String: Ticket] = [:]
    private var finished: Set<String> = []

    func begin(requestID: String, claimID: String, ownerSession: String, runtimeGeneration: String, bundleID: String = "") throws {
        lock.lock(); defer { lock.unlock() }
        if finished.contains(requestID) { throw NativeFailure("native_cancellation_finished") }
        guard !requestID.isEmpty, !claimID.isEmpty, !ownerSession.isEmpty,
              !stopped, !draining, !stoppedClaims.contains(claimID), !stoppedBundles.contains(bundleID), tickets[requestID] == nil, tickets.count < 32 else { throw NativeFailure("native_cancellation_ticket_invalid") }
        let pending = pendingCancels[requestID]
        if let pending = pending, pending.claimID != claimID || pending.ownerSession != ownerSession || pending.runtimeGeneration != runtimeGeneration {
            throw NativeFailure("native_cancellation_owner_mismatch")
        }
        tickets[requestID] = Ticket(requestID:requestID,claimID:claimID,ownerSession:ownerSession,runtimeGeneration:runtimeGeneration,bundleID:bundleID,cancelled:pending != nil)
        pendingCancels.removeValue(forKey:requestID)
    }
    func check(_ requestID: String) throws {
        lock.lock(); defer { lock.unlock() }
        if tickets[requestID]?.cancelled == true { throw NativeFailure("native_operation_cancelled", "unknown") }
    }
    func send(_ requestID: String, action: () throws -> Void) throws {
        lock.lock(); defer { lock.unlock() }
        guard !stopped, !draining, let ticket = tickets[requestID], !ticket.cancelled, !stoppedBundles.contains(ticket.bundleID) else { throw NativeFailure("native_operation_cancelled", "unknown") }
        try action()
    }
    func admit(_ claimID: String) throws {
        lock.lock(); defer { lock.unlock() }
        if stopped || draining || stoppedClaims.contains(claimID) { throw NativeFailure("native_access_stopped") }
    }
    func admitBundle(_ bundleID: String) throws {
        lock.lock(); defer { lock.unlock() }
        if stopped || stoppedBundles.contains(bundleID) { throw NativeFailure("native_access_stopped") }
    }
    /// Order one nonblocking document-open invocation against Stop and drain.
    /// Callers must wait for the OS callback only after this scope returns.
    func admitLaunch(bundleID: String, action: () throws -> Void) throws {
        lock.lock(); defer { lock.unlock() }
        guard !stopped, !draining, !stoppedBundles.contains(bundleID) else {
            throw NativeFailure("native_access_stopped")
        }
        try action()
    }
    func stopBundle(_ bundleID: String) { lock.lock(); stoppedBundles.insert(bundleID); lock.unlock() }
    func resumeBundleLocally(_ bundleID: String) { lock.lock(); stoppedBundles.remove(bundleID); lock.unlock() }
    func cancel(requestID: String, claimID: String, ownerSession: String, runtimeGeneration: String) throws -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        if finished.contains(requestID) { throw NativeFailure("native_cancellation_finished") }
        if tickets[requestID] == nil {
            guard !requestID.isEmpty, !claimID.isEmpty, !ownerSession.isEmpty, pendingCancels.count < 32 else { throw NativeFailure("native_cancellation_ticket_invalid") }
            let proposed = Ticket(requestID:requestID,claimID:claimID,ownerSession:ownerSession,runtimeGeneration:runtimeGeneration,bundleID:"",cancelled:true)
            if let prior = pendingCancels[requestID], prior.claimID != claimID || prior.ownerSession != ownerSession || prior.runtimeGeneration != runtimeGeneration {
                throw NativeFailure("native_cancellation_owner_mismatch")
            }
            pendingCancels[requestID] = proposed
            return ["ok":true,"operation_id":requestID,"cancel_requested":true,"release_state":"not_dispatched_or_not_yet_observed"]
        }
        guard var ticket = tickets[requestID], ticket.claimID == claimID, ticket.ownerSession == ownerSession,
              ticket.runtimeGeneration == runtimeGeneration else { throw NativeFailure("native_cancellation_owner_mismatch") }
        ticket.cancelled = true; tickets[requestID] = ticket
        return ["ok":true,"operation_id":requestID,"cancel_requested":true,"release_state":"not_yet_observed"]
    }
    func finish(_ requestID: String) {
        lock.lock(); tickets.removeValue(forKey:requestID); finished.insert(requestID)
        if finished.count > 1000 { finished.remove(finished.first!) }
        lock.unlock()
    }
    func cancelAll() {
        lock.lock(); defer { lock.unlock() }
        localEnableGeneration = UUID()
        stopped = true
        for var ticket in tickets.values { ticket.cancelled = true; tickets[ticket.requestID] = ticket }
    }
    func beginDrain() {
        lock.lock(); defer { lock.unlock() }
        localEnableGeneration = UUID()
        draining = true
        for var ticket in tickets.values { ticket.cancelled = true; tickets[ticket.requestID] = ticket }
    }
    func cancelClaim(_ claimID: String) {
        lock.lock(); defer { lock.unlock() }
        stoppedClaims.insert(claimID)
        for var ticket in tickets.values where ticket.claimID == claimID { ticket.cancelled = true; tickets[ticket.requestID] = ticket }
    }
    func newRuntime() { lock.lock(); tickets.removeAll(); pendingCancels.removeAll(); finished.removeAll(); draining = false; localEnableGeneration = UUID(); lock.unlock() }
    func localEnableRevision() -> UUID { lock.lock(); defer { lock.unlock() }; return localEnableGeneration }
    @discardableResult
    func enableLocally(ifUnchanged revision: UUID) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard localEnableGeneration == revision, !draining else { return false }
        stopped = false
        return true
    }
    func enableLocally() { lock.lock(); stopped = false; lock.unlock() }
}
