import Foundation

// Observation/claim owners pin their bindings; pressure can evict only unused
// identities. An enumeration also pins its own results until it completes.
final class NativeBindingCache<Owner: Equatable, Element> {
    struct Entry {
        let owner: Owner
        let element: Element
        var used: UInt64
    }
    private let limit: Int
    private let failure: String
    private let same: (Element, Element) -> Bool
    private let lock = NSRecursiveLock()
    private var entries: [String: Entry] = [:]
    private var retained: Set<String> = []
    private var batches: [UUID: Set<String>] = [:]
    private var clock: UInt64 = 0

    init(limit: Int, failure: String, same: @escaping (Element, Element) -> Bool) {
        precondition(limit > 0)
        self.limit = limit; self.failure = failure; self.same = same
    }
    func retain(_ ids: Set<String>) {
        lock.lock(); defer { lock.unlock() }
        retained = ids
    }
    func invalidate(_ id: String) {
        lock.lock(); defer { lock.unlock() }
        entries.removeValue(forKey: id); retained.remove(id)
        for batch in Array(batches.keys) { batches[batch]?.remove(id) }
    }
    func beginBatch() -> UUID {
        let batch = UUID()
        lock.lock(); batches[batch] = []; lock.unlock()
        return batch
    }
    func endBatch(_ batch: UUID) {
        lock.lock(); defer { lock.unlock() }
        batches.removeValue(forKey: batch)
    }
    func withBatch<T>(_ body: () throws -> T) rethrows -> T {
        let batch = beginBatch()
        defer { endBatch(batch) }
        return try body()
    }
    func entry(_ id: String) -> Entry? {
        lock.lock(); defer { lock.unlock() }
        guard var entry = entries[id] else { return nil }
        clock &+= 1; entry.used = clock; entries[id] = entry
        return entry
    }
    // References are observation candidates, never cached metadata or authority.
    // Pin the bounded snapshot in current discovery batches; release the lock
    // before the caller performs any native validation.
    func candidates(owner: Owner, limit maximum: Int) -> (entries: [(id: String, entry: Entry)], truncated: Bool) {
        lock.lock(); defer { lock.unlock() }
        let matching = entries.filter { $0.value.owner == owner }.sorted {
            $0.value.used == $1.value.used ? $0.key < $1.key : $0.value.used > $1.value.used
        }
        let selected = matching.prefix(max(0, maximum)).map { (id: $0.key, entry: $0.value) }
        let ids = Set(selected.map(\.id))
        for batch in Array(batches.keys) { batches[batch]?.formUnion(ids) }
        return (selected, matching.count > selected.count)
    }
    func identifier(_ element: Element, owner: Owner) throws -> String {
        lock.lock(); defer { lock.unlock() }
        let id: String
        if let existing = entries.first(where: { $0.value.owner == owner && same($0.value.element, element) }) {
            id = existing.key
        } else {
            if entries.count >= limit {
                let pinned = batches.values.reduce(retained) { $0.union($1) }
                guard let oldest = entries.filter({ !pinned.contains($0.key) }).min(by: { $0.value.used < $1.value.used }) else {
                    throw NativeFailure(failure)
                }
                entries.removeValue(forKey: oldest.key)
            }
            id = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        }
        clock &+= 1; entries[id] = Entry(owner: owner, element: element, used: clock)
        for batch in Array(batches.keys) { batches[batch]?.insert(id) }
        return id
    }
}
