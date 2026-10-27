import Foundation
import Darwin
import ReceiverProviderProtocol

/// A sibling of the disposable planner, with its own inherited ownership lease.
/// The broker owns the original connection and prebound release. Planner death
/// closes its input; host death produces the same EOF. Broker death is NOT a
/// recoverable transport boundary and must retain UNKNOWN/fail-closed history.
final class NativeElectronPointerBroker {
    typealias Reply = ([String: Any]) -> Void
    private let node: URL, entry: URL, packet: [String: Any]
    private let ownership: NativeProviderRecovery.ElectronOwnership
    private let request: String
    private let lock = NSLock(), writeLock = NSLock(), launchLock = NSLock()
    private let identities = NativeSystemProcessIdentity(metadata: { _ in nil })
    private var process: Process?, input: Pipe?, output: Pipe?
    private var pending: [String: Reply] = [:], seen: Set<String> = []
    private var buffer = Data(), total = 0
    private var closing = false, ended = false, cancelled = false
    private var completions: [() -> Void] = []

    init(node: URL, entry: URL, packet: [String: Any], ownership: NativeProviderRecovery.ElectronOwnership) {
        self.node = node; self.entry = entry; self.packet = packet; self.ownership = ownership
        self.request = packet["request_id"] as? String ?? ""
    }

    private static func integer(_ value: Any?, range: ClosedRange<Int>) -> Int? {
        guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(), !CFNumberIsFloatType(n),
              range.contains(n.intValue), n.int64Value == Int64(n.intValue) else { return nil }
        return n.intValue
    }
    private func failure(_ code: String = "electron_pointer_broker_closed") -> [String: Any] {
        ["ok": false, "error": ["code": code]]
    }
    private var isCancelled: Bool {
        lock.lock(); defer { lock.unlock() }; return cancelled
    }
    private func write(_ frame: [String: Any]) throws {
        var data = try JSONSerialization.data(withJSONObject: frame, options: [.sortedKeys])
        guard data.count <= 65536 else { throw NativeProviderHostFailure("native_electron_pointer_broker_frame_limit") }
        data.append(10)
        writeLock.lock(); defer { writeLock.unlock() }
        lock.lock(); let handle = input?.fileHandleForWriting; lock.unlock()
        guard let handle = handle else { throw NativeProviderHostFailure("native_electron_pointer_broker_closed") }
        try handle.write(contentsOf: data)
    }
    private func start() throws {
        launchLock.lock(); defer { launchLock.unlock() }
        lock.lock(); let unavailable = closing || ended; let started = process != nil; lock.unlock()
        guard !unavailable else { throw NativeProviderHostFailure("native_electron_pointer_broker_closed") }
        if started { return }
        guard FileManager.default.isExecutableFile(atPath: node.path), FileManager.default.fileExists(atPath: entry.path),
              let managed = packet["managed"] as? [String: Any] else {
            throw NativeProviderHostFailure("native_electron_pointer_broker_unavailable")
        }
        try ownership.verify(managed)
        let lease = try ownership.inheritedHandle(); defer { try? lease.close() }
        let child = Process(), source = Pipe(), destination = Pipe()
        child.executableURL = node; child.arguments = [entry.path]
        child.standardInput = source; child.standardOutput = destination; child.standardError = lease
        var environment = ProcessInfo.processInfo.environment
        for key in ["NODE_OPTIONS", "NODE_PATH", "ELECTRON_RUN_AS_NODE", "VSCODE_IPC_HOOK_CLI"] { environment.removeValue(forKey: key) }
        child.environment = environment
        destination.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let bytes = handle.availableData
            self?.receive(bytes)
            if bytes.isEmpty { handle.readabilityHandler = nil }
        }
        child.terminationHandler = { [weak self] original in self?.didEnd(); original.terminationHandler = nil }
        lock.lock(); process = child; input = source; output = destination; lock.unlock()
        do {
            try ownership.verify(managed); try child.run()
            // A kernel identity read is required, never a PID-only ownership claim.
            _ = try identities.snapshot(child.processIdentifier)
            try write(packet)
        } catch {
            closeInput()
            if !child.isRunning { didEnd() }
            throw error
        }
    }
    private func take(_ key: String) -> Reply? {
        lock.lock(); defer { lock.unlock() }; return pending.removeValue(forKey: key)
    }
    private func send(_ frame: [String: Any], key: String, nonRelease: Bool = false, reply: @escaping Reply) throws {
        if nonRelease && isCancelled { reply(failure("electron_pointer_stopped")); return }
        try start()
        lock.lock()
        // Registration is the cancellation boundary. A previously registered
        // RPC may already send; every later action registration is fenced.
        // Pipe I/O stays outside this lock so Stop never waits on a full pipe.
        let stopped = nonRelease && cancelled
        let accepted = !stopped && !closing && !ended && !seen.contains(key) && seen.count < 2048 && pending.count < 32
        if accepted { seen.insert(key); pending[key] = reply }
        lock.unlock()
        if stopped { reply(failure("electron_pointer_stopped")); return }
        guard accepted else { throw NativeProviderHostFailure("native_electron_pointer_broker_sequence") }
        do { try write(frame) }
        catch { take(key)?(failure()); closeInput(); throw error }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2.5) { [self] in
            if let reply = take(key) { reply(failure("electron_pointer_broker_timeout")); closeInput() }
        }
    }
    func forward(_ frame: [String: Any], reply: @escaping Reply) throws {
        guard frame["event"] as? String == "pointer_transport", frame["request_id"] as? String == request,
              let id = Self.integer(frame["rpc_id"], range: 1...1024), let command = frame["command"] as? String,
              ["connect", "call", "close"].contains(command) else {
            throw NativeProviderHostFailure("native_electron_pointer_broker_protocol")
        }
        let parameters = frame["params"] as? [String: Any]
        let timed = command == "call" && frame["method"] as? String == "Input.dispatchMouseEvent" && parameters?["type"] as? String != "mouseReleased"
        var keys: Set<String> = command == "call"
            ? ["event", "request_id", "rpc_id", "command", "method", "params", "session_id", "timeout"]
            : ["event", "request_id", "rpc_id", "command"]
        if timed {
            keys.insert("pointer_deadline_ns")
            guard let deadline = frame["pointer_deadline_ns"] as? String,
                  deadline.range(of: "^[0-9]{1,30}$", options: .regularExpression) != nil else {
                throw NativeProviderHostFailure("native_electron_pointer_broker_protocol")
            }
        }
        guard Set(frame.keys) == keys else { throw NativeProviderHostFailure("native_electron_pointer_broker_protocol") }
        if command == "call" {
            guard let method = frame["method"] as? String, method.utf8.count <= 128,
                  frame["params"] is [String: Any], Self.integer(frame["timeout"], range: 1...2000) != nil,
                  frame["session_id"] is NSNull || (frame["session_id"] as? String).map({ !$0.isEmpty && $0.utf8.count <= 128 }) == true else {
                throw NativeProviderHostFailure("native_electron_pointer_broker_protocol")
            }
        }
        // Cooperative Stop fences further action RPCs without destroying the
        // original cleanup path. Previously registered input remains uncertain;
        // only its prebound release may complete on the original connection.
        try send(frame, key: "rpc:\(id)", nonRelease: timed, reply: reply)
    }
    /// This is a host-created grant after the original signed authority callback.
    /// Its ACK precedes the planner's ACK; a broker refusal never becomes a grant.
    func admit(_ record: [String: Any], allowed: Bool) throws -> Bool {
        guard let sequence = Self.integer(record["sequence"], range: 1...1024) else {
            throw NativeProviderHostFailure("native_electron_pointer_broker_admission")
        }
        let semaphore = DispatchSemaphore(value: 0), resultLock = NSLock()
        var result: [String: Any]?
        let permitted = allowed && !isCancelled
        try send(["event": "pointer_admission", "request_id": request, "record": record, "allowed": permitted],
                 key: "admission:\(sequence)") { value in
            resultLock.lock(); result = value; resultLock.unlock(); semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + 1) == .success else { closeInput(); return false }
        resultLock.lock(); let granted = result?["allowed"] as? Bool == true; resultLock.unlock()
        return permitted && granted && !isCancelled
    }
    private func receive(_ bytes: Data) {
        lock.lock()
        total += bytes.count
        if total > 262144 { lock.unlock(); closeInput(); return }
        buffer.append(bytes); var lines: [Data] = []
        while let end = buffer.firstIndex(of: 10) { lines.append(Data(buffer[..<end])); buffer.removeSubrange(...end) }
        let truncated = bytes.isEmpty && !buffer.isEmpty
        lock.unlock()
        for line in lines {
            guard let frame = LWProviderDecodeJSON(line, nil) as? [String: Any], frame["request_id"] as? String == request,
                  let event = frame["event"] as? String else { closeInput(); return }
            if event == "pointer_transport_result", Set(frame.keys) == ["event", "request_id", "rpc_id", "response"],
               let id = Self.integer(frame["rpc_id"], range: 1...1024), let response = frame["response"] as? [String: Any],
               let ok = response["ok"] as? Bool, Set(response.keys) == (ok ? ["ok", "result"] : ["ok", "error"]),
               ok ? response["result"] is [String: Any] : (response["error"] as? [String: Any]).map({
                   Set($0.keys) == ["code"] && ($0["code"] as? String)?.range(of: "^electron_[a-z0-9_]+$", options: .regularExpression) != nil
               }) == true {
                guard let reply = take("rpc:\(id)") else { closeInput(); return }; reply(response)
            } else if event == "pointer_admitted", Set(frame.keys) == ["event", "request_id", "sequence", "allowed"],
                      let sequence = Self.integer(frame["sequence"], range: 1...1024), let allowed = frame["allowed"] as? Bool {
                guard let reply = take("admission:\(sequence)") else { closeInput(); return }; reply(["allowed": allowed])
            } else if event == "broker_settled", Set(frame.keys) == ["event", "request_id", "result"], frame["result"] is [String: Any] {
                // This diagnostic does not retire the lease. Actual Process exit does.
            } else { closeInput(); return }
        }
        if truncated { closeInput() }
    }
    private func closeInput() {
        writeLock.lock()
        lock.lock(); closing = true; let handle = input?.fileHandleForWriting; lock.unlock()
        try? handle?.close(); writeLock.unlock()
    }
    func stop() {
        lock.lock(); closing = true; lock.unlock()
        // Cancellation can originate on the native authority lane. A full
        // child pipe must never block that lane behind an outstanding write.
        DispatchQueue.global(qos: .userInitiated).async { [self] in closeInput() }
    }
    /// The original planner still needs its release ACK. Actual planner exit,
    /// host EOF or a protocol failure retains the independent EOF fallback.
    func cancel() {
        lock.lock(); cancelled = true; lock.unlock()
    }
    /// Completion is tied to kernel-observed Process termination, not stdout EOF
    /// or a broker_settled frame. No hard-kill may abandon a possible original UP.
    func finish(_ completion: @escaping () -> Void) {
        launchLock.lock()
        lock.lock(); let done = ended || process == nil
        if !done { completions.append(completion) }
        lock.unlock()
        closeInput(); launchLock.unlock()
        if done { completion() }
    }
    private func didEnd() {
        lock.lock()
        if ended { lock.unlock(); return }
        ended = true; closing = true
        let callbacks = completions
        completions.removeAll(); lock.unlock()
        // Original stdout callbacks can trail kernel termination. Let those
        // already-written ACKs drain; each unresolved RPC has its own timeout.
        for callback in callbacks { callback() }
    }
}
