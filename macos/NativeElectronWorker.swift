import Foundation
import Darwin
import ReceiverProviderProtocol
import ReceiverProviderFileSecurity
import CryptoKit

/// The signed host alone constructs managed context and authorises effects.
/// Key operations use a sealed guardian which owns the original transport and
/// release independently of its validation child. Other routes keep the direct
/// worker. Losing host stdin prevents new work; no effect is retried.
final class NativeElectronWorker {
    typealias Authorise = ([String: Any]) throws -> Void
    typealias PointerProgress = ([String: Any]) throws -> Void
    /// A local arm observes one immutable original. It never grants authority.
    private final class Diagnostic {
        let directory: Int32, nonce: String, base: [String: Any]
        deinit { close(directory) }
        private init(directory: Int32, nonce: String, base: [String: Any]) {
            self.directory = directory; self.nonce = nonce; self.base = base
        }
        private static func safeFile(_ fd: Int32, _ info: stat) -> Bool {
            info.st_mode & S_IFMT == S_IFREG && info.st_uid == geteuid() && info.st_nlink == 1 &&
                info.st_mode & 0o7777 == 0o600 && LWProviderHasPrivateACL(fd)
        }
        static func arm(managed: [String: Any], operation: String, method: String, payload: [String: Any],
                        node: URL, entry: URL, birth: NativeProcessSnapshot, host: NativeProcessSnapshot, leaseInfo: stat,
                        launchedAt: Double, launchedMonotonic: Double) -> Diagnostic? {
            guard method == "pointer", !operation.isEmpty, operation.utf8.count <= 128,
                  let path = managed["session_root"] as? String else { return nil }
            let root = URL(fileURLWithPath: path, isDirectory: true)
            let directory = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard directory >= 0 else { return nil }
            var keep = false
            defer { if !keep { close(directory) } }
            var dir = stat(), named = stat()
            guard fstat(directory, &dir) == 0, lstat(path, &named) == 0,
                  dir.st_dev == named.st_dev, dir.st_ino == named.st_ino,
                  dir.st_mode & 0o7777 == 0o700, dir.st_uid == geteuid(), LWProviderHasPrivateACL(directory) else { return nil }
            let fd = openat(directory, "worker-lifecycle-arm.json", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { return nil }
            defer { close(fd) }
            guard (try? NativeProviderRecovery.validatePrivateDirectory(root)) != nil else { return nil }
            var before = stat(), after = stat()
            guard fstat(fd, &before) == 0, safeFile(fd, before), before.st_size > 0, before.st_size <= 4096 else { return nil }
            var bytes = Data(count: Int(before.st_size))
            let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            guard count == bytes.count, fstat(fd, &after) == 0, safeFile(fd, after),
                  before.st_size == after.st_size, before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
                  before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
                  let arm = LWProviderDecodeJSON(bytes, nil) as? [String: Any],
                  Set(arm.keys) == ["version", "nonce", "operation_id", "method", "issued_at", "expires_at"],
                  let version = arm["version"] as? NSNumber, CFGetTypeID(version) != CFBooleanGetTypeID(), !CFNumberIsFloatType(version), version == 1,
                  let nonce = arm["nonce"] as? String, UUID(uuidString: nonce) != nil,
                  arm["operation_id"] as? String == operation, arm["method"] as? String == "pointer",
                  let issued = arm["issued_at"] as? NSNumber, CFGetTypeID(issued) != CFBooleanGetTypeID(),
                  let expiry = arm["expires_at"] as? NSNumber, CFGetTypeID(expiry) != CFBooleanGetTypeID() else { return nil }
            let now = Date().timeIntervalSince1970
            guard issued.doubleValue.isFinite, expiry.doubleValue.isFinite, issued.doubleValue <= launchedAt,
                  launchedAt - issued.doubleValue <= 300, expiry.doubleValue > launchedAt, expiry.doubleValue > now,
                  expiry.doubleValue > issued.doubleValue, expiry.doubleValue - issued.doubleValue <= 300,
                  let payloadBytes = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]),
                  let context = try? NativeProviderRecovery.electronContextHash(managed) else { return nil }
            guard leaseInfo.st_mode & S_IFMT == S_IFREG, leaseInfo.st_uid == geteuid(),
                  leaseInfo.st_mode & 0o7777 == 0o600, leaseInfo.st_nlink == 1 else { return nil }
            func process(_ snapshot: NativeProcessSnapshot) -> [String: Any] {
                ["pid": snapshot.pid, "pid_version": snapshot.version, "uid": snapshot.uid, "real_uid": snapshot.realUID,
                 "start_seconds": snapshot.startSeconds, "start_microseconds": snapshot.startMicroseconds,
                 "executable": snapshot.executable]
            }
            let diagnostic = Diagnostic(directory: directory, nonce: nonce.lowercased(), base: [
                "version": 1, "nonce": nonce, "operation_id": operation, "method": method,
                "launched_at": launchedAt, "launched_monotonic": launchedMonotonic,
                "arm_issued_at": issued, "arm_expires_at": expiry,
                "process": process(birth), "host": process(host), "executable": node.path, "argv": [node.path, entry.path],
                "lease": ["device": String(leaseInfo.st_dev), "inode": String(leaseInfo.st_ino)],
                "context_sha256": context, "payload_sha256": SHA256.hash(data: payloadBytes).map { String(format: "%02x", $0) }.joined()])
            // Exclusive atomic publication makes nonce reuse fail closed locally.
            keep = true
            guard diagnostic.publish("launched") else { return nil }
            return diagnostic
        }
        @discardableResult func publish(_ phase: String, status: Int32? = nil, reason: Int? = nil, terminationObserved: Double? = nil) -> Bool {
            var row = base
            row["phase"] = phase; row["observed_at"] = Date().timeIntervalSince1970
            row["host_monotonic"] = ProcessInfo.processInfo.systemUptime
            if let terminationObserved = terminationObserved { row["termination_observed_monotonic"] = terminationObserved }
            if let status = status { row["termination_status"] = status }
            if let reason = reason { row["termination_reason"] = reason }
            guard var data = try? JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]), data.count < 8192 else { return false }
            data.append(10)
            let temp = ".worker-lifecycle-" + UUID().uuidString.lowercased()
            let fd = openat(directory, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
            guard fd >= 0 else { return false }
            defer { close(fd); unlinkat(directory, temp, 0) }
            var info = stat()
            guard fstat(fd, &info) == 0, Self.safeFile(fd, info) else { return false }
            let count = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
            guard count == data.count, fsync(fd) == 0 else { return false }
            // linkat never overwrites an existing record and publishes complete bytes.
            return linkat(directory, temp, directory, "worker-lifecycle-" + nonce + "." + phase + ".json", 0) == 0
        }
    }
    private final class DiagnosticSettlement {
        let lock = NSLock()
        var diagnostic: Diagnostic?, terminal: (Int32, Int, Double)?
        func attach(_ value: Diagnostic?) {
            lock.lock(); diagnostic = value; let ended = terminal; lock.unlock()
            if let ended = ended { value?.publish("settled", status: ended.0, reason: ended.1, terminationObserved: ended.2) }
        }
        func ended(status: Int32, reason: Int, observed: Double) -> Diagnostic? {
            lock.lock(); defer { lock.unlock() }
            terminal = (status, reason, observed); return diagnostic
        }
    }
    private final class Flight {
        let process: Process
        let operation: String, claim: String, bundle: String
        let birth: NativeProcessSnapshot
        let pointerBroker: NativeElectronPointerBroker?
        init(_ process: Process, operation: String, claim: String, bundle: String, birth: NativeProcessSnapshot,
             pointerBroker: NativeElectronPointerBroker?) {
            self.process = process; self.operation = operation; self.claim = claim; self.bundle = bundle; self.birth = birth
            self.pointerBroker = pointerBroker
        }
    }
    /// Handles an original child which exits before registration. Retirement
    /// waits for both that child and its independent release broker.
    private final class FlightRegistration {
        let lock = NSLock()
        var ended = false
        func register(_ body: () -> Void) { lock.lock(); defer { lock.unlock() }; if !ended { body() } }
        func end(_ body: () -> Void) { lock.lock(); defer { lock.unlock() }; guard !ended else { return }; ended = true; body() }
    }
    private final class Output {
        let lock = NSLock(), available = DispatchSemaphore(value: 0)
        var buffer = Data(), lines: [Data] = []
        var ended = false, failed = false, total = 0
        func append(_ data: Data) {
            lock.lock(); defer { lock.unlock(); available.signal() }
            total += data.count
            guard total <= 262144 else { failed = true; return }
            if data.isEmpty { ended = true; return }
            buffer.append(data)
            while let newline = buffer.firstIndex(of: 10) {
                lines.append(Data(buffer[..<newline])); buffer.removeSubrange(...newline)
            }
        }
        func next() -> (Data?, Bool) {
            lock.lock(); defer { lock.unlock() }
            if !lines.isEmpty { return (lines.removeFirst(), false) }
            return (nil, ended || failed)
        }
    }
    private let node: URL, script: URL, keyScript: URL?, pointerBrokerScript: URL?
    private let diagnosticQueue: DispatchQueue
    private let identities = NativeSystemProcessIdentity(metadata: { _ in nil })
    private let lock = NSLock()
    private var flights: [String: Flight] = [:]
    init(node: URL, script: URL, keyScript: URL? = nil,
         pointerBrokerScript: URL? = nil,
         diagnosticQueue: DispatchQueue = .global(qos: .utility)) {
        self.node = node; self.script = script; self.keyScript = keyScript; self.pointerBrokerScript = pointerBrokerScript; self.diagnosticQueue = diagnosticQueue
    }

    var activeIDs: [String] {
        lock.lock(); defer { lock.unlock() }
        return flights.values.map { $0.operation }.filter { !$0.isEmpty }
    }

    private func stop(_ flight: Flight, cooperative: Bool = false) {
        if cooperative { flight.pointerBroker?.cancel() }
        else { flight.pointerBroker?.stop() }
        if flight.process.isRunning,
           (try? identities.snapshot(flight.process.processIdentifier)) == flight.birth { flight.process.terminate() }
    }

    func cancel(operation: String? = nil, claim: String? = nil, bundle: String? = nil) {
        lock.lock()
        let selected = flights.values.filter {
            (operation == nil || $0.operation == operation) && (claim == nil || $0.claim == claim)
                && (bundle == nil || $0.bundle == bundle)
        }
        lock.unlock()
        for flight in selected {
            // Never signal a reused PID; the child handles SIGTERM as Stop and
            // still attempts its original, immutable key-up after a down.
            stop(flight, cooperative: true)
        }
    }

    func exchange(requestID: String, method: String, payload: [String: Any], managed: [String: Any],
                  operation: String = "", claim: String = "", bundle: String = "",
                  ownership: NativeProviderRecovery.ElectronOwnership,
                  pointerProgress: PointerProgress? = nil,
                  settled: @escaping () -> Void = {},
                  authorise: Authorise) throws -> [String: Any] {
        var processStarted = false
        // No child means no original transport can still send. After launch,
        // only that exact Process termination handler establishes settlement.
        defer { if !processStarted { settled() } }
        let entry = ["key_pair", "key_chord", "pointer"].contains(method) ? (keyScript ?? script) : script
        guard UUID(uuidString: requestID) != nil,
              ["observe", "key_pair", "key_chord", "consume_plain_text", "receipt", "refresh_for_capture", "pointer"].contains(method),
              FileManager.default.isExecutableFile(atPath: node.path), FileManager.default.fileExists(atPath: entry.path) else {
            throw NativeProviderHostFailure("native_electron_worker_unavailable")
        }
        let packet: [String: Any] = ["version": 1, "request_id": requestID, "host_pid": getpid(),
            "host_uptime": ProcessInfo.processInfo.systemUptime, "method": method, "payload": payload, "managed": managed]
        let pointerBroker = method == "pointer" ? pointerBrokerScript.map {
            NativeElectronPointerBroker(node: node, entry: $0, packet: packet, ownership: ownership)
        } : nil
        var bytes = try JSONSerialization.data(withJSONObject: packet, options: [.sortedKeys])
        guard bytes.count <= 65536 else { throw NativeProviderHostFailure("native_electron_request_limit") }
        bytes.append(10)
        try ownership.verify(managed)
        let inheritedLease = try ownership.inheritedHandle()
        defer { try? inheritedLease.close() }
        let process = Process(), input = Pipe(), output = Pipe(), collected = Output(), writeLock = NSLock()
        let registration = FlightRegistration()
        func writeFrame(_ frame: [String: Any]) throws {
            var data = try JSONSerialization.data(withJSONObject: frame, options: [.sortedKeys]); data.append(10)
            guard data.count <= 65536 else { throw NativeProviderHostFailure("native_electron_worker_frame_limit") }
            writeLock.lock(); defer { writeLock.unlock() }
            try input.fileHandleForWriting.write(contentsOf: data)
        }
        let diagnosticSettlement = DiagnosticSettlement(), diagnosticQueue = self.diagnosticQueue
        process.executableURL = node; process.arguments = [entry.path]
        process.standardInput = input; process.standardOutput = output
        // fd2 is reserved read-only ownership, never a diagnostics pipe. Its
        // shared flock remains held through the child's immutable cleanup.
        process.standardError = inheritedLease
        var environment = ProcessInfo.processInfo.environment
        for key in ["NODE_OPTIONS", "NODE_PATH", "ELECTRON_RUN_AS_NODE", "VSCODE_IPC_HOOK_CLI"] { environment.removeValue(forKey: key) }
        process.environment = environment
        let id = UUID().uuidString
        output.fileHandleForReading.readabilityHandler = { handle in
            let bytes = handle.availableData; collected.append(bytes)
            if bytes.isEmpty { handle.readabilityHandler = nil }
        }
        process.terminationHandler = { [weak self] original in
            let terminationObserved = ProcessInfo.processInfo.systemUptime
            let status = original.terminationStatus, reason = original.terminationReason.rawValue
            // stdout EOF owns completion. A process exit can precede the last
            // readability callback and must not hide its original result.
            let finish = {
                registration.end { if let self = self { self.lock.lock(); self.flights.removeValue(forKey: id); self.lock.unlock() } }
                settled()
                // A late attachment publishes only after original callback AND
                // the independent original-transport broker have both settled.
                let diagnostic = diagnosticSettlement.ended(status: status, reason: reason, observed: terminationObserved)
                if let diagnostic = diagnostic {
                    diagnosticQueue.async {
                        diagnostic.publish("settled", status: status, reason: reason, terminationObserved: terminationObserved)
                    }
                }
            }
            if let broker = pointerBroker { broker.finish(finish) } else { finish() }
        }
        try ownership.verify(managed)
        do { try process.run(); processStarted = true }
        catch { throw NativeProviderHostFailure("native_electron_worker_start_failed") }
        let launchedAt = Date().timeIntervalSince1970, launchedMonotonic = ProcessInfo.processInfo.systemUptime
        let birth: NativeProcessSnapshot
        do { birth = try identities.snapshot(process.processIdentifier) }
        catch {
            try? input.fileHandleForWriting.close()
            throw NativeProviderHostFailure("native_electron_worker_identity_unavailable")
        }
        if method == "pointer" {
            var leaseInfo = stat()
            if fstat(inheritedLease.fileDescriptor, &leaseInfo) == 0, let host = try? identities.snapshot(getpid()) {
                let capturedLease = leaseInfo, node = self.node
                // Optional filesystem I/O never delays original dispatch or its
                // settlement callback, and holds no additional ownership lease.
                diagnosticQueue.async {
                    diagnosticSettlement.attach(Diagnostic.arm(managed: managed, operation: operation, method: method,
                        payload: payload, node: node, entry: entry, birth: birth, host: host, leaseInfo: capturedLease,
                        launchedAt: launchedAt, launchedMonotonic: launchedMonotonic))
                }
            }
        }
        let flight = Flight(process, operation: operation, claim: claim, bundle: bundle, birth: birth, pointerBroker: pointerBroker)
        registration.register { lock.lock(); flights[id] = flight; lock.unlock() }
        var admitted = false, pointerBegan = false, pointerSequence = 0
        func acceptPointerSequence(_ message: [String: Any]) throws {
            guard method == "pointer", let number = message["sequence"] as? NSNumber,
                  CFGetTypeID(number) != CFBooleanGetTypeID(), !CFNumberIsFloatType(number),
                  number.int64Value > Int64(pointerSequence), number.int64Value <= 1024 else {
                throw NativeProviderHostFailure("native_electron_pointer_sequence", effectState: admitted ? "unknown" : "none")
            }
            pointerSequence = number.intValue
        }
        defer {
            pointerBroker?.stop()
            writeLock.lock(); try? input.fileHandleForWriting.close(); writeLock.unlock()
            // Do not hard-kill on timeout/host return. The bounded child must
            // finish original release; its termination handler retires flight.
            if !process.isRunning {
                output.fileHandleForReading.readabilityHandler = nil
            }
        }
        try ownership.verify(managed)
        do { try input.fileHandleForWriting.write(contentsOf: bytes) }
        catch { throw NativeProviderHostFailure("native_electron_worker_input_failed") }
        let deadline = ProcessInfo.processInfo.systemUptime + 12
        while ProcessInfo.processInfo.systemUptime < deadline {
            let (line, ended) = collected.next()
            if let line = line {
                guard let message = LWProviderDecodeJSON(line, nil) as? [String: Any],
                      message["request_id"] as? String == requestID else {
                    stop(flight)
                    throw NativeProviderHostFailure("native_electron_worker_protocol", effectState: admitted ? "unknown" : "none")
                }
                if message["event"] as? String == "authorise" {
                    guard (method == "pointer" || !admitted), let nonce = message["nonce"] as? String, UUID(uuidString: nonce) != nil,
                          let hash = message["context_hash"] as? String,
                          hash == (try? NativeProviderRecovery.electronContextHash(managed)) else {
                        stop(flight)
                        throw NativeProviderHostFailure("native_electron_authorisation_protocol", effectState: admitted ? "unknown" : "none")
                    }
                    if method == "pointer" {
                        try acceptPointerSequence(message)
                        let purpose = message["purpose"] as? String ?? ""
                        guard (!pointerBegan && purpose == "pointer_begin") || (pointerBegan && admitted && ["pointer_step", "pointer_hold"].contains(purpose)) else {
                            stop(flight)
                            throw NativeProviderHostFailure("native_electron_pointer_phase", effectState: admitted ? "unknown" : "none")
                        }
                        pointerBegan = true
                    }
                    var allowed = false
                    do { try ownership.verify(managed); try authorise(message); try ownership.verify(managed); allowed = true } catch { allowed = false }
                    var remaining: Double?
                    if method == "refresh_for_capture" || method == "pointer" {
                        let capture = payload["capture"] as? [String: Any]
                        let deadline = method == "pointer" ? capture?["deadline_host_monotonic"] as? Double ?? .nan
                            : payload["deadline_monotonic"] as? Double ?? .nan
                        let value = deadline - ProcessInfo.processInfo.systemUptime
                        remaining = value.isFinite ? max(0, min(30, value)) : 0
                        if remaining == 0 && message["purpose"] as? String != "pointer_hold" { allowed = false }
                    }
                    if let broker = pointerBroker {
                        do { allowed = try broker.admit(message, allowed: allowed) }
                        catch { allowed = false; broker.stop() }
                    }
                    var ack: [String: Any] = ["event": "authorised", "request_id": requestID,
                        "nonce": nonce, "context_hash": hash, "allowed": allowed]
                    // Child anchors this remaining duration BEFORE it emits
                    // admission, conservatively including startup/pipe delay.
                    if let remaining = remaining { ack[method == "pointer" ? "pointer_remaining_seconds" : "capture_remaining_seconds"] = remaining }
                    // A failed ACK write can be partial; preserve possible effect.
                    admitted = admitted || allowed
                    do { try writeFrame(ack) }
                    catch { throw NativeProviderHostFailure("native_electron_ack_unknown", effectState: admitted ? "unknown" : "none") }
                } else if message["event"] as? String == "pointer_transport", let broker = pointerBroker {
                    do {
                        try broker.forward(message) { response in
                            guard let rpc = message["rpc_id"] else { return }
                            do { try writeFrame(["event": "pointer_transport_result", "request_id": requestID, "rpc_id": rpc, "response": response]) }
                            catch { broker.stop() }
                        }
                    } catch {
                        stop(flight)
                        let code = (error as? NativeProviderHostFailure)?.code ?? "native_electron_pointer_broker_protocol"
                        throw NativeProviderHostFailure(code, effectState: admitted ? "unknown" : "none")
                    }
                } else if message["event"] as? String == "pointer_progress" {
                    try acceptPointerSequence(message)
                    guard pointerBegan, let progress = pointerProgress else {
                        stop(flight)
                        throw NativeProviderHostFailure("native_electron_pointer_progress", effectState: admitted ? "unknown" : "none")
                    }
                    do { try progress(message) }
                    catch {
                        stop(flight)
                        throw NativeProviderHostFailure("native_electron_pointer_progress", effectState: admitted ? "unknown" : "none")
                    }
                } else if message["event"] as? String == "result", let response = message["response"] as? [String: Any] {
                    if method == "pointer", !admitted, let value = response["result"] as? [String: Any],
                       value["ready"] as? Bool == true || value["possibly_sent"] as? Bool == true || value["dispatch_attempted"] as? Bool == true {
                        stop(flight)
                        throw NativeProviderHostFailure("native_electron_pointer_unadmitted_result", effectState: "unknown")
                    }
                    return response
                } else {
                    throw NativeProviderHostFailure("native_electron_worker_protocol", effectState: admitted ? "unknown" : "none")
                }
            } else if ended {
                throw NativeProviderHostFailure("native_electron_worker_closed", effectState: admitted ? "unknown" : "none")
            } else {
                _ = collected.available.wait(timeout: .now() + 0.05)
            }
        }
        if (try? identities.snapshot(process.processIdentifier)) == birth, process.isRunning { process.terminate() }
        throw NativeProviderHostFailure("native_electron_worker_timeout", effectState: admitted ? "unknown" : "none")
    }
}
