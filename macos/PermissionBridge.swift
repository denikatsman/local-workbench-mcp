import Foundation
import Darwin
import Security

final class PermissionSocket {
    let generation = UUID().uuidString
    private(set) var launchID = UUID().uuidString
    private var runtimeGeneration: String?
    let token: String
    let path: String
    private let directory: String
    private let methods: Set<String>
    private let queue: DispatchQueue
    private let environmentPrefix: String
    private var listener: Int32 = -1
    private let clients = DispatchSemaphore(value: 4)
    private let admissionLock = NSLock()
    private var suspended = false
    var handler: (([String: Any]) -> [String: Any])?
    /// Optional completion path; completion occurs exactly once on queue. The
    /// client worker retains its fd/capacity while the ordinary lane is free.
    /// Overflow is parsed/rejected on the accept lane, never dispatched or queued.
    var deferredHandler: (([String: Any], @escaping ([String: Any]) -> Void) -> Void)?

    init(methods: Set<String> = ["snapshot", "poll", "commit_restart"], queue: DispatchQueue = .main,
         environmentPrefix: String = "LOCAL_WORKBENCH_NATIVE") throws {
        self.methods = methods; self.queue = queue; self.environmentPrefix = environmentPrefix
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw SetupError.message("Could not create private readiness capability.") }
        token = bytes.map { String(format: "%02x", $0) }.joined()
        var template = Array("/tmp/lwb-permissions-XXXXXX".utf8CString)
        guard let result = mkdtemp(&template) else { throw SetupError.message("Could not create private readiness directory.") }
        directory = String(cString: result); path = directory + "/s"
        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw SetupError.message("Could not create private readiness socket.") }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutablePointer(to: &address.sun_path) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: 104) { target in
                _ = path.withCString { strlcpy(target, $0, 104) }
            }
        }
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard bound == 0, chmod(path, 0o600) == 0, listen(listener, 8) == 0 else {
            Darwin.close(listener); listener = -1
            throw SetupError.message("Could not bind private readiness channel.")
        }
    }

    func newLaunch() -> [String: String] {
        admissionLock.lock(); defer { admissionLock.unlock() }
        launchID = UUID().uuidString; runtimeGeneration = nil; suspended = false
        return [environmentPrefix + "_SOCKET": path, environmentPrefix + "_TOKEN": token,
                environmentPrefix + "_GENERATION": generation, environmentPrefix + "_LAUNCH": launchID]
    }

    func suspend() {
        admissionLock.lock(); suspended = true; admissionLock.unlock()
    }

    func start() {
        let fd = listener
        DispatchQueue.global(qos: .utility).async { [weak self] in
            while let self = self, self.listener == fd {
                let client = accept(fd, nil, nil)
                if client < 0 { if errno == EINTR { continue }; break }
                guard self.clients.wait(timeout: .now()) == .success else {
                    // One bounded overflow peer on this lane; do not create more
                    // workers or retain an unbounded queue behind deferred work.
                    // Its response uses only admission state, not the engine lane.
                    self.serve(client, overloaded: true)
                    Darwin.close(client)
                    continue
                }
                DispatchQueue.global(qos: .utility).async {
                    defer { Darwin.close(client); self.clients.signal() }
                    self.serve(client)
                }
            }
        }
    }

    // All mutable launch/admission identity is protected independently of the
    // handler queue so overload reporting cannot wait on a blocked effect edge.
    private func admissionResponse(_ request: [String: Any], overloaded: Bool) -> ([String: Any], Bool) {
        admissionLock.lock(); defer { admissionLock.unlock() }
        var response: [String: Any] = ["version": 1, "request_id": request["request_id"] as? String ?? "",
            "app_generation": generation, "launch_id": launchID,
            "runtime_generation": request["runtime_generation"] as? String ?? "", "ok": false]
        guard request["version"] as? Int == 1, request["app_generation"] as? String == generation,
              request["launch_id"] as? String == launchID,
              let runtime = request["runtime_generation"] as? String, runtime.count == 32,
              let method = request["method"] as? String, methods.contains(method) else { return (response, false) }
        if let expected = runtimeGeneration, expected != runtime { return (response, false) }
        if suspended {
            response["error"] = ["code": "native_executor_stopping", "effect_state": "none"]
            return (response, false)
        }
        if overloaded {
            // This exact socket never enters the handler, even if capacity is
            // freed while its frame is read. Rejection must not pin a runtime.
            response["error"] = ["code": "native_executor_busy", "effect_state": "none"]
            return (response, false)
        }
        runtimeGeneration = runtime
        return (response, true)
    }

    private func serve(_ fd: Int32, overloaded: Bool = false) {
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, uid == getuid() else { return }
        var timeout = timeval(tv_sec: 3, tv_usec: 0)
        var noSignal: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
              setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
              setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else { return }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 8192)
        let readDeadline = ProcessInfo.processInfo.systemUptime + 3
        while data.count <= 262144 && !data.contains(10) {
            // A trickling peer must not renew the receive budget on each read,
            // especially while it owns the single overflow parsing lane.
            let remaining = readDeadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { return }
            let micros = max(1, Int(remaining * 1_000_000))
            var receiveTimeout = timeval(tv_sec: micros / 1_000_000, tv_usec: suseconds_t(micros % 1_000_000))
            guard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &receiveTimeout, socklen_t(MemoryLayout<timeval>.size)) == 0 else { return }
            let n = Darwin.read(fd, &buffer, min(buffer.count, 262145 - data.count))
            if n <= 0 { return }
            data.append(contentsOf: buffer.prefix(n))
        }
        guard data.count <= 262144, data.last == 10,
              let request = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let supplied = request["token"] as? String, secureEqual(supplied, token) else { return }
        var response: [String: Any] = [:]
        let completed = DispatchSemaphore(value: 0)
        var awaitingCompletion = false
        if overloaded {
            response = admissionResponse(request, overloaded: true).0
        } else {
            queue.sync {
                let admission = admissionResponse(request, overloaded: false)
                response = admission.0
                guard admission.1 else { return }
                if let deferredHandler = deferredHandler {
                    awaitingCompletion = true
                    var once = false
                    deferredHandler(request) { result in
                        guard !once else { return }
                        once = true
                        response.merge(result) { _, new in new }
                        completed.signal()
                    }
                } else { response.merge(handler?(request) ?? ["ok": false]) { _, new in new } }
            }
        }
        // Never wait for elapsed input on the authoritative engine lane. A
        // disconnected client cannot cancel or replay an already possible send.
        if awaitingCompletion { completed.wait() }
        var encoded = try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys])
        if encoded == nil || encoded!.count >= 262144 {
            // Preserve correlation, but never turn a lost effect receipt into
            // an assertion that nothing happened.
            var failure: [String: Any] = ["ok": false, "error": ["code": "native_response_limit", "effect_state": "unknown"]]
            for key in ["version", "request_id", "app_generation", "launch_id", "runtime_generation"] {
                failure[key] = response[key]
            }
            encoded = try? JSONSerialization.data(withJSONObject: failure, options: [.sortedKeys])
        }
        guard var encoded = encoded, encoded.count < 262144 else { return }
        encoded.append(10)
        let writeDeadline = ProcessInfo.processInfo.systemUptime + 3
        encoded.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                // Partial progress by a slow reader cannot renew this budget.
                // Lost/partial replies after dispatch keep the caller's original
                // unknown-effect recovery path; no input is replayed here.
                let remaining = writeDeadline - ProcessInfo.processInfo.systemUptime
                guard remaining > 0 else { return }
                let micros = max(1, Int(remaining * 1_000_000))
                var sendTimeout = timeval(tv_sec: micros / 1_000_000, tv_usec: suseconds_t(micros % 1_000_000))
                guard setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &sendTimeout, socklen_t(MemoryLayout<timeval>.size)) == 0 else { return }
                let n = Darwin.write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if n <= 0 { return }
                offset += n
            }
        }
    }

    func close() {
        if listener >= 0 { let fd = listener; listener = -1; shutdown(fd, SHUT_RDWR); Darwin.close(fd) }
        unlink(path); rmdir(directory)
    }
    deinit { close() }
}

func secureEqual(_ a: String, _ b: String) -> Bool {
    let lhs = Array(a.utf8), rhs = Array(b.utf8)
    guard lhs.count == rhs.count else { return false }
    return zip(lhs, rhs).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
}
