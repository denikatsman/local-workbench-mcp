import Foundation
import Darwin
import ReceiverProviderProtocol

struct NativeProviderEndpoint {
    let socketPath: String
    let token: String
    let session: String
    let generation: String
    let peerAuditToken: Data
}

struct NativeProviderWireFailure: Error {
    let code: String
    // Transport uncertainty is not a claim that an input effect occurred.
    // The caller must recover the original operation receipt, never resend it.
    let requestMayHaveBeenReceived: Bool
}

enum NativeProviderWire {
    static let maximumBytes = 262144

    static func now() -> Double {
        var value = timespec()
        guard clock_gettime(CLOCK_MONOTONIC, &value) == 0 else { return .nan }
        return Double(value.tv_sec) + Double(value.tv_nsec) / 1_000_000_000
    }

    static func exchange(endpoint: NativeProviderEndpoint, requestID: String, method: String,
                         payload: [String: Any], timeout: Double = 3) throws -> [String: Any] {
        var sent = 0
        func failure(_ code: String) -> NativeProviderWireFailure {
            NativeProviderWireFailure(code: code, requestMayHaveBeenReceived: sent > 0)
        }
        guard timeout.isFinite, timeout > 0, timeout <= 10,
              endpoint.socketPath.hasPrefix("/"), endpoint.socketPath.utf8.count < 104,
              !endpoint.socketPath.utf8.contains(0),
              endpoint.token.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              UUID(uuidString: endpoint.session) != nil, UUID(uuidString: endpoint.generation) != nil,
              UUID(uuidString: requestID) != nil,
              ["hello", "observe", "key_pair", "key_chord", "key_sequence", "consume_plain_text", "cancel", "cancel_request", "receipt", "handover"].contains(method),
              method != "handover" || payload.isEmpty,
              endpoint.peerAuditToken.count == MemoryLayout<audit_token_t>.size else {
            throw failure("native_provider_envelope_invalid")
        }
        let started = now(), deadline = started + timeout
        guard started.isFinite, deadline.isFinite else { throw failure("native_provider_clock_unavailable") }
        let packet: [String: Any] = ["version": 1, "request_id": requestID, "method": method,
            "token": endpoint.token, "session": endpoint.session, "generation": endpoint.generation,
            "transport_clock": "clock_monotonic_v1", "deadline_monotonic": deadline, "payload": payload]
        guard JSONSerialization.isValidJSONObject(packet),
              var encoded = try? JSONSerialization.data(withJSONObject: packet, options: [.sortedKeys]),
              encoded.count < maximumBytes else { throw failure("native_provider_request_limit") }
        encoded.append(10)

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw failure("native_provider_socket_unavailable") }
        defer { Darwin.close(fd) }
        let flags = fcntl(fd, F_GETFL, 0)
        var noSignal: Int32 = 1
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
              fcntl(fd, F_SETFD, FD_CLOEXEC) == 0,
              setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout.size(ofValue: noSignal))) == 0 else {
            throw failure("native_provider_socket_setup_failed")
        }
        func waitFor(_ events: Int16) throws {
            while true {
                let remaining = deadline - now()
                guard remaining.isFinite, remaining > 0 else { throw failure("native_provider_timeout") }
                var item = pollfd(fd: fd, events: events, revents: 0)
                let result = poll(&item, 1, Int32(max(1, min(10_000, ceil(remaining * 1000)))))
                if result < 0, errno == EINTR { continue }
                guard result > 0 else { throw failure(result == 0 ? "native_provider_timeout" : "native_provider_poll_failed") }
                if item.revents & events != 0 { return }
                if events == Int16(POLLIN), item.revents & Int16(POLLHUP) != 0 { return }
                throw failure("native_provider_connection_closed")
            }
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutablePointer(to: &address.sun_path) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: 104) { target in
                _ = endpoint.socketPath.withCString { strlcpy(target, $0, 104) }
            }
        }
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if connected != 0 {
            guard [EINPROGRESS, EAGAIN, EINTR].contains(errno) else { throw failure("native_provider_connect_failed") }
            try waitFor(Int16(POLLOUT))
            var error: Int32 = 0, length = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0, error == 0 else {
                throw failure("native_provider_connect_failed")
            }
        }
        // Bind the socket to the exact kernel-issued process generation before
        // transmitting the capability or any task data. UID alone is insufficient.
        var audit = audit_token_t(), length = socklen_t(MemoryLayout<audit_token_t>.size)
        let peerResult = withUnsafeMutableBytes(of: &audit) {
            getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, $0.baseAddress, &length)
        }
        let actualAudit = withUnsafeBytes(of: audit) { Data($0) }
        guard peerResult == 0, length == MemoryLayout<audit_token_t>.size,
              actualAudit == endpoint.peerAuditToken else { throw failure("native_provider_peer_changed") }

        try encoded.withUnsafeBytes { bytes in
            while sent < bytes.count {
                try waitFor(Int16(POLLOUT))
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: sent), bytes.count - sent)
                if count < 0, [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
                guard count > 0 else { throw failure("native_provider_write_failed") }
                sent += count
            }
        }
        // The peer must see a complete, single request followed by write EOF
        // before scheduling work. Packet boundaries are not message boundaries.
        guard shutdown(fd, SHUT_WR) == 0 else { throw failure("native_provider_write_eof_failed") }
        var response = Data(), buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            try waitFor(Int16(POLLIN))
            let count = Darwin.read(fd, &buffer, min(buffer.count, max(1, maximumBytes - response.count)))
            if count < 0, [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
            if count == 0 { break }
            guard count > 0 else { throw failure("native_provider_read_failed") }
            guard response.count + count <= maximumBytes else { throw failure("native_provider_response_limit") }
            response.append(contentsOf: buffer.prefix(count))
        }
        guard response.last == 10, response.dropLast().contains(10) == false,
              let value = LWProviderDecodeJSON(response, nil) as? [String: Any],
              let version = value["version"] as? NSNumber,
              CFGetTypeID(version) != CFBooleanGetTypeID(),
              !CFNumberIsFloatType(version), version == 1,
              value["request_id"] as? String == requestID,
              value["session"] as? String == endpoint.session,
              value["generation"] as? String == endpoint.generation else {
            throw failure("native_provider_response_binding_invalid")
        }
        guard now() < deadline else { throw failure("native_provider_timeout") }
        return value
    }
}
