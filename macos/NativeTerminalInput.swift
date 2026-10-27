import AppKit
import SwiftUI
import Darwin

final class NativeTerminalInput: ObservableObject {
    struct Prompt {
        let id: String, terminalID: String, generation: String, socket: String, token: String
        let program: String, workspace: String, expires: Double
        var state = "pending", receipt: [String: Any]?
        var submissionID = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    }
    private let lock = NSLock()
    private var prompts: [String: Prompt] = [:]
    @Published var rows: [[String: Any]] = []
    @Published var selectedID: String?
    @Published var secret = ""
    @Published var appendReturn = true
    @Published var message = "No terminal is waiting for local input."
    var onPrompt: (() -> Void)?

    private func summary(_ prompt: Prompt) -> [String: Any] {
        ["prompt_id": prompt.id, "terminal_id": prompt.terminalID, "generation": prompt.generation,
         "program": prompt.program, "workspace": prompt.workspace, "expires_at": prompt.expires,
         "state": prompt.state, "receipt": prompt.receipt as Any? ?? NSNull()]
    }
    func refresh() {
        lock.lock()
        let now = Date().timeIntervalSince1970
        for (id, var prompt) in prompts where prompt.state == "pending" && prompt.expires <= now {
            prompt.state = "expired"; prompts[id] = prompt
        }
        let rows = prompts.values.sorted { $0.expires < $1.expires }.map(summary)
        lock.unlock()
        DispatchQueue.main.async { self.rows = rows }
    }
    func request(_ packet: [String: Any]) throws -> [String: Any] {
        let id = packet["prompt_id"] as? String ?? ""
        let terminal = packet["terminal_id"] as? String ?? "", generation = packet["generation"] as? String ?? ""
        let token = packet["local_token"] as? String ?? "", socket = packet["local_socket"] as? String ?? ""
        guard [id, terminal, generation].allSatisfy({ $0.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil }),
              token.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              socket.hasPrefix("/tmp/lwb-pty-input-"), socket.hasSuffix("/s"), socket.utf8.count < 104,
              let program = packet["program"] as? String, program.utf8.count <= 4096,
              let workspace = packet["workspace"] as? String, workspace.utf8.count <= 4096 else {
            throw NativeFailure("local_terminal_prompt_invalid")
        }
        lock.lock()
        defer { lock.unlock() }
        if let old = prompts[id] {
            guard old.terminalID == terminal, old.generation == generation, old.socket == socket, old.token == token else {
                throw NativeFailure("local_terminal_prompt_conflict")
            }
            return ["ok": true, "prompt": summary(old), "replayed": true]
        }
        if prompts.count >= 20 { prompts = prompts.filter { ["pending", "sending", "unknown"].contains($0.value.state) } }
        guard prompts.count < 20 else { throw NativeFailure("local_terminal_prompt_limit") }
        let prompt = Prompt(id: id, terminalID: terminal, generation: generation, socket: socket, token: token,
                            program: program, workspace: workspace, expires: Date().timeIntervalSince1970 + 300)
        prompts[id] = prompt
        DispatchQueue.main.async { self.selectedID = id; self.message = "A terminal needs local input. Check the program and workspace before sending."; self.onPrompt?(); self.refresh() }
        return ["ok": true, "prompt": summary(prompt), "local_input_required": true]
    }
    func status(_ id: String) throws -> [String: Any] {
        refresh(); lock.lock(); defer { lock.unlock() }
        guard let prompt = prompts[id] else { throw NativeFailure("local_terminal_prompt_unknown") }
        return ["ok": true, "prompt": summary(prompt)]
    }
    func activeIDs() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return prompts.values.filter { ["pending", "sending", "unknown"].contains($0.state) && $0.expires > Date().timeIntervalSince1970 }
            .map { "terminal-input:" + $0.id }
    }
    func cancel(_ id: String) {
        lock.lock()
        if var prompt = prompts[id], prompt.state != "sending" { prompt.state = "cancelled"; prompts[id] = prompt }
        lock.unlock(); secret = ""; refresh()
    }
    func submit() {
        guard let id = selectedID else { return }
        let bytes = Data((secret + (appendReturn ? "\n" : "")).utf8)
        secret = ""
        guard bytes.count > 0 && bytes.count <= 4096 else { message = "Enter at most 4 KiB for local terminal input."; return }
        lock.lock()
        guard var prompt = prompts[id], prompt.state == "pending", prompt.expires > Date().timeIntervalSince1970 else { lock.unlock(); message = "This local input request has ended."; return }
        prompt.state = "sending"; prompts[id] = prompt; lock.unlock()
        refresh()
        DispatchQueue.global(qos: .userInitiated).async {
            var receipt: [String: Any]
            do { receipt = try self.deliver(prompt, bytes: bytes) }
            catch { receipt = ["ok": false, "error": "local_delivery_unknown", "effect_state": "unknown"] }
            self.lock.lock()
            if var current = self.prompts[id] {
                current.receipt = receipt
                current.state = receipt["ok"] as? Bool == true ? "submitted" : receipt["effect_state"] as? String == "none" ? "refused" : "unknown"
                self.prompts[id] = current
            }
            self.lock.unlock()
            DispatchQueue.main.async {
                self.message = receipt["ok"] as? Bool == true ? "Input sent locally. Check the terminal for the program’s result."
                    : receipt["effect_state"] as? String == "none" ? "Input was refused before delivery. Inspect the terminal and request local input again."
                    : "Delivery is uncertain. Inspect the terminal before entering the input again."
                self.refresh()
            }
        }
    }
    private func deliver(_ prompt: Prompt, bytes: Data) throws -> [String: Any] {
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw NativeFailure("local_terminal_unavailable") }
        defer { Darwin.close(fd) }
        var timeout = timeval(tv_sec: 3, tv_usec: 0), noSignal: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX); address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutablePointer(to: &address.sun_path) { pointer in pointer.withMemoryRebound(to: CChar.self, capacity: 104) { target in
            _ = prompt.socket.withCString { strlcpy(target, $0, 104) }
        } }
        let connected = withUnsafePointer(to: &address) { pointer in pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard connected == 0 else { throw NativeFailure("local_terminal_unavailable") }
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, uid == getuid() else { throw NativeFailure("local_terminal_identity") }
        let payload = try JSONSerialization.data(withJSONObject: ["version": 1, "terminal_id": prompt.terminalID,
            "generation": prompt.generation, "token": prompt.token, "submission_id": prompt.submissionID, "data": bytes.base64EncodedString()])
        var length = UInt32(payload.count)
        var framed = withUnsafeBytes(of: &length) { Data($0) }; framed.append(payload)
        try framed.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                guard count > 0 else { throw NativeFailure("local_terminal_delivery_unknown", "unknown") }; offset += count
            }
        }
        func exact(_ count: Int) throws -> Data {
            var result = Data(), buffer = [UInt8](repeating: 0, count: count)
            while result.count < count {
                let read = Darwin.read(fd, &buffer, count - result.count)
                guard read > 0 else { throw NativeFailure("local_terminal_delivery_unknown", "unknown") }
                result.append(contentsOf: buffer.prefix(read))
            }
            return result
        }
        let header = try exact(4)
        let count = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
        guard count > 0 && count <= 65536,
              let receipt = try JSONSerialization.jsonObject(with: exact(Int(count))) as? [String: Any],
              receipt["terminal_id"] as? String == prompt.terminalID,
              receipt["generation"] as? String == prompt.generation,
              receipt["submission_id"] as? String == prompt.submissionID else { throw NativeFailure("local_terminal_receipt_mismatch", "unknown") }
        return receipt
    }
}

struct NativeTerminalInputView: View {
    @ObservedObject var model: NativeTerminalInput
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Local terminal input").font(.title2.bold())
            Text("Input goes directly to the selected owned terminal. It is not sent through the model or a tool argument.").foregroundStyle(.secondary)
            ForEach(model.rows.indices, id: \.self) { index in
                let row = model.rows[index]
                VStack(alignment: .leading, spacing: 5) {
                    Text(row["program"] as? String ?? "Selected program").font(.headline)
                    Text(row["workspace"] as? String ?? "").font(.caption).foregroundStyle(.secondary)
                    HStack {
                        Text(row["state"] as? String ?? "Unknown")
                        if let id = row["prompt_id"] as? String, row["state"] as? String == "pending" {
                            Button("Select") { model.secret = ""; model.selectedID = id }
                            Button("Cancel request") { model.cancel(id) }
                        }
                    }
                }
            }
            SecureField("Local input", text: $model.secret)
            Toggle("Send Return after input", isOn: $model.appendReturn)
            Button("Send to terminal") { model.submit() }.disabled(model.secret.isEmpty || model.selectedID == nil)
            Text(model.message).font(.callout).fixedSize(horizontal: false, vertical: true)
            Text("The terminal must still have echo disabled. The destination program controls any later output. Cancelling this request leaves the job running.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }.padding(24).frame(minWidth: 560, minHeight: 350)
    }
}
