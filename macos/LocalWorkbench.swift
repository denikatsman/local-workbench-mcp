import AppKit
import SwiftUI
import Security
import WorkbenchProcessSupport

private let bundleID = Bundle.main.bundleIdentifier ?? "tools.localworkbench.launcher"

enum SetupError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case .message(let value) = self { return value }; return nil }
}

enum PairingCode {
    static func load() throws -> String {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: bundleID, kSecAttrAccount as String: "owner-consent"]
        var result: CFTypeRef?
        let status = SecItemCopyMatching((query.merging([kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne]) { _, new in new }) as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data,
           let value = String(data: data, encoding: .utf8), value.count >= 32 { return value }
        guard status == errSecItemNotFound else {
            throw SetupError.message("Unable to read the pairing code from Keychain (\(status)). Unlock your login keychain and try again.")
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw SetupError.message("Unable to generate a pairing code.")
        }
        let value = Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        var item = query
        item[kSecValueData as String] = Data(value.utf8)
        item[kSecAttrLabel as String] = "Local Workbench pairing code"
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let saved = SecItemAdd(item as CFDictionary, nil)
        guard saved == errSecSuccess else {
            throw SetupError.message("Unable to save the pairing code to Keychain (\(saved)).")
        }
        return value
    }
}

final class WorkbenchModel: ObservableObject {
    @Published var workspace = UserDefaults.standard.string(forKey: "workspace") ?? "" { didSet { if oldValue != workspace { cancelAutomaticRecovery() } } }
    @Published var permissions = UserDefaults.standard.object(forKey: "permissions") as? Int ?? 1 { didSet { if oldValue != permissions { cancelAutomaticRecovery() } } }
    @Published var capabilityProfile = ToolProfileSettings(defaults: .standard).profile { didSet { if oldValue != capabilityProfile { cancelAutomaticRecovery() } } }
    @Published var historyAccess = ToolProfileSettings(defaults: .standard).historyAccess { didSet { if oldValue != historyAccess { cancelAutomaticRecovery() } } }
    @Published var incomingFolder = UserDefaults.standard.string(forKey: "incomingFolder") ?? "" { didSet { if oldValue != incomingFolder { cancelAutomaticRecovery() } } }
    @Published private(set) var runningIncomingFolder = ""
    @Published var folderAccessMessage = ""
    @Published var incomingFolderDraft = ""
    @Published var autoStart = WorkbenchLaunchPolicy(arguments: ProcessInfo.processInfo.arguments, defaults: .standard).automaticStart { didSet { if oldValue != autoStart { cancelAutomaticRecovery() } } }
    @Published var status = "stopped"
    @Published var message = "Choose a project folder to get started."
    @Published var serverURL = ""
    @Published var copied = ""
    @Published var nativeDrainActive = false
    var process: Process?
    var input: FileHandle?
    var onStopped: (() -> Void)?
    var onShowPermissions: (() -> Void)?
    var onShowAppAccess: (() -> Void)?
    var onShowTerminalInput: (() -> Void)?
    var onShowFolderAccess: (() -> Void)?
    lazy var permissionCentre = PermissionsModel(directory: dataDirectory, preview: preview)
    lazy var appAccess = NativeOperationCentre(directory: dataDirectory)
    private var secret = ""
    private var hadError = false
    private var stopRequested = false
    private var ownedChildrenStopped = false
    private var childTickets = LauncherChildTickets()
    private var nativeReservation: FileHandle?
    private var nativeLifecycle = true
    private var listenerHandoffComplete = false
    private var listenerAcknowledged = false
    private var launcherExitObserved = false
    private var nativeDrainStarted = false
    private var nativeDrainAcknowledged = false
    private var nativeDrainWaiters: [() -> Void] = []
    private var nativeDrainGeneration = UUID()
    var cleanupUncertain = false
    private var recoveryPolicy = LauncherRecoveryPolicy()
    private var recoveryIdentity: LauncherRecoveryIdentity?
    private var recoveryOwnerSecret: String?
    private var recoveryDelay: TimeInterval?
    private var recoveryWork: DispatchWorkItem?
    private var recoveryGeneration = UUID()
    private var recoveryAllowedForLaunch = false
    private var runningRecoverySettings: [String: String] = [:]
    private let launchPolicy = WorkbenchLaunchPolicy(arguments: ProcessInfo.processInfo.arguments, defaults: .standard)
    private var preview: Bool { launchPolicy.preview }
    let dataDirectory = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(bundleID == "tools.localworkbench.launcher"
            ? "Library/Application Support/Local Workbench"
            : "Library/Application Support/Local Workbench Tests/" + bundleID, isDirectory: true)

    var busy: Bool { process != nil || nativeDrainActive || recoveryDelay != nil || recoveryWork != nil || cleanupUncertain }
    var ready: Bool { status == "ready" }
    var incomingFolderPending: Bool { busy && incomingFolder != runningIncomingFolder }
    var accessExplanation: String {
        if capabilityProfile == "source_research" { return "This profile permits source reads and evidence tools. File edits, general commands and app control are off." }
        if capabilityProfile == "selected_app" { return "App operation requires run access. This profile keeps general file tools and commands off." }
        return permissions == 2 ? "Commands run as your Mac user and can access files outside this folder."
                               : "File tools are limited to this folder. Command execution is off."
    }
    var permanent: Bool { FileManager.default.fileExists(atPath:
        dataDirectory.appendingPathComponent("named-tunnel.json").path) }

    func appear() {
        if preview {
            workspace = "~/Projects/My project"
            message = "Preview only. No connection has been started."
            return
        }
        if launchPolicy.permissionsOnly {
            message = "Permission checks only. The server will stay stopped until you choose Start."
            return
        }
        if !workspace.isEmpty {
            message = "Ready to start."
            if launchPolicy.shouldStart(resumeService: permissionCentre.preferences.resume_service,
                                        hasStarted: UserDefaults.standard.bool(forKey: "hasStarted")) { start() }
            else { permissionCentre.connectionReady() }
        }
        else if !permissionCentre.preferences.resume_service { permissionCentre.connectionReady() }
    }

    func chooseFolder() {
        let panel = NSOpenPanel()
        panel.title = "Choose the project folder ChatGPT can work with"
        panel.prompt = "Use this folder"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        if !workspace.isEmpty { panel.directoryURL = URL(fileURLWithPath: workspace) }
        if panel.runModal() == .OK, let url = panel.url {
            workspace = url.path
            message = "Ready to start."
            status = "stopped"
            save()
        }
    }

    func save() {
        guard !preview else { return }
        UserDefaults.standard.set(workspace, forKey: "workspace")
        UserDefaults.standard.set(permissions, forKey: "permissions")
        UserDefaults.standard.set(autoStart, forKey: "autoStart")
        UserDefaults.standard.set(incomingFolder, forKey: "incomingFolder")
        ToolProfileSettings(profile: capabilityProfile, historyAccess: historyAccess).save(defaults: .standard)
    }

    func chooseIncomingFolder() {
        guard !preview, !["committed", "relaunching", "verifying"].contains(permissionCentre.restartPhase) else { return }
        let panel = NSOpenPanel()
        panel.title = "Choose the folder where Chrome saves downloads"
        panel.message = "This additional access permits reading files; it does not grant editing or command execution. Existing project access and Chrome's download location stay unchanged."
        panel.prompt = "Allow reading this folder"
        panel.canChooseFiles = false; panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.directoryURL = incomingFolder.isEmpty
            ? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads", isDirectory: true)
            : URL(fileURLWithPath: incomingFolder)
        guard panel.runModal() == .OK, let selected = panel.url,
              !["committed", "relaunching", "verifying"].contains(permissionCentre.restartPhase) else { return }
        configureIncomingFolder(selected.path)
    }

    func configureIncomingFolder(_ path: String) {
        guard !preview, !["committed", "relaunching", "verifying"].contains(permissionCentre.restartPhase) else { return }
        do {
            let folder = try FolderAccessSettings.validate(path, privateDirectory: dataDirectory)
            incomingFolder = folder.path
            incomingFolderDraft = folder.path
            folderAccessMessage = ""
            save()
        } catch {
            folderAccessMessage = error.localizedDescription
        }
    }

    func removeIncomingFolder() {
        guard !preview, !["committed", "relaunching", "verifying"].contains(permissionCentre.restartPhase) else { return }
        incomingFolder = ""
        incomingFolderDraft = ""
        folderAccessMessage = ""
        save()
    }

    func applyFolderAccess() {
        guard !preview, incomingFolderPending else { return }
        permissionCentre.queueRestart()
    }

    func start() {
        guard !busy else { return }
        cancelAutomaticRecovery()
        startService()
    }

    private func startService() {
        guard !busy, !workspace.isEmpty, !preview else { return }
        hadError = false
        stopRequested = false
        ownedChildrenStopped = false
        childTickets = LauncherChildTickets()
        listenerHandoffComplete = false
        listenerAcknowledged = false
        launcherExitObserved = false
        nativeDrainStarted = false
        nativeDrainAcknowledged = false
        nativeDrainWaiters = []
        nativeDrainGeneration = UUID()
        cleanupUncertain = false
        recoveryAllowedForLaunch = true
        runningRecoverySettings = recoverySettings
        copied = ""
        serverURL = ""
        do {
            guard let settingsURL = Bundle.main.url(forResource: "runtime", withExtension: "json"),
                  let settings = try JSONSerialization.jsonObject(with: Data(contentsOf: settingsURL)) as? [String: String],
                  let resources = Bundle.main.resourceURL else {
                throw SetupError.message("App runtime settings are missing. Re-run the Mac app installer.")
            }
            let runtime = try WorkbenchRuntimeSettings.load(settings, resources: resources,
                fixture: bundleID.hasPrefix("tools.localworkbench.test."))
            if runtime.manifest != nil {
                var code: SecStaticCode?
                let created = SecStaticCodeCreateWithPath(Bundle.main.bundleURL as CFURL, SecCSFlags(), &code)
                guard created == errSecSuccess, let code,
                      SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess else {
                    throw SetupError.message("The installed app or its packaged runtime failed signature verification. Reinstall the verified build.")
                }
            }
            let repository = runtime.repository.path, python = runtime.python.path, cloudflared = runtime.cloudflared.path
            for path in [python, cloudflared] {
                guard FileManager.default.isExecutableFile(atPath: path) else {
                    throw SetupError.message("A required program is missing: \(path). Re-run the Mac app installer.")
                }
            }
            guard FileManager.default.fileExists(atPath: repository + "/src/local_workbench/launcher.py") else {
                throw SetupError.message("The Local Workbench project folder moved. Re-run its Mac app installer from the new location.")
            }
            let profileArguments = try ToolProfileSettings(profile: capabilityProfile, historyAccess: historyAccess).arguments()
            let oauthSettings = try OAuthDiscoverySettings(defaults: .standard)
            guard runningRecoverySettings["oauthDiscovery"] == oauthSettings.mode else {
                throw SetupError.message("The OAuth discovery setting changed while preparing launch. Start again to apply it safely.")
            }
            let oauthArguments = oauthSettings.arguments()
            let pairingCode = try PairingCode.load()
            guard recoveryOwnerSecret == nil || recoveryOwnerSecret == pairingCode else {
                throw SetupError.message("The pairing identity changed. Stop and Start to apply it safely.")
            }
            secret = pairingCode
            let child = Process()
            let lifecycleNonce = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            child.executableURL = URL(fileURLWithPath: python)
            child.currentDirectoryURL = URL(fileURLWithPath: repository)
            child.arguments = ["-B", "-s", "-m", "local_workbench.launcher", "--workspace", workspace,
                               "--data-dir", dataDirectory.path, "--cloudflared", cloudflared,
                               "--lifecycle-nonce", lifecycleNonce]
            if permissions >= 1 { child.arguments?.append("--allow-edits") }
            if permissions >= 2 { child.arguments?.append("--allow-commands") }
            child.arguments?.append(contentsOf: profileArguments)
            child.arguments?.append(contentsOf: oauthArguments)
            if !incomingFolder.isEmpty { child.arguments?.append(contentsOf: ["--incoming-folder", incomingFolder]) }
            runningIncomingFolder = incomingFolder
            let inherited = ProcessInfo.processInfo.environment
            var env = [String: String]()
            for key in ["HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR"] { env[key] = inherited[key] }
            env["HOME"] = FileManager.default.homeDirectoryForCurrentUser.path
            env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
            env["PYTHONPATH"] = repository + "/src"
            env["PYTHONUNBUFFERED"] = "1"
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            env["PYTHONNOUSERSITE"] = "1"
            if let browsers = runtime.browsers { env["PLAYWRIGHT_BROWSERS_PATH"] = browsers.path }
            env["LOCAL_WORKBENCH_OWNER_SECRET"] = secret
            env["LOCAL_WORKBENCH_BROWSER_REGISTRY"] = dataDirectory.appendingPathComponent("browser-bridge.json").path
            if let native = permissionCentre.bridge { env.merge(native.newLaunch()) { _, new in new } }
            env.merge(appAccess.newRuntimeEnvironment()) { _, new in new }
            child.environment = env
            let output = Pipe()
            var descriptors: [Int32] = [-1, -1]
            guard WB_CreateLifecyclePair(&descriptors) == 0 else {
                throw SetupError.message("Unable to create the owned lifecycle channel.")
            }
            let control = FileHandle(fileDescriptor: descriptors[0], closeOnDealloc: true)
            let childInput = FileHandle(fileDescriptor: descriptors[1], closeOnDealloc: true)
            // Receiver owns a distinct CLOEXEC descriptor. Stop may close the
            // writing handle without racing recvmsg against fd-number reuse.
            let receiveFD = fcntl(control.fileDescriptor, F_DUPFD_CLOEXEC, 0)
            guard receiveFD >= 0 else { throw SetupError.message("Unable to duplicate the listener receiver.") }
            var receiverScheduled = false
            defer { if !receiverScheduled { close(receiveFD) } }
            child.standardOutput = output
            child.standardInput = childInput
            var expectedPort: UInt16 = 0
            if permanent {
                let namedURL = dataDirectory.appendingPathComponent("named-tunnel.json")
                guard let named = try JSONSerialization.jsonObject(with: Data(contentsOf: namedURL)) as? [String: Any],
                      let number = named["port"] as? Int, let port = UInt16(exactly: number), port >= 1024 else {
                    throw SetupError.message("The permanent connection port is invalid.")
                }
                expectedPort = port
            }
            try FileManager.default.createDirectory(at: dataDirectory, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            let startupLog = dataDirectory.appendingPathComponent("startup.log")
            if !FileManager.default.fileExists(atPath: startupLog.path) {
                guard FileManager.default.createFile(atPath: startupLog.path, contents: nil,
                    attributes: [.posixPermissions: 0o600]) else {
                    throw SetupError.message("Unable to create the local startup log.")
                }
            }
            let errors = try FileHandle(forWritingTo: startupLog)
            try errors.truncate(atOffset: 0)
            defer { try? errors.close() }
            child.standardError = errors
            var decoder = LauncherEventDecoder()
            let generation = launcherCallbacks.begin()
            let termination = LauncherTerminationJoin(requireHandoff: true, requireDrain: true)
            output.fileHandleForReading.readabilityHandler = { [weak self] handle in
                let data = handle.availableData
                if data.isEmpty {
                    handle.readabilityHandler = nil
                    let incomplete = decoder.finish()
                    DispatchQueue.main.async {
                        guard let self = self else { return }
                        self.launcherCallbacks.perform(for: generation) {
                            if incomplete {
                                self.childTickets.invalidate()
                                self.message = "An incomplete launcher event was rejected. Open diagnostics."
                            }
                            if let status = termination.receiveEOF() { self.launcherStopped(status) }
                        }
                    }
                    return
                }
                let batch = decoder.append(data)
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    self.launcherCallbacks.perform(for: generation) {
                        if batch.omittedEvents > 0 {
                            self.childTickets.invalidate()
                            self.hadError = true
                            self.status = "error"
                            self.serverURL = ""
                            self.message = "Launcher status exceeded its event limit; \(batch.omittedEvents) events were omitted. Stop and restart Workbench."
                            return
                        }
                        for event in batch.events { self.receive(event) }
                        if batch.oversizedFrames > 0 || batch.rejectedFrames > 0 {
                            self.childTickets.invalidate()
                            self.message = "Invalid launcher status was rejected (\(batch.oversizedFrames) oversized, \(batch.rejectedFrames) malformed). Open diagnostics."
                        }
                    }
                }
            }
            child.terminationHandler = { [weak self] finished in
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    self.launcherCallbacks.perform(for: generation) {
                        self.launcherExited(finished.terminationStatus, termination: termination)
                    }
                }
            }
            save()
            status = "starting"
            message = "Starting…"
            try child.run()
            process = child
            input = control
            try? childInput.close()
            receiverScheduled = true
            DispatchQueue.global(qos: .utility).async { [weak self] in
                let fd = lifecycleNonce.withCString { WB_ReceiveLoopbackReservation(receiveFD, $0, expectedPort) }
                close(receiveFD) // sole receiver owner closes exactly once

                DispatchQueue.main.async {
                    guard let self else { if fd >= 0 { close(fd) }; return }
                    let accepted = self.launcherCallbacks.perform(for: generation) {
                        if fd >= 0 {
                            self.nativeReservation = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
                            if !self.stopRequested {
                                do {
                                    try control.write(contentsOf: Data(("reserved " + lifecycleNonce + "\n").utf8))
                                    self.listenerAcknowledged = true
                                } catch { /* No new child can precede the exact ACK. */ }
                            }
                        }
                        self.listenerHandoffComplete = true
                        if let status = termination.receiveHandoff() { self.launcherStopped(status) }
                    }
                    if !accepted && fd >= 0 { close(fd) }
                }
            }
        } catch {
            status = "error"
            message = error.localizedDescription
            secret = ""
            // Local validation/signature/runtime prerequisites require repair;
            // they are not transient child failures to retry unattended.
            cancelAutomaticRecovery()
        }
    }

    private func launcherExited(_ status: Int32, termination: LauncherTerminationJoin) {
        launcherExitObserved = true
        serverURL = ""
        if !hadError {
            self.status = "stopping"
            message = "Finishing native input and owned tools after launcher exit…"
        }
        // Cancellation must not depend on guardian EOF: a backend finalizer
        // may itself be waiting for the native operation to drain.
        requestNativeDrain { [weak self] in
            if let final = termination.receiveDrain() { self?.launcherStopped(final) }
        }
        if let final = termination.receiveExit(status) { launcherStopped(final) }
    }

    func requestNativeDrain(_ completion: @escaping () -> Void) {
        requestNativeDrain(using: { [weak self] done in self?.appAccess.finishServer(done) }, completion: completion)
    }

    func requestNativeDrain(using drain: (@escaping () -> Void) -> Void, completion: @escaping () -> Void) {
        if nativeDrainAcknowledged { completion(); return }
        nativeDrainWaiters.append(completion)
        guard !nativeDrainStarted else { return }
        nativeDrainStarted = true
        nativeDrainActive = true
        let generation = nativeDrainGeneration
        drain { [weak self] in
            guard let self, self.nativeDrainGeneration == generation, !self.nativeDrainAcknowledged else { return }
            self.nativeDrainAcknowledged = true
            self.nativeDrainActive = false
            let waiters = self.nativeDrainWaiters
            self.nativeDrainWaiters = []
            for waiter in waiters { waiter() }
        }
    }

    private func launcherStopped(_ terminationStatus: Int32) {
        launcherCallbacks.invalidate()
        recoveryDelay = recoveryPolicy.stopped(intentional: stopRequested,
            now: ProcessInfo.processInfo.systemUptime)
        let cleanupConfirmed = nativeLifecycle
            ? listenerHandoffComplete && (childTickets.emptyAndValid ||
                (listenerAcknowledged && nativeReservation != nil && childTickets.cleanupConfirmed))
            : ownedChildrenStopped
        if !cleanupConfirmed {
            cleanupUncertain = true
            cancelAutomaticRecovery()
            hadError = true
            status = "error"
            message = "The launcher exited without confirming child shutdown. Old tools or tunnel processes may still be running. Automatic recovery is paused; open diagnostics before starting again."
        } else {
            try? nativeReservation?.close()
            nativeReservation = nil
            cleanupUncertain = false
        }
        process = nil
        try? input?.close()
        input = nil
        serverURL = ""
        secret = ""
        if !hadError {
            status = terminationStatus == 0 || stopRequested ? "stopped" : "error"
            message = status == "error"
                ? "The launcher stopped unexpectedly. Open diagnostics, then try Start again."
                : "Stopped. Your files and saved tool history are retained."
        }
        onStopped?()
    }

    private var recoverySettings: [String: String] {
        ["workspace": workspace, "permissions": String(permissions), "profile": capabilityProfile,
         "history": String(historyAccess), "incoming": incomingFolder, "autoStart": String(autoStart),
         "oauthDiscovery": (try? OAuthDiscoverySettings(defaults: .standard).mode) ?? "invalid"]
    }

    func cancelAutomaticRecovery() {
        if process == nil && !nativeDrainActive && (recoveryDelay != nil || recoveryWork != nil) {
            status = "stopped"
            message = "Automatic recovery cancelled. Choose Start when ready."
        }
        recoveryAllowedForLaunch = false
        recoveryGeneration = UUID()
        recoveryWork?.cancel()
        recoveryWork = nil
        recoveryDelay = nil
        recoveryPolicy.cancel()
        recoveryIdentity = nil
        recoveryOwnerSecret = nil
    }

    // Called only after finishServer acknowledges the native cancellation and
    // retirement barrier. Normal Start rotates native claims/launch credentials.
    func scheduleRecoveryAfterDrain() {
        guard let delay = recoveryDelay, !stopRequested, !nativeDrainActive else { return }
        recoveryDelay = nil
        guard let identity = recoveryIdentity,
              (try? LauncherRecoveryIdentity.capture(directory: dataDirectory, settings: recoverySettings)) == identity,
              permissionCentre.restartPhase == "none" else {
            cancelAutomaticRecovery()
            status = "error"
            message = "The connection configuration changed. Stop and Start to apply it safely."
            return
        }
        let generation = recoveryGeneration
        status = "starting"
        message = "Restoring your permanent connection in \(Int(delay)) seconds. Interrupted work is not replayed…"
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.recoveryGeneration == generation else { return }
            self.recoveryWork = nil
            guard !self.stopRequested, !self.nativeDrainActive, self.process == nil,
                  self.permissionCentre.restartPhase == "none",
                  (try? LauncherRecoveryIdentity.capture(directory: self.dataDirectory, settings: self.recoverySettings)) == identity else {
                self.cancelAutomaticRecovery()
                self.status = "error"
                self.message = "The connection configuration changed. Stop and Start to apply it safely."
                return
            }
            self.startService()
        }
        recoveryWork = work
        enqueueRecovery(after: delay, work: work)
    }

    private func enqueueRecovery(after delay: TimeInterval, work: DispatchWorkItem) {
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: work)
    }

    private let launcherCallbacks = LauncherCallbackGate()

    private func receive(_ event: LauncherEvent) {
        let next = event.status
        if ["child_started", "child_stopped"].contains(next) {
            childTickets.receive(event)
            return
        }
        if next == "children_stopped" {
            ownedChildrenStopped = true
            return
        }
        guard !nativeDrainActive, !launcherExitObserved else { return }
        if stopRequested && (next == "starting" || next == "ready") { return }
        if next == "ready" && nativeLifecycle && (nativeReservation == nil || !childTickets.readyCoverage) {
            childTickets.invalidate()
            hadError = true
            status = "error"
            serverURL = ""
            message = "Owned child registration is incomplete. The reserved address is retained; recovery is blocked."
            return
        }
        if next == "error" { hadError = true }
        if hadError && next != "error" { return }
        status = next
        message = event.message ?? message
        if next == "ready" {
            if event.connection == "stable" && recoveryAllowedForLaunch && runningRecoverySettings == recoverySettings {
                let identity = try? LauncherRecoveryIdentity.capture(directory: dataDirectory, settings: recoverySettings)
                if recoveryIdentity == nil {
                    recoveryIdentity = identity
                    recoveryOwnerSecret = secret
                }
                if identity != nil && identity == recoveryIdentity {
                    recoveryPolicy.ready(permanent: true, now: ProcessInfo.processInfo.systemUptime)
                } else { cancelAutomaticRecovery() }
            } else { cancelAutomaticRecovery() }
            serverURL = event.url ?? ""
            UserDefaults.standard.set(true, forKey: "hasStarted")
            permissionCentre.connectionReady()
        }
        else { serverURL = "" }
    }

    func stop() {
        let wasBusy = busy
        cancelAutomaticRecovery()
        if cleanupUncertain {
            status = "error"
            serverURL = ""
            message = "Owned child shutdown is uncertain. The reserved address remains held; open diagnostics."
            return
        }
        guard wasBusy, !stopRequested else { return }
        stopRequested = true
        status = "stopping"
        serverURL = ""
        message = "Stopping the connection and local tools…"
        try? input?.write(contentsOf: Data("stop\n".utf8))
        try? input?.close()
        if process == nil && !nativeDrainActive {
            status = "stopped"
            message = "Stopped. Your files and saved tool history are retained."
        }
    }

    func copy(_ value: String, label: String, sensitive: Bool = false) {
        guard !value.isEmpty else { return }
        let clipboard = NSPasteboard.general
        clipboard.clearContents()
        if sensitive {
            clipboard.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
            clipboard.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.AutoGeneratedType"))
        }
        clipboard.setString(value, forType: .string)
        let version = clipboard.changeCount
        copied = label + " copied"
        if sensitive {
            DispatchQueue.main.asyncAfter(deadline: .now() + 90) {
                if clipboard.changeCount == version { clipboard.clearContents() }
            }
        }
    }

    func copyPairingCode() { copy(secret, label: "Pairing code", sensitive: true) }
    func openDiagnostics() {
        let startup = dataDirectory.appendingPathComponent("startup.log")
        let attributes = try? FileManager.default.attributesOfItem(atPath: startup.path)
        let path = ((attributes?[.size] as? NSNumber)?.intValue ?? 0) > 0
            ? startup : dataDirectory.appendingPathComponent("diagnostics.log")
        if FileManager.default.fileExists(atPath: path.path) { NSWorkspace.shared.open(path) }
    }
}

struct WorkbenchView: View {
    @ObservedObject var model: WorkbenchModel
    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            HStack(spacing: 14) {
                Image(systemName: "hammer.circle.fill").font(.system(size: 42)).foregroundStyle(.blue)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Local Workbench").font(.system(size: 25, weight: .semibold))
                    Text("Your local tools, connected to ChatGPT.").foregroundStyle(.secondary)
                }
                Spacer()
            }
            VStack(alignment: .leading, spacing: 12) {
                Text("Project folder").font(.headline)
                HStack {
                    Image(systemName: "folder").foregroundStyle(.secondary)
                    Text(model.workspace.isEmpty ? "No folder selected" : model.workspace)
                        .lineLimit(2).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                    Button("Choose…") { model.chooseFolder() }.disabled(model.busy)
                }
                Picker("Workbench access", selection: $model.permissions) {
                    Text("Read only").tag(0)
                    Text("Read & edit").tag(1)
                    Text("Read, edit & run").tag(2)
                }.pickerStyle(.segmented).disabled(model.busy)
                    .onChange(of: model.permissions) { _ in model.save() }
                Text(model.accessExplanation)
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Divider()
            HStack(alignment: .center, spacing: 12) {
                Circle().fill(model.ready ? Color.green : model.status == "error" ? Color.red : Color.secondary.opacity(0.5))
                    .frame(width: 9, height: 9)
                VStack(alignment: .leading, spacing: 5) {
                    Text(model.ready ? "Ready to connect" : model.status.capitalized).font(.headline)
                    Text(model.message).font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }.frame(maxWidth: .infinity, alignment: .leading)
                if model.status == "starting" || model.status == "stopping" { ProgressView().controlSize(.small) }
                Button(model.busy ? "Stop" : "Start") { model.busy ? model.stop() : model.start() }
                    .buttonStyle(.borderedProminent).controlSize(.large)
                    .disabled(model.workspace.isEmpty || model.status == "stopping")
            }
            .padding(14)
            .background(Color.secondary.opacity(0.07))
            .clipShape(RoundedRectangle(cornerRadius: 10))
            VStack(alignment: .leading, spacing: 12) {
                Text("Connect in ChatGPT").font(.headline)
                Text("1. Add a custom MCP connection using this server URL and OAuth.")
                    .font(.callout)
                HStack {
                    Text(model.serverURL.isEmpty ? "Your address appears after Start" : model.serverURL)
                        .font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading).lineLimit(3)
                    Button("Copy URL") { model.copy(model.serverURL, label: "Server URL") }.disabled(!model.ready)
                }.padding(12).background(Color.secondary.opacity(0.07)).clipShape(RoundedRectangle(cornerRadius: 8))
                Text("2. On the Local Workbench approval page, paste your pairing code into the owner secret field.")
                    .font(.callout).fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Copy pairing code") { model.copyPairingCode() }.disabled(!model.ready)
                    Button("Open ChatGPT ↗") { NSWorkspace.shared.open(URL(string: "https://chatgpt.com/")!) }
                    Spacer()
                    Text(model.copied).font(.caption).foregroundStyle(.secondary)
                }
                Text("Keep the pairing code private. Paste it only into the approval page, never into a chat. Copied codes clear after 90 seconds while this app is open.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Divider()
            VStack(alignment: .leading, spacing: 10) {
                Toggle("Start automatically when I open this app", isOn: $model.autoStart)
                    .onChange(of: model.autoStart) { _ in model.save() }
                Text(model.permanent
                    ? "Your server address stays the same after restarting. Keep this app running while using ChatGPT. Closing or quitting stops the connection and its running jobs."
                    : "The temporary address changes each time you start. Reconnect ChatGPT with the new URL. Closing or quitting this app stops the connection and its running jobs.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Permissions & Readiness…") { model.onShowPermissions?() }
                    Button("App access…") { model.onShowAppAccess?() }.disabled(ProcessInfo.processInfo.arguments.contains("--preview"))
                    Button("Folder access…") { model.onShowFolderAccess?() }.disabled(ProcessInfo.processInfo.arguments.contains("--preview"))
                }
                HStack {
                    Button("Local terminal input…") { model.onShowTerminalInput?() }.disabled(ProcessInfo.processInfo.arguments.contains("--preview"))
                    Spacer()
                    Button("Open diagnostics") { model.openDiagnostics() }.buttonStyle(.link)
                }
            }
        }.padding(28).frame(width: 590).fixedSize(horizontal: false, vertical: true)
    }
}

struct FolderAccessView: View {
    @ObservedObject var model: WorkbenchModel
    @ObservedObject var permissions: PermissionsModel

    var body: some View {
        ScrollView {
        VStack(alignment: .leading, spacing: 16) {
            Text("Folder access").font(.title2.bold())
            Text("Your project folder keeps its existing Workbench access. Add a separate read-only folder to capture files downloaded by Chrome.")
                .fixedSize(horizontal: false, vertical: true)
            Text("Incoming downloads").font(.headline)
            Text(model.incomingFolder.isEmpty ? "No incoming folder selected" : model.incomingFolder)
                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            Text("Choose Chrome's existing download folder. This additional access permits reading files; it does not grant editing or command execution. Existing project access still applies if the folders overlap. Chrome's download location stays unchanged.")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Choose folder…") { model.chooseIncomingFolder() }
                Button("Remove access") { model.removeIncomingFolder() }.disabled(model.incomingFolder.isEmpty)
            }.disabled(["committed", "relaunching", "verifying"].contains(permissions.restartPhase))
            TextField("Full incoming folder path", text: $model.incomingFolderDraft)
                .textFieldStyle(.roundedBorder)
                .disabled(["committed", "relaunching", "verifying"].contains(permissions.restartPhase))
            Button("Allow reading entered folder") { model.configureIncomingFolder(model.incomingFolderDraft) }
                .disabled(model.incomingFolderDraft.isEmpty || ["committed", "relaunching", "verifying"].contains(permissions.restartPhase))
            if !model.folderAccessMessage.isEmpty {
                Text(model.folderAccessMessage).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }
            if model.incomingFolderPending {
                Text("Folder access changes take effect after Workbench restarts. Current work keeps its existing access until then.")
                    .fixedSize(horizontal: false, vertical: true)
                if permissions.restartPhase == "queued" {
                    Text("Restart waiting for current work to finish.")
                    Button("Cancel pending restart") { permissions.cancelRestart() }
                } else {
                    Button("Apply when idle") { model.applyFolderAccess() }
                        .disabled(permissions.requestInProgress != nil || permissions.restartPhase != "none")
                }
            } else if !model.busy {
                Text("These choices apply when you next start Workbench.").foregroundStyle(.secondary)
            } else {
                Text(model.incomingFolder.isEmpty ? "No incoming folder access is enabled." : model.ready ? "Current folder access is active." : "Folder access is configured for this server start.").foregroundStyle(.secondary)
            }
        }.padding(24).frame(minWidth: 540, maxWidth: .infinity, alignment: .leading)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    let model = WorkbenchModel()
    var window: NSWindow!
    var quitting = false
    var restarting = false
    var permissionsWindow: NSWindow?
    var appAccessWindow: NSWindow?
    var terminalInputWindow: NSWindow?
    var toolProfilesWindow: NSWindow?
    var folderAccessWindow: NSWindow?
    var relaunchProcess: Process?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let presentsInitialUI = WorkbenchLaunchPolicy(arguments: ProcessInfo.processInfo.arguments,
            defaults: .standard).presentsInitialUI
        // Finder normally reuses the running bundle; enforce that for direct
        // binary launches too. The supervisor adds a separate ownership lock.
        if let peer = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
            .first(where: { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }) {
            if presentsInitialUI { peer.activate(options: [.activateAllWindows]) }
            NSApp.terminate(nil)
            return
        }
        let view = NSHostingView(rootView: WorkbenchView(model: model))
        model.onShowPermissions = { [weak self] in self?.showPermissions() }
        model.onShowAppAccess = { [weak self] in self?.showAppAccess() }
        model.onShowTerminalInput = { [weak self] in self?.showTerminalInput() }
        model.onShowFolderAccess = { [weak self] in self?.showFolderAccess() }
        model.permissionCentre.serviceRunning = { [weak self] in self?.model.busy ?? false }
        model.permissionCentre.windowVisible = { [weak self] in self?.permissionsWindow?.isVisible ?? false }
        model.permissionCentre.onRestart = { [weak self] in self?.restartWhenReady() }
        model.permissionCentre.startBridge()
        if !ProcessInfo.processInfo.arguments.contains("--preview") {
            model.appAccess.restartPending = { [weak self] in self?.model.permissionCentre.restartPhase != "none" }
            model.permissionCentre.nativeActivity = { [weak self] in self?.model.appAccess.activeIDs() ?? [] }
            model.permissionCentre.blockNativeGrants = { [weak self] blocked in self?.model.appAccess.blockGrants(blocked) }
            model.appAccess.blockGrants(model.permissionCentre.restartPhase != "none")
            model.appAccess.start()
            model.appAccess.terminalInput.onPrompt = { [weak self] in self?.model.message = "A terminal needs local input. Open Local terminal input to review it." }
        }
        // Passive checks must not depend on an activation notification.
        model.permissionCentre.refresh()
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 646, height: 720),
            styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "Local Workbench"
        window.contentView = view
        window.setContentSize(view.fittingSize)
        window.delegate = self
        window.center()
        if presentsInitialUI {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        }
        model.onStopped = { [weak self] in
            self?.finishChildShutdown()
        }
        model.appear()
        if presentsInitialUI && (!UserDefaults.standard.bool(forKey: "permissions-window-v2-seen") || ProcessInfo.processInfo.arguments.contains("--preview") || ProcessInfo.processInfo.arguments.contains("--permissions-only")) {
            UserDefaults.standard.set(true, forKey: "permissions-window-v2-seen")
            showPermissions()
        }
    }

    func finishChildShutdown() {
        finishChildShutdown { [weak self] completion in self?.model.appAccess.finishServer(completion) }
    }

    func finishChildShutdown(using drain: (@escaping () -> Void) -> Void) {
        let finalStatus = model.status, finalMessage = model.message
        model.nativeDrainActive = true
        model.status = "stopping"
        model.message = "Finishing native input before stopping…"
        model.requestNativeDrain(using: drain) { [weak self] in
            guard let self = self else { return }
            self.model.nativeDrainActive = false
            self.model.status = finalStatus
            self.model.message = finalMessage
            if self.quitting {
                if self.model.cleanupUncertain {
                    self.quitting = false
                    NSApp.reply(toApplicationShouldTerminate: false)
                } else { NSApp.reply(toApplicationShouldTerminate: true) }
            }
            else if self.restarting && !self.model.cleanupUncertain { self.completeRelaunch() }
            else { self.model.scheduleRecoveryAfterDrain() }
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        window?.makeKeyAndOrderFront(nil)
        return true
    }

    @objc func showPermissions() {
        if permissionsWindow == nil {
            let created = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 980, height: 750),
                                   styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
            created.title = "Permissions & Readiness"
            created.isReleasedWhenClosed = false
            created.contentView = NSHostingView(rootView: PermissionsView(model: model.permissionCentre))
            created.center(); permissionsWindow = created
        }
        permissionsWindow?.makeKeyAndOrderFront(nil)
        model.permissionCentre.refresh()
    }
    @objc func showAppAccess() {
        guard !ProcessInfo.processInfo.arguments.contains("--preview") else { return }
        if appAccessWindow == nil {
            let created = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 600, height: 480),
                styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
            created.title = "App access"; created.isReleasedWhenClosed = false
            created.contentView = NSHostingView(rootView: NativeOperationView(model: model.appAccess)); created.center()
            appAccessWindow = created
        }
        model.appAccess.refresh(); appAccessWindow?.makeKeyAndOrderFront(nil)
    }
    @objc func showTerminalInput() {
        guard !ProcessInfo.processInfo.arguments.contains("--preview") else { return }
        if terminalInputWindow == nil {
            let created = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 620, height: 450),
                styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
            created.title = "Local terminal input"; created.isReleasedWhenClosed = false
            created.contentView = NSHostingView(rootView: NativeTerminalInputView(model: model.appAccess.terminalInput))
            created.center(); terminalInputWindow = created
        }
        model.appAccess.terminalInput.refresh(); terminalInputWindow?.makeKeyAndOrderFront(nil)
    }

    @objc func showToolProfiles() {
        if toolProfilesWindow == nil {
            let created = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 580, height: 650),
                styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
            created.title = "Tool access"; created.isReleasedWhenClosed = false
            created.contentView = NSHostingView(rootView: ToolProfilesView(model: model))
            created.center(); toolProfilesWindow = created
        }
        toolProfilesWindow?.makeKeyAndOrderFront(nil)
    }

    @objc func showFolderAccess() {
        if folderAccessWindow == nil {
            let created = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 600, height: 560),
                styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
            created.title = "Folder access"; created.isReleasedWhenClosed = false
            created.contentView = NSHostingView(rootView: FolderAccessView(model: model, permissions: model.permissionCentre))
            created.center(); folderAccessWindow = created
        }
        folderAccessWindow?.makeKeyAndOrderFront(nil)
    }

    func restartWhenReady() {
        guard !model.cleanupUncertain else {
            model.permissionCentre.message = "Owned child shutdown is uncertain. The reserved address must remain held; relaunch is blocked."
            return
        }
        guard !restarting else { return }
        restarting = true
        let shouldResume = model.busy
        model.cancelAutomaticRecovery()
        model.permissionCentre.preferences.resume_service = shouldResume
        model.permissionCentre.save()
        if model.busy { model.stop() } else { completeRelaunch() }
    }

    func completeRelaunch() {
        guard restarting, relaunchProcess == nil else { return }
        guard let executable = Bundle.main.url(forAuxiliaryExecutable: "WorkbenchRelaunch") else {
            model.permissionCentre.message = "Relaunch helper is missing. Quit and reopen Workbench to finish the pending restart."; return
        }
        let process = Process(), output = Pipe()
        process.executableURL = executable
        process.arguments = [String(ProcessInfo.processInfo.processIdentifier), Bundle.main.bundlePath]
        process.standardOutput = output; process.standardInput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run(); relaunchProcess = process
            DispatchQueue.global().async { [weak self] in
                let reply = try? output.fileHandleForReading.read(upToCount: 6)
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    if reply == Data("ready\n".utf8) {
                        self.model.permissionCentre.preferences.restart_phase = "relaunching"
                        self.model.permissionCentre.save()
                        NSApp.terminate(nil)
                    } else {
                        self.model.permissionCentre.message = "Automatic relaunch could not be prepared. Quit and reopen Workbench; saved work and credentials are retained."
                    }
                }
            }
        } catch { model.permissionCentre.message = "Could not prepare relaunch: \(error.localizedDescription)" }
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if sender !== window { return true }
        NSApp.terminate(nil); return false
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !model.cleanupUncertain else {
            model.message = "Owned child shutdown is uncertain. The reserved address is retained; normal Quit is blocked. Open diagnostics."
            return .terminateCancel
        }
        let wasBusy = model.process != nil || model.nativeDrainActive
        model.cancelAutomaticRecovery()
        guard wasBusy else { return .terminateNow }
        quitting = true
        model.stop()
        return .terminateLater
    }
    func applicationWillTerminate(_ notification: Notification) {
        model.permissionCentre.bridge?.close()
        model.appAccess.bridge?.close()
        model.appAccess.controlBridge?.close()
    }
}

@main
struct LocalWorkbenchMain {
static func main() {
if CommandLine.arguments.contains("--owned-parked-capture-probe") || CommandLine.arguments.contains("--owned-parked-capture-public-best-probe") {
    FileHandle.standardError.write(Data("{\"status\":\"refused\",\"error\":\"owned_probe_not_compiled\"}\n".utf8))
    exit(64)
}
let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
let menu = NSMenu()
let applicationMenu = NSMenu()
applicationMenu.addItem(withTitle: "About Local Workbench", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
applicationMenu.addItem(NSMenuItem.separator())
let permissionsItem = NSMenuItem(title: "Permissions & Readiness…", action: #selector(AppDelegate.showPermissions), keyEquivalent: ",")
permissionsItem.target = delegate
applicationMenu.addItem(permissionsItem)
let appAccessItem = NSMenuItem(title: "App access…", action: #selector(AppDelegate.showAppAccess), keyEquivalent: "")
appAccessItem.target = delegate
applicationMenu.addItem(appAccessItem)
let folderAccessItem = NSMenuItem(title: "Folder access…", action: #selector(AppDelegate.showFolderAccess), keyEquivalent: "")
folderAccessItem.target = delegate
applicationMenu.addItem(folderAccessItem)
let terminalInputItem = NSMenuItem(title: "Local terminal input…", action: #selector(AppDelegate.showTerminalInput), keyEquivalent: "")
terminalInputItem.target = delegate
applicationMenu.addItem(terminalInputItem)
let toolProfilesItem = NSMenuItem(title: "Tool access…", action: #selector(AppDelegate.showToolProfiles), keyEquivalent: "")
toolProfilesItem.target = delegate
applicationMenu.addItem(toolProfilesItem)
applicationMenu.addItem(NSMenuItem.separator())
applicationMenu.addItem(withTitle: "Quit Local Workbench", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
let root = NSMenuItem()
root.submenu = applicationMenu
menu.addItem(root)
app.mainMenu = menu
app.run()
}
}
