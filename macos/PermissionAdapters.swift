import AppKit
import ApplicationServices
import AVFoundation
import AppTrackingTransparency
import Contacts
import CoreBluetooth
import CoreLocation
import CoreAudio
import EventKit
import Intents
import Network
import Photos
import Security
import Speech
import UserNotifications
import UniformTypeIdentifiers

final class PermissionsModel: NSObject, ObservableObject, CLLocationManagerDelegate, CBCentralManagerDelegate {
    @Published var catalogue: PermissionCatalogue?
    @Published var observations: [String: PermissionObservation] = [:]
    @Published var message = "Choose a permission to set it up."
    @Published var requestInProgress: String?
    @Published var restartPhase = "none"
    @Published var restartCancellationPending = false
    @Published var activity = "Waiting for current service activity."
    @Published var search = ""
    @Published var filter = "Setup"
    @Published var selection: String?
    @Published var queue: [String] = []
    @Published var queueIndex = 0
    @Published var showPreparation = false
    @Published var preparing = false
    @Published var selectedForPreparation: Set<String> = []
    @Published var setupStateWritable = true
    let directory: URL
    let preview: Bool
    var preferences = PermissionPreferences()
    var bridge: PermissionSocket?
    var nativeActivity: (() -> [String])?
    var blockNativeGrants: ((Bool) -> Void)?
    var onRestart: (() -> Void)?
    var serviceRunning: (() -> Bool)?
    var locationManager: CLLocationManager?
    var bluetoothManager: CBCentralManager?
    var networkBrowser: NWBrowser?
    var networkRequestID: UUID?
    let eventStore = EKEventStore()
    private var refreshPending = false
    private var launchedAfterRestart = false
    private var requestTimeout: DispatchWorkItem?
    private var snapshotWrite: DispatchWorkItem?
    private var requestAttempt: UUID?
    var windowVisible: (() -> Bool)?
    private var statusTimer: Timer?
    private var watchedSettings: String?
    private var watchedUntil = Date.distantPast
    private var lastRefresh = Date.distantPast

    init(directory: URL, preview: Bool) {
        self.directory = directory
        self.preview = preview
        super.init()
        do {
            guard let url = Bundle.main.url(forResource: "permissions_catalogue", withExtension: "json") else {
                throw SetupError.message("The permission catalogue is missing. Reinstall this build.")
            }
            catalogue = try JSONDecoder().decode(PermissionCatalogue.self, from: Data(contentsOf: url))
            if !preview, let data = try? Data(contentsOf: stateURL) {
                preferences = try JSONDecoder().decode(PermissionPreferences.self, from: data)
            }
            launchedAfterRestart = ["queued", "committed", "relaunching", "verifying"].contains(preferences.restart_phase)
            if launchedAfterRestart { preferences.restart_phase = "verifying" }
            restartPhase = preferences.restart_phase
            queue = preferences.preparation_queue; queueIndex = preferences.preparation_index
            preparing = queueIndex < queue.count
            selection = preparing ? queueCurrent?.id : catalogue?.entries.first?.id
        } catch {
            setupStateWritable = false
            message = "Saved permission setup could not load and has been preserved: \(error.localizedDescription). Passive checks remain available."
        }
        NotificationCenter.default.addObserver(forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in
            self?.refresh()
        }
        statusTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            self?.finishLocalRestartIfIdle()
            guard let self = self, !self.preview, self.windowVisible?() == true else { return }
            let watching = self.watchedSettings != nil && Date() < self.watchedUntil
            if watching || Date().timeIntervalSince(self.lastRefresh) >= 5 {
                self.refresh()
                if let id = self.watchedSettings, self.observations[id]?.approval == "allowed" {
                    self.watchedSettings = nil
                    self.message = "\(self.entries.first(where: { $0.id == id })?.name ?? "Access") is enabled."
                    self.save()
                }
            }
            if Date() >= self.watchedUntil { self.watchedSettings = nil }
        }
    }

    var stateURL: URL { directory.appendingPathComponent("permissions-readiness.json") }
    var entries: [PermissionEntry] { catalogue?.entries ?? [] }
    var current: PermissionEntry? { entries.first { $0.id == selection } }
    var queueCurrent: PermissionEntry? {
        guard preparing, queueIndex < queue.count else { return nil }
        return entries.first { $0.id == queue[queueIndex] }
    }
    var filtered: [PermissionEntry] {
        entries.filter { entry in
            let state = observations[entry.id] ?? PermissionObservation()
            let matches = entry.matchesSearch(search)
            let usable = entry.setupEntry && state.readiness != "unavailable"
            let included = filter == "Full catalogue" || (filter == "Setup" && usable)
                || (filter == "Needs attention" && usable && state.needsAttention)
                || (filter == "Pending restart" && preferences.restart_categories.contains(entry.id))
            return matches && included
        }
    }

    @discardableResult func save() -> Bool {
        guard !preview, setupStateWritable else { return false }
        do { try writePermissionState(JSONEncoder().encode(preferences), to: stateURL); return true }
        catch { message = "Could not save setup progress. \(error.localizedDescription)"; return false }
    }

    func publish(_ id: String, _ approval: String, note: String = "Authorization API checked for this native app; no personal records were read.", verified: Bool = true, levels: [String: String]? = nil) {
        guard let entry = entries.first(where: { $0.id == id }) else { return }
        let old = observations[id]
        var value = PermissionObservation(approval: approval,
            readiness: ["allowed", "limited"].contains(approval) && verified ? "verified" : "unverified",
            note: note, target: preferences.targets[id], access_levels: levels,
            verification: verified ? "authorization_api" : "not_established")
        if !entry.available || approval == "unavailable" { value.readiness = "unavailable" }
        // A successful current-process preflight is already effective. Do not
        // invent a restart requirement solely because its value changed.
        if preferences.restart_categories.contains(id) { value.readiness = "pending_restart" }
        observations[id] = value
        preferences.previous_approvals[id] = approval
        if old?.approval != value.approval || old?.readiness != value.readiness || old?.note != value.note || old?.target != value.target || old?.access_levels != value.access_levels {
            scheduleSnapshot()
        }
    }

    private func scheduleSnapshot() {
        guard !preview else { return }
        snapshotWrite?.cancel()
        let pending = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            let snapshot: [String: Any] = ["schema_version": 1, "owner": permissionOwner(),
                "recorded_at": Date().timeIntervalSince1970, "catalogue_version": self.catalogue?.catalogue_version ?? "unknown",
                "request_in_progress": self.requestInProgress as Any? ?? NSNull(),
                "observations": self.observations.mapValues { jsonDictionary($0) },
                "restart_phase": self.restartPhase,
                "scope": "diagnostic snapshot; each entry retains its own observation time, not a permanent authorization record"]
            if let data = try? JSONSerialization.data(withJSONObject: snapshot, options: [.sortedKeys]) {
                try? writePermissionState(data, to: self.directory.appendingPathComponent("permissions-observation.json"))
            }
        }
        snapshotWrite = pending
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3, execute: pending)
    }

    func refresh() {
        lastRefresh = Date()
        guard !preview else {
            for entry in entries { publish(entry.id, "unknown", note: "Preview only. No permission API was called.", verified: false) }
            return
        }
        for entry in entries {
            switch entry.adapter {
            case "accessibility": publish(entry.id, AXIsProcessTrusted() ? "allowed" : "unknown", note: "Current process Accessibility trust. False does not distinguish a refusal from access never requested.")
            case "listen": publish(entry.id, CGPreflightListenEventAccess() ? "allowed" : "unknown", note: "Current process event-listening preflight; no input was monitored.")
            case "post": publish(entry.id, CGPreflightPostEventAccess() ? "allowed" : "unknown", note: "Current process event-posting preflight; no input was sent.")
            case "screen": publish(entry.id, CGPreflightScreenCaptureAccess() ? "allowed" : "unknown", note: "Current process screen-capture preflight; this check does not capture the desktop.")
            case "camera", "microphone": publish(entry.id, avState(AVCaptureDevice.authorizationStatus(for: entry.adapter == "camera" ? .video : .audio)))
            case "contacts":
                let value = CNContactStore.authorizationStatus(for: .contacts)
                publish(entry.id, value.rawValue == 4 ? "limited" : authorization(Int(value.rawValue), allowed: 3))
            case "calendar":
                let value = EKEventStore.authorizationStatus(for: .event)
                let state = authorization(Int(value.rawValue), allowed: 3)
                publish(entry.id, value.rawValue == 4 ? "limited" : state,
                        levels: ["full": state, "write_only": [3,4].contains(value.rawValue) ? "allowed" : state])
            case "reminders": publish(entry.id, authorization(Int(EKEventStore.authorizationStatus(for: .reminder).rawValue), allowed: 3))
            case "photos", "photos_add":
                let value = PHPhotoLibrary.authorizationStatus(for: entry.adapter == "photos" ? .readWrite : .addOnly)
                publish(entry.id, value == .limited ? "limited" : authorization(Int(value.rawValue), allowed: 3))
            case "speech":
                let value = SFSpeechRecognizer.authorizationStatus()
                publish(entry.id, value == .denied ? "denied" : value == .restricted ? "restricted" : value == .authorized ? "allowed" : "not_requested")
            case "tracking": publish(entry.id, authorization(Int(ATTrackingManager.trackingAuthorizationStatus.rawValue), allowed: 3))
            case "personal_voice":
                if #available(macOS 14, *) { publish(entry.id, personalVoiceState(AVSpeechSynthesizer.personalVoiceAuthorizationStatus)) }
                else { publish(entry.id, "unavailable", note: "Personal Voice authorization requires macOS 14 or later.", verified: false) }
            case "focus": publish(entry.id, authorization(Int(INFocusStatusCenter.default.authorizationStatus.rawValue), allowed: 3))
            case "bluetooth": publish(entry.id, authorization(Int(CBManager.authorization.rawValue), allowed: 3))
            case "location":
                if locationManager == nil { locationManager = CLLocationManager(); locationManager?.delegate = self }
                let state = locationManager?.authorizationStatus ?? .notDetermined
                publish(entry.id, locationState(state))
            case "notifications": break // asynchronous, below
            case "clipboard":
                if #available(macOS 15.4, *) {
                    let state = NSPasteboard.general.accessBehavior
                    let approval: String = state == .alwaysAllow ? "allowed" : state == .alwaysDeny ? "denied" : state == .ask ? "ask_each_time" : "not_requested"
                    publish(entry.id, approval, note: "Clipboard policy only. User-initiated paste and programmatic access have different rules; no clipboard content was read.")
                } else { publish(entry.id, "unavailable", note: "A public clipboard-policy query requires macOS 15.4 or later.", verified: false) }
            case "automation":
                if let path = preferences.targets[entry.id], let app = Bundle(path: path), let id = app.bundleIdentifier {
                    // An asynchronous worker avoids stalling the GUI on an unresponsive target.
                    if !refreshPending {
                        refreshPending = true
                        DispatchQueue.global().async { [weak self] in
                            let value = appleEventAuthorization(id, prompt: false)
                            DispatchQueue.main.async {
                                guard let self = self else { return }
                                self.refreshPending = false
                                if self.preferences.targets["automation"] == path { self.publishAutomation(value, target: id) }
                                else { self.observations.removeValue(forKey: "automation"); self.refresh() }
                            }
                        }
                    }
                } else { publish(entry.id, "unknown", note: "Choose the application you want Workbench to control.", verified: false) }
            case "audio":
                if let record = preferences.audio_probe, record.unresolved { publishAudioProbeObligation(record) }
                else if observations[entry.id] == nil { publish(entry.id, "unknown", note: entry.description, verified: false) }
            case "folder", "keychain", "local_network":
                if observations[entry.id] == nil { publish(entry.id, "unknown", note: entry.description, verified: false) }
            default: publish(entry.id, "unknown", note: entry.description, verified: false)
            }
        }
        UNUserNotificationCenter.current().getNotificationSettings { [weak self] settings in
            let state: String
            switch settings.authorizationStatus {
            case .authorized: state = "allowed"
            case .denied: state = "denied"
            case .notDetermined: state = "not_requested"
            case .provisional, .ephemeral: state = "limited"
            @unknown default: state = "unknown"
            }
            DispatchQueue.main.async { self?.publish("notifications", state) }
        }
    }

    func chooseTarget(_ entry: PermissionEntry) {
        guard !preview, setupStateWritable, requestInProgress == nil else { return }
        let panel = NSOpenPanel()
        panel.title = entry.adapter == "automation" ? "Choose the app Workbench may control" : "Choose the exact location to verify"
        panel.prompt = "Use this target"
        panel.canChooseDirectories = entry.adapter != "automation"
        panel.canChooseFiles = entry.adapter == "automation" || entry.id == "filesystem"
        panel.allowsMultipleSelection = false
        if entry.adapter == "automation" { panel.allowedContentTypes = [.applicationBundle]; panel.directoryURL = URL(fileURLWithPath: "/Applications") }
        panel.begin { [weak self] response in
            guard response == .OK, let url = panel.url else { return }
            self?.preferences.targets[entry.id] = url.path
            if entry.adapter == "folder" {
                do {
                    self?.preferences.bookmarks[entry.id] = try url.bookmarkData(options: [.withSecurityScope, .securityScopeAllowOnlyReadAccess], includingResourceValuesForKeys: nil, relativeTo: nil)
                } catch {
                    self?.preferences.bookmarks.removeValue(forKey: entry.id)
                    self?.message = "The target was selected, but persistent scoped access could not be saved. Recheck it after relaunch."
                }
            }
            self?.observations.removeValue(forKey: entry.id)
            self?.save(); self?.refresh()
            if entry.adapter == "folder" { self?.verifyFolder(entry) }
        }
    }

    func openSettings(_ entry: PermissionEntry) {
        guard !preview else { message = "Settings navigation is disabled in preview."; return }
        let special = ["LoginItems": "com.apple.LoginItems-Settings.extension", "Notifications": "com.apple.Notifications-Settings.extension",
                       "Network": "com.apple.Network-Settings.extension", "Firewall": "com.apple.Network-Settings.extension?Firewall"]
        let destination = special[entry.settings] ?? "com.apple.settings.PrivacySecurity.extension?\(entry.settings.isEmpty ? "Privacy" : entry.settings)"
        watchedSettings = entry.id; watchedUntil = Date().addingTimeInterval(300)
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: "/System/Applications/System Settings.app"), configuration: configuration) { [weak self] app, error in
            DispatchQueue.main.async {
                if error != nil { self?.message = "Open System Settings → Privacy & Security → \(entry.name)."; return }
                if let url = URL(string: "x-apple.systempreferences:" + destination) { NSWorkspace.shared.open(url) }
                app?.activate(options: [.activateIgnoringOtherApps])
            }
        }
        message = entry.guidedSettings ? "Turn on Local Workbench in System Settings. This window checks for the change automatically." : "Manage this approval in System Settings. Follow the instructions shown here."
    }

    func finishedRequest(_ id: String, note: String? = nil, attempt: UUID? = nil) {
        guard requestInProgress == id else { return }
        if let attempt = attempt, attempt != requestAttempt { return }
        requestTimeout?.cancel(); requestTimeout = nil
        requestInProgress = nil
        requestAttempt = nil
        refresh()
        if let note = note { message = note }
        else { message = "Permission checked." }
        save()
        scheduleSnapshot()
    }

    func request(_ entry: PermissionEntry, writeOnly: Bool = false) {
        guard !preview, setupStateWritable, requestInProgress == nil, entry.available, !["committed", "relaunching"].contains(restartPhase) else { return }
        if entry.requiresTarget && preferences.targets[entry.id] == nil { chooseTarget(entry); return }
        if entry.guidedSettings {
            // These APIs do not provide a completion callback and may show no
            // prompt. Register the request, then always open a concrete setup
            // route. Passive polling observes the actual grant; no spinner.
            switch entry.adapter {
            case "accessibility": _ = AXIsProcessTrustedWithOptions([kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary)
            case "listen": _ = CGRequestListenEventAccess()
            case "post": _ = CGRequestPostEventAccess()
            case "screen": _ = CGRequestScreenCaptureAccess()
            default: break
            }
            refresh()
            if observations[entry.id]?.approval != "allowed" { openSettings(entry) }
            else { message = "\(entry.name) is enabled." }
            return
        }
        if entry.adapter == "settings" || entry.adapter == "clipboard" { openSettings(entry); return }
        requestInProgress = entry.id
        let attempt = UUID(); requestAttempt = attempt
        scheduleSnapshot()
        let finish: () -> Void = { [weak self] in DispatchQueue.main.async { self?.finishedRequest(entry.id, attempt: attempt) } }
        switch entry.adapter {
        case "camera", "microphone": AVCaptureDevice.requestAccess(for: entry.adapter == "camera" ? .video : .audio) { _ in finish() }
        case "contacts": CNContactStore().requestAccess(for: .contacts) { _, _ in finish() }
        case "calendar":
            if #available(macOS 14, *) {
                if writeOnly { eventStore.requestWriteOnlyAccessToEvents { _,_ in finish() } }
                else { eventStore.requestFullAccessToEvents { _,_ in finish() } }
            } else { eventStore.requestAccess(to: .event) { _,_ in finish() } }
        case "reminders":
            if #available(macOS 14, *) { eventStore.requestFullAccessToReminders { _,_ in finish() } }
            else { eventStore.requestAccess(to: .reminder) { _,_ in finish() } }
        case "photos", "photos_add": PHPhotoLibrary.requestAuthorization(for: entry.adapter == "photos" ? .readWrite : .addOnly) { _ in finish() }
        case "speech": SFSpeechRecognizer.requestAuthorization { _ in finish() }
        case "tracking": ATTrackingManager.requestTrackingAuthorization { _ in finish() }
        case "focus": INFocusStatusCenter.default.requestAuthorization { _ in finish() }
        case "personal_voice":
            if #available(macOS 14, *) { AVSpeechSynthesizer.requestPersonalVoiceAuthorization { _ in finish() } }
            else { finish() }
        case "notifications": UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _,_ in finish() }
        case "location":
            if locationManager == nil { locationManager = CLLocationManager(); locationManager?.delegate = self }
            locationManager?.requestWhenInUseAuthorization()
        case "bluetooth": bluetoothManager = CBCentralManager(delegate: self, queue: .main, options: [CBCentralManagerOptionShowPowerAlertKey: false])
        case "local_network": requestLocalNetwork()
        case "automation":
            guard let path = preferences.targets[entry.id], let id = Bundle(path: path)?.bundleIdentifier else { finish(); return }
            if NSRunningApplication.runningApplications(withBundleIdentifier: id).isEmpty {
                finishedRequest(entry.id, note: "Open the selected app, then request Automation access. Workbench does not launch unrelated apps automatically.")
                return
            }
            DispatchQueue.global().async { [weak self] in
                let state = appleEventAuthorization(id, prompt: true)
                DispatchQueue.main.async {
                    guard self?.requestAttempt == attempt else { return }
                    self?.publishAutomation(state, target: id); self?.finishedRequest(entry.id, attempt: attempt)
                }
            }
        case "folder":
            verifyFolder(entry); finish()
        case "keychain": verifyKeychain(); finish()
        case "audio":
            requestSystemAudio(finish: finish)
        default: finish()
        }
        if requestInProgress != nil {
            let timeout = DispatchWorkItem { [weak self] in
                guard self?.requestInProgress == entry.id else { return }
                self?.message = "macOS has not returned a decision. Complete the system dialog or stop preparation; no second request will be started automatically."
            }
            requestTimeout = timeout
            DispatchQueue.main.asyncAfter(deadline: .now() + 30, execute: timeout)
        }
    }

    func verify(_ entry: PermissionEntry) {
        guard !preview, requestInProgress == nil else { return }
        if entry.adapter == "folder" {
            if preferences.targets[entry.id] == nil { chooseTarget(entry) } else { verifyFolder(entry) }
        } else if entry.adapter == "keychain" { verifyKeychain() }
        else { refresh() }
    }

    private func verifyFolder(_ entry: PermissionEntry) {
        guard let target = preferences.targets[entry.id] else { return }
        var location = URL(fileURLWithPath: target), scoped = false
        defer { if scoped { location.stopAccessingSecurityScopedResource() } }
        if let bookmark = preferences.bookmarks[entry.id] {
            do {
                var stale = false
                location = try URL(resolvingBookmarkData: bookmark, options: [.withSecurityScope, .withoutUI], relativeTo: nil, bookmarkDataIsStale: &stale)
                scoped = location.startAccessingSecurityScopedResource()
                if stale {
                    preferences.bookmarks[entry.id] = try location.bookmarkData(options: [.withSecurityScope, .securityScopeAllowOnlyReadAccess], includingResourceValuesForKeys: nil, relativeTo: nil)
                    preferences.targets[entry.id] = location.path; save()
                }
            } catch {
                publish(entry.id, "unknown", note: "The saved target could not be resolved without a new user decision. Choose it again; no permission is assumed.", verified: false)
                return
            }
        }
        // Opening a directory verifies that exact path without enumerating it.
        let fd = Darwin.open(location.path, O_RDONLY | O_CLOEXEC | O_NONBLOCK)
        if fd >= 0 {
            Darwin.close(fd)
            publish(entry.id, "unknown", note: "Read access to the selected path succeeded. No file contents or directory entries were read. This does not establish write access or a category-wide grant.", verified: false)
            observations[entry.id]?.readiness = "verified"
            observations[entry.id]?.verification = "selected_path_read_open"
        } else {
            publish(entry.id, "unknown", note: "The selected path could not be opened (OS error \(errno)). Permissions, availability or filesystem policy may be responsible.", verified: false)
        }
    }

    private func verifyKeychain() {
        let service = (Bundle.main.bundleIdentifier ?? "tools.localworkbench.launcher") + ".permission-canary"
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
            kSecAttrAccount as String: "readiness", kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var item: CFTypeRef?
        var status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            let add: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                kSecAttrAccount as String: "readiness", kSecValueData as String: Data("workbench-readiness-canary-v1".utf8)]
            status = SecItemAdd(add as CFDictionary, nil)
            if status == errSecSuccess { status = SecItemCopyMatching(query as CFDictionary, &item) }
        }
        let valid = status == errSecSuccess && (item as? Data) == Data("workbench-readiness-canary-v1".utf8)
        publish("keychain", valid ? "allowed" : "unknown", note: valid ? "The dedicated Workbench canary is accessible. Other Keychain items retain their own approval and authentication rules." : "The dedicated canary check failed (OS status \(status)). Existing items were preserved.", verified: valid)
        observations["keychain"]?.verification = valid ? "dedicated_keychain_canary" : "not_established"
    }

    func publishAutomation(_ code: OSStatus, target: String) {
        let state = code == noErr ? "allowed" : code == -1743 ? "denied" : code == -1744 ? "not_requested" : "unknown"
        publish("automation", state, note: "Apple Events authorization for \(target) only. OS status \(code). A missing or unavailable target is not a denial.", verified: code == noErr)
        if code == -600 { observations["automation"]?.condition = "target_not_running"; scheduleSnapshot() }
    }

    func openAutomationTarget() {
        guard !preview, let path = preferences.targets["automation"] else { return }
        let configuration = NSWorkspace.OpenConfiguration(); configuration.activates = true
        NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: path), configuration: configuration) { [weak self] _, error in
            DispatchQueue.main.async {
                guard self?.preferences.targets["automation"] == path else { return }
                if error != nil { self?.message = "The selected app could not be opened. Choose an installed app and try again." }
                self?.refresh()
            }
        }
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        publish("location", locationState(manager.authorizationStatus))
        if manager.authorizationStatus != .notDetermined { finishedRequest("location") }
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard central === bluetoothManager else { return }
        publish("bluetooth", authorization(Int(CBManager.authorization.rawValue), allowed: 3))
        if CBManager.authorization != .notDetermined {
            central.stopScan(); finishedRequest("bluetooth")
        } else if requestInProgress == "bluetooth", central.state == .poweredOn {
            // Discover only our test service; discard every discovery. Some OS
            // versions defer the permission request until actual scanning.
            central.scanForPeripherals(withServices: [CBUUID(string: "AE35AB22-BF71-4F29-AC54-C771320406ED")], options: nil)
            let attempt = requestAttempt
            DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in
                central.stopScan()
                self?.finishedRequest("bluetooth", note: "Bluetooth request checked. No device information was retained.", attempt: attempt)
            }
        } else if requestInProgress == "bluetooth", [.poweredOff, .unsupported].contains(central.state) {
            finishedRequest("bluetooth", note: central.state == .poweredOff ? "Bluetooth is off. Turn it on in System Settings before requesting access." : "Bluetooth is unavailable on this Mac.")
        }
    }

    private func requestLocalNetwork() {
        let request = UUID(); networkRequestID = request
        let browser = NWBrowser(for: .bonjour(type: "_lw-readiness._tcp", domain: nil), using: .tcp)
        networkBrowser = browser
        browser.stateUpdateHandler = { [weak self] state in
            DispatchQueue.main.async {
                guard self?.networkRequestID == request else { return }
                if case .failed(_) = state {
                    self?.publish("local_network", "unknown", note: "The bounded local-network request failed. This does not identify a universal permission state.", verified: false)
                }
            }
        }
        browser.start(queue: .global())
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in
            guard self?.networkRequestID == request else { return }
            browser.cancel(); self?.networkBrowser = nil; self?.networkRequestID = nil
            self?.publish("local_network", "unknown", note: "Setup made a bounded request for the Workbench test service. No device data was retained. Confirm the app's Local Network setting; discovery alone cannot prove a universal grant.", verified: false)
            self?.finishedRequest("local_network")
        }
    }

    private func publishAudioProbeObligation(_ record: PermissionAudioProbeRecord, owner: PermissionProbeOwner = .current) {
        let sameOwner = record.owner == owner
        let created = record.createStatus == noErr && (record.tapID ?? 0) != 0
        let context = "Probe \(record.probeID), owner PID \(record.owner.pid), process generation \(record.owner.generation), phase \(record.phase)."
        let explanation = sameOwner
            ? "The previous probe has no confirmed cleanup. No new tap or repeated destruction was attempted."
            : "The previous process's probe disposition is unknown. Restart does not verify release; its saved numeric tap ID will not be reused. No new tap was created."
        publish("system_audio", sameOwner && created ? "allowed" : "unknown",
            note: "\(explanation) \(context) Keep this optional check paused until the exact probe's release or absence is established through a supported cleanup check.", verified: false)
        // Passive refresh must not make an old creation/cleanup observation
        // look like a new OS approval check.
        observations["system_audio"]?.checked_at = record.observed_at
        observations["system_audio"]?.condition = sameOwner ? "audio_cleanup_pending" : "audio_cleanup_previous_owner"
        observations["system_audio"]?.verification = "not_established"
    }

    // Also used by the headless owned-fixture check with substituted API edges.
    // Neither a saved numeric ID nor a restart authorizes another destruction.
    func performSystemAudioProbe(using api: PermissionAudioProbeAPI, owner: PermissionProbeOwner = .current) {
        guard !preview, setupStateWritable else { return }
        if let record = preferences.audio_probe, record.unresolved {
            publishAudioProbeObligation(record, owner: owner); return
        }
        let previous = preferences.audio_probe
        var record = PermissionAudioProbeRecord(probeID: UUID().uuidString, owner: owner,
            phase: "creating", tapID: nil, createStatus: nil, destroyStatus: nil)
        preferences.audio_probe = record
        // Preserve the intent before a resource can exist. A crash after this
        // point leaves an unresolved record, never an automatic numeric retry.
        guard save() else {
            preferences.audio_probe = previous
            publish("system_audio", "unknown", note: "The probe intent could not be saved. No audio tap was created.", verified: false)
            observations["system_audio"]?.condition = "audio_cleanup_record_unsaved"
            return
        }
        let created = api.create(UUID(uuidString: record.probeID)!)
        record.createStatus = created.status; record.observed_at = Date().timeIntervalSince1970
        if created.status != noErr, created.tapID != 0 {
            record.tapID = created.tapID; record.phase = "creation_unverified"
            preferences.audio_probe = record; _ = save()
            publishAudioProbeObligation(record, owner: owner); return
        }
        if created.status != noErr {
            record.phase = "create_failed"
            preferences.audio_probe = record
            let stored = save()
            publish("system_audio", "unknown", note: "Audio-tap creation failed (OS status \(created.status)). This is not a universal permission denial. No destruction was attempted." + (stored ? "" : " The result could not be saved."), verified: false)
            return
        }
        record.tapID = created.tapID
        guard created.tapID != 0 else {
            record.phase = "identity_unavailable"; preferences.audio_probe = record; _ = save()
            publishAudioProbeObligation(record, owner: owner); return
        }
        record.phase = "owned"; preferences.audio_probe = record
        let ownershipStored = save()
        // This is the one original cleanup of the exact resource just created,
        // not a replay from disk. Even a failed persistence write must not make
        // us abandon its current-process cleanup without this attempt.
        record.destroyStatus = api.destroy(created.tapID); record.observed_at = Date().timeIntervalSince1970
        record.phase = record.destroyStatus == noErr ? "released" : "cleanup_pending"
        preferences.audio_probe = record
        let terminalStored = save()
        if record.phase == "cleanup_pending" {
            publishAudioProbeObligation(record, owner: owner)
            observations["system_audio"]?.note += " Cleanup OS status \(record.destroyStatus!)." + (ownershipStored && terminalStored ? "" : " The cleanup record could not be fully saved; its in-memory obligation is retained.")
            return
        }
        publish("system_audio", "allowed", note: terminalStored
            ? "The exact private audio tap was created and its cleanup confirmed. No audio samples were read or retained; this does not verify an audio workflow."
            : "The exact tap cleanup succeeded, but its terminal record could not be saved. No new readiness claim is made.", verified: terminalStored)
        observations["system_audio"]?.checked_at = record.observed_at
        observations["system_audio"]?.verification = terminalStored ? "temporary_audio_tap_no_samples" : "not_established"
        if !terminalStored { observations["system_audio"]?.condition = "audio_cleanup_record_unsaved" }
    }

    private func requestSystemAudio(finish: @escaping () -> Void) {
        if #available(macOS 14.2, *) {
            let api = PermissionAudioProbeAPI(create: { id in
                let description = CATapDescription(stereoGlobalTapButExcludeProcesses: [])
                description.uuid = id
                description.isPrivate = true
                description.muteBehavior = .unmuted
                var tap: AudioObjectID = 0
                let status = AudioHardwareCreateProcessTap(description, &tap)
                return (status, tap)
            }, destroy: { AudioHardwareDestroyProcessTap($0) })
            performSystemAudioProbe(using: api)
        } else { publish("system_audio", "unavailable", note: "System-audio tap setup requires macOS 14.2 or later.", verified: false) }
        finish()
    }

    func queueRestart(category: String? = nil) {
        guard !preview, setupStateWritable, restartPhase != "committed", !restartCancellationPending, requestInProgress == nil else { return }
        if let category = category, !preferences.restart_categories.contains(category) { preferences.restart_categories.append(category) }
        preferences.restart_ticket = preferences.restart_ticket ?? UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        preferences.restart_phase = "queued"; restartPhase = "queued"
        blockNativeGrants?(true)
        guard save() else { preferences.restart_ticket = nil; preferences.restart_phase = "none"; restartPhase = "none"; blockNativeGrants?(false); return }
        message = "Restart queued. Workbench will wait for current work to finish."
        finishLocalRestartIfIdle()
    }
    func finishLocalRestartIfIdle() {
        guard restartPhase == "queued", !restartCancellationPending, serviceRunning?() != true, (nativeActivity?() ?? []).isEmpty,
              requestInProgress == nil else { return }
        preferences.restart_phase = "committed"; restartPhase = "committed"
        if save() { onRestart?() }
        else { preferences.restart_phase = "queued"; restartPhase = "queued" }
    }

    func cancelRestart() {
        guard restartPhase == "queued" else { return }
        let previous = preferences
        preferences.restart_ticket = nil; preferences.restart_phase = "none"
        guard save() else {
            // A failed write may occur after atomic replacement. Keep the
            // cancellation intent authoritative in memory and withhold every
            // restart commit until a retry durably saves the cancellation.
            preferences = previous
            restartCancellationPending = true
            message = "Could not save the cancellation. Restart is held; try Cancel restart again when storage is writable."
            return
        }
        restartCancellationPending = false
        restartPhase = "none"
        blockNativeGrants?(false)
        message = "Restart cancelled. Workbench is still running."
    }

    func connectionReady() {
        guard launchedAfterRestart, !restartCancellationPending else { return }
        launchedAfterRestart = false
        preferences.restart_categories.removeAll()
        preferences.restart_ticket = nil; preferences.restart_phase = "none"; restartPhase = "none"
        preferences.resume_service = false
        blockNativeGrants?(false)
        refresh(); save(); message = "Restart completed and permission checks refreshed. Unverified categories remain unverified."
    }

    func startPreparation() {
        selectedForPreparation = Set(entries.filter { $0.setupEntry }.map { $0.id })
        showPreparation = true
    }
    func beginQueue() {
        guard setupStateWritable else { return }
        queue = entries.filter { selectedForPreparation.contains($0.id) }.map { $0.id }
        queueIndex = 0; preparing = !queue.isEmpty; showPreparation = false
        preferences.preparation_queue = queue; preferences.preparation_index = 0; save()
        if let first = queue.first { selection = first }
    }
    func nextInQueue() {
        guard preparing, queueIndex < queue.count, requestInProgress == nil else { return }
        queueIndex += 1
        preferences.preparation_index = queueIndex; save()
        if queueIndex >= queue.count { preparing = false; message = "Preparation complete. Review pending restarts and unverified entries." }
        else { selection = queue[queueIndex] }
    }
    func stopPreparation() {
        preparing = false
        preferences.preparation_queue = []; preferences.preparation_index = 0; save()
        // In-flight system dialogs cannot be cancelled by pretending completion.
        message = requestInProgress == nil ? "Preparation stopped. Existing approvals are retained." : "Preparation stopped. Finish or dismiss the current macOS dialog; no further requests will follow."
    }
}

func authorization(_ raw: Int, allowed: Int) -> String {
    switch raw { case 0: return "not_requested"; case 1: return "restricted"; case 2: return "denied"; case allowed: return "allowed"; default: return "unknown" }
}
func avState(_ status: AVAuthorizationStatus) -> String { authorization(Int(status.rawValue), allowed: 3) }
func locationState(_ status: CLAuthorizationStatus) -> String {
    switch status { case .notDetermined: return "not_requested"; case .restricted: return "restricted"; case .denied: return "denied"; case .authorizedAlways, .authorizedWhenInUse: return "allowed"; @unknown default: return "unknown" }
}
@available(macOS 14, *)
func personalVoiceState(_ status: AVSpeechSynthesizer.PersonalVoiceAuthorizationStatus) -> String {
    switch status { case .notDetermined: return "not_requested"; case .denied: return "denied"; case .authorized: return "allowed"; case .unsupported: return "unavailable"; @unknown default: return "unknown" }
}
func appleEventAuthorization(_ bundleID: String, prompt: Bool) -> OSStatus {
    var target = AEAddressDesc()
    let data = Data(bundleID.utf8)
    let made = data.withUnsafeBytes { AECreateDesc(DescType(typeApplicationBundleID), $0.baseAddress, data.count, &target) }
    guard made == noErr else { return OSStatus(made) }
    defer { AEDisposeDesc(&target) }
    return AEDeterminePermissionToAutomateTarget(&target, AEEventClass(typeWildCard), AEEventID(typeWildCard), prompt)
}

extension PermissionsModel {
    func startBridge() {
        guard !preview else { return }
        do {
            let channel = try PermissionSocket()
            channel.handler = { [weak self] packet in self?.handleNativeMessage(packet) ?? ["ok": false] }
            channel.start(); bridge = channel
        } catch { message = "Native readiness reporting unavailable: \(error.localizedDescription)" }
    }

    func handleNativeMessage(_ request: [String: Any]) -> [String: Any] {
        switch request["method"] as? String {
        case "snapshot":
            refresh()
            return ["ok": true, "available": true, "owner": permissionOwner(),
                    "observed_at": Date().timeIntervalSince1970, "observations": observations.mapValues { jsonDictionary($0) },
                    "restart": ["phase": restartPhase, "categories": preferences.restart_categories,
                                "cancellation_pending": restartCancellationPending],
                    "request_in_progress": requestInProgress as Any? ?? NSNull(),
                    "note": "Each entry has its own observation timestamp; operational probes run only from local user actions."]
        case "poll":
            if let state = request["activity"] as? [String: Any], let calls = state["in_flight_calls"] as? Int,
               let jobs = state["job_count"] as? Int, let browsers = state["browser_count"] as? Int {
                let ids = ((state["job_ids"] as? [String] ?? []) + (state["browser_ids"] as? [String] ?? [])).prefix(5).joined(separator: ", ")
                activity = "\(calls) tool calls · \(jobs) jobs · \(browsers) browser contexts" + (ids.isEmpty ? "" : "\nResources: \(ids)")
            }
            return ["ok": true, "restart_ticket": restartCancellationPending ? NSNull() : (preferences.restart_ticket as Any? ?? NSNull()),
                    "native_lease_ids": nativeActivity?() ?? []]
        case "commit_restart":
            guard let ticket = request["ticket"] as? String, ticket == preferences.restart_ticket else { return ["ok": true, "committed": false] }
            if restartPhase == "committed" { return ["ok": true, "committed": true] }
            guard restartPhase == "queued", !restartCancellationPending, requestInProgress == nil, (nativeActivity?() ?? []).isEmpty else { return ["ok": true, "committed": false] }
            preferences.restart_phase = "committed"; restartPhase = "committed"
            guard save() else { preferences.restart_phase = "queued"; restartPhase = "queued"; return ["ok": true, "committed": false] }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { [weak self] in self?.onRestart?() }
            return ["ok": true, "committed": true]
        default: return ["ok": false]
        }
    }
}
