import AppKit
import Foundation
import Darwin

// This helper never requests permissions, signals a process or reads credentials.
// It registers for its direct parent's exit before acknowledging readiness.
let arguments = CommandLine.arguments
guard arguments.count == 3, let parent = Int32(arguments[1]), parent == getppid() else { exit(2) }
let url = URL(fileURLWithPath: arguments[2]).standardizedFileURL
guard url.pathExtension == "app", FileManager.default.fileExists(atPath: url.path) else { exit(2) }
let exited = DispatchSemaphore(value: 0)
let watcher = DispatchSource.makeProcessSource(identifier: parent, eventMask: .exit, queue: .global())
watcher.setEventHandler { exited.signal() }
watcher.resume()
FileHandle.standardOutput.write(Data("ready\n".utf8))
guard exited.wait(timeout: .now() + 60) == .success else { exit(3) }
let configuration = NSWorkspace.OpenConfiguration()
configuration.createsNewApplicationInstance = true
NSWorkspace.shared.openApplication(at: url, configuration: configuration) { _, error in exit(error == nil ? 0 : 4) }
RunLoop.main.run()
