import Foundation

struct WorkbenchRuntimeSettings {
    let repository: URL
    let python: URL
    let cloudflared: URL
    let browsers: URL?
    let manifest: URL?

    static func load(_ values: [String: String], resources: URL, fixture: Bool) throws -> Self {
        func invalid(_ message: String) -> NSError {
            NSError(domain: "LocalWorkbench.Runtime", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
        }
        if values["layout_version"] != "2" {
            guard fixture, let repository = values["repository"], let python = values["python"], let cloudflared = values["cloudflared"] else {
                throw invalid("This build has no verified packaged runtime. Rebuild Local Workbench with its production installer.")
            }
            return Self(repository: URL(fileURLWithPath: repository), python: URL(fileURLWithPath: python),
                        cloudflared: URL(fileURLWithPath: cloudflared), browsers: nil, manifest: nil)
        }
        let root = resources.resolvingSymlinksInPath().standardizedFileURL
        func contained(_ name: String) throws -> URL {
            guard let relative = values[name], !relative.isEmpty, !relative.hasPrefix("/"), !relative.split(separator: "/").contains("..") else {
                throw invalid("Packaged runtime path is invalid: \(name).")
            }
            let path = root.appendingPathComponent(relative).resolvingSymlinksInPath().standardizedFileURL
            guard path.path.hasPrefix(root.path + "/"), FileManager.default.fileExists(atPath: path.path) else {
                throw invalid("Packaged runtime component is missing or outside this app: \(name).")
            }
            return path
        }
        let settings = try Self(repository: contained("repository"), python: contained("python"),
                                cloudflared: contained("cloudflared"), browsers: contained("browsers"), manifest: contained("manifest"))
        guard FileManager.default.isExecutableFile(atPath: settings.python.path),
              FileManager.default.isExecutableFile(atPath: settings.cloudflared.path),
              FileManager.default.fileExists(atPath: settings.repository.appendingPathComponent("src/local_workbench/launcher.py").path) else {
            throw invalid("The packaged Workbench runtime is incomplete. Reinstall the verified build.")
        }
        return settings
    }
}
