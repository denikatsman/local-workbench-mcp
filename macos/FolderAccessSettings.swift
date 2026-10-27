import Foundation
import Darwin

enum FolderAccessSettings {
    private static func identity(_ url: URL) -> String? {
        var value = stat()
        guard url.path.withCString({ fstatat(AT_FDCWD, $0, &value, 0) }) == 0 else { return nil }
        return "\(value.st_dev):\(value.st_ino)"
    }

    private static func ancestry(_ url: URL, readIdentity: (URL) -> String?) throws -> Set<String> {
        var path = (url.path as NSString).standardizingPath, found = Set<String>()
        while true {
            let current = URL(fileURLWithPath: path, isDirectory: true)
            guard let value = readIdentity(current) else {
                throw NSError(domain: "LocalWorkbench.FolderAccess", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Access to \(current.path) could not be verified. Existing access is unchanged."])
            }
            found.insert(value)
            if path == "/" { return found }
            let parent = (path as NSString).deletingLastPathComponent
            guard parent.hasPrefix("/"), parent.utf8.count < path.utf8.count else {
                throw NSError(domain: "LocalWorkbench.FolderAccess", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "The folder path could not be verified. Existing access is unchanged."])
            }
            path = parent
        }
    }

    static func validate(_ path: String, privateDirectory: URL,
                         identityReader: ((URL) -> String?)? = nil) throws -> URL {
        func invalid(_ message: String) -> NSError {
            NSError(domain: "LocalWorkbench.FolderAccess", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: message])
        }
        guard path.hasPrefix("/") || path.hasPrefix("~/"), !path.utf8.contains(0), path.utf8.count <= 4096 else {
            throw invalid("Enter a full folder path starting with / or ~/.")
        }
        let folder = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
            .resolvingSymlinksInPath().standardizedFileURL
        let readIdentity = identityReader ?? identity
        var directory = ObjCBool(false)
        guard FileManager.default.fileExists(atPath: folder.path, isDirectory: &directory), directory.boolValue,
              let folderID = readIdentity(folder), let privateID = readIdentity(privateDirectory.resolvingSymlinksInPath()) else {
            throw invalid("Choose an existing folder. Workbench's private directory must also be available.")
        }
        let privateRoot = privateDirectory.resolvingSymlinksInPath().standardizedFileURL
        guard try !ancestry(folder, readIdentity: readIdentity).contains(privateID),
              try !ancestry(privateRoot, readIdentity: readIdentity).contains(folderID) else {
            throw invalid("Choose a folder that does not include Workbench's private connection data.")
        }
        return folder
    }
}
