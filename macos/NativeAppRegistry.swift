import AppKit

enum NativeAppRegistry {
    struct Limits {
        var records = 300
        var visitedEntries = 3000
        var seconds: TimeInterval = 2
    }

    private static let applicationRoots = ["/Applications", "/System/Applications", NSHomeDirectory() + "/Applications"]

    static func installed(bundleID: String? = nil, appPath: String? = nil,
                          roots: [String] = applicationRoots, limits: Limits = Limits()) -> [String: Any] {
        var records: [[String: Any]] = [], gaps: [[String: String]] = []
        var seen: Set<String> = []
        let deadline = Date().timeIntervalSince1970 + limits.seconds
        var visited = 0, incomplete = false
        let exactURL = appPath.map { URL(fileURLWithPath: $0).standardizedFileURL }

        func record(at url: URL) -> [String: Any]? {
            guard url.pathExtension.lowercased() == "app",
                  let bundle = Bundle(url: url), let identifier = bundle.bundleIdentifier,
                  bundleID == nil || identifier == bundleID else { return nil }
            let name = bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
                ?? bundle.object(forInfoDictionaryKey: "CFBundleName") as? String ?? url.deletingPathExtension().lastPathComponent
            return ["name": name, "bundle_id": identifier, "app_path": url.path,
                    "version": bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"]
        }

        if let url = exactURL {
            visited = 1
            if visited > limits.visitedEntries || limits.records <= 0 || Date().timeIntervalSince1970 > deadline {
                incomplete = true
            } else {
                do {
                    let values = try url.resourceValues(forKeys: [.isDirectoryKey])
                    if values.isDirectory == true, url.pathExtension.lowercased() == "app",
                       let bundle = Bundle(url: url), bundle.bundleIdentifier != nil {
                        if let match = record(at: url) { records.append(match) }
                    } else {
                        gaps.append(["path": url.path, "reason": "application_metadata_unavailable"])
                        incomplete = true
                    }
                } catch {
                    let missing = (error as NSError).domain == NSCocoaErrorDomain
                        && (error as NSError).code == NSFileReadNoSuchFileError
                    gaps.append(["path": url.path, "reason": missing ? "not_present" : "application_lookup_unavailable"])
                    incomplete = !missing
                }
            }
            return ["apps": records, "roots": [], "gaps": gaps, "incomplete": incomplete,
                    "visited_entries": visited, "scope": "exact standardized app_path lookup"]
        }
        for root in roots {
            let base = URL(fileURLWithPath: root)
            guard FileManager.default.fileExists(atPath: root) else { gaps.append(["root": root, "reason": "not_present"]); continue }
            guard let enumerator = FileManager.default.enumerator(at: base, includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles, .skipsPackageDescendants], errorHandler: { url,_ in
                    gaps.append(["root": root, "path": url.path, "reason": "enumeration_unavailable"]); return true
                }) else { gaps.append(["root": root, "reason": "enumeration_unavailable"]); continue }
            while let url = enumerator.nextObject() as? URL {
                visited += 1
                if visited > limits.visitedEntries || Date().timeIntervalSince1970 > deadline { incomplete = true; break }
                if enumerator.level > 3 { enumerator.skipDescendants(); continue }
                let normalizedURL = url.standardizedFileURL
                guard normalizedURL.pathExtension.lowercased() == "app",
                      seen.insert(normalizedURL.path).inserted, let match = record(at: normalizedURL) else { continue }
                if records.count >= limits.records { incomplete = true; break }
                records.append(match)
            }
            if incomplete { break }
        }
        return ["apps": records.sorted { ($0["app_path"] as! String) < ($1["app_path"] as! String) },
                "roots": roots, "gaps": gaps, "incomplete": incomplete, "visited_entries": visited,
                "scope": "known application folders through depth three; other locations require exact app_path"]
    }
}
