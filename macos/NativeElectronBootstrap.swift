import Foundation
import Darwin
import CoreGraphics

/// Private authenticated Python->signed-host packet. Public calls provide only
/// a relative path in a writable executable workspace, never a URI/profile.
enum NativeElectronBootstrap {
    static func contained(_ rect: NativeRect, in display: NativeRect) -> Bool {
        rect.finite && display.finite && rect.width >= 640 && rect.height >= 480 &&
        rect.x >= display.x && rect.y >= display.y &&
        rect.x + rect.width <= display.x + display.width && rect.y + rect.height <= display.y + display.height
    }
    static func storageState(bounds: NativeRect) -> [String: Any] {
        ["windowsState": ["lastActiveWindow": ["uiState": ["mode": 1, "x": bounds.x, "y": bounds.y,
            "width": bounds.width, "height": bounds.height]], "openedWindows": []]]
    }
    private static func number(_ value: Any?) -> UInt64? {
        guard let n=value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(),
              !["f","d"].contains(String(cString:n.objCType)),n.int64Value >= 0 else { return nil }
        return n.uint64Value
    }
    static func fileURL(_ proof: [String: Any]) throws -> URL {
        let keys:Set<String>=["workspace_root","relative_path","root_device","root_inode","device","inode","uid","size","modified_seconds","modified_nanoseconds","changed_seconds","changed_nanoseconds"]
        guard Set(proof.keys)==keys,let root=proof["workspace_root"] as? String,root.hasPrefix("/"),
              root.utf8.count<=4096,!root.utf8.contains(0),
              root=="/" || root.dropFirst().split(separator:"/",omittingEmptySubsequences:false).allSatisfy({!$0.isEmpty && $0 != "." && $0 != ".."}),
              let relative=proof["relative_path"] as? String,!relative.hasPrefix("/"),!relative.contains("\\"),!relative.utf8.contains(0),
              relative.utf8.count<=4096 else {throw NativeProviderHostFailure("native_electron_file_authority_invalid")}
        let parts=relative.split(separator:"/",omittingEmptySubsequences:false)
        guard !parts.isEmpty,parts.allSatisfy({!$0.isEmpty && $0 != "." && $0 != ".."}) else {throw NativeProviderHostFailure("native_electron_file_authority_invalid")}
        var fd=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        guard fd>=0 else {throw NativeProviderHostFailure("native_electron_file_unavailable")}
        defer {close(fd)}
        for part in root.split(separator:"/") {
            let next=openat(fd,String(part),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
            guard next>=0 else {throw NativeProviderHostFailure("native_electron_file_unavailable")}
            close(fd);fd=next
        }
        var rootInfo=stat();guard fstat(fd,&rootInfo)==0,
            number(proof["root_device"])==UInt64(UInt32(bitPattern:rootInfo.st_dev)),number(proof["root_inode"])==rootInfo.st_ino else {
            throw NativeProviderHostFailure("native_electron_workspace_changed")}
        for part in parts.dropLast(){let next=openat(fd,String(part),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
            guard next>=0 else {throw NativeProviderHostFailure("native_electron_file_unavailable")};close(fd);fd=next}
        let file=openat(fd,String(parts.last!),O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC)
        guard file>=0 else {throw NativeProviderHostFailure("native_electron_file_unavailable")};defer{close(file)}
        var info=stat();guard fstat(file,&info)==0,info.st_mode&S_IFMT==S_IFREG,info.st_nlink==1,
            info.st_size>=0,info.st_mtimespec.tv_sec>=0,info.st_ctimespec.tv_sec>=0,
            number(proof["device"])==UInt64(UInt32(bitPattern:info.st_dev)),number(proof["inode"])==info.st_ino,
            number(proof["uid"])==UInt64(info.st_uid),number(proof["size"])==UInt64(info.st_size),
            number(proof["modified_seconds"])==UInt64(info.st_mtimespec.tv_sec),number(proof["modified_nanoseconds"])==UInt64(info.st_mtimespec.tv_nsec),
            number(proof["changed_seconds"])==UInt64(info.st_ctimespec.tv_sec),number(proof["changed_nanoseconds"])==UInt64(info.st_ctimespec.tv_nsec) else {
            throw NativeProviderHostFailure("native_electron_file_changed")}
        return URL(fileURLWithPath:root).appendingPathComponent(relative)
    }
    static func activeDisplayBounds(_ id: UInt32) -> NativeRect? {
        guard CGDisplayIsActive(id) != 0 else { return nil }
        let cg = CGDisplayBounds(id)
        return NativeRect(x: cg.origin.x, y: cg.origin.y, width: cg.width, height: cg.height)
    }
    static func bounds(_ packet: [String: Any],
                       displayBounds: (UInt32) -> NativeRect? = activeDisplayBounds) throws -> NativeRect? {
        guard packet["initial_bounds"] != nil || packet["initial_display_id"] != nil else {return nil}
        guard let raw=packet["initial_bounds"] as? [String:Any],Set(raw.keys)==["x","y","width","height"],
            let id=number(packet["initial_display_id"]),id>0,id<=UInt32.max,
            let display=displayBounds(UInt32(id)) else {
            throw NativeProviderHostFailure("native_electron_initial_display_invalid")}
        let data=try JSONSerialization.data(withJSONObject:raw),rect=try JSONDecoder().decode(NativeRect.self,from:data)
        guard contained(rect,in:display) else {throw NativeProviderHostFailure("native_electron_initial_bounds_invalid")}
        return rect
    }
}
