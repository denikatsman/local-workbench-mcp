#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <sys/stat.h>
#import <unistd.h>
#import "ProviderFileSecurity.h"
#import "ProviderBootstrap.h"

@protocol LWTextMateController <NSObject>
- (CGFloat)version;
@end

// This function's executable address belongs to the MH_BUNDLE, never the helper.
__attribute__((noinline, used)) static void LWTextMateWrapperMarker(void) {}

static BOOL LWWrapperPath(id value) {
    if (![value isKindOfClass:NSString.class] || ![value hasPrefix:@"/"] ||
        [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 4096 ||
        [value rangeOfCharacterFromSet:[NSCharacterSet characterSetWithRange:NSMakeRange(0, 1)]].location != NSNotFound) return NO;
    NSArray *parts = [value componentsSeparatedByString:@"/"];
    if (parts.count < 2) return NO;
    for (NSUInteger i = 1; i < parts.count; i++)
        if (![parts[i] length] || [parts[i] isEqual:@"."] || [parts[i] isEqual:@".."]) return NO;
    return YES;
}
// Same stable ancestry policy as NativeProviderRecovery.safe: root/current-user,
// no write grants except root-owned sticky temporary directories; safe read ACLs.
static BOOL LWWrapperStableDirectory(int fd) {
    struct stat s;
    return !fstat(fd, &s) && S_ISDIR(s.st_mode) && s.st_nlink > 0 &&
        (s.st_mode & 07000) == (s.st_mode & S_ISVTX) &&
        (s.st_uid == 0 || s.st_uid == geteuid()) &&
        (!(s.st_mode & 0022) || (s.st_uid == 0 && (s.st_mode & S_ISVTX))) &&
        LWProviderHasStableAncestorACL(fd);
}
static int LWWrapperDirectory(NSString *path, BOOL private) {
    if (!LWWrapperPath(path)) return -1;
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    for (NSString *part in path.pathComponents) {
        if ([part isEqual:@"/"]) continue;
        if (fd < 0) return -1;
        if (!LWWrapperStableDirectory(fd)) { close(fd); return -1; }
        int next = openat(fd, part.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(fd); fd = next;
    }
    struct stat s;
    if (fd < 0) return -1;
    if (fstat(fd, &s) || !S_ISDIR(s.st_mode) || !LWWrapperStableDirectory(fd) || (private &&
        (s.st_uid != geteuid() || (s.st_mode & 07777) != 0700 || !LWProviderHasPrivateACL(fd)))) {
        close(fd); return -1;
    }
    return fd;
}
static BOOL LWWrapperSameFile(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid && a->st_nlink == b->st_nlink &&
        a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
static NSDictionary *LWWrapperConfig(NSString *path) {
    if (!LWWrapperPath(path)) return nil;
    NSString *parent = path.stringByDeletingLastPathComponent;
    int directory = LWWrapperDirectory(parent, YES);
    if (directory < 0) return nil;
    int fd = openat(directory, path.lastPathComponent.fileSystemRepresentation, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    @try {
        struct stat before, after, named, oldParent, newParent;
        if (fd < 0 || fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_uid != geteuid() ||
            (before.st_mode & 07777) != 0600 || before.st_nlink != 1 || before.st_size <= 0 ||
            before.st_size > 16384 || !LWProviderHasPrivateACL(fd)) return nil;
        NSMutableData *bytes = [NSMutableData dataWithLength:(NSUInteger)before.st_size];
        NSUInteger at = 0;
        while (at < bytes.length) {
            ssize_t n = read(fd, (uint8_t *)bytes.mutableBytes + at, bytes.length - at);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return nil;
            at += (NSUInteger)n;
        }
        uint8_t extra;
        if (read(fd, &extra, 1) != 0 || fstat(fd, &after) || !LWWrapperSameFile(&before, &after) ||
            !LWProviderHasPrivateACL(fd) || fstatat(directory, path.lastPathComponent.fileSystemRepresentation, &named, AT_SYMLINK_NOFOLLOW) ||
            !LWWrapperSameFile(&before, &named)) return nil;
        int fresh = LWWrapperDirectory(parent, YES);
        if (fresh < 0) return nil;
        BOOL same = !fstat(directory, &oldParent) && !fstat(fresh, &newParent) &&
            oldParent.st_dev == newParent.st_dev && oldParent.st_ino == newParent.st_ino;
        close(fresh);
        if (!same) return nil;
        id values = [NSJSONSerialization JSONObjectWithData:bytes options:0 error:NULL];
        if (![values isKindOfClass:NSDictionary.class]) return nil;
        id version = values[@"version"];
        if (![version isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)version) == CFBooleanGetTypeID() ||
            CFNumberIsFloatType((__bridge CFNumberRef)version) ||
            ([version longLongValue] != 3 && [version longLongValue] != 4 && [version longLongValue] != 5 && [version longLongValue] != 6 && [version longLongValue] != 7 && [version longLongValue] != 8) ||
            ![values[@"route"] isEqual:@"textmate_api2_plugin"] ||
            ![values[@"receiver_classes"] isEqual:@[@"NSTextView"]] || values[@"key_only_receiver_classes"] ||
            values[@"key_only_window_classes"] || ![values[@"helper"] isKindOfClass:NSDictionary.class]) return nil;
        if (([version longLongValue] >= 4) &&
            (![values[@"target"][@"cdhash"] isEqual:LWProviderReviewedTextMateCDHash] ||
             ![values[@"text_input_client_receiver_classes"] isEqual:@[@"OakTextView"]] ||
             ![values[@"text_input_client_window_classes"] isEqual:@[@"NSWindow"]] ||
             ![values[@"text_input_client_document_classes"] isEqual:@[@"OakDocument"]])) return nil;
        if ([version longLongValue] == 3 && (values[@"text_input_client_receiver_classes"] ||
            values[@"text_input_client_window_classes"] || values[@"text_input_client_document_classes"])) return nil;
        id contextKeys = values[@"text_input_context_keys"];
        if ([version longLongValue] >= 5) {
            if (![contextKeys isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)contextKeys) != CFBooleanGetTypeID() || ![contextKeys boolValue]) return nil;
        } else if (contextKeys) return nil;
        id shift = values[@"text_input_context_shift"];
        if ([version longLongValue] >= 6) {
            if (![shift isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)shift) != CFBooleanGetTypeID() || ![shift boolValue]) return nil;
        } else if (shift) return nil;
        id controlOption=values[@"text_input_context_control_option"];
        if ([version longLongValue] >= 7) {
            if (![controlOption isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)controlOption) != CFBooleanGetTypeID() || ![controlOption boolValue]) return nil;
        } else if(controlOption) return nil;
        id receiverKeyUp=values[@"text_input_context_receiver_key_up"];
        if ([version longLongValue] == 8) {
            if (![receiverKeyUp isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)receiverKeyUp) != CFBooleanGetTypeID() || ![receiverKeyUp boolValue]) return nil;
        } else if(receiverKeyUp) return nil;
        // Full exact schema and duplicate-key rejection remain bootstrap-owned.
        return values;
    } @finally { if (fd >= 0) close(fd); close(directory); }
}
static NSDictionary *LWWrapperSignedInfo(NSString *path) {
    SecStaticCodeRef code = NULL; SecRequirementRef requirement = NULL; CFDictionaryRef raw = NULL;
    @try {
        if (SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:path], kSecCSDefaultFlags, &code) != errSecSuccess ||
            SecRequirementCreateWithString(CFSTR("anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"),
                kSecCSDefaultFlags, &requirement) != errSecSuccess ||
            SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, requirement) != errSecSuccess ||
            SecCodeCopySigningInformation(code, kSecCSSigningInformation, &raw) != errSecSuccess || !raw) return nil;
        NSDictionary *info = CFBridgingRelease(raw); raw = NULL;
        return info;
    } @finally { if (raw) CFRelease(raw); if (requirement) CFRelease(requirement); if (code) CFRelease(code); }
}
static BOOL LWWrapperPrivateHelper(int fd, struct stat *s) {
    return !fstat(fd, s) && S_ISREG(s->st_mode) && s->st_uid == geteuid() &&
        (s->st_mode & 07777) == 0600 && s->st_nlink == 1 && LWProviderHasPrivateACL(fd);
}
static BOOL LWWrapperHelperStillAtPath(int parent, NSString *parentPath, int fd,
                                     NSString *name, const struct stat *before) {
    struct stat after, named, pinnedParent, observedParent;
    if (!LWWrapperPrivateHelper(fd, &after) || !LWWrapperSameFile(before, &after) ||
        fstatat(parent, name.fileSystemRepresentation, &named, AT_SYMLINK_NOFOLLOW) ||
        !LWWrapperSameFile(before, &named)) return NO;
    int fresh = LWWrapperDirectory(parentPath, YES);
    if (fresh < 0) return NO;
    BOOL same = !fstat(parent, &pinnedParent) && !fstat(fresh, &observedParent) &&
        pinnedParent.st_dev == observedParent.st_dev && pinnedParent.st_ino == observedParent.st_ino &&
        pinnedParent.st_uid == geteuid() && (pinnedParent.st_mode & 07777) == 0700 && LWProviderHasPrivateACL(parent);
    close(fresh); return same;
}
static BOOL LWWrapperHelper(NSDictionary *pin, NSString *wrapperPath) {
    NSString *path = pin[@"path"];
    if (!LWWrapperPath(path) || pin.count != 4) return NO;
    NSString *parentPath = path.stringByDeletingLastPathComponent;
    int parent = LWWrapperDirectory(parentPath, YES);
    if (parent < 0) return NO;
    int fd = openat(parent, path.lastPathComponent.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    @try {
        struct stat before;
        if (fd < 0 || !LWWrapperPrivateHelper(fd, &before)) return NO;
        NSDictionary *helper = LWWrapperSignedInfo(path), *wrapper = LWWrapperSignedInfo(wrapperPath);
        if (!helper || !wrapper) return NO;
        NSString *identifier = helper[(__bridge NSString *)kSecCodeInfoIdentifier];
        NSString *team = helper[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
        NSData *hash = helper[(__bridge NSString *)kSecCodeInfoUnique];
        NSURL *executable = helper[(__bridge NSString *)kSecCodeInfoMainExecutable];
        if (![identifier isKindOfClass:NSString.class] || !identifier.length ||
            ![identifier isEqual:pin[@"signing_identifier"]] || ![team isKindOfClass:NSString.class] || !team.length ||
            ![team isEqual:pin[@"team_identifier"]] || ![team isEqual:wrapper[(__bridge NSString *)kSecCodeInfoTeamIdentifier]] ||
            ![wrapper[(__bridge NSString *)kSecCodeInfoIdentifier] isEqual:@"tools.localworkbench.textmate.receiver"] ||
            ![hash isKindOfClass:NSData.class] || hash.length < 20 || hash.length > 64 ||
            ![executable isKindOfClass:NSURL.class] || ![executable.path isEqual:path]) return NO;
        NSMutableString *hex = [NSMutableString string]; const uint8_t *bytes = hash.bytes;
        for (NSUInteger i = 0; i < hash.length; i++) [hex appendFormat:@"%02x", bytes[i]];
        if (![hex isEqual:pin[@"cdhash"]]) return NO;
        // Refuse path replacement during validation; bootstrap repeats signatures,
        // identities, vnode and mapped executable bytes after loading.
        return LWWrapperHelperStillAtPath(parent, parentPath, fd, path.lastPathComponent, &before);
    } @finally { if (fd >= 0) close(fd); close(parent); }
}

@interface WorkbenchTextMateReceiver : NSObject
@property(nonatomic, readonly, copy) NSString *startupStatus;
- (instancetype)initWithPlugInController:(id<LWTextMateController>)controller;
@end
@implementation WorkbenchTextMateReceiver {
    void *_helperHandle;
}
- (instancetype)initWithPlugInController:(id<LWTextMateController>)controller {
    if (!(self = [super init])) return nil;
    _startupStatus = @"inactive";
    @try {
        if (![NSThread isMainThread]) { _startupStatus = @"main_thread_required"; return self; }
        if (![controller respondsToSelector:@selector(version)] || [controller version] != 2.0) {
            _startupStatus = @"api2_controller_required"; return self;
        }
        const char *raw = getenv("LOCAL_WORKBENCH_PLUGIN_PROVIDER_CONFIG");
        if (!raw) return self;
        if (getenv("LOCAL_WORKBENCH_PROVIDER_CONFIG")) { _startupStatus = @"legacy_config_conflict"; return self; }
        size_t length = strnlen(raw, 4097);
        NSString *path = length && length <= 4096 ? [[NSString alloc] initWithBytes:raw length:length encoding:NSUTF8StringEncoding] : nil;
        NSDictionary *config = path ? LWWrapperConfig(path) : nil;
        if (!config) { _startupStatus = @"protected_v3_config_required"; return self; }
        Dl_info marker = {0};
        if (!dladdr((const void *)&LWTextMateWrapperMarker, &marker) || !marker.dli_fname) {
            _startupStatus = @"mapped_wrapper_required"; return self;
        }
        NSString *wrapperPath = [[NSString alloc] initWithUTF8String:marker.dli_fname];
        if (!LWWrapperHelper(config[@"helper"], wrapperPath)) { _startupStatus = @"signed_pinned_helper_required"; return self; }
        _helperHandle = dlopen([config[@"helper"][@"path"] fileSystemRepresentation], RTLD_NOW | RTLD_LOCAL);
        if (!_helperHandle) { _startupStatus = @"helper_load_refused"; return self; }
        BOOL (*start)(NSString *, const void *) = (BOOL (*)(NSString *, const void *))dlsym(_helperHandle, "LWProviderBootstrapStartFromTextMatePlugin");
        Dl_info entry = {0};
        if (!start || !dladdr((const void *)start, &entry) || !entry.dli_fname ||
            ![config[@"helper"][@"path"] isEqual:[[NSString alloc] initWithUTF8String:entry.dli_fname]]) {
            _startupStatus = @"explicit_helper_entry_required"; return self;
        }
        _startupStatus = start(path, (const void *)&LWTextMateWrapperMarker) ? @"running" : @"bootstrap_refused";
        // Keep the handle for the process lifetime: helper owns asynchronous state.
    } @catch (__unused NSException *exception) { _startupStatus = @"wrapper_exception"; }
    return self;
}
@end
