#import "ProviderBootstrap.h"
#import "ReceiverService.h"
#import <Security/Security.h>
#import <bsm/audit.h>
#import <dlfcn.h>
#import <libproc.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach-o/dyld.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <objc/runtime.h>
#import <stdatomic.h>
#import <sys/stat.h>
#import "ProviderFileSecurity.h"
#import "ProviderHostIdentity.h"
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>

static const NSUInteger LWBootstrapConfigLimit = 16384;
static const SecCSFlags LWBootstrapSigningFlags = kSecCSSigningInformation | kSecCSRequirementInformation;
typedef NS_ENUM(unsigned, LWBootstrapState) {
    LWBootstrapInactive, LWBootstrapScheduled, LWBootstrapRunning, LWBootstrapStopped,
    LWBootstrapWrongThread, LWBootstrapConfigRefused, LWBootstrapIdentityRefused,
    LWBootstrapClassRefused, LWBootstrapServiceRefused, LWBootstrapEndpointRefused,
    LWBootstrapException, LWBootstrapRestartRefused,
    LWBootstrapTargetPathRefused, LWBootstrapHelperPathRefused,
    LWBootstrapDynamicSecurityRefused, LWBootstrapBundleRefused,
    LWBootstrapSignatureRefused, LWBootstrapPinRefused,
    LWBootstrapMappedTargetRefused, LWBootstrapMappedHelperRefused,
    LWBootstrapLoaderRefused, LWBootstrapFreshIdentityRefused,
    LWBootstrapPluginMarkerRefused, LWBootstrapMappedPluginRefused,
    LWBootstrapDeveloperIDRefused,
};
static _Atomic(unsigned) LWBootstrapStateCode = LWBootstrapInactive;
static BOOL LWBootstrapAttempted;

static BOOL LWBootstrapString(id value, NSUInteger limit) {
    return [value isKindOfClass:NSString.class] && [value length] &&
        [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding] <= limit &&
        [value rangeOfCharacterFromSet:[NSCharacterSet characterSetWithRange:NSMakeRange(0, 1)]].location == NSNotFound;
}
static BOOL LWBootstrapPath(id path) {
    if (!LWBootstrapString(path, 4096) || ![path hasPrefix:@"/"] || [path hasSuffix:@"/"]) return NO;
    NSArray *components = [path componentsSeparatedByString:@"/"];
    for (NSUInteger i = 1; i < components.count; i++) {
        NSString *component = components[i];
        if (!component.length || [component isEqual:@"."] || [component isEqual:@".."]) return NO;
    }
    return YES;
}
static BOOL LWBootstrapKeys(id value, NSArray *keys) {
    return [value isKindOfClass:NSDictionary.class] &&
        [[NSSet setWithArray:[value allKeys]] isEqual:[NSSet setWithArray:keys]];
}
static BOOL LWBootstrapInteger(id value, uint32_t *out) {
    if (![value isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID() ||
        CFNumberIsFloatType((__bridge CFNumberRef)value)) return NO;
    long long n = [value longLongValue]; if (n < 0 || n > UINT32_MAX) return NO;
    if (out) *out = (uint32_t)n; return YES;
}
static BOOL LWBootstrapHash(id hash) {
    if (!LWBootstrapString(hash, 128) || [hash length] < 40 || [hash length] % 2) return NO;
    for (NSUInteger i = 0; i < [hash length]; i++) {
        unichar c = [hash characterAtIndex:i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return NO;
    }
    return YES;
}
static BOOL LWBootstrapPin(id identity, BOOL target) {
    if (!LWBootstrapKeys(identity, target ? @[@"bundle_identifier",@"executable",@"signing_identifier",@"team_identifier",@"cdhash"] :
        @[@"path",@"signing_identifier",@"team_identifier",@"cdhash"])) return NO;
    return LWBootstrapPath(identity[target ? @"executable" : @"path"]) &&
        (!target || LWBootstrapString(identity[@"bundle_identifier"], 512)) &&
        LWBootstrapString(identity[@"signing_identifier"], 512) &&
        LWBootstrapString(identity[@"team_identifier"], 128) && LWBootstrapHash(identity[@"cdhash"]);
}
static BOOL LWBootstrapPluginPin(id identity) {
    if (!LWBootstrapKeys(identity, @[@"bundle_path",@"executable",@"bundle_identifier",@"signing_identifier",@"team_identifier",@"cdhash"])) return NO;
    return LWBootstrapPath(identity[@"bundle_path"]) && [identity[@"bundle_path"] hasSuffix:@".tmplugin"] &&
        LWBootstrapPath(identity[@"executable"]) &&
        [identity[@"executable"] hasPrefix:[identity[@"bundle_path"] stringByAppendingString:@"/Contents/MacOS/"]] &&
        [identity[@"bundle_identifier"] isEqual:@"tools.localworkbench.textmate.receiver"] &&
        [identity[@"signing_identifier"] isEqual:@"tools.localworkbench.textmate.receiver"] &&
        LWBootstrapString(identity[@"team_identifier"], 128) && LWBootstrapHash(identity[@"cdhash"]);
}
static BOOL LWBootstrapClassName(id name) {
    if (!LWBootstrapString(name, 512)) return NO;
    NSData *bytes = [name dataUsingEncoding:NSASCIIStringEncoding allowLossyConversion:NO];
    if (!bytes) return NO;
    const uint8_t *p = bytes.bytes;
    for (NSUInteger i = 0; i < bytes.length; i++) {
        uint8_t c = p[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$' ||
              (i && ((c >= '0' && c <= '9') || c == '.')))) return NO;
    }
    return YES;
}
// Descriptor-relative component walking refuses symlinks in every ancestor.
// Only the final config parent/journal must be private0700; / itself need not be.
static int LWBootstrapOpenDirectory(NSString *path, BOOL privateDirectory) {
    if (!LWBootstrapPath(path)) return -1;
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    for (NSString *component in path.pathComponents) {
        if ([component isEqual:@"/"]) continue;
        int next = openat(fd, component.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(fd); fd = next; if (fd < 0) return -1;
    }
    struct stat s;
    if (fstat(fd, &s) || !S_ISDIR(s.st_mode) || (privateDirectory &&
        (s.st_uid != geteuid() || (s.st_mode & 07777) != 0700 || !LWProviderHasPrivateACL(fd)))) { close(fd); return -1; }
    return fd;
}
static BOOL LWBootstrapPrivateFile(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() && (s->st_mode & 07777) == 0600 &&
        s->st_nlink == 1 && s->st_size > 0 && s->st_size <= (off_t)LWBootstrapConfigLimit;
}
static BOOL LWBootstrapSameFile(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid && a->st_nlink == b->st_nlink &&
        a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
static BOOL LWBootstrapDirectoryStillAtPath(int fd, NSString *path) {
    int fresh = LWBootstrapOpenDirectory(path, YES); if (fresh < 0) return NO;
    struct stat a, b;
    BOOL same = !fstat(fd, &a) && !fstat(fresh, &b) && a.st_dev == b.st_dev && a.st_ino == b.st_ino;
    close(fresh); return same;
}

@interface LWBootstrapConfig : NSObject
@property(nonatomic, copy) NSDictionary *values;
@property(nonatomic) int parentFD, journalFD;
@property(nonatomic, copy) NSString *parentPath, *journalPath;
@end
@implementation LWBootstrapConfig
- (instancetype)init { if ((self = [super init])) { _parentFD = -1; _journalFD = -1; } return self; }
- (void)dealloc { if (_parentFD >= 0) close(_parentFD); if (_journalFD >= 0) close(_journalFD); }
@end

static LWBootstrapConfig *LWBootstrapReadConfigForRoute(NSString *path, BOOL pluginRoute) {
    if (!LWBootstrapPath(path)) return nil;
    LWBootstrapConfig *config = [LWBootstrapConfig new]; config.parentPath = path.stringByDeletingLastPathComponent;
    config.parentFD = LWBootstrapOpenDirectory(config.parentPath, YES);
    if (config.parentFD < 0) return nil;
    int fd = openat(config.parentFD, path.lastPathComponent.fileSystemRepresentation,
        O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return nil;
    NSData *bytes = nil;
    @try {
        struct stat before, after, named;
        if (fstat(fd, &before) || !LWBootstrapPrivateFile(&before) || !LWProviderHasPrivateACL(fd)) return nil;
        NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)before.st_size]; NSUInteger at = 0;
        while (at < data.length) {
            ssize_t n = read(fd, (uint8_t *)data.mutableBytes + at, data.length - at);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return nil; at += (NSUInteger)n;
        }
        uint8_t extra;
        if (read(fd, &extra, 1) != 0 || fstat(fd, &after) || !LWBootstrapPrivateFile(&after) || !LWProviderHasPrivateACL(fd) ||
            !LWBootstrapSameFile(&before, &after) ||
            fstatat(config.parentFD, path.lastPathComponent.fileSystemRepresentation, &named, AT_SYMLINK_NOFOLLOW) ||
            !LWBootstrapSameFile(&before, &named) || !LWBootstrapDirectoryStillAtPath(config.parentFD, config.parentPath)) return nil;
        bytes = [data copy];
    } @finally { close(fd); }
    id values = LWProviderDecodeJSON(bytes, NULL);
    uint32_t version;
    if (![values isKindOfClass:NSDictionary.class] || !LWBootstrapInteger(values[@"version"], &version) ||
        (pluginRoute ? (version != 3 && version != 4 && version != 5 && version != 6 && version != 7 && version != 8) : (version != 1 && version != 2))) return nil;
    NSArray *keys = @[@"version",@"socket_path",@"journal_path",@"token",@"session",@"generation",
        @"host_audit_token",@"target",@"helper",@"receiver_classes"];
    if (version == 2) keys = [keys arrayByAddingObjectsFromArray:@[@"key_only_receiver_classes",@"key_only_window_classes"]];
    if (version >= 3) keys = [keys arrayByAddingObjectsFromArray:@[@"route",@"plugin"]];
    if (version >= 4) keys = [keys arrayByAddingObjectsFromArray:@[@"text_input_client_receiver_classes",@"text_input_client_window_classes",@"text_input_client_document_classes"]];
    if (version >= 5) {
        keys = [keys arrayByAddingObject:@"text_input_context_keys"];
        id flag = values[@"text_input_context_keys"];
        if (![flag isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)flag) != CFBooleanGetTypeID() || ![flag boolValue]) return nil;
    }
    if (version >= 6) {
        keys=[keys arrayByAddingObject:@"text_input_context_shift"];
        id flag=values[@"text_input_context_shift"];
        if (![flag isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)flag) != CFBooleanGetTypeID() || ![flag boolValue]) return nil;
    }
    if (version >= 7) {
        keys=[keys arrayByAddingObject:@"text_input_context_control_option"];
        id flag=values[@"text_input_context_control_option"];
        if (![flag isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)flag) != CFBooleanGetTypeID() || ![flag boolValue]) return nil;
    }
    if (version == 8) {
        keys=[keys arrayByAddingObject:@"text_input_context_receiver_key_up"];
        id flag=values[@"text_input_context_receiver_key_up"];
        if (![flag isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)flag) != CFBooleanGetTypeID() || ![flag boolValue]) return nil;
    }
    if (!LWBootstrapKeys(values, keys) ||
        !LWBootstrapPath(values[@"socket_path"]) || !LWBootstrapPath(values[@"journal_path"]) ||
        ![[values[@"socket_path"] stringByDeletingLastPathComponent] isEqual:config.parentPath] ||
        [values[@"socket_path"] isEqual:path] || !LWBootstrapPin(values[@"target"], YES) || !LWBootstrapPin(values[@"helper"], NO)) return nil;
    if ((version >= 3) && (![values[@"route"] isEqual:@"textmate_api2_plugin"] ||
        !LWBootstrapPluginPin(values[@"plugin"]) ||
        ![values[@"plugin"][@"team_identifier"] isEqual:values[@"helper"][@"team_identifier"]] ||
        ![values[@"target"][@"bundle_identifier"] isEqual:@"com.macromates.TextMate"] ||
        ![values[@"target"][@"signing_identifier"] isEqual:@"com.macromates.TextMate"] ||
        ![values[@"target"][@"team_identifier"] isEqual:@"45TL96F76G"])) return nil;
    if (!LWBootstrapString(values[@"host_audit_token"], 64)) return nil;
    NSData *audit = [[NSData alloc] initWithBase64EncodedString:values[@"host_audit_token"] options:0];
    if (audit.length != sizeof(audit_token_t) || ![[audit base64EncodedStringWithOptions:0] isEqual:values[@"host_audit_token"]]) return nil;
    LWProviderConfiguration *endpoint = [[LWProviderConfiguration alloc] initWithSocketPath:values[@"socket_path"]
        token:values[@"token"] session:values[@"session"] generation:values[@"generation"] expectedHostAuditToken:audit requestTimeout:5];
    if (!endpoint) return nil;
    NSArray *names = values[@"receiver_classes"];
    if (![names isKindOfClass:NSArray.class] || !names.count || names.count > 32 || [NSSet setWithArray:names].count != names.count) return nil;
    for (id name in names) if (!LWBootstrapClassName(name)) return nil;
    if ((version >= 3) && ![names isEqual:@[@"NSTextView"]]) return nil;
    if ((version >= 4) && (![values[@"target"][@"cdhash"] isEqual:LWProviderReviewedTextMateCDHash] ||
        ![values[@"text_input_client_receiver_classes"] isEqual:@[@"OakTextView"]] ||
        ![values[@"text_input_client_window_classes"] isEqual:@[@"NSWindow"]] ||
        ![values[@"text_input_client_document_classes"] isEqual:@[@"OakDocument"]])) return nil;
    if (version == 2) {
        for (NSString *key in @[@"key_only_receiver_classes",@"key_only_window_classes"]) {
            NSArray *group = values[key];
            if (![group isKindOfClass:NSArray.class] || !group.count || group.count > 32 ||
                [NSSet setWithArray:group].count != group.count) return nil;
            for (id name in group) if (!LWBootstrapClassName(name)) return nil;
        }
        NSMutableSet *combined = [NSMutableSet setWithArray:names];
        for (NSString *name in values[@"key_only_receiver_classes"]) {
            if ([combined containsObject:name]) return nil;
            [combined addObject:name];
        }
    }
    struct stat existing;
    if (!fstatat(config.parentFD, [values[@"socket_path"] lastPathComponent].fileSystemRepresentation, &existing, AT_SYMLINK_NOFOLLOW) || errno != ENOENT) return nil;
    config.journalPath = values[@"journal_path"];
    if ([config.journalPath isEqual:config.parentPath] ||
        [config.journalPath hasPrefix:[config.parentPath stringByAppendingString:@"/"]]) return nil;
    config.journalFD = LWBootstrapOpenDirectory(config.journalPath, YES);
    if (config.journalFD < 0 || !LWBootstrapDirectoryStillAtPath(config.journalFD, config.journalPath)) return nil;
    config.values = values; return config;
}
static LWBootstrapConfig *LWBootstrapReadConfig(NSString *path) {
    return LWBootstrapReadConfigForRoute(path, NO);
}

static NSString *LWBootstrapCanonical(const char *raw) {
    if (!raw || !strnlen(raw, 4097) || strnlen(raw, 4097) > 4096) return nil;
    char resolved[PATH_MAX]; if (!realpath(raw, resolved)) return nil;
    NSString *path = [[NSString alloc] initWithUTF8String:resolved]; return LWBootstrapPath(path) ? path : nil;
}
static BOOL LWBootstrapBool(NSDictionary *entitlements, NSString *key, BOOL *enabled) {
    id value = entitlements[key];
    if (!value) { *enabled = NO; return YES; }
    if (CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID()) return NO;
    *enabled = [value boolValue]; return YES;
}
// Same loader policy as NativeProviderAdmission: no ad-hoc/linker/platform/
// restricted/privileged/sandbox code; existing DYLD and cross-Team exceptions.
static BOOL LWBootstrapLoaderPolicy(NSDictionary *target, NSDictionary *helper, BOOL targetRestricted, BOOL helperRestricted) {
    uint32_t targetFlags = 0;
    for (NSDictionary *info in @[target, helper]) {
        uint32_t flags, platform = 0;
        if (!LWBootstrapInteger(info[(__bridge NSString *)kSecCodeInfoFlags], &flags) ||
            (flags & (0x0002U | 0x0800U | 0x20000U)) ||
            !LWBootstrapString(info[(__bridge NSString *)kSecCodeInfoTeamIdentifier], 128) ||
            (info[(__bridge NSString *)kSecCodeInfoPlatformIdentifier] &&
                (!LWBootstrapInteger(info[(__bridge NSString *)kSecCodeInfoPlatformIdentifier], &platform) || platform))) return NO;
        id raw = info[(__bridge NSString *)kSecCodeInfoEntitlementsDict];
        if ((raw && ![raw isKindOfClass:NSDictionary.class]) || (!raw && info[(__bridge NSString *)kSecCodeInfoEntitlements])) return NO;
        NSDictionary *entitlements = raw ?: @{}; BOOL sandbox, dyld, disable;
        if (!LWBootstrapBool(entitlements, @"com.apple.security.app-sandbox", &sandbox) || sandbox ||
            !LWBootstrapBool(entitlements, @"com.apple.security.cs.allow-dyld-environment-variables", &dyld) ||
            !LWBootstrapBool(entitlements, @"com.apple.security.cs.disable-library-validation", &disable)) return NO;
        if (info == target) targetFlags = flags;
    }
    if (targetRestricted || helperRestricted) return NO;
    NSDictionary *entitlements = target[(__bridge NSString *)kSecCodeInfoEntitlementsDict] ?: @{};
    BOOL dyld, disable;
    if (!LWBootstrapBool(entitlements, @"com.apple.security.cs.allow-dyld-environment-variables", &dyld) ||
        !LWBootstrapBool(entitlements, @"com.apple.security.cs.disable-library-validation", &disable)) return NO;
    return (!(targetFlags & 0x10000U) || dyld) &&
        ([target[(__bridge NSString *)kSecCodeInfoTeamIdentifier] isEqual:helper[(__bridge NSString *)kSecCodeInfoTeamIdentifier]] || disable);
}
// Explicit normal-plugin loading contract. All original code restrictions
// remain; only this route does not depend on DYLD environment-variable opt-in.
static BOOL LWBootstrapPluginLoaderPolicy(NSDictionary *target, NSDictionary *helper, NSDictionary *plugin,
                                         BOOL targetRestricted, BOOL helperRestricted, BOOL pluginRestricted) {
    if (![target isKindOfClass:NSDictionary.class] || ![helper isKindOfClass:NSDictionary.class] ||
        ![plugin isKindOfClass:NSDictionary.class] || targetRestricted || helperRestricted || pluginRestricted) return NO;
    uint32_t targetFlags = 0;
    for (NSDictionary *info in @[target, helper, plugin]) {
        uint32_t flags, platform = 0;
        if (!LWBootstrapInteger(info[(__bridge NSString *)kSecCodeInfoFlags], &flags) ||
            (flags & (0x0002U | 0x0800U | 0x20000U)) ||
            !LWBootstrapString(info[(__bridge NSString *)kSecCodeInfoTeamIdentifier], 128) ||
            (info[(__bridge NSString *)kSecCodeInfoPlatformIdentifier] &&
                (!LWBootstrapInteger(info[(__bridge NSString *)kSecCodeInfoPlatformIdentifier], &platform) || platform))) return NO;
        id raw = info[(__bridge NSString *)kSecCodeInfoEntitlementsDict];
        if ((raw && ![raw isKindOfClass:NSDictionary.class]) || (!raw && info[(__bridge NSString *)kSecCodeInfoEntitlements])) return NO;
        NSDictionary *entitlements = raw ?: @{}; BOOL sandbox, dyld, disable;
        if (!LWBootstrapBool(entitlements, @"com.apple.security.app-sandbox", &sandbox) || sandbox ||
            !LWBootstrapBool(entitlements, @"com.apple.security.cs.allow-dyld-environment-variables", &dyld) ||
            !LWBootstrapBool(entitlements, @"com.apple.security.cs.disable-library-validation", &disable)) return NO;
        if (info == target) targetFlags = flags;
    }
    NSDictionary *targetPlist = target[(__bridge NSString *)kSecCodeInfoPList], *pluginPlist = plugin[(__bridge NSString *)kSecCodeInfoPList];
    if (![targetPlist isKindOfClass:NSDictionary.class] || ![pluginPlist isKindOfClass:NSDictionary.class] ||
        ![targetPlist[@"CFBundleIdentifier"] isEqual:@"com.macromates.TextMate"] ||
        ![target[(__bridge NSString *)kSecCodeInfoIdentifier] isEqual:@"com.macromates.TextMate"] ||
        ![target[(__bridge NSString *)kSecCodeInfoTeamIdentifier] isEqual:@"45TL96F76G"] ||
        ![pluginPlist[@"CFBundleIdentifier"] isEqual:@"tools.localworkbench.textmate.receiver"] ||
        ![plugin[(__bridge NSString *)kSecCodeInfoIdentifier] isEqual:@"tools.localworkbench.textmate.receiver"] ||
        ![plugin[(__bridge NSString *)kSecCodeInfoTeamIdentifier] isEqual:helper[(__bridge NSString *)kSecCodeInfoTeamIdentifier]]) return NO;
    BOOL disable;
    return (targetFlags & 0x10000U) &&
        LWBootstrapBool(target[(__bridge NSString *)kSecCodeInfoEntitlementsDict] ?: @{},
                        @"com.apple.security.cs.disable-library-validation", &disable) && disable;
}
static NSDictionary *LWBootstrapSigningInfo(SecStaticCodeRef code) {
    CFDictionaryRef raw = NULL;
    if (SecCodeCopySigningInformation(code, LWBootstrapSigningFlags, &raw) != errSecSuccess || !raw) return nil;
    return CFBridgingRelease(raw);
}
static BOOL LWBootstrapSameSigningInfo(NSDictionary *a, NSDictionary *b) {
    if (!a || !b) return NO;
    for (NSString *key in @[(__bridge NSString *)kSecCodeInfoIdentifier, (__bridge NSString *)kSecCodeInfoUnique,
        (__bridge NSString *)kSecCodeInfoFlags, (__bridge NSString *)kSecCodeInfoTeamIdentifier,
        (__bridge NSString *)kSecCodeInfoPlatformIdentifier, (__bridge NSString *)kSecCodeInfoMainExecutable,
        (__bridge NSString *)kSecCodeInfoPList, (__bridge NSString *)kSecCodeInfoEntitlementsDict,
        (__bridge NSString *)kSecCodeInfoEntitlements]) {
        id left = a[key], right = b[key];
        if ((left || right) && ![left isEqual:right]) return NO;
    }
    return YES;
}
static BOOL LWBootstrapDeveloperIDAnchor(SecStaticCodeRef code, NSDictionary *observedInfo) {
    if (!code || !observedInfo) return NO;
    // Certificate-chain requirements are enforced against the actual code
    // object. Claimed Team/identifier/requirement strings are not trust inputs.
    CFStringRef source = CFSTR("anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists");
    SecRequirementRef requirement = NULL;
    BOOL valid = SecRequirementCreateWithString(source, kSecCSDefaultFlags, &requirement) == errSecSuccess && requirement &&
        SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, requirement) == errSecSuccess &&
        LWBootstrapSameSigningInfo(LWBootstrapSigningInfo(code), observedInfo);
    if (requirement) CFRelease(requirement);
    return valid;
}
static NSDictionary *LWBootstrapIdentity(NSDictionary *info, NSString *path, BOOL target) {
    NSString *identifier = info[(__bridge NSString *)kSecCodeInfoIdentifier], *team = info[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
    NSData *hash = info[(__bridge NSString *)kSecCodeInfoUnique]; id executable = info[(__bridge NSString *)kSecCodeInfoMainExecutable];
    if (!LWBootstrapString(identifier, 512) || !LWBootstrapString(team, 128) ||
        ![hash isKindOfClass:NSData.class] || hash.length < 20 || hash.length > 64 ||
        ![executable isKindOfClass:NSURL.class] || ![LWBootstrapCanonical([executable fileSystemRepresentation]) isEqual:path]) return nil;
    NSMutableString *hex = [NSMutableString string]; const uint8_t *p = hash.bytes;
    for (NSUInteger i = 0; i < hash.length; i++) [hex appendFormat:@"%02x", p[i]];
    NSMutableDictionary *identity = [@{@"signing_identifier":identifier,@"team_identifier":team,@"cdhash":[hex copy],
        target ? @"executable" : @"path":path} mutableCopy];
    if (target) {
        id plist = info[(__bridge NSString *)kSecCodeInfoPList];
        if (![plist isKindOfClass:NSDictionary.class] || !LWBootstrapString(plist[@"CFBundleIdentifier"], 512)) return nil;
        identity[@"bundle_identifier"] = plist[@"CFBundleIdentifier"];
    }
    return [identity copy];
}
static NSDictionary *LWBootstrapPluginIdentity(SecStaticCodeRef code, NSDictionary *info, NSString *path) {
    NSDictionary *identity = LWBootstrapIdentity(info, path, YES);
    CFURLRef codeURL = NULL;
    if (!identity || SecCodeCopyPath(code, kSecCSDefaultFlags, &codeURL) != errSecSuccess || !codeURL) return nil;
    NSString *bundle = LWBootstrapCanonical([(__bridge NSURL *)codeURL fileSystemRepresentation]);
    CFRelease(codeURL);
    if (![bundle hasSuffix:@".tmplugin"] || ![path hasPrefix:[bundle stringByAppendingString:@"/Contents/MacOS/"]]) return nil;
    NSMutableDictionary *result = [identity mutableCopy]; result[@"bundle_path"] = bundle;
    return [result copy];
}
static BOOL LWBootstrapPRead(int fd, uint64_t offset, void *bytes, size_t length) {
    if (offset > INT64_MAX || length > INT64_MAX - offset) return NO;
    size_t at = 0;
    while (at < length) {
        ssize_t n = pread(fd, (uint8_t *)bytes + at, length - at, (off_t)(offset + at));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return NO; at += (size_t)n;
    }
    return YES;
}
static BOOL LWBootstrapReadMapped(uint64_t address, void *bytes, size_t length) {
    mach_vm_size_t copied = 0;
    return address <= UINT64_MAX - length && mach_vm_read_overwrite(mach_task_self(), address, length,
        (mach_vm_address_t)bytes, &copied) == KERN_SUCCESS && copied == length;
}
static uint32_t LWBootstrapBig32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | bytes[3];
}
// The path is independently obtained from dyld/dladdr/libproc. The mapped vnode
// must equal the reopened file and exact architecture headers. For our helper,
// every executable file-backed segment must also equal that signed file. No
// unchecked image dereferencing or mutable-data comparison is performed.
static BOOL LWBootstrapMappedImage(NSString *path, const struct mach_header *image, intptr_t slide,
                                   uint32_t kind, BOOL compareExecutable, BOOL *restricted) {
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return NO;
    BOOL matched = NO;
    @try {
        struct stat before, after; struct proc_regionwithpathinfo region = {0};
        if (fstat(fd, &before) || !S_ISREG(before.st_mode) || (before.st_mode & (S_ISUID | S_ISGID)) || before.st_size < 32 ||
            proc_pidinfo(getpid(), PROC_PIDREGIONPATHINFO, (uint64_t)image, &region, sizeof region) != sizeof region ||
            region.prp_vip.vip_vi.vi_stat.vst_dev != (uint32_t)before.st_dev ||
            region.prp_vip.vip_vi.vi_stat.vst_ino != before.st_ino) return NO;
        char mappedPath[PROC_PIDPATHINFO_MAXSIZE] = {0};
        if (proc_regionfilename(getpid(), (uint64_t)image, mappedPath, sizeof mappedPath) <= 0 ||
            ![LWBootstrapCanonical(mappedPath) isEqual:path]) return NO;
        struct mach_header_64 mapped;
        if (!LWBootstrapReadMapped((uint64_t)image, &mapped, sizeof mapped) || mapped.magic != MH_MAGIC_64 ||
            mapped.filetype != kind || mapped.ncmds > 8192 || mapped.sizeofcmds > 1024 * 1024) return NO;
        uint8_t first[8]; if (!LWBootstrapPRead(fd, 0, first, sizeof first)) return NO;
        uint64_t offset = 0, sliceLength = (uint64_t)before.st_size;
        uint32_t magic = LWBootstrapBig32(first);
        if (magic == FAT_MAGIC || magic == FAT_MAGIC_64) {
            uint32_t count = LWBootstrapBig32(first + 4); BOOL wide = magic == FAT_MAGIC_64;
            if (!count || count > 16) return NO;
            size_t stride = wide ? 32 : 20; uint8_t table[512];
            if (!LWBootstrapPRead(fd, 8, table, count * stride)) return NO;
            NSUInteger candidates = 0;
            for (uint32_t i = 0; i < count; i++) {
                const uint8_t *p = table + i * stride;
                if (LWBootstrapBig32(p) != (uint32_t)mapped.cputype || LWBootstrapBig32(p + 4) != (uint32_t)mapped.cpusubtype) continue;
                offset = wide ? ((uint64_t)LWBootstrapBig32(p + 8) << 32) | LWBootstrapBig32(p + 12) : LWBootstrapBig32(p + 8);
                sliceLength = wide ? ((uint64_t)LWBootstrapBig32(p + 16) << 32) | LWBootstrapBig32(p + 20) : LWBootstrapBig32(p + 12);
                candidates++;
            }
            if (candidates != 1 || offset > (uint64_t)before.st_size || sliceLength > (uint64_t)before.st_size - offset) return NO;
        }
        size_t headerBytes = sizeof mapped + mapped.sizeofcmds;
        if (headerBytes > sliceLength) return NO;
        NSMutableData *disk = [NSMutableData dataWithLength:headerBytes], *memory = [NSMutableData dataWithLength:headerBytes];
        if (!LWBootstrapPRead(fd, offset, disk.mutableBytes, headerBytes) ||
            !LWBootstrapReadMapped((uint64_t)image, memory.mutableBytes, headerBytes) || ![disk isEqual:memory]) return NO;
        const uint8_t *commands = (const uint8_t *)disk.bytes + sizeof mapped; size_t at = 0;
        uint64_t executableBytes = 0; BOOL sawExecutable = NO; *restricted = NO;
        for (uint32_t i = 0; i < mapped.ncmds; i++) {
            if (at > mapped.sizeofcmds || mapped.sizeofcmds - at < sizeof(struct load_command)) return NO;
            struct load_command command; memcpy(&command, commands + at, sizeof command);
            if (command.cmdsize < sizeof command || command.cmdsize > mapped.sizeofcmds - at) return NO;
            if (command.cmd == LC_SEGMENT) return NO; //64-bit images only.
            if (command.cmd == LC_SEGMENT_64) {
                if (command.cmdsize < sizeof(struct segment_command_64)) return NO;
                struct segment_command_64 segment; memcpy(&segment, commands + at, sizeof segment);
                if (!memcmp(segment.segname, "__RESTRICT", 11)) *restricted = YES;
                if ((segment.initprot & VM_PROT_EXECUTE) && segment.filesize) {
                    if (segment.fileoff > sliceLength || segment.filesize > sliceLength - segment.fileoff ||
                        segment.filesize > segment.vmsize) return NO;
                    sawExecutable = YES;
                    // Dynamic SecCode validity and the exact mapped vnode bind
                    // the target. Byte comparison is bounded to our own helper.
                    if (!compareExecutable) { at += command.cmdsize; continue; }
                    if (segment.filesize > 8 * 1024 * 1024 - executableBytes) return NO;
                    __int128 start = (__int128)segment.vmaddr + slide;
                    if (start < 0 || start > UINT64_MAX || (uint64_t)start > UINT64_MAX - segment.filesize) return NO;
                    uint8_t diskChunk[65536], memoryChunk[65536];
                    for (uint64_t done = 0; done < segment.filesize;) {
                        size_t size = (size_t)MIN(sizeof diskChunk, segment.filesize - done);
                        if (!LWBootstrapPRead(fd, offset + segment.fileoff + done, diskChunk, size) ||
                            !LWBootstrapReadMapped((uint64_t)start + done, memoryChunk, size) || memcmp(diskChunk, memoryChunk, size)) return NO;
                        done += size;
                    }
                    executableBytes += segment.filesize; sawExecutable = YES;
                }
            }
            at += command.cmdsize;
        }
        matched = at == mapped.sizeofcmds && sawExecutable && !fstat(fd, &after) && LWBootstrapSameFile(&before, &after);
    } @finally { close(fd); }
    return matched;
}

static NSDictionary *LWBootstrapIdentityFailure(LWBootstrapState state) {
    atomic_store(&LWBootstrapStateCode, state); return nil;
}
static NSDictionary *LWBootstrapVerifyIdentitiesForRoute(NSDictionary *pins, BOOL pluginRoute, const void *wrapperMarker) {
    uint32_t count = _dyld_image_count();
    if (!count || count > 4096) return LWBootstrapIdentityFailure(LWBootstrapIdentityRefused);
    NSString *pluginPath = nil;
    const struct mach_header *pluginHeader = NULL; intptr_t pluginSlide = 0;
    if (pluginRoute) {
        Dl_info wrapper = {0};
        if (!wrapperMarker || !dladdr(wrapperMarker, &wrapper) || !wrapper.dli_fbase || !wrapper.dli_fname)
            return LWBootstrapIdentityFailure(LWBootstrapPluginMarkerRefused);
        pluginPath = LWBootstrapCanonical(wrapper.dli_fname);
        if (![pluginPath isEqual:pins[@"plugin"][@"executable"]])
            return LWBootstrapIdentityFailure(LWBootstrapPluginMarkerRefused);
        NSUInteger matches = 0;
        for (uint32_t i = 0; i < count; i++) {
            const void *header = _dyld_get_image_header(i);
            BOOL samePath = [LWBootstrapCanonical(_dyld_get_image_name(i)) isEqual:pluginPath];
            if (header != wrapper.dli_fbase && !samePath) continue;
            // Require one image for this exact pinned path, not just one dyld
            // ordinal carrying the marker's base address.
            if (header != wrapper.dli_fbase || !samePath)
                return LWBootstrapIdentityFailure(LWBootstrapPluginMarkerRefused);
            pluginHeader = _dyld_get_image_header(i); pluginSlide = _dyld_get_image_vmaddr_slide(i); matches++;
        }
        if (matches != 1) return LWBootstrapIdentityFailure(LWBootstrapPluginMarkerRefused);
    }
    char processPath[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (proc_pidpath(getpid(), processPath, sizeof processPath) <= 0)
        return LWBootstrapIdentityFailure(LWBootstrapTargetPathRefused);
    NSString *targetPath = LWBootstrapCanonical(processPath);
    if (!targetPath || ![targetPath isEqual:pins[@"target"][@"executable"]])
        return LWBootstrapIdentityFailure(LWBootstrapTargetPathRefused);
    // Injected libraries can precede the executable in dyld's image list.
    // Bind the unique MH_EXECUTE image to the independently observed process
    // path, rather than giving image ordinal zero executable authority.
    const struct mach_header *targetHeader = NULL; intptr_t targetSlide = 0; NSUInteger targetMatches = 0;
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *header = _dyld_get_image_header(i);
        struct mach_header_64 observed;
        if (!header || !LWBootstrapReadMapped((uint64_t)header, &observed, sizeof observed) ||
            observed.magic != MH_MAGIC_64 || observed.filetype != MH_EXECUTE) continue;
        if (![LWBootstrapCanonical(_dyld_get_image_name(i)) isEqual:targetPath]) continue;
        targetHeader = header; targetSlide = _dyld_get_image_vmaddr_slide(i); targetMatches++;
    }
    if (targetMatches != 1) return LWBootstrapIdentityFailure(LWBootstrapTargetPathRefused);
    Dl_info own = {0};
    if (!dladdr((const void *)&LWProviderBootstrapStart, &own) || !own.dli_fbase || !own.dli_fname)
        return LWBootstrapIdentityFailure(LWBootstrapHelperPathRefused);
    NSString *helperPath = LWBootstrapCanonical(own.dli_fname);
    if (![helperPath isEqual:pins[@"helper"][@"path"]] || [helperPath isEqual:targetPath] ||
        (pluginRoute && ([pluginPath isEqual:targetPath] || [pluginPath isEqual:helperPath])))
        return LWBootstrapIdentityFailure(LWBootstrapHelperPathRefused);
    const struct mach_header *helperHeader = NULL; intptr_t helperSlide = 0; NSUInteger matching = 0;
    for (uint32_t i = 0; i < count; i++) {
        if ((const void *)_dyld_get_image_header(i) != own.dli_fbase) continue;
        if (![LWBootstrapCanonical(_dyld_get_image_name(i)) isEqual:helperPath])
            return LWBootstrapIdentityFailure(LWBootstrapHelperPathRefused);
        helperHeader = _dyld_get_image_header(i); helperSlide = _dyld_get_image_vmaddr_slide(i); matching++;
    }
    if (matching != 1) return LWBootstrapIdentityFailure(LWBootstrapHelperPathRefused);
    SecCodeRef selfCode = NULL; SecStaticCodeRef targetCode = NULL, helperCode = NULL, pluginCode = NULL;
    CFURLRef codeURL = NULL; NSDictionary *answer = nil;
    @try {
        if (SecCodeCopySelf(kSecCSDefaultFlags, &selfCode) != errSecSuccess ||
            SecCodeCheckValidity(selfCode, kSecCSDefaultFlags, NULL) != errSecSuccess ||
            SecCodeCopyStaticCode(selfCode, kSecCSDefaultFlags, &targetCode) != errSecSuccess ||
            SecCodeCopyPath(selfCode, kSecCSDefaultFlags, &codeURL) != errSecSuccess ||
            SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:helperPath], kSecCSDefaultFlags, &helperCode) != errSecSuccess)
            return LWBootstrapIdentityFailure(LWBootstrapDynamicSecurityRefused);
        if (pluginRoute && SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:pins[@"plugin"][@"bundle_path"]],
            kSecCSDefaultFlags, &pluginCode) != errSecSuccess)
            return LWBootstrapIdentityFailure(LWBootstrapSignatureRefused);
        NSString *bundlePath = LWBootstrapCanonical([(__bridge NSURL *)codeURL fileSystemRepresentation]);
        if (![bundlePath hasSuffix:@".app"] || ![targetPath hasPrefix:[bundlePath stringByAppendingString:@"/Contents/MacOS/"]])
            return LWBootstrapIdentityFailure(LWBootstrapBundleRefused);
        SecCSFlags validityFlags = kSecCSStrictValidate | kSecCSCheckAllArchitectures;
        if (SecStaticCodeCheckValidity(targetCode, validityFlags, NULL) != errSecSuccess ||
            SecStaticCodeCheckValidity(helperCode, validityFlags, NULL) != errSecSuccess ||
            (pluginRoute && SecStaticCodeCheckValidity(pluginCode, validityFlags, NULL) != errSecSuccess))
            return LWBootstrapIdentityFailure(LWBootstrapSignatureRefused);
        NSDictionary *targetInfo = LWBootstrapSigningInfo((SecStaticCodeRef)selfCode), *helperInfo = LWBootstrapSigningInfo(helperCode);
        NSDictionary *pluginInfo = pluginRoute ? LWBootstrapSigningInfo(pluginCode) : nil;
        NSDictionary *targetIdentity = LWBootstrapIdentity(targetInfo, targetPath, YES), *helperIdentity = LWBootstrapIdentity(helperInfo, helperPath, NO);
        NSDictionary *pluginIdentity = pluginRoute ? LWBootstrapPluginIdentity(pluginCode, pluginInfo, pluginPath) : nil;
        if (![targetIdentity isEqual:pins[@"target"]] || ![helperIdentity isEqual:pins[@"helper"]])
            return LWBootstrapIdentityFailure(LWBootstrapPinRefused);
        if (pluginRoute && ![pluginIdentity isEqual:pins[@"plugin"]])
            return LWBootstrapIdentityFailure(LWBootstrapPinRefused);
        BOOL targetRestricted, helperRestricted;
        if (!LWBootstrapMappedImage(targetPath, targetHeader, targetSlide, MH_EXECUTE, NO, &targetRestricted))
            return LWBootstrapIdentityFailure(LWBootstrapMappedTargetRefused);
        if (!LWBootstrapMappedImage(helperPath, helperHeader, helperSlide, MH_DYLIB, YES, &helperRestricted))
            return LWBootstrapIdentityFailure(LWBootstrapMappedHelperRefused);
        BOOL pluginRestricted = NO;
        if (pluginRoute && !LWBootstrapMappedImage(pluginPath, pluginHeader, pluginSlide, MH_BUNDLE, YES, &pluginRestricted))
            return LWBootstrapIdentityFailure(LWBootstrapMappedPluginRefused);
        if (pluginRoute ? !LWBootstrapPluginLoaderPolicy(targetInfo, helperInfo, pluginInfo, targetRestricted, helperRestricted, pluginRestricted) :
                         !LWBootstrapLoaderPolicy(targetInfo, helperInfo, targetRestricted, helperRestricted))
            return LWBootstrapIdentityFailure(LWBootstrapLoaderRefused);
        if (pluginRoute && (!LWBootstrapDeveloperIDAnchor(targetCode, targetInfo) ||
            !LWBootstrapDeveloperIDAnchor(helperCode, helperInfo) || !LWBootstrapDeveloperIDAnchor(pluginCode, pluginInfo)))
            return LWBootstrapIdentityFailure(LWBootstrapDeveloperIDRefused);
        // Reopen fresh objects after the mapped-file comparison. Security objects
        // may cache metadata; disk replacement/update cannot silently retain pins.
        SecStaticCodeRef freshTarget = NULL, freshHelper = NULL, freshPlugin = NULL;
        @try {
            if (SecStaticCodeCreateWithPath(codeURL, kSecCSDefaultFlags, &freshTarget) != errSecSuccess ||
                SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:helperPath], kSecCSDefaultFlags, &freshHelper) != errSecSuccess ||
                SecStaticCodeCheckValidity(freshTarget, validityFlags, NULL) != errSecSuccess ||
                SecStaticCodeCheckValidity(freshHelper, validityFlags, NULL) != errSecSuccess ||
                (pluginRoute && (SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:pluginIdentity[@"bundle_path"]],
                    kSecCSDefaultFlags, &freshPlugin) != errSecSuccess ||
                    SecStaticCodeCheckValidity(freshPlugin, validityFlags, NULL) != errSecSuccess)))
                return LWBootstrapIdentityFailure(LWBootstrapSignatureRefused);
            NSDictionary *freshTargetInfo = LWBootstrapSigningInfo(freshTarget), *freshHelperInfo = LWBootstrapSigningInfo(freshHelper);
            NSDictionary *freshPluginInfo = pluginRoute ? LWBootstrapSigningInfo(freshPlugin) : nil;
            if (![LWBootstrapIdentity(freshTargetInfo, targetPath, YES) isEqual:targetIdentity] ||
                ![LWBootstrapIdentity(freshHelperInfo, helperPath, NO) isEqual:helperIdentity] ||
                (pluginRoute ? (!LWBootstrapSameSigningInfo(freshTargetInfo, targetInfo) ||
                    !LWBootstrapSameSigningInfo(freshHelperInfo, helperInfo) || !LWBootstrapSameSigningInfo(freshPluginInfo, pluginInfo) ||
                    ![LWBootstrapPluginIdentity(freshPlugin, freshPluginInfo, pluginPath) isEqual:pluginIdentity] ||
                    !LWBootstrapPluginLoaderPolicy(freshTargetInfo, freshHelperInfo, freshPluginInfo, targetRestricted, helperRestricted, pluginRestricted) ||
                    !LWBootstrapDeveloperIDAnchor(freshTarget, freshTargetInfo) || !LWBootstrapDeveloperIDAnchor(freshHelper, freshHelperInfo) ||
                    !LWBootstrapDeveloperIDAnchor(freshPlugin, freshPluginInfo)) :
                    !LWBootstrapLoaderPolicy(freshTargetInfo, freshHelperInfo, targetRestricted, helperRestricted)))
                return LWBootstrapIdentityFailure(LWBootstrapFreshIdentityRefused);
            answer = pluginRoute ? @{@"target":targetIdentity,@"helper":helperIdentity,@"route":@"textmate_api2_plugin",@"plugin":pluginIdentity} :
                @{@"target":targetIdentity,@"helper":helperIdentity};
        } @finally {
            if (freshTarget) CFRelease(freshTarget); if (freshHelper) CFRelease(freshHelper); if (freshPlugin) CFRelease(freshPlugin);
        }
    } @finally {
        if (codeURL) CFRelease(codeURL); if (selfCode) CFRelease(selfCode);
        if (targetCode) CFRelease(targetCode); if (helperCode) CFRelease(helperCode); if (pluginCode) CFRelease(pluginCode);
    }
    return answer;
}
static NSDictionary *LWBootstrapVerifyIdentities(NSDictionary *pins) {
    return LWBootstrapVerifyIdentitiesForRoute(pins, NO, NULL);
}

@interface LWBootstrapRuntime : NSObject
@property(nonatomic, strong) LWProviderEndpoint *endpoint;
@property(nonatomic, strong) LWReceiverService *service;
@property(nonatomic, strong) LWProviderJournal *journal;
@property(nonatomic, strong) LWBootstrapConfig *config;
@property(nonatomic, strong) dispatch_source_t timer;
@property(nonatomic, copy) NSDictionary *identities;
@property(nonatomic, copy) NSArray<NSString *> *receiverClassNames;
@property(nonatomic, copy) NSArray<NSString *> *keyOnlyReceiverClassNames;
@property(nonatomic, copy) NSArray<NSString *> *keyOnlyWindowClassNames;
@property(nonatomic, copy) NSArray<NSString *> *textClientReceiverClassNames;
@property(nonatomic, copy) NSArray<NSString *> *textClientWindowClassNames;
@property(nonatomic, copy) NSArray<NSString *> *textClientDocumentClassNames;
@property(nonatomic) BOOL allowTextClientInputContextKeys;
@property(nonatomic) BOOL allowTextClientInputContextShift;
@property(nonatomic) BOOL allowTextClientInputContextControlOption;
@property(nonatomic) BOOL allowTextClientInputContextReceiverKeyUp;
@end
@implementation LWBootstrapRuntime @end
static LWBootstrapRuntime *LWBootstrapRuntimeInstance;

// C7 OakTextView inherits the audited AppKit NSResponder release handler.
// An initial foreign/swizzled handler must not become a trusted saved release.
static BOOL LWBootstrapReviewedReceiverKeyUp(Class receiverClass) {
    Method receiverMethod=class_getInstanceMethod(receiverClass,@selector(keyUp:));
    Method systemMethod=class_getInstanceMethod(NSResponder.class,@selector(keyUp:));
    IMP receiver=receiverMethod?method_getImplementation(receiverMethod):NULL;
    IMP system=systemMethod?method_getImplementation(systemMethod):NULL;
    Dl_info image={0};
    return receiver && receiver==system && dladdr((const void *)receiver,&image) && image.dli_fbase && image.dli_fname &&
        !strcmp(image.dli_fname,"/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit");
}
static NSString *LWBootstrapEnsureService(LWBootstrapRuntime *runtime) {
    if (runtime.service) return nil;
    if (!NSThread.isMainThread || !runtime.journal) return @"service_unavailable";
    NSMutableSet<Class> *classes = [NSMutableSet set];
    for (NSString *name in runtime.receiverClassNames) {
        Class type = NSClassFromString(name);
        if (!type) return @"reviewed_receiver_class_not_ready";
        [classes addObject:type];
    }
    NSMutableSet<Class> *keyClasses = [NSMutableSet set], *windowClasses = [NSMutableSet set];
    for (NSString *name in runtime.keyOnlyReceiverClassNames) {
        Class type = NSClassFromString(name);
        if (!type) return @"reviewed_key_only_receiver_class_not_ready";
        [keyClasses addObject:type];
    }
    for (NSString *name in runtime.keyOnlyWindowClassNames) {
        Class type = NSClassFromString(name);
        if (!type) return @"reviewed_key_only_window_class_not_ready";
        [windowClasses addObject:type];
    }
    NSMutableSet<Class> *textClients = [NSMutableSet set], *textWindows = [NSMutableSet set], *documents = [NSMutableSet set];
    for (NSArray *pair in @[@[runtime.textClientReceiverClassNames ?: @[], textClients],
                            @[runtime.textClientWindowClassNames ?: @[], textWindows],
                            @[runtime.textClientDocumentClassNames ?: @[], documents]]) {
        for (NSString *name in pair[0]) {
            Class type = NSClassFromString(name);
            if (!type) return @"reviewed_text_client_class_not_ready";
            [pair[1] addObject:type];
        }
    }
    if (runtime.allowTextClientInputContextReceiverKeyUp) {
        Class oak=NSClassFromString(@"OakTextView");
        if (!oak || textClients.count!=1 || ![textClients containsObject:oak] || !LWBootstrapReviewedReceiverKeyUp(oak))
            return @"reviewed_receiver_key_up_implementation_invalid";
    }
    LWReceiverPolicy *policy = [[LWReceiverPolicy alloc] initWithExactReceiverClasses:classes
        exactKeyOnlyReceiverClasses:keyClasses exactKeyOnlyWindowClasses:windowClasses
        exactTextClientReceiverClasses:textClients exactTextClientWindowClasses:textWindows exactTextClientDocumentClasses:documents
        allowTextClientInputContextKeys:runtime.allowTextClientInputContextKeys allowTextClientInputContextShift:runtime.allowTextClientInputContextShift
        allowTextClientInputContextControlOption:runtime.allowTextClientInputContextControlOption
        allowTextClientInputContextReceiverKeyUp:runtime.allowTextClientInputContextReceiverKeyUp
        maximumTextUTF16Units:4096 maximumInputUTF16Units:4096 bindingLifetime:30];
    if (!policy) return @"reviewed_receiver_class_policy_invalid";
    runtime.service = [[LWReceiverService alloc] initWithPolicy:policy journal:runtime.journal windowLookup:^NSWindow *(NSInteger number) {
        // NSApp may still be nil. Never call sharedApplication, activate, create
        // windows or enumerate unrelated processes to make a target ready.
        return NSApp ? [NSApp windowWithWindowNumber:number] : nil;
    } clock:^double { return NSProcessInfo.processInfo.systemUptime; }];
    return runtime.service ? nil : @"service_unavailable";
}

static BOOL LWBootstrapOwner(id owner) {
    NSArray *keys = @[@"claim_id",@"owner_session",@"runtime_generation",@"target_generation",@"window_id"];
    if (!LWBootstrapKeys(owner, keys)) return NO;
    for (NSString *key in keys) if (!LWBootstrapString(owner[key], 128)) return NO;
    return YES;
}
static void LWBootstrapRetireRuntime(LWBootstrapRuntime *runtime) {
    // Teardown steps are independent: an embedding exception in one must not
    // skip releasing retained AppKit references in the others.
    @try { [runtime.endpoint stop]; } @catch (__unused NSException *exception) {}
    @try {
        if (runtime.timer) { dispatch_source_cancel(runtime.timer); runtime.timer = nil; }
    } @catch (__unused NSException *exception) {}
    @try { [runtime.service retireAllBindings]; } @catch (__unused NSException *exception) {}
}

NSString *LWProviderBootstrapStatus(void) {
    switch (atomic_load(&LWBootstrapStateCode)) {
        case LWBootstrapScheduled: return @"scheduled";
        case LWBootstrapRunning: return @"running";
        case LWBootstrapStopped: return @"stopped";
        case LWBootstrapWrongThread: return @"main_thread_required";
        case LWBootstrapConfigRefused: return @"protected_config_required";
        case LWBootstrapIdentityRefused: return @"verified_loaded_identity_and_existing_loader_policy_required";
        case LWBootstrapClassRefused: return @"reviewed_receiver_class_unavailable";
        case LWBootstrapServiceRefused: return @"service_unavailable";
        case LWBootstrapEndpointRefused: return @"endpoint_unavailable";
        case LWBootstrapException: return @"startup_exception_refused";
        case LWBootstrapRestartRefused: return @"new_permitted_launch_required";
        case LWBootstrapTargetPathRefused: return @"actual_target_process_path_required";
        case LWBootstrapHelperPathRefused: return @"actual_mapped_helper_path_required";
        case LWBootstrapDynamicSecurityRefused: return @"dynamic_security_identity_required";
        case LWBootstrapBundleRefused: return @"signed_target_bundle_required";
        case LWBootstrapSignatureRefused: return @"current_valid_signed_code_required";
        case LWBootstrapPinRefused: return @"actual_loaded_identity_pin_mismatch";
        case LWBootstrapMappedTargetRefused: return @"mapped_target_vnode_and_header_unverified";
        case LWBootstrapMappedHelperRefused: return @"mapped_helper_vnode_and_executable_bytes_unverified";
        case LWBootstrapLoaderRefused: return @"existing_loader_entitlements_and_restrictions_required";
        case LWBootstrapFreshIdentityRefused: return @"signing_identity_changed_during_inspection";
        case LWBootstrapPluginMarkerRefused: return @"actual_mapped_plugin_marker_required";
        case LWBootstrapMappedPluginRefused: return @"mapped_plugin_vnode_and_executable_bytes_unverified";
        case LWBootstrapDeveloperIDRefused: return @"current_apple_developer_id_signatures_required";
        default: return @"inactive";
    }
}
BOOL LWProviderBootstrapStop(void) {
    if (!NSThread.isMainThread) return NO;
    LWBootstrapRuntime *runtime = LWBootstrapRuntimeInstance;
    LWBootstrapRetireRuntime(runtime);
    LWBootstrapRuntimeInstance = nil;
    if (LWBootstrapAttempted) atomic_store(&LWBootstrapStateCode, LWBootstrapStopped);
    return YES;
}
static BOOL LWBootstrapStartForRoute(NSString *path, BOOL pluginRoute, const void *wrapperMarker) {
    if (!NSThread.isMainThread) { atomic_store(&LWBootstrapStateCode, LWBootstrapWrongThread); return NO; }
    if (LWBootstrapAttempted) { atomic_store(&LWBootstrapStateCode, LWBootstrapRestartRefused); return NO; }
    LWBootstrapAttempted = YES;
    LWBootstrapRuntime *runtime = nil;
    @try {
        runtime = [LWBootstrapRuntime new];
        runtime.config = pluginRoute ? LWBootstrapReadConfigForRoute(path, YES) : LWBootstrapReadConfig(path);
        if (!runtime.config) { atomic_store(&LWBootstrapStateCode, LWBootstrapConfigRefused); return NO; }
        NSDictionary *values = runtime.config.values;
        runtime.identities = pluginRoute ? LWBootstrapVerifyIdentitiesForRoute(values, YES, wrapperMarker) : LWBootstrapVerifyIdentities(values);
        if (!runtime.identities) return NO;
        runtime.receiverClassNames = values[@"receiver_classes"];
        runtime.keyOnlyReceiverClassNames = values[@"key_only_receiver_classes"] ?: @[];
        runtime.keyOnlyWindowClassNames = values[@"key_only_window_classes"] ?: @[];
        runtime.textClientReceiverClassNames = values[@"text_input_client_receiver_classes"] ?: @[];
        runtime.textClientWindowClassNames = values[@"text_input_client_window_classes"] ?: @[];
        runtime.textClientDocumentClassNames = values[@"text_input_client_document_classes"] ?: @[];
        runtime.allowTextClientInputContextKeys = [values[@"version"] unsignedIntValue] >= 5;
        runtime.allowTextClientInputContextShift = [values[@"version"] unsignedIntValue] >= 6;
        runtime.allowTextClientInputContextControlOption = [values[@"version"] unsignedIntValue] >= 7;
        runtime.allowTextClientInputContextReceiverKeyUp = [values[@"version"] unsignedIntValue] == 8;
        runtime.journal = [[LWProviderJournal alloc] initWithDirectory:runtime.config.journalPath];
        if (!runtime.journal || !LWBootstrapDirectoryStillAtPath(runtime.config.parentFD, runtime.config.parentPath) ||
            !LWBootstrapDirectoryStillAtPath(runtime.config.journalFD, runtime.config.journalPath)) {
            atomic_store(&LWBootstrapStateCode, LWBootstrapServiceRefused); return NO;
        }
        NSData *audit = [[NSData alloc] initWithBase64EncodedString:values[@"host_audit_token"] options:0];
        LWProviderConfiguration *configuration = [[LWProviderConfiguration alloc] initWithSocketPath:values[@"socket_path"]
            token:values[@"token"] session:values[@"session"] generation:values[@"generation"] expectedHostAuditToken:audit requestTimeout:5];
        __weak LWBootstrapRuntime *weakRuntime = runtime;
        runtime.endpoint = [[LWProviderEndpoint alloc] initWithConfiguration:configuration handlerQueue:dispatch_get_main_queue()
            handler:^NSDictionary *(NSString *method, NSDictionary *payload, NSString *requestID, LWProviderRequestGuard *guard) {
                LWBootstrapRuntime *r = weakRuntime;
                if (!r || !guard.valid || !NSThread.isMainThread) return @{@"ready":@NO,@"reason":@"runtime_stopped"};
                if ([method isEqual:@"hello"]) {
                    if (payload.count) return @{@"ready":@NO,@"reason":@"hello_fields_invalid"};
                    // Independently observed public identity, never config/token/audit.
                    NSMutableDictionary *hello = [@{@"ready":@YES,@"status":@"running",@"receiver_ready":r.service ? @YES : @NO,@"pid":@(getpid()),
                        @"target":r.identities[@"target"],@"helper":r.identities[@"helper"]} mutableCopy];
                    if (r.identities[@"plugin"]) {
                        hello[@"route"] = r.identities[@"route"]; hello[@"plugin"] = r.identities[@"plugin"];
                    }
                    if (r.allowTextClientInputContextKeys) hello[@"text_input_context_keys"] = @YES;
                    if (r.allowTextClientInputContextShift) hello[@"text_input_context_shift"] = @YES;
                    if (r.allowTextClientInputContextControlOption) hello[@"text_input_context_control_option"] = @YES;
                    if (r.allowTextClientInputContextReceiverKeyUp) hello[@"text_input_context_receiver_key_up"] = @YES;
                    [hello addEntriesFromDictionary:[r.endpoint hostAuthorityMetadata]];
                    return [hello copy];
                }
                if ([method isEqual:@"cancel"]) {
                    if (payload.count == 0) return @{@"ready":@YES,@"retired":@([r.service retireAllBindings])};
                    if (LWBootstrapKeys(payload, @[@"owner"]) && LWBootstrapOwner(payload[@"owner"]))
                        return @{@"ready":@YES,@"retired":@([r.service retireBindingsForOwner:payload[@"owner"]])};
                    return @{@"ready":@NO,@"reason":@"cancel_fields_invalid"};
                }
                if ([method isEqual:@"observe"]) {
                    NSString *reason = LWBootstrapEnsureService(r);
                    if (reason) return @{@"ready":@NO,@"outcome":@"not_ready",@"reason":reason,
                        @"dispatch_attempted":@NO,@"effect_state":@"none"};
                }
                if (!r.service) return @{@"ready":@NO,@"outcome":@"not_dispatched",@"reason":@"fresh_observation_required",
                    @"dispatch_attempted":@NO,@"effect_state":@"none"};
                return [r.service handleMethod:method payload:payload requestID:requestID guard:guard];
            }];
        // Capture the live original host's signed requirement once. Compatible
        // replacements must keep path/ID/team/Apple provenance and prove the
        // current kernel process generation has ended, never merely timed out.
        LWProviderHostIdentity *hostIdentity = [[LWProviderHostIdentity alloc]
            initWithOriginalAuditToken:audit expectedHelperTeam:runtime.identities[@"helper"][@"team_identifier"]];
        if (hostIdentity) {
            [runtime.endpoint enableHostReplacementWithPolicy:^BOOL(NSData *current, NSData *candidate) {
                return [LWProviderHostIdentity presenceOfAuditToken:current] == LWProviderHostAbsent &&
                    [hostIdentity qualifiesReplacementAuditToken:candidate];
            } retireAuthority:^BOOL {
                LWBootstrapRuntime *r = weakRuntime;
                if (!r || !NSThread.isMainThread) return NO;
                if (r.service) [r.service retireAllBindings];
                return YES;
            }];
        }
        if (![runtime.endpoint start:NULL]) { atomic_store(&LWBootstrapStateCode, LWBootstrapEndpointRefused); return NO; }
        // Keep no raw config dictionary after extracting the endpoint authority.
        runtime.config.values = nil;
        runtime.timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
        if (!runtime.timer) { [runtime.endpoint stop]; atomic_store(&LWBootstrapStateCode, LWBootstrapServiceRefused); return NO; }
        dispatch_source_set_timer(runtime.timer, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), NSEC_PER_SEC, NSEC_PER_SEC / 10);
        dispatch_source_set_event_handler(runtime.timer, ^{
            @try { [weakRuntime.service retireExpiredBindings]; }
            @catch (__unused NSException *exception) { LWProviderBootstrapStop(); }
        });
        LWBootstrapRuntimeInstance = runtime;
        dispatch_resume(runtime.timer);
        atomic_store(&LWBootstrapStateCode, LWBootstrapRunning); return YES;
    } @catch (__unused NSException *exception) {
        LWBootstrapRetireRuntime(runtime);
        atomic_store(&LWBootstrapStateCode, LWBootstrapException); return NO;
    }
}
BOOL LWProviderBootstrapStart(NSString *path) {
    return LWBootstrapStartForRoute(path, NO, NULL);
}
BOOL LWProviderBootstrapStartFromTextMatePlugin(NSString *path, const void *wrapperMarkerAddress) {
    return LWBootstrapStartForRoute(path, YES, wrapperMarkerAddress);
}

#if !defined(LW_PROVIDER_BOOTSTRAP_DISABLE_CONSTRUCTOR)
__attribute__((constructor)) static void LWBootstrapConstructor(void) {
    const char *raw = getenv("LOCAL_WORKBENCH_PROVIDER_CONFIG");
    if (!raw) return; // No Foundation/AppKit/filesystem work absent explicit env.
    @autoreleasepool {
        @try {
            size_t length = strnlen(raw, 4097);
            if (!length || length > 4096) { atomic_store(&LWBootstrapStateCode, LWBootstrapConfigRefused); return; }
            NSString *path = [[NSString alloc] initWithBytes:raw length:length encoding:NSUTF8StringEncoding];
            if (!path) { atomic_store(&LWBootstrapStateCode, LWBootstrapConfigRefused); return; }
            atomic_store(&LWBootstrapStateCode, LWBootstrapScheduled);
            dispatch_async(dispatch_get_main_queue(), ^{ LWProviderBootstrapStart(path); });
        } @catch (__unused NSException *exception) { atomic_store(&LWBootstrapStateCode, LWBootstrapException); }
    }
}
#endif
