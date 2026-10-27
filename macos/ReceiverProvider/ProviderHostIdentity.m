#import "ProviderHostIdentity.h"
#import <Security/Security.h>
#import <bsm/libbsm.h>
#import <libproc.h>
#import <limits.h>
#import <unistd.h>
#import <mach/mach.h>
#import <sys/proc_info.h>
#import <signal.h>
#import <errno.h>

static BOOL LWHostAudit(NSData *data, audit_token_t *token) {
    if (![data isKindOfClass:NSData.class] || data.length != sizeof(audit_token_t)) return NO;
    memcpy(token, data.bytes, sizeof *token);
    return audit_token_to_pid(*token) > 0 && audit_token_to_euid(*token) == geteuid() &&
        audit_token_to_ruid(*token) == getuid();
}

static OSStatus LWHostGuest(NSData *audit, SecCodeRef *guest) {
    *guest = NULL;
    return SecCodeCopyGuestWithAttributes(NULL,
        (__bridge CFDictionaryRef)@{(__bridge NSString *)kSecGuestAttributeAudit: audit},
        kSecCSDefaultFlags, guest);
}

static BOOL LWHostString(id value, NSUInteger limit) {
    return [value isKindOfClass:NSString.class] && [value length] &&
        [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding] <= limit &&
        [value rangeOfCharacterFromSet:[NSCharacterSet characterSetWithRange:NSMakeRange(0, 1)]].location == NSNotFound;
}

static NSString *LWHostCanonical(const char *path) {
    char resolved[PATH_MAX];
    if (!path || !realpath(path, resolved)) return nil;
    NSString *value = [[NSString alloc] initWithUTF8String:resolved];
    return LWHostString(value, PATH_MAX) && [value hasPrefix:@"/"] ? value : nil;
}

static NSDictionary *LWHostMetadata(SecCodeRef guest, audit_token_t token) {
    SecStaticCodeRef code = NULL;
    if (SecCodeCopyStaticCode(guest, kSecCSDefaultFlags, &code) != errSecSuccess || !code) return nil;
    CFDictionaryRef raw = NULL;
    OSStatus status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &raw);
    CFRelease(code);
    if (status != errSecSuccess || !raw) return nil;
    NSDictionary *info = CFBridgingRelease(raw);
    id identifier = info[(__bridge NSString *)kSecCodeInfoIdentifier];
    id team = info[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
    id flags = info[(__bridge NSString *)kSecCodeInfoFlags];
    id platform = info[(__bridge NSString *)kSecCodeInfoPlatformIdentifier];
    id plist = info[(__bridge NSString *)kSecCodeInfoPList];
    id executable = info[(__bridge NSString *)kSecCodeInfoMainExecutable];
    if (!LWHostString(identifier, 512) || !LWHostString(team, 128) ||
        ![flags isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)flags) == CFBooleanGetTypeID() ||
        CFNumberIsFloatType((__bridge CFNumberRef)flags) || [flags longLongValue] < 0 || [flags unsignedLongLongValue] > UINT32_MAX ||
        ([flags unsignedIntValue] & (0x0002U | 0x20000U)) ||
        (platform && (![platform isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)platform) == CFBooleanGetTypeID() ||
            CFNumberIsFloatType((__bridge CFNumberRef)platform) || [platform longLongValue] != 0)) ||
        ![plist isKindOfClass:NSDictionary.class] || ![plist[@"CFBundleIdentifier"] isEqual:identifier] ||
        ![executable isKindOfClass:NSURL.class]) return nil;
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(audit_token_to_pid(token), path, sizeof path) <= 0) return nil;
    NSString *actualPath = LWHostCanonical(path);
    NSString *signedPath = LWHostCanonical([executable fileSystemRepresentation]);
    if (!actualPath || ![actualPath isEqual:signedPath]) return nil;
    // Re-query the exact audit identity after the PID-addressed path lookup.
    // A recycled PID cannot supply a path for a now-absent original guest.
    SecCodeRef fresh = NULL;
    NSData *audit = [NSData dataWithBytes:&token length:sizeof token];
    if (LWHostGuest(audit, &fresh) != errSecSuccess || !fresh) return nil;
    status = SecCodeCheckValidity(fresh, kSecCSStrictValidate, NULL);
    CFRelease(fresh);
    if (status != errSecSuccess) return nil;
    return @{@"identifier": identifier, @"team": team, @"path": actualPath};
}

@interface LWProviderHostIdentity () {
    SecRequirementRef _requirement, _appleRequirement;
}
@end

@implementation LWProviderHostIdentity
- (instancetype)initWithOriginalAuditToken:(NSData *)audit expectedHelperTeam:(NSString *)team {
    audit_token_t token;
    if (!LWHostAudit(audit, &token) || !LWHostString(team, 128)) return nil;
    SecCodeRef guest = NULL;
    if (LWHostGuest(audit, &guest) != errSecSuccess || !guest) return nil;
    SecRequirementRef apple = NULL, requirement = NULL;
    SecStaticCodeRef code = NULL;
    NSDictionary *metadata = nil;
    @try {
        // Require an Apple-rooted signed host as well as its own requirement.
        // A self-signed certificate with a copied OU is not this authority.
        if (SecRequirementCreateWithString(CFSTR("anchor apple generic"), kSecCSDefaultFlags, &apple) != errSecSuccess || !apple ||
            SecCodeCheckValidity(guest, kSecCSStrictValidate, apple) != errSecSuccess) return nil;
        metadata = LWHostMetadata(guest, token);
        if (!metadata || ![metadata[@"team"] isEqual:team] ||
            SecCodeCopyStaticCode(guest, kSecCSDefaultFlags, &code) != errSecSuccess || !code ||
            SecCodeCopyDesignatedRequirement(code, kSecCSDefaultFlags, &requirement) != errSecSuccess || !requirement ||
            SecCodeCheckValidity(guest, kSecCSStrictValidate, requirement) != errSecSuccess) return nil;
        if ((self = [super init])) {
            _originalAuditToken = [audit copy]; _signingIdentifier = [metadata[@"identifier"] copy];
            _teamIdentifier = [metadata[@"team"] copy]; _executablePath = [metadata[@"path"] copy];
            _requirement = requirement; requirement = NULL;
            _appleRequirement = apple; apple = NULL;
        }
        return self;
    } @finally {
        if (code) CFRelease(code);
        if (requirement) CFRelease(requirement);
        if (apple) CFRelease(apple);
        CFRelease(guest);
    }
}
- (void)dealloc {
    if (_requirement) CFRelease(_requirement);
    if (_appleRequirement) CFRelease(_appleRequirement);
}
- (BOOL)qualifiesReplacementAuditToken:(NSData *)audit {
    audit_token_t token;
    if (!LWHostAudit(audit, &token) || !_requirement || !_appleRequirement) return NO;
    SecCodeRef guest = NULL;
    if (LWHostGuest(audit, &guest) != errSecSuccess || !guest) return NO;
    @try {
        // An original host may have an explicitly broad designated requirement.
        // Preserve the independently checked Apple provenance on every peer.
        if (SecCodeCheckValidity(guest, kSecCSStrictValidate, _appleRequirement) != errSecSuccess ||
            SecCodeCheckValidity(guest, kSecCSStrictValidate, _requirement) != errSecSuccess) return NO;
        NSDictionary *metadata = LWHostMetadata(guest, token);
        return metadata && [metadata[@"identifier"] isEqual:_signingIdentifier] &&
            [metadata[@"team"] isEqual:_teamIdentifier] && [metadata[@"path"] isEqual:_executablePath];
    } @finally { CFRelease(guest); }
}
+ (LWProviderHostPresence)presenceOfAuditToken:(NSData *)audit {
    audit_token_t token;
    if (!LWHostAudit(audit, &token)) return LWProviderHostPresenceUnverified;
    pid_t pid = audit_token_to_pid(token);
    mach_port_name_t name = MACH_PORT_NULL;
    kern_return_t lookup = task_name_for_pid(mach_task_self(), pid, &name);
    if (lookup == KERN_SUCCESS && name != MACH_PORT_NULL) {
        audit_token_t current = {0}; mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
        kern_return_t status = task_info(name, TASK_AUDIT_TOKEN, (task_info_t)&current, &count);
        mach_port_deallocate(mach_task_self(), name);
        if (status == KERN_SUCCESS && count == TASK_AUDIT_TOKEN_COUNT && audit_token_to_pid(current) == pid) {
            // Principal/session changes do not make a live owner dead. Only a
            // different kernel PID version proves the original process ended.
            return audit_token_to_pidversion(current) == audit_token_to_pidversion(token)
                ? LWProviderHostPresent : LWProviderHostAbsent;
        }
    } else if (name != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), name);
    struct proc_bsdinfo info = {0}; errno = 0;
    int bytes = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof info), error = errno;
    if (bytes == 0 && error == ESRCH) {
        // SIG0 is a non-mutating existence check. A permission denial or a
        // newly visible recycled PID cannot become an absence assertion.
        errno = 0;
        if (kill(pid, 0) == -1 && errno == ESRCH) return LWProviderHostAbsent;
    }
    return LWProviderHostPresenceUnverified;
}
@end
