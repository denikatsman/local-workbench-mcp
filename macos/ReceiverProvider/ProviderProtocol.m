#import "ProviderProtocol.h"
#import <bsm/audit.h>
#import <sys/socket.h>
#import <sys/un.h>
#import <sys/stat.h>
#import <fcntl.h>
#import <poll.h>
#import <unistd.h>
#import <math.h>
#import <errno.h>
#import <limits.h>
#import <xlocale.h>

const NSUInteger LWProviderMaximumFrameBytes = 262144;
NSString *const LWProviderProtocolErrorDomain = @"LocalWorkbench.ProviderProtocol";
static NSError *LWError(NSString *code) {
    return [NSError errorWithDomain:LWProviderProtocolErrorDomain code:1
                          userInfo:@{NSLocalizedDescriptionKey:code}];
}
static double LWNow(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return NAN;
    return (double)t.tv_sec + (double)t.tv_nsec / 1000000000.0;
}
static BOOL LWUUID(NSString *s) {
    return [s isKindOfClass:NSString.class] && s.length == 36 &&
        [[NSUUID alloc] initWithUUIDString:s] != nil;
}
static BOOL LWExactInteger(id value, long long expected) {
    return [value isKindOfClass:NSNumber.class] &&
        CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID() &&
        !CFNumberIsFloatType((__bridge CFNumberRef)value) && [value longLongValue] == expected;
}
static BOOL LWEqualSecret(NSString *a, NSString *b) {
    NSData *x = [a dataUsingEncoding:NSUTF8StringEncoding], *y = [b dataUsingEncoding:NSUTF8StringEncoding];
    if (x.length != 64 || y.length != 64) return NO;
    const uint8_t *p = x.bytes, *q = y.bytes; uint8_t difference = 0;
    for (NSUInteger i = 0; i < 64; i++) difference |= p[i] ^ q[i];
    return difference == 0;
}

@interface LWJSONParser : NSObject
@property(nonatomic, strong) NSData *data;
@property(nonatomic) NSUInteger position, values;
@property(nonatomic, copy) NSString *failure;
- (id)parseValue:(NSUInteger)depth;
@end
@implementation LWJSONParser
- (uint8_t)peek { return _position < _data.length ? ((const uint8_t *)_data.bytes)[_position] : 0; }
- (void)space {
    while (_position < _data.length) {
        uint8_t c = [self peek];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        _position++;
    }
}
- (id)fail:(NSString *)code { if (!_failure) _failure = code; return nil; }
- (BOOL)hexUnit:(uint32_t *)value {
    if (_data.length - _position < 4) return NO;
    uint32_t unit = 0;
    for (NSUInteger i = 0; i < 4; i++) {
        uint8_t c = [self peek]; _position++;
        int nibble = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 :
            c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (nibble < 0) return NO;
        unit = (unit << 4) | (uint32_t)nibble;
    }
    *value = unit; return YES;
}
- (NSString *)string {
    if ([self peek] != '"') return [self fail:@"json_string_expected"];
    _position++;
    NSMutableData *decoded = [NSMutableData data];
    BOOL closed = NO;
    while (_position < _data.length) {
        uint8_t c = [self peek]; _position++;
        if (c == '"') { closed = YES; break; }
        if (c < 0x20) return [self fail:@"json_unescaped_control"];
        if (c != '\\') [decoded appendBytes:&c length:1];
        else {
            if (_position == _data.length) return [self fail:@"json_escape_truncated"];
            c = [self peek]; _position++;
            if (c == '"' || c == '\\' || c == '/') [decoded appendBytes:&c length:1];
            else if (c == 'b' || c == 'f' || c == 'n' || c == 'r' || c == 't') {
                uint8_t mapped = c == 'b' ? 8 : c == 'f' ? 12 : c == 'n' ? 10 : c == 'r' ? 13 : 9;
                [decoded appendBytes:&mapped length:1];
            } else if (c == 'u') {
                uint32_t scalar = 0;
                if (![self hexUnit:&scalar]) return [self fail:@"json_unicode_escape_invalid"];
                if (scalar >= 0xd800 && scalar <= 0xdbff) {
                    if (_data.length - _position < 6 || [self peek] != '\\') return [self fail:@"json_surrogate_invalid"];
                    _position++; if ([self peek] != 'u') return [self fail:@"json_surrogate_invalid"]; _position++;
                    uint32_t low = 0;
                    if (![self hexUnit:&low] || low < 0xdc00 || low > 0xdfff) return [self fail:@"json_surrogate_invalid"];
                    scalar = 0x10000 + ((scalar - 0xd800) << 10) + low - 0xdc00;
                } else if (scalar >= 0xdc00 && scalar <= 0xdfff) return [self fail:@"json_surrogate_invalid"];
                uint8_t encoded[4]; NSUInteger count;
                if (scalar < 0x80) { encoded[0] = (uint8_t)scalar; count = 1; }
                else if (scalar < 0x800) {
                    encoded[0] = 0xc0 | (scalar >> 6); encoded[1] = 0x80 | (scalar & 63); count = 2;
                } else if (scalar < 0x10000) {
                    encoded[0] = 0xe0 | (scalar >> 12); encoded[1] = 0x80 | ((scalar >> 6) & 63);
                    encoded[2] = 0x80 | (scalar & 63); count = 3;
                } else {
                    encoded[0] = 0xf0 | (scalar >> 18); encoded[1] = 0x80 | ((scalar >> 12) & 63);
                    encoded[2] = 0x80 | ((scalar >> 6) & 63); encoded[3] = 0x80 | (scalar & 63); count = 4;
                }
                [decoded appendBytes:encoded length:count];
            } else return [self fail:@"json_escape_invalid"];
        }
        if (decoded.length > 65536) return [self fail:@"json_string_limit"];
    }
    if (!closed) return [self fail:@"json_string_truncated"];
    NSString *string = [[NSString alloc] initWithData:decoded encoding:NSUTF8StringEncoding];
    return string ?: [self fail:@"json_utf8_invalid"];
}
- (id)number {
    NSUInteger start = _position;
    if ([self peek] == '-') _position++;
    uint8_t c = [self peek];
    if (c == '0') _position++;
    else if (c >= '1' && c <= '9') while ([self peek] >= '0' && [self peek] <= '9') _position++;
    else return [self fail:@"json_number_invalid"];
    BOOL floating = NO;
    if ([self peek] == '.') {
        floating = YES; _position++;
        if ([self peek] < '0' || [self peek] > '9') return [self fail:@"json_number_invalid"];
        while ([self peek] >= '0' && [self peek] <= '9') _position++;
    }
    if ([self peek] == 'e' || [self peek] == 'E') {
        floating = YES; _position++;
        if ([self peek] == '+' || [self peek] == '-') _position++;
        if ([self peek] < '0' || [self peek] > '9') return [self fail:@"json_number_invalid"];
        while ([self peek] >= '0' && [self peek] <= '9') _position++;
    }
    NSUInteger length = _position - start;
    if (length > 128) return [self fail:@"json_number_limit"];
    char buffer[129]; memcpy(buffer, (const uint8_t *)_data.bytes + start, length); buffer[length] = 0;
    char *end = NULL; errno = 0;
    if (!floating) {
        long long value = strtoll(buffer, &end, 10);
        if (errno || end != buffer + length) return [self fail:@"json_integer_range"];
        return @(value);
    }
    locale_t locale = newlocale(LC_NUMERIC_MASK, "C", NULL);
    if (!locale) return [self fail:@"json_number_locale_unavailable"];
    errno = 0;
    double value = strtod_l(buffer, &end, locale); int saved = errno; freelocale(locale);
    if (saved || end != buffer + length || !isfinite(value)) return [self fail:@"json_number_range"];
    return @(value);
}
- (id)parseValue:(NSUInteger)depth {
    [self space];
    if (depth > 32 || ++_values > 4096) return [self fail:@"json_structure_limit"];
    uint8_t c = [self peek];
    if (c == '"') return [self string];
    if (c == '-' || (c >= '0' && c <= '9')) return [self number];
    if (c == '{') {
        _position++; [self space]; NSMutableDictionary *object = [NSMutableDictionary dictionary];
        if ([self peek] == '}') { _position++; return [object copy]; }
        while (_position < _data.length) {
            if (object.count >= 256) return [self fail:@"json_object_limit"];
            NSString *key = [self string]; if (!key) return nil;
            if (object[key] != nil) return [self fail:@"json_duplicate_key"];
            [self space]; if ([self peek] != ':') return [self fail:@"json_colon_expected"];
            _position++; id value = [self parseValue:depth + 1]; if (!value) return nil;
            object[key] = value; [self space]; c = [self peek]; _position++;
            if (c == '}') return [object copy];
            if (c != ',') return [self fail:@"json_object_separator"];
            [self space];
        }
        return [self fail:@"json_object_truncated"];
    }
    if (c == '[') {
        _position++; [self space]; NSMutableArray *array = [NSMutableArray array];
        if ([self peek] == ']') { _position++; return [array copy]; }
        while (_position < _data.length) {
            id value = [self parseValue:depth + 1]; if (!value) return nil;
            [array addObject:value]; [self space]; c = [self peek]; _position++;
            if (c == ']') return [array copy];
            if (c != ',') return [self fail:@"json_array_separator"];
        }
        return [self fail:@"json_array_truncated"];
    }
    const char *literal = c == 't' ? "true" : c == 'f' ? "false" : c == 'n' ? "null" : NULL;
    if (!literal) return [self fail:@"json_value_invalid"];
    NSUInteger length = strlen(literal);
    if (_data.length - _position < length || memcmp((const uint8_t *)_data.bytes + _position, literal, length))
        return [self fail:@"json_literal_invalid"];
    _position += length;
    return c == 't' ? @YES : c == 'f' ? @NO : NSNull.null;
}
@end

id LWProviderDecodeJSON(NSData *data, NSError **error) {
    if (error) *error = nil;
    if (![data isKindOfClass:NSData.class] || !data.length || data.length > LWProviderMaximumFrameBytes) {
        if (error) *error = LWError(@"json_byte_limit"); return nil;
    }
    NSData *immutable = [data copy];
    if (![[NSString alloc] initWithData:immutable encoding:NSUTF8StringEncoding]) {
        if (error) *error = LWError(@"json_utf8_invalid"); return nil;
    }
    LWJSONParser *parser = [LWJSONParser new]; parser.data = immutable;
    @try {
        id value = [parser parseValue:0]; [parser space];
        if (!value || parser.position != immutable.length) {
            if (error) *error = LWError(parser.failure ?: @"json_trailing_data"); return nil;
        }
        return value;
    } @catch (NSException *exception) {
        if (error) *error = LWError(@"json_decoder_exception"); return nil;
    }
}

@implementation LWProviderConfiguration
- (instancetype)initWithSocketPath:(NSString *)path token:(NSString *)token session:(NSString *)session
                        generation:(NSString *)generation expectedHostAuditToken:(NSData *)audit requestTimeout:(NSTimeInterval)timeout {
    if (![path isKindOfClass:NSString.class] || ![token isKindOfClass:NSString.class] ||
        ![audit isKindOfClass:NSData.class]) return nil;
    NSData *pathBytes = [path dataUsingEncoding:NSUTF8StringEncoding]; uint8_t zero = 0;
    NSData *nul = [NSData dataWithBytes:&zero length:1];
    if (![path hasPrefix:@"/"] || !pathBytes.length || pathBytes.length >= 104 ||
        [pathBytes rangeOfData:nul options:0 range:NSMakeRange(0, pathBytes.length)].location != NSNotFound || token.length != 64 ||
        !LWUUID(session) || !LWUUID(generation) || audit.length != sizeof(audit_token_t) ||
        !isfinite(timeout) || timeout <= 0 || timeout > 10) return nil;
    for (NSUInteger i = 0; i < token.length; i++) {
        unichar c = [token characterAtIndex:i]; if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return nil;
    }
    if ((self = [super init])) {
        _socketPath = [path copy]; _token = [token copy]; _session = [session copy];
        _generation = [generation copy]; _expectedHostAuditToken = [audit copy]; _requestTimeout = timeout;
    }
    return self;
}
@end

@interface LWProviderRequestGuard () {
    NSLock *_guardLock;
    dispatch_semaphore_t _replyCancellationWake;
    BOOL _cancelled, _reserved, _executionStarted, _executionFinished;
}
@property(nonatomic, copy) NSString *activeRequestID;
@property(nonatomic) BOOL cancellationControl;
- (instancetype)initWithDeadline:(double)deadline;
- (BOOL)beginExecution;
- (void)finishExecution;
- (NSString *)cancelIfOutstanding;
- (void)wakeReplyOnCancellation:(dispatch_semaphore_t)wake;
@end
@implementation LWProviderRequestGuard
- (instancetype)initWithDeadline:(double)deadline {
    if ((self = [super init])) { _deadline = deadline; _guardLock = [NSLock new]; }
    return self;
}
- (BOOL)validLocked {
    double now = LWNow(); return !_cancelled && isfinite(now) && isfinite(_deadline) && now < _deadline;
}
- (BOOL)isValid { [_guardLock lock]; BOOL value = [self validLocked]; [_guardLock unlock]; return value; }
- (BOOL)effectReserved { [_guardLock lock]; BOOL value = _reserved; [_guardLock unlock]; return value; }
- (BOOL)beginExecution {
    [_guardLock lock]; BOOL value = !_executionStarted && [self validLocked];
    if (value) _executionStarted = YES; [_guardLock unlock]; return value;
}
- (void)finishExecution {
    [_guardLock lock]; _executionFinished = YES; [_guardLock unlock];
}
// The connection worker owns close(fd). Wake its existing reply wait rather
// than closing a potentially reused descriptor from Stop/control threads.
- (void)wakeReplyOnCancellation:(dispatch_semaphore_t)wake {
    [_guardLock lock]; _replyCancellationWake = wake;
    // Cancellation may win before the reply waiter is registered.
    if (_cancelled) dispatch_semaphore_signal(_replyCancellationWake);
    [_guardLock unlock];
}
- (NSString *)cancelIfOutstanding {
    [_guardLock lock];
    if (_executionFinished) { [_guardLock unlock]; return nil; }
    _cancelled = YES;
    if (_replyCancellationWake) dispatch_semaphore_signal(_replyCancellationWake);
    NSString *result = _reserved ? @"already_reserved_unknown" : @"cancelled_before_reservation";
    [_guardLock unlock]; return result;
}
- (BOOL)reserveEffect {
    [_guardLock lock]; BOOL value = _executionStarted && !_reserved && [self validLocked];
    if (value) _reserved = YES; [_guardLock unlock]; return value;
}
- (BOOL)constrainBeforeExecutionToDeadline:(NSTimeInterval)deadline {
    [_guardLock lock];
    BOOL allowed = !_executionStarted && isfinite(deadline) && deadline > 0;
    if (allowed) _deadline = fmin(_deadline, deadline);
    allowed = allowed && [self validLocked];
    [_guardLock unlock]; return allowed;
}
- (LWProviderCancellationDisposition)cancel {
    [_guardLock lock]; _cancelled = YES;
    if (_replyCancellationWake) dispatch_semaphore_signal(_replyCancellationWake);
    LWProviderCancellationDisposition result = _reserved ? LWProviderAlreadyReservedUnknown : LWProviderCancelledBeforeReservation;
    [_guardLock unlock]; return result;
}
@end

@interface LWProviderReply : NSObject
@property(nonatomic, strong) NSLock *lock;
@property(nonatomic, copy) NSDictionary *body;
@property(nonatomic, strong) dispatch_semaphore_t done;
@end
@implementation LWProviderReply @end

@interface LWProviderEndpoint () {
    NSLock *_stateLock;
    BOOL _running, _everStarted;
    int _listener;
    dev_t _socketDevice;
    ino_t _socketInode;
    dispatch_queue_t _acceptQueue, _workers, _handlerQueue;
    LWProviderHandler _handler;
    NSMutableDictionary<NSNumber *, LWProviderRequestGuard *> *_connections;
    NSMutableSet<NSString *> *_activeRequests;
    NSMutableSet<LWProviderRequestGuard *> *_handlerGuards;
    NSMutableDictionary<NSString *, NSNumber *> *_pendingCancellations;
    NSData *_currentHostAudit;
    NSString *_authorityEpoch;
    LWProviderHostReplacementPolicy _replacementPolicy;
    LWProviderRetireAuthority _retireAuthority;
}
@end

static BOOL LWWait(int fd, short events, LWProviderRequestGuard *guard) {
    while (guard.valid) {
        double remaining = guard.deadline - LWNow();
        if (!isfinite(remaining) || remaining <= 0) return NO;
        struct pollfd item = {fd, events, 0};
        int result = poll(&item, 1, (int)fmax(1, fmin(100, ceil(remaining * 1000))));
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return NO;
        if (result == 0) continue;
        if (item.revents & events) return YES;
        return NO;
    }
    return NO;
}

@implementation LWProviderEndpoint
- (instancetype)initWithConfiguration:(LWProviderConfiguration *)configuration handlerQueue:(dispatch_queue_t)queue
                               handler:(LWProviderHandler)handler {
    if (!configuration || !queue || !handler) return nil;
    if ((self = [super init])) {
        _configuration = configuration; _handlerQueue = queue; _handler = [handler copy];
        _currentHostAudit = [configuration.expectedHostAuditToken copy];
        _stateLock = [NSLock new]; _connections = [NSMutableDictionary dictionary]; _activeRequests = [NSMutableSet set];
        _handlerGuards = [NSMutableSet set]; _pendingCancellations = [NSMutableDictionary dictionary];
        _listener = -1; _acceptQueue = dispatch_queue_create("local-workbench.provider.accept", DISPATCH_QUEUE_SERIAL);
        _workers = dispatch_queue_create("local-workbench.provider.connections", DISPATCH_QUEUE_CONCURRENT);
    }
    return self;
}
- (BOOL)enableHostReplacementWithPolicy:(LWProviderHostReplacementPolicy)policy
                       retireAuthority:(LWProviderRetireAuthority)retire {
    [_stateLock lock];
    BOOL allowed = !_everStarted && !_replacementPolicy && policy && retire;
    if (allowed) {
        _replacementPolicy = [policy copy]; _retireAuthority = [retire copy];
        _authorityEpoch = NSUUID.UUID.UUIDString;
    }
    [_stateLock unlock]; return allowed;
}
- (NSDictionary *)hostAuthorityMetadata {
    [_stateLock lock];
    NSDictionary *result = _replacementPolicy ? @{@"host_rebind_version":@2,@"authority_epoch":_authorityEpoch} : @{};
    [_stateLock unlock]; return result;
}
// Called only on handlerQueue. Production uses the main serial queue so prior
// receiver effects finish before old bindings are retired. An already-current
// peer only reads status: a lost handover reply never repeats retirement.
- (BOOL)handoverPeer:(NSData *)peer guard:(LWProviderRequestGuard *)guard {
    [_stateLock lock];
    @try {
        if (!_running || !guard.valid || !_replacementPolicy) return NO;
        if ([_currentHostAudit isEqual:peer]) return YES;
        if (!_replacementPolicy(_currentHostAudit, peer) || !guard.valid) return NO;
        NSMutableSet *previous = [_handlerGuards mutableCopy];
        [previous addObjectsFromArray:_connections.allValues];
        for (LWProviderRequestGuard *old in previous) if (old != guard) [old cancel];
        for (NSNumber *fd in _connections) if (_connections[fd] != guard) shutdown(fd.intValue, SHUT_RDWR);
        [_pendingCancellations removeAllObjects];
        if (!_retireAuthority() || !guard.valid) return NO;
        _currentHostAudit = [peer copy]; _authorityEpoch = NSUUID.UUID.UUIDString;
        return YES;
    } @finally { [_stateLock unlock]; }
}
- (BOOL)start:(NSError **)error {
    if (error) *error = nil;
    [_stateLock lock];
    if (_everStarted) { [_stateLock unlock]; if (error) *error = LWError(@"endpoint_start_once_only"); return NO; }
    struct stat parent, existing;
    NSString *directory = _configuration.socketPath.stringByDeletingLastPathComponent;
    if (lstat(directory.fileSystemRepresentation, &parent) || !S_ISDIR(parent.st_mode) || parent.st_uid != geteuid() ||
        (parent.st_mode & 0022) || lstat(_configuration.socketPath.fileSystemRepresentation, &existing) == 0 || errno != ENOENT) {
        [_stateLock unlock]; if (error) *error = LWError(@"owned_socket_directory_or_new_path_required"); return NO;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0), noSignal = 1;
    if (fd < 0) { [_stateLock unlock]; if (error) *error = LWError(@"endpoint_socket_unavailable"); return NO; }
    struct sockaddr_un address = {0}; address.sun_family = AF_UNIX; address.sun_len = sizeof address;
    strlcpy(address.sun_path, _configuration.socketPath.fileSystemRepresentation, sizeof address.sun_path);
    int flags = fcntl(fd, F_GETFL, 0);
    BOOL bound = NO, ready = flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 &&
        fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 && setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, sizeof noSignal) == 0;
    if (ready) bound = bind(fd, (struct sockaddr *)&address, sizeof address) == 0;
    struct stat owned;
    ready = ready && bound && lstat(_configuration.socketPath.fileSystemRepresentation, &owned) == 0 &&
        S_ISSOCK(owned.st_mode) && owned.st_uid == geteuid();
    if (ready) { _socketDevice = owned.st_dev; _socketInode = owned.st_ino; }
    ready = ready && chmod(_configuration.socketPath.fileSystemRepresentation, 0600) == 0 && listen(fd, 8) == 0;
    if (!ready) {
        close(fd);
        if (bound && _socketInode && lstat(_configuration.socketPath.fileSystemRepresentation, &owned) == 0 &&
            owned.st_dev == _socketDevice && owned.st_ino == _socketInode && S_ISSOCK(owned.st_mode))
            unlink(_configuration.socketPath.fileSystemRepresentation);
        [_stateLock unlock]; if (error) *error = LWError(@"endpoint_bind_or_setup_failed"); return NO;
    }
    _listener = fd; _running = YES; _everStarted = YES; [_stateLock unlock];
    dispatch_async(_acceptQueue, ^{ @autoreleasepool { [self acceptLoop:fd]; } });
    return YES;
}
- (BOOL)running { [_stateLock lock]; BOOL running = _running; [_stateLock unlock]; return running; }
- (void)acceptLoop:(int)listener {
    while ([self running]) {
        struct pollfd item = {listener, POLLIN, 0}; int ready = poll(&item, 1, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) { if (ready < 0) break; continue; }
        if (!(item.revents & POLLIN)) break;
        int fd = accept(listener, NULL, NULL);
        if (fd < 0) { if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue; break; }
        double started = LWNow();
        audit_token_t peer; socklen_t length = sizeof peer;
        // This precedes read/recv. Replacement code qualification alone grants
        // only access to the bounded handover envelope, never task authority.
        if (!isfinite(started) || getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &peer, &length) != 0 ||
            length != sizeof peer) { close(fd); continue; }
        NSData *peerAudit = [NSData dataWithBytes:&peer length:sizeof peer];
        [_stateLock lock];
        BOOL currentPeer = [_currentHostAudit isEqual:peerAudit];
        NSData *owner = [_currentHostAudit copy]; LWProviderHostReplacementPolicy policy = _replacementPolicy;
        [_stateLock unlock];
        if (!currentPeer && (!policy || !policy(owner, peerAudit))) { close(fd); continue; }
        int flags = fcntl(fd, F_GETFL, 0), noSignal = 1;
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) || fcntl(fd, F_SETFD, FD_CLOEXEC) ||
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, sizeof noSignal)) { close(fd); continue; }
        LWProviderRequestGuard *guard = [[LWProviderRequestGuard alloc] initWithDeadline:started + _configuration.requestTimeout];
        [_stateLock lock];
        BOOL allowed = _running && _connections.count < 8;
        if (allowed) _connections[@(fd)] = guard;
        [_stateLock unlock];
        if (!allowed) { close(fd); continue; }
        dispatch_async(_workers, ^{ @autoreleasepool {
            @try { [self serve:fd guard:guard peer:peerAudit]; }
            @catch (NSException *exception) { /* Close without logging task data. */ }
            @finally {
                [guard cancel];
                [_stateLock lock]; [_connections removeObjectForKey:@(fd)];
                if (guard.activeRequestID) [_activeRequests removeObject:guard.activeRequestID];
                [_stateLock unlock]; close(fd);
            }
        } });
    }
    [_stateLock lock]; _running = NO; _listener = -1;
    for (NSNumber *number in _connections) {
        [_connections[number] cancel]; shutdown(number.intValue, SHUT_RDWR);
    }
    for (LWProviderRequestGuard *guard in _handlerGuards) [guard cancel];
    close(listener);
    struct stat current;
    if (lstat(_configuration.socketPath.fileSystemRepresentation, &current) == 0 && S_ISSOCK(current.st_mode) &&
        current.st_dev == _socketDevice && current.st_ino == _socketInode) unlink(_configuration.socketPath.fileSystemRepresentation);
    [_stateLock unlock];
}
- (NSDictionary *)envelope:(NSData *)frame {
    id value = LWProviderDecodeJSON(frame, NULL);
    if (![value isKindOfClass:NSDictionary.class]) return nil;
    NSDictionary *packet = value;
    NSSet *keys = [NSSet setWithArray:@[@"version", @"request_id", @"method", @"token", @"session", @"generation", @"payload", @"transport_clock", @"deadline_monotonic"]];
    NSSet *methods = [NSSet setWithArray:@[@"hello", @"observe", @"key_pair", @"key_chord", @"key_sequence", @"consume_plain_text", @"cancel", @"receipt", @"cancel_request", @"handover"]];
    if (![[NSSet setWithArray:packet.allKeys] isEqual:keys] || !LWExactInteger(packet[@"version"], 1) ||
        !LWUUID(packet[@"request_id"]) || ![methods containsObject:packet[@"method"]] ||
        ![packet[@"transport_clock"] isEqual:@"clock_monotonic_v1"] ||
        ![packet[@"deadline_monotonic"] isKindOfClass:NSNumber.class] ||
        CFGetTypeID((__bridge CFTypeRef)packet[@"deadline_monotonic"]) == CFBooleanGetTypeID() ||
        !isfinite([packet[@"deadline_monotonic"] doubleValue]) ||
        ![packet[@"payload"] isKindOfClass:NSDictionary.class] ||
        ![packet[@"session"] isEqual:_configuration.session] || ![packet[@"generation"] isEqual:_configuration.generation] ||
        ![packet[@"token"] isKindOfClass:NSString.class] || !LWEqualSecret(packet[@"token"], _configuration.token)) return nil;
    return packet;
}
- (void)prunePendingCancellationsLockedAt:(double)now {
    for (NSString *identifier in _pendingCancellations.allKeys) {
        double deadline = [_pendingCancellations[identifier] doubleValue];
        if (!isfinite(now) || !isfinite(deadline) || deadline <= now) [_pendingCancellations removeObjectForKey:identifier];
    }
}
- (NSDictionary *)cancelRequest:(NSDictionary *)payload guard:(LWProviderRequestGuard *)requestGuard {
    if (payload.count != 1 || !LWUUID(payload[@"target_request_id"]))
        return @{@"ok":@NO,@"error":@"cancel_request_payload_invalid"};
    NSString *identifier = [[NSUUID alloc] initWithUUIDString:payload[@"target_request_id"]].UUIDString;
    [_stateLock lock];
    @try {
        double now = LWNow();
        if (!_running || !requestGuard.valid || !isfinite(now)) return nil;
        [self prunePendingCancellationsLockedAt:now];
        NSMutableSet<LWProviderRequestGuard *> *guards = [_handlerGuards mutableCopy];
        [guards addObjectsFromArray:_connections.allValues];
        NSString *disposition = nil;
        for (LWProviderRequestGuard *guard in guards) {
            if (guard.cancellationControl || ![guard.activeRequestID isEqual:identifier]) continue;
            NSString *cancelled = [guard cancelIfOutstanding];
            if ([cancelled isEqual:@"already_reserved_unknown"] || !disposition) disposition = cancelled;
        }
        if (disposition) return @{@"ok":@YES,@"result":@{@"disposition":disposition,@"pending_cancellation":@NO}};
        // No live outstanding guard proves anything about prior effects. Keep
        // a bounded future-admission refusal, without replacing/evicting a live
        // cancellation or extending it through repeated control requests.
        BOOL pending = _pendingCancellations[identifier] != nil;
        if (!pending && _pendingCancellations.count < 64) {
            _pendingCancellations[identifier] = @(now + 10); pending = YES;
        }
        return @{@"ok":@YES,@"result":@{@"disposition":@"not_observed",@"pending_cancellation":@(pending)}};
    } @finally { [_stateLock unlock]; }
}
- (void)serve:(int)fd guard:(LWProviderRequestGuard *)guard peer:(NSData *)peer {
    NSMutableData *frame = [NSMutableData data]; BOOL complete = NO, eof = NO;
    while (LWWait(fd, POLLIN, guard)) {
        if (!complete && frame.length >= LWProviderMaximumFrameBytes) break;
        uint8_t buffer[8192];
        NSUInteger capacity = complete ? 1 : MIN(sizeof buffer, LWProviderMaximumFrameBytes - frame.length);
        ssize_t count = read(fd, buffer, capacity);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (count == 0) { eof = YES; break; }
        if (count < 0) break;
        // After the delimiter only EOF is permitted, including across reads.
        if (complete) { [guard cancel]; return; }
        [frame appendBytes:buffer length:(NSUInteger)count];
        const uint8_t *bytes = frame.bytes; NSUInteger newlines = 0;
        for (NSUInteger i = 0; i < frame.length; i++) if (bytes[i] == '\n') newlines++;
        if (newlines) {
            complete = newlines == 1 && bytes[frame.length - 1] == '\n';
            if (!complete) { [guard cancel]; return; }
        }
    }
    if (!complete || !eof || !guard.valid) { [guard cancel]; return; }
    NSDictionary *packet = [self envelope:[frame subdataWithRange:NSMakeRange(0, frame.length - 1)]];
    if (!packet || ![guard constrainBeforeExecutionToDeadline:[packet[@"deadline_monotonic"] doubleValue]]) { [guard cancel]; return; }
    BOOL handover = [packet[@"method"] isEqual:@"handover"];
    [_stateLock lock];
    BOOL authorized = handover ? (_replacementPolicy != nil && [packet[@"payload"] count] == 0) : [_currentHostAudit isEqual:peer];
    [_stateLock unlock];
    if (!authorized) { [guard cancel]; return; }
    NSString *requestID = packet[@"request_id"], *canonical = [[NSUUID alloc] initWithUUIDString:requestID].UUIDString;
    [_stateLock lock]; BOOL accepted = _running && _activeRequests.count < 8 && ![_activeRequests containsObject:canonical];
    if (accepted) {
        [_activeRequests addObject:canonical]; guard.activeRequestID = canonical;
        guard.cancellationControl = [packet[@"method"] isEqual:@"cancel_request"];
        [self prunePendingCancellationsLockedAt:LWNow()];
        if (!guard.cancellationControl && _pendingCancellations[canonical]) [guard cancel];
    }
    [_stateLock unlock];
    NSDictionary *body;
    if (!accepted) body = @{@"ok":@NO, @"error":@"active_request_id_refused"};
    else if (guard.cancellationControl) body = [self cancelRequest:packet[@"payload"] guard:guard];
    else {
        [_stateLock lock]; BOOL scheduled = _running && guard.valid && _handlerGuards.count < 8;
        if (scheduled) [_handlerGuards addObject:guard]; [_stateLock unlock];
        if (!scheduled) body = @{@"ok":@NO, @"error":@"handler_queue_capacity_or_stopped"};
        else {
        LWProviderReply *reply = [LWProviderReply new]; reply.lock = [NSLock new]; reply.done = dispatch_semaphore_create(0);
        [guard wakeReplyOnCancellation:reply.done];
        LWProviderHandler handler = _handler;
        dispatch_async(_handlerQueue, ^{ @autoreleasepool {
            NSDictionary *answer = nil;
            // Serialize beginning execution with stop, which holds this same
            // lock while cancelling connection and queued/in-flight guards.
            [_stateLock lock]; BOOL execute = _running && (handover || [_currentHostAudit isEqual:peer]) && [guard beginExecution]; [_stateLock unlock];
            if (execute) {
                @try {
                    NSDictionary *result;
                    if (handover && ![self handoverPeer:peer guard:guard]) result = @{@"ready":@NO,@"reason":@"host_handover_refused"};
                    else result = handler(handover ? @"hello" : packet[@"method"], packet[@"payload"], requestID, guard);
                    answer = [result isKindOfClass:NSDictionary.class] ? @{@"ok":@YES, @"result":[result copy]} :
                        @{@"ok":@NO, @"error":@"handler_result_invalid"};
                } @catch (NSException *exception) { answer = @{@"ok":@NO, @"error":@"handler_exception_outcome_unknown"}; }
            } else answer = @{@"ok":@NO, @"error":@"request_expired_or_cancelled_before_execution"};
            [guard finishExecution];
            [reply.lock lock]; reply.body = answer; [reply.lock unlock]; dispatch_semaphore_signal(reply.done);
            [_stateLock lock]; [_handlerGuards removeObject:guard]; [_stateLock unlock];
        } });
        double remaining = guard.deadline - LWNow();
        if (!isfinite(remaining) || remaining <= 0 ||
            dispatch_semaphore_wait(reply.done, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(remaining * NSEC_PER_SEC))) != 0 ||
            !guard.valid) { [guard cancel]; return; }
        [reply.lock lock]; body = reply.body; [reply.lock unlock];
        }
    }
    if (!guard.valid || !body) { [guard cancel]; return; }
    NSMutableDictionary *response = [body mutableCopy];
    response[@"version"] = @1; response[@"request_id"] = requestID;
    response[@"session"] = _configuration.session; response[@"generation"] = _configuration.generation;
    NSData *encoded = nil;
    @try { encoded = [NSJSONSerialization dataWithJSONObject:response options:NSJSONWritingSortedKeys error:NULL]; }
    @catch (NSException *exception) {}
    if (!encoded || encoded.length >= LWProviderMaximumFrameBytes || !LWProviderDecodeJSON(encoded, NULL)) { [guard cancel]; return; }
    NSMutableData *output = [encoded mutableCopy]; uint8_t newline = '\n'; [output appendBytes:&newline length:1];
    NSUInteger sent = 0;
    while (sent < output.length && LWWait(fd, POLLOUT, guard)) {
        ssize_t count = write(fd, (const uint8_t *)output.bytes + sent, output.length - sent);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (count <= 0) break; sent += (NSUInteger)count;
    }
    [guard cancel];
}
- (NSDictionary *)stop {
    [_stateLock lock]; _running = NO; NSUInteger reserved = 0, cancelled = 0;
    [_pendingCancellations removeAllObjects];
    NSMutableSet *allGuards = [_handlerGuards mutableCopy]; [allGuards addObjectsFromArray:_connections.allValues];
    for (LWProviderRequestGuard *guard in allGuards) {
        if ([guard cancel] == LWProviderAlreadyReservedUnknown) reserved++; else cancelled++;
    }
    for (NSNumber *number in _connections) {
        shutdown(number.intValue, SHUT_RDWR);
    }
    if (_listener >= 0) shutdown(_listener, SHUT_RDWR);
    [_stateLock unlock];
    return @{ @"cancelled_before_reservation":@(cancelled), @"already_reserved_unknown":@(reserved),
              @"contract":@"reserved_or_missing_terminal_effect_outcomes_remain_unknown_never_replay" };
}
@end
