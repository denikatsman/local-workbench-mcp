#import "ProviderJournal.h"
#import "ProviderFileSecurity.h"
#import <sys/stat.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>

static const NSUInteger LWJournalLimit = 65536;
static NSString *LWJournalName(NSString *onceID, NSString *stage) {
    if (![onceID isKindOfClass:NSString.class] || ![[NSUUID alloc] initWithUUIDString:onceID] ||
        ![@[@"intent", @"result"] containsObject:stage]) return nil;
    return [NSString stringWithFormat:@"%@.%@.json", onceID.lowercaseString, stage];
}
static BOOL LWJournalOwnedFile(int fd, off_t size) {
    struct stat s;
    return fstat(fd, &s) == 0 && S_ISREG(s.st_mode) && s.st_uid == geteuid() &&
        (s.st_mode & 0777) == 0600 && s.st_nlink == 1 && s.st_size == size && LWProviderHasPrivateACL(fd);
}

@implementation LWProviderJournal {
    int _directory;
    NSLock *_lock;
}
- (instancetype)initWithDirectory:(NSString *)directory {
    if ((self = [super init])) {
        _directory = -1;
        if (![directory isKindOfClass:NSString.class] || !directory.isAbsolutePath ||
            directory.length > 4096 || [directory rangeOfCharacterFromSet:
                [NSCharacterSet characterSetWithRange:NSMakeRange(0, 1)]].location != NSNotFound) return nil;
        int fd = open(directory.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat s;
        if (fd < 0) return nil;
        if (fstat(fd, &s) != 0 || !S_ISDIR(s.st_mode) || s.st_uid != geteuid() ||
            (s.st_mode & 0777) != 0700 || !LWProviderHasPrivateACL(fd)) { close(fd); return nil; }
        _directory = fd; _lock = [NSLock new];
    }
    return self;
}
- (void)dealloc { if (_directory >= 0) close(_directory); }
- (BOOL)writeOnceID:(NSString *)onceID stage:(NSString *)stage record:(NSDictionary *)record {
    NSString *name = LWJournalName(onceID, stage);
    if (!name || ![record isKindOfClass:NSDictionary.class]) return NO;
    NSData *bytes;
    @try {
        if (![NSJSONSerialization isValidJSONObject:record]) return NO;
        bytes = [NSJSONSerialization dataWithJSONObject:record options:NSJSONWritingSortedKeys error:NULL];
    } @catch (NSException *exception) { return NO; }
    if (!bytes || !bytes.length || bytes.length > LWJournalLimit) return NO;
    [_lock lock];
    int fd = openat(_directory, name.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { [_lock unlock]; return NO; }
    if (!LWJournalOwnedFile(fd, 0)) { close(fd); [_lock unlock]; return NO; }
    BOOL success = NO;
    @try {
        const uint8_t *source = bytes.bytes;
        NSUInteger written = 0;
        while (written < bytes.length) {
            ssize_t n = write(fd, source + written, bytes.length - written);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return NO;
            written += (NSUInteger)n;
        }
        // Full file flush plus directory fsync. If either is unconfirmed the
        // immutable file remains for recovery; the caller must report unknown.
        success = LWJournalOwnedFile(fd, (off_t)bytes.length) &&
            fcntl(fd, F_FULLFSYNC) == 0 && fsync(_directory) == 0;
    } @finally { close(fd); [_lock unlock]; }
    return success;
}
- (NSData *)readOnceID:(NSString *)onceID stage:(NSString *)stage {
    NSString *name = LWJournalName(onceID, stage);
    if (!name) return nil;
    [_lock lock];
    int fd = openat(_directory, name.fileSystemRepresentation, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { [_lock unlock]; return nil; }
    NSData *result = nil;
    @try {
        struct stat before, after;
        if (fstat(fd, &before) != 0 || before.st_size <= 0 || before.st_size > (off_t)LWJournalLimit ||
            !LWJournalOwnedFile(fd, before.st_size)) return nil;
        NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)before.st_size];
        NSUInteger readBytes = 0;
        while (readBytes < data.length) {
            ssize_t n = read(fd, (uint8_t *)data.mutableBytes + readBytes, data.length - readBytes);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return nil;
            readBytes += (NSUInteger)n;
        }
        uint8_t extra;
        if (read(fd, &extra, 1) != 0 || fstat(fd, &after) != 0 ||
            before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
            before.st_size != after.st_size || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec ||
            before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec || !LWJournalOwnedFile(fd, after.st_size)) return nil;
        result = [data copy];
    } @finally { close(fd); [_lock unlock]; }
    return result;
}
@end
