#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Private, create-only records. The directory must already be owned by this
/// user with mode 0700. An uncertain write is retained and never overwritten.
@interface LWProviderJournal : NSObject
- (nullable instancetype)initWithDirectory:(NSString *)directory NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;
- (BOOL)writeOnceID:(NSString *)onceID stage:(NSString *)stage record:(NSDictionary *)record;
- (nullable NSData *)readOnceID:(NSString *)onceID stage:(NSString *)stage;
@end

NS_ASSUME_NONNULL_END
