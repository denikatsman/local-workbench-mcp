#import "ReceiverCore.h"
#import "ProviderJournal.h"
#import "ProviderProtocol.h"

NS_ASSUME_NONNULL_BEGIN

/// Admitted in-process service. Transport authenticates the signed host; that
/// host validates its task/claim and serializes Stop before sending commands.
/// No class policy or window lookup implementation is accepted from the wire.
@interface LWReceiverService : NSObject
- (nullable instancetype)initWithPolicy:(LWReceiverPolicy *)policy
                               journal:(LWProviderJournal *)journal
                          windowLookup:(NSWindow * _Nullable (^)(NSInteger))lookup
                                 clock:(LWReceiverClock)clock;
- (NSDictionary *)handleMethod:(NSString *)method payload:(NSDictionary *)payload
                     requestID:(NSString *)requestID guard:(LWProviderRequestGuard *)guard;
/// Main-thread lifecycle only. Retires retained AppKit references and cancels
/// any binding guard; create-only journal receipts are never removed/replayed.
- (NSUInteger)retireExpiredBindings;
- (NSUInteger)retireBindingsForOwner:(NSDictionary *)owner;
- (NSUInteger)retireAllBindings;
@end

NS_ASSUME_NONNULL_END
