#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>

NS_ASSUME_NONNULL_BEGIN
FOUNDATION_EXPORT const NSUInteger LWProviderMaximumFrameBytes;
FOUNDATION_EXPORT NSString *const LWProviderProtocolErrorDomain;

/// Immutable Foundation values. Strict UTF-8/JSON, decoded duplicate keys,
/// finite representable numbers, depth <=32, <=256 entries per object,
/// <=4096 total values, and <=65536 decoded UTF-8 bytes per string.
/// Errors contain fixed codes only; never source bytes or decoded values.
FOUNDATION_EXPORT id _Nullable LWProviderDecodeJSON(NSData *data, NSError **error);

@interface LWProviderConfiguration : NSObject
@property(nonatomic, readonly, copy) NSString *socketPath, *token, *session, *generation;
@property(nonatomic, readonly, copy) NSData *expectedHostAuditToken;
@property(nonatomic, readonly) NSTimeInterval requestTimeout;
- (nullable instancetype)initWithSocketPath:(NSString *)socketPath
                                    token:(NSString *)token
                                  session:(NSString *)session
                               generation:(NSString *)generation
                   expectedHostAuditToken:(NSData *)auditToken
                           requestTimeout:(NSTimeInterval)timeout NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;
@end

typedef NS_ENUM(NSUInteger, LWProviderCancellationDisposition) {
    LWProviderCancelledBeforeReservation,
    LWProviderAlreadyReservedUnknown,
};

/// Original CLOCK_MONOTONIC deadline, shared by transport and handler.
/// reserveEffect atomically checks the deadline/cancel state and reserves once.
/// Host admission and ReceiverCore ReserveEffect must also qualify the target.
/// After reservation cancellation cannot certify that no effect occurred.
@interface LWProviderRequestGuard : NSObject
@property(nonatomic, readonly) NSTimeInterval deadline;
@property(nonatomic, readonly, getter=isValid) BOOL valid;
@property(nonatomic, readonly) BOOL effectReserved;
- (BOOL)reserveEffect;
/// Shortens the original transport deadline before handler admission; never
/// extends it. This carries the sender's same-clock budget across the socket.
- (BOOL)constrainBeforeExecutionToDeadline:(NSTimeInterval)deadline;
- (LWProviderCancellationDisposition)cancel;
@end

/// Synchronous handler on the supplied queue. The endpoint checks the guard
/// immediately before invocation. The handler must check guard.valid during
/// admission and call reserveEffect immediately before any effect; a queued
/// request that expires or is stopped is never passed to the handler.
/// Return an immutable, JSON-compatible dictionary; do not include secrets.
typedef NSDictionary * _Nullable (^LWProviderHandler)(NSString *method, NSDictionary *payload,
                                           NSString *requestID, LWProviderRequestGuard *guard);

/// Optional local policy, installed before start. Both tokens come from the
/// kernel, never a request body. Qualify the candidate and definitively absent
/// CURRENT owner, including after successive handovers. Runs without effects.
typedef BOOL (^LWProviderHostReplacementPolicy)(NSData *currentOwner, NSData *candidate);
/// Runs on handlerQueue after older handlers settle. Retires all old bindings
/// without rewriting original journals. NO must leave the endpoint unbound.
typedef BOOL (^LWProviderRetireAuthority)(void);

/// Explicit lifecycle; no constructor/bootstrap/loading/signing/AppKit calls.
/// New owned socket only (0600); existing paths are never removed/replaced.
/// <=8 concurrent connections and <=8 queued/in-flight handler blocks, including
/// wrappers retained after a connection timeout. One frame followed by peer
/// write-half EOF per connection, before scheduling the handler. The response
/// is one newline frame followed by endpoint close. Both EOFs share the original
/// request deadline; fragmented trailing records cannot be accepted.
/// Exact kernel LOCAL_PEERTOKEN is checked before reading any request data.
/// Concurrent duplicate request IDs are refused; released on connection close.
/// Durable action replay protection belongs to binding/once IDs and the host
/// journal, not transport correlation IDs. Never automatically resend a task.
/// Response: version/request_id/session/generation plus ok and result/error.
/// Transport timeout after handler start is unknown; never replay that action.
/// Internal authenticated method cancel_request takes exactly
/// {target_request_id:UUID}. It runs on a connection worker, never handlerQueue,
/// and cancels matching queued/in-flight guards under their reservation lock.
/// Its result has disposition cancelled_before_reservation,
/// already_reserved_unknown, or not_observed, plus pending_cancellation:Boolean.
/// Missing/finished IDs never certify no effect. At most 64 missing IDs remain
/// cancelled for 10 CLOCK_MONOTONIC seconds (repeat cancel never extends expiry),
/// independently of the cancellation exchange's shorter reply deadline. A
/// later authenticated envelope applies that cancellation before scheduling.
/// This is correlation cancellation, never durable action replay authority.
@interface LWProviderEndpoint : NSObject
@property(nonatomic, readonly, strong) LWProviderConfiguration *configuration;
- (instancetype)initWithConfiguration:(LWProviderConfiguration *)configuration
                          handlerQueue:(dispatch_queue_t)queue
                               handler:(LWProviderHandler)handler NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;
- (BOOL)start:(NSError **)error;
/// Opt-in only; existing exact-audit endpoints remain unchanged. Handover uses
/// a token-authenticated empty control envelope, never an input payload, and
/// cancels old transport guards before retiring bindings. Stop remains final.
- (BOOL)enableHostReplacementWithPolicy:(LWProviderHostReplacementPolicy)policy
                       retireAuthority:(LWProviderRetireAuthority)retire;
/// Empty for legacy endpoints; otherwise host_rebind_version and current
/// authority_epoch. No token, audit identity or socket is exposed.
- (NSDictionary *)hostAuthorityMetadata;
/// Cancels queued/in-flight guards and shuts down their sockets. Reserved
/// effects may already have started; the returned counts are not effect proof.
- (NSDictionary *)stop;
@end
NS_ASSUME_NONNULL_END
