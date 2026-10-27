#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, LWProviderHostPresence) {
    LWProviderHostPresent,
    LWProviderHostAbsent,
    LWProviderHostPresenceUnverified,
};

/// Captured from the original kernel-issued host identity while it is alive.
/// The policy qualifies code only. It does not replace endpoint authority,
/// accept a payload, retire bindings, or establish an input effect.
@interface LWProviderHostIdentity : NSObject
@property(nonatomic, readonly, copy) NSData *originalAuditToken;
@property(nonatomic, readonly, copy) NSString *signingIdentifier, *teamIdentifier, *executablePath;
- (nullable instancetype)initWithOriginalAuditToken:(NSData *)auditToken
                              expectedHelperTeam:(NSString *)team NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;
/// Candidate must have the same user, canonical path, identifier and Team, and
/// satisfy the original designated requirement. A compatible update's CDHash
/// may change. Pass the socket's actual LOCAL_PEERTOKEN, never payload bytes.
- (BOOL)qualifiesReplacementAuditToken:(NSData *)auditToken;
/// Public kernel audit lookup distinguishes the original process generation
/// from PID reuse. Definitive BSD plus signal-zero absence is a second route.
/// Signature/permission/partial lookup failures remain unverified. A stopped
/// or hung original process remains present and owns its endpoint.
+ (LWProviderHostPresence)presenceOfAuditToken:(NSData *)auditToken;
@end

NS_ASSUME_NONNULL_END
