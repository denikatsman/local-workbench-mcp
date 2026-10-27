#import <AppKit/AppKit.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, LWReceiverPhase) {
    LWReceiverPhaseObserve,
    LWReceiverPhasePreflight,
    LWReceiverPhaseReserveEffect,
    LWReceiverPhaseReadback,
    /// Recheck original authority/cancellation/contention; never reserve again.
    LWReceiverPhaseSequenceStep,
};

/// Trusted, local host policy. Never construct this from remote class names.
/// Exact local classes; subclasses are not implicitly admitted. Only the
/// opt-in custom policies permit authenticated canonical Foundation KVO wrappers.
@interface LWReceiverPolicy : NSObject
@property(nonatomic, readonly, copy) NSSet<Class> *exactReceiverClasses;
@property(nonatomic, readonly, copy) NSSet<Class> *exactKeyOnlyReceiverClasses;
@property(nonatomic, readonly, copy) NSSet<Class> *exactKeyOnlyWindowClasses;
@property(nonatomic, readonly, copy) NSSet<Class> *exactTextClientReceiverClasses;
@property(nonatomic, readonly, copy) NSSet<Class> *exactTextClientWindowClasses;
@property(nonatomic, readonly, copy) NSSet<Class> *exactTextClientDocumentClasses;
@property(nonatomic, readonly) BOOL allowTextClientInputContextKeys;
@property(nonatomic, readonly) BOOL allowTextClientInputContextShift;
@property(nonatomic, readonly) BOOL allowTextClientInputContextControlOption;
@property(nonatomic, readonly) BOOL allowTextClientInputContextReceiverKeyUp;
- (BOOL)admitsInputContextModifiers:(NSArray *)modifiers;
@property(nonatomic, readonly) NSUInteger maximumTextUTF16Units;
@property(nonatomic, readonly) NSUInteger maximumInputUTF16Units;
@property(nonatomic, readonly) NSTimeInterval bindingLifetime;
- (nullable instancetype)initWithExactReceiverClasses:(NSSet<Class> *)classes
                                maximumTextUTF16Units:(NSUInteger)textLimit
                               maximumInputUTF16Units:(NSUInteger)inputLimit
                                      bindingLifetime:(NSTimeInterval)lifetime;
/// Opt-in key-only custom NSView classes and exact custom NSWindow classes.
/// Empty sets preserve the typed-text-only policy. Both sets must be supplied
/// together; broad framework base classes and text/secure classes are refused.
- (nullable instancetype)initWithExactReceiverClasses:(NSSet<Class> *)classes
                         exactKeyOnlyReceiverClasses:(NSSet<Class> *)keyClasses
                           exactKeyOnlyWindowClasses:(NSSet<Class> *)windowClasses
                                maximumTextUTF16Units:(NSUInteger)textLimit
                               maximumInputUTF16Units:(NSUInteger)inputLimit
                                      bindingLifetime:(NSTimeInterval)lifetime;
/// Separate locally audited document text-client route, literal insertion only.
/// Exact classes or authenticated Foundation KVO wrappers; never remote names.
/// All three text-client sets must be supplied together. NSWindow is permitted
/// here; key-only restrictions remain unchanged. Document getters must provide
/// path/identifier/isLoaded/isLoading; receiver also provides selectionString.
- (nullable instancetype)initWithExactReceiverClasses:(NSSet<Class> *)classes
                         exactKeyOnlyReceiverClasses:(NSSet<Class> *)keyClasses
                           exactKeyOnlyWindowClasses:(NSSet<Class> *)windowClasses
                      exactTextClientReceiverClasses:(NSSet<Class> *)textClasses
                        exactTextClientWindowClasses:(NSSet<Class> *)textWindows
                      exactTextClientDocumentClasses:(NSSet<Class> *)documents
                                maximumTextUTF16Units:(NSUInteger)textLimit
                               maximumInputUTF16Units:(NSUInteger)inputLimit
                                      bindingLifetime:(NSTimeInterval)lifetime;
/// Explicit local opt-in for audited exact per-view inputContext key pairs.
/// Requires all three text-client sets; existing constructors default to NO.
/// No context activation, vendor keyDown/keyUp, shortcuts or IME guarantee.
- (nullable instancetype)initWithExactReceiverClasses:(NSSet<Class> *)classes
                         exactKeyOnlyReceiverClasses:(NSSet<Class> *)keyClasses
                           exactKeyOnlyWindowClasses:(NSSet<Class> *)windowClasses
                      exactTextClientReceiverClasses:(NSSet<Class> *)textClasses
                        exactTextClientWindowClasses:(NSSet<Class> *)textWindows
                      exactTextClientDocumentClasses:(NSSet<Class> *)documents
                     allowTextClientInputContextKeys:(BOOL)allowContextKeys
                                maximumTextUTF16Units:(NSUInteger)textLimit
                               maximumInputUTF16Units:(NSUInteger)inputLimit
                                      bindingLifetime:(NSTimeInterval)lifetime;
/// Separately negotiated Shift-only opt-in; requires the exact inputContext key policy.
- (nullable instancetype)initWithExactReceiverClasses:(NSSet<Class> *)classes
                         exactKeyOnlyReceiverClasses:(NSSet<Class> *)keyClasses
                           exactKeyOnlyWindowClasses:(NSSet<Class> *)windowClasses
                      exactTextClientReceiverClasses:(NSSet<Class> *)textClasses
                        exactTextClientWindowClasses:(NSSet<Class> *)textWindows
                      exactTextClientDocumentClasses:(NSSet<Class> *)documents
                     allowTextClientInputContextKeys:(BOOL)allowContextKeys
                    allowTextClientInputContextShift:(BOOL)allowShift
                                maximumTextUTF16Units:(NSUInteger)textLimit
                               maximumInputUTF16Units:(NSUInteger)inputLimit
                                      bindingLifetime:(NSTimeInterval)lifetime;
/// Separately negotiated single Shift/Control/Option context policy; requires keys and Shift.
- (nullable instancetype)initWithExactReceiverClasses:(NSSet<Class> *)classes
                         exactKeyOnlyReceiverClasses:(NSSet<Class> *)keyClasses
                           exactKeyOnlyWindowClasses:(NSSet<Class> *)windowClasses
                      exactTextClientReceiverClasses:(NSSet<Class> *)textClasses
                        exactTextClientWindowClasses:(NSSet<Class> *)textWindows
                      exactTextClientDocumentClasses:(NSSet<Class> *)documents
                     allowTextClientInputContextKeys:(BOOL)allowContextKeys
                    allowTextClientInputContextShift:(BOOL)allowShift
             allowTextClientInputContextControlOption:(BOOL)allowControlOption
                                maximumTextUTF16Units:(NSUInteger)textLimit
                               maximumInputUTF16Units:(NSUInteger)inputLimit
                                      bindingLifetime:(NSTimeInterval)lifetime;
/// Strict v8 opt-in: context handles only down; original authenticated receiver handles up in finally.
- (nullable instancetype)initWithExactReceiverClasses:(NSSet<Class> *)classes
                         exactKeyOnlyReceiverClasses:(NSSet<Class> *)keyClasses
                           exactKeyOnlyWindowClasses:(NSSet<Class> *)windowClasses
                      exactTextClientReceiverClasses:(NSSet<Class> *)textClasses
                        exactTextClientWindowClasses:(NSSet<Class> *)textWindows
                      exactTextClientDocumentClasses:(NSSet<Class> *)documents
                     allowTextClientInputContextKeys:(BOOL)allowContextKeys
                    allowTextClientInputContextShift:(BOOL)allowShift
             allowTextClientInputContextControlOption:(BOOL)allowControlOption
             allowTextClientInputContextReceiverKeyUp:(BOOL)allowReceiverKeyUp
                                maximumTextUTF16Units:(NSUInteger)textLimit
                               maximumInputUTF16Units:(NSUInteger)inputLimit
                                      bindingLifetime:(NSTimeInterval)lifetime NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;
@end

/// Called only on the main thread. The host checks admission, exact process
/// identity, cancellation and target contention at every phase. ReserveEffect
/// must atomically check those authorities and reserve the once_id under the
/// host's cancellation lock. Readback refusal prevents a subsequent text read.
typedef BOOL (^LWReceiverAuthorityCheck)(NSWindow *window, NSView *receiver,
                                        NSString *bindingID, NSString *onceID,
                                        LWReceiverPhase phase);
/// Durable, create-only journal. YES means the exact record is durably stored.
/// A refused/uncertain intent never dispatches. An intent without a durable
/// terminal result is UNKNOWN and must never be replayed, including on restart.
/// Records contain bounded metadata/hashes, never raw receiver text or payload.
typedef BOOL (^LWReceiverJournal)(NSString *onceID, NSString *stage, NSDictionary *record);
/// Production freshness and NSEvent timestamp clock: NSProcessInfo.systemUptime.
/// Tests may inject that clock's simulated values. This is not CLOCK_MONOTONIC;
/// transport deadlines use their own clock and must never be subtracted here.
/// NaN, infinity, backward movement and the original deadline fail closed.
typedef NSTimeInterval (^LWReceiverClock)(void);

/// In-process component, explicitly created and invoked by the admitted host.
/// All methods require the main thread; none schedule, focus, activate or hook.
/// A core retains at most 64 fresh bindings/results, without eviction/replay.
/// Create a new core only as part of the host's durable admission lifecycle.
@interface LWReceiverCore : NSObject
- (nullable instancetype)initWithPolicy:(LWReceiverPolicy *)policy
                        authorityCheck:(LWReceiverAuthorityCheck)authority
                               journal:(LWReceiverJournal)journal
                                 clock:(LWReceiverClock)clock NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

/// Supply an exact host-selected NSWindow. The current firstResponder must
/// qualify. Secure/unqualified/marked/oversize text is never copied or logged.
/// includeText is a local host disclosure decision; default host use is NO.
/// Successful output includes fresh opaque binding_id/once_id, original
/// observed_monotonic/deadline, receiver_kind, capabilities and metadata.
/// Typed receivers include copied text/selection SHA-256. Key-only receivers
/// never read or return text/selection, even when includeText is YES.
- (NSDictionary *)observeWindow:(NSWindow *)window includeText:(BOOL)includeText;

/// One pair, zero modifier flags, no repeat. The explicit hardware keyCode and
/// both literal character strings are separately supplied: no keyboard-layout
/// or physical-key mapping is inferred. Modifier keyCodes are refused.
/// One action total per binding (pair OR consume); retries return the identical
/// immutable terminal result, without repeating journal/dispatch.
/// Custom-view results report dispatched_unverified/unknown: returned events
/// and recipient metadata revalidation do not prove application completion.
- (NSDictionary *)performKeyPairWithBindingID:(NSString *)bindingID
                                      onceID:(NSString *)onceID
                                     keyCode:(unsigned short)keyCode
                                  characters:(NSString *)characters
                 charactersIgnoringModifiers:(NSString *)charactersIgnoringModifiers;

/// Historic selector; delegates to the locally negotiated single-modifier context route.
/// v6 admits Shift only; v7 admits one of Shift/Control/Option, never Command.
- (NSDictionary *)performShiftChordWithBindingID:(NSString *)bindingID
                                          onceID:(NSString *)onceID
                                         keyCode:(unsigned short)keyCode
                                      characters:(NSString *)characters
                     charactersIgnoringModifiers:(NSString *)charactersIgnoringModifiers
                                       modifiers:(NSArray<NSString *> *)modifiers;

/// Internal opt-in bounded sequence, only for the exact input-context route
/// with authenticated original-receiver keyUp. Descriptors have exactly
/// key_code, characters, characters_ignoring_modifiers, modifiers (empty or one
/// locally admitted modifier). All 2..8 descriptors freeze before callbacks.
/// One original binding/reservation/deadline; intermediate marks are permitted
/// only inside this call. SequenceStep must check original Stop/contention.
/// Ordered dispatch is not atomic text, causal attribution or OSIME proof.
- (NSDictionary *)performKeySequenceWithBindingID:(NSString *)bindingID
                                           onceID:(NSString *)onceID
                                             keys:(NSArray<NSDictionary *> *)keys;

/// Literal UTF-8 plain text only. Creates one uniquely named private pasteboard,
/// verifies its exact byte/type/generation lease, and invokes the retained
/// receiver's public typed consumer once. No system clipboard is accessed.
/// The audited exact OakTextView profile consumes that board through its pinned
/// readSelectionFromPasteboard: implementation. Other custom text clients retain
/// direct insertText:replacementRange: after the same lease/authority checks;
/// its void return is never presented as a BOOL. Key pairs require the separate local context opt-in.
/// Exact replacement readback and consumer BOOL are reported independently;
/// sanitation/other native behavior is reported as replacement mismatch.
- (NSDictionary *)consumePlainTextWithBindingID:(NSString *)bindingID
                                        onceID:(NSString *)onceID
                                          text:(NSString *)text;
@end

NS_ASSUME_NONNULL_END
