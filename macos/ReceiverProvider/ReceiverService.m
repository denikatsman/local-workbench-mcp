#import "ReceiverService.h"
#import <CommonCrypto/CommonDigest.h>

static NSDictionary *LWServiceFailure(NSString *reason) {
    return @{@"ready":@NO, @"outcome":@"not_dispatched", @"reason":reason,
             @"dispatch_attempted":@NO, @"effect_state":@"none"};
}
static BOOL LWServiceOwner(NSDictionary *owner) {
    NSArray *keys = @[@"claim_id", @"owner_session", @"runtime_generation", @"target_generation", @"window_id"];
    if (![owner isKindOfClass:NSDictionary.class] || owner.count != keys.count) return NO;
    for (NSString *key in keys) {
        id value = owner[key];
        if (![value isKindOfClass:NSString.class] || ![value length] || [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 128) return NO;
    }
    return YES;
}
static BOOL LWServiceUUID(id value) {
    return [value isKindOfClass:NSString.class] && [[NSUUID alloc] initWithUUIDString:value] != nil;
}
static BOOL LWServiceNumber(id value, NSInteger minimum, NSInteger maximum) {
    if (![value isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID()) return NO;
    double d = [value doubleValue];
    return isfinite(d) && d >= minimum && d <= maximum && d == [value integerValue];
}

@interface LWServiceBinding : NSObject
@property(nonatomic, strong) LWReceiverCore *core;
@property(nonatomic, copy) NSDictionary *owner;
@property(nonatomic, copy) NSString *bindingID, *onceID;
@property(nonatomic) double deadline;
@property(nonatomic) BOOL sequence;
@property(nonatomic, strong) LWProviderRequestGuard *requestGuard;
@end
@implementation LWServiceBinding @end

@implementation LWReceiverService {
    LWReceiverPolicy *_policy;
    LWProviderJournal *_journal;
    NSWindow *(^_lookup)(NSInteger);
    LWReceiverClock _clock;
    NSMutableDictionary<NSString *, LWServiceBinding *> *_bindings;
}
- (instancetype)initWithPolicy:(LWReceiverPolicy *)policy journal:(LWProviderJournal *)journal
                  windowLookup:(NSWindow *(^)(NSInteger))lookup clock:(LWReceiverClock)clock {
    if (!NSThread.isMainThread || !policy || !journal || !lookup || !clock) return nil;
    if ((self = [super init])) {
        _policy = policy; _journal = journal; _lookup = [lookup copy]; _clock = [clock copy];
        _bindings = [NSMutableDictionary dictionary];
    }
    return self;
}
// Narrow factory seam for headless integration tests, not configurable via IPC.
- (LWReceiverCore *)coreWithAuthority:(LWReceiverAuthorityCheck)authority journal:(LWReceiverJournal)journal {
    return [[LWReceiverCore alloc] initWithPolicy:_policy authorityCheck:authority journal:journal clock:_clock];
}
- (NSUInteger)retireExpiredBindings {
    if (!NSThread.isMainThread) return 0;
    return [self retireExpiredAt:_clock()];
}
- (void)retireBinding:(LWServiceBinding *)binding {
    [binding.requestGuard cancel];
    binding.requestGuard = nil;
    // Dictionary access may autorelease a binding. Clear its core immediately
    // so a surrounding host pool cannot delay retirement of AppKit references.
    binding.core = nil;
    [_bindings removeObjectForKey:binding.bindingID];
}
- (NSUInteger)retireExpiredAt:(double)now {
    // An unavailable clock cannot certify that any retained binding is fresh.
    NSUInteger retired = 0;
    for (NSString *key in _bindings.allKeys) {
        LWServiceBinding *binding = _bindings[key];
        if (!isfinite(now) || !isfinite(binding.deadline) || binding.deadline <= now) {
            [self retireBinding:binding]; retired++;
        }
    }
    return retired;
}
- (NSUInteger)retireBindingsForOwner:(NSDictionary *)owner {
    if (!NSThread.isMainThread || !LWServiceOwner(owner)) return 0;
    NSUInteger retired = 0;
    for (NSString *key in _bindings.allKeys) {
        LWServiceBinding *binding = _bindings[key];
        if ([binding.owner isEqual:owner]) {
            [self retireBinding:binding]; retired++;
        }
    }
    return retired;
}
- (NSUInteger)retireAllBindings {
    if (!NSThread.isMainThread) return 0;
    NSUInteger retired = _bindings.count;
    // Iterate keys: an autoreleased allValues array would itself retain every
    // core/window/receiver until the embedding app next drains its pool.
    for (NSString *key in _bindings.allKeys) [self retireBinding:_bindings[key]];
    [_bindings removeAllObjects];
    return retired;
}
- (NSDictionary *)receipt:(NSDictionary *)payload {
    if (payload.count != 2 || !LWServiceOwner(payload[@"owner"]) || !LWServiceUUID(payload[@"once_id"]))
        return LWServiceFailure(@"receipt_binding_invalid");
    NSData *bytes = [_journal readOnceID:payload[@"once_id"] stage:@"result"];
    id decoded = bytes ? LWProviderDecodeJSON(bytes, NULL) : nil;
    NSDictionary *record = [decoded isKindOfClass:NSDictionary.class] ? decoded : nil;
    if (!record || ![record[@"owner"] isEqual:payload[@"owner"]] ||
        ![record[@"once_id"] isEqual:payload[@"once_id"]] || ![record[@"stage"] isEqual:@"result"] ||
        ![record[@"result"] isKindOfClass:NSDictionary.class])
        return @{@"ready":@NO, @"outcome":@"unknown_receipt", @"reason":@"original_receipt_unavailable_or_owner_mismatch",
                 @"effect_state":@"unknown", @"retry_allowed":@NO};
    NSMutableDictionary *result = [record[@"result"] mutableCopy];
    result[@"receipt_recovered"] = @YES;
    // Existence/readback alone does not recreate the historical flush result.
    result[@"receipt_read_verified"] = @YES;
    return [result copy];
}
- (NSDictionary *)handleMethod:(NSString *)method payload:(NSDictionary *)payload
                     requestID:(NSString *)requestID guard:(LWProviderRequestGuard *)guard {
    if (!NSThread.isMainThread || !guard.isValid) return LWServiceFailure(@"request_not_admitted");
    if ([method isEqual:@"receipt"]) return [self receipt:payload];
    if (![payload isKindOfClass:NSDictionary.class] || !LWServiceOwner(payload[@"owner"]))
        return LWServiceFailure(@"owner_binding_required");
    if ([method isEqual:@"observe"]) {
        NSSet *allowed = [NSSet setWithArray:@[@"owner", @"cg_window_id", @"include_text"]];
        if (![[NSSet setWithArray:payload.allKeys] isSubsetOfSet:allowed] ||
            !LWServiceNumber(payload[@"cg_window_id"], 1, INT32_MAX)) return LWServiceFailure(@"window_number_invalid");
        if (payload[@"include_text"] && CFGetTypeID((__bridge CFTypeRef)payload[@"include_text"]) != CFBooleanGetTypeID())
            return LWServiceFailure(@"text_disclosure_invalid");
        double now = _clock();
        if (!isfinite(now)) return LWServiceFailure(@"clock_unavailable");
        [self retireExpiredAt:now];
        if (_bindings.count >= 64) return LWServiceFailure(@"active_binding_limit");
        LWServiceBinding *binding = [LWServiceBinding new];
        // Freeze authority values; a caller cannot mutate a retained dictionary.
        NSData *ownerBytes = [NSJSONSerialization dataWithJSONObject:payload[@"owner"] options:0 error:NULL];
        binding.owner = LWProviderDecodeJSON(ownerBytes, NULL);
        binding.requestGuard = guard;
        LWProviderJournal *journal = _journal;
        __weak LWServiceBinding *weakBinding = binding;
        LWReceiverAuthorityCheck authority = ^BOOL(NSWindow *window, NSView *receiver, NSString *bindingID, NSString *onceID, LWReceiverPhase phase) {
            // ReceiverCore rechecks exact window/receiver affiliation. This
            // callback supplies request authority and its atomic reservation.
            (void)window; (void)receiver;
            LWServiceBinding *b = weakBinding;
            if (!b || !b.requestGuard.isValid) return NO;
            if (b.bindingID && (![b.bindingID isEqual:bindingID] || ![b.onceID isEqual:onceID])) return NO;
            return phase == LWReceiverPhaseReserveEffect ? [b.requestGuard reserveEffect] : YES;
        };
        LWReceiverJournal persist = ^BOOL(NSString *onceID, NSString *stage, NSDictionary *record) {
            LWServiceBinding *b = weakBinding;
            if (!b || ![b.onceID isEqual:onceID]) return NO;
            return [journal writeOnceID:onceID stage:stage record:@{@"owner":b.owner, @"once_id":onceID,
                @"binding_id":b.bindingID, @"stage":stage, @"result":record}];
        };
        binding.core = [self coreWithAuthority:authority journal:persist];
        NSWindow *window = _lookup([payload[@"cg_window_id"] integerValue]);
        NSDictionary *result = [binding.core observeWindow:window includeText:[payload[@"include_text"] boolValue]];
        if ([result[@"ready"] boolValue]) {
            if (!LWServiceUUID(result[@"binding_id"]) || !LWServiceUUID(result[@"once_id"]) ||
                ![result[@"deadline_monotonic"] isKindOfClass:NSNumber.class]) return LWServiceFailure(@"component_binding_invalid");
            binding.bindingID = result[@"binding_id"]; binding.onceID = result[@"once_id"];
            binding.deadline = [result[@"deadline_monotonic"] doubleValue]; binding.requestGuard = nil;
            binding.sequence = _policy.allowTextClientInputContextReceiverKeyUp &&
                [result[@"receiver_kind"] isEqual:@"custom_text_input_client"] &&
                [result[@"key_pair_route"] isEqual:@"exact_view_input_context"] &&
                [result[@"key_up_route"] isEqual:@"original_receiver_key_up"];
            if (binding.sequence) {
                NSMutableDictionary *advertised = [result mutableCopy];
                NSMutableDictionary *caps = [result[@"capabilities"] mutableCopy]; caps[@"key_sequence"] = @YES;
                advertised[@"capabilities"] = [caps copy]; advertised[@"key_sequence_version"] = @1;
                result = [advertised copy];
            }
            _bindings[binding.bindingID] = binding;
        }
        return result ?: LWServiceFailure(@"component_unavailable");
    }
    if (![@[@"key_pair", @"key_chord", @"key_sequence", @"consume_plain_text"] containsObject:method]) return LWServiceFailure(@"method_unavailable");
    LWServiceBinding *binding = LWServiceUUID(payload[@"binding_id"]) ? _bindings[payload[@"binding_id"]] : nil;
    if (!binding || ![binding.onceID isEqual:payload[@"once_id"]] || ![binding.owner isEqual:payload[@"owner"]])
        return LWServiceFailure(@"binding_expired_retired_or_owner_mismatch");
    BOOL key = [@[@"key_pair", @"key_chord"] containsObject:method];
    BOOL sequence = [method isEqual:@"key_sequence"];
    if (sequence && !binding.sequence) return LWServiceFailure(@"key_sequence_not_supported");
    BOOL chord = [method isEqual:@"key_chord"];
    if (chord && ![_policy admitsInputContextModifiers:payload[@"modifiers"]]) return LWServiceFailure(@"shift_input_context_chord_not_supported");
    NSSet *allowed = [NSSet setWithArray:key ?
        @[@"owner", @"binding_id", @"once_id", @"key_code", @"characters", @"characters_ignoring_modifiers"] :
        @[@"owner", @"binding_id", @"once_id", @"text"]];
    if (chord) allowed = [allowed setByAddingObject:@"modifiers"];
    if (sequence) allowed = [NSSet setWithArray:@[@"owner", @"binding_id", @"once_id", @"keys"]];
    if (![[NSSet setWithArray:payload.allKeys] isEqual:allowed]) return LWServiceFailure(@"action_fields_invalid");
    if (key && !LWServiceNumber(payload[@"key_code"], 0, 127)) return LWServiceFailure(@"key_code_invalid");
    binding.requestGuard = guard;
    NSDictionary *result;
    @try {
        result = sequence ? [binding.core performKeySequenceWithBindingID:binding.bindingID onceID:binding.onceID keys:payload[@"keys"]] : chord ? [binding.core performShiftChordWithBindingID:binding.bindingID onceID:binding.onceID
            keyCode:[payload[@"key_code"] unsignedShortValue] characters:payload[@"characters"]
            charactersIgnoringModifiers:payload[@"characters_ignoring_modifiers"] modifiers:payload[@"modifiers"]] : key ?
            [binding.core performKeyPairWithBindingID:binding.bindingID onceID:binding.onceID
                keyCode:[payload[@"key_code"] unsignedShortValue] characters:payload[@"characters"]
                charactersIgnoringModifiers:payload[@"characters_ignoring_modifiers"]] :
            [binding.core consumePlainTextWithBindingID:binding.bindingID onceID:binding.onceID text:payload[@"text"]];
    } @finally { binding.requestGuard = nil; }
    // Results are recoverable from the create-only journal. Retirement never
    // makes an old binding executable again, and frees retained AppKit objects.
    if ([result[@"receipt_durable"] boolValue]) [self retireBinding:binding];
    return result ?: LWServiceFailure(@"component_unavailable");
}
@end
