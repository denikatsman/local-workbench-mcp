#import "ReceiverCore.h"
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <math.h>
#import <string.h>

static const NSUInteger LWTextHardLimit = 4096, LWByteHardLimit = 16384;
static const NSUInteger LWBindingLimit = 64, LWAncestorLimit = 64, LWWindowLimit = 1024;

static BOOL LWInherits(Class type, Class parent) {
    for (Class c = type; c; c = class_getSuperclass(c)) if (c == parent) return YES;
    return NO;
}
static BOOL LWSecure(id object) {
    Class c = object ? object_getClass(object) : Nil;
    return LWInherits(c, NSSecureTextField.class) || LWInherits(c, NSSecureTextFieldCell.class);
}
static BOOL LWSecureControl(id object) {
    return LWSecure(object) || (object && LWInherits(object_getClass(object), NSControl.class) &&
                              LWSecure([(NSControl *)object cell]));
}
static BOOL LWClassConforms(Class type, Protocol *protocol) {
    for (Class c = type; c; c = class_getSuperclass(c)) if (class_conformsToProtocol(c, protocol)) return YES;
    return NO;
}
static NSDictionary *LWImplementations(Class type, NSArray<NSString *> *selectors) {
    NSMutableDictionary *imps = [NSMutableDictionary dictionary];
    for (NSString *name in selectors) {
        SEL selector = NSSelectorFromString(name);
        if (!class_getInstanceMethod(type, selector)) return nil;
        IMP imp = class_getMethodImplementation(type, selector);
        if (!imp) return nil;
        imps[name] = [NSValue valueWithPointer:imp];
    }
    return [imps copy];
}
static NSArray<NSString *> *LWWindowGuardSelectors(void) {
    return @[@"firstResponder", @"windowNumber", @"isVisible", @"isKeyWindow", @"frame", @"attachedSheet", @"fieldEditor:forObject:"];
}
static BOOL LWFoundationImagePath(const char *path) {
    // dladdr uses the mapped system image identity, not a class name or an
    // app-supplied path. Private, relative and unavailable images fail closed.
    return path && !strcmp(path, "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation");
}
static BOOL LWFoundationClassReporter(IMP imp) {
    Dl_info info = {0};
    return imp && dladdr((const void *)imp, &info) && info.dli_fbase && LWFoundationImagePath(info.dli_fname);
}
static Class LWAdmittedClass(id object, NSSet<Class> *approved, NSArray<NSString *> *selectors) {
    Class runtime = object_getClass(object);
    if ([approved containsObject:runtime]) return runtime;
    // The only non-exact runtime admission is one Foundation KVO wrapper over
    // a locally exact class. Neither names nor reported class alone qualify it.
    Class base = class_getSuperclass(runtime);
    if (!base || ![approved containsObject:base]) return Nil;
    const char *name = class_getName(runtime), *baseName = class_getName(base);
    const char prefix[] = "NSKVONotifying_";
    if (!name || !baseName || strnlen(baseName, 257) > 256 ||
        strncmp(name, prefix, sizeof prefix - 1) || strcmp(name + sizeof prefix - 1, baseName)) return Nil;
    Method reporter = class_getInstanceMethod(runtime, @selector(class));
    IMP reportingIMP = reporter ? method_getImplementation(reporter) : NULL;
    if (reportingIMP == class_getMethodImplementation(base, @selector(class)) ||
        !LWFoundationClassReporter(reportingIMP) || [object class] != base) return Nil;
    NSDictionary *actual = LWImplementations(runtime, selectors);
    NSDictionary *expected = LWImplementations(base, selectors);
    return actual && expected && [actual isEqual:expected] ? base : Nil;
}
static Class LWAdmittedWindowClass(NSWindow *window, NSSet<Class> *approved) {
    return LWAdmittedClass(window, approved, LWWindowGuardSelectors());
}
@protocol LWDocumentTextIdentity <NSObject>
- (NSString *)path;
- (NSUUID *)identifier;
- (BOOL)isLoaded;
- (BOOL)isLoading;
@end
@protocol LWDocumentTextClient <NSTextInputClient>
- (id<LWDocumentTextIdentity>)document;
- (NSString *)selectionString;
@end
static NSArray<NSString *> *LWTextClientSelectors(BOOL receiverKeyUp) {
    NSArray *selectors=@[@"document", @"selectionString", @"selectedRange", @"hasMarkedText",
        @"attributedSubstringForProposedRange:actualRange:", @"insertText:replacementRange:",
        @"window", @"superview", @"frame", @"bounds", @"visibleRect", @"isHidden",
        @"isHiddenOrHasHiddenAncestor", @"conformsToProtocol:"];
    return receiverKeyUp ? [selectors arrayByAddingObject:@"keyUp:"] : selectors;
}
// The sole audited vendor text-client profile has a literal supplied-board
// NSServicesMenuRequestor endpoint. Other text clients retain insertText:.
static BOOL LWUsesPlainBoard(Class admitted) {
    return admitted && admitted == NSClassFromString(@"OakTextView") &&
        !strcmp(class_getName(admitted), "OakTextView");
}
static IMP LWPlainBoardIMP(id receiver, Class admitted) {
    if (!LWUsesPlainBoard(admitted)) return NULL;
    SEL selector = @selector(readSelectionFromPasteboard:);
    Method method = class_getInstanceMethod(admitted, selector);
    IMP imp = method ? method_getImplementation(method) : NULL;
    Method runtimeMethod = class_getInstanceMethod(object_getClass(receiver), selector);
    if (!imp || !runtimeMethod || method_getNumberOfArguments(method) != 3 ||
        strcmp(method_getTypeEncoding(runtimeMethod), method_getTypeEncoding(method)) ||
        method_getImplementation(runtimeMethod) != imp) return NULL;
    char *result = method_copyReturnType(method), *argument = method_copyArgumentType(method, 2);
    BOOL abi = result && argument && !strcmp(result, @encode(BOOL)) && !strcmp(argument, @encode(id));
    free(result); free(argument);
    Dl_info image = {0};
    const char *executable = NSBundle.mainBundle.executablePath.fileSystemRepresentation;
    return abi && executable && dladdr((const void *)imp, &image) && image.dli_fbase &&
        image.dli_fname && !strcmp(image.dli_fname, executable) ? imp : NULL;
}
static NSArray<NSString *> *LWDocumentSelectors(void) {
    return @[@"path", @"identifier", @"isLoaded", @"isLoading"];
}
static NSString *LWReceiverKind(BOOL keyOnly, BOOL textClient) {
    return keyOnly ? @"custom_view_key_only" : textClient ? @"custom_text_input_client" : @"typed_text_view";
}
static BOOL LWValidRect(NSRect r) {
    return isfinite(r.origin.x) && isfinite(r.origin.y) && isfinite(r.size.width) &&
        isfinite(r.size.height) && r.size.width > 0 && r.size.height > 0;
}
static NSArray *LWRect(NSRect r) {
    return @[@(r.origin.x), @(r.origin.y), @(r.size.width), @(r.size.height)];
}
static NSString *LWHash(NSData *data) {
    if (!data || data.length > LWByteHardLimit) return nil;
    unsigned char bytes[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, bytes);
    NSMutableString *hash = [NSMutableString stringWithCapacity:64];
    for (NSUInteger i = 0; i < sizeof bytes; i++) [hash appendFormat:@"%02x", bytes[i]];
    return [hash copy];
}
static NSData *LWBoundedUTF8(NSString *string, NSUInteger limit) {
    if (![string isKindOfClass:NSString.class] || string.length > limit ||
        [string lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > LWByteHardLimit) return nil;
    NSData *bytes = [string dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    return bytes.length <= LWByteHardLimit ? bytes : nil;
}
// Audited TextMate text::pos_t serializes 1-based line and UTF-8 byte
// column; virtual offsets use '+', columnar ranges 'x', multicarets '&'.
static NSString *LWTextPosition(NSString *text, NSUInteger utf16) {
    if (utf16 > text.length) return nil;
    NSData *prefix = LWBoundedUTF8([text substringToIndex:utf16], LWTextHardLimit);
    if (!prefix) return nil; // Also refuses a split UTF-16 surrogate.
    NSUInteger line = 1, column = 0; const uint8_t *bytes = prefix.bytes;
    for (NSUInteger i = 0; i < prefix.length; i++) {
        if (bytes[i] == '\n') { line++; column = 0; } else column++;
    }
    return column ? [NSString stringWithFormat:@"%lu:%lu", (unsigned long)line, (unsigned long)column + 1] :
        [NSString stringWithFormat:@"%lu", (unsigned long)line];
}
static BOOL LWPlainSelection(NSString *serialized, NSString *text, NSRange range) {
    if (!LWBoundedUTF8(serialized, 128) || !serialized.length || range.location == NSNotFound ||
        range.location > text.length || range.length > text.length - range.location) return NO;
    NSString *from = LWTextPosition(text, range.location), *to = LWTextPosition(text, NSMaxRange(range));
    if (!from || !to) return NO;
    if (!range.length) return [serialized isEqual:from];
    return [serialized isEqual:[NSString stringWithFormat:@"%@-%@", from, to]] ||
        [serialized isEqual:[NSString stringWithFormat:@"%@-%@", to, from]];
}
static BOOL LWClockValid(double observed, double deadline, double last, double now) {
    return isfinite(observed) && isfinite(deadline) && isfinite(last) && isfinite(now) &&
        observed >= 0 && deadline > observed && now >= last && now >= observed && now < deadline;
}
static BOOL LWKeyAllowed(unsigned short code) {
    return code <= 127 && !(code >= 54 && code <= 63);
}
static void LWStop(void) __attribute__((noreturn));
static void LWStop(void) {
    @throw [NSException exceptionWithName:@"LWReceiverGuardRefusal" reason:nil userInfo:nil];
}
static NSDictionary *LWRefusal(NSString *reason) {
    return @{@"ready":@NO, @"outcome":@"not_dispatched", @"reason":reason,
             @"dispatch_attempted":@NO, @"effect_state":@"none"};
}

@interface LWReceiverPolicy ()
@property(nonatomic,copy) NSDictionary<NSString *,NSValue *> *textClientKeyUpPolicyIMPs;
@end
@implementation LWReceiverPolicy
- (instancetype)initWithExactReceiverClasses:(NSSet<Class> *)classes
                         maximumTextUTF16Units:(NSUInteger)textLimit
                        maximumInputUTF16Units:(NSUInteger)inputLimit
                               bindingLifetime:(NSTimeInterval)lifetime {
    return [self initWithExactReceiverClasses:classes exactKeyOnlyReceiverClasses:[NSSet set]
        exactKeyOnlyWindowClasses:[NSSet set] maximumTextUTF16Units:textLimit
        maximumInputUTF16Units:inputLimit bindingLifetime:lifetime];
}
- (instancetype)initWithExactReceiverClasses:(NSSet<Class> *)classes
                  exactKeyOnlyReceiverClasses:(NSSet<Class> *)keyClasses
                    exactKeyOnlyWindowClasses:(NSSet<Class> *)windowClasses
                         maximumTextUTF16Units:(NSUInteger)textLimit
                        maximumInputUTF16Units:(NSUInteger)inputLimit
                               bindingLifetime:(NSTimeInterval)lifetime {
    return [self initWithExactReceiverClasses:classes exactKeyOnlyReceiverClasses:keyClasses
        exactKeyOnlyWindowClasses:windowClasses exactTextClientReceiverClasses:[NSSet set]
        exactTextClientWindowClasses:[NSSet set] exactTextClientDocumentClasses:[NSSet set]
        maximumTextUTF16Units:textLimit maximumInputUTF16Units:inputLimit bindingLifetime:lifetime];
}
- (instancetype)initWithExactReceiverClasses:(NSSet<Class> *)classes
                  exactKeyOnlyReceiverClasses:(NSSet<Class> *)keyClasses
                    exactKeyOnlyWindowClasses:(NSSet<Class> *)windowClasses
               exactTextClientReceiverClasses:(NSSet<Class> *)textClasses
                 exactTextClientWindowClasses:(NSSet<Class> *)textWindows
               exactTextClientDocumentClasses:(NSSet<Class> *)documents
                         maximumTextUTF16Units:(NSUInteger)textLimit
                        maximumInputUTF16Units:(NSUInteger)inputLimit
                               bindingLifetime:(NSTimeInterval)lifetime {
    return [self initWithExactReceiverClasses:classes exactKeyOnlyReceiverClasses:keyClasses
        exactKeyOnlyWindowClasses:windowClasses exactTextClientReceiverClasses:textClasses
        exactTextClientWindowClasses:textWindows exactTextClientDocumentClasses:documents
        allowTextClientInputContextKeys:NO maximumTextUTF16Units:textLimit
        maximumInputUTF16Units:inputLimit bindingLifetime:lifetime];
}
- (instancetype)initWithExactReceiverClasses:(NSSet<Class> *)classes
                  exactKeyOnlyReceiverClasses:(NSSet<Class> *)keyClasses
                    exactKeyOnlyWindowClasses:(NSSet<Class> *)windowClasses
               exactTextClientReceiverClasses:(NSSet<Class> *)textClasses
                 exactTextClientWindowClasses:(NSSet<Class> *)textWindows
               exactTextClientDocumentClasses:(NSSet<Class> *)documents
              allowTextClientInputContextKeys:(BOOL)allowContextKeys
                         maximumTextUTF16Units:(NSUInteger)textLimit
                        maximumInputUTF16Units:(NSUInteger)inputLimit
                               bindingLifetime:(NSTimeInterval)lifetime {
    return [self initWithExactReceiverClasses:classes exactKeyOnlyReceiverClasses:keyClasses
        exactKeyOnlyWindowClasses:windowClasses exactTextClientReceiverClasses:textClasses
        exactTextClientWindowClasses:textWindows exactTextClientDocumentClasses:documents
        allowTextClientInputContextKeys:allowContextKeys allowTextClientInputContextShift:NO
        maximumTextUTF16Units:textLimit maximumInputUTF16Units:inputLimit bindingLifetime:lifetime];
}
- (instancetype)initWithExactReceiverClasses:(NSSet<Class> *)classes
                  exactKeyOnlyReceiverClasses:(NSSet<Class> *)keyClasses
                    exactKeyOnlyWindowClasses:(NSSet<Class> *)windowClasses
               exactTextClientReceiverClasses:(NSSet<Class> *)textClasses
                 exactTextClientWindowClasses:(NSSet<Class> *)textWindows
               exactTextClientDocumentClasses:(NSSet<Class> *)documents
              allowTextClientInputContextKeys:(BOOL)allowContextKeys
             allowTextClientInputContextShift:(BOOL)allowShift
                         maximumTextUTF16Units:(NSUInteger)textLimit
                        maximumInputUTF16Units:(NSUInteger)inputLimit
                               bindingLifetime:(NSTimeInterval)lifetime {
    return [self initWithExactReceiverClasses:classes exactKeyOnlyReceiverClasses:keyClasses
        exactKeyOnlyWindowClasses:windowClasses exactTextClientReceiverClasses:textClasses
        exactTextClientWindowClasses:textWindows exactTextClientDocumentClasses:documents
        allowTextClientInputContextKeys:allowContextKeys allowTextClientInputContextShift:allowShift
        allowTextClientInputContextControlOption:NO maximumTextUTF16Units:textLimit
        maximumInputUTF16Units:inputLimit bindingLifetime:lifetime];
}
- (instancetype)initWithExactReceiverClasses:(NSSet<Class> *)classes
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
                               bindingLifetime:(NSTimeInterval)lifetime {
    return [self initWithExactReceiverClasses:classes exactKeyOnlyReceiverClasses:keyClasses
        exactKeyOnlyWindowClasses:windowClasses exactTextClientReceiverClasses:textClasses
        exactTextClientWindowClasses:textWindows exactTextClientDocumentClasses:documents
        allowTextClientInputContextKeys:allowContextKeys allowTextClientInputContextShift:allowShift
        allowTextClientInputContextControlOption:allowControlOption allowTextClientInputContextReceiverKeyUp:NO
        maximumTextUTF16Units:textLimit maximumInputUTF16Units:inputLimit bindingLifetime:lifetime];
}
- (instancetype)initWithExactReceiverClasses:(NSSet<Class> *)classes
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
                               bindingLifetime:(NSTimeInterval)lifetime {
    if (![classes isKindOfClass:NSSet.class] || !classes.count || classes.count > 32 ||
        ![keyClasses isKindOfClass:NSSet.class] || keyClasses.count > 32 ||
        ![windowClasses isKindOfClass:NSSet.class] || windowClasses.count > 32 ||
        (!!keyClasses.count != !!windowClasses.count) ||
        !textLimit || textLimit > LWTextHardLimit || !inputLimit || inputLimit > textLimit ||
        !isfinite(lifetime) || lifetime <= 0 || lifetime > 30) return nil;
    if (![textClasses isKindOfClass:NSSet.class] || ![textWindows isKindOfClass:NSSet.class] ||
        ![documents isKindOfClass:NSSet.class] || textClasses.count > 32 || textWindows.count > 32 || documents.count > 32 ||
        (!!textClasses.count != !!textWindows.count) || (!!textClasses.count != !!documents.count)) return nil;
    if ((allowContextKeys && !textClasses.count) || (allowShift && !allowContextKeys) || (allowControlOption && !allowShift) || (allowReceiverKeyUp && !allowControlOption)) return nil;
    for (Class c in textClasses) if (!object_isClass(c) || !LWInherits(c, NSView.class) ||
        c == NSView.class || c == NSControl.class || LWInherits(c, NSTextView.class) ||
        LWInherits(c, NSSecureTextField.class) || [classes containsObject:c] || [keyClasses containsObject:c] ||
        !LWClassConforms(c, @protocol(NSTextInputClient)) || !LWImplementations(c, LWTextClientSelectors(allowReceiverKeyUp))) return nil;
    for (Class c in textWindows) if (!object_isClass(c) || !LWInherits(c, NSWindow.class) || LWInherits(c, NSPanel.class)) return nil;
    for (Class c in documents) if (!object_isClass(c) || c == NSObject.class ||
        !LWInherits(c, NSObject.class) || !LWImplementations(c, LWDocumentSelectors())) return nil;
    for (Class c in classes) if (!object_isClass(c) || !LWInherits(c, NSTextView.class)) return nil;
    for (Class c in keyClasses) if (!object_isClass(c) || !LWInherits(c, NSView.class) ||
        c == NSView.class || c == NSControl.class || LWInherits(c, NSTextView.class) ||
        LWInherits(c, NSSecureTextField.class) ||
        !LWClassConforms(c, @protocol(NSTextInputClient)) || [classes containsObject:c]) return nil;
    for (Class c in windowClasses) if (!object_isClass(c) || !LWInherits(c, NSWindow.class) ||
        c == NSWindow.class || c == NSPanel.class) return nil;
    NSMutableDictionary *releasePins=[NSMutableDictionary dictionary];
    if(allowReceiverKeyUp) for(Class c in textClasses) {
        IMP release=class_getMethodImplementation(c,@selector(keyUp:));
        if(!release)return nil;
        releasePins[NSStringFromClass(c)]=[NSValue valueWithPointer:release];
    }
    if ((self = [super init])) {
        _textClientKeyUpPolicyIMPs=[releasePins copy];
        _allowTextClientInputContextKeys = allowContextKeys; _allowTextClientInputContextShift = allowShift; _allowTextClientInputContextControlOption = allowControlOption; _allowTextClientInputContextReceiverKeyUp = allowReceiverKeyUp;
        _exactTextClientReceiverClasses = [textClasses copy]; _exactTextClientWindowClasses = [textWindows copy];
        _exactTextClientDocumentClasses = [documents copy];
        _exactReceiverClasses = [classes copy]; _maximumTextUTF16Units = textLimit;
        _exactKeyOnlyReceiverClasses = [keyClasses copy]; _exactKeyOnlyWindowClasses = [windowClasses copy];
        _maximumInputUTF16Units = inputLimit; _bindingLifetime = lifetime;
    }
    return self;
}
- (BOOL)admitsInputContextModifiers:(NSArray *)modifiers {
    if (!_allowTextClientInputContextKeys || !_allowTextClientInputContextShift ||
        ![modifiers isKindOfClass:NSArray.class] || modifiers.count!=1 ||
        ![modifiers[0] isKindOfClass:NSString.class]) return NO;
    return [modifiers isEqual:@[@"shift"]] || (_allowTextClientInputContextControlOption &&
        ([modifiers isEqual:@[@"control"]] || [modifiers isEqual:@[@"option"]]));
}
@end

// Document identity is process/session scoped, not filesystem authority. Only
// nil is an admitted unsaved path; malformed or empty strings never fall back.
static NSDictionary *LWDocumentPathIdentity(id rawPath) {
    // Classify the getter's actual value before invoking copy: a malformed
    // nonnil object (including a string subclass) may return nil from copying.
    if (!rawPath) return @{ @"kind":@"unsaved_document", @"path":NSNull.null };
    if (!LWInherits(object_getClass(rawPath), NSString.class)) return nil;
    id path = [rawPath copy];
    if (!path || !LWInherits(object_getClass(path), NSString.class) || ![path isAbsolutePath] ||
        ![path isEqual:[path stringByStandardizingPath]] || !LWBoundedUTF8(path, 4096) ||
        [path rangeOfCharacterFromSet:[NSCharacterSet characterSetWithRange:NSMakeRange(0, 1)]].location != NSNotFound) return nil;
    return @{ @"kind":@"named_path", @"path":path };
}
static BOOL LWDocumentPathMatches(id path, NSDictionary *identity) {
    NSDictionary *current = LWDocumentPathIdentity(path);
    return current && [current[@"kind"] isEqual:identity[@"kind"]] &&
        [current[@"path"] isEqual:identity[@"path"]];
}

@interface LWReceiverState : NSObject
@property(nonatomic, strong) NSWindow *window;
@property(nonatomic, strong) NSView *receiver;
@property(nonatomic, strong) id delegate;
@property(nonatomic, strong) NSView *superview;
@property(nonatomic, strong) NSResponder *fieldEditor;
@property(nonatomic, strong) NSResponder *targetFieldEditor;
@property(nonatomic, strong) id fieldEditorDelegate, targetFieldEditorDelegate;
@property(nonatomic) BOOL keyOnly, textClient;
@property(nonatomic, strong) id document;
@property(nonatomic, strong) NSTextInputContext *inputContext, *currentInputContext;
@property(nonatomic, strong) id currentInputContextClient;
@property(nonatomic, copy) NSDictionary *inputContextIMPs, *currentInputContextIMPs, *inputContextReceiverIMPs;
@property(nonatomic) Class inputContextClass, currentInputContextClass;
@property(nonatomic) IMP originalReceiverKeyUp, plainBoardIMP;
@property(nonatomic, copy) NSDictionary *guardedTextSnapshot;
@property(nonatomic, copy) NSString *guardedText;
@property(nonatomic, copy) NSArray<NSView *> *ancestors;
@property(nonatomic, copy) NSDictionary *facts;
@property(nonatomic, copy) NSDictionary *observations;
@end
@implementation LWReceiverState @end

@interface LWReceiverBinding : NSObject
@property(nonatomic, copy) NSString *bindingID, *onceID;
@property(nonatomic, strong) LWReceiverState *state;
@property(nonatomic, copy) NSString *originalText;
@property(nonatomic, copy) NSDictionary *textSnapshot;
@property(nonatomic) double observed, deadline, lastClock;
@property(nonatomic) BOOL includeText, consumed;
@property(nonatomic, copy) NSDictionary *result;
@end
@implementation LWReceiverBinding @end

@interface LWReceiverCore ()
@property(nonatomic, strong) LWReceiverPolicy *policy;
@property(nonatomic, copy) LWReceiverAuthorityCheck authority;
@property(nonatomic, copy) LWReceiverJournal journal;
@property(nonatomic, copy) LWReceiverClock clock;
@property(nonatomic, strong) NSMutableDictionary<NSString *, LWReceiverBinding *> *bindings;
// Last capture refusal is a fixed local enum, never caller/app-provided data.
@property(nonatomic, copy) NSString *qualificationReason;
@end

@implementation LWReceiverCore
- (instancetype)initWithPolicy:(LWReceiverPolicy *)policy authorityCheck:(LWReceiverAuthorityCheck)authority
                        journal:(LWReceiverJournal)journal clock:(LWReceiverClock)clock {
    if (!NSThread.isMainThread || !policy || !authority || !journal || !clock) return nil;
    if ((self = [super init])) {
        _policy = policy; _authority = [authority copy]; _journal = [journal copy];
        _clock = [clock copy]; _bindings = [NSMutableDictionary dictionary];
    }
    return self;
}

// Narrow internal seams are overridden only by the headless fake harness.
- (NSView *)firstResponderForWindow:(NSWindow *)window {
    return (NSView *)window.firstResponder;
}
- (NSArray<NSWindow *> *)applicationWindows { return NSApp ? NSApp.windows : @[]; }
- (BOOL)applicationActive { return NSApp.isActive; }
- (NSWindow *)applicationKeyWindow { return NSApp.keyWindow; }
- (NSWindow *)applicationMainWindow { return NSApp.mainWindow; }
- (id)applicationAccessibility { return NSApp; }
- (LWReceiverState *)refuseQualification:(NSString *)reason {
    _qualificationReason = reason;
    return nil;
}
- (NSDictionary *)qualificationRefusalForWindow:(NSWindow *)window receiver:(NSView *)receiver {
    NSMutableDictionary *result = [LWRefusal(@"unqualified_secure_marked_or_unaffiliated_target") mutableCopy];
    result[@"qualification_reason"] = _qualificationReason ?: @"unspecified_qualification_refusal";
    if ([_qualificationReason isEqual:@"custom_key_requires_selected_window"]) @try {
        // Observation-only diagnostics for the exact already authorized and
        // affiliated target. App key/main pointers are compared, never exposed
        // or traversed. These facts do not qualify selection or permit input.
        NSInteger number = window.windowNumber;
        BOOL active = [self applicationActive];
        NSWindow *key = [self applicationKeyWindow], *main = [self applicationMainWindow];
        id<NSAccessibility> application = [self applicationAccessibility];
        BOOL axMainAvailable = [(id)application respondsToSelector:@selector(accessibilityMainWindow)];
        BOOL axFocusedAvailable = [(id)application respondsToSelector:@selector(accessibilityFocusedWindow)];
        BOOL axElementAvailable = [(id)application respondsToSelector:@selector(accessibilityApplicationFocusedUIElement)];
        id axMain = axMainAvailable ? application.accessibilityMainWindow : nil;
        id axFocused = axFocusedAvailable ? application.accessibilityFocusedWindow : nil;
        id axElement = axElementAvailable ? application.accessibilityApplicationFocusedUIElement : nil;
        NSDictionary *diagnostics = @{
            @"cg_window_id":@(number), @"diagnostic_only":@YES, @"read_only":@YES,
            @"snapshot_atomic":@NO, @"app_active":@(active),
            @"window_key":@(window.isKeyWindow), @"window_main":@(window.isMainWindow),
            @"app_key_window_present":@((BOOL)(key != nil)), @"app_key_window_matches_target":@((BOOL)(key == window)),
            @"app_main_window_present":@((BOOL)(main != nil)), @"app_main_window_matches_target":@((BOOL)(main == window)),
            @"app_ax_main_window_available":@(axMainAvailable),
            @"app_ax_main_window_present":@((BOOL)(axMain != nil)),
            @"app_ax_main_window_matches_target":@((BOOL)(axMain == window)),
            @"app_ax_focused_window_available":@(axFocusedAvailable),
            @"app_ax_focused_window_present":@((BOOL)(axFocused != nil)),
            @"app_ax_focused_window_matches_target":@((BOOL)(axFocused == window)),
            @"app_ax_focused_ui_element_available":@(axElementAvailable),
            @"app_ax_focused_ui_element_present":@((BOOL)(axElement != nil)),
            @"app_ax_focused_ui_element_matches_target":@((BOOL)(axElement == receiver)) };
        // Metadata getters may reenter. Never label a changed window number
        // with the diagnostic sample's earlier identity.
        if (number > 0 && window.windowNumber == number) result[@"selection_diagnostics"] = diagnostics;
    } @catch (NSException *exception) {
        // Optional diagnostic failure must preserve the original refusal.
    }
    return [result copy];
}
- (LWReceiverState *)captureWindow:(NSWindow *)window receiver:(NSView *)receiver {
    return [self captureWindow:window receiver:receiver allowSequenceMarked:NO];
}
// Only the explicitly bounded sequence uses this metadata-only capture. It
// copies no intermediate text, and retains every normal affiliation guard.
- (LWReceiverState *)captureWindow:(NSWindow *)window receiver:(NSView *)receiver allowSequenceMarked:(BOOL)sequence {
    _qualificationReason = nil;
    if (!window || !receiver) return [self refuseQualification:@"missing_window_or_receiver"];
    Class wc = object_getClass(window), rc = object_getClass(receiver);
    BOOL typed = [_policy.exactReceiverClasses containsObject:rc] && LWInherits(rc, NSTextView.class);
    Class textClass = LWAdmittedClass(receiver, _policy.exactTextClientReceiverClasses, LWTextClientSelectors(_policy.allowTextClientInputContextReceiverKeyUp));
    Class textWindow = LWAdmittedWindowClass(window, _policy.exactTextClientWindowClasses);
    BOOL textClient = textClass && textWindow;
    IMP plainBoardIMP = textClient && LWUsesPlainBoard(textClass) ? LWPlainBoardIMP(receiver, textClass) : NULL;
    if (textClient && LWUsesPlainBoard(textClass) && !plainBoardIMP)
        return [self refuseQualification:@"text_client_plain_board_endpoint_unqualified"];
    Class admittedWindow = typed ? wc : textClient ? textWindow : LWAdmittedWindowClass(window, _policy.exactKeyOnlyWindowClasses);
    BOOL keyOnly = [_policy.exactKeyOnlyReceiverClasses containsObject:rc] && admittedWindow;
    if (!LWInherits(wc, NSWindow.class)) return [self refuseQualification:@"window_class_unqualified"];
    if (!typed && !textClass && ![_policy.exactKeyOnlyReceiverClasses containsObject:rc])
        return [self refuseQualification:@"receiver_class_unqualified"];
    if (!typed && !keyOnly && !textClient) return [self refuseQualification:textClass ?
        @"text_client_window_class_unqualified" : @"key_only_window_class_unqualified"];
    NSArray<NSWindow *> *windows = [self applicationWindows];
    if (windows.count > LWWindowLimit) return [self refuseQualification:@"application_window_capacity"];
    BOOL member = NO;
    for (NSWindow *candidate in windows) if (candidate == window) member = YES;
    if (!member) return [self refuseQualification:@"window_not_application_member"];
    if (window.windowNumber <= 0) return [self refuseQualification:@"window_number_invalid"];
    if (receiver.window != window) return [self refuseQualification:@"receiver_window_mismatch"];
    if (window.firstResponder != receiver) return [self refuseQualification:@"first_responder_mismatch"];
    if (!window.isVisible) return [self refuseQualification:@"window_not_visible"];
    // Custom commands can resolve through the application's selected document.
    // Until that routing is qualified, require its key window at every capture.
    if (keyOnly && !window.isKeyWindow) return [self refuseQualification:@"custom_key_requires_selected_window"];
    if (receiver.isHiddenOrHasHiddenAncestor) return [self refuseQualification:@"receiver_hidden"];
    if (![receiver conformsToProtocol:@protocol(NSTextInputClient)])
        return [self refuseQualification:@"text_input_protocol_missing"];
    if (!sequence && [(id<NSTextInputClient>)receiver hasMarkedText]) return [self refuseQualification:@"marked_text_present"];
    if ((keyOnly || textClient) && window.attachedSheet) return [self refuseQualification:@"attached_sheet_present"];
    NSTextView *textView = typed ? (NSTextView *)receiver : nil;
    if (typed && !textView.isEditable) return [self refuseQualification:@"typed_receiver_not_editable"];
    if (typed && !textView.isSelectable) return [self refuseQualification:@"typed_receiver_not_selectable"];
    // Key-only receivers have no text contract. Audited document clients use
    // their separate protocol snapshot; both inspect existing field editors.
    id delegate = typed ? textView.delegate : nil;
    NSView *superview = receiver.superview;
    NSResponder *editor = [window fieldEditor:NO forObject:nil];
    NSResponder *targetEditor = (keyOnly || textClient) ? [window fieldEditor:NO forObject:receiver] : editor;
    id editorDelegate = editor && LWInherits(object_getClass(editor), NSTextView.class) ?
        ((NSTextView *)editor).delegate : nil;
    id targetDelegate = targetEditor && LWInherits(object_getClass(targetEditor), NSTextView.class) ?
        ((NSTextView *)targetEditor).delegate : nil;
    if (LWSecureControl(receiver)) return [self refuseQualification:@"secure_receiver"];
    if (LWSecureControl(delegate)) return [self refuseQualification:@"secure_receiver_delegate"];
    if (LWSecureControl(editor)) return [self refuseQualification:@"secure_current_field_editor"];
    if (LWSecureControl(targetEditor)) return [self refuseQualification:@"secure_target_field_editor"];
    if (LWSecureControl(editorDelegate)) return [self refuseQualification:@"secure_current_field_editor_delegate"];
    if (LWSecureControl(targetDelegate)) return [self refuseQualification:@"secure_target_field_editor_delegate"];
    NSMutableArray *ancestors = [NSMutableArray array], *geometry = [NSMutableArray array];
    NSView *ancestor = receiver;
    while (ancestor && ancestors.count < LWAncestorLimit) {
        for (NSView *seen in ancestors) if (seen == ancestor) return [self refuseQualification:@"ancestor_cycle"];
        if (LWSecureControl(ancestor)) return [self refuseQualification:@"secure_ancestor"];
        if (ancestor.window != window) return [self refuseQualification:@"ancestor_window_mismatch"];
        if (ancestor.isHidden) return [self refuseQualification:@"ancestor_hidden"];
        if (!LWValidRect(ancestor.frame)) return [self refuseQualification:@"ancestor_frame_invalid"];
        if (!LWValidRect(ancestor.bounds)) return [self refuseQualification:@"ancestor_bounds_invalid"];
        [ancestors addObject:ancestor];
        NSMutableDictionary *metadata = [@{ @"class":NSStringFromClass(object_getClass(ancestor)),
            @"frame":LWRect(ancestor.frame), @"bounds":LWRect(ancestor.bounds) } mutableCopy];
        if (keyOnly || textClient) {
            NSArray *selectors = LWInherits(object_getClass(ancestor), NSControl.class) ?
                @[@"window", @"superview", @"frame", @"bounds", @"isHidden", @"cell"] :
                @[@"window", @"superview", @"frame", @"bounds", @"isHidden"];
            NSDictionary *imps = LWImplementations(object_getClass(ancestor), selectors);
            if (!imps) return [self refuseQualification:@"ancestor_implementation_missing"];
            metadata[@"runtime_class"] = [NSValue valueWithPointer:(__bridge const void *)object_getClass(ancestor)];
            metadata[@"imps"] = imps;
        }
        [geometry addObject:[metadata copy]];
        ancestor = ancestor.superview;
    }
    if (ancestor) return [self refuseQualification:@"ancestor_limit_exceeded"];
    if (!LWValidRect(window.frame)) return [self refuseQualification:@"window_frame_invalid"];
    if (!LWValidRect(receiver.visibleRect)) return [self refuseQualification:@"receiver_visible_rect_invalid"];
    NSMutableArray *editorGeometry = [NSMutableArray array];
    NSArray *editors = @[editor ?: NSNull.null, targetEditor ?: NSNull.null];
    for (NSUInteger i = 0; i < editors.count; i++) {
        id candidate = editors[i];
        if (candidate != NSNull.null && LWInherits(object_getClass(candidate), NSView.class)) {
            NSView *view = candidate;
            if (!LWValidRect(view.frame)) return [self refuseQualification:i ?
                @"target_field_editor_frame_invalid" : @"current_field_editor_frame_invalid"];
            if (!LWValidRect(view.bounds)) return [self refuseQualification:i ?
                @"target_field_editor_bounds_invalid" : @"current_field_editor_bounds_invalid"];
            [editorGeometry addObject:@{ @"class":NSStringFromClass(object_getClass(candidate)),
                @"frame":LWRect(view.frame), @"bounds":LWRect(view.bounds) }];
        } else [editorGeometry addObject:NSNull.null];
    }
    NSArray *selectors = textClient ? LWTextClientSelectors(_policy.allowTextClientInputContextReceiverKeyUp) : typed ? @[@"keyDown:", @"keyUp:", @"readSelectionFromPasteboard:type:",
        @"string", @"selectedRange", @"hasMarkedText"] : @[@"keyDown:", @"keyUp:", @"hasMarkedText",
        @"window", @"superview", @"frame", @"bounds", @"visibleRect", @"isHiddenOrHasHiddenAncestor", @"conformsToProtocol:"];
    NSDictionary *imps = LWImplementations(rc, textClient ? [selectors arrayByAddingObject:@"class"] : selectors);
    NSDictionary *windowImps = (keyOnly || textClient) ? LWImplementations(wc, [LWWindowGuardSelectors() arrayByAddingObject:@"class"]) : @{};
    if (!imps) return [self refuseQualification:@"receiver_implementation_missing"];
    if (!windowImps) return [self refuseQualification:@"window_implementation_missing"];
    id capturedEditorGeometry = [editorGeometry copy];
    if (typed) capturedEditorGeometry = editorGeometry[0] == NSNull.null ? NSNull.null :
        @{ @"frame":editorGeometry[0][@"frame"], @"bounds":editorGeometry[0][@"bounds"] };
    id<LWDocumentTextIdentity> document = nil;
    NSDictionary *documentFacts = @{};
    if (textClient) {
        document = [(id<LWDocumentTextClient>)receiver document];
        Class documentClass = LWAdmittedClass(document, _policy.exactTextClientDocumentClasses, LWDocumentSelectors());
        if (!documentClass || !document.isLoaded || document.isLoading) return [self refuseQualification:@"text_client_document_unqualified"];
        id rawPath = document.path; NSUUID *uuid = document.identifier;
        NSDictionary *pathIdentity = LWDocumentPathIdentity(rawPath);
        if (!pathIdentity || ![uuid isKindOfClass:NSUUID.class])
            return [self refuseQualification:@"text_client_document_identity_missing"];
        NSDictionary *docIMPs = LWImplementations(object_getClass(document), LWDocumentSelectors());
        if (!docIMPs) return [self refuseQualification:@"text_client_document_implementation_missing"];
        documentFacts = @{@"kind":pathIdentity[@"kind"], @"path":pathIdentity[@"path"], @"uuid":uuid.UUIDString, @"runtime_class":NSStringFromClass(object_getClass(document)),
            @"logical_class":NSStringFromClass(documentClass)};
    }
    LWReceiverState *state = [LWReceiverState new];
    state.document = document; state.textClient = textClient; state.plainBoardIMP = plainBoardIMP;
    state.window = window; state.receiver = receiver; state.delegate = delegate;
    state.superview = superview; state.fieldEditor = editor; state.targetFieldEditor = targetEditor;
    state.fieldEditorDelegate = editorDelegate; state.targetFieldEditorDelegate = targetDelegate;
    state.ancestors = [ancestors copy]; state.keyOnly = keyOnly;
    state.facts = @{ @"window_id":@(window.windowNumber), @"window_class":NSStringFromClass(wc),
        @"window_logical_class":NSStringFromClass(admittedWindow),
        @"window_logical_runtime_class":[NSValue valueWithPointer:(__bridge const void *)admittedWindow],
        @"receiver_class":NSStringFromClass(rc), @"receiver_runtime_class":[NSValue valueWithPointer:(__bridge const void *)rc],
        @"window_runtime_class":[NSValue valueWithPointer:(__bridge const void *)wc], @"imps":imps, @"window_imps":windowImps,
        @"receiver_kind":LWReceiverKind(keyOnly, textClient),
        @"document_identity":documentFacts, @"document_imps":document ? LWImplementations(object_getClass(document), [LWDocumentSelectors() arrayByAddingObject:@"class"]) : @{},
        @"delegate_class":delegate ? NSStringFromClass(object_getClass(delegate)) : @"",
        @"field_editor_class":editor ? NSStringFromClass(object_getClass(editor)) : @"",
        @"target_field_editor_class":targetEditor ? NSStringFromClass(object_getClass(targetEditor)) : @"",
        @"field_editor_delegate_class":editorDelegate ? NSStringFromClass(object_getClass(editorDelegate)) : @"",
        @"target_field_editor_delegate_class":targetDelegate ? NSStringFromClass(object_getClass(targetDelegate)) : @"",
        @"field_editor_geometry":capturedEditorGeometry,
        @"window_frame":LWRect(window.frame), @"receiver_visible_rect":LWRect(receiver.visibleRect),
        @"ancestor_geometry":[geometry copy], @"field_editor":@(typed && textView.isFieldEditor) };
    if (![self captureInputContextForState:state]) return [self refuseQualification:@"text_client_input_context_unqualified"];
    if (textClient && !sequence) {
        NSString *beforeMetadata = nil;
        state.guardedTextSnapshot = [self textForReceiver:(id)receiver copied:&beforeMetadata];
        state.guardedText = beforeMetadata;
        if (!state.guardedTextSnapshot) return [self refuseQualification:@"text_client_selection_or_snapshot_refused"];
    }
    if (!textClient) {
        NSMutableDictionary *legacyFacts = [state.facts mutableCopy];
        [legacyFacts removeObjectsForKeys:@[@"document_identity", @"document_imps"]];
        state.facts = [legacyFacts copy];
    }
    state.observations = @{ @"app_active":@(NSApp.isActive), @"window_key":@(window.isKeyWindow),
                            @"window_main":@(window.isMainWindow) };
    // Metadata getters can reenter application code and change its selection.
    // Close that capture interval after every metadata/observation read.
    if (keyOnly && !window.isKeyWindow) return [self refuseQualification:@"custom_key_requires_selected_window"];
    if (textClient && !sequence) {
        // Window/app metadata getters above may reenter application code. Close
        // their interval with two bounded text samples and direct identity/IMP
        // checks; never recurse into captureWindow or poll until stable.
        if (![self textClientIdentityCurrent:state]) return [self refuseQualification:@"text_client_changed_during_metadata"];
        NSString *afterMetadata = nil;
        NSDictionary *afterSnapshot = [self textForReceiver:(id)receiver copied:&afterMetadata];
        if (!afterSnapshot || ![afterSnapshot isEqual:state.guardedTextSnapshot] ||
            ![afterMetadata isEqual:state.guardedText] || ![self textClientIdentityCurrent:state])
            return [self refuseQualification:@"text_client_changed_during_metadata"];
    }
    if (sequence && (![self textClientDocumentIdentityCurrent:state allowSequenceMarked:YES] ||
        ![self inputContextIdentityCurrent:state])) return nil;
    return state;
}
- (NSTextInputContext *)sampleCurrentInputContext { return NSTextInputContext.currentInputContext; }
- (BOOL)captureInputContextForState:(LWReceiverState *)state {
    if (!state.textClient || !_policy.allowTextClientInputContextKeys) return YES;
    state.inputContextReceiverIMPs = LWImplementations(object_getClass(state.receiver),
        _policy.allowTextClientInputContextReceiverKeyUp ? @[@"inputContext",@"keyUp:"] : @[@"inputContext"]);
    if (_policy.allowTextClientInputContextReceiverKeyUp) {
        Class admitted=LWAdmittedClass(state.receiver,_policy.exactTextClientReceiverClasses,LWTextClientSelectors(YES));
        IMP policyRelease=admitted?(IMP)[_policy.textClientKeyUpPolicyIMPs[NSStringFromClass(admitted)] pointerValue]:NULL;
        IMP captured=(IMP)[state.inputContextReceiverIMPs[@"keyUp:"] pointerValue];
        if(!policyRelease || captured!=policyRelease)return NO;
        state.originalReceiverKeyUp=policyRelease;
    }
    state.inputContext = state.receiver.inputContext;
    state.currentInputContext = [self sampleCurrentInputContext];
    if (!state.inputContextReceiverIMPs || ![state.inputContext isKindOfClass:NSTextInputContext.class] ||
        (id)state.inputContext.client != state.receiver) return NO;
    state.inputContextIMPs = LWImplementations(object_getClass(state.inputContext), @[@"client", @"handleEvent:"]);
    state.currentInputContextIMPs = state.currentInputContext ?
        LWImplementations(object_getClass(state.currentInputContext), @[@"client"]) : @{};
    state.inputContextClass = object_getClass(state.inputContext);
    state.currentInputContextClass = object_getClass(state.currentInputContext);
    state.currentInputContextClient = state.currentInputContext.client;
    return state.inputContextIMPs && state.currentInputContextIMPs && [self inputContextIdentityCurrent:state];
}
- (BOOL)inputContextIdentityCurrent:(LWReceiverState *)state {
    if (!state.textClient || !_policy.allowTextClientInputContextKeys) return YES;
    // Validate implementations before invoking the context getters. Retain the
    // unrelated current context/client only to detect changes, never to route.
    if (!state.inputContext || object_getClass(state.inputContext) != state.inputContextClass ||
        object_getClass(state.currentInputContext) != state.currentInputContextClass ||
        ![LWImplementations(object_getClass(state.receiver), _policy.allowTextClientInputContextReceiverKeyUp ? @[@"inputContext",@"keyUp:"] : @[@"inputContext"]) isEqual:state.inputContextReceiverIMPs] ||
        ![LWImplementations(object_getClass(state.inputContext), @[@"client", @"handleEvent:"]) isEqual:state.inputContextIMPs] ||
        (state.currentInputContext && ![LWImplementations(object_getClass(state.currentInputContext), @[@"client"]) isEqual:state.currentInputContextIMPs])) return NO;
    return state.receiver.inputContext == state.inputContext && (id)state.inputContext.client == state.receiver &&
        [self sampleCurrentInputContext] == state.currentInputContext &&
        state.currentInputContext.client == state.currentInputContextClient &&
        // Client getters can reenter and replace the view/current contexts.
        // Close those pointer intervals without routing through either sample.
        state.receiver.inputContext == state.inputContext &&
        [self sampleCurrentInputContext] == state.currentInputContext;
}
- (BOOL)textClientIdentityCurrent:(LWReceiverState *)state {
    return [self textClientDocumentIdentityCurrent:state] && [self inputContextIdentityCurrent:state];
}
- (BOOL)textClientDocumentIdentityCurrent:(LWReceiverState *)state {
    return [self textClientDocumentIdentityCurrent:state allowSequenceMarked:NO];
}
- (BOOL)textClientDocumentIdentityCurrent:(LWReceiverState *)state allowSequenceMarked:(BOOL)sequence {
    NSView *receiver = state.receiver; NSWindow *window = state.window;
    id<LWDocumentTextIdentity> document = state.document;
    if (object_getClass(receiver) != [state.facts[@"receiver_runtime_class"] pointerValue] ||
        object_getClass(window) != [state.facts[@"window_runtime_class"] pointerValue] ||
        ![LWImplementations(object_getClass(receiver), [LWTextClientSelectors(_policy.allowTextClientInputContextReceiverKeyUp) arrayByAddingObject:@"class"]) isEqual:state.facts[@"imps"]] ||
        ![LWImplementations(object_getClass(window), [LWWindowGuardSelectors() arrayByAddingObject:@"class"]) isEqual:state.facts[@"window_imps"]] ||
        ![LWImplementations(object_getClass(document), [LWDocumentSelectors() arrayByAddingObject:@"class"]) isEqual:state.facts[@"document_imps"]] ||
        ![NSStringFromClass(object_getClass(document)) isEqual:state.facts[@"document_identity"][@"runtime_class"]] ||
        receiver.window != window || window.firstResponder != receiver ||
        (!sequence && [(id<NSTextInputClient>)receiver hasMarkedText]) || window.attachedSheet ||
        !document.isLoaded || document.isLoading ||
        !LWDocumentPathMatches(document.path, state.facts[@"document_identity"]) ||
        ![document.identifier.UUIDString isEqual:state.facts[@"document_identity"][@"uuid"]]) return NO;
    // The final getter is the audited vendor's document property, not another
    // window/app metadata read. Retained object identity cannot be substituted
    // by matching path/UUID strings from a replacement document.
    if ([(id<LWDocumentTextClient>)receiver document] != document) return NO;
    // Runtime-only endpoint checks close even the final vendor getter interval.
    // A missing/changed endpoint never falls back to the typing route.
    return !state.plainBoardIMP ||
        LWPlainBoardIMP(receiver, NSClassFromString(@"OakTextView")) == state.plainBoardIMP;
}
- (BOOL)closeInputContextTextState:(LWReceiverState *)state
                 matchingSnapshot:(NSDictionary *)snapshot text:(NSString *)text {
    if (!state.inputContext) return [self inputContextIdentityCurrent:state];
    if (![self inputContextIdentityCurrent:state] || ![self textClientDocumentIdentityCurrent:state]) return NO;
    // The new context/client getters run before this last independently copied
    // text/selection sample and document identity closure. Do not call context
    // getters again after the copy: that would reopen the demonstrated interval.
    // This is bounded evidence for audited getters, not universal atomicity
    // against arbitrarily reentrant application code.
    NSString *copy = nil;
    NSDictionary *closed = [self textForReceiver:(id)state.receiver copied:&copy];
    return closed && [closed isEqual:snapshot] && [copy isEqual:text] &&
        [self textClientDocumentIdentityCurrent:state];
}
- (BOOL)state:(LWReceiverState *)a equals:(LWReceiverState *)b {
    if (!a || !b || a.window != b.window || a.receiver != b.receiver || a.delegate != b.delegate ||
        a.superview != b.superview || a.fieldEditor != b.fieldEditor || a.ancestors.count != b.ancestors.count ||
        a.targetFieldEditor != b.targetFieldEditor || a.fieldEditorDelegate != b.fieldEditorDelegate ||
        a.targetFieldEditorDelegate != b.targetFieldEditorDelegate || a.keyOnly != b.keyOnly ||
        a.textClient != b.textClient || a.document != b.document ||
        a.inputContext != b.inputContext || a.currentInputContext != b.currentInputContext ||
        a.originalReceiverKeyUp != b.originalReceiverKeyUp || a.plainBoardIMP != b.plainBoardIMP ||
        a.inputContextClass != b.inputContextClass || a.currentInputContextClass != b.currentInputContextClass ||
        a.currentInputContextClient != b.currentInputContextClient ||
        !((a.inputContextIMPs == b.inputContextIMPs) || [a.inputContextIMPs isEqual:b.inputContextIMPs]) ||
        !((a.currentInputContextIMPs == b.currentInputContextIMPs) || [a.currentInputContextIMPs isEqual:b.currentInputContextIMPs]) ||
        !((a.inputContextReceiverIMPs == b.inputContextReceiverIMPs) || [a.inputContextReceiverIMPs isEqual:b.inputContextReceiverIMPs]) ||
        ![a.facts isEqual:b.facts]) return NO;
    for (NSUInteger i = 0; i < a.ancestors.count; i++) if (a.ancestors[i] != b.ancestors[i]) return NO;
    return YES;
}
- (NSDictionary *)publicState:(LWReceiverState *)state {
    NSMutableDictionary *record = [state.facts mutableCopy];
    [record removeObjectsForKeys:@[@"receiver_runtime_class", @"window_runtime_class", @"window_logical_runtime_class", @"imps", @"window_imps", @"document_imps"]];
    NSMutableArray *geometry = [NSMutableArray array];
    for (NSDictionary *ancestor in state.facts[@"ancestor_geometry"]) {
        NSMutableDictionary *publicAncestor = [ancestor mutableCopy];
        [publicAncestor removeObjectsForKeys:@[@"runtime_class", @"imps"]];
        [geometry addObject:[publicAncestor copy]];
    }
    if (state.facts[@"ancestor_geometry"]) record[@"ancestor_geometry"] = [geometry copy];
    if ([record[@"document_identity"][@"kind"] isEqual:@"unsaved_document"]) {
        // Exact object/UUID remain private binding facts. Observation needs only
        // the qualification kind, never an unsaved document's private identifier.
        record[@"document_identity"] = @{ @"kind":@"unsaved_document", @"path_kind":@"nil",
            @"uuid_valid":@YES, @"scope":@"process_session" };
    }
    record[@"observations"] = state.observations;
    return [record copy];
}
- (NSDictionary *)textForReceiver:(NSTextView *)receiver copied:(NSString **)copied {
    *copied = nil;
    BOOL textClient = LWAdmittedClass(receiver, _policy.exactTextClientReceiverClasses, LWTextClientSelectors(_policy.allowTextClientInputContextReceiverKeyUp)) != Nil;
    NSString *selectionString = nil, *live = nil;
    if (textClient) {
        NSRange actual = NSMakeRange(NSNotFound, 0);
        NSUInteger request = _policy.maximumTextUTF16Units + 1;
        NSAttributedString *substring = [(id<NSTextInputClient>)receiver
            attributedSubstringForProposedRange:NSMakeRange(0, request) actualRange:&actual];
        // This complete-short-substring guarantee is audited OakTextView
        // behavior (clamps to its buffer end), not a generic NSTextInputClient
        // promise. Equality to request remains ambiguous truncation/refused.
        if (![substring isKindOfClass:NSAttributedString.class] || actual.location != 0 ||
            actual.length != substring.length || actual.length >= request) return nil;
        live = substring.string;
        selectionString = [[(id<LWDocumentTextClient>)receiver selectionString] copy];
    } else live = receiver.string;
    if (!LWBoundedUTF8(live, _policy.maximumTextUTF16Units)) return nil;
    NSString *text = [live copy];
    NSData *bytes = LWBoundedUTF8(text, _policy.maximumTextUTF16Units);
    NSRange selection = [(id<NSTextInputClient>)receiver selectedRange];
    if (!bytes || selection.location == NSNotFound || selection.location > text.length ||
        selection.length > text.length - selection.location ||
        (textClient && !LWPlainSelection(selectionString, text, selection))) return nil;
    NSString *hash = LWHash(bytes);
    NSData *selectionBytes = [[NSString stringWithFormat:@"%@:%lu:%lu", hash,
        (unsigned long)selection.location, (unsigned long)selection.length] dataUsingEncoding:NSUTF8StringEncoding];
    *copied = text;
    NSMutableDictionary *snapshot = [@{ @"length_utf16":@(text.length), @"bytes_utf8":@(bytes.length), @"text_sha256":hash,
        @"selection_location":@(selection.location), @"selection_length":@(selection.length),
        @"text_selection_sha256":LWHash(selectionBytes) } mutableCopy];
    if (textClient) snapshot[@"selection_string"] = selectionString;
    return [snapshot copy];
}
- (BOOL)authorityFor:(LWReceiverBinding *)binding phase:(LWReceiverPhase)phase {
    double now = _clock();
    if (!LWClockValid(binding.observed, binding.deadline, binding.lastClock, now)) return NO;
    binding.lastClock = now;
    BOOL allowed = _authority(binding.state.window, binding.state.receiver, binding.bindingID, binding.onceID, phase);
    double after = _clock();
    if (!allowed || !LWClockValid(binding.observed, binding.deadline, binding.lastClock, after)) return NO;
    binding.lastClock = after;
    return YES;
}
- (BOOL)unchanged:(LWReceiverBinding *)binding requireOriginalText:(BOOL)original {
    if (![self inputContextIdentityCurrent:binding.state]) return NO;
    LWReceiverState *current = [self captureWindow:binding.state.window receiver:binding.state.receiver];
    if (![self state:current equals:binding.state]) return NO;
    if (!original || binding.state.keyOnly) return YES;
    NSString *copy = nil;
    NSDictionary *text = [self textForReceiver:(NSTextView *)binding.state.receiver copied:&copy];
    if (!text || ![text isEqual:binding.textSnapshot] || ![copy isEqual:binding.originalText]) return NO;
    LWReceiverState *last = [self captureWindow:binding.state.window receiver:binding.state.receiver];
    if (![self state:last equals:binding.state]) return NO;
    // The last custom capture closes its metadata interval. Its guarded text
    // must still equal the original, not just the pre-capture text sample.
    return !binding.state.textClient || ([last.guardedTextSnapshot isEqual:binding.textSnapshot] &&
        [last.guardedText isEqual:binding.originalText]);
}
- (NSDictionary *)observeWindow:(NSWindow *)window includeText:(BOOL)includeText {
    if (!NSThread.isMainThread) return LWRefusal(@"main_thread_required");
    if (_bindings.count >= LWBindingLimit) return LWRefusal(@"binding_capacity_exhausted");
    @try {
        double started = _clock();
        if (!isfinite(started) || started < 0) return LWRefusal(@"invalid_monotonic_clock");
        LWReceiverBinding *binding = [LWReceiverBinding new];
        binding.bindingID = NSUUID.UUID.UUIDString; binding.onceID = NSUUID.UUID.UUIDString;
        binding.observed = started; binding.lastClock = started;
        binding.deadline = started + _policy.bindingLifetime; binding.includeText = includeText;
        NSView *receiver = [self firstResponderForWindow:window];
        if (!window || !receiver || !_authority(window, receiver, binding.bindingID, binding.onceID,
                                                LWReceiverPhaseObserve)) return LWRefusal(@"host_observation_refused");
        binding.state = [self captureWindow:window receiver:receiver];
        if (!binding.state) return [self qualificationRefusalForWindow:window receiver:receiver];
        NSString *copy = nil;
        if (!binding.state.keyOnly) {
            binding.textSnapshot = [self textForReceiver:(NSTextView *)receiver copied:&copy]; binding.originalText = copy;
            if (!binding.textSnapshot) return LWRefusal(@"text_size_encoding_or_selection_refused");
        }
        if (![self authorityFor:binding phase:LWReceiverPhasePreflight] ||
            ![self unchanged:binding requireOriginalText:YES]) return LWRefusal(@"changed_during_observation");
        NSMutableDictionary *result = [@{ @"ready":@YES, @"binding_id":binding.bindingID,
            @"freshness_clock":@"system_uptime_v1",
            @"once_id":binding.onceID, @"observed_monotonic":@(binding.observed),
            @"deadline_monotonic":@(binding.deadline), @"state":[self publicState:binding.state],
            @"receiver_kind":LWReceiverKind(binding.state.keyOnly, binding.state.textClient),
            @"capabilities":@{ @"key_pair":(binding.state.textClient && !_policy.allowTextClientInputContextKeys) ? @NO : @YES, @"consume_plain_text":binding.state.keyOnly ? @NO : @YES } } mutableCopy];
        if (binding.state.inputContext) result[@"key_pair_route"] = @"exact_view_input_context";
        if (binding.state.inputContext && _policy.allowTextClientInputContextReceiverKeyUp) result[@"key_up_route"]=@"original_receiver_key_up";
        if (binding.state.inputContext && _policy.allowTextClientInputContextShift) {
            NSMutableDictionary *caps=[result[@"capabilities"] mutableCopy]; caps[@"key_chord"]=@YES;
            result[@"capabilities"]=caps; result[@"supported_modifiers"]=_policy.allowTextClientInputContextControlOption ? @[@"shift",@"control",@"option"] : @[@"shift"];
            if (_policy.allowTextClientInputContextControlOption) result[@"maximum_modifier_count"]=@1;
        }
        if (binding.textSnapshot) result[@"text_snapshot"] = binding.textSnapshot;
        if (includeText && copy) result[@"text"] = copy;
        _bindings[binding.bindingID] = binding;
        return [result copy];
    } @catch (NSException *exception) { return LWRefusal(@"observation_exception"); }
}

- (NSArray<NSEvent *> *)pairedEventsFor:(LWReceiverBinding *)binding keyCode:(unsigned short)code
                             characters:(NSString *)characters ignoring:(NSString *)ignoring {
    return [self pairedEventsFor:binding keyCode:code characters:characters ignoring:ignoring modifierFlags:0];
}
- (NSArray<NSEvent *> *)pairedEventsFor:(LWReceiverBinding *)binding keyCode:(unsigned short)code
                             characters:(NSString *)characters ignoring:(NSString *)ignoring modifierFlags:(NSEventModifierFlags)flags {
    double timestamp = _clock();
    if (!LWClockValid(binding.observed, binding.deadline, binding.lastClock, timestamp)) return nil;
    binding.lastClock = timestamp;
    NSInteger number = [binding.state.facts[@"window_id"] integerValue];
    NSEvent *down = [NSEvent keyEventWithType:NSEventTypeKeyDown location:NSZeroPoint modifierFlags:flags
        timestamp:timestamp windowNumber:number context:nil characters:characters
        charactersIgnoringModifiers:ignoring isARepeat:NO keyCode:code];
    NSEvent *up = [NSEvent keyEventWithType:NSEventTypeKeyUp location:NSZeroPoint modifierFlags:flags
        timestamp:timestamp windowNumber:number context:nil characters:characters
        charactersIgnoringModifiers:ignoring isARepeat:NO keyCode:code];
    if (!down || !up) return nil;
    NSArray *events = @[down, up];
    for (NSUInteger i = 0; i < events.count; i++) {
        NSEvent *event = events[i];
        if (event.type != (i ? NSEventTypeKeyUp : NSEventTypeKeyDown) || event.timestamp != timestamp ||
            event.windowNumber != number || event.keyCode != code || event.modifierFlags != flags || event.isARepeat ||
            ![event.characters isEqual:characters] || ![event.charactersIgnoringModifiers isEqual:ignoring]) return nil;
    }
    return events;
}
- (NSPasteboard *)ownedBoard { return [NSPasteboard pasteboardWithUniqueName]; }
- (NSDictionary *)boardTypes:(NSPasteboard *)board {
    NSArray *types = board.types, *items = board.pasteboardItems;
    if (!types || types.count > 2 || items.count != 1) return nil;
    NSArray *itemTypes = ((NSPasteboardItem *)items[0]).types;
    if (!itemTypes || itemTypes.count != 1 || ![itemTypes[0] isEqual:NSPasteboardTypeString]) return nil;
    for (id type in types) if (![type isKindOfClass:NSString.class] ||
        !([type isEqual:NSPasteboardTypeString] || [type isEqual:@"NSStringPboardType"])) return nil;
    NSSet *unique = [NSSet setWithArray:types];
    if (unique.count != types.count || ![unique containsObject:NSPasteboardTypeString]) return nil;
    return @{ @"board_types":[types sortedArrayUsingSelector:@selector(compare:)],
              @"item_types":@[NSPasteboardTypeString], @"item_count":@1 };
}
- (BOOL)board:(NSPasteboard *)board matchesName:(NSString *)name generation:(NSInteger)generation
         data:(NSData *)data types:(NSDictionary *)types {
    if (!board || !name.length || [name isEqual:NSPasteboardNameGeneral] || generation < 0 ||
        !types || ![board.name isEqual:name] || board.changeCount != generation) return NO;
    // Read only the component's already verified, uniquely named owned board.
    if (![[self boardTypes:board] isEqual:types]) return NO;
    NSData *current = [board dataForType:NSPasteboardTypeString];
    return current && current.length <= LWByteHardLimit && [current isEqual:data] &&
        board.changeCount == generation && [[self boardTypes:board] isEqual:types];
}
- (NSDictionary *)finish:(LWReceiverBinding *)binding result:(NSMutableDictionary *)result {
    result[@"binding_id"] = binding.bindingID; result[@"once_id"] = binding.onceID;
    // The journal record does not claim its own durability before the host
    // confirms the write. Durability is an outward receipt property.
    [result removeObjectForKey:@"receipt_durable"];
    result[@"receipt_state"] = @"terminal_result";
    BOOL durable = NO;
    @try { durable = _journal(binding.onceID, @"result", [result copy]); } @catch (NSException *exception) {}
    result[@"receipt_durable"] = @(durable);
    if (!durable) {
        result[@"receipt_durable"] = @NO; result[@"outcome"] = @"unknown_receipt";
        result[@"reason"] = @"terminal_journal_unconfirmed_never_replay";
    }
    binding.result = [result copy];
    return binding.result;
}
- (NSDictionary *)performKeySequenceWithBindingID:(NSString *)bindingID onceID:(NSString *)onceID keys:(NSArray<NSDictionary *> *)keys {
    if (!NSThread.isMainThread) return LWRefusal(@"main_thread_required");
    LWReceiverBinding *binding = [bindingID isKindOfClass:NSString.class] ? _bindings[bindingID] : nil;
    if (!binding || ![binding.onceID isEqual:onceID]) return LWRefusal(@"opaque_binding_or_once_id_mismatch");
    if (binding.consumed) return binding.result ?: @{@"outcome":@"unknown_in_flight", @"reason":@"never_replay"};
    binding.consumed = YES;
    NSMutableDictionary *result = [@{@"action":@"key_sequence", @"outcome":@"not_dispatched",
        @"effect_state":@"none", @"dispatch_attempted":@NO, @"intent_durable":@NO,
        @"readback_completed":@NO, @"completed_prefix_count":@0,
        @"sequence_atomic":@NO, @"final_marked_text":NSNull.null,
        @"final_state_evidence":@"bounded_non_atomic_samples", @"text_causality":@"not_attributed"} mutableCopy];
    NSMutableArray *steps = [NSMutableArray array], *events = [NSMutableArray array], *descriptors = [NSMutableArray array];
    BOOL attempted = NO, intentPending = NO;
    __attribute__((objc_precise_lifetime)) NSView *receiver = binding.state.receiver;
    @try {
        if (!binding.state.textClient || !binding.state.inputContext ||
            !_policy.allowTextClientInputContextReceiverKeyUp || !binding.state.originalReceiverKeyUp) {
            result[@"reason"] = @"sequence_exact_context_original_up_required"; LWStop();
        }
        if (![keys isKindOfClass:NSArray.class] || keys.count < 2 || keys.count > 8) {
            result[@"reason"] = @"bounded_sequence_required"; LWStop();
        }
        // Validate and deeply freeze the complete finite request before host or
        // recipient callbacks. No later value is taken from caller containers.
        for (id raw in keys) {
            NSSet *fields = [NSSet setWithArray:@[@"key_code", @"characters", @"characters_ignoring_modifiers", @"modifiers"]];
            if (![raw isKindOfClass:NSDictionary.class] || ![[NSSet setWithArray:[raw allKeys]] isEqual:fields]) {
                result[@"reason"] = @"sequence_descriptor_refused"; LWStop();
            }
            NSNumber *code = raw[@"key_code"]; NSArray *modifiers = raw[@"modifiers"];
            if (![code isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)code) == CFBooleanGetTypeID() ||
                CFNumberIsFloatType((__bridge CFNumberRef)code) || code.longLongValue < 0 || code.longLongValue > 127 ||
                !LWKeyAllowed(code.unsignedShortValue) || !LWBoundedUTF8(raw[@"characters"], 8) ||
                !LWBoundedUTF8(raw[@"characters_ignoring_modifiers"], 8) || ![modifiers isKindOfClass:NSArray.class] ||
                (modifiers.count && ![_policy admitsInputContextModifiers:modifiers])) {
                result[@"reason"] = @"sequence_descriptor_refused"; LWStop();
            }
            NSArray *frozenModifiers = !modifiers.count ? @[] : [modifiers isEqual:@[@"shift"]] ? @[@"shift"] :
                [modifiers isEqual:@[@"control"]] ? @[@"control"] : @[@"option"];
            [descriptors addObject:@{@"key_code":@(code.unsignedShortValue), @"characters":[raw[@"characters"] copy],
                @"characters_ignoring_modifiers":[raw[@"characters_ignoring_modifiers"] copy], @"modifiers":frozenModifiers}];
        }
        if (![self authorityFor:binding phase:LWReceiverPhasePreflight] || ![self unchanged:binding requireOriginalText:YES]) {
            result[@"reason"] = @"original_authority_affiliation_or_text_changed"; LWStop();
        }
        NSMutableArray *intentKeys = [NSMutableArray array];
        for (NSDictionary *key in descriptors) {
            NSArray *mods = key[@"modifiers"];
            NSEventModifierFlags flags = !mods.count ? 0 : [mods isEqual:@[@"shift"]] ? NSEventModifierFlagShift :
                [mods isEqual:@[@"control"]] ? NSEventModifierFlagControl : NSEventModifierFlagOption;
            NSArray *pair = [self pairedEventsFor:binding keyCode:[key[@"key_code"] unsignedShortValue]
                characters:key[@"characters"] ignoring:key[@"characters_ignoring_modifiers"] modifierFlags:flags];
            if (pair.count != 2) { result[@"reason"] = @"paired_event_factory_refused"; LWStop(); }
            [events addObject:pair];
            [intentKeys addObject:@{@"key_code":key[@"key_code"], @"modifiers":mods,
                @"characters_sha256":LWHash(LWBoundedUTF8(key[@"characters"],8)),
                @"characters_ignoring_modifiers_sha256":LWHash(LWBoundedUTF8(key[@"characters_ignoring_modifiers"],8))}];
        }
        result[@"requested_count"] = @(events.count);
        result[@"key_pair_route"] = @"exact_view_input_context";
        result[@"key_up_route"] = @"original_receiver_key_up";
        intentPending = YES;
        if (!_journal(binding.onceID, @"intent", @{@"binding_id":binding.bindingID, @"once_id":binding.onceID,
            @"action":@"key_sequence", @"keys":[intentKeys copy], @"before":binding.textSnapshot,
            @"state":[self publicState:binding.state], @"observed_monotonic":@(binding.observed),
            @"deadline_monotonic":@(binding.deadline), @"contract":@"missing_terminal_result_is_unknown_never_replay"})) {
            result[@"outcome"] = @"unknown_intent"; result[@"reason"] = @"intent_journal_unconfirmed_never_replay"; LWStop();
        }
        intentPending = NO; result[@"intent_durable"] = @YES;
        if (![self unchanged:binding requireOriginalText:YES] || ![self authorityFor:binding phase:LWReceiverPhaseReserveEffect] ||
            ![self unchanged:binding requireOriginalText:YES]) {
            result[@"reason"] = @"last_state_or_atomic_authority_refused"; LWStop();
        }
        for (NSArray *pair in events) {
            // Reuse the original authority; this phase must NOT reserve again.
            // Metadata capture retains all exact receiver/document/context,
            // geometry, privacy and implementation checks but reads no preedit.
            if (![self authorityFor:binding phase:LWReceiverPhaseSequenceStep] ||
                ![self state:[self captureWindow:binding.state.window receiver:receiver allowSequenceMarked:YES] equals:binding.state] ||
                ![self authorityFor:binding phase:LWReceiverPhaseSequenceStep] ||
                ![self textClientDocumentIdentityCurrent:binding.state allowSequenceMarked:YES] ||
                ![self inputContextIdentityCurrent:binding.state]) {
                result[@"reason"] = @"sequence_authority_or_affiliation_changed"; LWStop();
            }
            // Context getters can reenter; close immutable document affiliation
            // and clock after them, before admitting this DOWN.
            if (![self textClientDocumentIdentityCurrent:binding.state allowSequenceMarked:YES] ||
                ![self authorityFor:binding phase:LWReceiverPhaseSequenceStep]) {
                result[@"reason"] = @"sequence_final_authority_or_affiliation_changed"; LWStop();
            }
            // Before the first DOWN there is no sequence-created intermediate
            // state. Reentrant authority/metadata/context getters above must not
            // replace the original unmarked text/selection precondition. Close
            // their interval with the same strict audited snapshot contract as
            // single-key admission; only later steps may preserve preedit.
            if (!attempted && (![self unchanged:binding requireOriginalText:YES] ||
                ![self closeInputContextTextState:binding.state matchingSnapshot:binding.textSnapshot text:binding.originalText])) {
                result[@"reason"] = @"sequence_initial_text_or_mark_changed_before_first_down"; LWStop();
            }
            // The strict initial closure above invokes audited app getters.
            // Close its Stop interval with the original trusted host check;
            // no further application getters run before this DOWN.
            if (!attempted && ![self authorityFor:binding phase:LWReceiverPhaseSequenceStep]) {
                result[@"reason"] = @"sequence_initial_authority_revoked_before_first_down"; LWStop();
            }
            double now = _clock();
            if (!LWClockValid(binding.observed,binding.deadline,binding.lastClock,now)) {
                result[@"reason"] = @"sequence_final_affiliation_or_deadline_changed"; LWStop();
            }
            binding.lastClock = now;
            NSMutableDictionary *step = [@{@"index":@(steps.count), @"down_attempted":@YES, @"down_returned":@NO,
                @"up_attempted":@NO, @"up_returned":@NO} mutableCopy];
            [steps addObject:step]; attempted = YES;
            result[@"dispatch_attempted"] = @YES; result[@"effect_state"] = @"unknown";
            result[@"outcome"] = @"unknown_after_attempt";
            @try {
                step[@"input_context_down_consumed"] = @([binding.state.inputContext handleEvent:pair[0]]);
                step[@"down_returned"] = @YES;
            } @finally {
                step[@"up_attempted"] = @YES;
                ((void (*)(id,SEL,NSEvent *))binding.state.originalReceiverKeyUp)(receiver,@selector(keyUp:),pair[1]);
                step[@"up_returned"] = @YES;
            }
            result[@"completed_prefix_count"] = @(steps.count);
        }
        if ([self authorityFor:binding phase:LWReceiverPhaseReadback] &&
            [self state:[self captureWindow:binding.state.window receiver:receiver allowSequenceMarked:YES] equals:binding.state]) {
            BOOL marked = [(id<NSTextInputClient>)receiver hasMarkedText];
            if ([self textClientDocumentIdentityCurrent:binding.state allowSequenceMarked:YES] &&
                [self inputContextIdentityCurrent:binding.state] &&
                [self authorityFor:binding phase:LWReceiverPhaseReadback]) result[@"final_marked_text"] = @(marked);
        }
        if ([self authorityFor:binding phase:LWReceiverPhaseReadback] && [self unchanged:binding requireOriginalText:NO]) {
            NSString *text = nil; NSDictionary *after = [self textForReceiver:(id)receiver copied:&text];
            LWReceiverState *finalState = after ? [self captureWindow:binding.state.window receiver:receiver] : nil;
            if ([self state:finalState equals:binding.state] &&
                [finalState.guardedTextSnapshot isEqual:after] && [finalState.guardedText isEqual:text] &&
                [self closeInputContextTextState:binding.state matchingSnapshot:after text:text]) {
                result[@"after"] = after; result[@"before"] = binding.textSnapshot;
                result[@"final_marked_text"] = @NO; result[@"readback_completed"] = @YES;
                result[@"outcome"] = @"bounded_readback"; result[@"effect_state"] = @"bounded_text_readback";
            }
        }
        if (![result[@"readback_completed"] boolValue]) result[@"reason"] = @"final_unmarked_bounded_readback_unavailable";
    } @catch (NSException *exception) {
        if (![exception.name isEqual:@"LWReceiverGuardRefusal"]) {
            result[@"reason"] = attempted ? @"sequence_dispatch_or_postcheck_exception" : @"sequence_pre_effect_exception";
            result[@"outcome"] = attempted ? @"unknown_after_attempt" : intentPending ? @"unknown_intent" : @"not_dispatched";
        }
    }
    // Freeze nested step records before storing or returning the terminal.
    NSMutableArray *frozenSteps = [NSMutableArray array];
    for (NSDictionary *step in steps) [frozenSteps addObject:[step copy]];
    result[@"steps"] = [frozenSteps copy];
    return [self finish:binding result:result];
}

- (NSDictionary *)performKeyPairWithBindingID:(NSString *)bindingID onceID:(NSString *)onceID
                                     keyCode:(unsigned short)code characters:(NSString *)characters
                 charactersIgnoringModifiers:(NSString *)ignoring {
    return [self execute:bindingID onceID:onceID code:code characters:characters ignoring:ignoring payload:nil modifiers:nil];
}
- (NSDictionary *)performShiftChordWithBindingID:(NSString *)bindingID onceID:(NSString *)onceID
                                      keyCode:(unsigned short)code characters:(NSString *)characters
                  charactersIgnoringModifiers:(NSString *)ignoring modifiers:(NSArray<NSString *> *)modifiers {
    return [self execute:bindingID onceID:onceID code:code characters:characters ignoring:ignoring payload:nil modifiers:modifiers ?: @[]];
}
- (NSDictionary *)consumePlainTextWithBindingID:(NSString *)bindingID onceID:(NSString *)onceID text:(NSString *)text {
    if (!text) return LWRefusal(@"literal_text_required");
    return [self execute:bindingID onceID:onceID code:0 characters:nil ignoring:nil payload:text modifiers:nil];
}
- (NSDictionary *)execute:(NSString *)bindingID onceID:(NSString *)onceID code:(unsigned short)code
                 characters:(NSString *)characters ignoring:(NSString *)ignoring payload:(NSString *)payload modifiers:(NSArray *)modifiers {
    if (!NSThread.isMainThread) return LWRefusal(@"main_thread_required");
    LWReceiverBinding *binding = [bindingID isKindOfClass:NSString.class] ? _bindings[bindingID] : nil;
    if (!binding || ![binding.onceID isEqual:onceID]) return LWRefusal(@"opaque_binding_or_once_id_mismatch");
    if (binding.consumed) return binding.result ?: @{ @"outcome":@"unknown_in_flight", @"once_id":binding.onceID,
        @"binding_id":binding.bindingID, @"reason":@"never_replay", @"dispatch_attempted":NSNull.null };
    binding.consumed = YES; // Before callbacks: reentrant invocation cannot dispatch.
    BOOL consume = payload != nil, chord = modifiers != nil;
    NSMutableDictionary *result = [@{ @"outcome":@"not_dispatched", @"effect_state":@"none",
        @"dispatch_attempted":@NO, @"down_attempted":@NO, @"up_attempted":@NO,
        @"intent_durable":@NO, @"readback_completed":@NO, @"consumer_returned_bool":NSNull.null,
        @"exact_plaintext_replacement":NSNull.null, @"own_board_release_requested":@NO,
        @"cleanup_deferred_unknown_board":@NO, @"action":consume ? @"literal_plaintext_consume" : chord ? @"key_chord" : @"key_pair" } mutableCopy];
    result[@"receiver_kind"] = LWReceiverKind(binding.state.keyOnly, binding.state.textClient);
    BOOL contextKeys = !consume && binding.state.textClient && _policy.allowTextClientInputContextKeys;
    if (chord && [_policy admitsInputContextModifiers:modifiers]) {
        // Freeze the admitted literal before any reentrant host callback; mutable
        // caller strings cannot alter the event/intent/result modifier contract.
        modifiers=[modifiers isEqual:@[@"shift"]] ? @[@"shift"] : [modifiers isEqual:@[@"control"]] ? @[@"control"] : @[@"option"];
        result[@"modifiers"]=modifiers;
    }
    if (contextKeys) result[@"key_pair_route"] = @"exact_view_input_context";
    if (contextKeys && _policy.allowTextClientInputContextReceiverKeyUp) result[@"key_up_route"]=@"original_receiver_key_up";
    if (binding.state.keyOnly) result[@"recipient_metadata_revalidated"] = @NO;
    __attribute__((objc_precise_lifetime)) NSView *receiver = binding.state.receiver;
    __attribute__((objc_precise_lifetime)) NSPasteboard *board = nil;
    NSString *boardName = nil; NSInteger generation = -1;
    NSDictionary *types = nil; NSData *payloadData = nil;
    BOOL attempted = NO, downReturned = NO, upReturned = NO, postReadback = NO, intentPending = NO;
    @try {
        if (chord && (!contextKeys || ![_policy admitsInputContextModifiers:modifiers])) {
            result[@"reason"]=@"shift_input_context_chord_not_supported"; LWStop();
        }
        if (!consume && binding.state.textClient && !contextKeys) {
            result[@"reason"] = @"text_client_literal_only"; LWStop();
        }
        if (consume && binding.state.keyOnly) {
            result[@"reason"] = @"receiver_does_not_consume_plain_text";
            LWStop();
        }
        if ((consume && !(payloadData = LWBoundedUTF8(payload, _policy.maximumInputUTF16Units))) ||
            (!consume && (!LWKeyAllowed(code) || !LWBoundedUTF8(characters, 8) ||
                          !LWBoundedUTF8(ignoring, 8)))) {
            result[@"reason"] = @"bounded_explicit_input_refused";
            LWStop();
        }
        // Freeze bounded caller values before invoking any reentrant host code.
        if (consume) payload = [payload copy];
        else { characters = [characters copy]; ignoring = [ignoring copy]; if(chord) modifiers=[modifiers copy]; }
        if (![self authorityFor:binding phase:LWReceiverPhasePreflight] ||
            ![self unchanged:binding requireOriginalText:YES]) {
            result[@"reason"] = @"original_authority_affiliation_or_text_changed";
            LWStop();
        }
        NSArray *events = nil;
        NSString *expected = nil;
        if (consume) {
            NSRange selection = NSMakeRange([binding.textSnapshot[@"selection_location"] unsignedIntegerValue],
                                           [binding.textSnapshot[@"selection_length"] unsignedIntegerValue]);
            NSUInteger remaining = binding.originalText.length - selection.length;
            if (payload.length > _policy.maximumTextUTF16Units - remaining) {
                result[@"reason"] = @"replacement_readback_size_refused";
                LWStop();
            }
            expected = [binding.originalText stringByReplacingCharactersInRange:selection withString:payload];
            if (!LWBoundedUTF8(expected, _policy.maximumTextUTF16Units)) {
                result[@"reason"] = @"replacement_encoding_refused";
                LWStop();
            }
            board = [self ownedBoard]; boardName = [board.name copy];
            if (!board || !boardName.length || [boardName isEqual:NSPasteboardNameGeneral]) {
                result[@"reason"] = @"unique_private_board_unavailable";
                LWStop();
            }
            [board declareTypes:@[NSPasteboardTypeString] owner:nil];
            BOOL published = [board setData:payloadData forType:NSPasteboardTypeString];
            generation = board.changeCount; types = [self boardTypes:board];
            if (!published || ![self board:board matchesName:boardName generation:generation data:payloadData types:types]) {
                result[@"reason"] = @"owned_board_lease_unverified";
                LWStop();
            }
        } else {
            events = chord ? [self pairedEventsFor:binding keyCode:code characters:characters ignoring:ignoring modifierFlags:([modifiers isEqual:@[@"shift"]] ? NSEventModifierFlagShift : [modifiers isEqual:@[@"control"]] ? NSEventModifierFlagControl : NSEventModifierFlagOption)] :
                [self pairedEventsFor:binding keyCode:code characters:characters ignoring:ignoring];
            if (!events) { result[@"reason"] = @"paired_event_factory_refused"; LWStop(); }
        }
        NSMutableDictionary *intent = [@{ @"binding_id":binding.bindingID, @"once_id":binding.onceID,
            @"action":result[@"action"], @"observed_monotonic":@(binding.observed),
            @"deadline_monotonic":@(binding.deadline), @"state":[self publicState:binding.state],
            @"receiver_kind":result[@"receiver_kind"],
            @"contract":@"missing_terminal_result_is_unknown_never_replay" } mutableCopy];
        if (chord) intent[@"modifiers"]=[modifiers copy];
        if (contextKeys) intent[@"key_pair_route"] = @"exact_view_input_context";
        if (contextKeys && _policy.allowTextClientInputContextReceiverKeyUp) intent[@"key_up_route"]=@"original_receiver_key_up";
        if (binding.textSnapshot) intent[@"before"] = binding.textSnapshot;
        if (consume) {
            intent[@"payload_bytes"] = @(payloadData.length); intent[@"payload_sha256"] = LWHash(payloadData);
            intent[@"board_name"] = boardName; intent[@"board_generation"] = @(generation); intent[@"board_types"] = types;
        } else {
            intent[@"key_code"] = @(code);
            intent[@"characters_sha256"] = LWHash(LWBoundedUTF8(characters, 8));
            intent[@"characters_ignoring_modifiers_sha256"] = LWHash(LWBoundedUTF8(ignoring, 8));
        }
        intentPending = YES;
        if (!_journal(binding.onceID, @"intent", [intent copy])) {
            result[@"outcome"] = @"unknown_intent";
            result[@"reason"] = @"intent_journal_unconfirmed_never_replay";
            LWStop();
        }
        intentPending = NO;
        result[@"intent_durable"] = @YES;
        if (![self unchanged:binding requireOriginalText:YES] ||
            (consume && ![self board:board matchesName:boardName generation:generation data:payloadData types:types]) ||
            ![self authorityFor:binding phase:LWReceiverPhaseReserveEffect] ||
            ![self unchanged:binding requireOriginalText:YES] ||
            (consume && ![self board:board matchesName:boardName generation:generation data:payloadData types:types])) {
            result[@"reason"] = @"last_state_lease_or_atomic_authority_refused";
            LWStop();
        }
        double lastNow = _clock();
        if (!LWClockValid(binding.observed, binding.deadline, binding.lastClock, lastNow)) {
            result[@"reason"] = @"original_deadline_or_monotonic_clock_refused";
            LWStop();
        }
        binding.lastClock = lastNow;
        if ((binding.state.textClient && ![self textClientDocumentIdentityCurrent:binding.state]) ||
            ![self inputContextIdentityCurrent:binding.state] ||
            (binding.state.inputContext && ![self closeInputContextTextState:binding.state
                matchingSnapshot:binding.textSnapshot text:binding.originalText])) {
            result[@"reason"] = @"input_context_changed_before_dispatch"; LWStop();
        }
        attempted = YES; result[@"dispatch_attempted"] = @YES; result[@"effect_state"] = @"unknown";
        if (consume) {
            if (binding.state.plainBoardIMP) {
                // Invoke the retained, ABI-checked vendor implementation once;
                // its BOOL is independent of the observed requested effect.
                BOOL returned = ((BOOL (*)(id, SEL, NSPasteboard *))binding.state.plainBoardIMP)(
                    receiver, @selector(readSelectionFromPasteboard:), board);
                result[@"consumer_returned_bool"] = @(returned);
            } else if (binding.state.textClient) {
                NSRange selected = NSMakeRange([binding.textSnapshot[@"selection_location"] unsignedIntegerValue],
                    [binding.textSnapshot[@"selection_length"] unsignedIntegerValue]);
                [(id<NSTextInputClient>)receiver insertText:payload replacementRange:selected];
                result[@"literal_insert_returned"] = @YES;
            } else {
                BOOL returned = [(NSTextView *)receiver readSelectionFromPasteboard:board type:NSPasteboardTypeString];
                result[@"consumer_returned_bool"] = @(returned);
            }
        } else {
            @try {
                result[@"down_attempted"] = @YES;
                if (contextKeys) result[@"input_context_down_consumed"] = @([binding.state.inputContext handleEvent:events[0]]);
                else [receiver keyDown:events[0]];
                downReturned = YES;
            } @finally {
                // This balances the original receiver even after focus changes,
                // cancellation, exceptions or deadline expiry during keyDown.
                result[@"up_attempted"] = @YES;
                if (contextKeys && _policy.allowTextClientInputContextReceiverKeyUp) {
                    // Captured/authenticated before callbacks. Never re-resolve a
                    // replacement IMP or skip the original release after down.
                    ((void (*)(id,SEL,NSEvent *))binding.state.originalReceiverKeyUp)(receiver,@selector(keyUp:),events[1]);
                } else if (contextKeys) result[@"input_context_up_consumed"] = @([binding.state.inputContext handleEvent:events[1]]);
                else [receiver keyUp:events[1]];
                upReturned = YES;
            }
        }
        if (binding.state.keyOnly) result[@"outcome"] = @"dispatched_unverified";
        if ([self authorityFor:binding phase:LWReceiverPhaseReadback] &&
            [self unchanged:binding requireOriginalText:NO]) {
            if (binding.state.keyOnly) {
                LWReceiverState *afterState = [self captureWindow:binding.state.window receiver:receiver];
                if ([self state:afterState equals:binding.state]) {
                    result[@"recipient_metadata_revalidated"] = @YES;
                    result[@"after_state"] = [self publicState:afterState];
                    postReadback = YES;
                }
            } else {
                NSString *afterText = nil;
                NSDictionary *after = [self textForReceiver:(NSTextView *)receiver copied:&afterText];
                BOOL lease = !consume || [self board:board matchesName:boardName generation:generation data:payloadData types:types];
                LWReceiverState *afterState = nil;
                if (after && lease && [self unchanged:binding requireOriginalText:NO])
                    afterState = [self captureWindow:binding.state.window receiver:receiver];
                if (afterState && [self state:afterState equals:binding.state] &&
                    [self closeInputContextTextState:binding.state matchingSnapshot:after text:afterText] &&
                    (!binding.state.textClient || ([afterState.guardedTextSnapshot isEqual:after] &&
                        [afterState.guardedText isEqual:afterText]))) {
                    result[@"before"] = binding.textSnapshot; result[@"after"] = after;
                    result[@"readback_completed"] = @YES; result[@"effect_state"] = @"bounded_text_readback";
                    result[@"outcome"] = @"bounded_readback"; postReadback = YES;
                    result[@"text_changed"] = @(![afterText isEqual:binding.originalText]);
                    if (consume) result[@"exact_plaintext_replacement"] = @([afterText isEqual:expected]);
                    // Raw text is returned only to a caller-authorized observation,
                    // and is excluded from the host's durable journal below.
                    if (binding.includeText) result[@"authorized_after_text"] = afterText;
                    result[@"after_observations"] = afterState.observations;
                    if (binding.state.textClient) {
                        result[@"sampled_focus_unchanged"] = @([binding.state.observations isEqual:result[@"after_observations"]]);
                        result[@"focus_evidence"] = @"app_and_window_samples_only";
                        if (contextKeys) {
                            result[@"sampled_input_context_unchanged"] = @YES;
                            result[@"input_context_evidence"] = @"exact_view_and_current_context_client_samples_only";
                        }
                        if (consume) result[@"exact_plaintext_selection"] = @(
                            [after[@"selection_location"] unsignedIntegerValue] ==
                                [binding.textSnapshot[@"selection_location"] unsignedIntegerValue] + payload.length &&
                            [after[@"selection_length"] unsignedIntegerValue] == 0);
                    }
                }
            }
        }
        if (!postReadback) {
            if (!binding.state.keyOnly) result[@"outcome"] = @"unknown_after_attempt";
            result[@"reason"] = binding.state.keyOnly ? @"recipient_metadata_revalidation_unavailable" : @"bounded_readback_unavailable";
        }
    } @catch (NSException *exception) {
        if (![exception.name isEqual:@"LWReceiverGuardRefusal"]) {
            result[@"outcome"] = attempted ? @"unknown_after_attempt" :
                (intentPending ? @"unknown_intent" : @"not_dispatched");
            result[@"reason"] = attempted ? @"receiver_or_postcheck_exception" :
                (intentPending ? @"intent_journal_exception_never_replay" : @"pre_effect_exception");
        }
    } @finally {
        if (board) {
            @try {
                if ((!attempted || postReadback) &&
                    [self board:board matchesName:boardName generation:generation data:payloadData types:types]) {
                    [board releaseGlobally]; result[@"own_board_release_requested"] = @YES;
                }
            } @catch (NSException *exception) {}
            result[@"cleanup_deferred_unknown_board"] = @(![result[@"own_board_release_requested"] boolValue]);
        }
        if (!consume) { result[@"down_returned"] = @(downReturned); result[@"up_returned"] = @(upReturned); }
    }
    // Host journals bounded hashes only, even when raw readback is authorized.
    NSString *authorizedText = result[@"authorized_after_text"];
    [result removeObjectForKey:@"authorized_after_text"];
    NSDictionary *terminal = [self finish:binding result:result];
    if (authorizedText) {
        NSMutableDictionary *disclosed = [terminal mutableCopy]; disclosed[@"authorized_after_text"] = authorizedText;
        binding.result = [disclosed copy];
    }
    return binding.result;
}
@end
