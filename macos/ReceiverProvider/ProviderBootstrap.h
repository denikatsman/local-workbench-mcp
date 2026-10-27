#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// TextMate2.0.23 executable audited for full bounded substring and selection
// semantics. Authentication alone does not qualify future vendor builds.
#define LWProviderReviewedTextMateCDHash @"c7f21e7c9c33f4c5b6fc2a7597b38ee192969bf3"
/// Explicit admitted lifecycle, on the main thread. No activation, windows,
/// prompts, running-app injection/relaunch or automatic effect retries.
/// Reads <=16KiB from an owned0600 nlink1 regular config under an owned0700
/// no-symlink parent; socket shares that parent, journal is separate durable0700.
/// Config v1 has exactly version/socket_path/journal_path/token/session/
/// generation/host_audit_token/target/helper/receiver_classes. Audit token is
/// canonical base64 of exactly32 bytes. Identities are independently verified.
FOUNDATION_EXPORT BOOL LWProviderBootstrapStart(NSString *absoluteConfigPath);
/// Separate vendor-plugin route: only protected config v3/v4, exact TextMate and
/// approved signed plugin/helper identities, mapped MH_BUNDLE wrapper marker.
/// The marker is never dereferenced; its image must independently match the pin.
/// Legacy Start and the DYLD constructor cannot select this route.
FOUNDATION_EXPORT BOOL LWProviderBootstrapStartFromTextMatePlugin(NSString *absoluteConfigPath,
                                                                const void * _Nullable wrapperMarkerAddress);
/// Stops transport and releases retained receiver/window references; journals
/// survive. A stopped bootstrap cannot restart in the same target process.
FOUNDATION_EXPORT BOOL LWProviderBootstrapStop(void);
/// Thread-safe fixed code only. Never contains config bytes, paths or secrets.
FOUNDATION_EXPORT NSString *LWProviderBootstrapStatus(void);
NS_ASSUME_NONNULL_END
