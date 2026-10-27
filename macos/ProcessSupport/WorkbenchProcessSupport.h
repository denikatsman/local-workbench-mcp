#include <bsm/libbsm.h>
#include <Security/SecCode.h>
#include <libproc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/param.h>

// A private per-launch socketpair carries only listener handoff and ACK/Stop.
// Native retains its socket copy until exact guardian completion is known.
static inline int WB_CreateLifecyclePair(int descriptors[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors)) return -1;
    for (int i = 0; i < 2; ++i) {
        int no_signal = 1;
        if (fcntl(descriptors[i], F_SETFD, FD_CLOEXEC) < 0 ||
            setsockopt(descriptors[i], SOL_SOCKET, SO_NOSIGPIPE, &no_signal, sizeof(no_signal))) {
            close(descriptors[0]); close(descriptors[1]); return -1;
        }
    }
    return 0;
}

static inline int WB_ReceiveLoopbackReservation(int channel, const char *nonce, uint16_t expected_port) {
    char bytes[128];
    // Darwin externalizes all rights before truncating a caller's ancillary
    // buffer. Receive the full kernel control-message bound, then reject extras;
    // a tiny one-FD buffer could leak installed but unreported descriptors.
    union { struct cmsghdr alignment; char bytes[CMSG_SPACE(MCLBYTES)]; } control;
    memset(&control, 0, sizeof(control));
    struct iovec vector = { .iov_base = bytes, .iov_len = sizeof(bytes) };
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &vector; message.msg_iovlen = 1;
    message.msg_control = control.bytes; message.msg_controllen = sizeof(control.bytes);
    struct timeval timeout = { .tv_sec = 10, .tv_usec = 0 };
    if (setsockopt(channel, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) return -1;
    ssize_t count;
    do { count = recvmsg(channel, &message, 0); } while (count < 0 && errno == EINTR);
    int found[MCLBYTES / sizeof(int)], total = 0, malformed = 0;
    for (struct cmsghdr *part = CMSG_FIRSTHDR(&message); part; part = CMSG_NXTHDR(&message, part)) {
        if (part->cmsg_level != SOL_SOCKET || part->cmsg_type != SCM_RIGHTS || part->cmsg_len < CMSG_LEN(0)) {
            malformed = 1; continue;
        }
        size_t length = part->cmsg_len - CMSG_LEN(0);
        size_t available = (size_t)((char *)&control + sizeof(control) - (char *)CMSG_DATA(part));
        if (length > available) { length = available; malformed = 1; }
        if (length % sizeof(int)) malformed = 1;
        for (size_t i = 0; i < length / sizeof(int); ++i) {
            int fd; memcpy(&fd, CMSG_DATA(part) + i * sizeof(int), sizeof(fd));
            if (total < (int)(MCLBYTES / sizeof(int))) found[total++] = fd; else { close(fd); malformed = 1; }
        }
    }
    int accepted = -1;
    if (count == 32 && strlen(nonce) == 32 && !memcmp(bytes, nonce, 32) && total == 1 &&
        !malformed && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
        struct sockaddr_in address; socklen_t length = sizeof(address);
        int type = 0; socklen_t type_length = sizeof(type);
        if (!getsockopt(found[0], SOL_SOCKET, SO_TYPE, &type, &type_length) && type == SOCK_STREAM &&
            !getsockname(found[0], (struct sockaddr *)&address, &length) &&
            length == sizeof(address) && address.sin_family == AF_INET &&
            ntohl(address.sin_addr.s_addr) == INADDR_LOOPBACK && ntohs(address.sin_port) >= 1024 &&
            (!expected_port || ntohs(address.sin_port) == expected_port) &&
            fcntl(found[0], F_SETFD, FD_CLOEXEC) == 0) accepted = found[0];
    }
    for (int i = 0; i < total; ++i) if (found[i] != accepted) close(found[i]);
    return accepted;
}

// Bounded kernel read of the exact process's IPv4 loopback listener. Endpoint
// metadata cannot substitute for ownership of the actual listening socket.
// The caller separately binds this PID to its original audit/birth/signature.
static inline int WB_ProcessOwnsLoopbackListener(int pid, uint16_t port) {
    if (pid <= 0 || port <= 1024) return 0;
    struct proc_fdinfo descriptors[4096];
    int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, descriptors, sizeof(descriptors));
    if (bytes <= 0 || bytes >= (int)sizeof(descriptors) || bytes % sizeof(descriptors[0])) return 0;
    int found = 0;
    for (int i = 0; i < bytes / (int)sizeof(descriptors[0]); ++i) {
        if (descriptors[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
        struct socket_fdinfo socket;
        memset(&socket, 0, sizeof(socket));
        if (proc_pidfdinfo(pid, descriptors[i].proc_fd, PROC_PIDFDSOCKETINFO, &socket, sizeof(socket)) != sizeof(socket)) continue;
        const struct socket_info *info = &socket.psi;
        if (info->soi_family != AF_INET || info->soi_kind != SOCKINFO_TCP || info->soi_type != SOCK_STREAM ||
            info->soi_protocol != IPPROTO_TCP || info->soi_proto.pri_tcp.tcpsi_state != TSI_S_LISTEN) continue;
        const struct in_sockinfo *address = &info->soi_proto.pri_tcp.tcpsi_ini;
        if ((address->insi_vflag & INI_IPV4) && ntohs((uint16_t)address->insi_lport) == port &&
            ntohl(address->insi_laddr.ina_46.i46a_addr4.s_addr) == INADDR_LOOPBACK) found++;
    }
    return found == 1;
}

// SecCode.h explicitly accepts a dynamic object for these static-typed APIs.
// Keep that documented C conversion out of Swift's CF type casts.
static inline OSStatus WB_CopyDynamicSigningInformation(SecCodeRef code, SecCSFlags flags,
    CFDictionaryRef * __nonnull CF_RETURNS_RETAINED information) {
    return SecCodeCopySigningInformation((SecStaticCodeRef)code, flags, information);
}
static inline OSStatus WB_CopyDynamicPath(SecCodeRef code, SecCSFlags flags,
    CFURLRef * __nonnull CF_RETURNS_RETAINED path) {
    return SecCodeCopyPath((SecStaticCodeRef)code, flags, path);
}
static inline OSStatus WB_CopyDynamicRequirement(SecCodeRef code, SecCSFlags flags,
    SecRequirementRef * __nonnull CF_RETURNS_RETAINED requirement) {
    return SecCodeCopyDesignatedRequirement((SecStaticCodeRef)code, flags, requirement);
}

#ifdef LOCAL_WORKBENCH_POINTER_ACCEPTANCE
#include <ApplicationServices/ApplicationServices.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <string.h>
#include <stdint.h>

// One version-qualified local acceptance diagnostic. The typed C boundary keeps
// CGRect's four-double ABI and the callee's +1 CF return convention explicit.
typedef CFArrayRef (*WB_ParkedCapture27Fn)(uint32_t, const uint32_t *, int32_t, uint32_t, CGRect);
typedef uint32_t (*WB_ParkedMain27Fn)(void);
typedef AXError (*WB_ParkedAX27Fn)(AXUIElementRef, uint32_t *);
typedef struct {
    void *sky_library;
    void *ax_library;
    WB_ParkedCapture27Fn capture;
    WB_ParkedMain27Fn main_connection;
    WB_ParkedAX27Fn ax_window;
} WB_ParkedCapture27API;

static inline int WB_ParkedImageUUID27(void *symbol, const char *path, const uint8_t expected[16]) {
    Dl_info info;
    if (!symbol || !dladdr(symbol, &info) || !info.dli_fname || strcmp(info.dli_fname, path)) return 0;
    const struct mach_header_64 *header = info.dli_fbase;
    if (!header || header->magic != MH_MAGIC_64 || header->cputype != CPU_TYPE_ARM64 ||
        header->ncmds > 100 || header->sizeofcmds > 65536) return 0;
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *end = cursor + header->sizeofcmds;
    for (uint32_t i = 0; i < header->ncmds; ++i) {
        if (cursor + sizeof(struct load_command) > end) return 0;
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) || command->cmdsize > (size_t)(end - cursor)) return 0;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != sizeof(struct uuid_command)) return 0;
            return memcmp(((const struct uuid_command *)command)->uuid, expected, 16) == 0;
        }
        cursor += command->cmdsize;
    }
    return 0;
}
static inline void WB_CloseParkedCapture27(WB_ParkedCapture27API *api) {
    if (api->sky_library) dlclose(api->sky_library);
    if (api->ax_library) dlclose(api->ax_library);
    memset(api, 0, sizeof(*api));
}
static inline int WB_ResolveParkedCapture27(WB_ParkedCapture27API *api) {
    memset(api, 0, sizeof(*api));
#if defined(__arm64__)
    const char *sky = "/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/SkyLight";
    const uint8_t sky_uuid[16] = {0x8a,0x3b,0x34,0x8e,0x46,0x37,0x36,0x85,0x92,0xd0,0x6c,0xbc,0x2f,0x36,0xa2,0x34};
    const char *his = "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/Frameworks/HIServices.framework/Versions/A/HIServices";
    const uint8_t his_uuid[16] = {0x18,0x5a,0x50,0x2d,0x7e,0x89,0x34,0x4d,0x97,0x18,0x11,0xff,0xb3,0x92,0x05,0xff};
    api->sky_library = dlopen(sky, RTLD_NOW | RTLD_LOCAL);
    api->ax_library = dlopen("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices", RTLD_NOW | RTLD_LOCAL);
    if (!api->sky_library || !api->ax_library) goto rejected;
    void *capture = dlsym(api->sky_library, "SLSHWCaptureWindowListInRect");
    void *main_connection = dlsym(RTLD_DEFAULT, "CGSMainConnectionID");
    void *ax_window = dlsym(api->ax_library, "_AXUIElementGetWindow");
    if (!WB_ParkedImageUUID27(capture, sky, sky_uuid) ||
        !WB_ParkedImageUUID27(main_connection, sky, sky_uuid) ||
        !WB_ParkedImageUUID27(ax_window, his, his_uuid)) goto rejected;
    api->capture = (WB_ParkedCapture27Fn)capture;
    api->main_connection = (WB_ParkedMain27Fn)main_connection;
    api->ax_window = (WB_ParkedAX27Fn)ax_window;
    return 1;
rejected:
    WB_CloseParkedCapture27(api);
#endif
    return 0;
}
static inline AXError WB_ParkedWindowID27(WB_ParkedCapture27API *api, AXUIElementRef element, uint32_t *window) {
    return api->ax_window ? api->ax_window(element, window) : kAXErrorNotImplemented;
}
static inline CFArrayRef _Nullable WB_CopyOwnedParkedImage27(WB_ParkedCapture27API *api,
    uint32_t window, CGRect rect, uint32_t *connection) CF_RETURNS_RETAINED {
    if (!api->capture || !api->main_connection || !window) return NULL;
    *connection = api->main_connection();
    if (!*connection) return NULL;
    return api->capture(*connection, &window, 1, 0x800, rect);
}
#endif
