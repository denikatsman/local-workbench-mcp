#ifndef LW_PROVIDER_FILE_SECURITY_H
#define LW_PROVIDER_FILE_SECURITY_H
#include <stdbool.h>
#include <sys/acl.h>
#include <errno.h>
#include <sys/stat.h>

// Mode bits alone do not describe macOS access: inherited ACLs can grant
// reads even on mode0600 files. Existing user ACLs are never edited here.
// Private provider objects accept empty/deny-only ACLs; any allow entry or
// unavailable/malformed ACL remains unverified, independent of group lookup.
static inline bool LWProviderACLAllowsOnly(int descriptor, bool allowReadEntries) {
    acl_t acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
    if (!acl) {
        // Current macOS reports ENOENT for an absent extended ACL even on an
        // open, still-linked object. Do not confuse other retrieval errors or
        // an invalid/unlinked descriptor with an empty ACL.
        int error = errno;
        struct stat value;
        return error == ENOENT && fstat(descriptor, &value) == 0 && value.st_nlink > 0;
    }
    if (acl_valid(acl) != 0) { acl_free(acl); return false; }
    bool safe = false;
    int selector = ACL_FIRST_ENTRY;
    for (unsigned int index = 0; index < 256; index++) {
        acl_entry_t entry = NULL;
        errno = 0;
        if (acl_get_entry(acl, selector, &entry) != 0) {
            // macOS returns -1/EINVAL at the end, including an empty valid ACL.
            safe = errno == EINVAL;
            break;
        }
        acl_tag_t tag;
        if (acl_get_tag_type(entry, &tag) != 0) break;
        if (tag != ACL_EXTENDED_DENY) {
            if (!allowReadEntries || tag != ACL_EXTENDED_ALLOW) break;
            acl_permset_mask_t mask = 0;
            const acl_permset_mask_t readable = ACL_READ_DATA | ACL_EXECUTE | ACL_READ_ATTRIBUTES |
                ACL_READ_EXTATTRIBUTES | ACL_READ_SECURITY;
            if (acl_get_permset_mask_np(entry, &mask) != 0 || (mask & ~readable) != 0) break;
        }
        selector = ACL_NEXT_ENTRY;
    }
    acl_free(acl);
    return safe;
}
static inline bool LWProviderHasPrivateACL(int descriptor) {
    return LWProviderACLAllowsOnly(descriptor, false);
}
// Shared/system ancestry may legitimately grant traversal or metadata reads.
// No write/delete/ownership/security-change or unknown permission is accepted.
// Private roots/files below it still require empty or deny-only ACLs.
static inline bool LWProviderHasStableAncestorACL(int descriptor) {
    return LWProviderACLAllowsOnly(descriptor, true);
}
#endif
