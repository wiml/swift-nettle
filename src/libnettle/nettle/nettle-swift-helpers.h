
#ifndef NETTLE_SWIFT_HELPERS_H
#define NETTLE_SWIFT_HELPERS_H

#include <nettle/nettle-meta.h>

/* It's not possible (at least as of Swift 5) to obtain a pointer
 * to an externally defined const struct. These inlines allow
 * the hash structs to be visible to Swift code in a useful
 * way. In "release" builds, the compiler is smart enough to fully
 * inline this, like you'd hope.
 */

static inline const struct nettle_hash * _Nonnull nettle_swift_sha1_ptr()   { return &nettle_sha1; }
static inline const struct nettle_hash * _Nonnull nettle_swift_sha224_ptr() { return &nettle_sha224; }
static inline const struct nettle_hash * _Nonnull nettle_swift_sha256_ptr() { return &nettle_sha256; }
static inline const struct nettle_hash * _Nonnull nettle_swift_sha384_ptr() { return &nettle_sha384; }
static inline const struct nettle_hash * _Nonnull nettle_swift_sha512_ptr() { return &nettle_sha512; }

#endif /* NETTLE_SWIFT_HELPERS_H */
