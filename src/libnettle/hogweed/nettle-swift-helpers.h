#include <nettle/rsa.h>

/* Some GMP routines are visible to C here, but not to Swift, at least
 * not in a useful way.  The Swift-C importer is smart enough to
 * understand these inlines and produce a usable interface for Swift
 * code.
 */

static inline void nettle_swift_mpz_init(mpz_ptr v)
{
  mpz_init(v);
}

static inline void nettle_swift_mpz_clear(mpz_ptr v)
{
  mpz_clear(v);
}

static inline void nettle_swift_mpz_set_ui(mpz_ptr v, unsigned long va)
{
  mpz_set_ui(v, va);
}

static inline int nettle_swift_mpz_odd_p(mpz_srcptr v)
{
  return mpz_odd_p(v);
}

static inline int nettle_swift_mpz_cmp(mpz_srcptr l, mpz_srcptr r) {
  return mpz_cmp(l, r);
}

static inline int nettle_swift_mpz_sizeinbase_2(mpz_srcptr v) {
  return mpz_sizeinbase(v, 2);
}
