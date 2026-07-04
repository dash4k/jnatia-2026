/*
 * rsa_sig_api.h
 *
 * Minimal RSASSA-PKCS1-v1_5 signature API, per IETF RFC 8017 (PKCS#1 v2.2).
 * Wraps OpenSSL's BIGNUM/RSA primitives behind a small, RFC-mapped interface.
 *
 * Sections implemented:
 *   - 9.2   EMSA-PKCS1-v1_5 encoding
 *   - 5.2.1 RSASP1 (signature primitive)
 *   - 5.2.2 RSAVP1 (verification primitive)
 *   - 8.2.1 RSASSA-PKCS1-v1_5-SIGN
 *   - 8.2.2 RSASSA-PKCS1-v1_5-VERIFY
 */

#ifndef RSA_SIG_API_H
#define RSA_SIG_API_H

#include <stddef.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes returned by the API. Keep this small and explicit rather
 * than overloading a single int; makes caller error handling unambiguous. */
typedef enum {
    RSA_SIG_OK                     = 0,
    RSA_SIG_ERR_ALLOC              = -1,
    RSA_SIG_ERR_EM_TOO_SHORT        = -2, /* RFC 8017 9.2 step 3 */
    RSA_SIG_ERR_OUT_OF_RANGE        = -3, /* RFC 8017 5.2.1/5.2.2 step 1 */
    RSA_SIG_ERR_BAD_SIG_LEN         = -4, /* RFC 8017 8.2.2 step 1 */
    RSA_SIG_ERR_VERIFY_MISMATCH     = -5, /* padding/hash mismatch */
    RSA_SIG_ERR_UNSUPPORTED_HASH    = -6,
    RSA_SIG_ERR_KEYGEN              = -7,
    RSA_SIG_ERR_INTERNAL            = -8
} rsa_sig_status_t;

/* Supported hash algorithms for EMSA-PKCS1-v1_5 (Section 9.2, Note 1). */
typedef enum {
    RSA_SIG_HASH_SHA256 = 0,
    RSA_SIG_HASH_SHA384,
    RSA_SIG_HASH_SHA512
} rsa_sig_hash_t;

/* Opaque keypair handle. Internally wraps an OpenSSL RSA*. */
typedef struct rsa_sig_key rsa_sig_key_t;

/* --- Key management --- */

/* Generate a new RSA keypair. modulus_bits should be >= 2048 for any
 * current-day use (RFC 8017 gives no fixed minimum; this is general
 * best practice as of this writing). pub_exponent is usually 65537. */
rsa_sig_status_t rsa_sig_keygen(int modulus_bits, unsigned long pub_exponent,
                                 rsa_sig_key_t **out_key);

/* Load a keypair (or public-only key) from PEM data in memory. */
rsa_sig_status_t rsa_sig_key_from_pem(const unsigned char *pem_data,
                                       size_t pem_len,
                                       int is_private,
                                       rsa_sig_key_t **out_key);

void rsa_sig_key_free(rsa_sig_key_t *key);

/* Size in bytes of the modulus (== signature length, k in RFC notation). */
size_t rsa_sig_key_size(const rsa_sig_key_t *key);

/* --- Sign / verify (RFC 8017 Section 8.2) --- */

/* Sign `msg_len` bytes at `msg` with the private key in `key`.
 * `sig` must point to a buffer of at least rsa_sig_key_size(key) bytes.
 * On success, *sig_len is set to the signature length. */
rsa_sig_status_t rsa_sig_sign(const rsa_sig_key_t *key,
                               rsa_sig_hash_t hash,
                               const unsigned char *msg, size_t msg_len,
                               unsigned char *sig, size_t *sig_len);

/* Verify `sig`/`sig_len` against `msg`/`msg_len` using the public key
 * portion of `key`. Returns RSA_SIG_OK only on a valid signature. */
rsa_sig_status_t rsa_sig_verify(const rsa_sig_key_t *key,
                                 rsa_sig_hash_t hash,
                                 const unsigned char *msg, size_t msg_len,
                                 const unsigned char *sig, size_t sig_len);

/* Human-readable string for a status code, for logging/diagnostics. */
const char *rsa_sig_strerror(rsa_sig_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* RSA_SIG_API_H */