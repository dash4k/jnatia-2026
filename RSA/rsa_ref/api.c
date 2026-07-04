/*
 * api.c
 *
 * Implementation of the RSASSA-PKCS1-v1_5 API declared in api.h,
 * following IETF RFC 8017 (PKCS#1 v2.2), using OpenSSL 3.0's EVP_PKEY API.
 */

#include "api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

struct rsa_sig_key {
    EVP_PKEY *pkey;
    int has_private;
};

/* ---------------------------------------------------------------------
 * DER-encoded DigestInfo prefixes, per RFC 8017 Section 9.2, Note 1.
 * ------------------------------------------------------------------- */

static const unsigned char SHA256_PREFIX[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};
static const unsigned char SHA384_PREFIX[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30
};
static const unsigned char SHA512_PREFIX[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40
};

static int compute_digest(rsa_sig_hash_t hash,
                           const unsigned char *msg, size_t msg_len,
                           unsigned char *digest_out, size_t *digest_len_out,
                           const unsigned char **prefix_out,
                           size_t *prefix_len_out,
                           const EVP_MD **md_out)
{
    switch (hash) {
    case RSA_SIG_HASH_SHA256:
        SHA256(msg, msg_len, digest_out);
        *digest_len_out = SHA256_DIGEST_LENGTH;
        *prefix_out = SHA256_PREFIX;
        *prefix_len_out = sizeof(SHA256_PREFIX);
        *md_out = EVP_sha256();
        return 0;
    case RSA_SIG_HASH_SHA384:
        SHA384(msg, msg_len, digest_out);
        *digest_len_out = SHA384_DIGEST_LENGTH;
        *prefix_out = SHA384_PREFIX;
        *prefix_len_out = sizeof(SHA384_PREFIX);
        *md_out = EVP_sha384();
        return 0;
    case RSA_SIG_HASH_SHA512:
        SHA512(msg, msg_len, digest_out);
        *digest_len_out = SHA512_DIGEST_LENGTH;
        *prefix_out = SHA512_PREFIX;
        *prefix_len_out = sizeof(SHA512_PREFIX);
        *md_out = EVP_sha512();
        return 0;
    default:
        return -1;
    }
}

/* ---------------------------------------------------------------------
 * RFC 8017 Section 9.2: EMSA-PKCS1-v1_5-ENCODE(M, emLen)
 * Kept exactly as before — this is pure RFC bit-twiddling and doesn't
 * touch the deprecated RSA* API at all.
 * ------------------------------------------------------------------- */
static rsa_sig_status_t emsa_pkcs1_v15_encode(rsa_sig_hash_t hash,
                                               const unsigned char *msg,
                                               size_t msg_len,
                                               unsigned char *em,
                                               size_t em_len)
{
    unsigned char digest[64];
    size_t digest_len;
    const unsigned char *prefix;
    size_t prefix_len;
    const EVP_MD *md;

    if (compute_digest(hash, msg, msg_len, digest, &digest_len,
                        &prefix, &prefix_len, &md) != 0)
        return RSA_SIG_ERR_UNSUPPORTED_HASH;

    size_t t_len = prefix_len + digest_len;

    if (em_len < t_len + 11)
        return RSA_SIG_ERR_EM_TOO_SHORT;

    size_t ps_len = em_len - t_len - 3;
    size_t i = 0;

    em[i++] = 0x00;
    em[i++] = 0x01;
    memset(em + i, 0xff, ps_len);
    i += ps_len;
    em[i++] = 0x00;
    memcpy(em + i, prefix, prefix_len);
    i += prefix_len;
    memcpy(em + i, digest, digest_len);
    i += digest_len;

    return (i == em_len) ? RSA_SIG_OK : RSA_SIG_ERR_INTERNAL;
}

/* ======================================================================
 * Public API
 * ==================================================================== */

rsa_sig_status_t rsa_sig_keygen(int modulus_bits, unsigned long pub_exponent,
                                 rsa_sig_key_t **out_key)
{
    if (!out_key)
        return RSA_SIG_ERR_INTERNAL;

    rsa_sig_key_t *key = calloc(1, sizeof(*key));
    if (!key)
        return RSA_SIG_ERR_ALLOC;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) {
        free(key);
        return RSA_SIG_ERR_ALLOC;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        free(key);
        return RSA_SIG_ERR_KEYGEN;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, modulus_bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        free(key);
        return RSA_SIG_ERR_KEYGEN;
    }

    BIGNUM *e = BN_new();
    BN_set_word(e, pub_exponent);
    if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e) <= 0) {
        BN_free(e);
        EVP_PKEY_CTX_free(ctx);
        free(key);
        return RSA_SIG_ERR_KEYGEN;
    }
    BN_free(e); /* set1_ copies internally, safe to free */

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        free(key);
        return RSA_SIG_ERR_KEYGEN;
    }

    EVP_PKEY_CTX_free(ctx);
    key->pkey = pkey;
    key->has_private = 1;
    *out_key = key;
    return RSA_SIG_OK;
}

rsa_sig_status_t rsa_sig_key_from_pem(const unsigned char *pem_data,
                                       size_t pem_len,
                                       int is_private,
                                       rsa_sig_key_t **out_key)
{
    if (!out_key || !pem_data)
        return RSA_SIG_ERR_INTERNAL;

    BIO *bio = BIO_new_mem_buf(pem_data, (int)pem_len);
    if (!bio)
        return RSA_SIG_ERR_ALLOC;

    rsa_sig_key_t *key = calloc(1, sizeof(*key));
    if (!key) {
        BIO_free(bio);
        return RSA_SIG_ERR_ALLOC;
    }

    if (is_private) {
        key->pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        key->has_private = 1;
    } else {
        key->pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        key->has_private = 0;
    }

    BIO_free(bio);

    if (!key->pkey) {
        free(key);
        return RSA_SIG_ERR_INTERNAL;
    }

    *out_key = key;
    return RSA_SIG_OK;
}

void rsa_sig_key_free(rsa_sig_key_t *key)
{
    if (!key)
        return;
    EVP_PKEY_free(key->pkey);
    free(key);
}

size_t rsa_sig_key_size(const rsa_sig_key_t *key)
{
    if (!key || !key->pkey)
        return 0;
    return (size_t)EVP_PKEY_get_size(key->pkey); /* k, per RFC 8017 notation */
}

/* RFC 8017 Section 8.2.1: RSASSA-PKCS1-v1_5-SIGN(K, M)
 *
 * We keep the manual EMSA-PKCS1-v1_5 padding step (for RFC fidelity /
 * education) but hand the *raw* padded block to EVP_PKEY_sign with
 * padding disabled (RSA_NO_PADDING), so this is still literally doing
 * RSASP1 = m^d mod n via the modern API, not EVP's built-in
 * hash-then-pad-then-sign shortcut. */
rsa_sig_status_t rsa_sig_sign(const rsa_sig_key_t *key,
                               rsa_sig_hash_t hash,
                               const unsigned char *msg, size_t msg_len,
                               unsigned char *sig, size_t *sig_len)
{
    if (!key || !key->pkey || !key->has_private || !msg || !sig || !sig_len)
        return RSA_SIG_ERR_INTERNAL;

    size_t k = rsa_sig_key_size(key);
    rsa_sig_status_t status = RSA_SIG_OK;

    unsigned char *em = malloc(k);
    if (!em)
        return RSA_SIG_ERR_ALLOC;

    /* Step 1: EMSA-PKCS1-v1_5 encoding */
    status = emsa_pkcs1_v15_encode(hash, msg, msg_len, em, k);
    if (status != RSA_SIG_OK) {
        free(em);
        return status;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->pkey, NULL);
    if (!ctx) {
        free(em);
        return RSA_SIG_ERR_ALLOC;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) <= 0) {
        status = RSA_SIG_ERR_INTERNAL;
        goto cleanup;
    }

    /* Step 2b+2c combined: raw RSASP1 exponentiation on the already-padded
     * block em, producing the k-byte signature directly. */
    size_t out_len = k;
    if (EVP_PKEY_sign(ctx, sig, &out_len, em, k) <= 0) {
        status = RSA_SIG_ERR_INTERNAL;
        goto cleanup;
    }
    *sig_len = out_len;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    free(em);
    return status;
}

/* RFC 8017 Section 8.2.2: RSASSA-PKCS1-v1_5-VERIFY((n, e), M, S)
 *
 * Same approach: raw RSAVP1 via EVP_PKEY_verify_recover with
 * RSA_NO_PADDING, then manually re-derive and compare EM ourselves
 * (constant-time), matching the RFC's explicit steps rather than
 * delegating the comparison to EVP_PKEY_verify's built-in padding check. */
rsa_sig_status_t rsa_sig_verify(const rsa_sig_key_t *key,
                                 rsa_sig_hash_t hash,
                                 const unsigned char *msg, size_t msg_len,
                                 const unsigned char *sig, size_t sig_len)
{
    if (!key || !key->pkey || !msg || !sig)
        return RSA_SIG_ERR_INTERNAL;

    size_t k = rsa_sig_key_size(key);

    /* Step 1: length check */
    if (sig_len != k)
        return RSA_SIG_ERR_BAD_SIG_LEN;

    rsa_sig_status_t status = RSA_SIG_OK;
    unsigned char *em = NULL;
    unsigned char *em_expected = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->pkey, NULL);
    if (!ctx)
        return RSA_SIG_ERR_ALLOC;

    if (EVP_PKEY_verify_recover_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) <= 0) {
        status = RSA_SIG_ERR_INTERNAL;
        goto cleanup;
    }

    em = malloc(k);
    em_expected = malloc(k);
    if (!em || !em_expected) {
        status = RSA_SIG_ERR_ALLOC;
        goto cleanup;
    }

    /* Step 2: m = RSAVP1((n, e), s), recovered as the raw padded block */
    size_t em_len = k;
    if (EVP_PKEY_verify_recover(ctx, em, &em_len, sig, sig_len) <= 0 ||
        em_len != k) {
        status = RSA_SIG_ERR_OUT_OF_RANGE;
        goto cleanup;
    }

    /* Step 3/4: re-encode M ourselves and compare in constant time,
     * exactly per the RFC, rather than trusting EVP's own check. */
    status = emsa_pkcs1_v15_encode(hash, msg, msg_len, em_expected, k);
    if (status != RSA_SIG_OK)
        goto cleanup;

    if (CRYPTO_memcmp(em, em_expected, k) != 0)
        status = RSA_SIG_ERR_VERIFY_MISMATCH;

cleanup:
    free(em);
    free(em_expected);
    EVP_PKEY_CTX_free(ctx);
    return status;
}

const char *rsa_sig_strerror(rsa_sig_status_t status)
{
    switch (status) {
    case RSA_SIG_OK:                  return "success";
    case RSA_SIG_ERR_ALLOC:           return "memory allocation failure";
    case RSA_SIG_ERR_EM_TOO_SHORT:    return "intended encoded message length too short (RFC 8017 9.2 step 3)";
    case RSA_SIG_ERR_OUT_OF_RANGE:    return "representative out of range (RFC 8017 5.2.1/5.2.2 step 1)";
    case RSA_SIG_ERR_BAD_SIG_LEN:     return "invalid signature length (RFC 8017 8.2.2 step 1)";
    case RSA_SIG_ERR_VERIFY_MISMATCH: return "signature verification failed";
    case RSA_SIG_ERR_UNSUPPORTED_HASH:return "unsupported hash algorithm";
    case RSA_SIG_ERR_KEYGEN:          return "RSA key generation failed";
    case RSA_SIG_ERR_INTERNAL:        return "internal error / invalid argument";
    default:                          return "unknown status";
    }
}