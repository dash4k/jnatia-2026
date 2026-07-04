#ifndef crypto_hash_h
#define crypto_hash_h
extern int crypto_hash(unsigned char *out, const unsigned char *in, unsigned long long inlen);
#define crypto_hash crypto_hash_sha512
#endif