#ifndef crypto_hashblocks_h
#define crypto_hashblocks_h
extern int crypto_hashblocks(unsigned char *statebytes, const unsigned char *in, unsigned long long inlen);
#define crypto_hashblocks crypto_hashblocks_sha512
#endif