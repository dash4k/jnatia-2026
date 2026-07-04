#include <stdio.h>
#include <stdlib.h>
#include "randombytes.h"
void randombytes(unsigned char *buf, unsigned long long len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) { fprintf(stderr, "cannot open /dev/urandom\n"); exit(1); }
    if (fread(buf, 1, len, f) != len) { fprintf(stderr, "read failed\n"); exit(1); }
    fclose(f);
}