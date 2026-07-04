#!/bin/bash
gcc -include ed25519_ref/shims/crypto_namespace.h \
    -Ied25519_ref/cryptoint \
    -Ied25519_ref/ref10 \
    -Ied25519_ref/shims \
    -Ied25519_ref/sha512 \
    -Ied25519_ref/hashblocks \
    -Ied25519_ref/verify32 \
    ed25519_ref/ref10/*.c \
    ed25519_ref/sha512/*.c \
    ed25519_ref/hashblocks/*.c \
    ed25519_ref/verify32/*.c \
    randombytes.c app.c \
    -o app