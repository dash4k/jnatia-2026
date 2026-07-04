#!/bin/bash
gcc -DDILITHIUM_MODE=2 \
    -O3 \
    -I dilithium_ref \
    -o app \
    app.c \
    dilithium_ref/sign.c \
    dilithium_ref/packing.c \
    dilithium_ref/polyvec.c \
    dilithium_ref/poly.c \
    dilithium_ref/ntt.c \
    dilithium_ref/reduce.c \
    dilithium_ref/rounding.c \
    dilithium_ref/symmetric-shake.c \
    dilithium_ref/fips202.c \
    dilithium_ref/randombytes.c