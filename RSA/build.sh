#!/bin/bash
rm -f app
gcc app.c \
    ../utils/util.o \
    rsa_ref/api.o \
    -I../utils \
    -o app \
    -lssl \
    -lcrypto \
    -lm