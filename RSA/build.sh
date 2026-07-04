#!/bin/bash
rm -f app
gcc app.c \
    rsa_ref/api.o \
    -o app \
    -lssl \
    -lcrypto