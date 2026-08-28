.PHONY: all build run clean \
        build-dilithium build-ed25519 build-rsa \
        run-dilithium run-ed25519 run-rsa

ALGOS := Dilithium Ed25519 RSA

all: build run

build: build-utils build-dilithium build-ed25519 build-rsa

run: run-dilithium run-ed25519 run-rsa

build-utils:
	cd utils && gcc -c util.c -o util.o

build-dilithium:
	cd Dilithium && ./build.sh

build-ed25519:
	cd Ed25519 && ./build.sh

build-rsa:
	cd RSA && ./build.sh

run-dilithium: build-dilithium
	cd Dilithium && ./app ../inputs ../outputs/dilithium

run-ed25519: build-ed25519
	cd Ed25519 && ./app ../inputs ../outputs/ed25519

run-rsa: build-rsa
	cd RSA && ./app ../inputs ../outputs/rsa

clean:
	rm -f Dilithium/app Ed25519/app RSA/app utils/util.o && rm -rf logs/ outputs/