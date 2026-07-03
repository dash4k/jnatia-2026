#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "api.h"

#define BMP_HEADER_SIZE 54

void print_hex(const char *label, const uint8_t *buf, size_t len);

static uint8_t *read_file(const char *path, size_t *out_len);
static int write_file(const char *path, uint8_t *buf, long size);
static void clear_lsb(uint8_t *buf, size_t len);

static int encode(const char *in_bmp, const char *out_bmp, const uint8_t *message, size_t msg_len);
static char *decode(const char *in_bmp, size_t *out_len);

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path-to-image>\n", argv[0]);
    }

    size_t mlen;
    uint8_t *msg = read_file(argv[1], &mlen);
    clear_lsb(msg, mlen);

    printf("Read %zu bytes from %s\n", mlen, argv[1]);
    
    uint8_t pk[pqcrystals_dilithium2_ref_PUBLICKEYBYTES];
    uint8_t sk[pqcrystals_dilithium2_ref_SECRETKEYBYTES];
    uint8_t sig[pqcrystals_dilithium2_ref_BYTES];
    size_t siglen;

    if (pqcrystals_dilithium2_ref_keypair(pk, sk)) {
        fprintf(stderr, "keypair generation failed\n");
        free(msg);
        return 1;
    }

    if (pqcrystals_dilithium2_ref_signature(sig, &siglen, (const uint8_t*)msg, mlen, NULL, 0, sk)) {
        fprintf(stderr, "signing failed\n");
        free(msg);
        return 1;
    }

    int ok = pqcrystals_dilithium2_ref_verify(sig, siglen, (const uint8_t*)msg, mlen, NULL, 0, pk);
    printf("Verification: %s\n", ok == 0 ? "Valid" : "Invalid");

    printf("-----------------------------------------------------------------------------\n");
    printf("Metadata:\n");
    print_hex("Public Key", pk, sizeof(pk));
    print_hex("Secret Key", sk, sizeof(sk));
    print_hex("Signature", sig, sizeof(sig));
    printf("Signature Length: %zu\n", siglen);
    printf("-----------------------------------------------------------------------------\n\n");

    if (encode(argv[1], argv[2], sig, siglen) != 0) {
        fprintf(stderr, "Encoding failed");
        free(msg);
        return 1;
    }
    printf("Signature encoded into %s\n\n", argv[2]);

    size_t encoded_mlen;
    uint8_t *encoded_msg = read_file(argv[2], &encoded_mlen);
    clear_lsb(encoded_msg, encoded_mlen);

    size_t decoded_len;
    uint8_t *decoded_sig = decode(argv[2], &decoded_len);
    if (!decoded_sig) {
        fprintf(stderr, "Decoding failed\n");
        free(msg);
        return 1;
    }

    printf("Decoded %zu bytes from %s\n", decoded_len, argv[2]);

    if (decoded_len != siglen) {
        fprintf(stderr, "ERROR: Dedocded signature length mismatch (expected %zu, got %zu)\n", siglen, decoded_len);
        free(msg);
        free(decoded_sig);
        return 1;
    }

    int decoded_ok = pqcrystals_dilithium2_ref_verify(decoded_sig, decoded_len, encoded_msg, encoded_mlen, NULL, 0, pk);
    printf("Decoded Signature Verification: %s\n", decoded_ok == 0 ? "Valid" : "Invalid");

    print_hex("Decoded Signature", decoded_sig, decoded_len);
    
    free(msg);
    free(decoded_sig);
    return 0;
};

void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n\n");
};

static uint8_t *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return NULL;
    };

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    if (size < 0) {
        perror("ftell");
        fclose(f);
        return NULL;
    }
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = malloc(size);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        fclose(f);
        return NULL;
    }

    size_t read = fread(buf, 1, size, f);
    fclose(f);

    if (read != (size_t)size) {
        fprintf(stderr, "short read\n");
        free(buf);
        return NULL;
    }

    *out_len = (size_t)size;
    return buf;
};

static int write_file(const char *path, uint8_t *buf, long size) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror("fopen");
        return -1;
    }

    fwrite(buf, 1, size, f);
    fclose(f);
    return 0;
};

static void clear_lsb(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] &= 0xFE;
    }
}

static int encode(const char *in_bmp, const char *out_bmp, const uint8_t *message, size_t msg_len) {
    long size;
    uint8_t *img = read_file(in_bmp, &size);
    if (!img) return -1;

    if (img[0] != 'B' || img[1] != 'M') {
        fprintf(stderr, "Not a valid BMP file\n");
        free(img);
        return -1;
    }

    uint32_t total_len = (uint32_t)msg_len;

    size_t bits_needed = 32 + (msg_len * 8);
    size_t pixel_data_available = (size - BMP_HEADER_SIZE) * 1;

    if (bits_needed > pixel_data_available) {
        fprintf(stderr, "Message too large for this image (need %zu bits, have %zu)\n", bits_needed, pixel_data_available);
        free(img);
        return -1;
    };

    size_t byte_idx = BMP_HEADER_SIZE;

    for (int i = 31; i >= 0; i--) {
        uint8_t bit = (total_len >> i) & 1;
        img[byte_idx] = (img[byte_idx] & 0xFE) | bit;
        byte_idx++;
    }

    for (size_t i = 0; i < msg_len; i++) {
        uint8_t c = (uint8_t)message[i];
        for (int b = 7; b >= 0; b--) {
            uint8_t bit = (c >> b) & 1;
            img[byte_idx] = (img[byte_idx] & 0xFE) | bit;
            byte_idx++;
        }
    }

    int ret = write_file(out_bmp, img, size);
    free(img);
    return ret;
};

static char *decode(const char *in_bmp, size_t *out_len) {
    long size;
    uint8_t *img = read_file(in_bmp, &size);
    if (!img) return NULL;

    if (img[0] != 'B' || img[1] != 'M') {
        fprintf(stderr, "Not a valid BMP file\n");
        free(img);
        return NULL;
    }

    size_t byte_idx = BMP_HEADER_SIZE;

    uint32_t total_len = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t bit = img[byte_idx] & 1;
        total_len = (total_len << 1) | bit;
        byte_idx++;
    }

    if (total_len == 0 || total_len > (uint32_t)size) {
        fprintf(stderr, "No valid hidden message found (bad length)\n");
        free(img);
        return NULL;
    }

    uint8_t *message = malloc(total_len + 1);
    for (uint32_t i = 0; i <total_len; i++) {
        uint8_t c = 0;
        for (int b = 0; b < 8; b++) {
            uint8_t bit = img[byte_idx] & 1;
            c = (c << 1) | bit;
            byte_idx++;
        }
        message[i] = (char)c;
    }
    message[total_len] = '\0';

    *out_len = total_len;
    free(img);
    return message;
}