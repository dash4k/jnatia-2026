#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "crypto_sign.h"

#define BMP_HEADER_SIZE 54

void print_hex(const char *label, const uint8_t *buf, size_t len);

static uint8_t *read_file(const char *path, size_t *out_len);
static int write_file(const char *path, uint8_t *buf, long size);
static void clear_lsb(uint8_t *buf, size_t len);

static int encode(const char *in_bmp, const char *out_bmp, const uint8_t *message, size_t msg_len);
static uint8_t *decode(const char *in_bmp, size_t *out_len);

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <input-file> <output-bmp>\n", argv[0]);
        return 1;
    }

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];

    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "keypair generation failed\n");
        return 1;
    }

    size_t mlen;
    uint8_t *msg = read_file(argv[1], &mlen);
    if (!msg) {
        return 1;
    }
    clear_lsb(msg, mlen);

    printf("Read %zu bytes from %s\n", mlen, argv[1]);

    unsigned char sig[crypto_sign_BYTES];
    unsigned long long siglen = 0;

    unsigned char *sm = malloc(mlen + crypto_sign_BYTES);
    if (!sm) {
        fprintf(stderr, "malloc failed for signed message buffer\n");
        free(msg);
        return 1;
    }

    unsigned long long smlen = 0;
    if (crypto_sign(sm, &smlen, msg, mlen, sk) != 0) {
        fprintf(stderr, "signing failed\n");
        free(msg);
        free(sm);
        return 1;
    }

    memcpy(sig, sm, crypto_sign_BYTES);
    siglen = crypto_sign_BYTES;

    unsigned char *m_recovered = malloc(mlen + crypto_sign_BYTES);
    unsigned long long m_recovered_len = 0;

    int verify_result = crypto_sign_open(m_recovered, &m_recovered_len, sm, smlen, pk);
    printf("Verification: %s\n", (verify_result == 0) ? "Valid" : "Invalid");

    printf("-----------------------------------------------------------------------------\n");
    printf("Metadata:\n");
    printf("Public Key Size: %d bytes\n", crypto_sign_PUBLICKEYBYTES);
    printf("Secret Key Size: %d bytes\n", crypto_sign_SECRETKEYBYTES);
    print_hex("Public Key", pk, crypto_sign_PUBLICKEYBYTES);
    print_hex("Signature", sig, siglen);
    printf("Signature Length: %llu\n", siglen);
    printf("-----------------------------------------------------------------------------\n\n");

    if (encode(argv[1], argv[2], sig, siglen) != 0) {
        fprintf(stderr, "Encoding failed\n");
        free(msg);
        free(sm);
        free(m_recovered);
        return 1;
    }
    printf("Signature encoded into %s\n\n", argv[2]);

    size_t encoded_mlen;
    uint8_t *encoded_msg = read_file(argv[2], &encoded_mlen);
    if (!encoded_msg) {
        fprintf(stderr, "Reading encoded file failed\n");
        free(msg);
        free(sm);
        free(m_recovered);
        return 1;
    }
    clear_lsb(encoded_msg, encoded_mlen);

    size_t decoded_len;
    uint8_t *decoded_sig = decode(argv[2], &decoded_len);
    if (!decoded_sig) {
        fprintf(stderr, "Decoding failed\n");
        free(msg);
        free(sm);
        free(m_recovered);
        free(encoded_msg);
        return 1;
    }

    printf("Decoded %zu bytes from %s\n", decoded_len, argv[2]);

    if (decoded_len != siglen) {
        fprintf(stderr, "ERROR: Decoded signature length mismatch (expected %zu, got %zu)\n", (size_t)siglen, decoded_len);
        free(msg);
        free(sm);
        free(m_recovered);
        free(encoded_msg);
        free(decoded_sig);
        return 1;
    }

    unsigned char *sm_decoded = malloc(encoded_mlen + crypto_sign_BYTES);
    unsigned long long sm_decoded_len = 0;
    memcpy(sm_decoded, decoded_sig, decoded_len);
    memcpy(sm_decoded + decoded_len, encoded_msg, encoded_mlen);
    sm_decoded_len = decoded_len + encoded_mlen;

    int verify_decoded = crypto_sign_open(m_recovered, &m_recovered_len, sm_decoded, sm_decoded_len, pk);
    printf("Decoded Signature Verification: %s\n", (verify_decoded == 0) ? "Valid" : "Invalid");

    print_hex("Decoded Signature", decoded_sig, decoded_len);

    free(msg);
    free(sm);
    free(m_recovered);
    free(encoded_msg);
    free(decoded_sig);
    free(sm_decoded);
    return 0;
}

void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n\n");
}

static uint8_t *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return NULL;
    }

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
}

static int write_file(const char *path, uint8_t *buf, long size) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror("fopen");
        return -1;
    }

    fwrite(buf, 1, size, f);
    fclose(f);
    return 0;
}

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
    }

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
}

static uint8_t *decode(const char *in_bmp, size_t *out_len) {
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

    uint8_t *message = malloc(total_len);
    for (uint32_t i = 0; i < total_len; i++) {
        uint8_t c = 0;
        for (int b = 0; b < 8; b++) {
            uint8_t bit = img[byte_idx] & 1;
            c = (c << 1) | bit;
            byte_idx++;
        }
        message[i] = c;
    }

    *out_len = total_len;
    free(img);
    return message;
}