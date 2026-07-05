#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include "crypto_sign.h"

#define BMP_HEADER_SIZE 54
#define MAX_FILENAME 512

static FILE *log_file = NULL;

static int init_log(const char *log_path);
static void close_log(void);
static void log_entry(const char *input_file, const char *output_file, const uint8_t * sig, size_t siglen, int verified);
static void log_verification(const char *file, size_t decoded_len, int verified);

static int mkdir_if_needed(const char *path);
static uint8_t *read_file(const char *path, size_t *out_len);
static int write_file(const char *path, uint8_t *buf, long size);
static void clear_lsb(uint8_t *buf, size_t len);

static int encode(const char *in_bmp, const char *out_bmp, const uint8_t *message, size_t msg_len);
static uint8_t *decode(const char *in_bmp, size_t *out_len);

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <input-folder> <output-folder>\n", argv[0]);
        return 1;
    }

    DIR *dir = opendir(argv[1]);
    if (!dir) {
        perror("opendir");
        return -1;
    }
    
    if (mkdir_if_needed(argv[2]) != 0) {
        perror("mkdir");
        closedir(dir);
        return -1;
    }

    char log_path[MAX_FILENAME];
    snprintf(log_path, sizeof(log_path), "%s/ed25519_log.txt", argv[2]);

    if (init_log(log_path) != 0) {
        fprintf(stderr, "Failed to create log file\n");
        return 1;
    }

    printf("Log file: %s\n\n", log_path);

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];

    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "keypair generation failed\n");
        return 1;
    }

    struct dirent *entry;
    int count = 0;
    int errors = 0;

    printf("=================================================\n");
    printf("PHASE 1: Signing and encoding images\n");
    printf("=================================================\n");

    while ((entry = readdir(dir)) != NULL ) {
        if (entry->d_type != DT_REG || entry->d_name[0] == '.') {
            continue;
        }

        const char *ext = strrchr(entry->d_name, '.');
        if (!ext || strcasecmp(ext, ".bmp") != 0) {
            continue;
        }
        
        char in_path[MAX_FILENAME];
        char out_path[MAX_FILENAME];
        snprintf(in_path, sizeof(in_path), "%s/%s", argv[1], entry->d_name);
        snprintf(out_path, sizeof(out_path), "%s/output_%d.bmp", argv[2], count);

        printf("\nProcessing: %s\n", entry->d_name);
        
        size_t mlen;
        uint8_t *msg = read_file(in_path, &mlen);
        if (!msg) {
            fprintf(stderr, " Failed to read file\n");
            errors++;
            continue;
        }
        clear_lsb(msg, mlen);
    
        unsigned char sig[crypto_sign_BYTES];
        unsigned long long siglen = 0;
    
        unsigned char *sm = malloc(mlen + crypto_sign_BYTES);
        if (!sm) {
            fprintf(stderr, "malloc failed for signed message buffer\n");
            free(msg);
            errors++;
            continue;
        }
    
        unsigned long long smlen = 0;
        if (crypto_sign(sm, &smlen, msg, mlen, sk) != 0) {
            fprintf(stderr, "signing failed\n");
            free(msg);
            free(sm);
            errors++;
            continue;
        }
    
        memcpy(sig, sm, crypto_sign_BYTES);
        siglen = crypto_sign_BYTES;
    
        unsigned char *m_recovered = malloc(mlen + crypto_sign_BYTES);
        unsigned long long m_recovered_len = 0;
    
        int ok = crypto_sign_open(m_recovered, &m_recovered_len, sm, smlen, pk);
        if (ok != 0) {
            fprintf(stderr, " Verification failed\n");
            free(msg);
            free(sm);
            free(m_recovered);
            errors++;
            continue;
        }
        
        if (encode(in_path, out_path, sig, siglen) != 0) {
            fprintf(stderr, "Encoding failed\n");
            free(msg);
            free(sm);
            free(m_recovered);
            return 1;
        }

        printf(" Signed and encoded\n");
        log_entry(in_path, out_path, sig, siglen, ok);
        free(msg);
        free(sm);
        free(m_recovered);
        count++;
    }

    closedir(dir);
    printf("\nPhase 1 complete: Processed %d files, %d errors\n\n", count, errors);
    printf("=================================================\n");
    
    printf("PHASE 2: Decoding and verifying signatures\n");
    printf("=================================================\n");
    
    dir = opendir(argv[2]);
    if (!dir) {
        perror("opendir");
        return -1;
    }
    
    count = 0;
    errors = 0;

    while ((entry = readdir(dir)) != NULL ) {
        if (entry->d_type != DT_REG || entry->d_name[0] == '.') {
            continue;
        }
        
        const char *ext = strrchr(entry->d_name, '.');
        if (!ext || strcasecmp(ext, ".bmp") != 0) {
            continue;
        }

        char in_path[MAX_FILENAME];
        snprintf(in_path, sizeof(in_path), "%s/%s", argv[2], entry->d_name);
        
        printf("\nProcessing: %s\n", entry->d_name);
        
        size_t encoded_mlen;
        uint8_t *encoded_msg = read_file(in_path, &encoded_mlen);
        if (!encoded_msg) {
            fprintf(stderr, " Failed to read file\n");
            free(encoded_msg);
            errors++;
            continue;
        }
        clear_lsb(encoded_msg, encoded_mlen);

        size_t decoded_len;
        uint8_t *decoded_sig = decode(in_path, &decoded_len);
        if (!decoded_sig) {
            fprintf(stderr, " Decoding failed\n");
            free(encoded_msg);
            free(decoded_sig);
            errors++;
            continue;
        }

        
        unsigned char *sm_decoded = malloc(encoded_mlen + crypto_sign_BYTES);
        unsigned long long sm_decoded_len = 0;
        memcpy(sm_decoded, decoded_sig, decoded_len);
        memcpy(sm_decoded + decoded_len, encoded_msg, encoded_mlen);
        sm_decoded_len = decoded_len + encoded_mlen;
        
        unsigned char *m_recovered = malloc(encoded_mlen + crypto_sign_BYTES);
        unsigned long long m_recovered_len = 0;

        int decoded_ok = crypto_sign_open(m_recovered, &m_recovered_len, sm_decoded, sm_decoded_len, pk);
        if (decoded_ok != 0) {
            fprintf(stderr, " Verification failed\n");
            free(m_recovered);
            free(encoded_msg);
            free(decoded_sig);
            free(sm_decoded);
            errors++;
            continue;
        }

        printf(" Decoded and verified\n");
        log_verification(in_path, decoded_len, decoded_ok);
        free(m_recovered);
        free(encoded_msg);
        free(decoded_sig);
        free(sm_decoded);
        count++;
    }

    closedir(dir);
    printf("\nPhase 2 complete: Verified %d files, %d errors\n\n", count, errors);
    printf("=================================================\n");
    close_log();
    return 0;
}

static int init_log(const char *log_path) {
    log_file = fopen(log_path, "w");
    if (!log_file) {
        perror("fopen (log)");
        return -1;
    }

    time_t now = time(NULL);
    fprintf(log_file, "=== Ed25519 Signature Log ===\n");
    fprintf(log_file, "Generated: %s\n", ctime(&now));
    fprintf(log_file, "============================\n\n");
    fflush(log_file);
    return 0;
}

static void close_log(void) {
    if (log_file) {
        fprintf(log_file, "\n=== End of Log ===\n");
        fclose(log_file);
    }
}

static void log_entry(const char *input_file, const char *output_file, const uint8_t * sig, size_t siglen, int verified) {
    if (!log_file) return;

    fprintf(log_file, "Input: %s\n", input_file);
    fprintf(log_file, "Output: %s\n", output_file);
    fprintf(log_file, "Signature Size: %zu bytes\n", siglen);
    fprintf(log_file, "Signature: ");
    for (size_t i = 0; i < siglen; i++) {
        fprintf(log_file, "%02x", sig[i]);
    }
    fprintf(log_file, "\n");
    fprintf(log_file, "Verification: %s\n", verified == 0 ? "OK" : "FAILED");
    fprintf(log_file, "---\n\n");
    fflush(log_file);
}

static void log_verification(const char *file, size_t decoded_len, int verified) {
    if (!log_file) return;

    fprintf(log_file, "File: %s\n", file);
    fprintf(log_file, "Decoded Signature Size: %zu bytes\n", decoded_len);
    fprintf(log_file, "Verification: %s\n", verified == 0 ? "OK" : "FAILED");
    fprintf(log_file, "---\n\n");
    fflush(log_file);
}

static int mkdir_if_needed(const char *path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        return mkdir(path, 0700);
    }
    return 0;
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