/*
 * util.c
 *
 * Implementation of shared logging, file I/O, and BMP LSB
 * steganography utilities declared in util.h.
 */

#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

/* File-local state: only util.c needs direct access to the log handle. */
static FILE *log_file = NULL;

int init_log(const char *log_path) {
    log_file = fopen(log_path, "w");
    if (!log_file) {
        perror("fopen (log)");
        return -1;
    }

    time_t now = time(NULL);
    fprintf(log_file, "=== RSA Signature Log ===\n");
    fprintf(log_file, "Generated: %s\n", ctime(&now));
    fprintf(log_file, "============================\n\n");
    fflush(log_file);
    return 0;
}

void close_log(void) {
    if (log_file) {
        fprintf(log_file, "\n=== End of Log ===\n");
        fclose(log_file);
        log_file = NULL;
    }
}

void log_entry(const char *input_file, const char *output_file,
               const uint8_t *sig, size_t siglen, int verified) {
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

void log_verification(const char *file, size_t decoded_len, int verified) {
    if (!log_file) return;

    fprintf(log_file, "File: %s\n", file);
    fprintf(log_file, "Decoded Signature Size: %zu bytes\n", decoded_len);
    fprintf(log_file, "Verification: %s\n", verified == 0 ? "OK" : "FAILED");
    fprintf(log_file, "---\n\n");
    fflush(log_file);
}

int mkdir_if_needed(const char *path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        return mkdir(path, 0700);
    }
    return 0;
}

uint8_t *read_file(const char *path, size_t *out_len) {
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

int write_file(const char *path, uint8_t *buf, long size) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror("fopen");
        return -1;
    }

    fwrite(buf, 1, size, f);
    fclose(f);
    return 0;
}

void clear_lsb(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] &= 0xFE;
    }
}

int encode(const char *in_bmp, const char *out_bmp,
           const uint8_t *message, size_t msg_len) {
    size_t size;
    uint8_t *img = read_file(in_bmp, &size);
    if (!img) return -1;

    if (img[0] != 'B' || img[1] != 'M') {
        fprintf(stderr, "Not a valid BMP file\n");
        free(img);
        return -1;
    }

    uint32_t total_len = (uint32_t)msg_len;

    size_t bits_needed = 32 + (msg_len * 8);
    size_t pixel_data_available = (size > BMP_HEADER_SIZE) ? (size - BMP_HEADER_SIZE) : 0;

    if (bits_needed > pixel_data_available) {
        fprintf(stderr, "Message too large for this image (need %zu bits, have %zu)\n",
                bits_needed, pixel_data_available);
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
        uint8_t c = message[i];
        for (int b = 7; b >= 0; b--) {
            uint8_t bit = (c >> b) & 1;
            img[byte_idx] = (img[byte_idx] & 0xFE) | bit;
            byte_idx++;
        }
    }

    int ret = write_file(out_bmp, img, (long)size);
    free(img);
    return ret;
}

char *decode(const char *in_bmp, size_t *out_len) {
    size_t size;
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

    if (total_len == 0 || (size_t)total_len > size) {
        fprintf(stderr, "No valid hidden message found (bad length)\n");
        free(img);
        return NULL;
    }

    uint8_t *message = malloc((size_t)total_len + 1);
    if (!message) {
        free(img);
        return NULL;
    }

    for (uint32_t i = 0; i < total_len; i++) {
        uint8_t c = 0;
        for (int b = 0; b < 8; b++) {
            uint8_t bit = img[byte_idx] & 1;
            c = (c << 1) | bit;
            byte_idx++;
        }
        message[i] = c;
    }
    message[total_len] = '\0';

    *out_len = total_len;
    free(img);
    return (char *)message;
}