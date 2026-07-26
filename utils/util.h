/*
 * util.h
 *
 * Shared utilities: logging, file I/O, and LSB steganography
 * for embedding/extracting digital signatures in BMP or PNG images.
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "stb_image.h"

#define BMP_HEADER_SIZE 54
#define MAX_FILENAME 512

typedef enum {
    IMG_FORMAT_UNKNOWN = 0,
    IMG_FORMAT_BMP,
    IMG_FORMAT_PNG
} img_format_t;

/* --- Logging --- */
int  init_log(const char *log_path, const char *algorithm_name);
void close_log(void);
void log_entry(const char *input_file, const char *output_file,
               const uint8_t *sig, size_t siglen, int verified, size_t mlen, double psnr, double ssim);
void log_verification(const char *file, size_t decoded_len, int verified);

/* --- Filesystem helpers --- */
int      mkdir_if_needed(const char *path);
uint8_t *read_file(const char *path, size_t *out_len);
int      write_file(const char *path, uint8_t *buf, long size);

/* --- Format detection --- */
img_format_t detect_format(const char *path);

/* --- LSB steganography (format-agnostic entry points) --- */
void  clear_lsb(uint8_t *buf, size_t len);
int   encode(const char *in_img, const char *out_img,
             const uint8_t *message, size_t msg_len);
char *decode(const char *in_img, size_t *out_len);

/* Returns a buffer suitable for signing: for BMP, the raw file bytes
 * (LSB-cleared); for PNG, the decoded pixel buffer (LSB-cleared). */
uint8_t *get_canonical_message(const char *path, size_t *out_len);

/* Image quality metrics */
double calculate_psnr(const uint8_t *original, const uint8_t *modified, 
                      int width, int height, int channels);
double calculate_ssim(const uint8_t *original, const uint8_t *modified,
                      int width, int height, int channels);

/* Logger for keys */
void log_key_hex(const char *label, const uint8_t *data, size_t len);
void log_key_pem(const char *label, const unsigned char *pem, size_t len);

/* Timestampt */
char *timestampt(void);

#endif /* UTIL_H */