/*
 * util.h
 *
 * Shared utilities: logging, file I/O, and BMP LSB steganography
 * for embedding/extracting digital signatures.
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#define BMP_HEADER_SIZE 54
#define MAX_FILENAME 512

/* --- Logging --- */
int  init_log(const char *log_path);
void close_log(void);
void log_entry(const char *input_file, const char *output_file,
               const uint8_t *sig, size_t siglen, int verified);
void log_verification(const char *file, size_t decoded_len, int verified);

/* --- Filesystem helpers --- */
int      mkdir_if_needed(const char *path);
uint8_t *read_file(const char *path, size_t *out_len);
int      write_file(const char *path, uint8_t *buf, long size);

/* --- BMP LSB steganography --- */
void  clear_lsb(uint8_t *buf, size_t len);
int   encode(const char *in_bmp, const char *out_bmp,
             const uint8_t *message, size_t msg_len);
char *decode(const char *in_bmp, size_t *out_len);

#endif /* UTIL_H */