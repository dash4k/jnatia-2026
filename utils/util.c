/*
 * util.c
 *
 * Implementation of shared logging, file I/O, and LSB
 * steganography utilities declared in util.h.
 *
 * BMP is handled via raw byte manipulation (uncompressed pixel data).
 * PNG is handled by decoding to a raw pixel buffer via stb_image,
 * embedding/extracting bits there, then re-encoding via stb_image_write.
 * Both formats share the same bit-packing logic on a uint8_t buffer.
 */

#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

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
               const uint8_t *sig, size_t siglen, int verified, size_t mlen, double psnr, double ssim) {
    if (!log_file) return;

    fprintf(log_file, "Input: %s\n", input_file);
    fprintf(log_file, "Output: %s\n", output_file);
    fprintf(log_file, "Message Size: %zu bytes\n", mlen);
    fprintf(log_file, "Signature Size: %zu bytes\n", siglen);
    fprintf(log_file, "Signature: ");
    for (size_t i = 0; i < siglen; i++) {
        fprintf(log_file, "%02x", sig[i]);
    }
    fprintf(log_file, "\n");
    fprintf(log_file, "Verification: %s\n", verified == 0 ? "OK" : "FAILED");
    fprintf(log_file, "SSIM value: %lf\n", ssim);
    fprintf(log_file, "PSNR value: %lf\n", psnr);
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

/* --- Format detection by magic bytes (more reliable than extension) --- */

img_format_t detect_format(const char *path) {
    uint8_t header[8] = {0};
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return IMG_FORMAT_UNKNOWN;
    }
    size_t n = fread(header, 1, sizeof(header), f);
    fclose(f);

    if (n >= 2 && header[0] == 'B' && header[1] == 'M') {
        return IMG_FORMAT_BMP;
    }

    static const uint8_t png_sig[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    if (n >= 8 && memcmp(header, png_sig, 8) == 0) {
        return IMG_FORMAT_PNG;
    }

    return IMG_FORMAT_UNKNOWN;
}

/* --- Shared bit-packing core: operates on any raw byte buffer --- */

static int pack_message(uint8_t *buf, size_t capacity,
                         const uint8_t *message, size_t msg_len) {
    size_t bits_needed = 32 + (msg_len * 8);
    if (bits_needed > capacity) {
        fprintf(stderr, "Message too large for this image (need %zu bits, have %zu)\n",
                bits_needed, capacity);
        return -1;
    }

    size_t idx = 0;
    uint32_t total_len = (uint32_t)msg_len;

    for (int i = 31; i >= 0; i--) {
        uint8_t bit = (total_len >> i) & 1;
        buf[idx] = (buf[idx] & 0xFE) | bit;
        idx++;
    }

    for (size_t i = 0; i < msg_len; i++) {
        uint8_t c = message[i];
        for (int b = 7; b >= 0; b--) {
            uint8_t bit = (c >> b) & 1;
            buf[idx] = (buf[idx] & 0xFE) | bit;
            idx++;
        }
    }

    return 0;
}

static uint8_t *unpack_message(const uint8_t *buf, size_t capacity, size_t *out_len) {
    if (capacity < 32) {
        fprintf(stderr, "Buffer too small to contain a length header\n");
        return NULL;
    }

    size_t idx = 0;
    uint32_t total_len = 0;
    for (int i = 0; i < 32; i++) {
        total_len = (total_len << 1) | (buf[idx] & 1);
        idx++;
    }

    size_t bits_needed = 32 + ((size_t)total_len * 8);
    if (total_len == 0 || bits_needed > capacity) {
        fprintf(stderr, "No valid hidden message found (bad length)\n");
        return NULL;
    }

    uint8_t *message = malloc((size_t)total_len + 1);
    if (!message) return NULL;

    for (uint32_t i = 0; i < total_len; i++) {
        uint8_t c = 0;
        for (int b = 0; b < 8; b++) {
            c = (c << 1) | (buf[idx] & 1);
            idx++;
        }
        message[i] = c;
    }
    message[total_len] = '\0';

    *out_len = total_len;
    return message;
}

/* --- BMP-specific I/O (raw byte manipulation after fixed header) --- */

static int encode_bmp(const char *in_bmp, const char *out_bmp,
                       const uint8_t *message, size_t msg_len) {
    size_t size;
    uint8_t *img = read_file(in_bmp, &size);
    if (!img) return -1;

    if (size <= BMP_HEADER_SIZE) {
        fprintf(stderr, "BMP file too small\n");
        free(img);
        return -1;
    }

    size_t capacity = size - BMP_HEADER_SIZE;
    int ret = pack_message(img + BMP_HEADER_SIZE, capacity, message, msg_len);
    if (ret != 0) {
        free(img);
        return -1;
    }

    ret = write_file(out_bmp, img, (long)size);
    free(img);
    return ret;
}

static char *decode_bmp(const char *in_bmp, size_t *out_len) {
    size_t size;
    uint8_t *img = read_file(in_bmp, &size);
    if (!img) return NULL;

    if (size <= BMP_HEADER_SIZE) {
        fprintf(stderr, "BMP file too small\n");
        free(img);
        return NULL;
    }

    uint8_t *message = unpack_message(img + BMP_HEADER_SIZE, size - BMP_HEADER_SIZE, out_len);
    free(img);
    return (char *)message;
}

/* --- PNG-specific I/O (decode to raw pixels, embed, re-encode) --- */

static int encode_png(const char *in_png, const char *out_png,
                       const uint8_t *message, size_t msg_len) {
    int w, h, channels;
    uint8_t *img = stbi_load(in_png, &w, &h, &channels, 0);
    if (!img) {
        fprintf(stderr, "Failed to load PNG: %s\n", in_png);
        return -1;
    }

    size_t capacity = (size_t)w * (size_t)h * (size_t)channels;
    int ret = pack_message(img, capacity, message, msg_len);
    if (ret != 0) {
        stbi_image_free(img);
        return -1;
    }

    ret = stbi_write_png(out_png, w, h, channels, img, w * channels);
    stbi_image_free(img);
    return ret ? 0 : -1;
}

static char *decode_png(const char *in_png, size_t *out_len) {
    int w, h, channels;
    uint8_t *img = stbi_load(in_png, &w, &h, &channels, 0);
    if (!img) {
        fprintf(stderr, "Failed to load PNG: %s\n", in_png);
        return NULL;
    }

    size_t capacity = (size_t)w * (size_t)h * (size_t)channels;
    uint8_t *message = unpack_message(img, capacity, out_len);
    stbi_image_free(img);
    return (char *)message;
}

/* --- Public dispatch: pick BMP or PNG path based on file signature --- */

int encode(const char *in_img, const char *out_img,
           const uint8_t *message, size_t msg_len) {
    img_format_t fmt = detect_format(in_img);
    switch (fmt) {
        case IMG_FORMAT_BMP:
            return encode_bmp(in_img, out_img, message, msg_len);
        case IMG_FORMAT_PNG:
            return encode_png(in_img, out_img, message, msg_len);
        default:
            fprintf(stderr, "Unsupported or unrecognized image format: %s\n", in_img);
            return -1;
    }
}

char *decode(const char *in_img, size_t *out_len) {
    img_format_t fmt = detect_format(in_img);
    switch (fmt) {
        case IMG_FORMAT_BMP:
            return decode_bmp(in_img, out_len);
        case IMG_FORMAT_PNG:
            return decode_png(in_img, out_len);
        default:
            fprintf(stderr, "Unsupported or unrecognized image format: %s\n", in_img);
            return NULL;
    }
}

uint8_t *get_canonical_message(const char *path, size_t *out_len) {
    img_format_t fmt = detect_format(path);

    if (fmt == IMG_FORMAT_BMP) {
        size_t size;
        uint8_t *buf = read_file(path, &size);
        if (!buf) return NULL;
        clear_lsb(buf, size);
        *out_len = size;
        return buf;
    }

    if (fmt == IMG_FORMAT_PNG) {
        int w, h, channels;
        uint8_t *img = stbi_load(path, &w, &h, &channels, 0);
        if (!img) return NULL;
        size_t size = (size_t)w * h * channels;
        clear_lsb(img, size);
        *out_len = size;
        return img;  /* caller frees with free(), stbi_load uses malloc internally */
    }

    return NULL;
}

/* --- Image Quality Metrics --- */

/* PSNR: Peak Signal-to-Noise Ratio
 * Measures pixel-level difference. Higher is better (typically 20-50 dB for image processing).
 * Returns -1 if images are identical (infinite PSNR). */
double calculate_psnr(const uint8_t *original, const uint8_t *modified,
                      int width, int height, int channels) {
    if (!original || !modified || width <= 0 || height <= 0 || channels <= 0) {
        return -1.0;
    }

    size_t num_pixels = (size_t)width * height * channels;
    double mse = 0.0;
    int identical = 1;

    for (size_t i = 0; i < num_pixels; i++) {
        int diff = (int)original[i] - (int)modified[i];
        if (diff != 0) identical = 0;
        mse += diff * diff;
    }

    if (identical) {
        return 100.0;  /* Identical images */
    }

    mse /= num_pixels;
    if (mse < 1e-10) return 100.0;

    /* PSNR = 20 * log10(MAX_PIXEL_VALUE / sqrt(MSE)) */
    double psnr = 20.0 * log10(255.0 / sqrt(mse));
    return psnr;
}

/* SSIM: Structural Similarity Index
 * Measures perceived quality including luminance, contrast, structure.
 * Range: -1 to 1 (1 = identical, 0 = no similarity).
 * Uses a sliding window approach with Gaussian weighting. */
double calculate_ssim(const uint8_t *original, const uint8_t *modified,
                      int width, int height, int channels) {
    if (!original || !modified || width < 11 || height < 11 || channels <= 0) {
        return -1.0;
    }

    /* SSIM constants */
    const double C1 = 6.5025;   /* (0.01 * 255)^2 */
    const double C2 = 58.5225;  /* (0.03 * 255)^2 */
    const int window_size = 11;
    const double sigma = 1.5;

    /* Build Gaussian kernel (1D, will apply separably) */
    double kernel[11];
    double sum = 0.0;
    for (int i = 0; i < window_size; i++) {
        int x = i - window_size / 2;
        kernel[i] = exp(-(x * x) / (2.0 * sigma * sigma));
        sum += kernel[i];
    }
    for (int i = 0; i < window_size; i++) {
        kernel[i] /= sum;
    }

    double ssim_sum = 0.0;
    int num_windows = 0;

    /* Slide window over image (only first channel for simplicity) */
    /* Slide window over image (full coverage, no stride) */
    for (int y = 0; y <= height - window_size; y++) {  /* removed += 4 stride */
        for (int x = 0; x <= width - window_size; x++) {
            double mu1 = 0.0, mu2 = 0.0;
            double mu1_sq = 0.0, mu2_sq = 0.0, mu1_mu2 = 0.0;
            double sigma1_sq = 0.0, sigma2_sq = 0.0, sigma12 = 0.0;

            /* Compute local means and variances */
            for (int wy = 0; wy < window_size; wy++) {
                for (int wx = 0; wx < window_size; wx++) {
                    size_t idx = ((y + wy) * width + (x + wx)) * channels;
                    double w = kernel[wy] * kernel[wx];
                    double p1 = original[idx];
                    double p2 = modified[idx];

                    mu1 += w * p1;
                    mu2 += w * p2;
                }
            }

            for (int wy = 0; wy < window_size; wy++) {
                for (int wx = 0; wx < window_size; wx++) {
                    size_t idx = ((y + wy) * width + (x + wx)) * channels;
                    double w = kernel[wy] * kernel[wx];
                    double p1 = original[idx];
                    double p2 = modified[idx];

                    double d1 = p1 - mu1;
                    double d2 = p2 - mu2;

                    mu1_sq += w * p1 * p1;
                    mu2_sq += w * p2 * p2;
                    mu1_mu2 += w * p1 * p2;
                    sigma1_sq += w * d1 * d1;
                    sigma2_sq += w * d2 * d2;
                    sigma12 += w * d1 * d2;
                }
            }

            /* SSIM formula */
            double num = (2.0 * mu1 * mu2 + C1) * (2.0 * sigma12 + C2);
            double denom = (mu1_sq + mu2_sq + C1) * (sigma1_sq + sigma2_sq + C2);
            ssim_sum += num / denom;
            num_windows++;
        }
    }

    return ssim_sum / num_windows;
}