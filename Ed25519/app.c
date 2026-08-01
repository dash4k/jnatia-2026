#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <math.h>
#include "util.h"
#include "crypto_sign.h"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <input-folder> <output-folder>\n", argv[0]);
        return -1;
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

    if (mkdir_if_needed("../logs") != 0) {
        perror("mkdir");
        closedir(dir);
        return -1;
    }

    char log_path[MAX_FILENAME];
    snprintf(log_path, sizeof(log_path), "../logs/ed25519_log_%s.txt", timestampt());

    if (init_log(log_path, "Ed25519") != 0) {
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

    log_key_hex("Public Key", pk, crypto_sign_PUBLICKEYBYTES);
    log_key_hex("Secret Key", sk, crypto_sign_SECRETKEYBYTES);

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
        
        char in_path[MAX_FILENAME];
        char out_path[MAX_FILENAME];
        snprintf(in_path, sizeof(in_path), "%s/%s", argv[1], entry->d_name);
        snprintf(out_path, sizeof(out_path), "%s/ed25519_%s", argv[2], entry->d_name);

        if (detect_format(in_path) == IMG_FORMAT_UNKNOWN) {
            continue;
        }

        printf("\nProcessing: %s\n", entry->d_name);

        size_t file_size;
        uint8_t *file_message = read_file(in_path, &file_size);
        free(file_message);
        
        size_t mlen;
        uint8_t *msg = get_canonical_message(in_path, &mlen);
        if (!msg) {
            fprintf(stderr, " Failed to read file\n");
            errors++;
            continue;
        }
    
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

        int w1, h1, c1;
        uint8_t *original = stbi_load(in_path, &w1, &h1, &c1, 0);
        
        int w2, h2, c2;
        uint8_t *encoded = stbi_load(out_path, &w2, &h2, &c2, 0);

        double psnr = -1.0, ssim = -1.0;
        if (original && encoded && w1 == w2 && h1 == h2 && c1 == c2) {
            psnr = calculate_psnr(original, encoded, w1, h1, c1);
            ssim = calculate_ssim(original, encoded, w1, h1, c1);

        }

        printf(" Signed and encoded\n");
        log_entry(in_path, out_path, sig, siglen, ok, file_size, psnr, ssim);
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

        char in_path[MAX_FILENAME];
        snprintf(in_path, sizeof(in_path), "%s/%s", argv[2], entry->d_name);

        if (detect_format(in_path) == IMG_FORMAT_UNKNOWN) {
            continue;
        }
        
        printf("\nProcessing: %s\n", entry->d_name);
        
        size_t encoded_mlen;
        uint8_t *encoded_msg = get_canonical_message(in_path, &encoded_mlen);
        if (!encoded_msg) {
            fprintf(stderr, " Failed to read file\n");
            free(encoded_msg);
            errors++;
            continue;
        }

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
