#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include "util.h"
#include "dilithium_ref/api.h"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <input-folder> <output-folder>\n", argv[0]);
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
    snprintf(log_path, sizeof(log_path), "%s/dilithium_log.txt", argv[2]);

    if (init_log(log_path) != 0) {
        fprintf(stderr, "Failed to create log file\n");
        return 1;
    }

    printf("Log file: %s\n\n", log_path);
    
    uint8_t pk[pqcrystals_dilithium2_ref_PUBLICKEYBYTES];
    uint8_t sk[pqcrystals_dilithium2_ref_SECRETKEYBYTES];
    
    if (pqcrystals_dilithium2_ref_keypair(pk, sk)) {
        fprintf(stderr, "keypair generation failed\n");
        closedir(dir);
        return 1;
    }
    
    struct dirent *entry;
    int count = 0;
    int errors = 0;

    printf("=================================================\n");
    printf("PHASE 1: Signing and encoding images\n");
    printf("=================================================\n");
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG || entry->d_name[0] == '.') {
            continue;
        }
        
        char in_path[MAX_FILENAME];
        char out_path[MAX_FILENAME];
        snprintf(in_path, sizeof(in_path), "%s/%s", argv[1], entry->d_name);
        snprintf(out_path, sizeof(out_path), "%s/dilithium_%s", argv[2], entry->d_name);

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
        
        uint8_t sig[pqcrystals_dilithium2_ref_BYTES];
        size_t siglen;
        
        if (pqcrystals_dilithium2_ref_signature(sig, &siglen, msg, mlen, NULL, 0, sk)) {
            fprintf(stderr, " Encoding failed\n");
            free(msg);
            errors++;
            continue;
        }

        int ok = pqcrystals_dilithium2_ref_verify(sig, siglen, (const uint8_t*)msg, mlen, NULL, 0, pk);
        if (ok != 0) {
            fprintf(stderr, " Verification failed\n");
            free(msg);
            errors++;
            continue;
        }

        if (encode(in_path, out_path, sig, siglen) != 0) {
            fprintf(stderr, " Encoding failed\n");
            free(msg);
            errors++;
            continue;
        }

        printf(" Signed and encoded\n");
        log_entry(in_path, out_path, sig, siglen, ok, file_size);
        free(msg);
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
    
    while ((entry = readdir(dir)) != NULL) {
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
            errors++;
            continue;
        }

        size_t decoded_len;
        uint8_t *decoded_sig = decode(in_path, &decoded_len);
        if (!decoded_sig) {
            fprintf(stderr, " Decoding failed\n");
            errors++;
            continue;
        }
        
        int decoded_ok = pqcrystals_dilithium2_ref_verify(decoded_sig, decoded_len, encoded_msg, encoded_mlen, NULL, 0, pk);
        if (decoded_ok != 0) {
            fprintf(stderr, " Verification failed\n");
            free(encoded_msg);
            free(decoded_sig);
            errors++;
            continue;
        }
        
        printf(" Decoded and verified\n");
        log_verification(in_path, decoded_len, decoded_ok);
        free(encoded_msg);
        free(decoded_sig);
        count++;
    }
    
    closedir(dir);
    printf("\nPhase 2 complete: Verified %d files, %d errors\n\n", count, errors);
    printf("=================================================\n");
    close_log();
    return 0;
};
