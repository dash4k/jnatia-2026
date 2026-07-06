#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include "util.h"
#include "rsa_ref/api.h"

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
    snprintf(log_path, sizeof(log_path), "%s/rsa_log.txt", argv[2]);

    if (init_log(log_path) != 0) {
        fprintf(stderr, "Failed to create log file\n");
        return 1;
    }

    printf("Log file: %s\n\n", log_path);

    rsa_sig_status_t st;
    rsa_sig_key_t *priv_key = NULL;

    st = rsa_sig_keygen(2048, 65537, &priv_key);
    if (st != RSA_SIG_OK) {
        fprintf(stderr, "keygen failed: %s\n", rsa_sig_strerror(st));
        return 1;
    }

    unsigned char *pub_pem = NULL;
    size_t pub_len = 0;
    st = rsa_sig_export_public_pem(priv_key, &pub_pem, &pub_len);
    if (st != RSA_SIG_OK) {
        fprintf(stderr, "export failed: %s\n", rsa_sig_strerror(st));
        rsa_sig_key_free(priv_key);
        return 1;
    }

    rsa_sig_key_t *pub_key = NULL;
    st = rsa_sig_key_from_pem(pub_pem, pub_len, /*is_private=*/0, &pub_key);
    free(pub_pem);
    if (st != RSA_SIG_OK) {
        fprintf(stderr, "loading pubkey failed: %s\n", rsa_sig_strerror(st));
        rsa_sig_key_free(priv_key);
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
    
        size_t sig_cap = rsa_sig_key_size(priv_key);
        uint8_t *sig = malloc(sig_cap);
        if (!sig) {
            fprintf(stderr, "malloc failed for signature buffer\n");
            free(msg);
            errors++;
            continue;
        }
    
        size_t siglen = 0;
        st = rsa_sig_sign(priv_key, RSA_SIG_HASH_SHA256, msg, mlen, sig, &siglen);
        if (st != RSA_SIG_OK) {
            free(msg);
            free(sig);
            errors++;
            continue;
        }
    
        st = rsa_sig_verify(pub_key, RSA_SIG_HASH_SHA256, msg, mlen, sig, siglen);
        if (st != RSA_SIG_OK) {
            fprintf(stderr, " Verification failed\n");
            free(msg);
            free(sig);
            errors++;
            continue;
        }

        if (encode(in_path, out_path, sig, siglen) != 0) {
            fprintf(stderr, "Encoding failed");
            free(msg);
            free(sig);
            return 1;
        }

        printf(" Signed and encoded\n");
        log_entry(in_path, out_path, sig, siglen, st == RSA_SIG_OK);
        free(msg);
        free(sig);
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
            fprintf(stderr, "Decoding failed\n");
            errors++;
            continue;
        }
        clear_lsb(encoded_msg, encoded_mlen);
    
        size_t decoded_len;
        uint8_t *decoded_sig = decode(in_path, &decoded_len);
        if (!decoded_sig) {
            fprintf(stderr, "Decoding failed\n");
            free(encoded_msg);
            errors++;
            continue;
        }
        
        st = rsa_sig_verify(pub_key, RSA_SIG_HASH_SHA256, encoded_msg, encoded_mlen, decoded_sig, decoded_len);
        if (st != RSA_SIG_OK) {
            fprintf(stderr, " Verification failed\n");
            free(encoded_msg);
            free(decoded_sig);
            errors++;
            continue;
        }
        
        printf(" Decoded and verified\n");
        log_verification(in_path, decoded_len, st == RSA_SIG_OK);
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
