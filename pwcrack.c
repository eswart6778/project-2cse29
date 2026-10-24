#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>

#define MAX_PASSWORD_LEN 256

// Helper function to compute SHA256 hash of a string and return it as a hex string
void compute_sha256(const char *str, char output_hex[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)str, strlen(str), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output_hex + (i * 2), "%02x", hash[i]);
    }
    output_hex[64] = '\0';
}

// Checks if candidate password's hash matches the target hash
int try_password(const char *candidate, const char *target_hash) {
    char computed_hash[65];
    compute_sha256(candidate, computed_hash);
    
    if (strcmp(computed_hash, target_hash) == 0) {
        printf("Found password: SHA256(%s) = %s\n", candidate, target_hash);
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <sha256_hash>\n", argv[0]);
        return 1;
    }

    char *target_hash = argv[1];
    char line[MAX_PASSWORD_LEN];

    // Read potential passwords from stdin line by line
    while (fgets(line, sizeof(line), stdin) != NULL) {
        // Remove trailing newline character(s) if present
        size_t len = strlen(line);
        if (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[len - 1] = '\0';
            len--;
        }

        // 1. Check the original password as-is
        if (try_password(line, target_hash)) {
            return 0;
        }

        // 2. Check single-character case mutations (uppercase and lowercase)
        for (int i = 0; i < len; i++) {
            char variant[MAX_PASSWORD_LEN];

            // Test uppercase mutation at index i
            strcpy(variant, line);
            variant[i] = toupper((unsigned char)variant[i]);
            if (try_password(variant, target_hash)) {
                return 0;
            }

            // Test lowercase mutation at index i
            strcpy(variant, line);
            variant[i] = tolower((unsigned char)variant[i]);
            if (try_password(variant, target_hash)) {
                return 0;
            }
        }
    }

    // If no matching password was found across all inputs and mutations
    printf("Did not find a matching password\n");
    return 1;
}