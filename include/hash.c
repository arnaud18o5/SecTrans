#include "./hash.h"

#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char* calculate_hash(FILE* file) {
    // Ensure we're starting from the beginning of the file
    fseek(file, 0, SEEK_SET);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char* buffer = malloc(SHA256_DIGEST_LENGTH * sizeof(unsigned char));
    if (!buffer) return NULL;

    const int bufSize = 32768;
    unsigned char* file_buffer = malloc(bufSize);
    if (!file_buffer) {
        free(buffer);
        return NULL;
    }

    int bytesRead = 0;
    while ((bytesRead = fread(file_buffer, 1, bufSize, file))) {
        SHA256_Update(&sha256, file_buffer, bytesRead);
    }

    SHA256_Final(hash, &sha256);

    memcpy(buffer, hash, SHA256_DIGEST_LENGTH);

    free(file_buffer);

    // Reset the file pointer to the beginning of the file
    fseek(file, 0, SEEK_SET);

    return buffer;
}