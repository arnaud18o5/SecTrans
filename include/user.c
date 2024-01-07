#include "user.h"
#include "base_encoding.h"

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// The passwords are written in the hexadecimal format
User users[] = {
    {"samuel", "6eac1114aa783f6549327e7d01f63752995da7b31f1f37092b7dcb9f49cf5651", "Compta", 0}, // Mot de passe : pwd1
    {"arnaud", "149d2937d1bce53fa683ae652291bd54cc8754444216a9e278b45776b76375af", "Compta", 0}, // Mot de passe : pwd2
    {"alexis", "ffc169417b4146cebe09a3e9ffbca33db82e3e593b4d04c0959a89c05b87e15d", "Finance", 0}, // Mot de passe : pwd3
    {"julian", "54775a53a76ae02141d920fd2a4682f6e7d3aef1f35210b9e4d253ad3db7e3a8", "Finance", 0} // Mot de passe : pwd4
};

User* authenticateUser(const char *username, const char *password) {
    for (int i = 0; i < sizeof(users) / sizeof(User); i++) {
        if (strcmp(username, users[i].username) == 0 && strcmp(password, users[i].password) == 0) {
            return &(users[i]);
        }
    }
    return NULL;
}

unsigned char *decryptToken(const unsigned char *encryptedToken, size_t tokenSize, const unsigned char *key) {
    AES_KEY aesKey;
    AES_set_decrypt_key(key, 256, &aesKey);

    unsigned char *decryptedToken = (unsigned char *)malloc(tokenSize);
    memset(decryptedToken, 0, sizeof(decryptedToken));

    AES_decrypt(encryptedToken, decryptedToken, &aesKey);

    return decryptedToken;
}

User* getUserFromToken(const char *token, const unsigned char *key) {
    size_t decryptTokenLength;
    unsigned char *decodedToken = base64_decode(token, &decryptTokenLength);

    unsigned char *decryptedToken = decryptToken(decodedToken, decryptTokenLength, key);

    char *username = strtok(decryptedToken, ",");
    char *role = strtok(NULL, ",");
    if (username == NULL || role == NULL) {
        fprintf(stderr, "Error parsing token\n");
        return NULL;
    }

    for (int i = 0; i < sizeof(users) / sizeof(User); i++) {
        if (strcmp(username, users[i].username) == 0) {
            return &(users[i]);
        }
    }
}

char* createSpecialToken(const char *username, const char *role) {
    size_t tokenSize = strlen(username) + strlen(role) + 2;

    char *specialToken = (char *)malloc(tokenSize);
    if (specialToken == NULL) {
        fprintf(stderr, "Error during allocation for the token\n");
        return NULL;
    }

    snprintf(specialToken, tokenSize, "%s,%s", username, role);

    return specialToken;
}

unsigned char* encryptToken(const unsigned char *token, size_t tokenSize, const unsigned char *key) {
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 256, &aesKey);

    size_t encryptedSize = (tokenSize / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

    unsigned char *encryptedToken = (unsigned char *)malloc(encryptedSize);
    if (encryptedToken == NULL) {
        fprintf(stderr, "Error allocating memory for encrypted token\n");
        return NULL;
    }

    memset(encryptedToken, 0, encryptedSize);

    AES_encrypt(token, encryptedToken, &aesKey);

    return encryptedToken;
}

void getLoginAndPassword(char message[], char login[], char password[]) {
    char *token = strtok(message, ",");
    token = strtok(NULL, ",");

    if (token != NULL) {
        strcpy(login, token);
        login[strlen(token)] = '\0';
    }
    else {
        fprintf(stderr, "Bad credentials\n");
        exit(EXIT_FAILURE);
    }

    token = strtok(NULL, ",");

    if (token != NULL) {
        strcpy(password, token);
        password[strlen(token)] = '\0';
    }
    else {
        fprintf(stderr, "Bad credentials\n");
        exit(EXIT_FAILURE);
    }
}