#include "signature.h"
#include "hash.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stddef.h>

int verifySignature(FILE* file, unsigned char* signature, size_t signature_len, char* publicKey) {
    // Set file to beginning
    fseek(file, 0, SEEK_SET);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }

    // Read public key
    BIO* bio = BIO_new_mem_buf(publicKey, -1);
    RSA* rsa_key = NULL;
    PEM_read_bio_RSAPublicKey(bio, &rsa_key, NULL, NULL);
    BIO_free(bio);

    // Check if public key is valid
    if (!rsa_key) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Create EVP_PKEY from RSA key
    EVP_PKEY* evp_key = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(evp_key, rsa_key)) {
        EVP_PKEY_free(evp_key);
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Initialize verification
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, evp_key) != 1) {
        EVP_PKEY_free(evp_key);
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Calculate hash of file
    unsigned char* file_hash = calculate_hash(file);
    // Check if hash is valid
    if (EVP_DigestVerifyUpdate(ctx, file_hash, SHA256_DIGEST_LENGTH) != 1) {
        EVP_PKEY_free(evp_key);
        EVP_MD_CTX_free(ctx);
        free(file_hash);
        return 0;
    }

    // Verify signature
    int ret = EVP_DigestVerifyFinal(ctx, signature, signature_len);
    EVP_PKEY_free(evp_key);
    EVP_MD_CTX_free(ctx);
    free(file_hash);

    return (ret == 1);
}

unsigned char* getFileSignature(FILE* file, unsigned int* signature_length, char* privateKeyName) {
    // Create signed hash
    unsigned char* hash = calculate_hash(file);
    // Get the private key to sign the hash
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if(!mdctx) {
        fprintf(stderr, "Error creating EVP_MD_CTX structure.\n");
        return NULL;
    }

    // Open the private key file
    char* fullPrivateKeyPath = malloc(strlen(privateKeyName) + 1 + strlen("_private.pem") + 1);
    strcpy(fullPrivateKeyPath, privateKeyName);
    strcat(fullPrivateKeyPath, "_private.pem");
    FILE *privateKeyFile = fopen(fullPrivateKeyPath, "r");
    if (privateKeyFile == NULL)
    {
        fprintf(stderr, "Erreur lors de l'ouverture du fichier\n");
        return NULL;
    }
    // Load the private key
    EVP_PKEY *privateKey;
    if (!(privateKey = EVP_PKEY_new())) {
        fprintf(stderr, "Error creating EVP_PKEY structure.\n");
        return NULL;
    }
    PEM_read_PrivateKey(privateKeyFile, &privateKey, NULL, NULL);

    // Create the signature
    unsigned char *signature_encrypted = malloc(EVP_PKEY_size(privateKey));
    if (EVP_SignInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "Error initializing EVP_SignInit_ex.\n");
        return NULL;
    }
    if (EVP_SignUpdate(mdctx, hash, SHA256_DIGEST_LENGTH) != 1) {
        fprintf(stderr, "Error in EVP_SignUpdate.\n");
        return NULL;
    }
    if (EVP_SignFinal(mdctx, signature_encrypted, signature_length, privateKey) != 1) {
        fprintf(stderr, "Error in EVP_SignFinal.\n");
        return NULL;
    }
    EVP_PKEY_free(privateKey);
    EVP_MD_CTX_free(mdctx);

    // Set file to beginning
    fseek(file, 0, SEEK_SET);

    return signature_encrypted;
}