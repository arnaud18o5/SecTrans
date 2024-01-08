#include "rsa.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

int generate_rsa_keypair(int bits, char* prefix) {
    int ret = 0;
    RSA *r = NULL;
    BIGNUM *bne = NULL;
    unsigned long e = RSA_F4;

    unsigned long exponent = RSA_F4; // 65537
    FILE *privateKeyFile, *publicKeyFile;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        goto free_stuff;
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        goto free_stuff;
    }

    // 2. save private key
    char* privateKeyFilename = malloc(strlen(prefix) + strlen("_private.pem") + 1);
    strcpy(privateKeyFilename, prefix);
    strcat(privateKeyFilename, "_private.pem");
    privateKeyFile = fopen(privateKeyFilename, "w");
    if(privateKeyFile == NULL){
        goto free_stuff;
    }
    ret = PEM_write_RSAPrivateKey(privateKeyFile, r, NULL, NULL, 0, NULL, NULL);
    if(ret != 1){
        goto free_stuff;
    }

    // 3. save public key
    char* publicKeyFilename = malloc(strlen(prefix) + strlen("_public.pem") + 1);
    strcpy(publicKeyFilename, prefix);
    strcat(publicKeyFilename, "_public.pem");
    publicKeyFile = fopen(publicKeyFilename, "w");
    if(publicKeyFile == NULL){
        goto free_stuff;
    }
    ret = PEM_write_RSAPublicKey(publicKeyFile, r);
    if(ret != 1){
        goto free_stuff;
    }

free_stuff:
    RSA_free(r);
    BN_free(bne);
    if(privateKeyFile) fclose(privateKeyFile);
    if(publicKeyFile) fclose(publicKeyFile);

    return (ret == 1) ? 0 : 1;
}

char* load_key(char* filename){
    FILE *publicKeyFile = fopen(filename, "r");
    if (publicKeyFile == NULL)
    {
        fprintf(stderr, "Erreur lors de l'ouverture du fichier\n");
        return NULL;
    }

    // Get the public key
    char* publicKey = malloc(2048);
    // Read all the file content
    char c;
    int i = 0;
    while ((c = fgetc(publicKeyFile)) != EOF)
    {
        publicKey[i] = c;
        i++;
    }
    publicKey[i] = '\0';

    fclose(publicKeyFile);

    return publicKey;
}
