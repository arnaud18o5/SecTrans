#include "rsa.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

int generate_rsa_keypair() {
    int ret = 0;
    RSA *r = NULL;
    BIGNUM *bne = NULL;
    unsigned long e = RSA_F4;

    int bits = 2048;
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
    privateKeyFile = fopen("client_private.pem", "w");
    if(privateKeyFile == NULL){
        goto free_stuff;
    }
    ret = PEM_write_RSAPrivateKey(privateKeyFile, r, NULL, NULL, 0, NULL, NULL);
    if(ret != 1){
        goto free_stuff;
    }

    // 3. save public key
    publicKeyFile = fopen("client_public.pem", "w");
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
