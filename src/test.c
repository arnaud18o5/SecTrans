
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>

#define KEY_LENGTH 512
#define PUB_EXP 65537
#define PRINT_KEYS
#define WRITE_TO_FILE

void removeBeginPublicKey(char *str)
{
    char *start_ptr = strstr(str, "-----BEGIN RSA PUBLIC KEY-----");
    if (start_ptr != NULL)
    {
        size_t prefix_len = strlen("-----BEGIN RSA PUBLIC KEY-----");
        memmove(start_ptr, start_ptr + prefix_len, strlen(start_ptr + prefix_len) + 1);
    }
}

void removeNewlines(char *str)
{
    char *pos;
    while ((pos = strchr(str, '\n')) != NULL)
    {
        memmove(pos, pos + 1, strlen(pos));
    }
}

void removeEndPublicKey(char *str)
{
    char *end_ptr = strstr(str, "-----END RSA PUBLIC KEY-----");
    if (end_ptr != NULL)
    {
        size_t suffix_len = strlen("-----END RSA PUBLIC KEY-----");
        *end_ptr = '\0';
    }
}

int main(void)
{
    size_t pri_len; // Length of private key
    size_t pub_len; // Length of public key
    char *pri_key;  // Private key
    char *pub_key;  // Public key
    /*char *encrypt = NULL; // Encrypted message
    char *decrypt = NULL; // Decrypted message
    char *err;            // Buffer for any error messages*/

    // char msg[KEY_LENGTH / 8]; // Message to encrypt
    //  Generate key pair
    // printf("Generating RSA (%d bits) keypair...", KEY_LENGTH);
    //  fflush(stdout);
    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = malloc(pri_len + 1);
    pub_key = malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    printf("\nprivate : %s\npublic : %s\n", pri_key, pub_key);

    // reformatKey(pub_key);
    // char public_key[sizeof(pub_key)];
    // strcpy(public_key, pub_key);

    char str[] = "-----BEGIN RSA PUBLIC KEY-----\nMEgCQQDawg/kNlkmsa4q9IBd0eFVTX7qMB4USm+4a/I/ckskajuDug9oLksyRZ65\noMaJQODb5oXL22fEUQtqqyHZM8ytAgMBAAE=\n-----END RSA PUBLIC KEY-----";

    removeBeginPublicKey(str);
    removeNewlines(str);
    removeEndPublicKey(str);
    printf("public : %s\n", str);
}