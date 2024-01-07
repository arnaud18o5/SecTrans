
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

RSA *load_public_key_from_string(const char *public_key_str)
{
    BIO *key_bio = BIO_new_mem_buf((void *)public_key_str, -1);
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(key_bio, NULL, NULL, NULL);
    BIO_free(key_bio);
    return rsa;
}

unsigned char *encrypt_message(const unsigned char *message, int message_len, RSA *public_key, int *encrypted_len)
{
    printf("1");
    char *err;
    unsigned char *encrypted = (unsigned char *)malloc(RSA_size(public_key));
    *encrypted_len = RSA_public_encrypt(message_len, message, encrypted, public_key, RSA_PKCS1_PADDING);
    printf("2");
    if (*encrypted_len == -1)
    {
        // ERR_load_crypto_strings();
        // ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
        return NULL;
    }
    return encrypted;
}

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

    RSA *rsa = NULL;
    // Charger la clé publique RSA depuis la chaîne PEM
    BIO *bio = BIO_new_mem_buf(pub_key, -1);
    if (bio == NULL)
    {
        perror("Erreur lors de la création du BIO");
        exit(EXIT_FAILURE);
    }

    rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    if (rsa == NULL)
    {
        // ERR_print_errors_fp(stderr); // Imprimer des informations sur les erreurs
        perror("Erreur lors de la lecture de la clé publique");
        BIO_free(bio);
        exit(EXIT_FAILURE);
    }

    BIO_free(bio);

    // Message à chiffrer
    const char *message = "Hello, RSA!";
    size_t message_len = strlen(message);

    // Taille du bloc chiffré
    int rsa_len = RSA_size(rsa);

    // Buffers pour le message chiffré et le message original
    unsigned char *encrypted_message = (unsigned char *)malloc(rsa_len);
    if (encrypted_message == NULL)
    {
        perror("Erreur d'allocation de mémoire");
        RSA_free(rsa);
        exit(EXIT_FAILURE);
    }

    // Chiffrement RSA
    int result = RSA_public_encrypt(message_len, (const unsigned char *)message, encrypted_message, rsa, RSA_PKCS1_PADDING);
    if (result == -1)
    {
        perror("Erreur lors du chiffrement RSA");
        free(encrypted_message);
        RSA_free(rsa);
        exit(EXIT_FAILURE);
    }

    // Afficher le message chiffré (en hexadécimal)
    printf("Message chiffré (hex) : ");
    for (int i = 0; i < rsa_len; i++)
    {
        printf("%02x", encrypted_message[i]);
    }
    printf("\n");

    // Libérer la mémoire
    free(encrypted_message);
    RSA_free(rsa);

    return 0;
    /*removeBeginPublicKey(str);
    removeNewlines(str);
    removeEndPublicKey(str);
    printf("public : %s\n", str);

    RSA *pubKey = load_public_key_from_string(str);

    char *message = "salut les foufous";
    int encrypted_size;
    char *encrypted = encrypt_message((const unsigned char *)message, sizeof(message), pubKey, &encrypted_size);
    printf("message encrypté: %s\n", encrypted);*/
}