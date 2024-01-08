
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/encryption.h"

#include "../include/base_encoding.h"

#define KEY_LENGTH 512
#define PUB_EXP 65537
#define PRINT_KEYS
#define WRITE_TO_FILE

int main(void)
{
    /*size_t pri_len; // Length of private key
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
    /*RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

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

    return 0;*/
    /*removeBeginPublicKey(str);
    removeNewlines(str);
    removeEndPublicKey(str);
    printf("public : %s\n", str);

    RSA *pubKey = load_public_key_from_string(str);

    char *message = "salut les foufous";
    int encrypted_size;
    char *encrypted = encrypt_message((const unsigned char *)message, sizeof(message), pubKey, &encrypted_size);
    printf("message encrypté: %s\n", encrypted);*/

    const char *message = "8A2j3NlVAADgvWyCZ38AALUDhdt573Ar/rFZgsjDqkESA0noT+/f1ZEHBttYY6YG2CaB3nAUQsWg3vXFQogtLPxERlUDCMzUH8SkqbSb/LfEThudpufVTnT0VuQfOOZKQo+3q9js+l/ESM0j41Z9W6ExesGDz5StFpZpjGR45h0YH6nOdVHAihbOb8MbP80KcKRx3oV1QnESbTWQkBJCJjg/IhXsiw2mKzGyybmfgOWvAu4hSa3fDcAPdtkikfLzYJLX+obAlM0ZZU5dR0H/NL17z/4VTgGwLdVi4/fNlWT72y4b6bgizs3p/A0HHnuICp7XZcF5/8y7zlI/xeJRi04BgfRkHbqbHj3ZqzeDC8Dq/fEHLwqFW165nwjOsPZKBBDAqtB/YdyJUugImy7ERi6/jxGyUJDt65ADy6ptWUhN0YA+RTSnAKaMrUJGVnSSR3KNKD2twaDxPSYEsbEAjb6+3VM39Li6FOhRTrsf5tyK93TD5SmzI8KBw5V1I29AgVGtoQ9l9G4Wey3QaXifiPHqhi0uFu1Tf66quyDuRyPSKVP6L0WzPI75KB6kAmszcgSd+FJtdOApunzxL5Jqa805CjuOagasGiw8HnfcK4P5cYL4gu2TOpTwVJRgurc49CRr2340TJ8up6fqgU7BdzXLROhIhVlAtYgBJ3DASoA=";

    // decode base64
    unsigned char *decoded_message = base64_decode(message, strlen(message));
    printf("message décodé: %s\n", decoded_message);
}