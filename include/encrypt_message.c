#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>

#include "encrypt_message.h"

char *decryptMessage(char *pri_key, char *message)
{
    RSA *rsa = NULL;

    // Charger la clé privée RSA depuis la chaîne PEM
    BIO *bio_priv = BIO_new_mem_buf(pri_key, -1);
    if (bio_priv == NULL)
    {
        perror("Erreur lors de la création du BIO pour la clé privée");
        exit(EXIT_FAILURE);
    }

    rsa = PEM_read_bio_RSAPrivateKey(bio_priv, NULL, NULL, NULL);
    if (rsa == NULL)
    {
        ERR_print_errors_fp(stderr); // Imprimer des informations sur les erreurs
        perror("Erreur lors de la lecture de la clé privée");
        BIO_free(bio_priv);
        exit(EXIT_FAILURE);
    }

    BIO_free(bio_priv);

    int rsa_len = RSA_size(rsa);

    // Buffer pour le message déchiffré
    unsigned char *decrypted_message = (unsigned char *)malloc(rsa_len);

    // Déchiffrement RSA
    int result = RSA_private_decrypt(rsa_len, message, decrypted_message, rsa, RSA_PKCS1_PADDING);
    if (result == -1)
    {
        ERR_print_errors_fp(stderr); // Imprimer des informations sur les erreurs
        perror("Erreur lors du déchiffrement RSA");
        RSA_free(rsa);
        free(decrypted_message);
        exit(EXIT_FAILURE);
    }

    RSA_free(rsa);

    return (char *)decrypted_message;
}

char *encryptMessage(char *pub_key, char *message)
{
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
}