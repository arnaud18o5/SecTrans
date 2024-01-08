#include "client.h"
#include "server.h"
#include "hash.h"
#include "encryption.h"
#include "base_encoding.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

long sndmsgencrypted(unsigned char *msg, int port)
{
    printf("msg : %s\n", msg);
    FILE *public_key_file = NULL;
    // Open the public key file
    if (port == SERVER_PORT)
    {
        public_key_file = fopen("server_public.pem", "r");
        if (public_key_file == NULL)
        {

            fprintf(stderr, "Erreur lors de l'ouverture du fichier de clé publique\n");
            return EXIT_FAILURE;
        }
    }
    else
    {
        public_key_file = fopen("client_public.pem", "r");
        if (public_key_file == NULL)
        {

            fprintf(stderr, "Erreur lors de l'ouverture du fichier de clé publique\n");
            return EXIT_FAILURE;
        }
    }

    // Get the public key
    RSA *publicKey = PEM_read_RSAPublicKey(public_key_file, NULL, NULL, NULL);
    if (publicKey == NULL)
    {
        ERR_print_errors_fp(stderr); // Imprimer des informations sur les erreurs OpenSSL
        fprintf(stderr, "Erreur lors de la lecture de la clé publique");
        return EXIT_FAILURE;
    }

    unsigned char *encrypted_message = (unsigned char *)malloc(RSA_size(publicKey));

    // Encrypt message
    int encrypted_message_len;
    // while (encrypted_message_len != RSA_size(publicKey) && encrypted_message_len != -1)
    encrypted_message_len = RSA_public_encrypt(strlen(msg), msg, encrypted_message, (unsigned char *)publicKey, RSA_PKCS1_PADDING);
    if (encrypted_message_len == -1)
    {
        ERR_print_errors_fp(stderr); // Imprimer des informations sur les erreurs OpenSSL
        fprintf(stderr, "Erreur lors du chiffrement RSA");
        return EXIT_FAILURE;
    }

    // Log encrypted message hexa and size
    printf("Message chiffré envoyé au serveur :");
    for (int i = 0; i < strlen(encrypted_message); i++)
    {
        printf("%02x", encrypted_message[i]);
    }
    printf("\n");
    // close public key file
    fclose(public_key_file);

    // test(encrypted_message);

    // free(encrypted_message);

    char *base64_msg = base64_encode(encrypted_message, encrypted_message_len);
    // Log base64 message and size
    printf("Message en base64 envoyé au serveur : %s\n", base64_msg);
    printf("Taille du message en base64 envoyé au serveur : %ld\n", strlen(base64_msg));
    long long result = sndmsg(base64_msg, port);

    test(encrypted_message);

    free(base64_msg);
    free(encrypted_message);

    return result;
}