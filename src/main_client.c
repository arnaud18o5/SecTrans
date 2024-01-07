#include "../include/client.h"
#include "../include/server.h"
#include "../include/encryption.h"
#include "../include/hash.h"

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
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int generate_rsa_keypair()
{
    int ret = 0;
    RSA *r = NULL;
    BIGNUM *bne = NULL;
    unsigned long e = RSA_F4;

    char *server_public_key = NULL;

    int bits = 2048;
    unsigned long exponent = RSA_F4; // 65537
    FILE *privateKeyFile, *publicKeyFile;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne, e);
    if (ret != 1)
    {
        goto free_stuff;
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if (ret != 1)
    {
        goto free_stuff;
    }

    // 2. save private key
    privateKeyFile = fopen("client_private.pem", "w");
    if (privateKeyFile == NULL)
    {
        goto free_stuff;
    }
    ret = PEM_write_RSAPrivateKey(privateKeyFile, r, NULL, NULL, 0, NULL, NULL);
    if (ret != 1)
    {
        goto free_stuff;
    }

    // 3. save public key
    publicKeyFile = fopen("client_public.pem", "w");
    if (publicKeyFile == NULL)
    {
        goto free_stuff;
    }
    ret = PEM_write_RSAPublicKey(publicKeyFile, r);
    if (ret != 1)
    {
        goto free_stuff;
    }

free_stuff:
    RSA_free(r);
    BN_free(bne);
    if (privateKeyFile)
        fclose(privateKeyFile);
    if (publicKeyFile)
        fclose(publicKeyFile);

    return (ret == 1) ? 0 : 1;
}

// Function to encode data to Base64
char *base64_encode(const unsigned char *buffer, size_t length)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    char *ret = (char *)malloc((bufferPtr->length + 1) * sizeof(char));
    memcpy(ret, bufferPtr->data, bufferPtr->length);
    ret[bufferPtr->length] = '\0';

    return ret;
}

// Fonction pour charger une clé publique RSA à partir d'une chaîne de caractères
RSA *load_public_key_from_string(const char *public_key_str)
{
    BIO *key_bio = BIO_new_mem_buf((void *)public_key_str, -1);
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(key_bio, NULL, NULL, NULL);
    BIO_free(key_bio);
    return rsa;
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

void reformatKey(char *str)
{
    removeBeginPublicKey(str);
    removeNewlines(str);
    removeEndPublicKey(str);
}

// Fonction pour chiffrer un message avec une clé publique RSA
// message : le message à chiffrer
// public_key : la clé publique RSA
// encrypted_len : la longueur du message chiffré
// Retourne le message chiffré
/*unsigned char *encrypt_message(const unsigned char *message, int message_len, RSA *public_key, int *encrypted_len)
{
    char *err;
    unsigned char *encrypted = (unsigned char *)malloc(RSA_size(public_key));
    printf("1");
    *encrypted_len = RSA_public_encrypt(message_len, message, encrypted, public_key, RSA_PKCS1_PADDING);
    printf("2");
    if (*encrypted_len == -1)
    {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
        return NULL;
    }
    return encrypted;
}*/

int print_usage()
{
    fprintf(stderr, "Usage: ./client <option>\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -up <message>: Upload a message to the server\n");
    fprintf(stderr, "  -list: List files stored on the server\n");
    fprintf(stderr, "  -down <message>: Download a message from the server\n");
    return EXIT_FAILURE;
}

int main(int argc, char *argv[])
{
    // TO BE MOVED WHEN LOGIN ??
    generate_rsa_keypair();

    int port = 12345;
    int portClient = 12346;

    if (argc < 2)
        return print_usage();

    // Traitement des options en fonction des arguments de la ligne de commande
    if (strcmp(argv[1], "-up") == 0 && argc >= 3)
    {
        // Exemple d'utilisation : ./client -up <nom du fichier>

        // Start server to receive server messages
        if (startserver(portClient) == -1)
        {
            fprintf(stderr, "Failed to start the server client\n");
            return EXIT_FAILURE;
        }

        // Open the file, read its content in 999 chars; store it in server_message and send it
        FILE *file = fopen(argv[2], "r");
        if (file == NULL)
        {
            fprintf(stderr, "Erreur lors de l'ouverture du fichier\n");
            return EXIT_FAILURE;
        }

        // Get total file length
        fseek(file, 0, SEEK_END);
        long long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);

        long long total_read = 0;

        // Send to the server a first message containing a start hint and the filename
        char server_message[1024] = "up,FILE_START,";
        strcat(server_message, argv[2]);
        long long result = sndmsg(server_message, port);
        if (result != 0)
        {
            fprintf(stderr, "Erreur lors de l'envoi du message au serveur\n");
            return EXIT_FAILURE;
        }

        while (!feof(file))
        {
            char server_message[1024] = "up,";
            // Calculate the max num of chars to read
            int max_retreive_size = (1024 - 1024 / 128 * 11) - strlen(server_message) - 1 - 1; // 1 for the comma, 1 for the null-terminator
            // Take in account the base64 encoding
            max_retreive_size = (int)floor(max_retreive_size / 1.37);
            unsigned char message[max_retreive_size];
            size_t num_read = fread(message, 1, max_retreive_size - 1, file);
            message[num_read] = '\0'; // Null-terminate the string
            unsigned char encrypted_message[max_retreive_size];
            // Split the message into packets of 128
            int packet_size = 128 - 11;
            int num_packets = (num_read + packet_size - 1) / packet_size;
            for (int i = 0; i < num_packets; i++)
            {
                char packet[packet_size + 1];
                strncpy(packet, message + i * packet_size, packet_size);
                packet[packet_size] = '\0'; // Null-terminate the packet

                // Open the public key file
                FILE *public_key_file = fopen("server_public_key.pem", "r");
                if (public_key_file == NULL)
                {
                    fprintf(stderr, "Erreur lors de l'ouverture du fichier de clé publique\n");
                    return EXIT_FAILURE;
                }

                // Get the public key
                char publicKey[1024];
                // Read all the file content
                char c;
                int i = 0;
                while ((c = fgetc(public_key_file)) != EOF)
                {
                    publicKey[i] = c;
                    i++;
                }
                publicKey[i] = '\0';

                char *encryptedPacket = encryptMessage(publicKey, packet);
                printf("encryptedPacket : %s\n", encryptedPacket);

                // add encrypted packet to encrypted message
                strcat(encrypted_message, encryptedPacket);

                printf("size packet : %d\n", strlen(packet));
            }

            printf("encrypted_message : %s\n", encrypted_message);

            // Encode the message to base64
            char *encoded_message = base64_encode(encrypted_message, num_read);
            free(encrypted_message);
            strcat(server_message, encoded_message);
            free(encoded_message);

            long long result = sndmsg(server_message, port);
            if (result != 0)
            {
                fprintf(stderr, "Erreur lors de l'envoi du message au serveur\n");
                return EXIT_FAILURE;
            }
            // Show progress
            total_read += num_read;
            printf("Progress: %lld/%lld (%lld%%)\n", total_read, file_size, total_read * 100 / file_size);
        }

        // Send the public key to the server
        char server_message1[1024] = "up,PUBLIC_KEY,";
        FILE *publicKeyFile = fopen("client_public.pem", "r");
        if (publicKeyFile == NULL)
        {
            fprintf(stderr, "Erreur lors de l'ouverture du fichier\n");
            return EXIT_FAILURE;
        }
        // Get the public key
        char publicKey[1024];
        // Read all the file content
        char c;
        int i = 0;
        while ((c = fgetc(publicKeyFile)) != EOF)
        {
            publicKey[i] = c;
            i++;
        }
        publicKey[i] = '\0';
        strcat(server_message1, publicKey);
        long long result1 = sndmsg(server_message1, port);
        if (result1 != 0)
        {
            fprintf(stderr, "Erreur lors de l'envoi du message au serveur\n");
            return EXIT_FAILURE;
        }

        // Create signed hash
        unsigned char *hash = calculate_hash(file);
        // Get the private key to sign the hash
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx)
        {
            fprintf(stderr, "Error creating EVP_MD_CTX structure.\n");
            return EXIT_FAILURE;
        }
        FILE *privateKeyFile = fopen("client_private.pem", "r");
        if (privateKeyFile == NULL)
        {
            fprintf(stderr, "Erreur lors de l'ouverture du fichier\n");
            return EXIT_FAILURE;
        }
        // Load the private key
        EVP_PKEY *privateKey;
        if (!(privateKey = EVP_PKEY_new()))
        {
            fprintf(stderr, "Error creating EVP_PKEY structure.\n");
            return EXIT_FAILURE;
        }
        PEM_read_PrivateKey(privateKeyFile, &privateKey, NULL, NULL);

        // Create the signature
        unsigned char *signature_encrypted = malloc(EVP_PKEY_size(privateKey));
        unsigned int signature_length;
        if (EVP_SignInit_ex(mdctx, EVP_sha256(), NULL) != 1)
        {
            fprintf(stderr, "Error initializing EVP_SignInit_ex.\n");
            return EXIT_FAILURE;
        }
        if (EVP_SignUpdate(mdctx, hash, SHA256_DIGEST_LENGTH) != 1)
        {
            fprintf(stderr, "Error in EVP_SignUpdate.\n");
            return EXIT_FAILURE;
        }
        if (EVP_SignFinal(mdctx, signature_encrypted, &signature_length, privateKey) != 1)
        {
            fprintf(stderr, "Error in EVP_SignFinal.\n");
            return EXIT_FAILURE;
        }
        EVP_PKEY_free(privateKey);
        EVP_MD_CTX_free(mdctx);

        // Encode the signature to base64
        char *encoded_signature = base64_encode(signature_encrypted, signature_length);
        free(signature_encrypted);

        // Send to the server a last message containing an end hint with signed hash
        char server_message2[1024] = "up,FILE_END";
        strcat(server_message2, ",");
        strcat(server_message2, encoded_signature);
        free(encoded_signature);
        long long result2 = sndmsg(server_message2, port);
        if (result2 != 0)
        {
            fprintf(stderr, "Erreur lors de l'envoi du message au serveur\n");
            return EXIT_FAILURE;
        }

        char received_msg[1024] = "";
        if (getmsg(received_msg) == -1)
        {
            fprintf(stderr, "Error while receiving message\n");
            return EXIT_FAILURE;
        }
        printf("%s\n", received_msg);

        fclose(file);
        stopserver();
    }
    else if (strcmp(argv[1], "-list") == 0 && argc == 2)
    {
        // Exemple d'utilisation : ./client -list
        char server_message[1024] = "list,";
        char portStr[10];                   // Crée une chaîne pour stocker la représentation en chaîne de l'entier
        sprintf(portStr, "%d", portClient); // Convertit l'entier en chaîne de caractères
        strcat(server_message, portStr);    // Concatène la chaîne représentant l'entier à server_message
        sndmsg(server_message, port);
        // Affichez la liste des fichiers reçue du serveur
        if (startserver(portClient) == -1)
        {
            fprintf(stderr, "Failed to start the server client\n");
            return EXIT_FAILURE;
        }
        int messageReceived = 0;
        char received_msg[1024] = "";
        while (messageReceived == 0)
        {
            if (getmsg(received_msg) == -1)
            {
                fprintf(stderr, "Error while receiving message\n");
                break;
            }
            if (strcmp(received_msg, ""))
            {
                printf("Liste des fichiers stockés sur le serveur :\n%s\n", received_msg);
                messageReceived = 1;
            }
        }
    }
    else if (strcmp(argv[1], "-down") == 0 && argc == 3)
    {
        // Exemple d'utilisation : ./client -down "filename"
        char server_message[1024] = "down,";
        char portStr[10];                    // Crée une chaîne pour stocker la représentation en chaîne de l'entier
        sprintf(portStr, "%d,", portClient); // Convertit l'entier en chaîne de caractères
        strcat(server_message, portStr);     // Concatène la chaîne représentant l'entier à server_message
        strcat(server_message, argv[2]);

        sndmsg(server_message, port);

        if (startserver(portClient) == -1)
        {
            fprintf(stderr, "Failed to start the server client\n");
            return EXIT_FAILURE;
        }
        int messageReceived = 0;
        char received_msg[1024];
        while (messageReceived == 0)
        {
            if (getmsg(received_msg) == -1)
            {
                fprintf(stderr, "Error while receiving message\n");
                break;
            }
            if (strcmp(received_msg, ""))
            {
                printf("Message reçu du serveur : %s\n", received_msg);
                messageReceived = 1;
            }
        }

        // int result = read_server_message(server_message);// if (result != 0)
        // {
        //    fprintf(stderr, "Erreur lors de la récupération du message du serveur\n");
        //  return EXIT_FAILURE;
        //}
        // printf("Message reçu du serveur : %s\n", server_message);
    }
    else if (strcmp(argv[1], "-rsa") == 0 && argc == 2)
    {
        char server_message[1024] = "rsa,";
        char portStr[10];                    // Crée une chaîne pour stocker la représentation en chaîne de l'entier
        sprintf(portStr, "%d,", portClient); // Convertit l'entier en chaîne de caractères
        strcat(server_message, portStr);
        sndmsg(server_message, port);

        if (startserver(portClient) == -1)
        {
            fprintf(stderr, "Failed to start the server client\n");
            return EXIT_FAILURE;
        }

        int messageReceived = 0;
        char received_msg[1024];
        while (messageReceived == 0)
        {
            if (getmsg(received_msg) == -1)
            {
                fprintf(stderr, "Error while receiving message\n");
                break;
            }
            if (strcmp(received_msg, ""))
            {
                // sauvegarde de la clef publique du serveur
                FILE *file = fopen("server_public_key.pem", "w");
                if (file == NULL)
                {
                    fprintf(stderr, "Failed to open the file\n");
                    return EXIT_FAILURE;
                }
                fprintf(file, "%s", received_msg);
                fclose(file);
                /*printf("Message reçu du serveur : %s\n", received_msg);
                char *rsa = "Hello les foufous les foufous ca va les foufous de foufous ???";
                printf("envoie du message vers serveur : %s\n", rsa);

                char *encrypted_message = encryptMessage(received_msg, rsa);
                sleep(1);
                printf("envoie du message vers serveur : %s\n", rsa);
                printf("envoie du message vers serveur : %s\n", encrypted_message);
                printf("size : %d\n", strlen(encrypted_message));
                printf("port : %d\n", port);
                sndmsg(encrypted_message, port);

                printf("Message envoyé avec succès au serveur.\n");
                messageReceived = 1;
                // Libérer la mémoire
                free(encrypted_message);*/
            }
        }
    }
    else
    {
        fprintf(stderr, "Option non reconnue ou nombre incorrect d'arguments.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}