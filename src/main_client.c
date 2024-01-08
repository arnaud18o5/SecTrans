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

const int SERVER_PORT = 12345;
const int DEFAULT_CLIENT_PORT = 12346;

char *token;
int attribuedPort;

unsigned char *test(unsigned char msg[1024]){
    printf("test\n");
    // Load private key
    FILE *privateKeyFile = fopen("server_private.pem", "r");
    if (privateKeyFile == NULL)
    {
        fprintf(stderr, "Erreur lors de l'ouverture du fichier\n");
        return NULL;
    }
    printf("test1\n");
    // Get the public key
    // char privateKey[2048];
    // // Read all the file content
    // char c;
    // int i = 0;
    // while ((c = fgetc(privateKeyFile)) != EOF)
    // {
    //     privateKey[i] = c;
    //     i++;
    // }
    // privateKey[i] = '\0';

    RSA *privateKey = PEM_read_RSAPrivateKey(privateKeyFile, NULL, NULL, NULL);
    if (privateKey == NULL)
    {
        fprintf(stderr, "Erreur lors de la lecture de la clé privée\n");
        return NULL;
    }
    printf("test2\n");

    // unsigned char* decryptedMessage = (unsigned char*) malloc(1024 * sizeof(char));

     // Decrypt the message
    // unsigned char* decryptedMessage = (unsigned char*) malloc(1024 * sizeof(char));
    int rsa_len = RSA_size(privateKey);
    printf("rsa_len : %d\n", rsa_len);
    // Determine the size of the decrypted message
    int decryptedMessageSize = (strlen(msg) / rsa_len + 1) * rsa_len;
    // Log size
    printf("Decrypted message size: %d\n", decryptedMessageSize);
    // Allocate memory for the decrypted message
    unsigned char* decryptedMessage = (unsigned char*) malloc(decryptedMessageSize);

    for (int i = 0; i < strlen(msg); i += rsa_len)
    {
        // Log
        printf("Decryption of packet %d\n", i / rsa_len);
        if (RSA_private_decrypt(rsa_len, msg + i, decryptedMessage + i, privateKey, RSA_PKCS1_PADDING) == -1)
        {
            fprintf(stderr, "Erreur lors du décryptage\n");
            return NULL;
        }
    }

    printf("Decrypted message: %s\n", decryptedMessage);
    printf("Decrypted message size: %ld\n", strlen(decryptedMessage));

    free(decryptedMessage);
    return "";
}

long sndmsgencrypted(unsigned char msg[585], int port)
{
    char *testa = "Ceci est le message test";
    // Log message and size
    printf("Message envoyé au serveur : %s\n", testa);
    printf("Taille du message envoyé au serveur : %ld\n", strlen(testa));

     // Open the public key file
    FILE *public_key_file = fopen("server_public.pem", "r");
    if (public_key_file == NULL)
    {
        
        fprintf(stderr, "Erreur lors de l'ouverture du fichier de clé publique\n");
        return EXIT_FAILURE;
    }

    // Get the public key
    RSA *publicKey = PEM_read_RSAPublicKey(public_key_file, NULL, NULL, NULL);
    if (publicKey == NULL)
    {
        ERR_print_errors_fp(stderr); // Imprimer des informations sur les erreurs OpenSSL
        fprintf(stderr, "Erreur lors de la lecture de la clé publique");
        return EXIT_FAILURE;
    }

    // Determine the maximum chunk size. If using RSA_PKCS1_PADDING, the maximum size is the size of the key minus 11.
    int max_chunk_size = RSA_size(publicKey) - RSA_PKCS1_PADDING_SIZE;

    // Log RSA Size
    printf("RSA size: %d\n", RSA_size(publicKey));
    // Allocate memory for the encrypted message
    unsigned char *encrypted_message = (unsigned char *)malloc(strlen(testa) / max_chunk_size * RSA_size(publicKey));
    int encrypted_message_length = 0;

    // Encrypt the message in chunks
    int offset = 0;
    for (int i = 0; i < strlen(testa); i += max_chunk_size)
    {
        int chunk_size = strlen(testa) - i;
        if (chunk_size > max_chunk_size)
            chunk_size = max_chunk_size;

        // Buffers pour le message chiffré et le message original
        unsigned char *temp_buff = (unsigned char *)malloc(RSA_size(publicKey));
        if (temp_buff == NULL)
        {
            perror("Erreur d'allocation de mémoire pour le message chiffré");
            exit(EXIT_FAILURE);
        }

        int result;

        while (result != RSA_size(publicKey))
        {
            // Chiffrement RSA
            result = RSA_public_encrypt(chunk_size, testa + i, temp_buff, publicKey, RSA_PKCS1_PADDING);
            if (result == -1)
            {
                fprintf(stderr, "Erreur lors de l'encryption\n");
            return EXIT_FAILURE;
            }
        }

        // Copy the encrypted chunk into the encrypted message
        memcpy(encrypted_message + encrypted_message_length, temp_buff, result);
        encrypted_message_length += result;

        free(temp_buff);

        // if (RSA_public_encrypt(chunk_size, testa + i, encrypted_message + offset, publicKey, RSA_PKCS1_PADDING) == -1)
        // {
        //     fprintf(stderr, "Erreur lors de l'encryption\n");
        //     return EXIT_FAILURE;
        // }

        offset += RSA_size(publicKey);
    }

    // Log encrypted message hexa and size
    printf("Message chiffré envoyé au serveur :");
    for (int i = 0; i < strlen(encrypted_message); i++) {
        printf("%02x", encrypted_message[i]);
    }
    printf("\n");
    printf("Taille du message chiffré envoyé au serveur : %ld\n", strlen(encrypted_message));

    // close public key file
    fclose(public_key_file);

    test(encrypted_message);

    exit(0);

    char *base64_msg = base64_encode(encrypted_message, strlen(encrypted_message));
    // Log base64 message and size
    printf("Message en base64 envoyé au serveur : %s\n", base64_msg);
    printf("Taille du message en base64 envoyé au serveur : %ld\n", strlen(base64_msg));
    long long result = sndmsg(base64_msg, port);

    free(base64_msg);
    free(encrypted_message);

    return result;
}

int generate_rsa_keypair(char* name) {
    int ret = 0;
    RSA *r = NULL;
    BIGNUM *bne = NULL;
    unsigned long e = RSA_F4;

    char *server_public_key = NULL;

    int bits = 4096;
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
    char* private_key_file_name = malloc(strlen(name) + strlen("_private.pem") + 1);
    strcpy(private_key_file_name, name);
    strcat(private_key_file_name, "_private.pem");
    privateKeyFile = fopen(private_key_file_name, "w");
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
    char* public_key_file_name = malloc(strlen(name) + strlen("_public.pem") + 1);
    strcpy(public_key_file_name, name);
    strcat(public_key_file_name, "_public.pem");
    publicKeyFile = fopen(public_key_file_name, "w");
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
    generate_rsa_keypair("client");
    generate_rsa_keypair("server");

    printf("Veuillez entrez votre nom d'utilisateur : \n");
    char username[100];
    scanf("%s", username);

    printf("Veuillez entrez votre mot de passe : \n");
    char password[100];
    scanf("%s", password);
    unsigned char* password_hash = calculate_hash_from_string(password);
    char* password_hash_hexa = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(password_hash_hexa + (i * 2), "%02x", password_hash[i]);
    }
    free(password_hash);

    startserver(DEFAULT_CLIENT_PORT);

    char auth_message[585] = "auth,";
    strcat(auth_message, username);
    strcat(auth_message, ",");
    strcat(auth_message, password_hash_hexa);

    // Encode the auth message in base64
    // char *base64_auth_message = base64_encode(auth_message, strlen(auth_message));
    
    // if (sndmsg(base64_auth_message, SERVER_PORT) != 0)
    if (sndmsgencrypted(auth_message, SERVER_PORT) != 0)
    {
        fprintf(stderr, "Erreur lors de l'envoi des informations d'authentification au serveur\n");
        return EXIT_FAILURE;
    }

    free(password_hash_hexa);

    char response[1024] = "";
    if (getmsg(response) == -1) {
        fprintf(stderr, "Error while receiving AES token message\n");
        return EXIT_FAILURE;
    }
    stopserver();

    // Check if token_msg contains "error", if so, show message and exit
    if (strstr(response, "error") != NULL) {
        // Get message after comma
        char* error_msg = strchr(response, ',') + 1;
        printf("Error while authenticating: %s\n", error_msg);
        return EXIT_FAILURE;
    }

    // Save token
    char *attribuedToken = strtok(response, ",");
    token = malloc(strlen(attribuedToken));
    strcpy(token, attribuedToken);
    // Save port
    char *attribuedPortStr = strtok(NULL, ",");
    attribuedPort = atoi(attribuedPortStr);

    if (argc < 2)
        return print_usage();

    // Traitement des options en fonction des arguments de la ligne de commande
    if (strcmp(argv[1], "-up") == 0 && argc >= 3)
    {
        // Exemple d'utilisation : ./client -up <nom du fichier>

        // Start server to receive server messages
        if (startserver(attribuedPort) == -1)
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
        char server_message[1024] = "up,";
        // Add token
        strcat(server_message, token);
        strcat(server_message, ",FILE_START,");
        strcat(server_message, argv[2]);

        // Encode the server message in base64
        char *base64_server_message = base64_encode(server_message, strlen(server_message));
        long long result = sndmsg(base64_server_message, SERVER_PORT);
        if (result != 0)
        {
            fprintf(stderr, "Erreur lors de l'envoi du message au serveur\n");
            return EXIT_FAILURE;
        }

        // Get server response
        char server_response[1024] = "";
        if (getmsg(server_response) == -1)
        {
            fprintf(stderr, "Error while receiving message\n");
            return EXIT_FAILURE;
        }
        // Check if server response contains "error", if so, show message and exit
        if (strstr(server_response, "error") != NULL) {
            // Get message after comma
            char* error_msg = strchr(server_response, ',') + 1;
            printf("%s\n", error_msg);
            return EXIT_FAILURE;
        }
        printf("%s\n", server_response);

        while (!feof(file))
        {
            char server_message[1024] = "up,";
            // Add token
            strcat(server_message, token);
            strcat(server_message, ",");
            // Calculate the max num of chars to read
            int max_retreive_size = (1024 - 1024 / 128 * 11) - strlen(server_message) - 1 - 1; // 1 for the comma, 1 for the null-terminator
            // Take in account the base64 encoding
            max_retreive_size = (int)floor(max_retreive_size / 1.37);
            unsigned char message[max_retreive_size];
            size_t num_read = fread(message, 1, max_retreive_size - 1, file);
            message[num_read] = '\0'; // Null-terminate the string

            printf("max retreive size : %d\n", max_retreive_size);
            unsigned char encrypted_message[max_retreive_size];
            // Split the message into packets of 128
            int packet_size = 128 - 11;
            int num_packets = (num_read) / packet_size - 1;
            // Open the public key file
            FILE *public_key_file = fopen("server_public.pem", "r");
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

            // printf("publicKey : %s\n", publicKey);
            for (int i = 0; i < num_packets; i++)
            {
                char packet[packet_size + 1];
                strncpy(packet, message + i * packet_size, packet_size);
                packet[packet_size] = '\0'; // Null-terminate the packet

                char *encryptedPacket = encryptMessage(publicKey, packet);
                // printf("encryptedPacket : %s\n", encryptedPacket);

                // add encrypted packet to encrypted message
                strcat(encrypted_message, encryptedPacket);

                printf("size packet : %ld\n", strlen(encryptedPacket));
            }

            // close public key file
            fclose(public_key_file);

            // printf("encrypted_message : %s\n", encrypted_message);
            // printf("size encrypted_message : %d\n", strlen(encrypted_message));

            // Encode the message to base64
            strcat(server_message, encrypted_message);
            printf("size server_message : %ld\n", strlen(server_message));
            char *encoded_message = base64_encode(server_message, strlen(server_message));
            printf("encoded_message : %s\n", encoded_message);
            printf("size encoded_message : %ld\n", strlen(encoded_message));
            long long result = sndmsg(encoded_message, SERVER_PORT);
            // free(encoded_message);
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
        char server_message1[1024] = "up,";
        // Add token
        strcat(server_message1, token);
        strcat(server_message1, ",PUBLIC_KEY,");
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
        long long result1 = sndmsg(server_message1, SERVER_PORT);
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
        char *encoded_signature = base64_encode(signature_encrypted, strlen(signature_encrypted));
        free(signature_encrypted);

        // Send to the server a last message containing an end hint with signed hash
        char server_message2[1024] = "up,";
        // Add token
        strcat(server_message2, token);
        strcat(server_message2, ",FILE_END");
        strcat(server_message2, ",");
        strcat(server_message2, encoded_signature);
        free(encoded_signature);
        long long result2 = sndmsg(server_message2, SERVER_PORT);
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
        // Add token
        strcat(server_message, token);
        sndmsg(server_message, SERVER_PORT);
        // Affichez la liste des fichiers reçue du serveur
        if (startserver(attribuedPort) == -1)
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
        // Add token
        strcat(server_message, token);
        strcat(server_message, ",");
        strcat(server_message, argv[2]);

        sndmsg(server_message, SERVER_PORT);

        if (startserver(attribuedPort) == -1)
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
                // Check if message contains error
                if (strstr(received_msg, "error") != NULL) {
                    // Get message after comma
                    char* error_msg = strchr(received_msg, ',') + 1;
                    printf("%s\n", error_msg);
                    break;
                }
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

        char *base64_server_message = base64_encode(server_message, strlen(server_message));
        sndmsg(base64_server_message, SERVER_PORT);

        if (startserver(DEFAULT_CLIENT_PORT) == -1)
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
                messageReceived = 1;
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

    free(token);

    return EXIT_SUCCESS;
}