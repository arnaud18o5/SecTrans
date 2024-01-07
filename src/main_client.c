#include "client.h"
#include "server.h"
#include "hash.h"
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

    startserver(portClient);

    char auth_message[1024] = "auth,";
    strcat(auth_message, username);
    strcat(auth_message, ",");
    strcat(auth_message, password_hash_hexa);
    if (sndmsg(auth_message, port) != 0)
    {
        fprintf(stderr, "Erreur lors de l'envoi des informations d'authentification au serveur\n");
        return EXIT_FAILURE;
    }

    free(password_hash_hexa);

    char token_msg[1024] = "";
    if (getmsg(token_msg) == -1) {
        fprintf(stderr, "Error while receiving AES token message\n");
        return EXIT_FAILURE;
    }
    stopserver();

    // Check if token_msg contains "error", if so, show message and exit
    if (strstr(token_msg, "error") != NULL) {
        // Get message after comma
        char* error_msg = strchr(token_msg, ',') + 1;
        printf("Error while authenticating: %s\n", error_msg);
        return EXIT_FAILURE;
    }

    // Log received message
    printf("Message reçu du serveur : %s\n", token_msg);
    // Length of the token
    int token_len = strlen(token_msg);
    // Print
    printf("Token length: %d\n", token_len);

    // TODO passer ici à < 3 pour que l'on puisse insérer le token par la suite
    // plus modiifer juste

    if (argc < 2) return print_usage();

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
            int max_retreive_size = 1024 - strlen(server_message) - 1 - 1; // 1 for the comma, 1 for the null-terminator
            // Take in account the base64 encoding
            max_retreive_size = (int)floor(max_retreive_size / 1.37);

            unsigned char message[max_retreive_size];
            size_t num_read = fread(message, 1, max_retreive_size - 1, file);
            message[num_read] = '\0'; // Null-terminate the string

            // Encode the message to base64
            char* encoded_message = base64_encode(message, num_read);
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
        unsigned char* hash = calculate_hash(file);
        // Get the private key to sign the hash
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if(!mdctx) {
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
        if (!(privateKey = EVP_PKEY_new())) {
            fprintf(stderr, "Error creating EVP_PKEY structure.\n");
            return EXIT_FAILURE;
        }
        PEM_read_PrivateKey(privateKeyFile, &privateKey, NULL, NULL);

        // Create the signature
        unsigned char *signature_encrypted = malloc(EVP_PKEY_size(privateKey));
        unsigned int signature_length;
        if (EVP_SignInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
            fprintf(stderr, "Error initializing EVP_SignInit_ex.\n");
            return EXIT_FAILURE;
        }
        if (EVP_SignUpdate(mdctx, hash, SHA256_DIGEST_LENGTH) != 1) {
            fprintf(stderr, "Error in EVP_SignUpdate.\n");
            return EXIT_FAILURE;
        }
        if (EVP_SignFinal(mdctx, signature_encrypted, &signature_length, privateKey) != 1) {
            fprintf(stderr, "Error in EVP_SignFinal.\n");
            return EXIT_FAILURE;
        }
        EVP_PKEY_free(privateKey);
        EVP_MD_CTX_free(mdctx);

        // Encode the signature to base64
        char* encoded_signature = base64_encode(signature_encrypted, signature_length);
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
    else
    {
        fprintf(stderr, "Option non reconnue ou nombre incorrect d'arguments.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}