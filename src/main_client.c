#include "client.h"
#include "server.h"
#include "hash.h"
#include "base_encoding.h"
#include "rsa.h"
#include "signature.h"

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

void checkError(char* message){
    // Check if message contains "error", if so, show message and exit
    if (strstr(message, "error") != NULL) {
        // Get message after comma
        char* error_msg = strchr(message, ',') + 1;
        printf("ERROR: %s\n", error_msg);
        exit(EXIT_FAILURE);
    }
}

void authenticate(){
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

    char auth_message[1024] = "auth,";
    strcat(auth_message, username);
    strcat(auth_message, ",");
    strcat(auth_message, password_hash_hexa);
    if (sndmsg(auth_message, SERVER_PORT) != 0)
    {
        fprintf(stderr, "Erreur lors de l'envoi des informations d'authentification au serveur\n");
        return;
    }

    free(password_hash_hexa);

    char response[1024] = "";
    if (getmsg(response) == -1) {
        fprintf(stderr, "Error while receiving AES token message\n");
        return;
    }
    stopserver();

    checkError(response);

    // Save token
    char *attribuedToken = strtok(response, ",");
    token = malloc(strlen(attribuedToken));
    strcpy(token, attribuedToken);
    // Save port
    char *attribuedPortStr = strtok(NULL, ",");
    attribuedPort = atoi(attribuedPortStr);
}

void processUploadFile(char* filename, char* token, int receivingPort, int destinationPort, bool sendPublicKey, char* keyRSAPrefix){
    // Start server to receive messages
    if (startserver(receivingPort) == -1)
    {
        fprintf(stderr, "ERREUR: Impossible de démarrer le serveur pour l'upload\n");
        return;
    }

    // Open the file descriptor to read
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        fprintf(stderr, "ERREUR: Impossible d'ouvrir le fichier à upload\n");
        return;
    }

    // Get total file length
    fseek(file, 0, SEEK_END);
    long long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    long long total_read = 0;

    // Send to the server a first message containing a start hint and the filename
    char server_message[1024] = "up,";
    // Add token if not null for authentication
    if (token != NULL) {
        strcat(server_message, token);
        strcat(server_message, ",");
    }
    strcat(server_message, "FILE_START,");
    strcat(server_message, filename);
    long long result = sndmsg(server_message, destinationPort);
    if (result != 0)
    {
        fprintf(stderr, "ERREUR: Envoi du message au destinataire impossible\n");
        return;
    }

    // Get server response
    char server_response[1024] = "";
    if (getmsg(server_response) == -1)
    {
        fprintf(stderr, "ERREUR: Impossible de recevoir un message\n");
        return;
    }

    checkError(server_response);

    printf("%s\n", server_response);

    while (!feof(file))
    {
        char server_message[1024] = "up,";
        // Add token
        if (token != NULL) {
            strcat(server_message, token);
            strcat(server_message, ",");
        }
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

        long long result = sndmsg(server_message, destinationPort);
        if (result != 0)
        {
            fprintf(stderr, "ERREUR: Envoi du message au destinataire impossible\n");
            return;
        }
        // Show progress
        total_read += num_read;
        printf("Progrès: %lld/%lld (%lld%%)\n", total_read, file_size, total_read * 100 / file_size);
    }

    if (sendPublicKey) {
        // Send the public key to the server
        char server_message1[1024] = "up,";
        // Add token
        if (token != NULL) {
            strcat(server_message1, token);
            strcat(server_message1, ",");
        }
        strcat(server_message1, "PUBLIC_KEY,");
        char* publicKeyName = malloc(strlen(keyRSAPrefix) + 1 + strlen("_public.pem") + 1);
        strcpy(publicKeyName, keyRSAPrefix);
        strcat(publicKeyName, "_public.pem");
        char* publicKey = load_key(publicKeyName);

        strcat(server_message1, publicKey);
        long long result1 = sndmsg(server_message1, destinationPort);
        if (result1 != 0)
        {
            fprintf(stderr, "ERREUR: Envoi du message au destinataire impossible\n");
            return;
        }

        free(publicKeyName);
        free(publicKey);
    }

    // Get file signature to send to recipient
    int signature_length;
    unsigned char *signature = getFileSignature(file, &signature_length, keyRSAPrefix);
    if (signature == NULL)
    {
        fprintf(stderr, "ERROR: Signature de fichier non générable\n");
        return;
    }

    // Encode the signature to base64
    char* encoded_signature = base64_encode(signature, signature_length);
    free(signature);

    // Send to the recipient a last message containing the signature
    char server_message2[1024] = "up,";
    // Add token
    if (token != NULL) {
        strcat(server_message2, token);
        strcat(server_message2, ",");
    }
    strcat(server_message2, "FILE_END");
    strcat(server_message2, ",");
    strcat(server_message2, encoded_signature);
    free(encoded_signature);
    long long result2 = sndmsg(server_message2, destinationPort);
    if (result2 != 0)
    {
        fprintf(stderr, "ERREUR: Envoi du message au destinatire impossible\n");
        return;
    }

    char received_msg[1024] = "";
    if (getmsg(received_msg) == -1)
    {
        fprintf(stderr, "ERREUR: Impossible de recevoir un message\n");
        return;
    }
    printf("%s\n", received_msg);

    fclose(file);
    stopserver();
}

void processListServerFiles(){
    char server_message[1024] = "list,";
    // Add token
    strcat(server_message, token);
    sndmsg(server_message, SERVER_PORT);
    // Affichez la liste des fichiers reçue du serveur
    if (startserver(attribuedPort) == -1)
    {
        fprintf(stderr, "Failed to start the server client\n");
        return;
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

void processDownload(char* filename){
    // Exemple d'utilisation : ./client -down "filename"
    char server_message[1024] = "down,";
    // Add token
    strcat(server_message, token);
    strcat(server_message, ",");
    strcat(server_message, filename);

    sndmsg(server_message, SERVER_PORT);

    if (startserver(attribuedPort) == -1)
    {
        fprintf(stderr, "Failed to start the server client\n");
        return;
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
    if (argc < 2) return print_usage();

    // Generate RSA key pair
    generate_rsa_keypair(2048);

    // Authenticate user from server and get token and port for future communications
    authenticate();

    // Traitement des options en fonction des arguments de la ligne de commande
    if (strcmp(argv[1], "-up") == 0 && argc >= 3)
    {
        // Exemple d'utilisation : ./client -up <nom du fichier>
        processUploadFile(argv[2], token, attribuedPort, SERVER_PORT, true, "client");
    }
    else if (strcmp(argv[1], "-list") == 0 && argc == 2)
    {
        // Exemple d'utilisation : ./client -list
        processListServerFiles();
    }
    else if (strcmp(argv[1], "-down") == 0 && argc == 3)
    {
        // Exemple d'utilisation : ./client -down "filename"
        processDownload(argv[2]);
    }
    else
    {
        fprintf(stderr, "Option non reconnue ou nombre incorrect d'arguments.\n");
        return EXIT_FAILURE;
    }

    free(token);

    return EXIT_SUCCESS;
}