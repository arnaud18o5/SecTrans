#include "client.h"
#include "server.h"
#include "hash.h"
#include "base_encoding.h"
#include "rsa.h"
#include "signature.h"
#include "file_transfer.h"
#include "error.h"

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
        processSendFile(argv[2], token, attribuedPort, SERVER_PORT, 1, "client");
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