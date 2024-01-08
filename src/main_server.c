
#include "server.h"
#include "client.h"
#include "base_encoding.h"
#include "signature.h"
#include "user.h"
#include "file_transfer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

unsigned char tokenKey[32];

const int SERVER_PORT = 12345;
const int DEFAULT_CLIENT_PORT = 12346;
int lastAttribuedClientPort = 12347;

void processListMessage(char *received_msg) {
    // Get token after the first comma
    char *token = strchr(received_msg, ',') + 1;
    User *user = getUserFromToken(token, tokenKey);
    if (user == NULL) return;

    // Ouvrir le répertoire /upload
    DIR *dir;
    struct dirent *entry;

    dir = opendir("upload/");

    if (dir == NULL) {
        perror("Erreur lors de l'ouverture du répertoire");
        exit(EXIT_FAILURE);
    }

    // Utiliser une chaîne dynamique pour stocker les noms de fichiers
    char *res = malloc(1); // Allocation initiale d'un octet
    res[0] = '\0'; // Chaîne vide

    // Parcourir les fichiers du répertoire
    while ((entry = readdir(dir)) != NULL) {
        // Get only file finished by .meta
        if (strstr(entry->d_name, ".meta") != NULL) {
            // Open file and read first line
            char *metadateFullFilename = malloc(strlen(entry->d_name) + 8);
            strcpy(metadateFullFilename, "upload/");
            strcat(metadateFullFilename, entry->d_name);
            FILE *metadataFile = fopen(metadateFullFilename, "r");
            if (metadataFile == NULL) continue;
            char role[20];
            fscanf(metadataFile, "%s", role);
            fclose(metadataFile);

            // Check if user has access to file
            if (strcmp(user->role, role) == 0) {
                // Allouer de l'espace pour le nouveau nom de fichier (sans .meta)
                char *filename = malloc(strlen(entry->d_name) - 5);
                // Reallouer la chaîne résultante pour y ajouter le nouveau nom de fichier
                res = realloc(res, strlen(res) + strlen(entry->d_name) - 5 + 5);
                
                // Concaténer le nouveau nom de fichier à la chaîne résultante (sans .meta)
                strncpy(filename, entry->d_name, strlen(entry->d_name) - 5);
                filename[strlen(entry->d_name) - 5] = '\0';
                strcat(res, " - ");
                strcat(res, filename);
                strcat(res, "\n");
            }
        }
    }
    // If res size is 0, no file was found
    if (strlen(res) == 0) {
        sndmsg("No file found!", user->attribuedPort);
    } else {
        sndmsg(res, user->attribuedPort);
    }

    // Libérer la mémoire allouée pour la chaîne résultante
    free(res);

    // Fermer le répertoire
    closedir(dir);

    printf("Liste de fichier envoyée au client\n");
}


void processDownMessage(char *received_msg)
{
    printf("DOWNLOAD: Envoie d'un fichier au client\n");

    // Get data
    strtok(received_msg, ",");
    char *token = strtok(NULL, ",");
    char *filename = strtok(NULL, ",");

    // Get user
    User *user = getUserFromToken(token, tokenKey);
    if (user == NULL) return;

    // Check if user has access to file
    char *metadataFilename = malloc(strlen(filename) + 5 + 8);
    strcpy(metadataFilename, "upload/");
    strcat(metadataFilename, filename);
    strcat(metadataFilename, ".meta");
    FILE *metadataFile = fopen(metadataFilename, "r");
    if (metadataFile == NULL) {
        char message[1024] = "error,File doesn't exist!";
        sndmsg(message, user->attribuedPort);
        printf("ERROR: File doesn't exist!\n");
        return;
    }
    char role[20];
    fscanf(metadataFile, "%s", role);
    fclose(metadataFile);
    if (strcmp(user->role, role) != 0) {
        char message[1024] = "error,You don't have access to this file!";
        sndmsg(message, user->attribuedPort);
        printf("ERROR: User doesn't have access to this file!\n");
        return;
    }

    // Start download
    char* fullFilename = malloc(strlen(filename) + 8);
    strcpy(fullFilename, "upload/");
    strcat(fullFilename, filename);
    processSendFile(fullFilename, NULL, 0, user->attribuedPort, 0, "server");
}

int main()
{
    // Generate RSA key pair
    generate_rsa_keypair(2048);

    // Generate the key for the token
    if (RAND_bytes(tokenKey, sizeof(tokenKey)) != 1) {
        fprintf(stderr, "Error generating AES key\n");
        return EXIT_FAILURE;
    }

    if (startserver(SERVER_PORT) == -1)
    {
        fprintf(stderr, "Failed to start the server\n");
        return EXIT_FAILURE;
    }

    char received_msg[1024];

    while (1)
    {
        if (getmsg(received_msg) == -1)
        {
            fprintf(stderr, "Error while receiving message\n");
            break;
        }

        char *commaPos = strchr(received_msg, ',');
        if (commaPos != NULL) {
            int tokenLength = commaPos - received_msg;
            char *token = malloc(tokenLength + 1); // +1 for the null-terminator
            if (token == NULL) {
                fprintf(stderr, "Failed to allocate memory for token\n");
                return EXIT_FAILURE;
            }
            strncpy(token, received_msg, tokenLength);
            token[tokenLength] = '\0'; // Null-terminate the string

            // TODO: decrypedToken
            if (strcmp(token, "up") == 0)
            {
                processReceiveFile(received_msg, 1, tokenKey, "upload/");
            }
            else if (strcmp(token, "list") == 0)
            {
                processListMessage(received_msg);
            }
            else if (strcmp(token, "down") == 0)
            {
                processDownMessage(received_msg);
            }
            else if (strcmp(token, "auth") == 0)
            {
                // Get login and password
                char clientUsername[30];
                char clientPassword[65];
                getLoginAndPassword(received_msg, clientUsername, clientPassword);

                // Authenticate user
                User *user = authenticateUser(clientUsername, clientPassword);
                if (user == NULL) {
                    sndmsg("error,Bad credentials", DEFAULT_CLIENT_PORT);
                    fprintf(stderr, "Error when authenticating: bad credentials\n");
                    continue;
                }

                // Generate token
                size_t tokenSize = strlen(clientUsername) + strlen(user->role) + 2;
                unsigned char *encryptedToken = encryptToken(createSpecialToken(clientUsername, user->role),tokenSize,tokenKey);
                size_t encryptedSize = (tokenSize / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
                char *base64Token = base64_encode(encryptedToken, encryptedSize);

                // Assign port to user
                user->attribuedPort = lastAttribuedClientPort;
                lastAttribuedClientPort++;

                // Send token to client with the port
                char message[1024];
                snprintf(message, 1024, "%s,%d", base64Token, user->attribuedPort);
                sndmsg(message, DEFAULT_CLIENT_PORT);
                
                // Free memory
                free(encryptedToken);
                free(base64Token);
            }

            free(token); // Don't forget to free the memory when you're done
        } else {
            fprintf(stderr, "No comma found in message\n");
        }
    }
    stopserver();

    return EXIT_SUCCESS;
}
