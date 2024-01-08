#include "file_transfer.h"
#include "client.h"
#include "server.h"
#include "hash.h"
#include "base_encoding.h"
#include "rsa.h"
#include "signature.h"
#include "error.h"
#include "user.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char currentReceivedFilename[256];
FILE *currentOpenedFileForReceiving;

void processSendFile(char* filename, char* token, int listeningPort, int receiverPort, int sendPublicKey, char* keyRSAPrefix){
    // If we don't send public key it means we are sending a file to a client (we are the server, so the client already have the public key)
    const int waitForReceiverResponse = sendPublicKey;

    // Start server to receive messages
    if (waitForReceiverResponse) {
        if(startserver(listeningPort) == -1) {
            fprintf(stderr, "ERREUR: Impossible de démarrer le serveur pour l'upload\n");
            return;
        }
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
    }
    strcat(server_message, ",FILE_START,");
    strcat(server_message, filename);
    long long result = sndmsg(server_message, receiverPort);
    if (result != 0)
    {
        fprintf(stderr, "ERREUR: Envoi du message au destinataire impossible\n");
        return;
    }

    if (waitForReceiverResponse) {
        // Get server response
        char server_response[1024] = "";
        if (getmsg(server_response) == -1)
        {
            fprintf(stderr, "ERREUR: Impossible de recevoir un message\n");
            return;
        }
        checkError(server_response);
        printf("%s\n", server_response);
    }

    while (!feof(file))
    {
        char server_message[1024] = "up,";
        // Add token
        if (token != NULL) {
            strcat(server_message, token);
        }
        strcat(server_message, ",");
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

        long long result = sndmsg(server_message, receiverPort);
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
        }
        strcat(server_message1, ",PUBLIC_KEY,");
        char* publicKeyName = malloc(strlen(keyRSAPrefix) + 1 + strlen("_public.pem") + 1);
        strcpy(publicKeyName, keyRSAPrefix);
        strcat(publicKeyName, "_public.pem");
        char* publicKey = load_key(publicKeyName);

        strcat(server_message1, publicKey);
        long long result1 = sndmsg(server_message1, receiverPort);
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
    }
    strcat(server_message2, ",FILE_END,");
    strcat(server_message2, encoded_signature);
    free(encoded_signature);
    long long result2 = sndmsg(server_message2, receiverPort);
    if (result2 != 0)
    {
        fprintf(stderr, "ERREUR: Envoi du message au destinatire impossible\n");
        return;
    }
    printf("ON EST ICI");

    if (waitForReceiverResponse) {
        char received_msg[1024] = "";
        if (getmsg(received_msg) == -1)
        {
            fprintf(stderr, "ERREUR: Impossible de recevoir un message\n");
            return;
        }
        printf("%s\n", received_msg);
    }

    fclose(file);
    stopserver();
}

void processReceiveFile(char *received_msg, int getUser, unsigned char* tokenKey, char* uploadDir)
{
    // Copy received message
    char *received_msg_copy = malloc(strlen(received_msg) + 1);
    strcpy(received_msg_copy, received_msg);
    // Get token after the first comma
    strtok(received_msg_copy, ",");
    char *token = strtok(NULL, ",");

    // Get user
    User *user = NULL;
    if (getUser) {
        user = getUserFromToken(token, tokenKey);
        if (user == NULL) return;
    }

    // Get the message after the 2 commas
    char *msg = strchr(received_msg, ',') + 1;
    msg = strchr(msg, ',') + 1;

    // Check if header contains FILE_START
    char *fileStart = "FILE_START";
    char *publicKey = "PUBLIC_KEY";
    char *fileEnd = "FILE_END";

    if (strstr(msg, fileStart) != NULL) {
        // Get filename
        char *filename = strchr(msg, ',') + 1;

        // Get only the filename without the path
        char *filenameWithoutPath = strrchr(filename, '/');
        if (filenameWithoutPath != NULL) {
            filename = filenameWithoutPath + 1;
        }

        // Create full filename
        char *fullFilename = malloc(strlen(uploadDir) + strlen(filename) + 1);
        strcpy(fullFilename, uploadDir);
        strcat(fullFilename, filename);
        printf("Receiving file: %s\n", fullFilename);
        if (getUser) strcpy(user->currentUploadFileName, fullFilename);
        else strcpy(currentReceivedFilename, fullFilename);

        // Check if file exists, if so send error
        if (access(fullFilename, F_OK) != -1) {
            if (getUser) {
                char message[1024] = "error,File already exists, please choose another name!";
                sndmsg(message, user->attribuedPort);
            }
            printf("ERROR: File already exists!\n");
            return;
        } else if (getUser) {
            char message[1024] = "Uploading started!";
            sndmsg(message, user->attribuedPort);
        }

        // Open file
        if (getUser) {
            user->currentOpenedFile = fopen(fullFilename, "w+");
            if (user->currentOpenedFile == NULL) {
                fprintf(stderr, "Erreur lors de l'ouverture du fichier\n");
            }
        } else {
            currentOpenedFileForReceiving = fopen(fullFilename, "w+");
            if (currentOpenedFileForReceiving == NULL) {
                fprintf(stderr, "Erreur lors de l'ouverture du fichier\n");
            }
        }

        // Only create metadata file if user is used
        if (getUser) {
            // Create metadata file with role in first line and owner in second line
            char *metadataFilename = malloc(strlen(fullFilename) + 5);
            strcpy(metadataFilename, fullFilename);
            strcat(metadataFilename, ".meta");
            FILE *metadataFile = fopen(metadataFilename, "w+");
            if (metadataFile == NULL) {
                fprintf(stderr, "Erreur lors de l'ouverture du fichier\n");
            }
            fprintf(metadataFile, "%s\n%s\n", user->role, user->username);
            fclose(metadataFile);
        }
    }
    // Check if header contains FILE_END
    else if (strstr(msg, fileEnd) != NULL) {
        // Get the signature after the comma
        char *signature = strchr(msg, ',') + 1;

        // Decode signature
        size_t decodedLength;
        unsigned char *decodedSignature = base64_decode(signature, &decodedLength);

        // Verify signature
        if (verifySignature(user->currentOpenedFile, decodedSignature, decodedLength, user->publicKey)) {
            char message[1024] = "File uploaded successfully!";
            fclose(getUser ? user->currentOpenedFile : currentOpenedFileForReceiving);
            // Notify client that file was uploaded successfully
            if (getUser) sndmsg(message, user->attribuedPort);
            printf("File uploaded successfully!\n");
        } else {
            char message[1024] = "Invalid signature, the file couldn't be uploaded, please retry!";
            // Close file and delete it
            fclose(getUser ? user->currentOpenedFile : currentOpenedFileForReceiving);
            unlink(getUser ? user->currentUploadFileName : currentReceivedFilename);
            // Notify client that file couldn't be uploaded
            if(getUser) sndmsg(message, user->attribuedPort);
            printf("ERROR: Invalid signature, the file is deleted!\n");
        }

        // Free memory
        free(decodedSignature);

        // If don't have a user system (so we're a client), close the program
        if (!getUser) exit(0);
    }

    // Check if header contains PUBLIC_KEY
    else if (strstr(msg, publicKey) != NULL && getUser) {
        // Get the public key after the comma and copy it in new memory location
        char *publicKey = strchr(msg, ',') + 1;
        strncpy(user->publicKey, publicKey, strlen(publicKey) + 1);
    }

    // Write to file
    else {
        // Decode and write to file
        size_t decodedLength;
        unsigned char *decodedMessage = base64_decode(msg, &decodedLength);
        fwrite(decodedMessage, 1, decodedLength, getUser ? user->currentOpenedFile : currentOpenedFileForReceiving);
        free(decodedMessage);
    }

    free(received_msg_copy);
}