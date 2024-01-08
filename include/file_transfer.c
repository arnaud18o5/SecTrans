#include "file_transfer.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void processUploadFile(char* filename, char* token, int receivingPort, int destinationPort, int sendPublicKey, char* keyRSAPrefix){
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