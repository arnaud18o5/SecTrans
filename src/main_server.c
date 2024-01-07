#include "server.h"
#include "client.h"
#include "../include/hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

FILE *currentOpenedFile;

int verifySignature(FILE* file, unsigned char* signature, size_t signature_len, char* publicKey) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        // handle error
        return 0;
    }

    // TEST
    // Create signed hash
    unsigned char* hash = calculate_hash(file);
    // Log the hash
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    // Log the file size
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    printf("\nFile size: %ld\n", fileSize);
    // Log the first 10 bytes
    fseek(file, 0, SEEK_SET);
    unsigned char testtest[100];
    fread(testtest, 1, 100, file);
    for (int i = 0; i < 100; i++) {
        printf("%02x", testtest[i]);
    }
    printf("\n");
    fseek(file, 0, SEEK_SET);

    EVP_PKEY* evp_key = NULL;
    BIO* bio = BIO_new_mem_buf(publicKey, -1);
    PEM_read_bio_PUBKEY(bio, &evp_key, NULL, NULL);
    BIO_free(bio);

    if (!evp_key) {
        // handle error
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, evp_key) != 1) {
        // handle error
        EVP_PKEY_free(evp_key);
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    unsigned char buffer[4096];
    size_t len;
    while ((len = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestVerifyUpdate(ctx, buffer, len) != 1) {
            // handle error
            EVP_PKEY_free(evp_key);
            EVP_MD_CTX_free(ctx);
            return 0;
        }
    }

    int ret = EVP_DigestVerifyFinal(ctx, signature, signature_len);

    EVP_PKEY_free(evp_key);
    EVP_MD_CTX_free(ctx);

    return (ret == 1);
}

// Function to decode Base64 to data
unsigned char* base64_decode(const char* buffer, size_t* length) {
    BIO *bio, *b64;

    int decodeLen = strlen(buffer);
    unsigned char* decode = (unsigned char*)malloc(decodeLen);
    memset(decode, 0, decodeLen);

    bio = BIO_new_mem_buf(buffer, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *length = BIO_read(bio, decode, decodeLen);

    BIO_free_all(bio);

    return decode;
}

void processUpMessage(char *received_msg)
{
    // Move the pointer to the first character after the comma
    char *msg = strchr(received_msg, ',') + 1;

    // Check if header contains FILE_START
    char *fileStart = "FILE_START";
    char *publicKey = "PUBLIC_KEY";
    char *fileEnd = "FILE_END";
    
    char *clientPublicKey;

    if (strstr(msg, fileStart) != NULL) {
        // Get filename
        char *filename = strchr(msg, ',') + 1;

        // Get only the filename without the path
        char *filenameWithoutPath = strrchr(filename, '/');
        if (filenameWithoutPath != NULL) {
            filename = filenameWithoutPath + 1;
        }

        // Create file in the directory upload
        char *uploadDir = "upload/";
        char *fullFilename = malloc(strlen(uploadDir) + strlen(filename) + 1);
        strcpy(fullFilename, uploadDir);
        strcat(fullFilename, filename);
        printf("Uploaded file: %s\n", fullFilename);

        // Open file
        currentOpenedFile = fopen(fullFilename, "w");
        if (currentOpenedFile == NULL) {
            fprintf(stderr, "Erreur lors de l'ouverture du fichier\n");
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
        if (verifySignature(currentOpenedFile, decodedSignature, decodedLength, clientPublicKey)) {
            printf("Signature verified!\n");
        } else {
            printf("Signature not verified!\n");
        }

        // Free memory
        free(decodedSignature);

        // Close file
        fclose(currentOpenedFile);

        printf("File uploaded!\n");
    }

    // Check if header contains PUBLIC_KEY
    else if (strstr(msg, publicKey) != NULL) {
        // Get the public key after the comma
        clientPublicKey = strchr(msg, ',') + 1;
    }

    // Write to file
    else {
        // Decode and write to file
        size_t decodedLength;
        unsigned char *decodedMessage = base64_decode(msg, &decodedLength);
        fwrite(decodedMessage, 1, decodedLength, currentOpenedFile);
        free(decodedMessage);
    }
} 


void processListMessage(char *port) {
    printf("Envoyer la liste de fichier au client\n");
    int portClient = atoi(port);
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
        // Ignorer les entrées spéciales "." et ".."
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            printf("%s\n", entry->d_name);
            
            // Allouer de l'espace pour le nouveau nom de fichier
            res = realloc(res, strlen(res) + strlen(entry->d_name) + 2);
            
            // Concaténer le nouveau nom de fichier à la chaîne résultante
            strcat(res, entry->d_name);
            strcat(res, "\n");
        }
    }

    sndmsg(res, portClient);

    // Libérer la mémoire allouée pour la chaîne résultante
    free(res);

    // Fermer le répertoire
    closedir(dir);
}


void processDownMessage(char *port, char *msg)
{
    printf("Envoyer le contenu du fichier au client\n");
    printf("Message à télécharger : %s\n", msg);
    int portClient = atoi(port);
    sndmsg(msg, portClient);
    // Ajoutez le code nécessaire pour envoyer le contenu du fichier au client
    // ...
}

int main()
{
    int port = 12345; // Choisissez le port que vous souhaitez utiliser

    if (startserver(port) == -1)
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

            if (strcmp(token, "up") == 0)
            {
                processUpMessage(received_msg);
            }
            else if (strcmp(token, "list") == 0)
            {
                processListMessage("12346");
            }
            else if (strcmp(token, "down") == 0)
            {
                char *port = strtok(NULL, ",");
                char *msg = strtok(NULL, ",");
                processDownMessage(port, msg);
            }

            free(token); // Don't forget to free the memory when you're done
        } else {
            fprintf(stderr, "No comma found in message\n");
        }
    }

    stopserver();

    return EXIT_SUCCESS;
}