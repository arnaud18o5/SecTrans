
#include "server.h"
#include "client.h"
#include "hash.h"
#include "base_encoding.h"

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

const int DEFAULT_CLIENT_PORT = 12346;
int lastAttribuedClientPort = 12347;

typedef struct {
    char username[30];
    char password[65];
    char role[20];
    int attribuedPort;
    FILE *currentOpenedFile;
    char currentUploadFileName[256];
    char publicKey[1024];
} User; 

// The passwords are written in the hexadecimal format
User users[] = {
    {"samuel", "6eac1114aa783f6549327e7d01f63752995da7b31f1f37092b7dcb9f49cf5651", "Compta", 0}, // Mot de passe : pwd1
    {"arnaud", "149d2937d1bce53fa683ae652291bd54cc8754444216a9e278b45776b76375af", "Compta", 0}, // Mot de passe : pwd2
    {"alexis", "ffc169417b4146cebe09a3e9ffbca33db82e3e593b4d04c0959a89c05b87e15d", "Finance", 0}, // Mot de passe : pwd3
    {"julian", "54775a53a76ae02141d920fd2a4682f6e7d3aef1f35210b9e4d253ad3db7e3a8", "Finance", 0} // Mot de passe : pwd4
};

User* authenticateUser(const char *username, const char *password) {
    for (int i = 0; i < sizeof(users) / sizeof(User); i++) {
        if (strcmp(username, users[i].username) == 0 && strcmp(password, users[i].password) == 0) {
            return &(users[i]);
        }
    }
    return NULL;
}

unsigned char *decryptToken(const unsigned char *encryptedToken, size_t tokenSize, const unsigned char *key) {
    AES_KEY aesKey;
    AES_set_decrypt_key(key, 256, &aesKey);

    unsigned char *decryptedToken = (unsigned char *)malloc(tokenSize);
    memset(decryptedToken, 0, sizeof(decryptedToken));

    AES_decrypt(encryptedToken, decryptedToken, &aesKey);

    return decryptedToken;
}

User* getUserFromToken(const char *token) {
    size_t decryptTokenLength;
    unsigned char *decodedToken = base64_decode(token, &decryptTokenLength);

    unsigned char *decryptedToken = decryptToken(decodedToken, decryptTokenLength, tokenKey);

    char *username = strtok(decryptedToken, ",");
    char *role = strtok(NULL, ",");
    if (username == NULL || role == NULL) {
        fprintf(stderr, "Error parsing token\n");
        return NULL;
    }

    for (int i = 0; i < sizeof(users) / sizeof(User); i++) {
        if (strcmp(username, users[i].username) == 0) {
            return &(users[i]);
        }
    }
}

int verifySignature(FILE* file, unsigned char* signature, size_t signature_len, char* publicKey) {
    // Set file to beginning
    fseek(file, 0, SEEK_SET);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }

    // Read public key
    BIO* bio = BIO_new_mem_buf(publicKey, -1);
    RSA* rsa_key = NULL;
    PEM_read_bio_RSAPublicKey(bio, &rsa_key, NULL, NULL);
    BIO_free(bio);

    // Check if public key is valid
    if (!rsa_key) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Create EVP_PKEY from RSA key
    EVP_PKEY* evp_key = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(evp_key, rsa_key)) {
        EVP_PKEY_free(evp_key);
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Initialize verification
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, evp_key) != 1) {
        EVP_PKEY_free(evp_key);
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Calculate hash of file
    unsigned char* file_hash = calculate_hash(file);
    // Check if hash is valid
    if (EVP_DigestVerifyUpdate(ctx, file_hash, SHA256_DIGEST_LENGTH) != 1) {
        EVP_PKEY_free(evp_key);
        EVP_MD_CTX_free(ctx);
        free(file_hash);
        return 0;
    }

    // Verify signature
    int ret = EVP_DigestVerifyFinal(ctx, signature, signature_len);
    EVP_PKEY_free(evp_key);
    EVP_MD_CTX_free(ctx);
    free(file_hash);

    return (ret == 1);
}

void processUpMessage(char *received_msg)
{
    // Copy received message
    char *received_msg_copy = malloc(strlen(received_msg) + 1);
    strcpy(received_msg_copy, received_msg);
    // Get token after the first comma
    strtok(received_msg_copy, ",");
    char *token = strtok(NULL, ",");

    // Get user
    User *user = getUserFromToken(token);
    if (user == NULL) return;

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
        char *uploadDir = "upload/";
        char *fullFilename = malloc(strlen(uploadDir) + strlen(filename) + 1);
        strcpy(fullFilename, uploadDir);
        strcat(fullFilename, filename);
        printf("Uploading file: %s\n", fullFilename);
        strcpy(user->currentUploadFileName, fullFilename);

        // Check if file exists, if so send error
        if (access(fullFilename, F_OK) != -1) {
            char message[1024] = "error,File already exists, please choose another name!";
            sndmsg(message, user->attribuedPort);
            printf("ERROR: File already exists!\n");
            return;
        } else {
            char message[1024] = "Uploading started!";
            sndmsg(message, user->attribuedPort);
        }

        // Open file
        user->currentOpenedFile = fopen(fullFilename, "w+");
        if (user->currentOpenedFile == NULL) {
            fprintf(stderr, "Erreur lors de l'ouverture du fichier\n");
        }

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
            fclose(user->currentOpenedFile);
            // Notify client that file was uploaded successfully
            sndmsg(message, user->attribuedPort);
            printf("File uploaded successfully!\n");
        } else {
            char message[1024] = "Invalid signature, the file couldn't be uploaded, please retry!";
            // Close file and delete it
            fclose(user->currentOpenedFile);
            unlink(user->currentUploadFileName);
            // Notify client that file couldn't be uploaded
            sndmsg(message, user->attribuedPort);
            printf("ERROR: Invalid signature, the file is deleted!\n");
        }

        // Free memory
        free(decodedSignature);
    }

    // Check if header contains PUBLIC_KEY
    else if (strstr(msg, publicKey) != NULL) {
        // Get the public key after the comma and copy it in new memory location
        char *publicKey = strchr(msg, ',') + 1;
        strncpy(user->publicKey, publicKey, strlen(publicKey) + 1);
    }

    // Write to file
    else {
        // Decode and write to file
        size_t decodedLength;
        unsigned char *decodedMessage = base64_decode(msg, &decodedLength);
        fwrite(decodedMessage, 1, decodedLength, user->currentOpenedFile);
        free(decodedMessage);
    }

    free(received_msg_copy);
}

void processListMessage(char *received_msg) {
    // Get token after the first comma
    char *token = strchr(received_msg, ',') + 1;
    User *user = getUserFromToken(token);
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
                // Log ok
                printf("User %s has access to file %s\n", user->username, entry->d_name);
                // Allouer de l'espace pour le nouveau nom de fichier (sans .meta)
                char *filename = malloc(strlen(entry->d_name) - 4);
                
                // Concaténer le nouveau nom de fichier à la chaîne résultante (sans .meta)
                strncpy(filename, entry->d_name, strlen(entry->d_name) - 5);
                strcat(res, "\n");
            }
        }
    }

    sndmsg(res, user->attribuedPort);

    // Libérer la mémoire allouée pour la chaîne résultante
    free(res);

    // Fermer le répertoire
    closedir(dir);

    printf("Liste de fichier envoyée au client\n");
}


void processDownMessage(char *received_msg)
{
    printf("Envoyer le contenu du fichier au client\n");

    // Get data
    strtok(received_msg, ",");
    char *token = strtok(NULL, ",");
    char *filename = strtok(NULL, ",");

    // Get user
    User *user = getUserFromToken(token);
    if (user == NULL) return;

    char msg[1024];
    snprintf(msg, 1024, "FILE_START,%s", filename);

    sndmsg(msg, user->attribuedPort);
    // Ajoutez le code nécessaire pour envoyer le contenu du fichier au client
    // ...
}

char* createSpecialToken(const char *username, const char *role) {
    size_t tokenSize = strlen(username) + strlen(role) + 2;

    char *specialToken = (char *)malloc(tokenSize);
    if (specialToken == NULL) {
        fprintf(stderr, "Error during allocation for the token\n");
        return NULL;
    }

    snprintf(specialToken, tokenSize, "%s,%s", username, role);

    return specialToken;
}

unsigned char* encryptToken(const unsigned char *token, size_t tokenSize, const unsigned char *key) {
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 256, &aesKey);

    size_t encryptedSize = (tokenSize / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

    unsigned char *encryptedToken = (unsigned char *)malloc(encryptedSize);
    if (encryptedToken == NULL) {
        fprintf(stderr, "Error allocating memory for encrypted token\n");
        return NULL;
    }

    memset(encryptedToken, 0, encryptedSize);

    AES_encrypt(token, encryptedToken, &aesKey);

    return encryptedToken;
}

void getLoginAndPassword(char message[], char login[], char password[]) {
    char *token = strtok(message, ",");
    token = strtok(NULL, ",");

    if (token != NULL) {
        strcpy(login, token);
        login[strlen(token)] = '\0';
    }
    else {
        fprintf(stderr, "Bad credentials\n");
        exit(EXIT_FAILURE);
    }

    token = strtok(NULL, ",");

    if (token != NULL) {
        strcpy(password, token);
        password[strlen(token)] = '\0';
    }
    else {
        fprintf(stderr, "Bad credentials\n");
        exit(EXIT_FAILURE);
    }
}

int main()
{
    int port = 12345; // Choisissez le port que vous souhaitez utiliser

    // Generate the key for the token
    if (RAND_bytes(tokenKey, sizeof(tokenKey)) != 1) {
        fprintf(stderr, "Error generating AES key\n");
        return EXIT_FAILURE;
    }

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

            // TODO: decrypedToken
            if (strcmp(token, "up") == 0)
            {
                processUpMessage(received_msg);
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
