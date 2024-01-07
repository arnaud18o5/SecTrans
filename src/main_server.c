    #include "server.h"
    #include "client.h"
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <openssl/bio.h>
    #include <openssl/evp.h>
    #include <openssl/buffer.h>

    FILE *currentOpenedFile;

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
        char *fileEnd = "FILE_END";

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
            // Close file
            fclose(currentOpenedFile);

            printf("File uploaded!\n");
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


    void processListMessage(char *port)
    {
        printf("envoyer la liste des fichiers au client au port %s\n", port);
        // Ajoutez le code nécessaire pour envoyer la liste des fichiers au client
        // ...
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

    typedef struct {
        char username[30];
        char password[30];
        char role[20];
    } User;

    User users[] = {
        {"samuel", "pwd1", "Reader"},
        {"arnaud", "pwd2", "Writer"},
        {"alexis", "pwd3", "Admin"},
        {"julian", "pwd4", "Admin"}
    };

    User* authenticateUser(const User *users, const char *username, const char *password) {
        for (int i = 0; i < sizeof(users) / sizeof(User); i++) {
            if (strcmp(username, users[i].username) == 0 && strcmp(password, users[i].password) == 0) {
                return &(users[i]);
            }
        }
        return NULL;
    }

    int isWriter(User user) {
        return (strcmp(user.role, "Writer") == 0 || strcmp(user.role, "Admin") == 0);

    }

    int isReader(User user) {
        return (strcmp(user.role, "Reader") == 0 || strcmp(user.role, "Admin") == 0);
    }


    int isAdmin(User user) {
        return (strcmp(user.role, "Admin") == 0);
    }

    char* getRole(const char *username, const char *password) {
    for (int i = 0; i < sizeof(users) / sizeof(User); i++) {
        if (strcmp(username, users[i].username) == 0 && strcmp(password, users[i].password) == 0) {
            return users[i].role;
        }
    }
    return NULL; 
}

    unsigned char* createSpecialToken(const char *username, const char *role) {
        size_t tokenSize = strlen(username) + strlen(role) + 1;

        char *specialToken = (char *)malloc(tokenSize);
        if (specialToken == NULL) {
            fprintf(stderr, "Error during allocation for the token\n");
            return NULL;
        }

        snprintf(specialToken, tokenSize, "%s%s", username, role);

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

    void decryptToken(const unsigned char *encryptedToken, size_t tokenSize, const unsigned char *key) {
        AES_KEY aesKey;
        AES_set_decrypt_key(key, 256, &aesKey);

        unsigned char decryptedToken[tokenSize];
        memset(decryptedToken, 0, sizeof(decryptedToken));

        AES_decrypt(encryptedToken, decryptedToken, &aesKey);
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

        if (getmsg(received_msg) == -1)
        {
            fprintf(stderr, "Error while receiving message\n");
            break;
        }

        char clientUsername[30];
        char clientPassword[30];
        char clientRole[20];

        clientUsername = getmsg(received_msg);
        clientPassword = getmsg(received_msg);

        

        unsigned char key[32];
        if (RAND_bytes(key, sizeof(key)) != 1) {
            fprintf(stderr, "Error generating AES key\n");
            return EXIT_FAILURE;
        }

        sndmsg(encryptToken(createSpecialToken(clientUsername, getRole(clientUsername, clientPassword))), 12346);



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

                if ((strcmp(token, "up") ==   0) && isReader(authenticatedUser))
                {
                    processUpMessage(received_msg);
                }
                else if (strcmp(token, "list") == 0 && isAdmin(authenticatedUser))
                {
                    char *port = strtok(NULL, ",");
                    processListMessage(port);
                }
                else if (strcmp(token, "down") == 0 && isWriter(authenticatedUser))
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
