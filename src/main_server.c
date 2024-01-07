#include "server.h"
#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>

#include "encryption.h"

#define KEY_LENGTH 512
#define PUB_EXP 65537

FILE *currentOpenedFile;

// Function to decode Base64 to data
unsigned char *base64_decode(const char *buffer, size_t *length)
{
    BIO *bio, *b64;

    int decodeLen = strlen(buffer);
    unsigned char *decode = (unsigned char *)malloc(decodeLen);
    memset(decode, 0, decodeLen);

    bio = BIO_new_mem_buf(buffer, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *length = BIO_read(bio, decode, decodeLen);

    BIO_free_all(bio);

    return decode;
}

/*char *decryptMessage(char *pri_key, char *received_msg)
{
    RSA *rsa = NULL;

    // Charger la clé privée RSA depuis la chaîne PEM
    BIO *bio_priv = BIO_new_mem_buf(pri_key, -1);
    if (bio_priv == NULL)
    {
        perror("Erreur lors de la création du BIO pour la clé privée");
        exit(EXIT_FAILURE);
    }

    rsa = PEM_read_bio_RSAPrivateKey(bio_priv, NULL, NULL, NULL);
    if (rsa == NULL)
    {
        ERR_print_errors_fp(stderr); // Imprimer des informations sur les erreurs
        perror("Erreur lors de la lecture de la clé privée");
        BIO_free(bio_priv);
        exit(EXIT_FAILURE);
    }

    BIO_free(bio_priv);

    int rsa_len = RSA_size(rsa);

    // Buffer pour le message déchiffré
    unsigned char *decrypted_message = (unsigned char *)malloc(rsa_len);

    // Déchiffrement RSA
    int result = RSA_private_decrypt(rsa_len, received_msg, decrypted_message, rsa, RSA_PKCS1_PADDING);
    if (result == -1)
    {
        ERR_print_errors_fp(stderr); // Imprimer des informations sur les erreurs
        perror("Erreur lors du déchiffrement RSA");
        RSA_free(rsa);
        free(decrypted_message);
        exit(EXIT_FAILURE);
    }

    RSA_free(rsa);

    return (char *)decrypted_message;
}*/

void processUpMessage(char *received_msg)
{
    // Move the pointer to the first character after the comma

    char *msg = strchr(received_msg, ',') + 1;

    // Check if header contains FILE_START
    char *fileStart = "FILE_START";
    char *fileEnd = "FILE_END";

    if (strstr(msg, fileStart) != NULL)
    {
        // Get filename
        char *filename = strchr(msg, ',') + 1;

        // Get only the filename without the path
        char *filenameWithoutPath = strrchr(filename, '/');
        if (filenameWithoutPath != NULL)
        {
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
        if (currentOpenedFile == NULL)
        {
            fprintf(stderr, "Erreur lors de l'ouverture du fichier\n");
        }
    }
    // Check if header contains FILE_END
    else if (strstr(msg, fileEnd) != NULL)
    {
        // Close file
        fclose(currentOpenedFile);

        printf("File uploaded!\n");
    }

    // Write to file
    else
    {
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

int main()
{
    int port = 12345; // Choisissez le port que vous souhaitez utiliser

    size_t pri_len; // Length of private key
    size_t pub_len; // Length of public key
    char *pri_key;  // Private key
    char *pub_key;  // Public key

    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = malloc(pri_len + 1);
    pub_key = malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    printf("\n%s\n%s\n", pri_key, pub_key);

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
        if (commaPos != NULL)
        {
            int tokenLength = commaPos - received_msg;
            char *token = malloc(tokenLength + 1); // +1 for the null-terminator
            if (token == NULL)
            {
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
                char *port = strtok(NULL, ",");
                processListMessage(port);
            }
            else if (strcmp(token, "down") == 0)
            {
                char *port = strtok(NULL, ",");
                char *msg = strtok(NULL, ",");
                processDownMessage(port, msg);
            }
            else if (strcmp(token, "rsa") == 0)
            {
                printf("Demande de clé publique\n");
                if (commaPos != NULL)
                {
                    char *secondComma = strchr(commaPos + 1, ',');
                    if (secondComma != NULL)
                    {
                        int length = secondComma - (commaPos + 1);
                        char token[10]; // Taille suffisante pour stocker le token
                        strncpy(token, commaPos + 1, length);
                        token[length] = '\0'; // Ajouter le caractère nul à la fin
                        int portClient = atoi(token);
                        sndmsg(pub_key, portClient);
                        printf("Clé publique envoyée au client\n");
                        if (startserver(port) == -1)
                        {
                            fprintf(stderr, "Failed to start the server\n");
                            return EXIT_FAILURE;
                        }

                        char msg_to_decrypt[1024];

                        int msg_received = 0;
                        printf("En attente de message du client...\n");
                        while (msg_received == 0)
                        {
                            if (getmsg(msg_to_decrypt) == -1)
                            {
                                fprintf(stderr, "Error while receiving message\n");
                                break;
                            }
                            printf("Message reçu : %s\n", msg_to_decrypt);
                            RSA *rsa = NULL;
                            char *decryptedMessage = decryptMessage(pri_key, msg_to_decrypt);
                            printf("Message déchiffré : %s\n", decryptedMessage);
                            msg_received = 1;
                        }
                    }

                    free(token); // Don't forget to free the memory when you're done
                }
                else
                {
                    fprintf(stderr, "No comma found in message\n");
                }
            }

            stopserver();

            return EXIT_SUCCESS;
        }
    }
}