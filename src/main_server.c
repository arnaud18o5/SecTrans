#include "server.h"
#include "client.h"
#include "../include/hash.h"
#include "encryption.h"

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

#define KEY_LENGTH 1024
#define PUB_EXP 65537

FILE *currentOpenedFile;
char *clientPublicKey;
char *currentUploadFileName;

const int CLIENT_PORT = 12346;

int verifySignature(FILE *file, unsigned char *signature, size_t signature_len, char *publicKey)
{
    // Set file to beginning
    fseek(file, 0, SEEK_SET);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        return 0;
    }

    // Read public key
    BIO *bio = BIO_new_mem_buf(publicKey, -1);
    RSA *rsa_key = NULL;
    PEM_read_bio_RSAPublicKey(bio, &rsa_key, NULL, NULL);
    BIO_free(bio);

    // Check if public key is valid
    if (!rsa_key)
    {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Create EVP_PKEY from RSA key
    EVP_PKEY *evp_key = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(evp_key, rsa_key))
    {
        EVP_PKEY_free(evp_key);
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Initialize verification
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, evp_key) != 1)
    {
        EVP_PKEY_free(evp_key);
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Calculate hash of file
    unsigned char *file_hash = calculate_hash(file);
    // Check if hash is valid
    if (EVP_DigestVerifyUpdate(ctx, file_hash, SHA256_DIGEST_LENGTH) != 1)
    {
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

    // decoupe decodedSignature tous les 128 char
    int nbBlocks = strlen(received_msg) / 128;

    FILE *privateKeyFile = fopen("private.pem", "r");
    if (privateKeyFile == NULL)
    {
        fprintf(stderr, "Erreur lors de l'ouverture du fichier\n");
        return EXIT_FAILURE;
    }
    // Get the public key
    char privateKey[1024];
    // Read all the file content
    char c;
    int i = 0;
    while ((c = fgetc(privateKeyFile)) != EOF)
    {
        privateKey[i] = c;
        i++;
    }
    privateKey[i] = '\0';

    printf("privateKey: %s\n", privateKey);

    char *decryptedSignature = malloc(strlen(received_msg) * sizeof(char));

    // decouper decodedSignature en pakcet de 128 char
    char *packet = malloc(128);
    int j = 0;
    int k = 0;
    for (j = 0; j < nbBlocks; j++)
    {
        for (k = 0; k < 128; k++)
        {
            packet[k] = received_msg[k + (j * 128)];
        }
        // decrypter packet
        char *decryptedPacket = decryptMessage(privateKey, packet);

        printf("decryptedPacket: %s\n", decryptedPacket);
        // concat decryptedPacket dans decryptedSignature
        strcat(decryptedSignature, decryptedPacket);
    }

    printf("decryptedSignature: %s\n", decryptedSignature);
    // Move the pointer to the first character after the comma

    char *msg = strchr(received_msg, ',') + 1;

    // Check if header contains FILE_START
    char *fileStart = "FILE_START";
    char *publicKey = "PUBLIC_KEY";
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
        printf("Uploading file: %s\n", fullFilename);
        currentUploadFileName = fullFilename;

        // Open file
        currentOpenedFile = fopen(fullFilename, "w+");
        if (currentOpenedFile == NULL)
        {
            fprintf(stderr, "Erreur lors de l'ouverture du fichier\n");
        }
        printf("File opened successfully!\n");
    }
    // Check if header contains FILE_END
    else if (strstr(msg, fileEnd) != NULL)
    {
        // Get the signature after the comma
        char *signature = strchr(msg, ',') + 1;

        // Decode signature
        size_t decodedLength;
        unsigned char *decodedSignature = base64_decode(signature, &decodedLength);

        printf("decoded signature: %s\n", decodedSignature);

        // Verify signature
        if (verifySignature(currentOpenedFile, decodedSignature, decodedLength, clientPublicKey))
        {
            char message[1024] = "File uploaded successfully!";
            fclose(currentOpenedFile);
            // Notify client that file was uploaded successfully
            sndmsg(message, CLIENT_PORT);
            printf("File uploaded successfully!\n");
        }
        else
        {
            char message[1024] = "Invalid signature, the file couldn't be uploaded, please retry!";
            // Close file and delete it
            fclose(currentOpenedFile);
            unlink(currentUploadFileName);
            // Notify client that file couldn't be uploaded
            sndmsg(message, CLIENT_PORT);
            printf("ERROR: Invalid signature, the file is deleted!\n");
        }

        // Free memory
        free(decodedSignature);
        free(clientPublicKey);
        free(currentUploadFileName);
    }

    // Check if header contains PUBLIC_KEY
    else if (strstr(msg, publicKey) != NULL)
    {
        // Get the public key after the comma and copy it in new memory location
        char *publicKey = strchr(msg, ',') + 1;
        clientPublicKey = malloc(strlen(publicKey) + 1);
        strncpy(clientPublicKey, publicKey, strlen(publicKey) + 1);
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

void processListMessage()
{
    // Ouvrir le répertoire /upload
    DIR *dir;
    struct dirent *entry;

    dir = opendir("upload/");

    if (dir == NULL)
    {
        perror("Erreur lors de l'ouverture du répertoire");
        exit(EXIT_FAILURE);
    }

    // Utiliser une chaîne dynamique pour stocker les noms de fichiers
    char *res = malloc(1); // Allocation initiale d'un octet
    res[0] = '\0';         // Chaîne vide

    // Parcourir les fichiers du répertoire
    while ((entry = readdir(dir)) != NULL)
    {
        // Ignorer les entrées spéciales "." et ".."
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {
            // Allouer de l'espace pour le nouveau nom de fichier
            res = realloc(res, strlen(res) + strlen(entry->d_name) + 2);

            // Concaténer le nouveau nom de fichier à la chaîne résultante
            strcat(res, entry->d_name);
            strcat(res, "\n");
        }
    }

    sndmsg(res, CLIENT_PORT);

    // Libérer la mémoire allouée pour la chaîne résultante
    free(res);

    // Fermer le répertoire
    closedir(dir);

    printf("Liste de fichier envoyée au client\n");
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

    // save private key

    FILE *file;
    file = fopen("private.pem", "w");
    if (file == NULL)
    {
        printf("Error opening file!\n");
        exit(1);
    }

    fprintf(file, "%s", pri_key);
    fclose(file);

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
                processListMessage();
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
                        /*if (startserver(port) == -1)
                        {
                            fprintf(stderr, "Failed to start the server\n");
                            return EXIT_FAILURE;
                        }*/

                        /*char msg_to_decrypt[1024];

                        int msg_received = 0;
                        printf("En attente de message du client...\n");
                        while (msg_received == 0)
                        {
                            printf("Entrée boucle\n");
                            if (getmsg(msg_to_decrypt) == -1)
                            {
                                printf("Erreur\n");
                                fprintf(stderr, "Error while receiving message\n");
                                break;
                            }
                            printf("Message reçu !!!\n");
                            printf("Message reçu : %s\n", msg_to_decrypt);
                            RSA *rsa = NULL;
                            char *decryptedMessage = decryptMessage(pri_key, msg_to_decrypt);
                            printf("Message déchiffré : %s\n", decryptedMessage);
                            msg_received = 1;
                        }*/
                    }

                    free(token); // Don't forget to free the memory when you're done
                }
                else
                {
                    fprintf(stderr, "No comma found in message\n");
                }
            }
        }
    }
    stopserver();

    return EXIT_SUCCESS;
}