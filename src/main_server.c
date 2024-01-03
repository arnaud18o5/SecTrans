#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

int verifyParameter(char *message)
{
    char *token = strtok(message, ", ");
    if (strcmp(token, "up"))
        return 1;
    if (strcmp(token, "list"))
        return 2;
    if (strcmp(token, "down"))
        return 3;
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
        const int token = verifyParameter(received_msg);
        if (token == 1)
        {
            printf("Message reçu du client : %s\n", received_msg);
            char *token = strtok(received_msg, ", ");
            token = strtok(NULL, ", ");
            printf("Message à stocker : %s\n", token);
            // Ajoutez le code nécessaire pour stocker le message dans un fichier
            // ...
        }
        else if (token == 2)
        {
            printf("envoyer la liste des fichiers au client\n");
            // Ajoutez le code nécessaire pour envoyer la liste des fichiers au client
            // ...
        }
        else if (token == 3)
        {
            printf("Envoyer le contenu du fichier au client\n");
            char *token = strtok(received_msg, ", ");
            token = strtok(NULL, ", ");
            printf("Message à télécharger : %s\n", token);
            // Ajoutez le code nécessaire pour envoyer le contenu du fichier au client
            // ...
        }
    }

    stopserver();

    return EXIT_SUCCESS;
}
