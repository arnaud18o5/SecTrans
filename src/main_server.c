#include "server.h"
#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void processUpMessage(char *received_msg)
{
    printf("Message reçu du client : %s\n", received_msg);
    char *msg = strtok(NULL, ",");
    printf("Message à stocker : %s\n", msg);
    // Ajoutez le code nécessaire pour stocker le message dans un fichier
    // ...
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
        const char *token = strtok(received_msg, ",");
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
    }

    stopserver();

    return EXIT_SUCCESS;
}