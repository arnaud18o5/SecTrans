#include "../include/client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char *argv[])
{
    int port = 12345;
    int portClient = 12346;
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <option>\n", argv[0]);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  -up <message>: Upload a message to the server\n");
        fprintf(stderr, "  -list: List files stored on the server\n");
        fprintf(stderr, "  -down <message>: Download a message from the server\n");
        return EXIT_FAILURE;
    }
    char message[1024] = "";
    for (int i = 2; i < argc; ++i)
    {
        strcat(message, argv[i]);
        if (i < argc - 1)
        {
            strcat(message, " "); // Ajoutez un espace entre les mots
        }
    }
    // Traitement des options en fonction des arguments de la ligne de commande
    if (strcmp(argv[1], "-up") == 0 && argc >= 3)
    {
        // Exemple d'utilisation : ./client -up "Hello, Server!"
        char server_message[1024] = "up,";
        strcat(server_message, message);
        long long result = sndmsg(server_message, port);
        if (result != 0)
        {
            fprintf(stderr, "Erreur lors de l'envoi du message au serveur\n");
            return EXIT_FAILURE;
        }
        printf("Message envoyé avec succès au serveur.\n");
    }
    else if (strcmp(argv[1], "-list") == 0 && argc == 2)
    {
        // Exemple d'utilisation : ./client -list
        // Ajoutez le code nécessaire pour demander la liste des fichiers au serveur
        // ...
        printf("Liste des fichiers stockés sur le serveur :\n");
        char server_message[1024] = "list,";
        char portStr[10];                   // Crée une chaîne pour stocker la représentation en chaîne de l'entier
        sprintf(portStr, "%d", portClient); // Convertit l'entier en chaîne de caractères
        strcat(server_message, portStr);    // Concatène la chaîne représentant l'entier à server_message
        sndmsg(server_message, port);
        // Affichez la liste des fichiers reçue du serveur
    }
    else if (strcmp(argv[1], "-down") == 0 && argc == 3)
    {
        // Exemple d'utilisation : ./client -down "filename"
        char server_message[1024] = "down,";
        char portStr[10];                    // Crée une chaîne pour stocker la représentation en chaîne de l'entier
        sprintf(portStr, "%d,", portClient); // Convertit l'entier en chaîne de caractères
        strcat(server_message, portStr);     // Concatène la chaîne représentant l'entier à server_message
        strcat(server_message, message);

        sndmsg(server_message, port);

        // int result = read_server_message(server_message);// if (result != 0)
        // {
        //    fprintf(stderr, "Erreur lors de la récupération du message du serveur\n");
        //  return EXIT_FAILURE;
        //}
        // printf("Message reçu du serveur : %s\n", server_message);
    }
    else
    {
        fprintf(stderr, "Option non reconnue ou nombre incorrect d'arguments.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}