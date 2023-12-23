#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "client.h"
#include "server.h"

int main() {
    // Démarrer le serveur
    printf("Démarrage du serveur...\n");
    startserver(8080);  // Remplacez 8080 par le port que vous souhaitez utiliser

    // Attendre un court moment pour que le serveur soit prêt
    // (Note: dans une application réelle, vous devriez gérer cela de manière asynchrone)
    printf("Attente du démarrage du serveur...\n");
    sleep(2);

    // Envoyer un fichier depuis le client vers le serveur
    char filename[] = "example.txt";
    char buffer[4096];  // Taille du tampon pour stocker le contenu du fichier

    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Erreur lors de l'ouverture du fichier");
        stopserver();
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    fread(buffer, 1, file_size, file);
    fclose(file);

    printf("Envoi du fichier vers le serveur...\n");
    sndmsg(buffer, file_size);

    // Récupérer le fichier du serveur vers le client
    char received_buffer[4096];
    printf("Récupération du fichier depuis le serveur...\n");
    getmsg(received_buffer);

    // Afficher le contenu reçu
    printf("Contenu reçu du serveur :\n%s\n", received_buffer);

    // Arrêter le serveur
    printf("Arrêt du serveur...\n");
    stopserver();

    return 0;
}
