#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

int main()
{
    int port = 12345; // Assurez-vous d'utiliser le même port que le serveur

    char message_to_send[1024] = "Hello, server!";

    if (sndmsg(message_to_send, port) == -1)
    {
        fprintf(stderr, "Failed to send message to the server\n");
        return EXIT_FAILURE;
    }

    printf("Message sent to the server: %s\n", message_to_send);

    return EXIT_SUCCESS;
}
