#include "server.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

unsigned short address;
unsigned short g_4040b2;
unsigned int g_4040b4;
unsigned int server_fd;
unsigned int addrlen;
unsigned int new_socket;
unsigned long long valread;

long long startserver(unsigned long a0) {
    unsigned int v0 = 1;
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        exit(1);
    } else if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &v0, sizeof(v0))) {
        perror("setsockopt");
        exit(1);
    } else {
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(a0);

        if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("bind failed");
            exit(1);
        }

        if (listen(server_fd, 3) < 0) {
            perror("listen");
            exit(1);
        }

        return 0;
    }
}

long long getmsg(char msg_read[1024]) {
    struct sockaddr_in client_addr;
    addrlen = sizeof(client_addr);

    new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
    if (new_socket >= 0) {
        valread = read(new_socket, msg_read, 1024);
        close(new_socket);
        return 0;
    }

    perror("accept");
    exit(1);
}

long long stopserver() {
    close(server_fd);
    return 0;
}
