#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern unsigned short address;
extern unsigned short g_4040b2;
extern unsigned int g_4040b4;
extern unsigned int server_fd;
extern unsigned int addrlen;
extern unsigned int new_socket;
extern unsigned long long valread;

long long startserver(unsigned long a0);
long long getmsg(char msg_read[1024]);
long long stopserver();

#endif  // SERVER_H
