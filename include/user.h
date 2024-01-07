#ifndef USER_H
#define USER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char username[30];
    char password[65];
    char role[20];
    int attribuedPort;
    FILE *currentOpenedFile;
    char currentUploadFileName[256];
    char publicKey[1024];
} User;

extern User users[];

User* authenticateUser(const char *username, const char *password);
User* getUserFromToken(const char *token);
char* createSpecialToken(const char *username, const char *role);
unsigned char* encryptToken(const unsigned char *token, size_t tokenSize, const unsigned char *key);
void getLoginAndPassword(char message[], char login[], char password[]);

#endif // USER_H