#include <openssl/rsa.h>

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

char *decryptMessage(char *pri_key, char *message);
char *encryptMessage(RSA *rsa, char *message);

#endif