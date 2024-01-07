#ifndef ENCRYPTION_H
#define ENCRYPTION_H

char *decryptMessage(char *pri_key, char *message);
char *encryptMessage(char *pub_key, char *message);

#endif