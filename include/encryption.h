#ifndef ENCRYPTION_H
#define ENCRYPTION_H

unsigned char *decryptMessage(char *pri_key, unsigned char *message);
unsigned char *encryptMessage(char *pub_key, unsigned char *message);

#endif