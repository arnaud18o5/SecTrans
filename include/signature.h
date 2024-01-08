#ifndef SIGNATURE_H
#define SIGNATURE_H

#include <stdio.h>
#include <stddef.h>

int verifySignature(FILE* file, unsigned char* signature, size_t signature_len, char* publicKey);
unsigned char* getFileSignature(FILE* file, unsigned int* signature_length, char* privateKey);

#endif // SIGNATURE_H