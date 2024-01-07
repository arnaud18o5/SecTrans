#ifndef HASH_H
#define HASH_H

#include <stdio.h>

unsigned char* calculate_hash(FILE* file);

unsigned char* calculate_hash_from_string(char* string);

#endif // HASH_H