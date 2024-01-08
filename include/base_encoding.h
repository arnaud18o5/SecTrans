#ifndef BASE_ENCODING_H
#define BASE_ENCODING_H

#include <stddef.h>

char *base64_encode(const unsigned char *buffer, size_t length);

unsigned char *base64_decode(const char *buffer, int length);

#endif // BASE64_H