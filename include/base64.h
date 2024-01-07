#ifndef BASE64_H
#define BASE64_H

char* base64_encode(const unsigned char* buffer, size_t length);

unsigned char* base64_decode(const char* buffer, size_t* length);

#endif // BASE64_H