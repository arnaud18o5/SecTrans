#include "base_encoding.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

// Function to decode Base64 to data
unsigned char *base64_decode(const char *input, int length)
{
    BIO *bio, *b64;

    unsigned char *buffer = (unsigned char *)malloc(length);
    memset(buffer, 0, length);

    bio = BIO_new_mem_buf((void *)input, length);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_read(bio, buffer, length);

    BIO_free_all(bio);

    return buffer;
}

// Function to encode data to Base64
char *base64_encode(const unsigned char *buffer, size_t length)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    char *ret = (char *)malloc((bufferPtr->length + 1) * sizeof(char));
    memcpy(ret, bufferPtr->data, bufferPtr->length);
    ret[bufferPtr->length] = '\0';

    return ret;
}