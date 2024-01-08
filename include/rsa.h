#ifndef RSA_H
#define RSA_H

int generate_rsa_keypair(int bits);
char* load_key(const char* filename);

#endif // RSA_H