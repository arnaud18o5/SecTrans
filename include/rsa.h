#ifndef RSA_H
#define RSA_H

int generate_rsa_keypair(int bits);
char* load_key(char* filename);

#endif // RSA_H