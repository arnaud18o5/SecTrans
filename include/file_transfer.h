#ifndef FILE_TRANSFER_H
#define FILE_TRANSFER_H

void processSendFile(char* filename, char* token, int receivingPort, int destinationPort, int sendPublicKey, char* keyRSAPrefix);

#endif // FILE_TRANSFER_H