#ifndef FILE_TRANSFER_H
#define FILE_TRANSFER_H

void processSendFile(char* filename, char* token, int receivingPort, int destinationPort, int sendPublicKey, char* keyRSAPrefix);
void processReceiveFile(char *received_msg, int getUser, unsigned char* tokenKey, char* uploadDir);

#endif // FILE_TRANSFER_H