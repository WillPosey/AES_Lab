#ifndef CTR_MODE
#define CTR_MODE

void encrypt_ctr_mode(unsigned char *key, unsigned char *msg, unsigned int msgLength, unsigned char* cipherBuf, unsigned int bufferSize);
void decrypt_ctr_mode(unsigned char *key, unsigned char* msgBuf, unsigned int bufferSize, unsigned char *cipherText,  unsigned int cipherTextLength);

#endif