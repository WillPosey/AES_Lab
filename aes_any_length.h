#ifndef AES_ANY_LEN
#define AES_ANY_LEN
#include "TI_aes.h"

void aes_encrypt_n(unsigned char *key, unsigned char *msg, unsigned int msgLength);
void aes_decrypt_n(unsigned char *key, unsigned char *msg, unsigned int msgLength);

#endif