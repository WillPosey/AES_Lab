#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes_any_length.h"

int main(int argc, char *argv[]) {
	const unsigned char ikey[] = {0xa1, 0xa2, 0xa3, 0xb4, 0xa5, 0xa6, 0xa7, 0xa8, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8};
	unsigned char msg[] = "Message is 76 bytes (not a factor of 16), leaving 12 bytes in the last block";
	int msgLen = strlen(msg);
	unsigned char ci[msgLen+1], pt[msgLen+1];
	unsigned int j;

	printf("Plain Text Before Encryption TXT  : '%s'\n", msg);
	printf("Plain Text Before Encryption HEX  : \n");
	for(j = 0;j< msgLen; j++) 
	{
		if(j>0 && (j%8)==0)
			printf("\n");
		printf("0x%x ",msg[j]);
	}
	printf("\n");

	aes_encrypt_n(ikey, msg, msgLen);
	memcpy(ci, msg, msgLen);
	ci[msgLen] = '\0';

	printf("\nCipher Text After Encryption      : '%s'\n", ci);
	printf("Cipher Text After Encryption HEX  : \n");
	for(j = 0; j<msgLen; j++) 
	{
		if(j>0 && (j%8)==0)
			printf("\n");
		printf("0x%x ",ci[j]);
	}
	printf("\n");
	
	aes_decrypt_n(ikey, ci, msgLen);
	memcpy(pt, ci, msgLen);
	pt[msgLen] = '\0';

	printf("\nPlain Text After Decryption       : '%s'\n", pt);
	printf("Plain Text After Decryption HEX   : \n");
	for(j = 0;j< msgLen; j++) 
	{
		if(j>0 && (j%8)==0)
			printf("\n");
		printf("0x%x ",pt[j]);
	}
	printf("\n");
}



