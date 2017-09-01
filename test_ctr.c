#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "counterMode.h"

int main(int argc, char *argv[]) {
	const unsigned char ikey[] = {0xa1, 0xa2, 0xa3, 0xb4, 0xa5, 0xa6, 0xa7, 0xa8, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8};
	unsigned char msg[] = "This message is longer than 16 bytes; it's exactly 64 bytes long";
	int msgLen = strlen(msg);
	int ciLen = msgLen+9;
	unsigned char *ci, *pt;
	unsigned int j;
	ci = (char*) malloc(ciLen * sizeof(char));
	pt = (char*) malloc(msgLen * sizeof(char));

	printf("Plain Text Before Encryption TXT  : '%s'\n", msg);
	printf("Plain Text Before Encryption HEX  : \n");
	for(j = 0;j< msgLen; j++) 
	{
		if(j>0 && (j%8)==0)
			printf("\n");
		printf("0x%x ",msg[j]);
	}
	printf("\n");

	encrypt_ctr_mode(ikey, msg, msgLen, ci, ciLen);
	ci[ciLen-1] = '\0';
	printf("\nCipher Text After Encryption      : '%s'\n", ci);
	printf("Cipher Text After Encryption HEX  : \n");
	for(j = 0; j<ciLen; j++) 
	{
		if(j>0 && (j%8)==0)
			printf("\n");
		printf("0x%x ",ci[j]);
	}
	printf("\n");
	
	decrypt_ctr_mode(ikey, pt, msgLen, ci, msgLen+8);
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
	free(ci);
	free(pt);
}



