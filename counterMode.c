#include "TI_aes.h"
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <math.h>

//create Nonce for CTR block cipher
uint64_t getNonce()
{
  uint64_t randval;
  FILE *f;

  f = fopen("/dev/urandom", "r");
  fread(&randval, sizeof(randval), 1, f);
  fclose(f);

  return randval;
}

void encrypt_ctr_mode(	unsigned char *key, 
						unsigned char *msg, 
						unsigned int msgLength, 
						unsigned char* cipherBuf, 
						unsigned int bufferSize)
{
	if(bufferSize < (msgLength + 8))
	{
		printf("ERROR: Buffer to store encrypted message must be able to store 8 bytes beyond message length\n");
		return;
	}

	unsigned int i, j, index;
	const unsigned int blockSize = 16;
	unsigned int maxBlockIndex = blockSize;

	/* retrieve number of blocks for message, last block size for message
	   and allocate space for a keystream for each block */
	unsigned int numBlocks = ceil(msgLength / 16.0);
	unsigned int lastBlockSize = msgLength % 16;
	unsigned char keystream[16];
	
	/* get random value for nonce, initialize counter */
	uint64_t nonce = getNonce();
	uint64_t cnt = 0;

	/* include nonce value in first 8 bytes for decryption */
	memcpy(cipherBuf, (unsigned char*)&nonce, 8);

	/* encrypt each block by generating keystream from encrypting 
	   the nonce and counter value with AES, then XOR with message */
	for(i=0; i<numBlocks; i++)
	{
		/* Set upper 64 bits of keystream input to nonce random value */
		memset(keystream, 0, 16);
		memcpy(keystream+8, (unsigned char*)&nonce, 8);
		memcpy(keystream, (unsigned char*)&cnt, 8);

		/* encrypt keystream with AES */
		aes_encrypt(keystream, key);

		/* handle last block size */
		if( i==(numBlocks-1) && lastBlockSize != 0)
			maxBlockIndex = lastBlockSize;

		/* encrypt plain text by XOR with keystream */
		for(j=0; j<maxBlockIndex; j++)
		{	
			index = (i*16) + j;
			cipherBuf[index+8] = msg[index] ^ keystream[j];
		}

		/* increment counter */
		cnt++;
	}
}

void decrypt_ctr_mode(	unsigned char *key, 
						unsigned char *msgBuf, 
						unsigned int bufferSize, 
						unsigned char* cipherText, 
						unsigned int cipherTextLength)
{
	if(bufferSize < (cipherTextLength - 8))
	{
		printf("ERROR: Buffer to store decrypted message not large enough\n");
		return;
	}

	unsigned int i, j, index;
	const unsigned int blockSize = 16;
	unsigned int maxBlockIndex = blockSize;
	unsigned int msgLength = (cipherTextLength-8);

	/* retrieve number of blocks for message, last block size for message
	   and allocate space for a keystream for each block */
	unsigned int numBlocks = ceil( msgLength / 16.0);
	unsigned int lastBlockSize = msgLength % 16;
	unsigned char keystream[16];
	
	/* initialize counter */
	uint64_t nonce;
	uint64_t cnt = 0;

	/* retrieve nonce value from first 8 bytes of cipher text */
	memcpy((unsigned char*)&nonce, cipherText, 8);

	/* encrypt each block by generating keystream from encrypting 
	   the nonce and counter value with AES, then XOR with message */
	for(i=0; i<numBlocks; i++)
	{
		/* Set upper 64 bits of keystream input to nonce random value */
		memset(keystream, 0, 16);
		memcpy(keystream+8, (unsigned char*)&nonce, 8);
		memcpy(keystream, (unsigned char*)&cnt, 8);

		/* encrypt keystream with AES */
		aes_encrypt(keystream, key);

		/* handle last block size */
		if( i==(numBlocks-1) && lastBlockSize != 0)
			maxBlockIndex = lastBlockSize;

		/* decrypt cipher text by XOR with keystream */
		for(j=0; j<maxBlockIndex; j++)
		{	
			index = (i*16) + j;
			msgBuf[index] = cipherText[index+8]^ keystream[j];
		}

		/* increment counter */
		cnt++;
	}
}