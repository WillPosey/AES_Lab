
/*******************************************************************************************************************/
void aes_encrypt_n(unsigned char *key, unsigned char *msg, unsigned int msgLength)
{
     unsigned int i, j, index;
     const unsigned int blockSize = 16;
     unsigned char block[blockSize];

     unsigned int numBlocks = ceil(msgLength / 16.0);
     unsigned int lastBlockSize = msgLength % blockSize;
     unsigned int lastBlockMissing = blockSize - lastBlockSize;

     for(i=0; i<numBlocks; i++)
     {
          /* handle last block size */
          if( i==(numBlocks-2) && lastBlockSize != 0)
          {
               aes_encrypt(msg+(i*blockSize), key);

               /* ciphertext stealing:
                  Take second to last encrypted block, append m bytes to the last plaintext block, where 
                  m is the missing number of bytes in last block. Copy second to last ciphertext block, 
                  up to the m missing bytes, to the last partial ciphertext block. Encrypt the plaintext 
                  appended by the already encrypted bytes block, store as the second to last ciphertext block.
               */
               memcpy(block, msg+((i+1)*blockSize), lastBlockSize); // place plaintext in last block into temp block
               memcpy(block+lastBlockSize, msg+(i*blockSize)+lastBlockSize, lastBlockMissing); // place missing bytes into temp block, from just encrypted block
               memcpy(msg+((i+1)*blockSize), msg+(i*blockSize), lastBlockSize); // place just encrypted block front bytes into last ciphertext block
               aes_encrypt(block, key); // encrypt plaintext appended by already encrypted bytes block
               memcpy(msg+(i*blockSize), block, blockSize); // copy back to ciphertext
               return;
          }
          /* encrypt as normal */
          else
               aes_encrypt(msg+(i*blockSize), key);

     }
}

/*******************************************************************************************************************/
void aes_decrypt_n(unsigned char *key, unsigned char *msg, unsigned int msgLength)
{
     unsigned int i, j, index;
     const unsigned int blockSize = 16;
     unsigned char block[blockSize];

     unsigned int numBlocks = ceil(msgLength / 16.0);
     unsigned int lastBlockSize = msgLength % blockSize;
     unsigned int lastBlockMissing = blockSize - lastBlockSize;

     for(i=0; i<numBlocks; i++)
     {
          /* handle last block size */
          if( i==(numBlocks-1) && lastBlockSize != 0)
          {
               memcpy(block, msg+(i*16), lastBlockSize); // save first part of encrypted block n-1
               memcpy(msg+(i*16), msg+((i-1)*16), lastBlockSize); // plaintext
               memcpy(msg+((i-1)*16), block, lastBlockSize); // recreate encrypted block n-1
               aes_decrypt(msg+((i-1)*16), key); // decrypt block n-1
               return;
          }
          /* decrypt as normal */
          else
               aes_decrypt(msg+(i*blockSize), key);

     }
}