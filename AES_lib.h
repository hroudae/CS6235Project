#ifndef AES_LIB_H
#define AES_LIB_H

#include "stdint.h"
#include "constants.h"

#define NUM_CHARS_IN_WORD   8
#define BASE_HEX            16

/* Mode of Operations functions */
int GetIV(uint8_t *iv);
void incrementCounter(uint8_t *ctr);

/* AES functions */
void KeyExpansion(uint32_t* key, uint32_t* roundKeys, AESVersion_t vers);
void AES_Encrypt_Block(unsigned char* plainText, unsigned char* cipherText, uint32_t* roundKeys, unsigned int numround);
void AES_Decrypt_Block(unsigned char* cipherText, unsigned char* plainText, uint32_t* roundKeys, unsigned int numround);

void getDecKeyfromAsciiKey(char* asciiKey, uint32_t* decimalKey, uint32_t keyLength_words);


#endif /* AES_LIB_H */