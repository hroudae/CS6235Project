#ifndef AES_LIB_H
#define AES_LIB_H

#include "stdint.h"
#include "constants.h"

#define NUM_CHARS_IN_WORD   8
#define BASE_HEX            16


void KeyExpansion(uint32_t* key, uint32_t* roundKeys, AESVersion_t vers);
int GetIV(uint8_t *iv);
extern __device__ void incrementCounter(uint8_t *new_ctr, uint8_t *ctr, int inc);
extern __device__ void AES_Encrypt_Block(uint8_t* plainText, uint8_t* cipherText, uint32_t* roundKeys, unsigned int numround);
extern __device__ void AES_Decrypt_Block(uint8_t* cipherText, uint8_t* plainText, uint32_t* roundKeys, unsigned int numround);

void getDecKeyfromAsciiKey(char* asciiKey, uint32_t* decimalKey, uint32_t keyLength_words);

#endif /* AES_LIB_H */