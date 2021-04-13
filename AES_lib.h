#ifndef AES_LIB_H
#define AES_LIB_H

#include "stdint.h"
#include "constants.h"

/* Mode of Operations functions */
int GetIV(uint8_t *iv);
void incrementCounter(uint8_t *ctr);

/* AES functions */
void KeyExpansion(uint32_t* key, uint32_t* roundKeys, AESVersion_t vers);
void AES_Encrypt_Block(unsigned char* plainText, unsigned char* cipherText, uint32_t* roundKeys, unsigned int numround);
void AES_Decrypt_Block(unsigned char* cipherText, unsigned char* plainText, uint32_t* roundKeys, unsigned int numround);


#endif /* AES_LIB_H */