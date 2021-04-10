#ifndef AES_LIB_H
#define AES_LIB_H

#include "stdint.h"
#include "constants.h"


void KeyExpansion(uint32_t* key, uint32_t* roundKeys, AESVersion_t vers);
extern __device__ void AES_Encrypt_Block(uint8_t* plainText, uint8_t* cipherText, uint32_t* roundKeys, unsigned int numround);
extern __device__ void AES_Decrypt_Block(uint8_t* cipherText, uint8_t* plainText, uint32_t* roundKeys, unsigned int numround);


#endif /* AES_LIB_H */