#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AES_lib.h"
#include "constants.h"

//
// void printState(state_t state) {
//     int i, j;
//     for (i = 0; i < 4; i++) {
//         for (j = 0; j < 4; j++) {
//             printf("%02x ", state[i][j]);
//         }
//         printf("\n");
//     }
// }

void AES_Encrypt(unsigned char* plainText, unsigned char* cipherText, uint32_t* roundKeys, AESVersion_t vers, int charCount) {
    unsigned int numround = 0;

    switch(vers) {
        case AES128_VERSION:
            numround = AES128_ROUNDS;
            break;
        case AES192_VERSION:
            numround = AES192_ROUNDS;
            break;
        case AES256_VERSION:
            numround = AES256_ROUNDS;
            break;
        default:
            numround = 0;
    }

    unsigned int blocks = (charCount + (BLOCK_SIZE_BITS / 8)-1) / (BLOCK_SIZE_BITS / 8);

    int i;
    for (i = 0; i < blocks; i++) {
        AES_Encrypt_Block(plainText+i*(BLOCK_SIZE_BITS / 8), cipherText+i*(BLOCK_SIZE_BITS / 8), roundKeys, numround);
    }
}

void AES_Decrypt(unsigned char* cipherText, unsigned char* plainText, uint32_t* roundKeys, AESVersion_t vers, int charCount) {
    unsigned int numround = 0;

    switch(vers) {
        case AES128_VERSION:
            numround = AES128_ROUNDS;
            break;
        case AES192_VERSION:
            numround = AES192_ROUNDS;
            break;
        case AES256_VERSION:
            numround = AES256_ROUNDS;
            break;
        default:
            numround = 0;
    }

    unsigned int blocks = (charCount + (BLOCK_SIZE_BITS / 8)-1) / (BLOCK_SIZE_BITS / 8);

    int i;
    for (i = 0; i < blocks; i++) {
        AES_Decrypt_Block(cipherText+i*(BLOCK_SIZE_BITS / 8), plainText+i*(BLOCK_SIZE_BITS / 8), roundKeys, numround);
    }
}

// useful test vectors:
// http://citeseer.ist.psu.edu/viewdoc/download;jsessionid=B640BEEE8389FD7D024F4A5160E56EA4?doi=10.1.1.21.5680&rep=rep1&type=pdf
int main(int argc, char* argv[]) {
    AESVersion_t version = AES256_VERSION;
    NumRounds_t rounds = AES256_ROUNDS;

    //uint32_t key[8] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f};
    uint32_t key[8] = {0xc47b0294, 0xdbbbee0f, 0xec4757f2, 0x2ffeee35, 0x87ca4730, 0xc3d33b69, 0x1df38bab, 0x076bc558};
    uint32_t *roundKeys = malloc(sizeof(uint32_t) * (4*rounds));

    KeyExpansion(key, roundKeys, version);

    int i;
    for (i = 0; i < 4*rounds; i++) {
        printf("%08x", roundKeys[i]);
        if ((i+1) % 4 == 0) printf("\n");
    }
    printf("\n");

    //unsigned char data[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    unsigned char data[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char cipherText[16] = {0};
    unsigned char decryptPlainText[16] = {0};
    unsigned char data_copy[16]  = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    for (i = 0; i < 16; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");

    AES_Encrypt(data, cipherText, roundKeys, version, 16);
    for (i = 0; i < 16; i++) {
        printf("%02x", data[i]);
        //above
    }
    printf("\n Cipher: ");

    for (i = 0; i < 16; i++) {
      printf("%02x", cipherText[i]);
        //above
    }
    printf("\n");


    AES_Decrypt(cipherText, decryptPlainText, roundKeys, version, 16);
    // for (i = 0; i < 16; i++) {
    //     printf("%02x", data[i]);
    //     if (decryptPlainText[i] != data_copy[i]) printf("\nERROR\n");
    // }
    printf("\n");
}
