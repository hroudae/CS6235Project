#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<time.h>

#include "AES_lib.h"
#include "constants.h"
#include "fileio.h"

// TODO: need to return IV somehow
void AES_Encrypt(unsigned char* plainText, unsigned char* cipherText, uint32_t* roundKeys, AESVersion_t vers, int charCount, ModeOfOperation_t mode, uint32_t iv[4]) {
    unsigned int numround = 0;
    uint32_t cnt[4] = {0, 0, 0, 0}; // counter for CTR mode

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

    // generate a random IV to be used in CTR mode
    if (mode == CTR) {
        GetIV(iv);
    }

    unsigned int blocks = (charCount + (BLOCK_SIZE_BITS / 8)-1) / (BLOCK_SIZE_BITS / 8);
    printf("blocks encr: %d\n", blocks);
    int i, j;
    for (i = 0; i < blocks; i++) {
        if (mode == CTR) { // Encrypt the IV XOR CNT value then XOR with plaintext to obtain ciphertext
            unsigned char ctr_char[16]; // char array to encrypt
            CTR_GetCounter(iv, cnt, ctr_char);
            AES_Encrypt_Block(ctr_char, cipherText+i*(BLOCK_SIZE_BITS / 8), roundKeys, numround);
            for (j = 0; j < 16; j++)
                *((cipherText+i*(BLOCK_SIZE_BITS / 8))+j) ^= *(plainText+i*(BLOCK_SIZE_BITS / 8)+j);
        }
        else AES_Encrypt_Block(plainText+i*(BLOCK_SIZE_BITS / 8), cipherText+i*(BLOCK_SIZE_BITS / 8), roundKeys, numround);
    }
}

void AES_Decrypt(unsigned char* cipherText, unsigned char* plainText, uint32_t* roundKeys, AESVersion_t vers, int charCount, ModeOfOperation_t mode, uint32_t iv[4]) {
    unsigned int numround = 0;
    uint32_t cnt[4] = {0, 0, 0, 0}; // counter for CTR mode

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
    printf("blocks decr: %d\n", blocks);
    int i, j;
    for (i = 0; i < blocks; i++) {
        if (mode == CTR) { // Encrypt the IV XOR CNT value then XOR with ciphertext to obtain plaintext
            unsigned char ctr_char[16]; // char array to encrypt
            CTR_GetCounter(iv, cnt, ctr_char);
            AES_Encrypt_Block(ctr_char, plainText+i*(BLOCK_SIZE_BITS / 8), roundKeys, numround);
            for (j = 0; j < 16; j++)
                *(plainText+i*(BLOCK_SIZE_BITS / 8)+j) ^= *((cipherText+i*(BLOCK_SIZE_BITS / 8))+j);
        }
        else AES_Decrypt_Block(cipherText+i*(BLOCK_SIZE_BITS / 8), plainText+i*(BLOCK_SIZE_BITS / 8), roundKeys, numround);
    }
}

// useful test vectors: 
// http://citeseer.ist.psu.edu/viewdoc/download;jsessionid=B640BEEE8389FD7D024F4A5160E56EA4?doi=10.1.1.21.5680&rep=rep1&type=pdf
int main(int argc, char* argv[]) {
    AESVersion_t version = AES256_VERSION;
    NumRounds_t rounds = AES256_ROUNDS;
    ModeOfOperation_t mode = CTR;

    // uint32_t key[8] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f};
    uint32_t key[8] = {0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4};
    uint32_t *roundKeys = malloc(sizeof(uint32_t) * (4*rounds));

    KeyExpansion(key, roundKeys, version);

    int i;
    for (i = 0; i < 4*rounds; i++) {
        printf("%08x", roundKeys[i]);
        if ((i+1) % 4 == 0) printf("\n");
    }
    printf("\n");

    unsigned char *string;
    int fsize = 0;
    if ((fsize = readfile("2701-0.txt", &string, 10485760)) < 1) {
        printf("ERROR reading input file.\n");
        return 1;
    }
    // unsigned char string[64] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    // 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    // 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    // 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    // int fsize = 64;
    unsigned char *cipherText =  malloc(fsize + 1);
    unsigned char *decryptPlainText =  malloc(fsize + 1);

    // for (i = 0; i < fsize; i++) {
    //     printf("%02x", string[i]);
    // }
    // printf("\n");
    uint32_t iv[4] = {0, 0, 0, 0};
    AES_Encrypt(string, cipherText, roundKeys, version, fsize, mode, iv);
    // for (i = 0; i < fsize; i++) {
    //     printf("%02x", cipherText[i]);
    // }
    // printf("\n");

    AES_Decrypt(cipherText, decryptPlainText, roundKeys, version, fsize, mode, iv);
    for (i = 0; i < fsize; i++) {
        // printf("%02x", decryptPlainText[i]);
        if (decryptPlainText[i] != string[i]) printf("\nERROR: %02x %02x\n", decryptPlainText[i], string[i]);
    }
    printf("\n");
    // printf("%s\n", string);

    free(string);
    free(cipherText);
    free(decryptPlainText);

    return 0;
}
