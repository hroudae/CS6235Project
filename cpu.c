#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AES_lib.h"
#include "constants.h"
#include "fileio.h"

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
    printf("blocks encr: %d\n", blocks);
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
    printf("blocks decr: %d\n", blocks);
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

    uint32_t key[8] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f};
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
    
    unsigned char *cipherText =  malloc(fsize + 1);
    unsigned char *decryptPlainText =  malloc(fsize + 1);

    // for (i = 0; i < fsize; i++) {
    //     printf("%02x", string[i]);
    // }
    // printf("\n");

    AES_Encrypt(string, cipherText, roundKeys, version, fsize);
    // for (i = 0; i < fsize; i++) {
    //     printf("%02x", cipherText[i]);
    // }
    // printf("\n");

    AES_Decrypt(cipherText, decryptPlainText, roundKeys, version, fsize);
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
