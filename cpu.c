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
void AES_Encrypt(unsigned char* plainText, unsigned char* cipherText, uint32_t* roundKeys, AESVersion_t vers, int charCount, ModeOfOperation_t mode, uint8_t *iv) {
    unsigned int numround = 0;
    uint8_t counter[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

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
        if (GetIV(iv) < 0) {
            printf("Error getting IV!\n");
            return;
        }
        // copy iv to the counter so iv is preserved for decryption
        int i;
        for (i = 0; i < 16; i++) counter[i] = iv[i];
    }

    unsigned int blocks = (charCount + (BLOCK_SIZE_BITS / 8)-1) / (BLOCK_SIZE_BITS / 8);
    printf("blocks encr: %d\n", blocks);
    int i, j;
    for (i = 0; i < blocks; i++) {
        if (mode == CTR) { // Encrypt the counter value then XOR with plaintext to obtain ciphertext
            incrementCounter(counter);
            AES_Encrypt_Block(counter, cipherText+i*(BLOCK_SIZE_BITS / 8), roundKeys, numround);
            for (j = 0; j < 16; j++)
                *((cipherText+i*(BLOCK_SIZE_BITS / 8))+j) ^= *(plainText+i*(BLOCK_SIZE_BITS / 8)+j);
        }
        else if (mode == CBC) {
            //Counter will be treated as Intrinsic Value to add to first block
            //The rest of blocks will take prior block
            //XOR Process of PlainText + Prior CipherText
            for (j = 0; j < 16; j++){
              if (i==0){ //First block uses IV
                *(plainText+i*(BLOCK_SIZE_BITS / 8)+j) ^= counter[j]; //*((cipherText+i*(BLOCK_SIZE_BITS / 8))+j);
              }
              else { //Rest use prior CipherText
                *(plainText+i*(BLOCK_SIZE_BITS / 8)+j) ^= *((cipherText+(i-1)*(BLOCK_SIZE_BITS / 8))+j);
                //*((cipherText+i*(BLOCK_SIZE_BITS / 8))+j) ^= *(plainText+i*(BLOCK_SIZE_BITS / 8)+j);
              }
            }

            AES_Encrypt_Block(plainText+i*(BLOCK_SIZE_BITS / 8), cipherText+i*(BLOCK_SIZE_BITS / 8), roundKeys, numround);
        }

        else {
         printf("ECB\n");
         AES_Encrypt_Block(plainText+i*(BLOCK_SIZE_BITS / 8), cipherText+i*(BLOCK_SIZE_BITS / 8), roundKeys, numround);
        }
    }
}

void AES_Decrypt(unsigned char* cipherText, unsigned char* plainText, uint32_t* roundKeys, AESVersion_t vers, int charCount, ModeOfOperation_t mode, uint8_t *iv) {
    unsigned int numround = 0;
    uint8_t counter[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    // unsigned char cipherStorage[16];

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

    if (mode == CTR) {
        // copy iv to the counter so iv is preserved
        int i;
        for (i = 0; i < 16; i++) counter[i] = iv[i];
    }

    unsigned int blocks = (charCount + (BLOCK_SIZE_BITS / 8)-1) / (BLOCK_SIZE_BITS / 8);
    printf("blocks decr: %d\n", blocks);
    int i, j;
    for (i = 0; i < blocks; i++) {
        if (mode == CTR) { // Encrypt the counter value then XOR with ciphertext to obtain plaintext
            incrementCounter(counter);
            AES_Encrypt_Block(counter, plainText+i*(BLOCK_SIZE_BITS / 8), roundKeys, numround);
            for (j = 0; j < 16; j++)
                *(plainText+i*(BLOCK_SIZE_BITS / 8)+j) ^= *((cipherText+i*(BLOCK_SIZE_BITS / 8))+j);
        }
        else if (mode == CBC){
          // for (i = 0; i < 16; i++) cipherStorage[i] = cipherText[i]; //Unsure if this will idx properly
          //Modifies plaintext in place
          AES_Decrypt_Block(cipherText+i*(BLOCK_SIZE_BITS / 8), plainText+i*(BLOCK_SIZE_BITS / 8), roundKeys, numround);
          if (i == 0){ //special first case
              for (j = 0; j < 16; j++){
                *(plainText+i*(BLOCK_SIZE_BITS / 8)+j) ^= counter[j];
              }
          }
          else {
              for (j = 0; j < 16; j++){
                *(plainText+i*(BLOCK_SIZE_BITS / 8)+j) ^= *((cipherText+(i-1)*(BLOCK_SIZE_BITS / 8))+j);
              }
          }
        }
        else AES_Decrypt_Block(cipherText+i*(BLOCK_SIZE_BITS / 8), plainText+i*(BLOCK_SIZE_BITS / 8), roundKeys, numround);
    }
}

// useful test vectors:
// http://citeseer.ist.psu.edu/viewdoc/download;jsessionid=B640BEEE8389FD7D024F4A5160E56EA4?doi=10.1.1.21.5680&rep=rep1&type=pdf
// CTR mode test with NIST example vectors:
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
int main(int argc, char* argv[]) {
    AESVersion_t version = AES256_VERSION;
    NumRounds_t rounds = AES256_ROUNDS;
    ModeOfOperation_t mode = CBC;

    uint32_t key[8] = {0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4};
    uint32_t *roundKeys = malloc(sizeof(uint32_t) * (4*rounds));

    KeyExpansion(key, roundKeys, version);

    int i;
    for (i = 0; i < 4*rounds; i++) {
        printf("%08x", roundKeys[i]);
        if ((i+1) % 4 == 0) printf("\n");
    }
    printf("\n");

    // unsigned char *string;
    // int fsize = 0;
    // if ((fsize = readfile("2701-0.txt", &string, 10485760)) < 1) {
    //     printf("ERROR reading input file.\n");
    //     return 1;
    // }
    unsigned char string[64] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    int fsize = 64;
    unsigned char *cipherText =  malloc(fsize + 1);
    unsigned char *decryptPlainText =  malloc(fsize + 1);

    unsigned char *plainCopy = malloc(fsize+1);
    memcpy(plainCopy, string, fsize+1);


    printf("\nOriginal String:");
    for (i = 0; i < fsize; i++) {
        printf("%02x", string[i]);
    }
    printf("\n");

    uint8_t *iv = malloc(16*sizeof(uint8_t));
    AES_Encrypt(string, cipherText, roundKeys, version, fsize, mode, iv);



    printf("\nCipherText (After Encry): ");
    for (i = 0; i < fsize; i++) {
        printf("%02x", cipherText[i]);
    }
    printf("\n");

    printf("\nPlainTxt (After Encry): ");
    for (i = 0; i < fsize; i++) {
        printf("%02x", string[i]);
    }
    printf("\n");

    printf("iv: ");
    for (i = 0; i < 16; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    AES_Decrypt(cipherText, decryptPlainText, roundKeys, version, fsize, mode, iv);

    printf("\nPlainText (After Decrypt):");
    for (i = 0; i < fsize; i++) {
        printf("%02x", decryptPlainText[i]);
    }
    printf("\n");

    //CBC Notes - Altering passed in plaintext is changing the string we compare to
    //Must copy or something

    for (i = 0; i < fsize; i++) {
        if (decryptPlainText[i] != plainCopy[i]) printf("\nERROR: %02x %02x\n", decryptPlainText[i], string[i]);
    }
    printf("\n");
    // printf("%s\n", string);

    // free(string);
    // free(cipherText);
    // free(decryptPlainText);
    // free(iv);

    return 0;
}
