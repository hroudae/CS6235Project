#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "AES_lib.h"
#include "constants.h"
#include "fileio.h"

#define KEY_SIZE_ARGUMENT_INDEX     1
#define KEY_FP_INDEX                2
#define PLAIN_TEXT_FP_INDEX         3
#define MODE_INDEX                  4

#define CHARS_PER_BYTE              2


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
    if (mode == CTR || mode == CBC) {
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

    if (mode == CTR || mode == CBC) {
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
    int USE_TEST_CODE = 0;
    int i;

    uint32_t plainTextSize_bytes = 0;
    uint32_t plainTextSizeAligned_bytes = 0;
    uint32_t loopNdx;

    uint32_t* key;
    uint32_t* roundKeys;

    KeySize_Word_t keySize_words = AES128_KEYSIZE;
    NumRounds_t rounds = AES128_ROUNDS;
    AESVersion_t version = AES128_VERSION;
    ModeOfOperation_t mode = ECB;

    uint8_t* en_plainText;
    uint8_t* de_plainText;
    uint8_t* plainText_verification;
    uint8_t* cipherText;
    uint8_t *iv = (uint8_t*)calloc(sizeof(uint8_t) * 16, sizeof(uint8_t));

    int verificationSuccessful = 1;

    unsigned char* inFilekey;
    uint32_t expectedKeySize;
    unsigned char* inputPlainText;
    uint32_t numCharRead = 0;
    uint32_t appendedZeroCnt_bytes = 0;


    if(argc > 1)
    {
        if(argc > 5)
        {
            fprintf(stderr, "Expecting at most 4 arguments: Keysize, KeyfilePath, PlainTextPath, Mode\n");
        }

        if(atoi(argv[KEY_SIZE_ARGUMENT_INDEX]) == BIT_KEY_128)
        {
            keySize_words = AES128_KEYSIZE;
            rounds        = AES128_ROUNDS;
            version       = AES128_VERSION;
        }
        else if(atoi(argv[KEY_SIZE_ARGUMENT_INDEX]) == BIT_KEY_192)
        {
            keySize_words = AES192_KEYSIZE;
            rounds        = AES192_ROUNDS;
            version       = AES192_VERSION;
        }
        else if(atoi(argv[KEY_SIZE_ARGUMENT_INDEX]) == BIT_KEY_256)
        {
            keySize_words = AES256_KEYSIZE;
            rounds        = AES256_ROUNDS;
            version       = AES256_VERSION;
        }
        else
        {
            fprintf(stderr, "Invalid key size: %d\n", atoi(argv[KEY_SIZE_ARGUMENT_INDEX]));
        }

        if (argc == 5 && atoi(argv[MODE_INDEX]) == ECB) {
            printf("ECB mode chosen.\n");
            mode = ECB;
        }
        else if (argc == 5 && atoi(argv[MODE_INDEX]) == CTR) {
            printf("CTR mode chosen.\n");
            mode = CTR;
        }
        else if (argc == 5 && atoi(argv[MODE_INDEX]) == CBC) {
            printf("CBC mode chosen.\n");
            mode = CBC;
        }
        else if (argc == 5) fprintf(stderr, "Invalid mode: %d\n", atoi(argv[MODE_INDEX]));
        else {
            printf("No mode provided, defaulting to ECB\n");
            mode = ECB;
        }


        expectedKeySize = keySize_words*sizeof(uint32_t)*CHARS_PER_BYTE;

        numCharRead = readfile(argv[KEY_FP_INDEX], &inFilekey, expectedKeySize);
        if (numCharRead < 1 || numCharRead != expectedKeySize)
        {
            fprintf(stderr, "ERROR reading key file with size: %d\n", numCharRead);
            return 1;
        }
        else
        {
            fprintf(stderr, "Read %d bytes from input key file\n", numCharRead/CHARS_PER_BYTE);
        }


        plainTextSize_bytes = readfile(argv[PLAIN_TEXT_FP_INDEX], &inputPlainText, 1073741824);
        if (plainTextSize_bytes < 1)
        {
            fprintf(stderr, "ERROR reading plainText file\n");
            return 1;
        }
        else
        {
            fprintf(stderr, "Read %d bytes from input plain text file\n", plainTextSize_bytes);
        }

        fprintf(stderr, "\n");
    }
    else
    {
        fprintf(stderr, "Using hardcoded test: 1 block and 256 bit key\n");
        USE_TEST_CODE = 1;
    }


    if (USE_TEST_CODE) {
        keySize_words       = AES256_KEYSIZE;
        rounds              = AES256_ROUNDS;
        plainTextSize_bytes = 17;
    }

    if ((plainTextSize_bytes*8)%BLOCK_SIZE_BITS)
        appendedZeroCnt_bytes = (BLOCK_SIZE_BITS - (plainTextSize_bytes*8)%BLOCK_SIZE_BITS) / 8;
    plainTextSizeAligned_bytes = plainTextSize_bytes + appendedZeroCnt_bytes;

    key = (uint32_t*)calloc(sizeof(uint32_t*) * keySize_words, sizeof(uint32_t));
    roundKeys = (uint32_t*)calloc(sizeof(uint32_t*) * rounds * 4, sizeof(uint32_t));
    en_plainText = (unsigned char*)calloc(sizeof(unsigned char) * plainTextSizeAligned_bytes, sizeof(uint8_t));
    de_plainText = (unsigned char*)calloc(sizeof(unsigned char) * plainTextSizeAligned_bytes, sizeof(uint8_t));
    plainText_verification = (unsigned char*)calloc(sizeof(unsigned char) * plainTextSizeAligned_bytes, sizeof(uint8_t));
    cipherText = (unsigned char*)calloc(sizeof(unsigned char) * plainTextSizeAligned_bytes, sizeof(uint8_t));

    if (USE_TEST_CODE) {
        uint32_t sample256Key[8] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
                                0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f};

        uint8_t sampleDataBlock[17] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                   0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x69};

        memcpy((void*)key, (void*)sample256Key, sizeof(uint32_t*)*keySize_words);
        memcpy((void*)en_plainText, (void*)sampleDataBlock, plainTextSize_bytes);
        memcpy((void*)plainText_verification, (void*)sampleDataBlock, plainTextSize_bytes);
    }

    else {
        // TODO: copy supplied key file into key
        /*uint32_t inputKey[8] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
                                0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f};*/

        getDecKeyfromAsciiKey((char*)inFilekey, key, keySize_words);
        memcpy((void*)en_plainText, (void*)inputPlainText, plainTextSize_bytes);
        memcpy((void*)plainText_verification, (void*)inputPlainText, plainTextSize_bytes);
    }

    KeyExpansion(key, roundKeys, version);

    struct timespec  begin, end;
    clock_gettime(CLOCK_MONOTONIC, &begin);
    AES_Encrypt(en_plainText, cipherText, roundKeys, version, plainTextSizeAligned_bytes, mode, iv);
    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_encrypt = ((double) (end.tv_nsec - begin.tv_nsec) / 1000000000.0 + (double) (end.tv_sec - begin.tv_sec)) * 1000.0;

    // printf("\nCipherText (After Encry): ");
    // for (i = 0; i < plainTextSizeAligned_bytes; i++) {
    //     printf("%02x", cipherText[i]);
    // }
    // printf("\n");

    // printf("\nPlainTxt (After Encry): ");
    // for (i = 0; i < plainTextSizeAligned_bytes; i++) {
    //     printf("%02x", plainText_verification[i]);
    // }
    // printf("\n");

    // printf("iv: ");
    // for (i = 0; i < 16; i++) {
    //     printf("%02x", iv[i]);
    // }
    // printf("\n");

    clock_gettime(CLOCK_MONOTONIC, &begin);
    AES_Decrypt(cipherText, de_plainText, roundKeys, version, plainTextSizeAligned_bytes, mode, iv);
    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_decrypt = ((double) (end.tv_nsec - begin.tv_nsec) / 1000000000.0 + (double) (end.tv_sec - begin.tv_sec)) * 1000.0;

    // printf("\nPlainText (After Decrypt):");
    // for (i = 0; i < plainTextSizeAligned_bytes; i++) {
    //     printf("%02x", de_plainText[i]);
    // }
    // printf("\n");
    

    //CBC Notes - Altering passed in plaintext is changing the string we compare to
    //Must copy or something

    for (i = 0; i < plainTextSizeAligned_bytes; i++) {
        if (de_plainText[i] != plainText_verification[i]) {
            printf("\nERROR: %02x %02x\n", de_plainText[i], plainText_verification[i]);
            verificationSuccessful = 0;
        }
    }
    printf("\n");
    // printf("%s\n", string);

    if (verificationSuccessful) fprintf(stderr, "\nVerification successful\n");

    free(key);
    free(roundKeys);
    free(iv);

    printf("Encrypt Execution Time: %lfms\n", time_encrypt);
    printf("Decrypt Execution Time: %lfms\n", time_decrypt);

    return 0;
}
