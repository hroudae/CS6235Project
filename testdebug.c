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


//Stuff for Reading Test Files
//Takes a line of test file to turn into NUM of 8hex vals
void parseKey(char* hex, uint32_t* out, int outLength){
   char subkey[8];
   char* idx;
   //Initial Offsets -- Feels Sloppy
   switch(hex[0]){
      case 'K':
         idx = hex+6;
         // idx = 6;
         break;
      case 'P':
         idx = hex+13; //12
         break;
      case 'C':
         idx = hex+14; //13
         break;
      default:
         return;
         printf("shouldn't happen \n");
   }
   //source of bug
   strncpy(subkey, idx, 8);
   for (int i = 0; i < outLength; i++) {
       strncpy(subkey, idx, 8);
       // printf("Subkey: %s\n", subkey);
       out[i] =  (uint32_t) strtoul(subkey, NULL, 16); //
       idx += 8;
       printf("out[%d] %08x \n", i, out[i]);
   }
}

//Stuff for Reading Test Files
//Takes a line of test file to turn into NUM of 8hex vals
void parseLine(char* hex, unsigned char* out[], int outLength){
   char subkey[2];
   char* idx;
   //Initial Offsets -- Feels Sloppy
   switch(hex[0]){
      case 'P':
         idx = hex+12;
         break;
      case 'C':
         idx = hex+13;
         break;
      default:
         return;
         printf("This shouldn't happen \n");
   }
   strncpy(subkey, idx, 2);

   for (int i = 0; i < outLength; i++) {
       strncpy(subkey, idx, 2);
       // printf("Subkey: %s\n", subkey);
       out[i] = (unsigned char)strtoul(subkey, NULL, 16);
       idx += 2;
       // printf("out[%d] %02x \n", i, out[i]);
   }
}

//Not working
void printUCharArr(unsigned char* arr, int len){
  for (int i = 0; i < len; i++) {
      printf("%x", arr[i]);
  }
  return;
}

//Testing WIP
//Jeff
int main(int argc, char* argv[]){
    FILE *fp;
    // char line[60];
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen("kat_aes/ECBKeySbox256.rsp", "r");
    if (fp == NULL) {
      printf("not found \n");
      exit(EXIT_FAILURE);
    }

    //Hardcoded change to size of key
    unsigned int keysize = AES256_KEYSIZE;

    // uint32_t key[keysize]; // = malloc(sizeof(uint32_t)*AES256_KEYSIZE);
    uint32_t *key = malloc(sizeof(uint32_t)*AES256_KEYSIZE); //

    AESVersion_t version = AES256_VERSION;
    NumRounds_t rounds = AES256_ROUNDS;
    uint32_t *roundKeys = malloc(sizeof(uint32_t) * (4*rounds));

    unsigned char cipherText[16] = {0x00};
    unsigned char emptyStorage[16] = {0x00};

    // unsigned char decryptPlainText[16] = {0};

    unsigned char *plaintext[16]; //Original Plaintext
    //unsigned char *ciphertext[16]; //Ciphertext Tested
    unsigned char *cipherknown[16]; //known Answer

    int flipper = -1;

    while ((read = getline(&line, &len, fp)) != -1) {
      switch(line[0]) {
          case 'K':
             printf("%s", line);
             flipper = -1;
             parseKey(line, key, keysize); //Functional But hardcoded
             printf("\n Key Text: ");
             // printUCharArr(cipherknown, 16);
             for (int i = 0; i < keysize; i++) {
                 printf("%08x", key[i]);
               }
               printf("\n");
             break;
          case 'P':
             printf("%s", line);
             parseLine(line, plaintext, 16); //Functional But hardcoded
             break;
          case 'C':
             if(line[1]== 'I'){
               printf("%s", line);
               parseLine(line, cipherknown, 16); //Functional But hardcoded
               // printf("\n Cipher Text: ");
               // // printUCharArr(cipherknown, 16);
               // for (int i = 0; i < 16; i++) {
               //     printf("%x", cipherknown[i]);
               // }
               flipper = 1;
             }
             break;
      }

      if (flipper == 1){
        //encrypt
        KeyExpansion(key, roundKeys, version);
        AES_Encrypt(plaintext, cipherText, roundKeys, version, 16);
        printf("\nKey Expansion:\n");
        for (int i = 0; i < 4*rounds; i++) {
            printf("%08x", roundKeys[i]);
            if ((i+1) % 4 == 0) printf("\n");
        }
        printf("\n");
        printf("\nInput: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", plaintext[i]);
        }

        printf("\nOutput: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", cipherText[i]);
        }
        printf("\nExpected Text: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", cipherknown[i]);
        }
        printf("\n End Test \n");

        //check answer

        flipper = -1;

        //Reset cipherText
        memcpy(cipherText, emptyStorage, sizeof(emptyStorage));
      }

      //
      // if (line[0] == 'K' || line[0] == 'P' || line[0] == 'C') {
      //   printf("line %s \n", line);
      //   if(line[1] != 'O'){
      //
      //     printf("Line: %s \n", line);
          // parseLine(line, key, 6); //Functional But hardcoded
      // }
      // }

       }
       fclose(fp);
       if (line)
           free(line);
       exit(EXIT_SUCCESS);
}
//
// int main(int argc, char* argv[]){
// }
