#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AES_lib.h"
#include "constants.h"

//Stuff for Reading Test Files
//Takes a line of test file to turn into NUM of 8hex vals
void parseKey(char* hex, uint32_t* out[], int outLength){
   char subkey[8];
   char* idx;
   //Initial Offsets -- Feels Sloppy
   switch(hex[0]){
      case 'K':
         idx = hex+6;
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
   strncpy(subkey, idx, 8);

   for (int i = 0; i < outLength; i++) {
       strncpy(subkey, idx, 8);
       //printf("Subkey: %s\n", subkey);
       out[i] = (uint32_t)strtoul(subkey, NULL, 16);
       idx += 8;
       //printf("out[%d] %08x \n", i, out[i]);
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
         printf("shouldn't happen \n");
   }
   strncpy(subkey, idx, 2);

   for (int i = 0; i < outLength; i++) {
       strncpy(subkey, idx, 2);
       printf("Subkey: %s\n", subkey);
       out[i] = (unsigned char)strtoul(subkey, NULL, 16);
       idx += 2;
       printf("out[%d] %02x \n", i, out[i]);
   }
}

//Testing WIP
//Jeff
int main(int argc, char* argv[]){
    FILE *fp;
    // char line[60];
    char * line = NULL;

    size_t len = 0;
    ssize_t read;

    fp = fopen("kat_aes/OFBKeySbox192.rsp", "r");
    if (fp == NULL) {
      printf("not found \n");
      exit(EXIT_FAILURE);
    }
    //Hardcoded change to size of key
    unsigned int keysize = AES192_KEYSIZE;

    uint32_t *key[keysize]; // = malloc(sizeof(uint32_t)*6);
    // uint32_t *plaintext[4];
    // uint32_t *cipher[4];
    unsigned char *plaintext[16];
    unsigned char *cipher[16];

    int flipper = -1;

    while ((read = getline(&line, &len, fp)) != -1) {
      switch(line[0]) {
          case 'K':
             printf("%s", line);
             parseKey(line, key, keysize); //Functional But hardcoded
             break;
          case 'P':
             printf("%s", line);
             parseLine(line, plaintext, 16); //Functional But hardcoded


             break;
          case 'C':
             if(line[1]== 'I'){
               printf("%s", line);
               parseLine(line, cipher, 16); //Functional But hardcoded
               flipper = 1;

             }
             else {
               flipper = 1;
             }
             break;
      }

      if (flipper == 1){
        //encrypt

        //check answer

        flipper = -1;
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
