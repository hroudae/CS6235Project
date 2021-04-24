#include "AES_lib.h"
#include "constants.h"

#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Debugging functions */
void printState(state_t state);

/* Key Functions */
uint32_t rotl32 (uint32_t value, unsigned int count);
uint32_t SubWord(uint32_t word);

/* Encrypt Functions */
void AddRoundKey(state_t* state, uint32_t* roundKeys, int round);
void SubBytes(state_t* state);
void ShiftRows(state_t* state);
void MixColumns(state_t* state);

/* Decrypt Functions */
void InvSubBytes(state_t* state);
void InvShiftRows(state_t* state);
void InvMixColumns(state_t* state);


// Get random bytes from /dev/urandom 
int GetIV(uint8_t *iv) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) { // couldn't open the file
        perror("ERROR");
        return -1;
    }
    else { // get 16 random bytes
        int rd = fread(iv, 1, 16, f);
        fclose(f);
        if (rd < 16) {
            perror("ERROR");
            return -1;
        }
    }
    return 0;
}

// Increment the 128 bit counter
void incrementCounter(uint8_t *ctr) {
    uint64_t high = ((uint64_t) ctr[0] << 56) | ((uint64_t) ctr[1] << 48) | 
                    ((uint64_t) ctr[2] << 40) | ((uint64_t) ctr[3] << 32) |
                    ((uint64_t) ctr[4] << 24) | ((uint64_t) ctr[5] << 16) | 
                    ((uint64_t) ctr[6] << 8)  | ((uint64_t) ctr[7]);
    uint64_t low  = ((uint64_t) ctr[8] << 56)  | ((uint64_t) ctr[9] << 48)  | 
                    ((uint64_t) ctr[10] << 40) | ((uint64_t) ctr[11] << 32) |
                    ((uint64_t) ctr[12] << 24) | ((uint64_t) ctr[13] << 16) | 
                    ((uint64_t) ctr[14] << 8)  | ((uint64_t) ctr[15]);
    if (++low == 0) ++high;
    int i, shift;
    for (i = 0, shift = 56; i < 8; i++, shift -= 8) {
        ctr[i] = (uint8_t) (high >> shift);
        ctr[i+8] = (uint8_t) (low >> shift);
    }
}

void printState(state_t state) {
    int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            printf("%02x ", state[i][j]);
        }
        printf("\n");
    }
}

// circular shift left: https://en.wikipedia.org/wiki/Circular_shift
uint32_t rotl32 (uint32_t value, unsigned int count) {
    const unsigned int mask = CHAR_BIT * sizeof(value) - 1;
    count &= mask;
    return (value << count) | (value >> (-count & mask));
}

uint32_t SubWord(uint32_t word) {
    // substitute word using sbox
    uint8_t byte0 = word >> 24;
    uint8_t byte1 = word >> 16 & ~(0xFF << 8);
    uint8_t byte2 = word >> 8 & ~(0xFFFF << 8);
    uint8_t byte3 = word & ~(0xFFFFFF << 8);
    uint32_t sub = (sbox[byte0] << 24) | (sbox[byte1] << 16) | (sbox[byte2] << 8) | sbox[byte3];
    return sub;
}

// key and roundKeys are stored in array of 32-bit unsigned int
// roundKey has 4(Number rounds)-1 32-bit words
void KeyExpansion(uint32_t* key, uint32_t* roundKeys, AESVersion_t vers) {
    unsigned int numround = 0;
    unsigned int keysize = 0;

    switch(vers) {
        case AES128_VERSION:
            numround = AES128_ROUNDS;
            keysize = AES128_KEYSIZE;
            break;
        case AES192_VERSION:
            numround = AES192_ROUNDS;
            keysize = AES192_KEYSIZE;
            break;
        case AES256_VERSION:
            numround = AES256_ROUNDS;
            keysize = AES256_KEYSIZE;
            break;
        default:
            numround = 0;
            keysize = 0;
    }

    int i;
    for (i = 0; i < 4*numround; i++) {
        if (i < keysize){
            roundKeys[i] = key[i];
        }
        else if (i >= keysize && i % keysize == 0) {
            // rotate one-byte left-circular
            uint32_t rot = rotl32(roundKeys[i-1],8);
            uint32_t sub = SubWord(rot);
            uint32_t rcon = rc[(i/keysize)-1] << 24;
            roundKeys[i] = roundKeys[i-keysize] ^ sub ^ rcon;
        }
        else if(i >= keysize && keysize > 6 && i % keysize == 4) {
            uint32_t sub = SubWord(roundKeys[i-1]);
            roundKeys[i] = roundKeys[i-keysize] ^ sub;
        }
        else {
            roundKeys[i] = roundKeys[i-keysize] ^ roundKeys[i-1];
        }
    }
}

void AddRoundKey(state_t* state, uint32_t* roundKeys, int round) {
    int i, j, s;
    for (i = 0, s = 3; i < 4; i++, s--) {
        for (j = 0; j < 4; j ++) {
            (*state)[i][j] ^= (uint8_t) (roundKeys[(round-1)*4 + j] >> (8*s));
        }
    }
}

void SubBytes(state_t* state) {
    int i, j;
    for (i = 0; i < 4; i++,j--) {
        for (j = 0; j < 4; j ++) {
            (*state)[i][j] = sbox[(*state)[i][j]];
        }
    }
}

void ShiftRows(state_t* state) {
    uint8_t temp = (*state)[1][0];
    (*state)[1][0] = (*state)[1][1];
    (*state)[1][1] = (*state)[1][2];
    (*state)[1][2] = (*state)[1][3];
    (*state)[1][3] = temp;

    temp = (*state)[2][0];
    (*state)[2][0] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp = (*state)[2][1];
    (*state)[2][1] = (*state)[2][3];
    (*state)[2][3] = temp;

    temp = (*state)[3][3];
    (*state)[3][3] = (*state)[3][2];
    (*state)[3][2] = (*state)[3][1];
    (*state)[3][1] = (*state)[3][0];
    (*state)[3][0] = temp;
}

void MixColumns(state_t* state) {
    int i, j;
    uint8_t col[4];
    uint8_t mult[4]; // each element of the column of state multiplied by 2
    for (j = 0; j < 4; j++) {
        for (i = 0; i < 4; i++) {
            col[i] = (*state)[i][j];
        }

        (*state)[0][j] = mult_x2[col[0]] ^ mult_x3[col[1]] ^ col[2] ^ col[3];
        (*state)[1][j] = col[0] ^ mult_x2[col[1]] ^ mult_x3[col[2]] ^ col[3];
        (*state)[2][j] = col[0] ^ col[1] ^ mult_x2[col[2]] ^ mult_x3[col[3]];
        (*state)[3][j] = mult_x3[col[0]] ^ col[1] ^ col[2] ^ mult_x2[col[3]];
    }
}

// 128 bit chunk of data - 16 chars
void AES_Encrypt_Block(unsigned char* plainText, unsigned char* cipherText, uint32_t* roundKeys, unsigned int numround) {
    state_t state;
    int i, j, d;
    for (i = 0, d = 0; i < 4; i++)
        for (j = 0; j < 4; j++, d++) {
            state[j][i] = (uint8_t) plainText[d];
        }
    // round 1 - just add key
    AddRoundKey(&state, roundKeys, 1);

    // the rest of the rounds except the final
    int round;
    for (round = 2; round < numround; round++) {
        SubBytes(&state);
        ShiftRows(&state);
        MixColumns(&state);
        AddRoundKey(&state, roundKeys, round);
    }

    // final round
    SubBytes(&state);
    ShiftRows(&state);
    AddRoundKey(&state, roundKeys, numround);

    for (i = 0, d = 0; i < 4; i++)
        for (j = 0; j < 4; j++, d++) {
            cipherText[d] = (uint8_t) state[j][i];
        }
}

void InvSubBytes(state_t* state) {
    int i, j;
    for (i = 0; i < 4; i++,j--) {
        for (j = 0; j < 4; j ++) {
            (*state)[i][j] = invsbox[(*state)[i][j]];
        }
    }
}

void InvShiftRows(state_t* state) {
    uint8_t temp = (*state)[1][3];
    (*state)[1][3] = (*state)[1][2];
    (*state)[1][2] = (*state)[1][1];
    (*state)[1][1] = (*state)[1][0];
    (*state)[1][0] = temp;

    temp = (*state)[2][0];
    (*state)[2][0] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp = (*state)[2][1];
    (*state)[2][1] = (*state)[2][3];
    (*state)[2][3] = temp;

    temp = (*state)[3][0];
    (*state)[3][0] = (*state)[3][1];
    (*state)[3][1] = (*state)[3][2];
    (*state)[3][2] = (*state)[3][3];
    (*state)[3][3] = temp;
}

void InvMixColumns(state_t* state) {
    int i, j;
    uint8_t col[4];
    for (j = 0; j < 4; j++) {
        for (i = 0; i < 4; i++) {
            col[i] = (*state)[i][j];
        }

        (*state)[0][j] = mult_x14[col[0]] ^ mult_x11[col[1]] ^ mult_x13[col[2]] ^ mult_x9[col[3]];
        (*state)[1][j] = mult_x9[col[0]] ^ mult_x14[col[1]] ^ mult_x11[col[2]] ^ mult_x13[col[3]];
        (*state)[2][j] = mult_x13[col[0]] ^ mult_x9[col[1]] ^ mult_x14[col[2]] ^ mult_x11[col[3]];
        (*state)[3][j] = mult_x11[col[0]] ^ mult_x13[col[1]] ^ mult_x9[col[2]] ^ mult_x14[col[3]];
    }
}

// 128 bit chunk of data - 16 chars
void AES_Decrypt_Block(unsigned char* cipherText, unsigned char* plainText, uint32_t* roundKeys, unsigned int numround) {
    state_t state;
    int i, j, d;
    for (i = 0, d = 0; i < 4; i++)
        for (j = 0; j < 4; j++, d++) {
            state[j][i] = (uint8_t) cipherText[d];
        }
    AddRoundKey(&state, roundKeys, numround);
    InvShiftRows(&state);
    InvSubBytes(&state);

    // the rest of the rounds except the final
    int round;
    for (round = numround-1; round > 1; round--) {
        AddRoundKey(&state, roundKeys, round);
        InvMixColumns(&state);
        InvShiftRows(&state);
        InvSubBytes(&state);
    }

    AddRoundKey(&state, roundKeys, 1);

    for (i = 0, d = 0; i < 4; i++)
        for (j = 0; j < 4; j++, d++) {
            plainText[d] = (uint8_t) state[j][i];
        }
}

void getDecKeyfromAsciiKey(char* asciiKey, uint32_t* decimalKey, uint32_t keyLength_words)
{
   char word[NUM_CHARS_IN_WORD];

   int i;
   for(i = 0; i < keyLength_words; i++)
   {
        strncpy(word, asciiKey+(i*NUM_CHARS_IN_WORD), NUM_CHARS_IN_WORD);
        decimalKey[i] = (uint32_t)strtoul(word, NULL, BASE_HEX);
   }

   return;
}
