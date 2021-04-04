#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "constants.h"

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
            // printf("%02x XOR %02x = ",(*state)[i][j], (uint8_t)(roundKeys[(round-1)*4 + j] >> (8*s)));
            (*state)[i][j] ^= (uint8_t) (roundKeys[(round-1)*4 + j] >> (8*s));
            // printf("%02x\n", (*state)[i][j]);
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
            uint8_t high = (col[i] >> 7) & 1;
            mult[i] = col[i] << 1; // multiply by 2
            mult[i] ^= high * 0x1b; // XOR with 0x1b if MSB was 1
        }

        // (*state)[0][j] = mult[0] ^ col[3] ^ col[2] ^ mult[1] ^ col[1];
        // (*state)[1][j] = mult[1] ^ col[0] ^ col[3] ^ mult[2] ^ col[2];
        // (*state)[2][j] = mult[2] ^ col[1] ^ col[0] ^ mult[3] ^ col[3];
        // (*state)[3][j] = mult[3] ^ col[2] ^ col[1] ^ mult[0] ^ col[0];

        (*state)[0][j] = mult_x2[col[0]] ^ mult_x3[col[1]] ^ col[2] ^ col[3];
        (*state)[1][j] = col[0] ^ mult_x2[col[1]] ^ mult_x3[col[2]] ^ col[3];
        (*state)[2][j] = col[0] ^ col[1] ^ mult_x2[col[2]] ^ mult_x3[col[3]];
        (*state)[3][j] = mult_x3[col[0]] ^ col[1] ^ col[2] ^ mult_x2[col[3]];
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

// 128 bit chunk of data - 16 chars
void AES_Encrypt_Block(char* data, uint32_t* roundKeys, unsigned int numround) {
    state_t state;
    int i, j, d;
    for (i = 0, d = 0; i < 4; i++)
        for (j = 0; j < 4; j++, d++) {
            state[j][i] = (uint8_t) data[d];
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
            data[d] = (uint8_t) state[j][i];
        }
}

void AES_Encrypt(char* data, uint32_t* roundKeys, AESVersion_t vers, int charCount) {
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
        AES_Encrypt_Block(data+i*(BLOCK_SIZE_BITS / 8) , roundKeys, numround);
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
void AES_Decrypt_Block(char* data, uint32_t* roundKeys, unsigned int numround) {
    state_t state;
    int i, j, d;
    for (i = 0, d = 0; i < 4; i++)
        for (j = 0; j < 4; j++, d++) {
            state[j][i] = (uint8_t) data[d];
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
            data[d] = (uint8_t) state[j][i];
        }
}

void AES_Decrypt(char* data, uint32_t* roundKeys, AESVersion_t vers, int charCount) {
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
        AES_Decrypt_Block(data+i*(BLOCK_SIZE_BITS / 8) , roundKeys, numround);
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

    unsigned char data[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    unsigned char data_copy[16]  = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    for (i = 0; i < 16; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");

    AES_Encrypt(data, roundKeys, version, 16);
    for (i = 0; i < 16; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");

    AES_Decrypt(data, roundKeys, version, 16);
    for (i = 0; i < 16; i++) {
        printf("%02x", data[i]);
        if (data[i] != data_copy[i]) printf("\nERROR\n");
    }
    printf("\n");
}
