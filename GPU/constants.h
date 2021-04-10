#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <stdint.h>

#define BLOCK_SIZE_BITS 128

#define BIT_KEY_128     128
#define BIT_KEY_192     192
#define BIT_KEY_256     256

// AES key sized used
typedef enum {
    AES128_VERSION,
    AES192_VERSION,
    AES256_VERSION
} AESVersion_t;

// Number of rounds
 typedef enum {
    AES128_ROUNDS = 11,
    AES192_ROUNDS = 13,
    AES256_ROUNDS = 15
} NumRounds_t;

/* Key sizes for AES variants:
 * AES-128: 4 32-bit words
 * AES-192: 6 32-bit words
 * AES-256: 8 32-bit words
 */
typedef enum {
    AES128_KEYSIZE = 4,
    AES192_KEYSIZE = 6,
    AES256_KEYSIZE = 8
} KeySize_Word_t;

typedef uint8_t state_t[4][4];


extern const uint8_t sbox[256];
extern __device__ const uint8_t sbox_d[256];
extern __device__ const uint8_t invsbox[256];
extern const uint8_t rc[10];

// Lookups for Mix Columns
extern __device__ const uint8_t mult_x2[256];
extern __device__ const uint8_t mult_x3[256];

// Lookups for Inverse Mix Columns
extern __device__ const uint8_t mult_x9[256];
extern __device__ const uint8_t mult_x11[256];
extern __device__ const uint8_t mult_x13[256];
extern __device__ const uint8_t mult_x14[256];


#endif // CONSTANTS_H
