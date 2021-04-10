#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "constants.h"
#include "AES_lib.h"

#define USE_TEST_CODE               1

#define KEY_SIZE_ARGUMENT_INDEX     1




__global__ void
naive_AES_encrypt(uint8_t* cipherText_d, uint8_t* plainText_d, uint32_t* roundKeys_d, NumRounds_t numRounds, uint32_t numPlainTextBlocks)
{
    int i = blockDim.x*blockIdx.x + threadIdx.x;

    if(i<numPlainTextBlocks)
    {
        AES_Encrypt_Block(plainText_d  + i * (BLOCK_SIZE_BITS / 8), 
                          cipherText_d + i * (BLOCK_SIZE_BITS / 8), 
                          roundKeys_d, numRounds);
    }
}

__global__ void
naive_AES_decrypt(uint8_t* plainText_d, uint8_t* cipherText_d, uint32_t* roundKeys_d, NumRounds_t numRounds, uint32_t numPlainTextBlocks)
{
    //int i = blockDim.x*blockIdx.x + threadIdx.x;

   /* if(i<numPlainTextBlocks)
    {
        AES_Decrypt_Block(cipherText_d + i * (BLOCK_SIZE_BITS / 8), 
                          plainText_d  + i * (BLOCK_SIZE_BITS / 8), 
                          roundKeys_d, numRounds);
    }   */

}

static cudaError_t AES_Encrypt(uint8_t* plainText_h, uint8_t* cipherText_h, uint32_t* roundKeys_h, NumRounds_t numRounds, uint32_t plainTextSize_bytes)
{
    cudaError_t err       = cudaSuccess;
    uint8_t* plainText_d  = NULL;
    uint8_t* cipherText_d = NULL;
    uint32_t* roundKeys_d = NULL;
    uint32_t plainTextBlockCnt;


    /*** Malloc Device memory ***/
    err = cudaMalloc((void**)&plainText_d, plainTextSize_bytes);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device vector plainText_d (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    err = cudaMalloc((void**)&roundKeys_d, sizeof(uint32_t) * numRounds * 4);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device vector roundKeys_d (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    err = cudaMalloc((void**)&cipherText_d, plainTextSize_bytes);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device vector cipherText_d (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    /*** Copy Data from Host to Device memory ***/
    err = cudaMemcpy(plainText_d, plainText_h, plainTextSize_bytes, cudaMemcpyHostToDevice);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to copy vector plainText from host to device (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    err = cudaMemcpy(roundKeys_d, roundKeys_h, sizeof(uint32_t) * numRounds * 4, cudaMemcpyHostToDevice);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to copy vector roundKeys from host to device (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }


    plainTextBlockCnt = (plainTextSize_bytes + (BLOCK_SIZE_BITS / 8)-1) / (BLOCK_SIZE_BITS / 8);

    int threadBlockDim = 256;
    dim3 threadsPerBlock(threadBlockDim, 1, 1);
    dim3 blocksPerGrid((plainTextSize_bytes+threadBlockDim-1)/threadBlockDim, 1, 1);

    naive_AES_encrypt<<<blocksPerGrid, threadsPerBlock>>>(cipherText_d, plainText_d, roundKeys_d, numRounds, plainTextBlockCnt);

    err = cudaGetLastError();
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to launch AES kernel (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    err = cudaMemcpy(cipherText_h, cipherText_d, plainTextSize_bytes, cudaMemcpyDeviceToHost);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to copy vector cipherText from device to host (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }



    /*** Free Device Mem ***/
    err = cudaFree(plainText_d);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to free device vector plainText (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    err = cudaFree(roundKeys_d);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to free device vector roundKeys (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    err = cudaFree(cipherText_d);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to free device vector cipherText (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }


    // TODO: Do we reset the device here or only at the end of main?

    return err;
}

cudaError_t AES_Decrypt(uint8_t* plainText_h, uint8_t* cipherText_h, uint32_t* roundKeys_h, NumRounds_t numRounds, uint32_t plainTextSize_bytes)
{
    cudaError_t err       = cudaSuccess;
    uint32_t* roundKeys_d = NULL;
    uint8_t* plainText_d  = NULL;
    uint8_t* cipherText_d = NULL;
    uint32_t plainTextBlockCnt;


    /*** Malloc Device memory ***/
    err = cudaMalloc((void**)&plainText_d, plainTextSize_bytes);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device vector plainText_d (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    err = cudaMalloc((void**)&roundKeys_d, sizeof(uint32_t) * numRounds * 4);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device vector roundKeys_d (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    err = cudaMalloc((void**)&cipherText_d, plainTextSize_bytes);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device vector cipherText_d (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    /*** Copy Data from Host to Device memory ***/
    err = cudaMemcpy(cipherText_d, cipherText_h, plainTextSize_bytes, cudaMemcpyHostToDevice);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to copy vector cipherText from host to device (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    err = cudaMemcpy(roundKeys_d, roundKeys_h, sizeof(uint32_t) * numRounds * 4, cudaMemcpyHostToDevice);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to copy vector roundKeys from host to device (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }


    plainTextBlockCnt = (plainTextSize_bytes + (BLOCK_SIZE_BITS / 8)-1) / (BLOCK_SIZE_BITS / 8);

    int threadBlockDim = 256;
    dim3 threadsPerBlock(threadBlockDim, 1, 1);
    dim3 blocksPerGrid((plainTextSize_bytes+threadBlockDim-1)/threadBlockDim, 1, 1);

    naive_AES_encrypt<<<blocksPerGrid, threadsPerBlock>>>(cipherText_d, plainText_d, roundKeys_d, numRounds, plainTextBlockCnt);

    err = cudaGetLastError();
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to launch AES kernel (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    err = cudaMemcpy(plainText_h, plainText_d, plainTextSize_bytes, cudaMemcpyDeviceToHost);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to copy vector plainText from device to host (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }



    /*** Free Device Mem ***/
    err = cudaFree(plainText_d);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to free device vector plainText (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    err = cudaFree(roundKeys_d);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to free device vector roundKeys (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    err = cudaFree(cipherText_d);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to free device vector cipherText (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }


    // TODO: Do we reset the device here or only at the end of main?

    return err;
}


main( int argc, char **argv )
{
    cudaError_t err = cudaSuccess;
    uint32_t plainTextSize_bytes = 0;

    uint32_t* key;
    uint32_t* roundKeys;

    KeySize_Word_t keySize_words = AES128_KEYSIZE;
    NumRounds_t rounds = AES128_ROUNDS;
    AESVersion_t version = AES128_VERSION;

    uint8_t* en_plainText;
    uint8_t* de_plainText;
    uint8_t* plainText_verification;
    uint8_t* cipherText;

    // TODO: Need to also supply filename of key 
    if(argc > 1)
    {
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
    }


#if (USE_TEST_CODE)
    keySize_words       = AES256_KEYSIZE;
    rounds              = AES256_ROUNDS;
    plainTextSize_bytes = 16;
#endif


    key = (uint32_t*)malloc(sizeof(uint32_t*) * keySize_words);
    roundKeys = (uint32_t*)malloc(sizeof(uint32_t*) * rounds * 4);
    en_plainText = (unsigned char*)malloc(sizeof(unsigned char) * plainTextSize_bytes);
    de_plainText = (unsigned char*)malloc(sizeof(unsigned char) * plainTextSize_bytes);
    plainText_verification = (unsigned char*)malloc(sizeof(unsigned char) * plainTextSize_bytes);
    cipherText = (unsigned char*)malloc(sizeof(unsigned char) * plainTextSize_bytes);

#if (USE_TEST_CODE)
    uint32_t sample256Key[8] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 
                                0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f};

    uint8_t sampleDataBlock[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                                   0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    memcpy((void*)key, (void*)sample256Key, sizeof(uint32_t*)*keySize_words);
    memcpy((void*)en_plainText, (void*)sampleDataBlock, plainTextSize_bytes);
    memcpy((void*)plainText_verification, (void*)sampleDataBlock, plainTextSize_bytes);

#else
    // TODO: copy supplied key file into key
    memcpy((void*)key, (void*)inputKey, sizeof(uint32_t*)*keySize_words);
    memcpy((void*)en_plainText, (void*)inputPlainText, plainTextSize_bytes);
    memcpy((void*)plainText_verification, (void*)inputPlainText, plainTextSize_bytes);
#endif

    KeyExpansion(key, roundKeys, version);

    err = AES_Encrypt(en_plainText, cipherText, roundKeys, rounds, plainTextSize_bytes);

    err = AES_Decrypt(de_plainText, cipherText, roundKeys, rounds, plainTextSize_bytes);

    /*** Free Host Memory ***/
    free(key);
    free(roundKeys);


    // TODO: What do we do with the data? (write to a file, compare against expected, return, etc) 

    err = cudaDeviceReset();
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to deinitialize the device! error=%s\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "GPU Implemntaion of AES Completed \n"); 
}
