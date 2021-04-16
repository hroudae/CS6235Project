#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "constants.h"
#include "AES_lib.h"
#include "fileio.h"


#define KEY_SIZE_ARGUMENT_INDEX     1
#define KEY_FP_INDEX                2
#define PLAIN_TEXT_FP_INDEX         3
#define MODE_INDEX                  4

#define CHARS_PER_BYTE              2


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
naive_AES_decrypt(uint8_t* cipherText_d, uint8_t* plainText_d, uint32_t* roundKeys_d, NumRounds_t numRounds, uint32_t numPlainTextBlocks)
{
    int i = blockDim.x*blockIdx.x + threadIdx.x;

    if(i<numPlainTextBlocks)
    {
        AES_Decrypt_Block(cipherText_d + i * (BLOCK_SIZE_BITS / 8),
                          plainText_d  + i * (BLOCK_SIZE_BITS / 8),
                          roundKeys_d, numRounds);
    }

}

__global__ void
ctr_AES_encrypt(uint8_t* cipherText_d, uint8_t* plainText_d, uint32_t* roundKeys_d, NumRounds_t numRounds, uint32_t numPlainTextBlocks, uint8_t* counter) {
    int i = blockDim.x*blockIdx.x + threadIdx.x;
    int j;

    if(i<numPlainTextBlocks)
    {
        uint8_t ctr[16];
        incrementCounter(ctr, counter, i);
        AES_Encrypt_Block(ctr,
                          cipherText_d + i * (BLOCK_SIZE_BITS / 8),
                          roundKeys_d, numRounds);

        for (j = 0; j < 16; j++) {
            *((cipherText_d+i*(BLOCK_SIZE_BITS / 8))+j) ^= *(plainText_d+i*(BLOCK_SIZE_BITS / 8)+j);
        }
    }
}

__global__ void
ctr_AES_decrypt(uint8_t* cipherText_d, uint8_t* plainText_d, uint32_t* roundKeys_d, NumRounds_t numRounds, uint32_t numPlainTextBlocks, uint8_t* counter) {
    int i = blockDim.x*blockIdx.x + threadIdx.x;
    int j;

    if(i<numPlainTextBlocks)
    {
        uint8_t ctr[16];
        incrementCounter(ctr, counter, i);
        AES_Encrypt_Block(ctr,
            plainText_d + i * (BLOCK_SIZE_BITS / 8),
            roundKeys_d, numRounds);

        for (j = 0; j < 16; j++)
            *(plainText_d+i*(BLOCK_SIZE_BITS / 8)+j) ^= *((cipherText_d+i*(BLOCK_SIZE_BITS / 8))+j);
    }
}

//NOT TESTED
__global__ void
cbc_AES_encrypt(uint8_t* cipherText_d, uint8_t* plainText_d, uint32_t* roundKeys_d, NumRounds_t numRounds, uint32_t numPlainTextBlocks, uint8_t* counter) {
    int i = blockDim.x*blockIdx.x + threadIdx.x;
    int j;

    int step = blockDim.x * blockDim.y * blockDim.z; // Should be 256 right now. Might need to mult by num blocks
    int initial = 0; //Janky way to do first step. Theres prob a cleaner mod math way but /shrug

    uint8_t ctr[16]; //Treating ctr as init vector. Moved up to avoid re-init
    incrementCounter(ctr, counter, i); //toss some values in there

    //Doesn't this process only happen once in other versions?
    //Need as many threads as you have blocks of data
    //Designing mine to assume that data blocks >>>> thread limit (1024 max)
    //But current setup is 256 threads so gonna roll w/ that
    while(i<numPlainTextBlocks)
    {
        if (initial != 0){ //Conditionals are bad in kernels aren't they. Wrapped to avoid doing 16 chex
            for (j = 0; j < 16; j++) {
                *(plainText_d+i*(BLOCK_SIZE_BITS / 8)+j) ^= *((cipherText_d+(i-step)*(BLOCK_SIZE_BITS / 8))+j);
            }
        }
      AES_Encrypt_Block(plainText_d+i*(BLOCK_SIZE_BITS / 8),
                        cipherText_d+i*(BLOCK_SIZE_BITS / 8),
                        roundKeys_d, numRounds);
        i+= step;
    }
}

__global__ void
cbc_AES_decrypt(uint8_t* cipherText_d, uint8_t* plainText_d, uint32_t* roundKeys_d, NumRounds_t numRounds, uint32_t numPlainTextBlocks, uint8_t* counter) {
    int i = blockDim.x*blockIdx.x + threadIdx.x;
    int j;
    int step = blockDim.x * blockDim.y * blockDim.z; // Should be 256 right now. Might need to mult by num blocks
    int initial = 0; //Janky way to do first step. Theres prob a cleaner mod math way but /shrug

    uint8_t ctr[16]; //Treating ctr as init vector. Moved up to avoid re-init
    incrementCounter(ctr, counter, i); //toss some values in there

    if(i<numPlainTextBlocks)
    {

        uint8_t ctr[16];
        incrementCounter(ctr, counter, i);
        AES_Encrypt_Block(ctr,
            plainText_d + i * (BLOCK_SIZE_BITS / 8),
            roundKeys_d, numRounds);

        for (j = 0; j < 16; j++)
            *(plainText_d+i*(BLOCK_SIZE_BITS / 8)+j) ^= *((cipherText_d+i*(BLOCK_SIZE_BITS / 8))+j);
    }
}

static cudaError_t AES_Encrypt(uint8_t* plainText_h, uint8_t* cipherText_h, uint32_t* roundKeys_h, NumRounds_t numRounds, uint32_t plainTextSize_bytes, ModeOfOperation_t mode, uint8_t *iv_h)
{
    cudaError_t err       = cudaSuccess;
    uint8_t* plainText_d  = NULL;
    uint8_t* cipherText_d = NULL;
    uint32_t* roundKeys_d = NULL;
    uint32_t plainTextBlockCnt;
    uint8_t* iv_d = NULL;

    cudaEvent_t start, stop;
    float seconds = 0;


    cudaEventCreate(&start);
    cudaEventCreate(&stop);


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

    if (mode == CTR) {
        err = cudaMalloc((void**)&iv_d, sizeof(uint8_t)*16);
        if (err != cudaSuccess)
        {
            fprintf(stderr, "Failed to allocate device IV_d (error code %s)!\n", cudaGetErrorString(err));
            exit(EXIT_FAILURE);
        }
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

    // generate a random IV to be used in CTR mode
    if (mode == CTR) {
        if (GetIV(iv_h) < 0) {
            printf("Error getting IV!\n");
            exit(EXIT_FAILURE);
        }
        err = cudaMemcpy(iv_d, iv_h, sizeof(uint8_t) * 16, cudaMemcpyHostToDevice);
        if (err != cudaSuccess) {
            fprintf(stderr, "Failed to copy IV from host to device (error code %s)!\n", cudaGetErrorString(err));
            exit(EXIT_FAILURE);
        }
    }

    plainTextBlockCnt = (plainTextSize_bytes + (BLOCK_SIZE_BITS / 8)-1) / (BLOCK_SIZE_BITS / 8);

    int threadBlockDim = 256;
    dim3 threadsPerBlock(threadBlockDim, 1, 1);
    dim3 blocksPerGrid((plainTextSize_bytes+threadBlockDim-1)/threadBlockDim, 1, 1);

    cudaEventRecord(start);
    if (mode == CTR)
        ctr_AES_encrypt<<<blocksPerGrid, threadsPerBlock>>>(cipherText_d, plainText_d, roundKeys_d, numRounds, plainTextBlockCnt, iv_d);
    else
        naive_AES_encrypt<<<blocksPerGrid, threadsPerBlock>>>(cipherText_d, plainText_d, roundKeys_d, numRounds, plainTextBlockCnt);
    cudaEventRecord(stop);

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

    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&seconds, start, stop);

    fprintf(stderr, "Encrypt Execution Time: %fs\n", seconds);


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

    if (mode == CTR) {
        err = cudaFree(iv_d);
        if (err != cudaSuccess)
        {
            fprintf(stderr, "Failed to free device vector IV (error code %s)!\n", cudaGetErrorString(err));
            exit(EXIT_FAILURE);
        }
    }

    // TODO: Do we reset the device here or only at the end of main?

    return err;
}

cudaError_t AES_Decrypt(uint8_t* plainText_h, uint8_t* cipherText_h, uint32_t* roundKeys_h, NumRounds_t numRounds, uint32_t plainTextSize_bytes, ModeOfOperation_t mode, uint8_t *iv_h)
{
    cudaError_t err       = cudaSuccess;
    uint32_t* roundKeys_d = NULL;
    uint8_t* plainText_d  = NULL;
    uint8_t* cipherText_d = NULL;
    uint32_t plainTextBlockCnt;
    uint8_t* iv_d = NULL;

    cudaEvent_t start, stop;
    float seconds = 0;


    cudaEventCreate(&start);
    cudaEventCreate(&stop);


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
    if (mode == CTR) {
        err = cudaMalloc((void**)&iv_d, sizeof(uint8_t)*16);
        if (err != cudaSuccess)
        {
            fprintf(stderr, "Failed to allocate device IV_d (error code %s)!\n", cudaGetErrorString(err));
            exit(EXIT_FAILURE);
        }
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

    if (mode == CTR) {
        err = cudaMemcpy(iv_d, iv_h, sizeof(uint8_t) * 16, cudaMemcpyHostToDevice);
        if (err != cudaSuccess)
        {
            fprintf(stderr, "Failed to copy IV from host to device (error code %s)!\n", cudaGetErrorString(err));
            exit(EXIT_FAILURE);
        }
    }

    plainTextBlockCnt = (plainTextSize_bytes + (BLOCK_SIZE_BITS / 8)-1) / (BLOCK_SIZE_BITS / 8);

    int threadBlockDim = 256;
    dim3 threadsPerBlock(threadBlockDim, 1, 1);
    dim3 blocksPerGrid((plainTextSize_bytes+threadBlockDim-1)/threadBlockDim, 1, 1);

    cudaEventRecord(start);
    if (mode == CTR)
        ctr_AES_decrypt<<<blocksPerGrid, threadsPerBlock>>>(cipherText_d, plainText_d, roundKeys_d, numRounds, plainTextBlockCnt, iv_d);
    else
        naive_AES_decrypt<<<blocksPerGrid, threadsPerBlock>>>(cipherText_d, plainText_d, roundKeys_d, numRounds, plainTextBlockCnt);
    cudaEventRecord(stop);

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

    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&seconds, start, stop);

    fprintf(stderr, "Decrypt Execution Time: %fs\n", seconds);


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

    if (mode == CTR) {
        err = cudaFree(iv_d);
        if (err != cudaSuccess)
        {
            fprintf(stderr, "Failed to free device vector IV (error code %s)!\n", cudaGetErrorString(err));
            exit(EXIT_FAILURE);
        }
    }

    // TODO: Do we reset the device here or only at the end of main?

    return err;
}

/* arguments keySize, keyFile, plainTextFile, mode*/
/* mode is 0 for ECB, 1 for CTR */
main( int argc, char **argv )
{
    cudaError_t err = cudaSuccess;
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

    bool verificationSuccessful = true;

#ifdef USE_TEST_CODE
    uint32_t appendedZeroCnt_bytes = 0;
#else
    unsigned char* inFilekey;
    uint32_t expectedKeySize;
    unsigned char* inputPlainText;
    uint32_t numCharRead = 0;
    uint32_t appendedZeroCnt_bytes = 0;
#endif


    if(argc > 1)
    {

#ifdef USE_TEST_CODE
        fprintf(stderr, "Test code enabled: Cannot supply arguments\n");
        return 1;
#else


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


        plainTextSize_bytes = readfile(argv[PLAIN_TEXT_FP_INDEX], &inputPlainText, 16777216);
        if (plainTextSize_bytes < 1)
        {
            fprintf(stderr, "ERROR reading plainText file\n");
            return 1;
        }
        else
        {
            fprintf(stderr, "Read %d bytes from input plain text file\n", plainTextSize_bytes);
        }

#if 0
        fprintf(stderr, "\n");
        for(loopNdx=0; loopNdx<100; loopNdx++)
        {
            fprintf(stderr,"%c", inputPlainText[loopNdx]);
        }
        fprintf(stderr, "\n");
#endif

        fprintf(stderr, "\n");
#endif
    }
    else
    {
#ifdef USE_TEST_CODE
        fprintf(stderr, "Using hardcoded test: 1 block and 256 bit key\n");
#else
        fprintf(stderr, "insufficient arguments and test code disabled.\n");
#endif
    }


#ifdef USE_TEST_CODE
    keySize_words       = AES256_KEYSIZE;
    rounds              = AES256_ROUNDS;
    plainTextSize_bytes = 16;
#endif

    appendedZeroCnt_bytes = BLOCK_SIZE_BITS - plainTextSize_bytes%BLOCK_SIZE_BITS;
    plainTextSizeAligned_bytes = plainTextSize_bytes + appendedZeroCnt_bytes;

    key = (uint32_t*)calloc(sizeof(uint32_t*) * keySize_words, sizeof(uint32_t));
    roundKeys = (uint32_t*)calloc(sizeof(uint32_t*) * rounds * 4, sizeof(uint32_t));
    en_plainText = (unsigned char*)calloc(sizeof(unsigned char) * plainTextSizeAligned_bytes, sizeof(uint8_t));
    de_plainText = (unsigned char*)calloc(sizeof(unsigned char) * plainTextSizeAligned_bytes, sizeof(uint8_t));
    plainText_verification = (unsigned char*)calloc(sizeof(unsigned char) * plainTextSize_bytes, sizeof(uint8_t));
    cipherText = (unsigned char*)calloc(sizeof(unsigned char) * plainTextSizeAligned_bytes, sizeof(uint8_t));

#ifdef USE_TEST_CODE
    uint32_t sample256Key[8] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
                                0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f};

    uint8_t sampleDataBlock[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                   0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    memcpy((void*)key, (void*)sample256Key, sizeof(uint32_t*)*keySize_words);
    memcpy((void*)en_plainText, (void*)sampleDataBlock, plainTextSize_bytes);
    memcpy((void*)plainText_verification, (void*)sampleDataBlock, plainTextSize_bytes);

#else
    // TODO: copy supplied key file into key
    /*uint32_t inputKey[8] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
                                0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f};*/

    getDecKeyfromAsciiKey((char*)inFilekey, key, keySize_words);

#if 0
    fprintf(stderr, "\n");
    for(loopNdx=0; loopNdx<keySize_words; loopNdx++)
    {
        fprintf(stderr,"key[%d]=0x%08x\n", loopNdx, key[loopNdx]);
    }
    fprintf(stderr, "\n");
#endif

    memcpy((void*)en_plainText, (void*)inputPlainText, plainTextSize_bytes);
    memcpy((void*)plainText_verification, (void*)inputPlainText, plainTextSize_bytes);
#endif

    KeyExpansion(key, roundKeys, version);

#if 0
    for(loopNdx=0; loopNdx<plainTextSizeAligned_bytes; loopNdx++)
    {
        printf("plaintText[%d]=%02x\n", loopNdx, en_plainText[loopNdx]);
    }
    fprintf(stderr, "\n");
#endif
    err = AES_Encrypt(en_plainText, cipherText, roundKeys, rounds, plainTextSizeAligned_bytes, mode, iv);

#if 0
    for(loopNdx=0; loopNdx<plainTextSizeAligned_bytes; loopNdx++)
    {
        printf("cipherText[%d]=%02x\n", loopNdx, cipherText[loopNdx]);
    }
    fprintf(stderr, "\n");
#endif

    err = AES_Decrypt(de_plainText, cipherText, roundKeys, rounds, plainTextSizeAligned_bytes, mode, iv);

#if 0
    fprintf(stderr, "Verifications plainTextSize_bytes: %d\n", plainTextSize_bytes);
    fprintf(stderr, "Verifications plainTextSizeAligned_bytes: %d\n", plainTextSizeAligned_bytes);
#endif

    for(loopNdx=0; loopNdx<plainTextSize_bytes; loopNdx++)
    {
        if(de_plainText[loopNdx] != plainText_verification[loopNdx])
        {
            fprintf(stderr, "Verification Failed at index %d! %02x!=%02x\n",
                loopNdx, de_plainText[loopNdx], plainText_verification[loopNdx]);

            verificationSuccessful = false;
        }
    }

    if(verificationSuccessful)
    {
        fprintf(stderr, "\nVerification successful\n");
    }

    /*** Free Host Memory ***/
    free(key);
    free(roundKeys);
    free(iv);


    // TODO: What do we do with the data? (write to a file, compare against expected, return, etc)

    err = cudaDeviceReset();
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to deinitialize the device! error=%s\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "AES Execution Completed\n");
}
