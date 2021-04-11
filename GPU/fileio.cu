#include <stdio.h>
#include <stdlib.h>
#include "fileio.h"



/*
 *  filename is the path to the input file
 *  buf_ptr should be a pointer to a char array
 *  maxsize should be the maximum size file to be read
 */
int readfile(const char* filename, unsigned char **buf_ptr, unsigned int maxsize) {
    *buf_ptr = NULL;

    FILE *f = fopen(filename, "rb");
    if (f == NULL) {
        perror("ERROR fopen");
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f); // should probably make sure file is not too big
    rewind(f);

    if (fsize > maxsize || fsize == -1) {
        perror("ERROR size");
        fprintf(stderr, "%d\n", fsize);
        return -1;
    }

    *buf_ptr = (unsigned char*)malloc(fsize + 1);

    if (*buf_ptr == NULL) {
        perror("ERROR malloc");
        return -1;
    }

    int rd = fread(*buf_ptr, 1, fsize, f);
    fclose(f);
    if (rd < fsize) {
        perror("ERROR fread");
        return -1;
    }
    
    (*buf_ptr)[fsize] = 0;

    return fsize;
}