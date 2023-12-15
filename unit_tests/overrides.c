#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include "../include/memdbg.h"

uint32_t trueRand(void);
static inline int randi(void); 
static uint32_t seed;

int main(void) {
    memdbg_Init((1 << MEMDBG_N_OPTIONS) - 1);

    seed = trueRand();

    FILE *fid[2];
    void *ptrs[3];
    
    char *modes[2];
    size_t alloc_sz[3];
    size_t elem_sz[3];

    int res[5];

    for (uint32_t i = 0; i < 3; i++) {
        if (i < 3) {
            int temp = randi();
            modes[i] = ((temp & 2) && (temp & 1))? "w+": ((temp & 2)? "a+": ((temp & 1)? "r": "w"));
        }
        alloc_sz[i] = randi();
        elem_sz[i] = 1 << (randi() & 7); // 1, 2, 4, 8, 16, 32 or 64;
    }

    fid[0] = fopen("unit_test1.txt", modes[0]);
    ptrs[0] = malloc(alloc_sz[0] * elem_sz[0]);
    res[0] = (int)fopen_s(&fid[1], "unit_test2.txt", modes[1]);
    ptrs[1] = realloc(ptrs[0], alloc_sz[1] * elem_sz[1]);
    ptrs[2] = calloc(alloc_sz[2], elem_sz[2]);
    if (*modes[0] != 'r')
        res[1] = fprintf(fid[0], "cool\n");
    else
        res[1] = -69;

    free(ptrs[1]);
    res[2] = fclose(fid[0]);
    if (*modes[1] != 'r')
        res[3] = fprintf(fid[1], "noice!\n");
    else
        res[3] = -69;
    free(ptrs[2]);
    res[4] = fclose(fid[1]);


    for (uint32_t i = 0; i < sizeof(res)/sizeof(res[0]); i++) {
        printf("%d, ", res[i]);
    }
    return 0;
}

unsigned int trueRand(void) {
    unsigned int res = 0;
    int n_fails = 0;
    while (!_rdseed32_step(&res)) {
        n_fails++;
        if (n_fails > 1000) {
            exit(EXIT_FAILURE);
        }
    }
    return res;
}

// random int from 0 to 32767
static inline int randi(void) {
    seed = (214013 * seed + 2531011);
    return (seed >> 16) & 0x7FFF;
}