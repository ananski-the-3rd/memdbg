#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include <pthread.h>
#include <unistd.h>
#include "../memdbg.h"

#ifdef __GNUC__
#define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#define UNUSED_FUNCTION(x) __attribute__((__unused__)) UNUSED_ ## x
#else
#define UNUSED(x) UNUSED_ ## x
#define UNUSED_FUNCTION(x) UNUSED_ ## x
#endif

void checkMalloc(void);
void checkCalloc(void);
void checkRealloc(void);
void checkFree(void);
void checkFopen(void);
void checkFopens(void);
void checkFclose(void);

uint32_t trueRand(void);
static inline int randi(void); 
static uint32_t seed;
#define N_RERUNS 100

int main(void) {
    memdbg_Init((MEMDBG_OPTIONS_MULTIPLE_ERRORS) |
                (MEMDBG_OPTIONS_OVERALLOC) |
                (MEMDBG_OPTIONS_PRINT_ALL) |
                (!MEMDBG_OPTIONS_THREADS));

    checkMalloc();
    checkCalloc();
    checkRealloc();
    checkFree();
    checkFopen();
    checkFopens();
    checkFclose();

    return 0;
}

void checkMalloc(void) {
    void *ptrs[3];
    for (int ii = 0; ii < N_RERUNS; ii++) {
        // allocsize0
        ptrs[0] = malloc(0);
        // allocnull
        ptrs[1] = malloc(INT64_MAX);
    }

    printf("\nCheckMalloc:\n");
    for (uint32_t i  = 0; i < sizeof(ptrs)/sizeof(ptrs[0]); i++) {
        printf("%p, ", ptrs[i]);
    }
    return;
}


void checkCalloc(void) {
    void *ptrs[2];
    for (int ii = 0; ii < N_RERUNS; ii++) { 
        // allocsize0
        ptrs[0] = calloc(0, 0);
        // allocnull
        ptrs[1] = calloc(INT64_MAX, 1);
        //
    }

    printf("\nCheckCalloc:\n");
    for (uint32_t i  = 0; i < sizeof(ptrs)/sizeof(ptrs[0]); i++) {
        printf("%p, ", ptrs[i]);
    }
    return;
}


void checkRealloc(void) {

    void *ptrs[5];
    for (int ii = 0; ii < N_RERUNS; ii++) {
        // argnull
        ptrs[0] = realloc(NULL, randi());
        // notpreviously
        int not_previously;
        ptrs[1] = realloc(&not_previously, randi());
        // already
        free(ptrs[0]);
        ptrs[2] = realloc(ptrs[0], 5);
        // bufferoverflow
        *((char *)ptrs[2] + 5) = (randi() % ('z' - 'a')) + 'a';
        // allocsize0
        ptrs[3] = realloc(ptrs[2], 0);
        // allocnull
        ptrs[4] = realloc(ptrs[3], INT64_MAX);
        //
    }
    printf("\nCheckRealloc:\n");
    for (uint32_t i  = 0; i < sizeof(ptrs)/sizeof(ptrs[0]); i++) {
        printf("%p, ", ptrs[i]);
    }
    return;
}


void checkFree(void) {
    for (int ii = 0; ii < N_RERUNS; ii++) {
        // argnull
        free(NULL);
        // notpreviously
        int not_previously;
        free(&not_previously);
        // already
        int *ptr = malloc(1);
        free(ptr);
        free(ptr);
        // bufferoverflow
        ptr = malloc(1);
        ptr[2] = 5;
        free(ptr);
        // bufferunderflow
        ptr = malloc(4);
        ptr[-1] = 7;
        free(ptr);
    }
    return;
}


void checkFopen(void) {
    FILE *fids[4];
    for (int ii = 0; ii < N_RERUNS; ii++) {
        // argnull
        fids[0] = fopen("error_checking.txt", NULL);
        fids[1] = fopen(NULL, "w+");
        fids[2] = fopen(NULL, NULL);
        // fail
        fids[3] = fopen("non-existing.txt", "r");
        //
    }
    printf("\nCheckFopen:\n");
    for (uint32_t i  = 0; i < sizeof(fids)/sizeof(fids[0]); i++) {
        printf("%p, ", (void *)fids[i]);
    }
    return;
}


void checkFopens(void) {

    int res[5];
    FILE *fid;
    for (int ii = 0; ii < N_RERUNS; ii++) {
        // argnull
        res[0] = fopen_s(&fid, "error_checking.txt", NULL);
        res[1] = fopen_s(&fid, NULL, "w+");
        res[2] = fopen_s(NULL, "error_checking.txt", "w+");
        res[3] = fopen_s(NULL, NULL, NULL);
        // fail
        res[4] = fopen_s(&fid, "non-existing.txt", "r");
        //
    }

    printf("\nCheckFopens:\n");
    for (uint32_t i  = 0; i < sizeof(res)/sizeof(res[0]); i++) {
        printf("%d, ", res[i]);
    }
    return;
}


void checkFclose(void) {
    int res[5];
    for (int ii = 0; ii < N_RERUNS; ii++) {
        // argnull
        res[0] = fclose(NULL);
        // notpreviously
        FILE not_previously;
        res[1] = fclose(&not_previously);
        // already
        FILE *fid = fopen("error_checking.txt", "w+");
        fprintf(fid, "noice!");
        res[2] = fclose(fid);
        res[3] = fclose(fid);
        // fail - TODO
        fid = fopen("error_checking.txt", "r");
        res[4] = fclose(fid);
        //
    }

    printf("\nCheckFclose:\n");
    for (uint32_t i  = 0; i < sizeof(res)/sizeof(res[0]); i++) {
        printf("%d, ", res[i]);
    }
    return;
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

