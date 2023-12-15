#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include <pthread.h>
#include <unistd.h>
#include "../include/memdbg.h"

#ifdef __GNUC__
#define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#define UNUSED_FUNCTION(x) __attribute__((__unused__)) UNUSED_ ## x
#else
#define UNUSED(x) UNUSED_ ## x
#define UNUSED_FUNCTION(x) UNUSED_ ## x
#endif

void *checkMalloc(void *);
void *checkCalloc(void *);
void *checkRealloc(void *);
void *checkFree(void *);
void *checkFopen(void *);
void *checkFopens(void *);
void *checkFclose(void *);

uint32_t trueRand(void);
static inline int randi(void);
static uint32_t seed;
static pthread_cond_t gates_open = 0;
static pthread_mutex_t gate_mx, print_mx;
static uint32_t dogs_counter = 0;
#define N_TESTS 7
#define N_RERUNS 100

int main(void) {
    void *(*all_checks[N_TESTS])(void *) = {checkMalloc,
                                     checkCalloc,
                                     checkRealloc,
                                     checkFree,
                                     checkFopen,
                                     checkFopens,
                                     checkFclose};

    pthread_t threads[N_TESTS];
    
    pthread_mutex_init(&gate_mx, NULL);
    pthread_mutex_init(&print_mx, NULL);
    pthread_cond_init(&gates_open, NULL);
    
    for (uint32_t i = 0; i < N_TESTS; i++) {
        if(pthread_create(threads+i, NULL, all_checks[i], NULL)) {
            printf("Could not create thread");
            exit(EXIT_FAILURE);
        }
    }

    while (dogs_counter != 7) {
        usleep(1000);
    }

    pthread_cond_broadcast(&gates_open);

    for (uint32_t i = 0; i < N_TESTS; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            perror("Could not join thread");
        }
    }
    pthread_mutex_destroy(&gate_mx);
    pthread_cond_destroy(&gates_open);

    return 0;
}

void *checkMalloc(void *UNUSED(unused)) {
    pthread_mutex_lock(&gate_mx);
    dogs_counter++;
    pthread_cond_wait(&gates_open, &gate_mx);
    pthread_mutex_unlock(&gate_mx);

    void *ptrs[2];
    for (int ii = 0; ii < N_RERUNS; ii++) {
        // allocsize0
        ptrs[0] = malloc(0);
        // allocnull
        ptrs[1] = malloc(INT64_MAX);
    }

    pthread_mutex_lock(&print_mx);
    printf("\nCheckMalloc:\n");
    for (uint32_t i  = 0; i < sizeof(ptrs)/sizeof(ptrs[0]); i++) {
        printf("%p, ", ptrs[i]);
    }
    pthread_mutex_unlock(&print_mx);
    return NULL;
}


void *checkCalloc(void *UNUSED(unused)) {
    pthread_mutex_lock(&gate_mx);
    dogs_counter++;
    pthread_cond_wait(&gates_open, &gate_mx);
    pthread_mutex_unlock(&gate_mx);

    void *ptrs[2];
    for (int ii = 0; ii < N_RERUNS; ii++) { 
        // allocsize0
        ptrs[0] = calloc(0, 0);
        // allocnull
        ptrs[1] = calloc(INT64_MAX, 1);
        //
    }

    pthread_mutex_lock(&print_mx);
    printf("\nCheckCalloc:\n");
    for (uint32_t i  = 0; i < sizeof(ptrs)/sizeof(ptrs[0]); i++) {
        printf("%p, ", ptrs[i]);
    }
    pthread_mutex_unlock(&print_mx);
    return NULL;
}


void *checkRealloc(void *UNUSED(unused)) {
    pthread_mutex_lock(&gate_mx);
    dogs_counter++;
    pthread_cond_wait(&gates_open, &gate_mx);
    pthread_mutex_unlock(&gate_mx);
    
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
    pthread_mutex_lock(&print_mx);
    printf("\nCheckRealloc:\n");
    for (uint32_t i  = 0; i < sizeof(ptrs)/sizeof(ptrs[0]); i++) {
        printf("%p, ", ptrs[i]);
    }
    pthread_mutex_unlock(&print_mx);
    return NULL;
}


void *checkFree(void *UNUSED(unused)) {
    pthread_mutex_lock(&gate_mx);
    dogs_counter++;
    pthread_cond_wait(&gates_open, &gate_mx);
    pthread_mutex_unlock(&gate_mx);

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
    return NULL;
}


void *checkFopen(void *UNUSED(unused)) {
    pthread_mutex_lock(&gate_mx);
    dogs_counter++;
    pthread_cond_wait(&gates_open, &gate_mx);
    pthread_mutex_unlock(&gate_mx);

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
    pthread_mutex_lock(&print_mx);
    printf("\nCheckFopen:\n");
    for (uint32_t i  = 0; i < sizeof(fids)/sizeof(fids[0]); i++) {
        printf("%p, ", (void *)fids[i]);
    }
    pthread_mutex_unlock(&print_mx);
    return NULL;
}


void *checkFopens(void *UNUSED(unused)) {
    pthread_mutex_lock(&gate_mx);
    dogs_counter++;
    pthread_cond_wait(&gates_open, &gate_mx);
    pthread_mutex_unlock(&gate_mx);
    
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

    pthread_mutex_lock(&print_mx);
    printf("\nCheckFopens:\n");
    for (uint32_t i  = 0; i < sizeof(res)/sizeof(res[0]); i++) {
        printf("%d, ", res[i]);
    }
    pthread_mutex_unlock(&print_mx);
    return NULL;
}


void *checkFclose(void *UNUSED(unused)) {
    pthread_mutex_lock(&gate_mx);
    dogs_counter++;
    pthread_cond_wait(&gates_open, &gate_mx);
    pthread_mutex_unlock(&gate_mx);

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

    pthread_mutex_lock(&print_mx);
    printf("\nCheckFclose:\n");
    for (uint32_t i  = 0; i < sizeof(res)/sizeof(res[0]); i++) {
        printf("%d, ", res[i]);
    }
    pthread_mutex_unlock(&print_mx);
    return NULL;
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

