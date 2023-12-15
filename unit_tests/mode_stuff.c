#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include "../include/memdbg.h"

uint32_t trueRand(void);

int main(void) {
    memdbg_mode_t mode;
    mode = trueRand() >> 28;


    memdbg_Init(mode);

    mode = memdbg_modeGet(); printf("%u, ", mode);
    mode = memdbg_modeSet(mode &(~MEMDBG_OPTIONS_PRINT_ALL)); printf("%u, ", mode);
    mode = memdbg_optionToggle(MEMDBG_OPTIONS_PRINT_ALL); printf("%u, ", mode);
    mode = memdbg_optionToggle(MEMDBG_OPTIONS_PRINT_ALL); printf("%u, ", mode);
    mode = memdbg_optionOff(MEMDBG_OPTIONS_MULTIPLE_ERRORS); printf("%u, ", mode);
    mode = memdbg_optionOn(MEMDBG_OPTIONS_PRINT_ALL); printf("%u, ", mode);
    if (memdbg_optionCheck(MEMDBG_OPTIONS_THREADS)) {
        mode = memdbg_optionOn(MEMDBG_OPTIONS_THREADS); printf("%u, ", mode);
    }

    mode = memdbg_optionOff(MEMDBG_OPTIONS_MULTIPLE_ERRORS); printf("%u, ", mode);


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