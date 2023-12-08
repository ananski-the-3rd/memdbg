#pragma once
// memdbg is a tool for finding memory errors in c programs. Use it in 3 simple steps:
// 1. Include "memdbg.h" in your project. Its macros will override your memory-related calls with calls to memdbg functions
// A full list of overriden function is at the MEMORY FUNCTION OVERRIDES section of memdbg.h.
// 2. Add MEMDBG_ENABLED as a define
// 3. Compile/link your project with memdbg.c
// 
// For example (steps 2 and 3), with gcc:
// gcc -D MEMDBG_ENABLED memdbg.c ... (the rest of your args) 
// 
// NOTE: Make sure "memdbg.h" is included after stdio.h and stdlib.h.
//
// Outputs memdbg_error_log.csv and memdbg_full_report.csv.


#ifdef MEMDBG_ENABLED
#include <stdio.h> // contains size_t and FILE types, as well as fopen & co.
#include <stdlib.h> // contains malloc & co.

//----------------PUBLIC UTILS----------------//
// These tools can help you play with the memdbg mode at runtime

typedef unsigned int memdbg_mode_t;

void memdbg_Init(memdbg_mode_t mode);
memdbg_mode_t memdbg_modeGet(void);
memdbg_mode_t memdbg_modeSet(memdbg_mode_t new_mode);
bool memdbg_optionCheck(memdbg_mode_t option_code);
memdbg_mode_t memdbg_optionOn(memdbg_mode_t option_code);
memdbg_mode_t memdbg_optionOff(memdbg_mode_t option_code);
memdbg_mode_t memdbg_optionToggle(memdbg_mode_t option_code);

//----------------MEMDBG OPTIONS----------------//

// How many allocations and fopens do you expect to have?
#ifndef MEMDBG_EXPECTED_N_ALLOCS
#define MEMDBG_EXPECTED_N_ALLOCS 100u
#endif

// How many threads do you use?
#ifndef MEMDBG_EXPECTED_N_THREADS
#define MEMDBG_EXPECTED_N_THREADS 10u
#endif

// These options can be toggled at runtime. The "mode" of memdbg is the '|' of all options that are on.
#define MEMDBG_N_OPTIONS 4u
// By default, all options are on
#define MEMDBG_DEFAULT_MODE ((1u << MEMDBG_N_OPTIONS) - 1u)

// memdbg will attempt to correct any errors it finds, such that more than one error may be reported per run. Recommended for larger projects.
#ifndef MEMDBG_OPTIONS_MULTIPLE_ERRORS
#define MEMDBG_OPTIONS_MULTIPLE_ERRORS 0b00000001u
#endif

// memdbg will over-allocate all allocations. This is required for finding potential buffer overflows. May be memory intensive.
#ifndef MEMDBG_OPTIONS_OVERALLOC
#define MEMDBG_OPTIONS_OVERALLOC 0b00000010u
#endif

// memdbg will report *every call* to the memory functions in a separate log. Errors will be reported as usual in an error log. Recommended for smaller projects.
#ifndef MEMDBG_OPTIONS_PRINT_ALL
#define MEMDBG_OPTIONS_PRINT_ALL 0b00000100u
#endif

// memdbg will be thread safe.
#ifndef MEMDBG_OPTIONS_THREADS
#define MEMDBG_OPTIONS_THREADS 0b00001000u
#endif

//----------------MEMORY FUNCTION OVERRIDES----------------//
// Functions that start with '_' should not be called directly from outside memdbg

const char *_memdbg_shortFileName(const char *_file);
#define malloc(sz) _memdbg_malloc(sz, _memdbg_shortFileName(__FILE__), __LINE__, __func__)
#define calloc(n, sz) _memdbg_calloc((n) * (sz), _memdbg_shortFileName(__FILE__), __LINE__, __func__)
#define realloc(p, sz) _memdbg_realloc(p, sz, _memdbg_shortFileName(__FILE__), __LINE__, __func__)
#define free(p) _memdbg_free(p, _memdbg_shortFileName(__FILE__), __LINE__, __func__)
#define fopen(fn, m) _memdbg_fopen(fn, m, _memdbg_shortFileName(__FILE__), __LINE__, __func__)
#define fopen_s(fid, fn, m) _memdbg_fopen_s(fid, fn, m, _memdbg_shortFileName(__FILE__), __LINE__, __func__)
#define fclose(p) _memdbg_fclose(p, _memdbg_shortFileName(__FILE__), __LINE__, __func__)

void *_memdbg_malloc(size_t sz, const char *_file, const int _line, const char *_func);
void *_memdbg_calloc(size_t sz, const char *_file, const int _line, const char *_func);
void *_memdbg_realloc(void *ptr, size_t sz, const char *_file, const int _line, const char *_func);
void _memdbg_free(void *ptr, const char *_file, const int _line, const char *_func);
FILE *_memdbg_fopen(const char *path, const char *mode, const char *_file, const int _line, const char *_func);
errno_t _memdbg_fopen_s(FILE **stream, const char *path, const char *mode, const char *_file, const int _line, const char *_func);
int _memdbg_fclose(FILE *stream, const char *_file, const int _line, const char *_func);

#endif