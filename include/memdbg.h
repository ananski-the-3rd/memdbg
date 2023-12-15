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
#include <stdbool.h>
#include "memdbg_export.h"

//----------------PUBLIC UTILS----------------//
// These tools can help you play with the memdbg mode at runtime

MEMDBG_EXPORT typedef unsigned int memdbg_mode_t;

MEMDBG_EXPORT void memdbg_Init(memdbg_mode_t mode);
MEMDBG_EXPORT memdbg_mode_t memdbg_modeGet(void);
MEMDBG_EXPORT memdbg_mode_t memdbg_modeSet(memdbg_mode_t new_mode);
MEMDBG_EXPORT bool memdbg_optionCheck(memdbg_mode_t option_code);
MEMDBG_EXPORT memdbg_mode_t memdbg_optionOn(memdbg_mode_t option_code);
MEMDBG_EXPORT memdbg_mode_t memdbg_optionOff(memdbg_mode_t option_code);
MEMDBG_EXPORT memdbg_mode_t memdbg_optionToggle(memdbg_mode_t option_code);

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
// things that start with '_' should not be called directly from outside memdbg


typedef enum _memdbg_func_enum_t {
    _MEMDBG_MALLOC_ID, _MEMDBG_CALLOC_ID, _MEMDBG_REALLOC_ID, _MEMDBG_FREE_ID,
    _MEMDBG_FOPEN_ID, _MEMDBG_FOPEN_S_ID, _MEMDBG_FCLOSE_ID, _MEMDBG_INTERNAL_ID, _MEMDBG_N_FUNC_TYPES
} _memdbg_func_enum_t;

typedef struct _memdbg_info_t {
    char *file;   // __FILE__
    char *func;   // __func__
    int line;     // __LINE__
    _memdbg_func_enum_t caller_id;
} _memdbg_info_t;

#define _MEMDBG_INFO_INITIALIZER(id)                     \
    (const _memdbg_info_t) {                             \
        .file = (char *)_memdbg_shortFileName(__FILE__), \
        .line = __LINE__,                                \
        .func = (char *)__func__,                        \
        .caller_id = id                                  \
    }

MEMDBG_EXPORT const char *_memdbg_shortFileName(const char *_file);
#define malloc(sz) _memdbg_malloc(sz, _MEMDBG_INFO_INITIALIZER(_MEMDBG_MALLOC_ID))
#define calloc(n, sz) _memdbg_calloc((n) * (sz), _MEMDBG_INFO_INITIALIZER(_MEMDBG_CALLOC_ID))
#define realloc(p, sz) _memdbg_realloc(p, sz, _MEMDBG_INFO_INITIALIZER(_MEMDBG_REALLOC_ID))
#define free(p) _memdbg_free(p, _MEMDBG_INFO_INITIALIZER(_MEMDBG_FREE_ID))
#define fopen(fn, m) _memdbg_fopen(fn, m, _MEMDBG_INFO_INITIALIZER(_MEMDBG_FOPEN_ID))
#define fopen_s(fid, fn, m) _memdbg_fopen_s(fid, fn, m, _MEMDBG_INFO_INITIALIZER(_MEMDBG_FOPEN_S_ID))
#define fclose(p) _memdbg_fclose(p, _MEMDBG_INFO_INITIALIZER(_MEMDBG_FCLOSE_ID))

MEMDBG_EXPORT void *_memdbg_malloc(size_t sz, const _memdbg_info_t info);
MEMDBG_EXPORT void *_memdbg_calloc(size_t sz, const _memdbg_info_t info);
MEMDBG_EXPORT void *_memdbg_realloc(void *ptr, size_t sz, const _memdbg_info_t info);
MEMDBG_EXPORT void _memdbg_free(void *ptr, const _memdbg_info_t info);
MEMDBG_EXPORT FILE *_memdbg_fopen(const char *path, const char *mode, const _memdbg_info_t info);
MEMDBG_EXPORT errno_t _memdbg_fopen_s(FILE **stream, const char *path, const char *mode, const _memdbg_info_t info);
MEMDBG_EXPORT int _memdbg_fclose(FILE *stream, const _memdbg_info_t info);

#endif
