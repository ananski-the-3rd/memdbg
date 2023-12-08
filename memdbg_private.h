#pragma once
#ifdef MEMDBG_ENABLED

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include "memdbg.h"


//----------------NORMAL MACROS----------------//

#define INT_NULL (uintptr_t)NULL

#define MEMDBG_OVERALLOC_AMOUNT_BYTES (4 * sizeof(intptr_t))
#define MEMDBG_OVERALLOC_FILL_VALUE UINT8_C(0x48)

#define MEMDBG_MAP_SIZE (((MEMDBG_EXPECTED_N_ALLOCS - (MEMDBG_EXPECTED_N_ALLOCS % 60) + 23) * 13) / 10) // size tends to be prime this way
#define MEMDBG_MAPTEX_SIZE (((MEMDBG_EXPECTED_N_ALLOCS + 3) * 13) / 10)
#define MEMDBG_MSG_SIZE 1024

#define N_COLUMNS_IN_ERROR_FILE 7

#ifdef __GNUC__
#define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#define UNUSED(x) UNUSED_ ## x
#endif

//----------------THREADS API----------------//

#if defined(_WIN32) && !defined(__MINGW32__)
    #include <windows.h>
    #define MEMDBG_USE_WINAPI
    int win32_clock_gettime(int UNUSED(unused), struct timespec *ts);
    #define clock_gettime win32_clock_gettime

    typedef HANDLE memdbg_thread_t;
    typedef DWORD memdbg_thread_return_t;
    typedef LPVOID memdbg_thread_arg_t;
    #define MEMDBG_THREAD_CREATE(th, routine)                          \
        do {                                                            \
            th = CreateThread(NULL, 0, routine, (LPVOID)NULL, 0, NULL); \
            if (th == NULL) _memdbg_Panik("Could not create thread!");  \
        } while (0)
    #define MEMDBG_THREAD_JOIN(th)                      \
        do {                                             \
            if (WaitForSingleObject(th, 10000))          \
                _memdbg_Panik("Could not join thread!"); \
        } while (0)
    #define MEMDBG_THREAD_EXIT(p_err_code) ExitThread((DWORD)(*(p_err_code)))

    typedef HANDLE memdbg_mutex_t;
    #define MEMDBG_MUTEX_INITIALIZER NULL
    #define MEMDBG_MUTEX_INIT(mutex) do {mutex = CreateMutex(NULL, FALSE, NULL);} while (0)
    #define MEMDBG_MUTEX_LOCK(mutex)  WaitForSingleObject(mutex, INFINITE)
    #define MEMDBG_MAPTEX_INIT(maptex)                                  \
        do {                                                         \
            for (uint32_t i = 0; i < MEMDBG_MAPTEX_SIZE; i++) { \
                maptex[i] = CreateMutex(NULL, FALSE, NULL);          \
            }                                                        \
        } while (0)

    #define MEMDBG_MUTEX_UNLOCK(mutex) ReleaseMutex(mutex)

    #define MEMDBG_SLEEP(ms) Sleep(ms)
#else  // PTHREADS or WINPTHREADS
    #include <pthread.h>
    #include <unistd.h>
    #define MEMDBG_USE_PTHREADS
    typedef pthread_t memdbg_thread_t;
    typedef void * memdbg_thread_return_t;
    typedef void * memdbg_thread_arg_t;
    #define MEMDBG_THREAD_CREATE(th, routine)             \
        do {                                               \
            if (pthread_create(&th, NULL, &routine, NULL)) \
                _memdbg_Panik("Could not create thread!"); \
        } while (0)
    #define MEMDBG_THREAD_JOIN(th)                      \
        do {                                             \
            if (pthread_join(th, NULL))                  \
                _memdbg_Panik("Could not join thread!"); \
        } while (0)
    
    #define MEMDBG_THREAD_EXIT(p_err_code) pthread_exit(p_err_code)

    typedef pthread_mutex_t memdbg_mutex_t;
    #define MEMDBG_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
    #define MEMDBG_MUTEX_INIT(mutex) pthread_mutex_init(&mutex, NULL)
    #define MEMDBG_MAPTEX_INIT(maptex)                                    \
        do {                                                               \
            for (uint32_t i = 0; i < MEMDBG_MAPTEX_SIZE; i++) {       \
                pthread_mutexattr_t attr;                                  \
                pthread_mutexattr_init(&attr);                             \
                pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE); \
                pthread_mutex_init(&maptex[i], &attr);                     \
            }                                                              \
        } while (0)

    #define MEMDBG_MUTEX_LOCK(mutex) pthread_mutex_lock(&mutex)
    #define MEMDBG_MUTEX_UNLOCK(mutex) pthread_mutex_unlock(&mutex)

    #define MEMDBG_SLEEP(ms) usleep(1000*ms)
#endif
#define MEMDBG_MAPTEX_LOCK(idx) MEMDBG_MUTEX_LOCK(memdbg_maptex[(idx) % (MEMDBG_MAPTEX_SIZE)])
#define MEMDBG_MAPTEX_UNLOCK(idx) MEMDBG_MUTEX_UNLOCK(memdbg_maptex[(idx) % (MEMDBG_MAPTEX_SIZE)])

//----------------HASH-MAP TYPEDEFS----------------//

typedef enum memdbg_func_enum_t {MALLOC_IDX, CALLOC_IDX, REALLOC_IDX, FREE_IDX, FOPEN_IDX, FOPEN_S_IDX, FCLOSE_IDX, INTERNAL_IDX, N_FUNC_TYPES} memdbg_func_enum_t;

// item.key === (uintptr_t)item.m.ptr === (uintptr_t)item.f.stream
typedef struct memdbg_item_t {
    memdbg_func_enum_t func_idx[2];
    const char *_file[2];  // __FILE__
    int _line[2];          // __LINE__
    const char *_func[2];  // __func__

    union {
        struct {                // Memory Stuff
            const void *ptr;    // hash key

            uintptr_t sz;       // allocation size
            const void *next;   // output of realloc

            uint8_t is_freed;
            uint8_t is_overallocd;
            uint8_t is_overflowd;
        } m;

        struct memdbg_files_t { // File Stuff
            FILE *stream;       // hash key

            const char *path;   // file path for fopen
            const char *mode;   // open-mode for fopen

            uint8_t is_closed;
        } f;

        struct {                // Generic Stuff
            uintptr_t key;      // hash key

            uintptr_t extra[2];

            uint8_t is_done;
        };
    };
} memdbg_item_t;

typedef struct memdbg_bucket_t {
    memdbg_item_t *items;
    uint16_t n_items;
    uint16_t n_items_allocd;
} memdbg_bucket_t;

typedef struct memdbg_map_t{
    memdbg_bucket_t *buckets;
    uint16_t n_buckets;
    uint16_t n_buckets_allocd;
} memdbg_map_t;

// STRUCTURE OF THE HASH-MAP:
//       hash
// [map] --> [bucket] --> [item][item][item]
// [map]     [bucket] --> [item]
// [map]     [bucket] --> [item][item]
// [map]
// [map] --> [bucket] --> [item][item][item][item]
// [map]
// 
// This structure uses a combination of chaining and linear probing. An item will always be found at index = hash(item.key). 
// Efficiency compared to other structures is yet to be tested.

//----------------MISCELLANEOUS TYPEDEFS----------------//

typedef enum memdbg_files_enum_t {ERROR_FILE, REPORT_FILE, N_OUTPUT_FILES} memdbg_files_enum_t;

//----------------PRIVATE UTILS----------------//

void _memdbg_fileOpen(memdbg_files_enum_t fid_idx, const char *mode);
void _memdbg_fileClose(memdbg_files_enum_t fid_idx);
uint32_t _memdbg_getTimeStamp(char *timestamp, uint32_t sz);

//----------------CHECKING FOR THESE ERRORS----------------//

bool _memdbg_checkAllocNull(void *alloc_result, size_t sz, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx);
bool _memdbg_checkAllocSize0(size_t sz, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx);
bool _memdbg_checkNotPreviously(uint16_t n_matches, void *ptr, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx);
bool _memdbg_checkAlready(const memdbg_item_t *item, void *ptr, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx);
bool _memdbg_checkFail(int res, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx);
bool _memdbg_checkArgNull(uint32_t n_arg, const void *stream, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx);
bool _memdbg_checkBufferOverflow(memdbg_item_t *item, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx);
memdbg_thread_return_t _memdbg_threadFunc(memdbg_thread_arg_t UNUSED(unused));
bool _memdbg_checkNotDone(const memdbg_item_t *item, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx);

//----------------HASH-MAP IMPLEMENTATION----------------//

uint32_t _memdbg_hashFunc(uintptr_t key);
memdbg_item_t _memdbg_itemInit(uintptr_t key, uintptr_t extra[2], bool is_overallocd, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx);
void _memdbg_itemFill(memdbg_item_t *item, uintptr_t key, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx);
memdbg_bucket_t *_memdbg_bucketCreate(uint32_t idx);
memdbg_bucket_t *_memdbg_itemLookup(uintptr_t key);
void _memdbg_itemInsert(const memdbg_item_t item);

//----------------LOGGING FUNCTIONS----------------//

void _memdbg_errorLog(const char *msg);
void _memdbg_itemLog(const memdbg_item_t item);

//----------------CLEANUP----------------//

void _memdbg_Cleanup(void);
void _memdbg_Panik(const char *msg);

#endif