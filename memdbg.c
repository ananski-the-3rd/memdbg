#include "memdbg_private.h"

#ifdef MEMDBG_ENABLED

static const char *FUNC_NAME_TABLE[N_FUNC_TYPES] = {"malloc", "calloc", "realloc", "free", "fopen", "fopen_s", "fclose", "MEMDBG"};
static const char *FILE_PATHS[N_OUTPUT_FILES] = {
    [ERROR_FILE] = "memdbg_error_log.csv",
    [REPORT_FILE] = "memdbg_full_report.csv"
};

static memdbg_mode_t memdbg_mode = 0;

static memdbg_map_t memdbg_map[MEMDBG_MAP_SIZE] = {0};

static FILE *memdbg_fid[N_OUTPUT_FILES] = {NULL, NULL};

static memdbg_mutex_t memdbg_maptex[MEMDBG_MAPTEX_SIZE]; // to be locked right before the first reference to an item in memdbg_map
static memdbg_mutex_t memdbg_mode_mutex;

//----------------MEMORY FUNCTION OVERRIDES----------------//

void *_memdbg_malloc(size_t sz, const char *_file, const int _line, const char *_func) {
    memdbg_Init(MEMDBG_DEFAULT_MODE); // only done once
    memdbg_func_enum_t func_idx = MALLOC_IDX;
    
    _memdbg_checkAllocSize0(sz, _file, _line, _func, func_idx);
    
    // Overallocate on both sides if the option is on
    size_t overalloc_total = 2 * MEMDBG_OVERALLOC_AMOUNT_BYTES * memdbg_optionCheck(MEMDBG_OPTIONS_OVERALLOC);
    void *res = (malloc)(sz + overalloc_total);
    
    if (_memdbg_checkAllocNull(res, sz, _file, _line, _func, func_idx)) {
        return NULL;
    }

    memdbg_item_t item = _memdbg_itemInit((uintptr_t)res, (uintptr_t[]){(uintptr_t)sz, INT_NULL}, !!overalloc_total,
                                          _file, _line, _func, func_idx);
    _memdbg_itemInsert(item);
    _memdbg_itemLog(item);

    return (void *)item.m.ptr;
}

void *_memdbg_calloc(size_t sz, const char *_file, const int _line, const char *_func) {
    memdbg_Init(MEMDBG_DEFAULT_MODE); // only done once
    memdbg_func_enum_t func_idx = CALLOC_IDX;

    _memdbg_checkAllocSize0(sz, _file, _line, _func, func_idx);

    // Overallocate on both sides if the option is on
    size_t overalloc_total = 2 * MEMDBG_OVERALLOC_AMOUNT_BYTES * memdbg_optionCheck(MEMDBG_OPTIONS_OVERALLOC);
    void *res = (calloc)(1, sz + overalloc_total);
    
    if (_memdbg_checkAllocNull(res, sz, _file, _line, _func, func_idx)) {
        return NULL;
    }

    memdbg_item_t item = _memdbg_itemInit((uintptr_t)res, (uintptr_t[]){(uintptr_t)sz, INT_NULL}, !!overalloc_total,
                                          _file, _line, _func, func_idx);
    _memdbg_itemInsert(item);
    _memdbg_itemLog(item);

    return (void *)item.m.ptr;
}

void *_memdbg_realloc(void *ptr, size_t sz, const char *_file, const int _line, const char *_func) {
    memdbg_Init(MEMDBG_DEFAULT_MODE); // only done once
    memdbg_func_enum_t func_idx = REALLOC_IDX;

    // realloc is basically 'free()' + 'malloc()'. free_item should be the 2nd half of an existing item, and alloc_item the 1st half of a new item
    
    // Doing 'free()'
    memdbg_item_t empty_item = {0};
    memdbg_item_t *free_item = &empty_item;

    const uint32_t map_idx = _memdbg_hashFunc((uintptr_t)ptr);
    MEMDBG_MAPTEX_LOCK(map_idx);
    memdbg_bucket_t *bucket = _memdbg_itemLookup((uintptr_t)ptr);
    void *free_arg = ptr;

    if (bucket == NULL || _memdbg_checkNotPreviously(bucket->n_items, ptr, _file, _line, _func, func_idx)) {
        free_arg = NULL;  // If ptr was not previously allocated we NULL it to avoid crash (assuming MEMDBG_OPTIONS_MULTIPLE_ERRORS is on)
    } else {
        free_item = &bucket->items[bucket->n_items - 1];
        if (free_item->m.is_overallocd) {
            free_arg = (char *)free_arg - MEMDBG_OVERALLOC_AMOUNT_BYTES; // free what was originally allocd
        }
        if (_memdbg_checkAlready(free_item, ptr, _file, _line, _func, func_idx)) {
            free_item = &empty_item;
            free_arg = NULL;  // If ptr was already freed we NULL it to avoid crash (assuming MEMDBG_OPTIONS_MULTIPLE_ERRORS is on)
        } else {
            _memdbg_checkBufferOverflow(free_item, _file, _line, _func, func_idx);
        }
    }
    _memdbg_itemFill(free_item, (uintptr_t)ptr, _file, _line, _func, func_idx); 

    // Mixed stage - 'free()' + 'malloc()'
    _memdbg_checkAllocSize0(sz, _file, _line, _func, func_idx);

    // Overallocate on both sides if the option is on
    size_t overalloc_total = 2 * MEMDBG_OVERALLOC_AMOUNT_BYTES * memdbg_optionCheck(MEMDBG_OPTIONS_OVERALLOC);
    void *res = (realloc)(free_arg, sz + overalloc_total);
    
    if (_memdbg_checkAllocNull(res, sz, _file, _line, _func, func_idx)) {
        // If there is not enough memory, the old memory block is NOT FREED - so don't log item
        MEMDBG_MAPTEX_UNLOCK(map_idx);
        return NULL;
    }
    memdbg_item_t alloc_item = _memdbg_itemInit((uintptr_t)res, (uintptr_t[]){(uintptr_t)sz, INT_NULL}, !!overalloc_total,
                                                _file, _line, _func, func_idx);
    // Finish 'free()'
    free_item->m.next = alloc_item.m.ptr;
    _memdbg_itemLog(*free_item);

    MEMDBG_MAPTEX_UNLOCK(map_idx);

    // Finish 'malloc()'
    _memdbg_itemInsert(alloc_item); // Must be done last or it will leave free_item dangling
    
    return (void *)alloc_item.m.ptr;
}

void _memdbg_free(void *ptr, const char *_file, const int _line, const char *_func) {
    memdbg_Init(MEMDBG_DEFAULT_MODE); // only done once
    memdbg_func_enum_t func_idx = FREE_IDX;

    memdbg_item_t empty_item = {0};
    memdbg_item_t *item = &empty_item;

    const uint32_t map_idx = _memdbg_hashFunc((uintptr_t)ptr);
    MEMDBG_MAPTEX_LOCK(map_idx);
    memdbg_bucket_t *bucket = _memdbg_itemLookup((uintptr_t)ptr);
    void *free_arg = ptr;

    if (bucket == NULL || _memdbg_checkNotPreviously(bucket->n_items, ptr, _file, _line, _func, func_idx)) {
        free_arg = NULL;  // If ptr was not previously allocated we NULL it to avoid crash (assuming MEMDBG_OPTIONS_MULTIPLE_ERRORS is on)
    } else {
        item = &bucket->items[bucket->n_items - 1];
        if (item->m.is_overallocd) {
            free_arg = (char *)free_arg - MEMDBG_OVERALLOC_AMOUNT_BYTES; // free what was originally allocd
        }
        if (_memdbg_checkAlready(item, ptr, _file, _line, _func, func_idx)) {
            item = &empty_item;
            free_arg = NULL;  // If ptr was already freed we NULL it to avoid crash (assuming MEMDBG_OPTIONS_MULTIPLE_ERRORS is on)
        } else {
            _memdbg_checkBufferOverflow(item, _file, _line, _func, func_idx);
        }
    }
    
    _memdbg_itemFill(item, (uintptr_t)ptr, _file, _line, _func, func_idx); 

    (free)(free_arg);

    _memdbg_itemLog(*item);

    MEMDBG_MAPTEX_UNLOCK(map_idx);
    return;
}

FILE *_memdbg_fopen(const char *path, const char *mode, const char *_file, const int _line, const char *_func) {
    memdbg_Init(MEMDBG_DEFAULT_MODE); // only done once
    memdbg_func_enum_t func_idx = FOPEN_IDX;

    if (_memdbg_checkArgNull(0, path, _file, _line, _func, func_idx) ||
        _memdbg_checkArgNull(1, mode, _file, _line, _func, func_idx)) {
        return NULL;
    }
    
    FILE *fid = NULL;
    errno_t err = 0;

    err = (fopen_s)(&fid, path, mode);

    if (_memdbg_checkFail(err, _file, _line, _func, func_idx)) {
        return fid;
    }

    memdbg_item_t item = _memdbg_itemInit((uintptr_t)fid, (uintptr_t[]){(uintptr_t)path, (uintptr_t)mode}, false,
                                          _file, _line, _func, func_idx);
    _memdbg_itemInsert(item);
    _memdbg_itemLog(item);
    return fid;
}

errno_t _memdbg_fopen_s(FILE **stream, const char *path, const char *mode, const char *_file, const int _line, const char *_func) {
    memdbg_Init(MEMDBG_DEFAULT_MODE); // only done once
    memdbg_func_enum_t func_idx = FOPEN_S_IDX;

    if (_memdbg_checkArgNull(0, stream, _file, _line, _func, func_idx)  ||
        _memdbg_checkArgNull(1, path, _file, _line, _func, func_idx)    ||
        _memdbg_checkArgNull(2, mode, _file, _line, _func, func_idx)) {
        return EOF;
    }

    errno_t err = 0;
    
    err = (fopen_s)(stream, path, mode);
    
    if (_memdbg_checkFail(err, _file, _line, _func, func_idx)) {
        return err;
    }

    memdbg_item_t item = _memdbg_itemInit((uintptr_t)*stream, (uintptr_t[]){(uintptr_t)path, (uintptr_t)mode}, false,
                                          _file, _line, _func, func_idx);
    _memdbg_itemInsert(item);
    _memdbg_itemLog(item);
    return err;
}

int _memdbg_fclose(FILE *stream, const char *_file, const int _line, const char *_func) {
    memdbg_Init(MEMDBG_DEFAULT_MODE); // only done once
    memdbg_func_enum_t func_idx = FCLOSE_IDX;

    int res;

    if (_memdbg_checkArgNull(0, stream, _file, _line, _func, func_idx)) {
        return EOF;
    }

    const uint32_t map_idx = _memdbg_hashFunc((uintptr_t)stream);
    MEMDBG_MAPTEX_LOCK(map_idx);
    
    memdbg_bucket_t *bucket = _memdbg_itemLookup((uintptr_t)stream);

    if (_memdbg_checkNotPreviously(bucket->n_items, stream, _file, _line, _func, func_idx)) {
        MEMDBG_MAPTEX_UNLOCK(map_idx);
        return EOF;
    }

    memdbg_item_t *item = &bucket->items[bucket->n_items-1];
    if (_memdbg_checkAlready(item, stream, _file, _line, _func, func_idx)) {
        MEMDBG_MAPTEX_UNLOCK(map_idx);
        return EOF;
    }

    res = (fclose)(stream);

    if (_memdbg_checkFail(res, _file, _line, _func, func_idx)) {
        MEMDBG_MAPTEX_UNLOCK(map_idx);
        return EOF;
    }

    _memdbg_itemFill(item, (uintptr_t)stream, _file, _line, _func, func_idx);
    _memdbg_itemLog(*item);

    MEMDBG_MAPTEX_UNLOCK(map_idx);
    return res;
}

//----------------PUBLIC UTILS----------------//

/// @brief Initiates memdbg. You don't have to call this function (MEMDBG_DEFAULT_MODE will be used).
/// @param mode specifies the options that will be used throughout the runtime:
/// @note MEMDBG_OPTIONS_MULTIPLE_ERRORS - memdbg will attempt to correct any errors it finds, such that more than one error may be reported per run. Recommended for larger projects.
/// @note MEMDBG_OPTIONS_OVERALLOC - memdbg will over-allocate all allocations. This is required for finding potential buffer overflows. May be memory intensive.
/// @note MEMDBG_OPTIONS_PRINT_ALL - memdbg will report *every call* to the memory functions in a separate log. Errors will be reported as usual in an error log. Recommended for smaller projects.
/// @note MEMDBG_OPTIONS_THREADS - memdbg will be thread safe.
void memdbg_Init(memdbg_mode_t mode) {
    static volatile bool memdbg_init_is_done = false;
    if (memdbg_init_is_done) return;

    // workaround for static init
    {
        static atomic_flag temp = ATOMIC_FLAG_INIT;
        while (atomic_flag_test_and_set(&temp)) {
            if (memdbg_init_is_done) return;
            MEMDBG_SLEEP(1);
        }
    }

    MEMDBG_MAPTEX_INIT(memdbg_maptex);
    MEMDBG_MUTEX_INIT(memdbg_mode_mutex);

    // Reset output files:
    _memdbg_fileOpen(ERROR_FILE, "w");
    if (fputs("TIMESTAMP,FILE,LINE,FUNCTION,DETECTED_AT,CAUSE,FIX\n", memdbg_fid[ERROR_FILE])) {
        _memdbg_Panik("Could not write to error log!");
    }

    _memdbg_fileOpen(REPORT_FILE, "w");
    if (fputs("TIMESTAMP,FILE,LINE,FUNCTION,EVENT\n", memdbg_fid[REPORT_FILE])) {
        _memdbg_Panik("Could not write to report log!");
    }
    _memdbg_fileClose(REPORT_FILE);

    memdbg_modeSet(mode);

    if (atexit(_memdbg_Cleanup)) {
        _memdbg_Panik("Failed to register cleanup at exit.");
    }

    memdbg_init_is_done = true;

    return;
}

/// @brief returns the current memdbg mode code
memdbg_mode_t memdbg_modeGet(void) {
    return (memdbg_mode);
}

/// @brief Sets memdbg mode to new_mode and handles option callbacks
/// @param new_mode the new memdbg mode code
/// @return new_mode
memdbg_mode_t memdbg_modeSet(memdbg_mode_t new_mode) {
    static memdbg_thread_t memdbg_check_buffers;
    
    bool use_mutex = new_mode & MEMDBG_OPTIONS_THREADS;
    if (use_mutex) MEMDBG_MUTEX_LOCK(memdbg_mode_mutex);

    // set the mode
    memdbg_mode_t temp = memdbg_mode;
    memdbg_mode = new_mode;

    // "Callbacks" for changing the mode
    if (!(temp & MEMDBG_OPTIONS_PRINT_ALL) && (memdbg_mode & MEMDBG_OPTIONS_PRINT_ALL)) {
        _memdbg_fileOpen(REPORT_FILE, "a+");
    } else if (!(memdbg_mode & MEMDBG_OPTIONS_PRINT_ALL) && (temp & MEMDBG_OPTIONS_PRINT_ALL)) {
        _memdbg_fileClose(REPORT_FILE);
    }

    if (!(temp & MEMDBG_OPTIONS_OVERALLOC) && (memdbg_mode & MEMDBG_OPTIONS_OVERALLOC)) {  // turned on overalloc
        MEMDBG_THREAD_CREATE(memdbg_check_buffers, _memdbg_threadFunc);
    } else if (!(memdbg_mode & MEMDBG_OPTIONS_OVERALLOC) && (temp & MEMDBG_OPTIONS_OVERALLOC)) {  // turned off overalloc
        MEMDBG_THREAD_JOIN(memdbg_check_buffers);
    }

    if (use_mutex) MEMDBG_MUTEX_UNLOCK(memdbg_mode_mutex);
    
    return memdbg_mode;
}

/// @brief true if the option is on, false if off.
bool memdbg_optionCheck(memdbg_mode_t option_code) {
    return (memdbg_mode & option_code);
}

/// @brief Activates the option supplied by OPTION_CODE
/// @param option_code a memdbg macro specifiyng an option
/// @return the new memdbg mode code, with the option activated
/// @note if the option is already activated - nothing changes.
memdbg_mode_t memdbg_optionOn(memdbg_mode_t option_code) {
    return memdbg_modeSet(memdbg_mode | option_code);
}

/// @brief Dectivates the option supplied by OPTION_CODE
/// @param option_code a memdbg macro specifiyng an option
/// @return the new memdbg mode code, with the option deactivated
/// @note if the option is already deactivated - nothing changes.
memdbg_mode_t memdbg_optionOff(memdbg_mode_t option_code) {
    return memdbg_modeSet(memdbg_mode & ~option_code);
}

/// @brief Toggles the option supplied by OPTION_CODE
/// @param option_code a memdbg macro specifiyng an option
/// @return the new memdbg mode code, with the option toggled
/// @note if the option is activated - deactivates it (and vice versa).
memdbg_mode_t memdbg_optionToggle(memdbg_mode_t option_code) {
    return memdbg_modeSet(memdbg_mode ^ option_code);
}

//----------------PRIVATE UTILS----------------//

/// @brief turns an absolute path to a short path indicating the file name and the parent dir
/// @param _file __FILE__ macro from the original call
/// @return a pointer just after the 2nd to last file separator in _file
/// @note /full/path/to/file.c -> to/file.c
const char *_memdbg_shortFileName(const char *_file) {
    static const char FILESEP =
    #ifdef _WIN32
        '\\';
    #else
        '/';
    #endif

    uint8_t n = 0;
    const char *p;
    for (p = _file + strlen(_file); p > _file; p--) {
        if (*p == FILESEP) n++;
        if (n == 2) {
            p++;
            break;
        };
    }

    return p;
}

/// @brief fopen with error checking
void _memdbg_fileOpen(memdbg_files_enum_t fid_idx, const char *mode) {

    int err;
    err = (fopen_s)(&memdbg_fid[fid_idx], FILE_PATHS[fid_idx], mode);
    if (err != 0 || memdbg_fid[fid_idx] == NULL) {
        char err_msg[MEMDBG_MSG_SIZE];
        sprintf_s(err_msg, MEMDBG_MSG_SIZE, "File could not be opened: %s", strerror(err));
        _memdbg_Panik(err_msg);
    }

    return;
}

/// @brief fclose with error checking
void _memdbg_fileClose(memdbg_files_enum_t fid_idx) {
    int err;
    if (memdbg_fid[fid_idx] == NULL) {
        return;
    }

    err = (fclose)(memdbg_fid[fid_idx]);
    memdbg_fid[fid_idx] = NULL;

    if (err != 0) {
        _memdbg_Panik("File could not be closed");
    }
    
    return;
}

/// @brief outputs the timestamp in 20/11/2023 21:30:38.805999600 format
/// @param sz should be 32.
/// @note TODO: implement for windows (non mingW)
uint32_t _memdbg_getTimeStamp(char *timestamp, uint32_t sz) {
    int len = 0;
    struct timespec ts;
    struct tm *tm_info;
    clock_gettime(CLOCK_REALTIME, &ts);
    tm_info = localtime(&ts.tv_sec);
    len += strftime(timestamp, sz, "%d/%m/%Y %H:%M:%S", tm_info);
    len += sprintf_s(timestamp + len, sz - len, ".%09ld", ts.tv_nsec);

    return len;
}

#ifdef MEMDBG_USE_WINAPI

int win32_clock_gettime(int UNUSED(unused), struct timespec *ts) {
    static const uint64_t win2unix_time0 = 11644473600;
    static const uint64_t TEN_MILLION = 10000000;

    FILETIME ft;
    ULARGE_INTEGER temp;

    GetSystemTimePreciseAsFileTime(&ft);
    temp.HighPart = ft.dwHighDateTime;
    temp.LowPart = ft.dwLowDateTime;
    temp.QuadPart -= win2unix_time0 * TEN_MILLION;

    ts->tv_sec = temp.QuadPart / TEN_MILLION;
    ts->tv_nsec = (temp.QuadPart % TEN_MILLION) * 100;
    return 0;
}

#endif

//----------------CHECKING FOR THESE ERRORS----------------//

/// @brief Checks if the output from the allocation function is NULL. Logs error to memdbg_error_log.csv.
/// @return true on error, false otherwise.
bool _memdbg_checkAllocNull(void *alloc_result, size_t sz, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx) {
    if (alloc_result != NULL) {
        return false;
    }

    char *msg = (malloc)(MEMDBG_MSG_SIZE);
    int len = _memdbg_getTimeStamp(msg, 32);
    sprintf_s(msg + len, MEMDBG_MSG_SIZE - len,
              ",%s,%d,%s,'%s',OS could not find a memory chunk of size %zu,"
              "Maybe some allocation is redundant\n",
              _file, _line, _func, FUNC_NAME_TABLE[func_idx], sz);
    _memdbg_errorLog(msg);
    (free)(msg);

    return true;
}

/// @brief Checks if an allocation of size 0 would occur. Logs error to memdbg_error_log.csv.
/// @return true on error, false otherwise.
bool _memdbg_checkAllocSize0(size_t sz, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx) {
    if (sz != 0) {
        return false;
    }

    char *msg = (malloc)(MEMDBG_MSG_SIZE);
    int len = _memdbg_getTimeStamp(msg, 32);
    sprintf_s(msg + len, MEMDBG_MSG_SIZE - len,
              ",%s,%d,%s,'%s',Requesting memory allocation of size 0,"
              "This is never good practice but not technically an error\n",
              _file, _line, _func, FUNC_NAME_TABLE[func_idx]);
    _memdbg_errorLog(msg);
    (free)(msg);

    return true;
}

/// @brief Checks if a pointer/stream that would be freed/closed was previously allocated/opened. Logs error to memdbg_error_log.csv.
/// @return true on error, false otherwise.
/// @note memdbg will try to circumvent this error for calls to free().
bool _memdbg_checkNotPreviously(uint16_t n_matches, void *ptr, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx) {
    if (n_matches != 0) {
        return false;
    }

    static const char *STR_TABLE[2][4] = {
        {"pointer", "allocat", "malloc", "allocate memory to"},
        {"filestream", "open", "fopen", "open"}
    };
    const char **help_str = STR_TABLE[(func_idx == FCLOSE_IDX)];

    char *msg = (malloc)(MEMDBG_MSG_SIZE);
    int len = _memdbg_getTimeStamp(msg, 32);
    sprintf_s(msg + len, MEMDBG_MSG_SIZE - len,
              ",%s,%d,%s,'%s',Input %s %p was not %sed by '%s' & co,"
              "Make sure to %s said %s or remove the call to '%s'\n",
              _file, _line, _func, FUNC_NAME_TABLE[func_idx],
              help_str[0], ptr, help_str[1], help_str[2],
              help_str[3], help_str[0], FUNC_NAME_TABLE[func_idx]);
    _memdbg_errorLog(msg);
    (free)(msg);

    return true;
}

/// @brief Checks if a pointer/stream that would be freed/closed has already been freed/closed. Logs error to memdbg_error_log.csv.
/// @return true on error, false otherwise.
/// @note memdbg will try to circumvent this error for calls to free().
bool _memdbg_checkAlready(const memdbg_item_t *item, void *ptr, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx) {
    if (!item->is_done) {
        return false;
    }

    char *help_str = (func_idx == FCLOSE_IDX) ? "close" : "free";
    char *msg = (malloc)(MEMDBG_MSG_SIZE);
    int len = _memdbg_getTimeStamp(msg, 32);
    sprintf_s(msg + len, MEMDBG_MSG_SIZE - len,
              ",%s,%d,%s,'%s',%p was already %sd by '%s',"
              "Remove this call or the other at: %s; %d; %s\n",
              _file, _line, _func, FUNC_NAME_TABLE[func_idx],
              ptr, help_str, FUNC_NAME_TABLE[item->func_idx[1]],
              item->_file[1], item->_line[1], item->_func[1]);
    _memdbg_errorLog(msg);
    (free)(msg);

    return true;
}

/// @brief Checks if fopen & co. failed. Logs error to memdbg_error_log.csv.
/// @return true on error, false otherwise.
bool _memdbg_checkFail(int res, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx) {
    if (res == 0) {
        return false;
    }
    char help_str[2][MEMDBG_MSG_SIZE];
    if (func_idx == FCLOSE_IDX) {
        sprintf_s(help_str[0], sizeof(help_str[0]), "File could not be closed");
        sprintf_s(help_str[1], sizeof(help_str[1]), "the file is not open in another process");
    } else {
        errno_t err = strerror_s(help_str[0], sizeof(help_str[0]), res);
        sprintf_s(help_str[1], sizeof(help_str[1]), "both the file path and open mode are valid");
        if (err) {
            _memdbg_Panik("Could not get error string from strerror!");
        }
    }

    char *msg = (malloc)(MEMDBG_MSG_SIZE);
    int len = _memdbg_getTimeStamp(msg, 32);
    sprintf_s(msg + len, MEMDBG_MSG_SIZE - len,
              ",%s,%d,%s,'%s',%s,"
              "Make sure %s\n",
              _file, _line, _func, FUNC_NAME_TABLE[func_idx], help_str[0], help_str[1]);
    _memdbg_errorLog(msg);
    (free)(msg);

    return true;
}

/// @brief checks if arg is NULL. Logs error to memdbg_error_log.csv.
/// @return true on error, false otherwise.
bool _memdbg_checkArgNull(uint32_t n_arg, const void *arg, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx) {
    if (arg != NULL) {
        return false;
    }

    static const char *STR_TABLE[3][4] = {
        {"const char *", "const char *", "\0",           "\0"}, // FOPEN_IDX
        {"FILE **",      "const char *", "const char *", "\0"}, // FOPEN_S_IDX
        {"FILE *",       "\0",           "\0",           "\0"}  // FCLOSE_IDX
    };
    const char *arg_type = STR_TABLE[func_idx - FOPEN_IDX][n_arg];

    if (*arg_type == '\0') {
        char error_msg[MEMDBG_MSG_SIZE];
        sprintf_s(error_msg, sizeof(error_msg), "%s: Function %s does not have # args!", __func__, FUNC_NAME_TABLE[func_idx], n_arg);
        _memdbg_Panik(error_msg);
    }

    char *msg = (malloc)(MEMDBG_MSG_SIZE);
    int len = _memdbg_getTimeStamp(msg, 32);
    sprintf_s(msg + len, MEMDBG_MSG_SIZE - len,
              ",%s,%d,%s,'%s',argument #%d == (%s)NULL,"
              "Check for NULL before calling '%s'\n",
              _file, _line, _func, FUNC_NAME_TABLE[func_idx], n_arg+1, arg_type, FUNC_NAME_TABLE[func_idx]);
    _memdbg_errorLog(msg);
    (free)(msg);

    return true;
}

/// @brief checks for possible buffer overflows or underflows. Logs error to memdbg_error_log.csv.
/// @return true on error, false otherwise.
/// @note A useful thing to do with a debugger is have a breakpoint on errors in this function, and then progress in your code line by line. You'll see when an overflow occured immediately.
bool _memdbg_checkBufferOverflow(memdbg_item_t *item, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx) {

    if (_line == 0 || // empty item
        item->m.is_freed ||
        !item->m.is_overallocd || // skips non-allocd items
        item->m.is_overflowd) {
        return false;
    }

    const char *p_mem;
    for (uint32_t i = MEMDBG_OVERALLOC_AMOUNT_BYTES; i > 0; i--) {
        p_mem = (const char *)item->m.ptr - i;
        // Check underflow
        if (*p_mem == MEMDBG_OVERALLOC_FILL_VALUE) {
            // Check overflow
            p_mem = (const char *)item->m.ptr + item->m.sz + i - 1;
            if (*p_mem == MEMDBG_OVERALLOC_FILL_VALUE) continue;
        }

        // Buffer (over/under)flow found!
        const char *help_str = (p_mem > (const char *)item->m.ptr)? "over": "under";
        
        char *msg = (malloc)(MEMDBG_MSG_SIZE);
        int len = _memdbg_getTimeStamp(msg, 32);
        sprintf_s(msg + len, MEMDBG_MSG_SIZE - len,
                  ",%s,%d,%s,'%s',Buffer %sflow of %lu bytes on pointer %p,"
                  "Check uses since original alloc of %lu bytes by '%s' at: %s; %d; %s\n",
                  _file, _line, _func, FUNC_NAME_TABLE[func_idx], help_str, i, item->m.ptr,
                  item->m.sz, FUNC_NAME_TABLE[item->func_idx[0]], item->_file[0], item->_line[0], item->_func[0]);
        _memdbg_errorLog(msg);
        (free)(msg);

        item->m.is_overflowd = true;
        break;
    }

    return item->m.is_overflowd;
}

/// @brief Runs _memdbg_checkBufferOverflow to detect these errors as they occur
memdbg_thread_return_t _memdbg_threadFunc(memdbg_thread_arg_t UNUSED(unused)) {
    const char *_file = _memdbg_shortFileName(__FILE__);
    uint32_t idx, i_bucket, i_item;
    memdbg_bucket_t *bucket;
    memdbg_item_t *item;
    while (memdbg_optionCheck(MEMDBG_OPTIONS_OVERALLOC)) {
        for (idx = 0; idx < MEMDBG_MAP_SIZE;
            MEMDBG_MAPTEX_UNLOCK(idx), idx++) {

            MEMDBG_MAPTEX_LOCK(idx);
            if (memdbg_map[idx].n_buckets == 0) continue;
            for (i_bucket = 0; i_bucket < memdbg_map[idx].n_buckets; i_bucket++) {
                bucket = &memdbg_map[idx].buckets[i_bucket];
                if (bucket->n_items == 0) continue;
                for (i_item = 0; i_item < bucket->n_items; i_item++) {
                    item = &bucket->items[i_item];
                    _memdbg_checkBufferOverflow(item, _file, __LINE__, __func__, INTERNAL_IDX);
                }
            }
            
        }
        MEMDBG_SLEEP(3);
    }

    return (memdbg_thread_return_t)0;
}

/// @brief Runs on cleanup, checks if a pointer/stream was freed/closed before runtime ended. Logs error to memdbg_error_log.csv.
/// @return true on error, false otherwise.
/// @note memdbg will try to circumvent this error for calls to free().
bool _memdbg_checkNotDone(const memdbg_item_t *item, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx) {
    if (item->is_done || item->_line[0] == 0) {
        return false;
    }

    static const char *STR_TABLE[2][2] = {
        {"close", "open"},
        {"free", "allocat"},
    };
    const char **help_str = STR_TABLE[(item->func_idx[0] < FOPEN_IDX)];

    char *msg = (malloc)(MEMDBG_MSG_SIZE);
    int len = _memdbg_getTimeStamp(msg, 32);
    sprintf_s(msg + len, MEMDBG_MSG_SIZE - len,
              ",%s,%d,%s,'%s',%p was not %sd properly,"
              "Make sure it is %sd after use (Originally %sed by '%s' at: %s; %d; %s)\n",
              _file, _line, _func, FUNC_NAME_TABLE[func_idx],
              item->key, help_str[0],
              help_str[0], help_str[1], FUNC_NAME_TABLE[item->func_idx[0]], item->_file[0], item->_line[0], item->_func[0]);
    _memdbg_errorLog(msg);
    (free)(msg);

    return true;
}

//----------------HASH-MAP IMPLEMENTATION----------------//

/// @brief Converts a key (an address treated as an integer) into an index into our hash map
uint32_t _memdbg_hashFunc(uintptr_t key) {
    return ((key - (key >> 2)) % MEMDBG_MAP_SIZE);
}

/// @brief Creates the first half of an item, for 'malloc' and 'fopen' etc.
memdbg_item_t _memdbg_itemInit(uintptr_t key, uintptr_t extra[2], bool is_overallocd, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx) {
    memdbg_item_t item = {0};

    item.func_idx[0] = func_idx;
    item._file[0] = _file;
    item._func[0] = _func;
    item.extra[0] = extra[0];
    item.extra[1] = extra[1];
    item._line[0] = _line;

    if (is_overallocd) {  // Correction for negative padding
        memset((char *)key, MEMDBG_OVERALLOC_FILL_VALUE, MEMDBG_OVERALLOC_AMOUNT_BYTES);
        key += MEMDBG_OVERALLOC_AMOUNT_BYTES;
        memset((char *)key + item.m.sz, MEMDBG_OVERALLOC_FILL_VALUE, MEMDBG_OVERALLOC_AMOUNT_BYTES);
        item.m.is_overallocd = true;
    }

    item.key = key;
    return item;
}

/// @brief Fills the missing fields of an item (excluding the extras), for 'free' and 'fclose' etc.
void _memdbg_itemFill(memdbg_item_t *item, uintptr_t key, const char *_file, const int _line, const char *_func, memdbg_func_enum_t func_idx) {
    
    if (item->is_done) return;

    if (item->key == INT_NULL || item->key == 0) {  // freeing null or sth that was not previously allocd
        item->key = key;
    } else if (key != INT_NULL && item->key != key) {
        _memdbg_Panik("Inconsistent _memdbg_itemInit and _memdbg_itemFill key values!");
    }

    item->func_idx[1] = func_idx;
    item->_file[1] = _file;
    item->_func[1] = _func;
    item->_line[1] = _line;
    item->is_done = true;
    
    return;
}

/// @brief Creates a new bucket at memdbg_map[idx].
memdbg_bucket_t *_memdbg_bucketCreate(uint32_t idx) {
    memdbg_bucket_t *bucket = NULL;
    
    if (memdbg_map[idx].n_buckets >= memdbg_map[idx].n_buckets_allocd) {
        uint16_t new_sz = (memdbg_map[idx].n_buckets_allocd * 3) / 2;
        memdbg_map[idx].buckets = (realloc)(memdbg_map[idx].buckets, new_sz * sizeof(memdbg_bucket_t));
        memdbg_bucket_t empty_bucket = {0};
        for (uint16_t i_bucket = memdbg_map[idx].n_buckets_allocd; i_bucket < new_sz; i_bucket++) {
            memdbg_map[idx].buckets[i_bucket] = empty_bucket;
        }
        memdbg_map[idx].n_buckets_allocd = new_sz;
    }

    bucket = &memdbg_map[idx].buckets[memdbg_map[idx].n_buckets];
    bucket->n_items = 0;
    bucket->n_items_allocd = 4;
    bucket->items = (calloc)(bucket->n_items_allocd, sizeof(memdbg_item_t));

    memdbg_map[idx].n_buckets++;

    return bucket;
}

/// @brief Looks in the hash table for the place hashed by key. If it's not there yet, allocate it.
/// @param key An address (cast to uintptr_t) is used here as a key
/// @return A pointer to where the item should be, or NULL if key is NULL.
memdbg_bucket_t *_memdbg_itemLookup(uintptr_t key) {
    if (key == INT_NULL || key == 0) {
        return NULL;
    }
    
    bool res = false;
    uint32_t idx = _memdbg_hashFunc(key); // hash

    MEMDBG_MAPTEX_LOCK(idx);

    memdbg_bucket_t *bucket = NULL;

    if (memdbg_map[idx].n_buckets_allocd == 0) {
        memdbg_map[idx].n_buckets = 0;
        memdbg_map[idx].n_buckets_allocd = 3;
        memdbg_map[idx].buckets = (calloc)(memdbg_map[idx].n_buckets_allocd, sizeof(memdbg_bucket_t));
        bucket = _memdbg_bucketCreate(idx);
        res = true;
    }

    for (uint32_t i_bucket = 0; i_bucket < memdbg_map[idx].n_buckets && !res; i_bucket++) {
        bucket = &memdbg_map[idx].buckets[i_bucket];
        
        // Not the right bucket
        if (bucket->items->key != key) continue;

        // Found the right bucket, return it.
        res = true;
    }

    if (!res) {
        // Create a new bucket and return it
        bucket = _memdbg_bucketCreate(idx);
    }

    MEMDBG_MAPTEX_UNLOCK(idx);

    return bucket;
}

/// @brief Copies the contents of item into the correct place in the hash map
void _memdbg_itemInsert(const memdbg_item_t item) {
    
    const uint32_t map_idx = _memdbg_hashFunc(item.key);
    MEMDBG_MAPTEX_LOCK(map_idx);

    memdbg_bucket_t *bucket = _memdbg_itemLookup(item.key);

    if (bucket->n_items >= bucket->n_items_allocd) {
        uint16_t new_sz = (bucket->n_items_allocd * 3) / 2;
        bucket->items = (realloc)(bucket->items, new_sz * sizeof(memdbg_item_t));
        memdbg_item_t empty_item = {0};
        for (uint16_t i_item = bucket->n_items_allocd; i_item < new_sz; i_item++) {
            bucket->items[i_item] = empty_item;
        }
        bucket->n_items_allocd = new_sz;
    }

    bucket->items[bucket->n_items++] = item;
    
    MEMDBG_MAPTEX_UNLOCK(map_idx);

    return;
}

//----------------LOGGING FUNCTIONS----------------//

/// @brief Write error messages to memdbg_error_log.txt
/// @param msg the message to be written (no extra formatting is done)
void _memdbg_errorLog(const char *msg) {

    // Check that the message is in the correct format
    uint8_t comma_count = 0;
    for (uint32_t i = 0; msg[i] != '\0'; i++) {
        if (msg[i] == ',') {
            comma_count++;
        }
    }
    if (comma_count != (N_COLUMNS_IN_ERROR_FILE - 1)) {
        _memdbg_Panik("Comma count in error message must fit the number of columns in the .csv file");
    }

    while (memdbg_fid[ERROR_FILE] == NULL) {
        MEMDBG_SLEEP(1000); // MEMDBG_OPTIONS_MULTIPLE_ERRORS is off and another thread is gonna panik
    }

    if (fputs(msg, memdbg_fid[ERROR_FILE])) {
        _memdbg_Panik("Could not write to error log!");
    }

    if (!memdbg_optionCheck(MEMDBG_OPTIONS_MULTIPLE_ERRORS)) {
        _memdbg_fileClose(ERROR_FILE);
        _memdbg_fileClose(REPORT_FILE);
        _memdbg_Panik("Exit on error found - check log file");
    }

    return;
}

/// @brief Log an item into "memdbg_full_report.csv". Only if MEMDBG_OPTIONS_PRINT_ALL
void _memdbg_itemLog(const memdbg_item_t item) {

    if (!memdbg_optionCheck(MEMDBG_OPTIONS_PRINT_ALL)) {
        return;
    }
    
    if (item._line[0] <= 0 && item._line[1] <= 0) {
        _memdbg_Panik("Attempt to log an empty item");
    }

    const uint32_t msg_sz = MEMDBG_MSG_SIZE;
    char msg[MEMDBG_MSG_SIZE];
    char timestamp[32];
    _memdbg_getTimeStamp(timestamp, sizeof(timestamp));
    int len = 0;
    len += sprintf_s(msg + len, msg_sz - len,
                     "%s,%s,%d,%s,",
                     timestamp,
                     item._file[item.is_done],
                     item._line[item.is_done],
                     item._func[item.is_done]);

    memdbg_func_enum_t func_idx = item.func_idx[item.is_done];
    
    if (item.is_done) {
        if (func_idx == REALLOC_IDX) {
            if (item.key == (uintptr_t)item.m.next) {
                len += sprintf_s(msg + len, msg_sz - len,
                         "Address %p resized in place to %lu bytes '%s'.\n",
                         item.m.ptr,
                         item.m.sz,
                         FUNC_NAME_TABLE[func_idx]);
            } else {
                len += sprintf_s(msg + len, msg_sz - len,
                         "Address %p moved to %p and resized to %lu bytes by '%s'.\n",
                         item.m.ptr,
                         item.m.next,
                         item.m.sz,
                         FUNC_NAME_TABLE[func_idx]);
            }
        } else if (item.func_idx[0] <= REALLOC_IDX) {  // free
            len += sprintf_s(msg + len, msg_sz - len,
                         "Address %p freed by '%s'.\n",
                         item.m.ptr,
                         FUNC_NAME_TABLE[func_idx]);
        } else if (func_idx >= FCLOSE_IDX) {  // close
            len += sprintf_s(msg + len, msg_sz - len,
                         "Stream %p closed by '%s' ending permission(s) '%s' for file %s.\n",
                         item.f.stream,
                         FUNC_NAME_TABLE[func_idx],
                         item.f.mode,
                         item.f.path);
        } else {
        _memdbg_Panik("Attempting to log an unknown item type!");
        }
    } else {
        if (func_idx <= REALLOC_IDX) {  // malloc & co.
            len += sprintf_s(msg + len, msg_sz - len,
                             "Address %p allocated %lu bytes by '%s'.\n",
                             item.m.ptr,
                             item.m.sz,
                             FUNC_NAME_TABLE[func_idx]);
        } else if (func_idx <= FOPEN_S_IDX) {  // fopen & co.
            len += sprintf_s(msg + len, msg_sz - len,
                             "Stream %p opened by '%s' with permission(s) '%s' for file %s.\n",
                             item.f.stream,
                             FUNC_NAME_TABLE[func_idx],
                             item.f.mode,
                             item.f.path);
        } else {
            _memdbg_Panik("Attempting to log an unknown item type!");
        }
    }

    if (memdbg_fid[REPORT_FILE] == NULL) {
        return;
    }

    if (fputs(msg, memdbg_fid[REPORT_FILE])) {
        _memdbg_Panik("Could not write to item log!");
    }
    
    return;
}

//----------------CLEANUP----------------//

/// @brief Is performed at exit, frees all memory that you forgot to free, as well as all internal memory (hash-map related)
void _memdbg_Cleanup(void) {
    uint32_t idx, i_bucket, i_item;
    int _line;
    const char *_file = _memdbg_shortFileName(__FILE__);
    memdbg_bucket_t *bucket;
    memdbg_item_t *item;

    memdbg_optionOff(MEMDBG_OPTIONS_OVERALLOC); // make sure the thread is no longer running

    for (idx = 0; idx < MEMDBG_MAP_SIZE; idx++) {
        if (memdbg_map[idx].n_buckets_allocd == 0) continue;

        for (i_bucket = 0; i_bucket < memdbg_map[idx].n_buckets_allocd; i_bucket++) {
            bucket = &memdbg_map[idx].buckets[i_bucket];
            if (bucket->n_items_allocd == 0) continue;

            for (i_item = 0; i_item < bucket->n_items_allocd; i_item++) {
                item = &bucket->items[i_item];
                if (!_memdbg_checkNotDone(item, _file, __LINE__, __func__, INTERNAL_IDX)) continue;

                if (item->func_idx[0] <= REALLOC_IDX) {
                    char *free_arg = (char *)item->m.ptr - (item->m.is_overallocd * MEMDBG_OVERALLOC_AMOUNT_BYTES); // free what was originally allocd
                    (free)(free_arg); _line = __LINE__;
                    _memdbg_itemFill(item, INT_NULL, _file, _line, __func__, INTERNAL_IDX);
                    item->m.next = NULL;
                } else {
                    item->f.is_closed = ((fclose)((FILE *)item->f.stream) == 0); _line = __LINE__;
                    _memdbg_itemFill(item, INT_NULL, _file, _line, __func__, INTERNAL_IDX);
                }
                _memdbg_itemLog(*item);
            }
            (free)(bucket->items);
        }
        (free)(memdbg_map[idx].buckets);
    }

    _memdbg_fileClose(ERROR_FILE);
    _memdbg_fileClose(REPORT_FILE);

    return;
}

/// @brief display a message to stdout, then write to null (will cause gdb to pause)
/// @note if MEMDBG_OPTIONS_MULTIPLE_ERRORS is off, memdbg will panik after one error.
/// @note this function is also used in case of internal memdbg error. Report to me at: https://github.com/ananski-the-3rd/memdbg/issues
void _memdbg_Panik(const char *msg) {
    fprintf(stderr, "\nMemdebug stopped with message:\n%s\nCheck call stack for more info", msg);
    *(volatile int *)0 = 0;
    return;
}

#endif

extern int this_translation_unit_is_not_empty;