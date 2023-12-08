# memdbg
memdbg is a tool for finding memory errors in c programs. Use it in 3 simple steps:
1. Include `memdbg.h` in your project. Its macros will override your memory-related calls with calls to memdbg functions
A full list of overriden function is at the MEMORY FUNCTION OVERRIDES section of `memdbg.h`.
2. Add `MEMDBG_ENABLED` as a define
3. Compile/link your project with `memdbg.c`

EXAMPLE (steps 2 & 3):
`gcc -D MEMDBG_ENABLED memdbg.c ...` (the rest of your args) 

NOTE: Make sure `memdbg.h` is included after `stdio.h` and `stdlib.h`.
Outputs `memdbg_error_log.csv` and `memdbg_full_report.csv`.

## Options
Memdbg has several options that can be toggled via compiler args. By default, all options are on.
**Options can be turned _off_ by defining them**: add the appropriate flag to your compiler (on clang, `-D<MEMDBG_OPTIONS_MULTIPLE_ERRORS>=<0>` to turn off).
### MEMDBG_OPTIONS_MULTIPLE_ERRORS
memdbg will attempt to correct any errors it finds, such that more than one error may be reported per run. Recommended for larger projects.
if this option is off, memdbg will "panik" after it has found an error, by writing to null (which will pause execution on GDB).
### MEMDBG_OPTIONS_OVERALLOC
memdbg will over-allocate all allocations. This is required for finding potential buffer overflows. May be memory intensive.
if this option is off, memdbg will not over-allocate and will not check for buffer overflows.
### MEMDBG_OPTIONS_PRINT_ALL
memdbg will report _every call_ to the memory functions in a separate log. Errors will be reported as usual in an error log. Recommended for smaller projects.
if this option is off, memdbg will only report errors (errors are always reported and they cannot be turned off).
### MEMDBG_OPTIONS_THREADS
memdbg will use (win)pthread.h or winapi threads from windows.h. This does not changes internal functionality.
if this option is off, memdbg will still use threads internally - currently one extra thread is used to find real-time buffer overflows (they are also detected on 'free()', but with a late timestamp).

### recommended: MEMDBG_EXPECTED_N_ALLOCS, MEMDBG_EXPECTED_N_THREADS
These special option are not binary, but on a scale. Specifiy with exacltly how many allocations you expect to have in your program, and how many threads you use. This can greatly improve memdbg's performance.
EXAMPLE: `gcc -D MEMDBG_EXPECTED_N_ALLOCS=2500`

## Display the results:
After the runtime ends, run `Import-Csv ./memdbg_error_log.csv |Out-GridView` in powershell (on windows) to view the log.
On unix-like systems: `column -s, -t < data.csv`

## Changelog
Version 1.0
- Improved performance in many ways
- Passed the integration test for threads
- Better documentation

- More consistent naming:
    - Capitalized static const variables, no prefix
    - `_memdbg_` prefix for functions
    - `memdbg_` prefix for non-const static variables
    - `MEMDBG_` prefix for macros
    - All typedefs are in `snake_case_t` format

- memdbg_item_t restructured for sweet, sweet sugary syntax:
    - item.field for generic fields that all items have
    - item.m.field for memory related fields
    - item.f.field for file related fields
