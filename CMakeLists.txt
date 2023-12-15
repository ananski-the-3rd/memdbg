cmake_minimum_required(VERSION 3.8.0)

project(memdbg
    VERSION 1.1
    DESCRIPTION "A tool for finding memory errors"
    LANGUAGES C
)

add_library(${PROJECT_NAME} SHARED
    src/memdbg.c
)

set_target_properties(${PROJECT_NAME}
    PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        PUBLIC_HEADER include/${PROJECT_NAME}.h
)

target_compile_features(${PROJECT_NAME}
    PUBLIC
        c_std_11
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
        "./include"
        "./src"
)

include(GNUInstallDirs)

include(GenerateExportHeader)
generate_export_header(${PROJECT_NAME})

# Compiler-specific compile flags

if(${CMAKE_C_COMPILER_ID} STREQUAL "MSVC")
    # MSVC
    target_compile_options(${PROJECT_NAME}
    PRIVATE
        /Z7 /W4 /wd4146 /wd4245 /RTCcsu
    )
    # Set the DLLEXPORT variable
    target_compile_definitions(${PROJECT_NAME} PRIVATE WIN_EXPORT)
else()
   # GCC or Clang
   target_compile_options(${PROJECT_NAME}
   PRIVATE
       -O3 -Wall -Wextra -Wconversion -Wdouble-promotion
       -Wno-unused-parameter -Wno-unused-function -Wno-sign-conversion
   )
endif()
target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        MEMDBG_ENABLED
        MEMDBG_EXPECTED_N_ALLOCS=1000
        MEMDBG_EXPECTED_N_THREADS=10
        MEMDBG_OPTIONS_MULTIPLE_ERRORS=1
        MEMDBG_OPTIONS_OVERALLOC=2
        MEMDBG_OPTIONS_PRINT_ALL=4
        MEMDBG_OPTIONS_THREADS=8
)


install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)