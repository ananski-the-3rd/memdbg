cmake_minimum_required(VERSION 3.8.0)

project(memdbg
    VERSION 1.1
    DESCRIPTION "A tool for finding memory errors"
    LANGUAGES C
)

add_library(${PROJECT_NAME} STATIC
    memdbg.c
)

target_compile_features(${PROJECT_NAME}
    PUBLIC
        c_std_11
)

target_compile_definitions(${PROJECT_NAME}
    PUBLIC
        MEMDBG_ENABLED
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

