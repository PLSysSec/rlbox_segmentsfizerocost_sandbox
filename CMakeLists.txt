cmake_minimum_required(VERSION 3.13)

set(COMPILER_LIB_PATH ${CMAKE_SOURCE_DIR}/../ffbuilds/zerocost_llvm_install/lib/clang/12.0.0)
set(CMAKE_C_COMPILER ${CMAKE_SOURCE_DIR}/../ffbuilds/zerocost_llvm_install/bin/clang)
set(CMAKE_CXX_COMPILER ${CMAKE_SOURCE_DIR}/../ffbuilds/zerocost_llvm_install/bin/clang++)

# set(COMPILER_LIB_PATH /mnt/sata/ffbuilds/zerocost_llvm_install/lib/clang/12.0.0)
# set(CMAKE_C_COMPILER /mnt/sata/ffbuilds/zerocost_llvm_install/bin/clang)
# set(CMAKE_CXX_COMPILER /mnt/sata/ffbuilds/zerocost_llvm_install/bin/clang++)

project(rlbox_segmentsfi
        VERSION 0.1
        DESCRIPTION "RLBox integration with Intel Segments based SFI")

# Project Settings ###################

# set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
SET(ASM_OPTIONS "-x assembler-with-cpp")
enable_language(C CXX ASM)

# This is meant to work only on 32-bit mode as Segments support is removed in 64-bit
add_compile_options(-m32)
add_link_options(-m32)

option(DEV "Use settings suitable for dev contributions to rlbox" OFF)

file(GLOB_RECURSE
     ALL_CXX_SOURCE_FILES
     ${CMAKE_SOURCE_DIR}/include/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/include/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/include/*.cc
     ${CMAKE_SOURCE_DIR}/include/*.hh
     ${CMAKE_SOURCE_DIR}/include/*.ii
     ${CMAKE_SOURCE_DIR}/include/*.[CHI]
     ${CMAKE_SOURCE_DIR}/test/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/test/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/test/*.cc
     ${CMAKE_SOURCE_DIR}/test/*.hh
     ${CMAKE_SOURCE_DIR}/test/*.ii
     ${CMAKE_SOURCE_DIR}/test/*.[CHI]
     ${CMAKE_SOURCE_DIR}/c_src/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/c_src/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/c_src/*.cc
     ${CMAKE_SOURCE_DIR}/c_src/*.hh
     ${CMAKE_SOURCE_DIR}/c_src/*.ii
     ${CMAKE_SOURCE_DIR}/c_src/*.[CHI])

# Dev Tools ###################

if(DEV)
  if(MSVC)
    add_compile_options(/W4) # warnings
    add_compile_options(/WX) # warnings as errors
  else()
    add_compile_options(-Wall -Wextra -pedantic) # warnings
    add_compile_options(-Werror) # warnings as errors
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
  endif()

  find_program(CLANG_TIDY "clang-tidy")
  if(CLANG_TIDY)
    # Config in .clang-tidy
    set(CMAKE_CXX_CLANG_TIDY clang-tidy)
  endif()

  find_program(CLANG_FORMAT "clang-format")
  if(CLANG_FORMAT)
    # Config in .clang-format
    add_custom_target(format-source
                      COMMAND clang-format
                              -i
                              -style=file
                              ${ALL_CXX_SOURCE_FILES})
  endif()

endif()

# Dependencies ###################

include(FetchContent)

FetchContent_Declare(
  rlbox
  GIT_REPOSITORY https://github.com/PLSysSec/rlbox_api_cpp17.git
  GIT_TAG origin/gettimeofday)
FetchContent_GetProperties(rlbox)
if(NOT rlbox_POPULATED)
  FetchContent_Populate(rlbox)
endif()

FetchContent_Declare(catch2
                     GIT_REPOSITORY https://github.com/catchorg/Catch2.git
                     GIT_TAG v2.9.1)
FetchContent_GetProperties(catch2)
if(NOT catch2_POPULATED)
  FetchContent_Populate(catch2)
endif()

add_subdirectory("${catch2_SOURCE_DIR}")
list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/contrib")

# Lib ###################

set(ZERO_COST_COMPILE_FLAGS
  -fno-asm -fno-asm-blocks -Werror=return-type # avoid easy bypasses
  -fsanitize=safe-stack -fstack-clash-protection # Safe stack
  -flto ##-fuse-ld=lld # Clang flags needed for cfi and maybe other passes
  -fsanitize=cfi-icall -fsanitize-cfi-canonical-jump-tables -fsanitize-cfi-cross-dso # forward edge protection
  ##${COMPILER_LIB_PATH}/lib/linux/libclang_rt.cfi-i386.a # clang cfi runtime library
  -ftrivial-auto-var-init=zero -enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang # stack variable initialization
)

set(ZERO_COST_LINK_FLAGS
  -fno-asm -fno-asm-blocks -Werror=return-type # avoid easy bypasses
  -fsanitize=safe-stack -fstack-clash-protection # Safe stack
  -flto -fuse-ld=lld # Clang flags needed for cfi and maybe other passes
  -fsanitize=cfi-icall -fsanitize-cfi-canonical-jump-tables -fsanitize-cfi-cross-dso # forward edge protection
  ${COMPILER_LIB_PATH}/lib/linux/libclang_rt.cfi-i386.a # clang cfi runtime library
  ##-ftrivial-auto-var-init=zero -enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang # stack variable initialization
)

set(SEGMENTSFI_COMPILE_FLAGS
  -mseparate-stack-seg
)
set(SEGMENTSFI_LINK_FLAGS
  -Wl,--wrap=malloc
  -Wl,--wrap=free
  -Wl,--wrap=calloc
  -Wl,--wrap=realloc
)

add_library(rlbox_glue_lib_static STATIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib/libtest.c
                                         c_src/dlmalloc.c)
target_include_directories(rlbox_glue_lib_static
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib
                                  ${CMAKE_SOURCE_DIR}/include)
target_compile_options(rlbox_glue_lib_static PRIVATE ${ZERO_COST_COMPILE_FLAGS} ${SEGMENTSFI_COMPILE_FLAGS} -Wno-expansion-to-defined)
target_link_options(rlbox_glue_lib_static PRIVATE ${ZERO_COST_LINK_FLAGS} ${SEGMENTSFI_LINK_FLAGS})

add_library(rlbox_glue_lib_shared SHARED ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib/libtest.c
                                         c_src/dlmalloc.c)
target_include_directories(rlbox_glue_lib_shared
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib
                                  ${CMAKE_SOURCE_DIR}/include)
target_compile_options(rlbox_glue_lib_shared PRIVATE ${ZERO_COST_COMPILE_FLAGS} ${SEGMENTSFI_COMPILE_FLAGS} -Wno-expansion-to-defined)
target_link_options(rlbox_glue_lib_shared PRIVATE ${ZERO_COST_LINK_FLAGS} ${SEGMENTSFI_LINK_FLAGS})

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(DYLIB_EXT "dylib")
else()
  set(DYLIB_EXT "so")
endif()
set(GLUE_LIB_SO "${CMAKE_BINARY_DIR}/librlbox_glue_lib_shared.${DYLIB_EXT}")

# Tests ###################

include(CTest)
include(Catch)

add_executable(test_rlbox_glue test/test_segmentsfi_sandbox_glue_main.cpp
                               test/test_segmentsfi_sandbox_glue.cpp
                               c_src/segmentsfi_sandbox_runtime.cpp
                               c_src/trampoline.S)
target_include_directories(test_rlbox_glue PUBLIC include)
target_include_directories(test_rlbox_glue
                           PUBLIC ${rlbox_SOURCE_DIR}/code/include)
target_include_directories(test_rlbox_glue
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue)
target_include_directories(test_rlbox_glue
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib)
target_compile_definitions(test_rlbox_glue PUBLIC
                           GLUE_LIB_PATH="${GLUE_LIB_SO}")
target_link_options(test_rlbox_glue PUBLIC
  -rdynamic
  -Wl,--whole-archive
  ${COMPILER_LIB_PATH}/lib/linux/libclang_rt.safestack-i386.a
  -Wl,--no-whole-archive
)

add_dependencies(test_rlbox_glue rlbox_glue_lib_shared)

find_package(Threads REQUIRED)

target_link_libraries(test_rlbox_glue
                      Catch2::Catch2
                      ${LINK_LUCET_LIB}
                      ${CMAKE_THREAD_LIBS_INIT}
                      ${CMAKE_DL_LIBS}
                      )

if(UNIX AND NOT (${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
  target_link_libraries(test_rlbox_glue rt)
endif()

catch_discover_tests(test_rlbox_glue)

# Shortcuts ###################

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} -V)
add_dependencies(check test_rlbox_glue)

