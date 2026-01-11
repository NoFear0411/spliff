# spliff - eBPF-based SSL/TLS Traffic Sniffer
# CMake build configuration

cmake_minimum_required(VERSION 3.20)

project(spliff
    VERSION 0.5.3
    DESCRIPTION "eBPF-based SSL/TLS traffic sniffer for capturing decrypted HTTPS traffic"
    HOMEPAGE_URL "https://github.com/NoFear0411/spliff"
    LANGUAGES C
)

# ============================================================================
# Build Options
# ============================================================================

option(ENABLE_SANITIZERS "Enable AddressSanitizer and UBSan in Debug builds" ON)
option(ENABLE_ZSTD "Enable zstd compression support" ON)
option(ENABLE_BROTLI "Enable brotli compression support" ON)

# ============================================================================
# C23 Standard Configuration
# ============================================================================

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)  # Enable GNU extensions (_GNU_SOURCE)

# Export compile_commands.json for IDE integration
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ============================================================================
# Compiler Flags
# ============================================================================

# Base flags for all build types
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Werror=format-security
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -Wno-unused-parameter
    -fstack-protector-strong
)

# GNU extensions required for POSIX functions
add_compile_definitions(_GNU_SOURCE)

# Fortify source for runtime buffer overflow detection (Release only)
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(_FORTIFY_SOURCE=2)
endif()

# ============================================================================
# Build Type Configuration
# ============================================================================

# Define RelWithSan build type (Release + Sanitizers)
set(CMAKE_C_FLAGS_RELWITHSAN "-O2 -g -DNDEBUG" CACHE STRING
    "Flags used by the C compiler during RelWithSan builds." FORCE)
set(CMAKE_EXE_LINKER_FLAGS_RELWITHSAN "" CACHE STRING
    "Flags used by the linker during RelWithSan builds." FORCE)

# Debug-specific flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(DEBUG)
endif()

# Sanitizer support for Debug and RelWithSan builds
if(ENABLE_SANITIZERS AND (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithSan"))
    # Check if sanitizer libraries are available by trying to compile+link
    include(CheckCSourceCompiles)

    # Check AddressSanitizer (compile and link test)
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=address")
    check_c_source_compiles("int main(void) { return 0; }" HAVE_ASAN)
    unset(CMAKE_REQUIRED_FLAGS)
    unset(CMAKE_REQUIRED_LIBRARIES)

    # Check UndefinedBehaviorSanitizer (compile and link test)
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=undefined")
    set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=undefined")
    check_c_source_compiles("int main(void) { return 0; }" HAVE_UBSAN)
    unset(CMAKE_REQUIRED_FLAGS)
    unset(CMAKE_REQUIRED_LIBRARIES)

    # Enable available sanitizers
    set(SANITIZER_FLAGS "")
    if(HAVE_ASAN)
        set(SANITIZER_FLAGS "${SANITIZER_FLAGS},address")
        message(STATUS "AddressSanitizer: enabled")
    else()
        message(STATUS "AddressSanitizer: not available (install libasan)")
    endif()

    if(HAVE_UBSAN)
        set(SANITIZER_FLAGS "${SANITIZER_FLAGS},undefined")
        message(STATUS "UndefinedBehaviorSanitizer: enabled")
    else()
        message(STATUS "UndefinedBehaviorSanitizer: not available (install libubsan)")
    endif()

    # Apply sanitizer flags if any are available
    if(SANITIZER_FLAGS)
        # Remove leading comma
        string(SUBSTRING "${SANITIZER_FLAGS}" 1 -1 SANITIZER_FLAGS)
        add_compile_options(-fsanitize=${SANITIZER_FLAGS} -fno-omit-frame-pointer)
        add_link_options(-fsanitize=${SANITIZER_FLAGS})
    endif()
endif()

# ============================================================================
# Architecture Detection
# ============================================================================

# Detect architecture for BPF compilation
execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE MACHINE_ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if(MACHINE_ARCH STREQUAL "x86_64")
    set(BPF_ARCH "x86")
elseif(MACHINE_ARCH STREQUAL "aarch64")
    set(BPF_ARCH "arm64")
else()
    set(BPF_ARCH ${MACHINE_ARCH})
endif()

message(STATUS "Machine architecture: ${MACHINE_ARCH}")
message(STATUS "BPF target architecture: ${BPF_ARCH}")

# ============================================================================
# Find Dependencies
# ============================================================================

find_package(PkgConfig REQUIRED)

# Required dependencies
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
pkg_check_modules(LIBELF REQUIRED IMPORTED_TARGET libelf)
pkg_check_modules(ZLIB REQUIRED IMPORTED_TARGET zlib)

# llhttp (required for HTTP/1.1 parsing)
pkg_check_modules(LLHTTP IMPORTED_TARGET libllhttp)
if(NOT LLHTTP_FOUND)
    # Fallback: try to find header and library directly
    find_path(LLHTTP_INCLUDE_DIR llhttp.h)
    find_library(LLHTTP_LIBRARY NAMES llhttp)
    if(LLHTTP_INCLUDE_DIR AND LLHTTP_LIBRARY)
        message(STATUS "Found llhttp via direct search")
        set(LLHTTP_FOUND TRUE)
        add_library(PkgConfig::LLHTTP INTERFACE IMPORTED)
        target_include_directories(PkgConfig::LLHTTP INTERFACE ${LLHTTP_INCLUDE_DIR})
        target_link_libraries(PkgConfig::LLHTTP INTERFACE ${LLHTTP_LIBRARY})
    else()
        message(FATAL_ERROR "llhttp not found. Install llhttp-devel (Fedora) or libllhttp-dev (Debian)")
    endif()
endif()
message(STATUS "Found llhttp: ${LLHTTP_VERSION}")

# nghttp2 (required for HTTP/2 parsing)
pkg_check_modules(NGHTTP2 IMPORTED_TARGET libnghttp2)
if(NOT NGHTTP2_FOUND)
    # Fallback: try to find header and library directly
    find_path(NGHTTP2_INCLUDE_DIR nghttp2/nghttp2.h)
    find_library(NGHTTP2_LIBRARY NAMES nghttp2)
    if(NGHTTP2_INCLUDE_DIR AND NGHTTP2_LIBRARY)
        message(STATUS "Found nghttp2 via direct search")
        set(NGHTTP2_FOUND TRUE)
        add_library(PkgConfig::NGHTTP2 INTERFACE IMPORTED)
        target_include_directories(PkgConfig::NGHTTP2 INTERFACE ${NGHTTP2_INCLUDE_DIR})
        target_link_libraries(PkgConfig::NGHTTP2 INTERFACE ${NGHTTP2_LIBRARY})
    else()
        message(FATAL_ERROR "nghttp2 not found. Install nghttp2-devel (Fedora) or libnghttp2-dev (Debian)")
    endif()
endif()
message(STATUS "Found nghttp2: ${NGHTTP2_VERSION}")

# Optional: zstd compression
if(ENABLE_ZSTD)
    pkg_check_modules(ZSTD IMPORTED_TARGET libzstd)
    if(ZSTD_FOUND)
        message(STATUS "Found zstd: ${ZSTD_VERSION}")
    else()
        message(STATUS "zstd not found (optional)")
    endif()
endif()

# Optional: brotli compression
if(ENABLE_BROTLI)
    pkg_check_modules(BROTLI IMPORTED_TARGET libbrotlidec)
    if(BROTLI_FOUND)
        message(STATUS "Found brotli: ${BROTLI_VERSION}")
    else()
        message(STATUS "brotli not found (optional)")
    endif()
endif()

# Find clang for BPF compilation
find_program(CLANG_EXECUTABLE clang REQUIRED)
message(STATUS "Found clang: ${CLANG_EXECUTABLE}")

# ============================================================================
# Source Files
# ============================================================================

set(SPLIFF_SOURCES
    src/main.c
    src/util/safe_str.c
    src/content/signatures.c
    src/content/decompressor.c
    src/protocol/http1.c
    src/protocol/http2.c
    src/bpf/bpf_loader.c
    src/bpf/probe_handler.c
    src/output/display.c
)

# ============================================================================
# BPF Program Compilation
# ============================================================================

set(BPF_SOURCE ${CMAKE_SOURCE_DIR}/src/bpf/spliff.bpf.c)
set(BPF_OBJECT ${CMAKE_BINARY_DIR}/spliff.bpf.o)

# Get system include path for BPF
execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE UNAME_M
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

add_custom_command(
    OUTPUT ${BPF_OBJECT}
    COMMAND ${CLANG_EXECUTABLE}
        -g -O2
        -target bpf
        -D__TARGET_ARCH_${BPF_ARCH}
        -I/usr/include/${UNAME_M}-linux-gnu
        -c ${BPF_SOURCE}
        -o ${BPF_OBJECT}
    DEPENDS ${BPF_SOURCE}
    COMMENT "Compiling BPF program..."
    VERBATIM
)

add_custom_target(bpf_object ALL DEPENDS ${BPF_OBJECT})

# ============================================================================
# Main Executable
# ============================================================================

add_executable(spliff ${SPLIFF_SOURCES})

# Add dependency on BPF object
add_dependencies(spliff bpf_object)

# Include directories
target_include_directories(spliff PRIVATE
    ${CMAKE_SOURCE_DIR}/src/include
)

# Link required libraries
target_link_libraries(spliff PRIVATE
    PkgConfig::LIBBPF
    PkgConfig::LIBELF
    PkgConfig::ZLIB
    PkgConfig::LLHTTP
    PkgConfig::NGHTTP2
    pthread
)

# Compile definitions
target_compile_definitions(spliff PRIVATE
    HAVE_LLHTTP
    HAVE_NGHTTP2
)

# Optional zstd support
if(ZSTD_FOUND)
    target_link_libraries(spliff PRIVATE PkgConfig::ZSTD)
    target_compile_definitions(spliff PRIVATE HAVE_ZSTD)
endif()

# Optional brotli support
if(BROTLI_FOUND)
    target_link_libraries(spliff PRIVATE PkgConfig::BROTLI)
    target_compile_definitions(spliff PRIVATE HAVE_BROTLI)
endif()

# Strip release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET spliff POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-all $<TARGET_FILE:spliff>
        COMMENT "Stripping spliff binary..."
    )
endif()

# ============================================================================
# Tests
# ============================================================================

enable_testing()

# Test sources (shared modules)
set(TEST_COMMON_SOURCES
    src/protocol/http1.c
    src/protocol/http2.c
    src/util/safe_str.c
    src/output/display.c
    src/content/decompressor.c
    src/content/signatures.c
)

# HTTP/1.1 parser tests (EXCLUDE_FROM_ALL - only built with 'make test' or explicitly)
add_executable(test_http1 EXCLUDE_FROM_ALL tests/test_http1.c tests/test_common.c ${TEST_COMMON_SOURCES})
target_include_directories(test_http1 PRIVATE ${CMAKE_SOURCE_DIR}/src/include)
target_link_libraries(test_http1 PRIVATE
    PkgConfig::LLHTTP
    PkgConfig::NGHTTP2
    PkgConfig::ZLIB
)
target_compile_definitions(test_http1 PRIVATE HAVE_LLHTTP HAVE_NGHTTP2)
if(ZSTD_FOUND)
    target_link_libraries(test_http1 PRIVATE PkgConfig::ZSTD)
    target_compile_definitions(test_http1 PRIVATE HAVE_ZSTD)
endif()
if(BROTLI_FOUND)
    target_link_libraries(test_http1 PRIVATE PkgConfig::BROTLI)
    target_compile_definitions(test_http1 PRIVATE HAVE_BROTLI)
endif()
add_test(NAME http1_parser_tests COMMAND test_http1)

# HTTP/2 parser tests (EXCLUDE_FROM_ALL - only built with 'make test' or explicitly)
add_executable(test_http2 EXCLUDE_FROM_ALL tests/test_http2.c tests/test_common.c ${TEST_COMMON_SOURCES})
target_include_directories(test_http2 PRIVATE ${CMAKE_SOURCE_DIR}/src/include)
target_link_libraries(test_http2 PRIVATE
    PkgConfig::LLHTTP
    PkgConfig::NGHTTP2
    PkgConfig::ZLIB
)
target_compile_definitions(test_http2 PRIVATE HAVE_LLHTTP HAVE_NGHTTP2)
if(ZSTD_FOUND)
    target_link_libraries(test_http2 PRIVATE PkgConfig::ZSTD)
    target_compile_definitions(test_http2 PRIVATE HAVE_ZSTD)
endif()
if(BROTLI_FOUND)
    target_link_libraries(test_http2 PRIVATE PkgConfig::BROTLI)
    target_compile_definitions(test_http2 PRIVATE HAVE_BROTLI)
endif()
add_test(NAME http2_parser_tests COMMAND test_http2)

# ============================================================================
# Installation
# ============================================================================

include(GNUInstallDirs)

# Install binary
install(TARGETS spliff
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install BPF object
install(FILES ${BPF_OBJECT}
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/spliff
)

# ============================================================================
# CPack Configuration for Packaging
# ============================================================================

set(CPACK_PACKAGE_NAME "spliff")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_VENDOR "spliff developers")
set(CPACK_PACKAGE_CONTACT "maintainer@example.com")

# License file (optional - only set if exists)
if(EXISTS "${CMAKE_SOURCE_DIR}/LICENSE")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
endif()

# Debian package configuration
set(CPACK_DEBIAN_PACKAGE_DEPENDS
    "libbpf1, libelf1, zlib1g, libllhttp1, libnghttp2-14"
)
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")

# RPM package configuration
set(CPACK_RPM_PACKAGE_LICENSE "GPL-3.0")
set(CPACK_RPM_PACKAGE_GROUP "Applications/System")
set(CPACK_RPM_PACKAGE_REQUIRES
    "libbpf, elfutils-libelf, zlib, llhttp, libnghttp2"
)

include(CPack)

# ============================================================================
# Summary
# ============================================================================

message(STATUS "")
message(STATUS "=== spliff ${PROJECT_VERSION} Configuration ===")
message(STATUS "Build type:       ${CMAKE_BUILD_TYPE}")
message(STATUS "C compiler:       ${CMAKE_C_COMPILER}")
message(STATUS "C standard:       C${CMAKE_C_STANDARD}")
message(STATUS "Install prefix:   ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
message(STATUS "Dependencies:")
message(STATUS "  libbpf:         ${LIBBPF_VERSION}")
message(STATUS "  libelf:         ${LIBELF_VERSION}")
message(STATUS "  zlib:           ${ZLIB_VERSION}")
message(STATUS "  llhttp:         ${LLHTTP_VERSION}")
message(STATUS "  nghttp2:        ${NGHTTP2_VERSION}")
if(ZSTD_FOUND)
    message(STATUS "  zstd:           ${ZSTD_VERSION}")
else()
    message(STATUS "  zstd:           not found (optional)")
endif()
if(BROTLI_FOUND)
    message(STATUS "  brotli:         ${BROTLI_VERSION}")
else()
    message(STATUS "  brotli:         not found (optional)")
endif()
message(STATUS "")
message(STATUS "Options:")
message(STATUS "  Sanitizers:     ${ENABLE_SANITIZERS}")
message(STATUS "  ZSTD support:   ${ENABLE_ZSTD}")
message(STATUS "  Brotli support: ${ENABLE_BROTLI}")
message(STATUS "")
