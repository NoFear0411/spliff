# spliff - eBPF-based SSL/TLS Traffic Sniffer
# CMake build configuration

cmake_minimum_required(VERSION 3.20)

project(spliff
    VERSION 0.8.1
    DESCRIPTION "eBPF-based SSL/TLS traffic sniffer for capturing decrypted HTTPS traffic"
    HOMEPAGE_URL "https://github.com/NoFear0411/spliff"
    LANGUAGES C
)

# ============================================================================
# Build Options
# ============================================================================

option(ENABLE_SANITIZERS "Enable AddressSanitizer and UBSan in Debug builds" ON)
option(ENABLE_COVERAGE "Enable code coverage instrumentation (gcov)" OFF)
option(ENABLE_ZSTD "Enable zstd compression support" ON)
option(ENABLE_BROTLI "Enable brotli compression support" ON)
option(ENABLE_XDP "Enable XDP packet capture support" ON)

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
# Code Coverage (gcov/lcov)
# ============================================================================
# Note: Coverage and sanitizers are mutually exclusive for accurate results

if(ENABLE_COVERAGE)
    if(ENABLE_SANITIZERS)
        message(WARNING "Coverage enabled with sanitizers - results may be inaccurate. "
                        "Consider -DENABLE_SANITIZERS=OFF for coverage builds.")
    endif()

    # Check for gcov support (requires compile+link test since --coverage affects linking)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "--coverage")
    set(CMAKE_REQUIRED_LINK_OPTIONS "--coverage")
    check_c_source_compiles("int main(void) { return 0; }" HAVE_COVERAGE)
    unset(CMAKE_REQUIRED_FLAGS)
    unset(CMAKE_REQUIRED_LINK_OPTIONS)

    if(HAVE_COVERAGE)
        message(STATUS "Code coverage: enabled (gcov)")
        add_compile_options(--coverage -fprofile-arcs -ftest-coverage)
        add_link_options(--coverage)

        # Disable optimizations for accurate line coverage
        if(CMAKE_BUILD_TYPE STREQUAL "Release")
            message(WARNING "Coverage with Release build may have inaccurate line mapping. "
                            "Consider Debug or RelWithDebInfo build type.")
        endif()
    else()
        message(WARNING "Code coverage requested but --coverage flag not supported")
        set(ENABLE_COVERAGE OFF)
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

# Concurrency Kit (ck) - lock-free data structures for threading
pkg_check_modules(CK IMPORTED_TARGET ck)
if(NOT CK_FOUND)
    # Fallback: try to find header and library directly
    find_path(CK_INCLUDE_DIR ck_ring.h PATH_SUFFIXES ck)
    find_library(CK_LIBRARY NAMES ck)
    if(CK_INCLUDE_DIR AND CK_LIBRARY)
        message(STATUS "Found ck via direct search")
        set(CK_FOUND TRUE)
        add_library(PkgConfig::CK INTERFACE IMPORTED)
        target_include_directories(PkgConfig::CK INTERFACE ${CK_INCLUDE_DIR})
        target_link_libraries(PkgConfig::CK INTERFACE ${CK_LIBRARY})
    else()
        message(STATUS "ck not found - multi-threading disabled")
        set(CK_FOUND FALSE)
    endif()
endif()
if(CK_FOUND)
    message(STATUS "Found ck: ${CK_VERSION}")
endif()

# libxdp (optional, for XDP/AF_XDP support)
if(ENABLE_XDP)
    pkg_check_modules(LIBXDP IMPORTED_TARGET libxdp)
    if(NOT LIBXDP_FOUND)
        # Fallback: try to find header and library directly
        find_path(LIBXDP_INCLUDE_DIR xdp/xsk.h)
        find_library(LIBXDP_LIBRARY NAMES xdp)
        if(LIBXDP_INCLUDE_DIR AND LIBXDP_LIBRARY)
            message(STATUS "Found libxdp via direct search")
            set(LIBXDP_FOUND TRUE)
            add_library(PkgConfig::LIBXDP INTERFACE IMPORTED)
            target_include_directories(PkgConfig::LIBXDP INTERFACE ${LIBXDP_INCLUDE_DIR})
            target_link_libraries(PkgConfig::LIBXDP INTERFACE ${LIBXDP_LIBRARY})
        else()
            message(STATUS "libxdp not found - XDP support disabled")
            set(LIBXDP_FOUND FALSE)
        endif()
    endif()
    if(LIBXDP_FOUND)
        message(STATUS "Found libxdp: ${LIBXDP_VERSION}")
    endif()
endif()

# liburcu (optional, for RCU-based shared data structures)
pkg_check_modules(LIBURCU IMPORTED_TARGET liburcu-memb)
if(NOT LIBURCU_FOUND)
    # Fallback: try to find header and library directly
    find_path(LIBURCU_INCLUDE_DIR urcu/urcu-memb.h)
    find_library(LIBURCU_LIBRARY NAMES urcu-memb)
    if(LIBURCU_INCLUDE_DIR AND LIBURCU_LIBRARY)
        message(STATUS "Found liburcu via direct search")
        set(LIBURCU_FOUND TRUE)
        add_library(PkgConfig::LIBURCU INTERFACE IMPORTED)
        target_include_directories(PkgConfig::LIBURCU INTERFACE ${LIBURCU_INCLUDE_DIR})
        target_link_libraries(PkgConfig::LIBURCU INTERFACE ${LIBURCU_LIBRARY})
    else()
        message(STATUS "liburcu not found (optional)")
        set(LIBURCU_FOUND FALSE)
    endif()
endif()
if(LIBURCU_FOUND)
    message(STATUS "Found liburcu: ${LIBURCU_VERSION}")
endif()

# jemalloc (optional, for optimized memory allocation)
pkg_check_modules(JEMALLOC IMPORTED_TARGET jemalloc)
if(NOT JEMALLOC_FOUND)
    find_path(JEMALLOC_INCLUDE_DIR jemalloc/jemalloc.h)
    find_library(JEMALLOC_LIBRARY NAMES jemalloc)
    if(JEMALLOC_INCLUDE_DIR AND JEMALLOC_LIBRARY)
        message(STATUS "Found jemalloc via direct search")
        set(JEMALLOC_FOUND TRUE)
        add_library(PkgConfig::JEMALLOC INTERFACE IMPORTED)
        target_include_directories(PkgConfig::JEMALLOC INTERFACE ${JEMALLOC_INCLUDE_DIR})
        target_link_libraries(PkgConfig::JEMALLOC INTERFACE ${JEMALLOC_LIBRARY})
    else()
        message(STATUS "jemalloc not found (optional)")
        set(JEMALLOC_FOUND FALSE)
    endif()
endif()
if(JEMALLOC_FOUND)
    message(STATUS "Found jemalloc: ${JEMALLOC_VERSION}")
endif()

# PCRE2 (required for RFC-compliant HTTP pattern matching with JIT)
pkg_check_modules(PCRE2 IMPORTED_TARGET libpcre2-8)
if(NOT PCRE2_FOUND)
    find_path(PCRE2_INCLUDE_DIR pcre2.h)
    find_library(PCRE2_LIBRARY NAMES pcre2-8)
    if(PCRE2_INCLUDE_DIR AND PCRE2_LIBRARY)
        message(STATUS "Found pcre2 via direct search")
        set(PCRE2_FOUND TRUE)
        add_library(PkgConfig::PCRE2 INTERFACE IMPORTED)
        target_include_directories(PkgConfig::PCRE2 INTERFACE ${PCRE2_INCLUDE_DIR})
        target_link_libraries(PkgConfig::PCRE2 INTERFACE ${PCRE2_LIBRARY})
    else()
        message(STATUS "pcre2 not found - RFC-compliant HTTP detection disabled")
        set(PCRE2_FOUND FALSE)
    endif()
endif()
if(PCRE2_FOUND)
    message(STATUS "Found pcre2: ${PCRE2_VERSION}")
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

# Threading sources (optional, requires ck library)
if(CK_FOUND)
    list(APPEND SPLIFF_SOURCES
        src/threading/pool.c
        src/threading/state.c
        src/threading/worker.c
        src/threading/dispatcher.c
        src/threading/output.c
        src/threading/manager.c
    )
endif()

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

# Threading support (requires ck library)
if(CK_FOUND)
    target_link_libraries(spliff PRIVATE PkgConfig::CK)
    target_compile_definitions(spliff PRIVATE HAVE_THREADING)
endif()

# XDP support (requires libxdp and threading)
if(LIBXDP_FOUND AND CK_FOUND)
    target_link_libraries(spliff PRIVATE PkgConfig::LIBXDP)
    target_compile_definitions(spliff PRIVATE HAVE_XDP)
endif()

# Optional liburcu support (RCU-based shared data)
if(LIBURCU_FOUND)
    target_link_libraries(spliff PRIVATE PkgConfig::LIBURCU)
    target_compile_definitions(spliff PRIVATE HAVE_LIBURCU)
endif()

# Optional jemalloc support (optimized memory allocation)
if(JEMALLOC_FOUND)
    target_link_libraries(spliff PRIVATE PkgConfig::JEMALLOC)
    target_compile_definitions(spliff PRIVATE HAVE_JEMALLOC)
endif()

# PCRE2 support (RFC-compliant HTTP pattern matching with JIT)
if(PCRE2_FOUND)
    target_link_libraries(spliff PRIVATE PkgConfig::PCRE2)
    target_compile_definitions(spliff PRIVATE HAVE_PCRE2 PCRE2_CODE_UNIT_WIDTH=8)
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

# XDP structure tests (v0.8.0+)
add_executable(test_xdp EXCLUDE_FROM_ALL tests/test_xdp.c tests/test_common.c
    src/bpf/bpf_loader.c
    src/util/safe_str.c
)
target_include_directories(test_xdp PRIVATE ${CMAKE_SOURCE_DIR}/src/include)
target_link_libraries(test_xdp PRIVATE
    PkgConfig::LIBBPF
    PkgConfig::LIBELF
)
add_test(NAME xdp_structure_tests COMMAND test_xdp)

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
# Standard naming: <name>_<version>-<release>_<arch>.deb
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_RELEASE "1")
# Architecture detection (fallback if dpkg not available)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "arm64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "armv7")
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "armhf")
else()
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "${CMAKE_SYSTEM_PROCESSOR}")
endif()
set(CPACK_DEBIAN_PACKAGE_DEPENDS
    "libbpf1, libelf1, zlib1g, libllhttp1, libnghttp2-14"
)
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")

# RPM package configuration
# Standard naming: <name>-<version>-<release>.<arch>.rpm
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_RELEASE "1")
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
if(CK_FOUND)
    message(STATUS "  ck:             ${CK_VERSION}")
else()
    message(STATUS "  ck:             not found (threading disabled)")
endif()
if(LIBXDP_FOUND)
    message(STATUS "  libxdp:         ${LIBXDP_VERSION}")
else()
    message(STATUS "  libxdp:         not found (XDP disabled)")
endif()
if(LIBURCU_FOUND)
    message(STATUS "  liburcu:        ${LIBURCU_VERSION}")
else()
    message(STATUS "  liburcu:        not found (optional)")
endif()
if(JEMALLOC_FOUND)
    message(STATUS "  jemalloc:       ${JEMALLOC_VERSION}")
else()
    message(STATUS "  jemalloc:       not found (optional)")
endif()
message(STATUS "")
message(STATUS "Options:")
message(STATUS "  Sanitizers:     ${ENABLE_SANITIZERS}")
message(STATUS "  Coverage:       ${ENABLE_COVERAGE}")
message(STATUS "  ZSTD support:   ${ENABLE_ZSTD}")
message(STATUS "  Brotli support: ${ENABLE_BROTLI}")
if(CK_FOUND)
    message(STATUS "  Threading:      ON (multi-threaded mode available)")
else()
    message(STATUS "  Threading:      OFF (single-threaded mode only)")
endif()
if(LIBXDP_FOUND AND CK_FOUND)
    message(STATUS "  XDP support:    ON (packet capture available)")
else()
    message(STATUS "  XDP support:    OFF (requires libxdp and ck)")
endif()
if(PCRE2_FOUND)
    message(STATUS "  PCRE2-JIT:      ON (RFC-compliant HTTP detection)")
else()
    message(STATUS "  PCRE2-JIT:      OFF (install pcre2)")
endif()
message(STATUS "")
