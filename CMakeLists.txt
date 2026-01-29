# spliff - eBPF-based SSL/TLS Traffic Sniffer
# CMake build configuration

cmake_minimum_required(VERSION 3.20)

project(spliff
    VERSION 0.9.8
    DESCRIPTION "eBPF-based SSL/TLS traffic sniffer for capturing decrypted HTTPS traffic"
    HOMEPAGE_URL "https://github.com/NoFear0411/spliff"
    LANGUAGES C
)

# ============================================================================
# Build Options
# ============================================================================

option(ENABLE_SANITIZERS "Enable AddressSanitizer and UBSan in Debug builds" ON)
option(ENABLE_COVERAGE "Enable code coverage instrumentation (gcov)" OFF)

# Performance library options (v0.9.5 Golden Thread optimizations)
option(USE_VECTORSCAN "Use vectorscan/hyperscan for O(n) protocol detection" ON)
option(USE_ZLIB_NG "Use zlib-ng for SIMD-accelerated decompression" ON)
option(USE_MIMALLOC "Use mimalloc instead of jemalloc (lower latency)" OFF)

# Packaging options (CI release builds)
option(ENABLE_STATIC_LIBS "Statically link vectorscan for portable RPMs" OFF)
option(ENABLE_FULL_STATIC "Statically link all libraries for portable binary" OFF)

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

# Default to Release build if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# LTO (Link Time Optimization) - 5-10% performance improvement
option(ENABLE_LTO "Enable Link Time Optimization for Release builds" ON)

# Define RelWithSan build type (Release + Sanitizers)
set(CMAKE_C_FLAGS_RELWITHSAN "-O2 -g -DNDEBUG" CACHE STRING
    "Flags used by the C compiler during RelWithSan builds." FORCE)
set(CMAKE_EXE_LINKER_FLAGS_RELWITHSAN "" CACHE STRING
    "Flags used by the linker during RelWithSan builds." FORCE)

# Define Sanitize build type (optimized for maximum sanitizer accuracy)
# -O1 preserves function calls for better stack traces
set(CMAKE_C_FLAGS_SANITIZE "-O1 -g -fno-omit-frame-pointer" CACHE STRING
    "Flags for Sanitize builds (ASan/UBSan optimized)." FORCE)
set(CMAKE_EXE_LINKER_FLAGS_SANITIZE "" CACHE STRING
    "Linker flags for Sanitize builds." FORCE)

# Debug-specific flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(DEBUG)
endif()

# LTO support for Release builds
if(ENABLE_LTO AND CMAKE_BUILD_TYPE STREQUAL "Release")
    include(CheckIPOSupported)
    check_ipo_supported(RESULT LTO_SUPPORTED OUTPUT LTO_ERROR)
    if(LTO_SUPPORTED)
        message(STATUS "LTO (Link Time Optimization): enabled")
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    else()
        message(STATUS "LTO not supported: ${LTO_ERROR}")
    endif()
endif()

# Sanitizer support for Debug, RelWithSan, and Sanitize builds
if(ENABLE_SANITIZERS AND (CMAKE_BUILD_TYPE STREQUAL "Debug" OR
                          CMAKE_BUILD_TYPE STREQUAL "RelWithSan" OR
                          CMAKE_BUILD_TYPE STREQUAL "Sanitize"))
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
# Architecture Detection and Validation
# ============================================================================

# Detect architecture for BPF compilation
execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE MACHINE_ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Validate supported architectures
if(MACHINE_ARCH STREQUAL "x86_64")
    set(BPF_ARCH "x86")
    set(ARCH_INCLUDE_PATH "/usr/include/x86_64-linux-gnu")
elseif(MACHINE_ARCH STREQUAL "aarch64")
    set(BPF_ARCH "arm64")
    set(ARCH_INCLUDE_PATH "/usr/include/aarch64-linux-gnu")
else()
    message(FATAL_ERROR "Unsupported architecture: ${MACHINE_ARCH}. Supported: x86_64, aarch64")
endif()

message(STATUS "Machine architecture: ${MACHINE_ARCH}")
message(STATUS "BPF target architecture: ${BPF_ARCH}")

# ============================================================================
# Find Required Dependencies
# ============================================================================

find_package(PkgConfig REQUIRED)

# Static linking support for portable RPMs (vectorscan only)
if(ENABLE_STATIC_LIBS)
    set(SPLIFF_STATIC_KEYWORD "STATIC")
    message(STATUS "Static linking: enabled for vectorscan")
else()
    set(SPLIFF_STATIC_KEYWORD "")
endif()

# --- Core BPF dependencies ---
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
message(STATUS "Found libbpf: ${LIBBPF_VERSION}")

pkg_check_modules(LIBELF REQUIRED IMPORTED_TARGET libelf)
message(STATUS "Found libelf: ${LIBELF_VERSION}")

# --- Compression dependencies ---
# zlib-ng provides SIMD-accelerated decompression (2-3x faster)
# API-compatible with zlib, just link different library
if(USE_ZLIB_NG)
    pkg_check_modules(ZLIB_NG IMPORTED_TARGET zlib-ng)
    if(ZLIB_NG_FOUND)
        message(STATUS "Found zlib-ng: ${ZLIB_NG_VERSION} (SIMD-accelerated)")
        set(ZLIB_TARGET PkgConfig::ZLIB_NG)
        set(HAVE_ZLIB_NG TRUE)
    else()
        # Try direct search for zlib-ng
        find_path(ZLIB_NG_INCLUDE_DIR zlib.h PATH_SUFFIXES zlib-ng)
        find_library(ZLIB_NG_LIBRARY NAMES z-ng zlib-ng)
        if(ZLIB_NG_INCLUDE_DIR AND ZLIB_NG_LIBRARY)
            message(STATUS "Found zlib-ng via direct search (SIMD-accelerated)")
            add_library(ZLIB_NG_TARGET INTERFACE IMPORTED)
            target_include_directories(ZLIB_NG_TARGET INTERFACE ${ZLIB_NG_INCLUDE_DIR})
            target_link_libraries(ZLIB_NG_TARGET INTERFACE ${ZLIB_NG_LIBRARY})
            set(ZLIB_TARGET ZLIB_NG_TARGET)
            set(HAVE_ZLIB_NG TRUE)
        else()
            message(STATUS "zlib-ng not found, falling back to standard zlib")
            set(USE_ZLIB_NG OFF)
        endif()
    endif()
endif()

if(NOT USE_ZLIB_NG OR NOT HAVE_ZLIB_NG)
    pkg_check_modules(ZLIB REQUIRED IMPORTED_TARGET zlib)
    message(STATUS "Found zlib: ${ZLIB_VERSION}")
    set(ZLIB_TARGET PkgConfig::ZLIB)
endif()

pkg_check_modules(ZSTD IMPORTED_TARGET libzstd)
if(NOT ZSTD_FOUND)
    find_path(ZSTD_INCLUDE_DIR zstd.h)
    find_library(ZSTD_LIBRARY NAMES zstd)
    if(ZSTD_INCLUDE_DIR AND ZSTD_LIBRARY)
        message(STATUS "Found zstd via direct search")
        set(ZSTD_FOUND TRUE)
        add_library(PkgConfig::ZSTD INTERFACE IMPORTED)
        target_include_directories(PkgConfig::ZSTD INTERFACE ${ZSTD_INCLUDE_DIR})
        target_link_libraries(PkgConfig::ZSTD INTERFACE ${ZSTD_LIBRARY})
    else()
        message(FATAL_ERROR "zstd not found. Install libzstd-devel (Fedora) or libzstd-dev (Debian)")
    endif()
endif()
message(STATUS "Found zstd: ${ZSTD_VERSION}")

pkg_check_modules(BROTLI IMPORTED_TARGET libbrotlidec)
if(NOT BROTLI_FOUND)
    find_path(BROTLI_INCLUDE_DIR brotli/decode.h)
    find_library(BROTLI_LIBRARY NAMES brotlidec)
    if(BROTLI_INCLUDE_DIR AND BROTLI_LIBRARY)
        message(STATUS "Found brotli via direct search")
        set(BROTLI_FOUND TRUE)
        add_library(PkgConfig::BROTLI INTERFACE IMPORTED)
        target_include_directories(PkgConfig::BROTLI INTERFACE ${BROTLI_INCLUDE_DIR})
        target_link_libraries(PkgConfig::BROTLI INTERFACE ${BROTLI_LIBRARY})
    else()
        message(FATAL_ERROR "brotli not found. Install brotli-devel (Fedora) or libbrotli-dev (Debian)")
    endif()
endif()
message(STATUS "Found brotli: ${BROTLI_VERSION}")

# --- HTTP parsing dependencies ---
pkg_check_modules(LLHTTP IMPORTED_TARGET libllhttp)
if(NOT LLHTTP_FOUND)
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

pkg_check_modules(NGHTTP2 IMPORTED_TARGET libnghttp2)
if(NOT NGHTTP2_FOUND)
    find_path(NGHTTP2_INCLUDE_DIR nghttp2/nghttp2.h)
    find_library(NGHTTP2_LIBRARY NAMES nghttp2)
    if(NGHTTP2_INCLUDE_DIR AND NGHTTP2_LIBRARY)
        message(STATUS "Found nghttp2 via direct search")
        set(NGHTTP2_FOUND TRUE)
        add_library(PkgConfig::NGHTTP2 INTERFACE IMPORTED)
        target_include_directories(PkgConfig::NGHTTP2 INTERFACE ${NGHTTP2_INCLUDE_DIR})
        target_link_libraries(PkgConfig::NGHTTP2 INTERFACE ${NGHTTP2_LIBRARY})
    else()
        message(FATAL_ERROR "nghttp2 not found. Install libnghttp2-devel (Fedora) or libnghttp2-dev (Debian)")
    endif()
endif()
message(STATUS "Found nghttp2: ${NGHTTP2_VERSION}")

# --- Threading dependencies ---
pkg_check_modules(CK IMPORTED_TARGET ck)
if(NOT CK_FOUND)
    find_path(CK_INCLUDE_DIR ck_ring.h PATH_SUFFIXES ck)
    find_library(CK_LIBRARY NAMES ck)
    if(CK_INCLUDE_DIR AND CK_LIBRARY)
        message(STATUS "Found ck via direct search")
        set(CK_FOUND TRUE)
        add_library(PkgConfig::CK INTERFACE IMPORTED)
        target_include_directories(PkgConfig::CK INTERFACE ${CK_INCLUDE_DIR})
        target_link_libraries(PkgConfig::CK INTERFACE ${CK_LIBRARY})
    else()
        message(FATAL_ERROR "Concurrency Kit (ck) not found. Install ck-devel (Fedora) or libck-dev (Debian)")
    endif()
endif()
message(STATUS "Found ck: ${CK_VERSION}")

# --- XDP support ---
pkg_check_modules(LIBXDP IMPORTED_TARGET libxdp)
if(NOT LIBXDP_FOUND)
    find_path(LIBXDP_INCLUDE_DIR xdp/xsk.h)
    find_library(LIBXDP_LIBRARY NAMES xdp)
    if(LIBXDP_INCLUDE_DIR AND LIBXDP_LIBRARY)
        message(STATUS "Found libxdp via direct search")
        set(LIBXDP_FOUND TRUE)
        add_library(PkgConfig::LIBXDP INTERFACE IMPORTED)
        target_include_directories(PkgConfig::LIBXDP INTERFACE ${LIBXDP_INCLUDE_DIR})
        target_link_libraries(PkgConfig::LIBXDP INTERFACE ${LIBXDP_LIBRARY})
    else()
        message(FATAL_ERROR "libxdp not found. Install libxdp-devel (Fedora) or libxdp-dev (Debian)")
    endif()
endif()
message(STATUS "Found libxdp: ${LIBXDP_VERSION}")

# --- RCU support ---
pkg_check_modules(LIBURCU IMPORTED_TARGET liburcu-memb)
if(NOT LIBURCU_FOUND)
    find_path(LIBURCU_INCLUDE_DIR urcu/urcu-memb.h)
    find_library(LIBURCU_LIBRARY NAMES urcu-memb)
    if(LIBURCU_INCLUDE_DIR AND LIBURCU_LIBRARY)
        message(STATUS "Found liburcu via direct search")
        set(LIBURCU_FOUND TRUE)
        add_library(PkgConfig::LIBURCU INTERFACE IMPORTED)
        target_include_directories(PkgConfig::LIBURCU INTERFACE ${LIBURCU_INCLUDE_DIR})
        target_link_libraries(PkgConfig::LIBURCU INTERFACE ${LIBURCU_LIBRARY})
    else()
        message(FATAL_ERROR "liburcu not found. Install userspace-rcu-devel (Fedora) or liburcu-dev (Debian)")
    endif()
endif()
message(STATUS "Found liburcu: ${LIBURCU_VERSION}")

# --- Memory allocator ---
# mimalloc provides lower latency for multi-threaded workloads
# jemalloc is still excellent, mimalloc is optional
if(USE_MIMALLOC)
    pkg_check_modules(MIMALLOC IMPORTED_TARGET mimalloc)
    if(NOT MIMALLOC_FOUND)
        find_path(MIMALLOC_INCLUDE_DIR mimalloc.h PATH_SUFFIXES mimalloc)
        find_library(MIMALLOC_LIBRARY NAMES mimalloc)
        if(MIMALLOC_INCLUDE_DIR AND MIMALLOC_LIBRARY)
            message(STATUS "Found mimalloc via direct search")
            set(MIMALLOC_FOUND TRUE)
            add_library(PkgConfig::MIMALLOC INTERFACE IMPORTED)
            target_include_directories(PkgConfig::MIMALLOC INTERFACE ${MIMALLOC_INCLUDE_DIR})
            target_link_libraries(PkgConfig::MIMALLOC INTERFACE ${MIMALLOC_LIBRARY})
        endif()
    endif()
    if(MIMALLOC_FOUND)
        message(STATUS "Found mimalloc: ${MIMALLOC_VERSION} (low-latency allocator)")
        set(ALLOCATOR_TARGET PkgConfig::MIMALLOC)
        set(HAVE_MIMALLOC TRUE)

        # Enable MI_TRACK_ASAN for sanitizer builds
        # This allows mimalloc to communicate with ASan runtime instead of conflicting
        if(ENABLE_SANITIZERS AND (CMAKE_BUILD_TYPE STREQUAL "Debug" OR
                                  CMAKE_BUILD_TYPE STREQUAL "RelWithSan" OR
                                  CMAKE_BUILD_TYPE STREQUAL "Sanitize"))
            message(STATUS "  -> MI_TRACK_ASAN enabled (mimalloc + ASan integration)")
            add_compile_definitions(MI_TRACK_ASAN=1)
            # MI_DEBUG=2 enables internal mimalloc consistency checks
            add_compile_definitions(MI_DEBUG=2)
        endif()
    else()
        message(STATUS "mimalloc not found, falling back to jemalloc")
        set(USE_MIMALLOC OFF)
    endif()
endif()

if(NOT USE_MIMALLOC OR NOT HAVE_MIMALLOC)
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
            message(FATAL_ERROR "No memory allocator found. Install jemalloc-devel or mimalloc-devel")
        endif()
    endif()
    message(STATUS "Found jemalloc: ${JEMALLOC_VERSION}")
    set(ALLOCATOR_TARGET PkgConfig::JEMALLOC)
    set(HAVE_JEMALLOC TRUE)
endif()

# --- Pattern matching engine ---
# vectorscan (portable hyperscan fork) provides O(n) linear-time matching
# Falls back to hyperscan, then pcre2
if(USE_VECTORSCAN)
    # Try vectorscan first (portable, works without AVX-512)
    pkg_check_modules(VECTORSCAN IMPORTED_TARGET ${SPLIFF_STATIC_KEYWORD} vectorscan)
    if(VECTORSCAN_FOUND)
        message(STATUS "Found vectorscan: ${VECTORSCAN_VERSION} (O(n) NFA engine)")
        set(PATTERN_TARGET PkgConfig::VECTORSCAN)
        set(HAVE_VECTORSCAN TRUE)
    else()
        # Try direct search for vectorscan
        find_path(VECTORSCAN_INCLUDE_DIR hs/hs.h PATH_SUFFIXES vectorscan)
        find_library(VECTORSCAN_LIBRARY NAMES hs vectorscan)
        if(VECTORSCAN_INCLUDE_DIR AND VECTORSCAN_LIBRARY)
            message(STATUS "Found vectorscan via direct search (O(n) NFA engine)")
            add_library(VECTORSCAN_TARGET INTERFACE IMPORTED)
            target_include_directories(VECTORSCAN_TARGET INTERFACE ${VECTORSCAN_INCLUDE_DIR})
            # Static vectorscan needs C++ standard library and math library
            if(ENABLE_STATIC_LIBS)
                target_link_libraries(VECTORSCAN_TARGET INTERFACE ${VECTORSCAN_LIBRARY} stdc++ m)
            else()
                target_link_libraries(VECTORSCAN_TARGET INTERFACE ${VECTORSCAN_LIBRARY})
            endif()
            set(PATTERN_TARGET VECTORSCAN_TARGET)
            set(HAVE_VECTORSCAN TRUE)
        else()
            # Try Intel hyperscan as fallback
            pkg_check_modules(HYPERSCAN IMPORTED_TARGET ${SPLIFF_STATIC_KEYWORD} hyperscan)
            if(HYPERSCAN_FOUND)
                message(STATUS "Found hyperscan: ${HYPERSCAN_VERSION} (O(n) NFA engine)")
                set(PATTERN_TARGET PkgConfig::HYPERSCAN)
                set(HAVE_HYPERSCAN TRUE)
            else()
                find_path(HYPERSCAN_INCLUDE_DIR hs/hs.h)
                find_library(HYPERSCAN_LIBRARY NAMES hs hyperscan)
                if(HYPERSCAN_INCLUDE_DIR AND HYPERSCAN_LIBRARY)
                    message(STATUS "Found hyperscan via direct search (O(n) NFA engine)")
                    add_library(HYPERSCAN_TARGET INTERFACE IMPORTED)
                    target_include_directories(HYPERSCAN_TARGET INTERFACE ${HYPERSCAN_INCLUDE_DIR})
                    target_link_libraries(HYPERSCAN_TARGET INTERFACE ${HYPERSCAN_LIBRARY})
                    set(PATTERN_TARGET HYPERSCAN_TARGET)
                    set(HAVE_HYPERSCAN TRUE)
                else()
                    message(STATUS "vectorscan/hyperscan not found, falling back to pcre2")
                    set(USE_VECTORSCAN OFF)
                endif()
            endif()
        endif()
    endif()
endif()

# Fallback to pcre2 (still needed for some features, always required)
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
        message(FATAL_ERROR "pcre2 not found. Install pcre2-devel (Fedora) or libpcre2-dev (Debian)")
    endif()
endif()
message(STATUS "Found pcre2: ${PCRE2_VERSION}")

# If no vectorscan/hyperscan, use pcre2 as pattern engine
if(NOT HAVE_VECTORSCAN AND NOT HAVE_HYPERSCAN)
    set(PATTERN_TARGET PkgConfig::PCRE2)
    set(HAVE_PCRE2_PATTERNS TRUE)
    message(STATUS "Using pcre2 for pattern matching (backtracking engine)")
endif()

# --- Build tools ---
find_program(CLANG_EXECUTABLE clang REQUIRED)
message(STATUS "Found clang: ${CLANG_EXECUTABLE}")

find_program(STRIP_EXECUTABLE strip REQUIRED)
message(STATUS "Found strip: ${STRIP_EXECUTABLE}")

# ============================================================================
# Source Files
# ============================================================================

set(SPLIFF_SOURCES
    src/main.c
    src/util/safe_str.c
    src/content/signatures.c
    src/content/decompressor.c
    # Protocol parsing and detection
    src/protocol/http1.c
    src/protocol/http2.c
    src/protocol/detector.c      # Vectorscan-powered protocol detection (v0.9.5)
    # BPF infrastructure
    src/bpf/bpf_loader.c
    src/bpf/binary_scanner.c
    src/bpf/probe_handler.c
    # Output formatting
    src/output/display.c
    # Correlation (unified flow context with dual indexes)
    src/correlation/flow_context.c
    # Threading subsystem
    src/threading/pool.c
    src/threading/state.c
    src/threading/worker.c
    src/threading/dispatcher.c
    src/threading/output.c
    src/threading/manager.c
)

# ============================================================================
# BPF Program Compilation
# ============================================================================

set(BPF_SOURCE ${CMAKE_SOURCE_DIR}/src/bpf/spliff.bpf.c)
set(BPF_OBJECT ${CMAKE_BINARY_DIR}/spliff.bpf.o)

# BPF include paths for architecture
if(EXISTS ${ARCH_INCLUDE_PATH})
    set(BPF_ARCH_INCLUDE "-I${ARCH_INCLUDE_PATH}")
else()
    set(BPF_ARCH_INCLUDE "")
endif()

add_custom_command(
    OUTPUT ${BPF_OBJECT}
    COMMAND ${CLANG_EXECUTABLE}
        -g -O2
        -target bpf
        -D__TARGET_ARCH_${BPF_ARCH}
        -I${CMAKE_SOURCE_DIR}/src/bpf
        ${BPF_ARCH_INCLUDE}
        -c ${BPF_SOURCE}
        -o ${BPF_OBJECT}
    DEPENDS ${BPF_SOURCE}
    COMMENT "Compiling BPF program for ${BPF_ARCH}..."
    VERBATIM
)

# Generate BPF skeleton header (embeds BPF bytecode + BTF for CO-RE)
# This allows stripping the final binary while keeping BPF functional
set(BPF_SKELETON ${CMAKE_BINARY_DIR}/spliff.skel.h)
add_custom_command(
    OUTPUT ${BPF_SKELETON}
    COMMAND bpftool gen skeleton ${BPF_OBJECT} > ${BPF_SKELETON}
    DEPENDS ${BPF_OBJECT}
    COMMENT "Generating BPF skeleton (CO-RE enabled, strip-safe)..."
    VERBATIM
)

add_custom_target(bpf_skeleton ALL DEPENDS ${BPF_SKELETON})

# ============================================================================
# Main Executable
# ============================================================================

add_executable(spliff ${SPLIFF_SOURCES})

# Add dependency on BPF skeleton (which depends on BPF object)
add_dependencies(spliff bpf_skeleton)

# Include directories (add build dir for generated skeleton header)
target_include_directories(spliff PRIVATE
    ${CMAKE_SOURCE_DIR}/src/include
    ${CMAKE_BINARY_DIR}
)

# Full static linking support for portable binary
if(ENABLE_FULL_STATIC)
    message(STATUS "Full static linking: enabled")
    # Use -static for all libraries except glibc
    # glibc static linking has NSS/DNS issues, so we link it dynamically
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc")

    # Find static libraries explicitly
    find_library(LIBBPF_STATIC NAMES libbpf.a PATHS /usr/lib64 /usr/lib)
    find_library(LIBELF_STATIC NAMES libelf.a PATHS /usr/lib64 /usr/lib)
    find_library(ZLIB_NG_STATIC NAMES libz-ng.a PATHS /usr/lib64 /usr/lib)
    find_library(ZSTD_STATIC NAMES libzstd.a PATHS /usr/lib64 /usr/lib)
    find_library(BROTLIDEC_STATIC NAMES libbrotlidec.a PATHS /usr/lib64 /usr/lib)
    find_library(BROTLICOMMON_STATIC NAMES libbrotlicommon.a PATHS /usr/lib64 /usr/lib)
    find_library(LLHTTP_STATIC NAMES libllhttp.a PATHS /usr/lib64 /usr/lib)
    find_library(NGHTTP2_STATIC NAMES libnghttp2.a PATHS /usr/lib64 /usr/lib)
    find_library(CK_STATIC NAMES libck.a PATHS /usr/lib64 /usr/lib)
    find_library(XDP_STATIC NAMES libxdp.a PATHS /usr/lib64 /usr/lib)
    find_library(URCU_STATIC NAMES liburcu-memb.a PATHS /usr/lib64 /usr/lib)
    find_library(URCU_COMMON_STATIC NAMES liburcu-common.a PATHS /usr/lib64 /usr/lib)
    find_library(JEMALLOC_STATIC NAMES libjemalloc.a PATHS /usr/lib64 /usr/lib)
    find_library(PCRE2_STATIC NAMES libpcre2-8.a PATHS /usr/lib64 /usr/lib)
    find_library(HS_STATIC NAMES libhs.a PATHS /usr/local/lib64 /usr/local/lib /usr/lib64 /usr/lib)
    find_library(HS_RUNTIME_STATIC NAMES libhs_runtime.a PATHS /usr/local/lib64 /usr/local/lib /usr/lib64 /usr/lib)

    # Link static libraries
    target_link_libraries(spliff PRIVATE
        # Use whole-archive for some libraries to ensure all symbols are included
        -Wl,--whole-archive
        ${LIBBPF_STATIC}
        -Wl,--no-whole-archive
        ${LIBELF_STATIC}
        ${ZLIB_NG_STATIC}
        ${ZSTD_STATIC}
        ${BROTLIDEC_STATIC}
        ${BROTLICOMMON_STATIC}
        ${LLHTTP_STATIC}
        ${NGHTTP2_STATIC}
        ${CK_STATIC}
        ${XDP_STATIC}
        ${URCU_STATIC}
        ${URCU_COMMON_STATIC}
        ${JEMALLOC_STATIC}
        ${HS_STATIC}
        ${HS_RUNTIME_STATIC}
        ${PCRE2_STATIC}
        # System libraries (dynamic)
        pthread
        dl
        m
        stdc++
        z
    )
else()
    # Link all required libraries (dynamic)
    target_link_libraries(spliff PRIVATE
        # Core BPF
        PkgConfig::LIBBPF
        PkgConfig::LIBELF
        # Compression (zlib-ng or zlib)
        ${ZLIB_TARGET}
        PkgConfig::ZSTD
        PkgConfig::BROTLI
        # HTTP parsing
        PkgConfig::LLHTTP
        PkgConfig::NGHTTP2
        # Threading and concurrency
        PkgConfig::CK
        PkgConfig::LIBXDP
        PkgConfig::LIBURCU
        # Memory allocator (mimalloc or jemalloc)
        ${ALLOCATOR_TARGET}
        # Pattern matching (vectorscan, hyperscan, or pcre2)
        ${PATTERN_TARGET}
        PkgConfig::PCRE2
        # POSIX threads
        pthread
    )
endif()

# Compile definitions for all features
target_compile_definitions(spliff PRIVATE
    PCRE2_CODE_UNIT_WIDTH=8
)

# Strip release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET spliff POST_BUILD
        COMMAND ${STRIP_EXECUTABLE} --strip-all $<TARGET_FILE:spliff>
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

# HTTP/1.1 parser tests
add_executable(test_http1 EXCLUDE_FROM_ALL
    tests/test_http1.c
    tests/test_common.c
    ${TEST_COMMON_SOURCES}
)
target_include_directories(test_http1 PRIVATE ${CMAKE_SOURCE_DIR}/src/include)
target_link_libraries(test_http1 PRIVATE
    PkgConfig::LLHTTP
    PkgConfig::NGHTTP2
    ${ZLIB_TARGET}
    PkgConfig::ZSTD
    PkgConfig::BROTLI
)
target_compile_definitions(test_http1 PRIVATE
    PCRE2_CODE_UNIT_WIDTH=8
)
add_test(NAME http1_parser_tests COMMAND test_http1)

# HTTP/2 parser tests
add_executable(test_http2 EXCLUDE_FROM_ALL
    tests/test_http2.c
    tests/test_common.c
    ${TEST_COMMON_SOURCES}
)
target_include_directories(test_http2 PRIVATE ${CMAKE_SOURCE_DIR}/src/include)
target_link_libraries(test_http2 PRIVATE
    PkgConfig::LLHTTP
    PkgConfig::NGHTTP2
    ${ZLIB_TARGET}
    PkgConfig::ZSTD
    PkgConfig::BROTLI
)
target_compile_definitions(test_http2 PRIVATE
    PCRE2_CODE_UNIT_WIDTH=8
)
add_test(NAME http2_parser_tests COMMAND test_http2)

# XDP structure tests
add_executable(test_xdp EXCLUDE_FROM_ALL
    tests/test_xdp.c
    tests/test_common.c
    src/bpf/bpf_loader.c
    src/util/safe_str.c
)
target_include_directories(test_xdp PRIVATE ${CMAKE_SOURCE_DIR}/src/include)
target_link_libraries(test_xdp PRIVATE
    PkgConfig::LIBBPF
    PkgConfig::LIBELF
)
add_test(NAME xdp_structure_tests COMMAND test_xdp)

# Custom target to build all tests
add_custom_target(build_tests
    DEPENDS test_http1 test_http2 test_xdp
    COMMENT "Building all test executables..."
)

# ============================================================================
# Documentation (Doxygen)
# ============================================================================

find_package(Doxygen OPTIONAL_COMPONENTS dot)

if(DOXYGEN_FOUND)
    message(STATUS "Doxygen found: ${DOXYGEN_EXECUTABLE}")
    message(STATUS "  Version: ${DOXYGEN_VERSION}")

    # Configure Doxyfile from project root
    set(DOXYFILE_IN ${CMAKE_SOURCE_DIR}/Doxyfile)

    if(EXISTS ${DOXYFILE_IN})
        # Create docs target that runs doxygen
        add_custom_target(docs
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_IN}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMENT "Generating API documentation with Doxygen..."
            VERBATIM
        )

        # Create clean-docs target
        add_custom_target(clean-docs
            COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/docs
            COMMENT "Removing generated documentation..."
            VERBATIM
        )

        message(STATUS "  Target 'docs' available for documentation generation")
        message(STATUS "  Target 'clean-docs' available for cleanup")
    else()
        message(STATUS "  Doxyfile not found at ${DOXYFILE_IN}")
    endif()

    # Check for Graphviz dot (CMake uses mixed-case variable names for components)
    if(Doxygen_dot_FOUND OR DOXYGEN_DOT_FOUND OR DOXYGEN_DOT_EXECUTABLE)
        message(STATUS "  Graphviz dot: ${DOXYGEN_DOT_EXECUTABLE} (diagrams enabled)")
    else()
        message(STATUS "  Graphviz dot: not found (diagrams disabled)")
        message(STATUS "    Install with: dnf install graphviz (Fedora)")
    endif()
else()
    message(STATUS "Doxygen not found - documentation target disabled")
    message(STATUS "  Install with: dnf install doxygen graphviz (Fedora)")
    message(STATUS "             or: apt install doxygen graphviz (Debian/Ubuntu)")
endif()

# ============================================================================
# Installation
# ============================================================================

include(GNUInstallDirs)

# Install binary
install(TARGETS spliff
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# ============================================================================
# CPack Configuration for Packaging
# ============================================================================

set(CPACK_PACKAGE_NAME "spliff")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_VENDOR "spliff developers")
set(CPACK_PACKAGE_CONTACT "9083405+NoFear0411@users.noreply.github.com")
set(CPACK_PACKAGE_DESCRIPTION "Capture and inspect decrypted HTTPS traffic in real-time using eBPF uprobes. Supports OpenSSL, GnuTLS, NSS, WolfSSL, and BoringSSL with full HTTP/1.1 and HTTP/2 protocol parsing, XDP packet-level flow tracking, and multi-threaded lock-free processing.")
set(CPACK_RPM_PACKAGE_DESCRIPTION "${CPACK_PACKAGE_DESCRIPTION}")
set(CPACK_RPM_PACKAGE_URL "https://github.com/NoFear0411/spliff")

# License file
if(EXISTS "${CMAKE_SOURCE_DIR}/LICENSE")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
endif()

# ============================================================================
# Distribution Detection for Package Dependencies
# ============================================================================

set(LINUX_DISTRO "unknown")
set(LINUX_DISTRO_VERSION "")

if(EXISTS "/etc/os-release")
    file(STRINGS "/etc/os-release" OS_RELEASE_CONTENTS)
    foreach(line ${OS_RELEASE_CONTENTS})
        if(line MATCHES "^ID=(.*)$")
            string(REGEX REPLACE "^ID=\"?([^\"]*)\"?$" "\\1" LINUX_DISTRO "${line}")
        endif()
        if(line MATCHES "^VERSION_ID=(.*)$")
            string(REGEX REPLACE "^VERSION_ID=\"?([^\"]*)\"?$" "\\1" LINUX_DISTRO_VERSION "${line}")
        endif()
    endforeach()
endif()

message(STATUS "Detected distribution: ${LINUX_DISTRO} ${LINUX_DISTRO_VERSION}")

# Generate dist tag for RPM naming (e.g., .fc43, .el10)
set(RPM_DIST_TAG "")
if(LINUX_DISTRO STREQUAL "fedora")
    # Strip minor version — Fedora uses major only (e.g., fc43)
    string(REGEX REPLACE "\\..*" "" _DISTRO_MAJOR "${LINUX_DISTRO_VERSION}")
    set(RPM_DIST_TAG ".fc${_DISTRO_MAJOR}")
elseif(LINUX_DISTRO STREQUAL "almalinux" OR
       LINUX_DISTRO STREQUAL "rocky" OR
       LINUX_DISTRO STREQUAL "rhel" OR
       LINUX_DISTRO STREQUAL "centos")
    string(REGEX REPLACE "\\..*" "" _DISTRO_MAJOR "${LINUX_DISTRO_VERSION}")
    set(RPM_DIST_TAG ".el${_DISTRO_MAJOR}")
endif()

# ============================================================================
# Debian/Ubuntu Package Configuration (local builds only)
# ============================================================================

# Standard naming: <name>_<version>-<release>_<arch>.deb
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_RELEASE "1")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")

# ============================================================================
# RPM Package Configuration (Fedora/RHEL/Alma)
# ============================================================================

# Standard naming: <name>-<version>-<release>.<dist>.<arch>.rpm
set(CPACK_RPM_PACKAGE_RELEASE "1${RPM_DIST_TAG}")
set(CPACK_RPM_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_RPM_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}.rpm")
set(CPACK_RPM_PACKAGE_LICENSE "GPL-3.0")
set(CPACK_RPM_PACKAGE_GROUP "Applications/System")

# Use automatic dependency detection for RPM
# This handles differences between Fedora 42/43, AlmaLinux 9/10, etc.
set(CPACK_RPM_PACKAGE_AUTOREQ ON)
set(CPACK_RPM_PACKAGE_AUTOPROV ON)

# Disable auto-provides when static linking (prevents advertising embedded libs)
if(ENABLE_STATIC_LIBS)
    set(CPACK_RPM_PACKAGE_AUTOPROV OFF)
endif()

# Minimal explicit dependencies (auto-req will add the rest)
# Note: On AlmaLinux some libs are built from source and won't have packages
set(CPACK_RPM_PACKAGE_REQUIRES "glibc")

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
message(STATUS "Architecture:     ${MACHINE_ARCH} (BPF: ${BPF_ARCH})")
message(STATUS "")
message(STATUS "Core Dependencies:")
message(STATUS "  libbpf:         ${LIBBPF_VERSION}")
message(STATUS "  libelf:         ${LIBELF_VERSION}")
message(STATUS "  llhttp:         ${LLHTTP_VERSION}")
message(STATUS "  nghttp2:        ${NGHTTP2_VERSION}")
message(STATUS "  ck:             ${CK_VERSION}")
message(STATUS "  libxdp:         ${LIBXDP_VERSION}")
message(STATUS "  liburcu:        ${LIBURCU_VERSION}")
message(STATUS "  pcre2:          ${PCRE2_VERSION}")
message(STATUS "")
message(STATUS "Performance Libraries (v0.9.5 Golden Thread):")
if(HAVE_ZLIB_NG)
    message(STATUS "  Compression:    zlib-ng ${ZLIB_NG_VERSION} (SIMD-accelerated)")
else()
    message(STATUS "  Compression:    zlib ${ZLIB_VERSION}")
endif()
message(STATUS "  + zstd:         ${ZSTD_VERSION}")
message(STATUS "  + brotli:       ${BROTLI_VERSION}")
if(HAVE_MIMALLOC)
    message(STATUS "  Allocator:      mimalloc ${MIMALLOC_VERSION} (low-latency)")
else()
    message(STATUS "  Allocator:      jemalloc ${JEMALLOC_VERSION}")
endif()
if(HAVE_VECTORSCAN)
    message(STATUS "  Pattern engine: vectorscan ${VECTORSCAN_VERSION} (O(n) NFA)")
elseif(HAVE_HYPERSCAN)
    message(STATUS "  Pattern engine: hyperscan ${HYPERSCAN_VERSION} (O(n) NFA)")
else()
    message(STATUS "  Pattern engine: pcre2 ${PCRE2_VERSION} (backtracking)")
endif()
message(STATUS "")
message(STATUS "Build Options:")
message(STATUS "  Sanitizers:     ${ENABLE_SANITIZERS}")
message(STATUS "  Coverage:       ${ENABLE_COVERAGE}")
message(STATUS "  LTO:            ${CMAKE_INTERPROCEDURAL_OPTIMIZATION}")
message(STATUS "  USE_VECTORSCAN: ${USE_VECTORSCAN}")
message(STATUS "  USE_ZLIB_NG:    ${USE_ZLIB_NG}")
message(STATUS "  USE_MIMALLOC:   ${USE_MIMALLOC}")
message(STATUS "  STATIC_LIBS:    ${ENABLE_STATIC_LIBS}")
message(STATUS "")
message(STATUS "Features:")
message(STATUS "  HTTP/1.1:       ON (llhttp)")
message(STATUS "  HTTP/2:         ON (nghttp2)")
message(STATUS "  Compression:    ON (zlib/zlib-ng, zstd, brotli)")
message(STATUS "  Threading:      ON (ck)")
message(STATUS "  XDP capture:    ON (libxdp)")
message(STATUS "  RCU support:    ON (liburcu)")
message(STATUS "  Protocol detect:ON (vectorscan/hyperscan/pcre2)")
message(STATUS "")
