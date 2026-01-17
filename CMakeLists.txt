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

# --- Core BPF dependencies ---
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
message(STATUS "Found libbpf: ${LIBBPF_VERSION}")

pkg_check_modules(LIBELF REQUIRED IMPORTED_TARGET libelf)
message(STATUS "Found libelf: ${LIBELF_VERSION}")

# --- Compression dependencies ---
pkg_check_modules(ZLIB REQUIRED IMPORTED_TARGET zlib)
message(STATUS "Found zlib: ${ZLIB_VERSION}")

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
        message(FATAL_ERROR "jemalloc not found. Install jemalloc-devel (Fedora) or libjemalloc-dev (Debian)")
    endif()
endif()
message(STATUS "Found jemalloc: ${JEMALLOC_VERSION}")

# --- Pattern matching ---
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
    src/protocol/http1.c
    src/protocol/http2.c
    src/bpf/bpf_loader.c
    src/bpf/binary_scanner.c
    src/bpf/probe_handler.c
    src/output/display.c
    # Threading sources (required)
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

# Link all required libraries
target_link_libraries(spliff PRIVATE
    PkgConfig::LIBBPF
    PkgConfig::LIBELF
    PkgConfig::ZLIB
    PkgConfig::ZSTD
    PkgConfig::BROTLI
    PkgConfig::LLHTTP
    PkgConfig::NGHTTP2
    PkgConfig::CK
    PkgConfig::LIBXDP
    PkgConfig::LIBURCU
    PkgConfig::JEMALLOC
    PkgConfig::PCRE2
    pthread
)

# Compile definitions for all features
target_compile_definitions(spliff PRIVATE
    HAVE_LLHTTP
    HAVE_NGHTTP2
    HAVE_ZSTD
    HAVE_BROTLI
    HAVE_THREADING
    HAVE_XDP
    HAVE_LIBURCU
    HAVE_JEMALLOC
    HAVE_PCRE2
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
    PkgConfig::ZLIB
    PkgConfig::ZSTD
    PkgConfig::BROTLI
)
target_compile_definitions(test_http1 PRIVATE
    HAVE_LLHTTP HAVE_NGHTTP2 HAVE_ZSTD HAVE_BROTLI
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
    PkgConfig::ZLIB
    PkgConfig::ZSTD
    PkgConfig::BROTLI
)
target_compile_definitions(test_http2 PRIVATE
    HAVE_LLHTTP HAVE_NGHTTP2 HAVE_ZSTD HAVE_BROTLI
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

# ============================================================================
# Debian/Ubuntu Package Configuration
# ============================================================================

# Standard naming: <name>_<version>-<release>_<arch>.deb
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_RELEASE "1")

# Architecture detection
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "arm64")
else()
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "${CMAKE_SYSTEM_PROCESSOR}")
endif()

# Use automatic shared library dependency detection
# This properly handles different library versions across Debian 12/13, Ubuntu, etc.
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

# Fallback dependencies (used if shlibdeps fails or for static builds)
# Note: Package names vary by version (e.g., liburcu8 vs liburcu8t64)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")

# ============================================================================
# RPM Package Configuration (Fedora/RHEL/Alma)
# ============================================================================

# Standard naming: <name>-<version>-<release>.<arch>.rpm
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_RELEASE "1")
set(CPACK_RPM_PACKAGE_LICENSE "GPL-3.0")
set(CPACK_RPM_PACKAGE_GROUP "Applications/System")

# Use automatic dependency detection for RPM
# This handles differences between Fedora 42/43, AlmaLinux 9/10, etc.
set(CPACK_RPM_PACKAGE_AUTOREQ ON)
set(CPACK_RPM_PACKAGE_AUTOPROV ON)

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
message(STATUS "Required Dependencies (all found):")
message(STATUS "  libbpf:         ${LIBBPF_VERSION}")
message(STATUS "  libelf:         ${LIBELF_VERSION}")
message(STATUS "  zlib:           ${ZLIB_VERSION}")
message(STATUS "  zstd:           ${ZSTD_VERSION}")
message(STATUS "  brotli:         ${BROTLI_VERSION}")
message(STATUS "  llhttp:         ${LLHTTP_VERSION}")
message(STATUS "  nghttp2:        ${NGHTTP2_VERSION}")
message(STATUS "  ck:             ${CK_VERSION}")
message(STATUS "  libxdp:         ${LIBXDP_VERSION}")
message(STATUS "  liburcu:        ${LIBURCU_VERSION}")
message(STATUS "  jemalloc:       ${JEMALLOC_VERSION}")
message(STATUS "  pcre2:          ${PCRE2_VERSION}")
message(STATUS "")
message(STATUS "Build Options:")
message(STATUS "  Sanitizers:     ${ENABLE_SANITIZERS}")
message(STATUS "  Coverage:       ${ENABLE_COVERAGE}")
message(STATUS "")
message(STATUS "Features (all enabled):")
message(STATUS "  HTTP/1.1:       ON (llhttp)")
message(STATUS "  HTTP/2:         ON (nghttp2)")
message(STATUS "  Compression:    ON (zlib, zstd, brotli)")
message(STATUS "  Threading:      ON (ck)")
message(STATUS "  XDP capture:    ON (libxdp)")
message(STATUS "  RCU support:    ON (liburcu)")
message(STATUS "  Memory alloc:   ON (jemalloc)")
message(STATUS "  Pattern match:  ON (pcre2)")
message(STATUS "")
