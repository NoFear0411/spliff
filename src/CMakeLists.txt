# spliff source libraries and main executable
#
# 3 OBJECT libraries enable compile-once-link-many:
#   spliff_memory  — shared by core + ring consumers
#   spliff_core    — correlation, protocol, content, threading, util
#   spliff_ring    — L1 transport layer (FROZEN)

# ============================================================================
# OBJECT Libraries
# ============================================================================

# Memory infrastructure — needed by both spliff_core (flow_context.c) and
# spliff_ring (spmc_ring.c), extracted to avoid duplicate symbols
add_library(spliff_memory OBJECT
    memory/mirrored_buffer.c
)
target_include_directories(spliff_memory PRIVATE ${PROJECT_SOURCE_DIR}/src/include)

# Core modules — the "flow_context cluster" that was previously duplicated
# across 6 test targets. Adding a dependency here now propagates automatically.
add_library(spliff_core OBJECT
    # Correlation
    correlation/flow_context.c
    correlation/ck_cookie_index.c
    correlation/ck_shadow_index.c
    # Protocol parsing
    protocol/http1.c
    protocol/http2.c
    # Output formatting
    output/display.c
    output/logger.c
    # Content handling
    content/decompressor.c
    content/stream_decompressor.c
    content/signatures.c
    # Utilities
    util/safe_str.c
    # Threading state (non-main-only parts)
    threading/state.c
    threading/deferred.c
    threading/pool.c
    threading/xdp_ring.c
)
target_include_directories(spliff_core PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
# Propagate include dirs from external deps (CMake 3.12+ OBJECT library support).
# This doesn't link anything — it just makes headers like <ck_hs.h>, <llhttp.h>,
# <nghttp2/nghttp2.h>, <zlib.h>, <zstd.h>, <brotli/decode.h> available at compile time.
target_link_libraries(spliff_core PRIVATE
    PkgConfig::CK
    PkgConfig::LLHTTP
    PkgConfig::NGHTTP2
    PkgConfig::LIBURCU
    PkgConfig::LIBURCU_CDS
    ${ALLOCATOR_TARGET}
    ${ZLIB_TARGET}
    PkgConfig::ZSTD
    PkgConfig::BROTLI
)

# Ring transport layer (Phase 2, FROZEN)
add_library(spliff_ring OBJECT
    ring/spmc_ring.c
    ring/affinity.c
    ring/backpressure.c
    ring/worker_dequeue.c
)
target_include_directories(spliff_ring PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
target_link_libraries(spliff_ring PRIVATE PkgConfig::CK)

# ============================================================================
# Main Executable
# ============================================================================

# Sources only used by the main executable (not shared with tests)
add_executable(spliff
    main.c
    util/process.c
    bpf/bpf_loader.c
    bpf/binary_scanner.c
    bpf/probe_handler.c
    output/stats.c
    protocol/detector.c
    threading/worker.c
    threading/dispatcher.c
    threading/output.c
    threading/manager.c
    memory/hugepage.c
    memory/numa_alloc.c
    $<TARGET_OBJECTS:spliff_core>
    $<TARGET_OBJECTS:spliff_ring>
    $<TARGET_OBJECTS:spliff_memory>
)

add_dependencies(spliff bpf_skeleton)

target_include_directories(spliff PRIVATE
    ${PROJECT_SOURCE_DIR}/src/include
    ${CMAKE_BINARY_DIR}
)

# Compile definitions
target_compile_definitions(spliff PRIVATE
    PCRE2_CODE_UNIT_WIDTH=8
)

# Full static linking support for portable binary
if(ENABLE_FULL_STATIC)
    message(STATUS "Full static linking: enabled")
    # FIX: was CMAKE_EXE_LINKER_FLAGS string append, now uses target_link_options
    target_link_options(spliff PRIVATE -static-libgcc)

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

    target_link_libraries(spliff PRIVATE
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
        pthread
        dl
        m
        stdc++
        z
    )
else()
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
        PkgConfig::LIBURCU_CDS
        # Memory allocator (mimalloc or jemalloc)
        ${ALLOCATOR_TARGET}
        # Pattern matching (vectorscan, hyperscan, or pcre2)
        ${PATTERN_TARGET}
        PkgConfig::PCRE2
        # POSIX threads
        pthread
    )
endif()

# Strip release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET spliff POST_BUILD
        COMMAND ${STRIP_EXECUTABLE} --strip-all $<TARGET_FILE:spliff>
        COMMENT "Stripping spliff binary..."
    )
endif()
