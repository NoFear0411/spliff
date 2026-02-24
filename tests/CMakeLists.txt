# spliff test targets
#
# Test architecture:
#   Heavy tests    — link spliff_core + spliff_memory + spliff_common_deps
#   Ring tests     — link spliff_ring + spliff_memory + CK + pthread
#   Lightweight    — direct sources only, no object libraries

# ============================================================================
# Shared Test Dependencies
# ============================================================================

# INTERFACE library wrapping the 9 link deps shared by heavy test targets.
# FIX: Previously each test hardcoded PkgConfig::JEMALLOC, breaking mimalloc builds.
# Now uses ${ALLOCATOR_TARGET} which resolves to whichever allocator was configured.
add_library(spliff_common_deps INTERFACE)
target_link_libraries(spliff_common_deps INTERFACE
    PkgConfig::LLHTTP
    PkgConfig::NGHTTP2
    PkgConfig::CK
    ${ALLOCATOR_TARGET}
    PkgConfig::LIBURCU
    PkgConfig::LIBURCU_CDS
    ${ZLIB_TARGET}
    PkgConfig::ZSTD
    PkgConfig::BROTLI
)

# ============================================================================
# Heavy Tests — spliff_core + spliff_memory + common deps
# ============================================================================
# These tests exercise flow_context and its transitive dependencies.
# test_common.c / test_stubs.c are listed directly per target since usage varies.

# HTTP/1.1 parser tests
add_executable(test_http1 EXCLUDE_FROM_ALL
    test_http1.c
    test_common.c
    test_stubs.c
    $<TARGET_OBJECTS:spliff_core>
    $<TARGET_OBJECTS:spliff_memory>
)
target_include_directories(test_http1 PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
target_link_libraries(test_http1 PRIVATE spliff_common_deps)
add_test(NAME http1_parser_tests COMMAND test_http1)

# HTTP/2 parser tests
add_executable(test_http2 EXCLUDE_FROM_ALL
    test_http2.c
    test_stubs.c
    $<TARGET_OBJECTS:spliff_core>
    $<TARGET_OBJECTS:spliff_memory>
)
target_include_directories(test_http2 PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
target_link_libraries(test_http2 PRIVATE spliff_common_deps)
add_test(NAME http2_parser_tests COMMAND test_http2)

# Flow context tests (core state management)
add_executable(test_flow_context EXCLUDE_FROM_ALL
    test_flow_context.c
    test_stubs.c
    $<TARGET_OBJECTS:spliff_core>
    $<TARGET_OBJECTS:spliff_memory>
)
target_include_directories(test_flow_context PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
target_link_libraries(test_flow_context PRIVATE spliff_common_deps)
add_test(NAME flow_context_tests COMMAND test_flow_context)

# Flow refcount + plaintext tests (lifecycle management)
add_executable(test_flow_refcount EXCLUDE_FROM_ALL
    test_flow_refcount.c
    test_stubs.c
    $<TARGET_OBJECTS:spliff_core>
    $<TARGET_OBJECTS:spliff_memory>
)
target_include_directories(test_flow_refcount PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
target_link_libraries(test_flow_refcount PRIVATE spliff_common_deps)
add_test(NAME flow_refcount_tests COMMAND test_flow_refcount)

# Protocol detector tests (vectorscan patterns)
add_executable(test_detector EXCLUDE_FROM_ALL
    test_detector.c
    test_common.c
    test_stubs.c
    ${PROJECT_SOURCE_DIR}/src/protocol/detector.c
    $<TARGET_OBJECTS:spliff_core>
    $<TARGET_OBJECTS:spliff_memory>
)
target_include_directories(test_detector PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
target_link_libraries(test_detector PRIVATE spliff_common_deps ${PATTERN_TARGET})
target_compile_definitions(test_detector PRIVATE PCRE2_CODE_UNIT_WIDTH=8)
add_test(NAME detector_tests COMMAND test_detector)

# ============================================================================
# Ring Tests — spliff_ring + spliff_memory + CK + pthread
# ============================================================================

# SPMC ring tests (lock-free transport)
add_executable(test_spmc_ring EXCLUDE_FROM_ALL
    test_spmc_ring.c
    $<TARGET_OBJECTS:spliff_ring>
    $<TARGET_OBJECTS:spliff_memory>
)
target_include_directories(test_spmc_ring PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
target_link_libraries(test_spmc_ring PRIVATE PkgConfig::CK pthread)
add_test(NAME spmc_ring_tests COMMAND test_spmc_ring)

# Concurrent stress tests (lock-free verification)
add_executable(test_concurrent EXCLUDE_FROM_ALL
    test_concurrent.c
    $<TARGET_OBJECTS:spliff_ring>
    $<TARGET_OBJECTS:spliff_memory>
)
target_include_directories(test_concurrent PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
target_link_libraries(test_concurrent PRIVATE PkgConfig::CK pthread)
add_test(NAME concurrent_tests COMMAND test_concurrent)

# Worker dequeue + adaptive poll tests (worker consumption)
add_executable(test_worker_dequeue EXCLUDE_FROM_ALL
    test_worker_dequeue.c
    $<TARGET_OBJECTS:spliff_ring>
    $<TARGET_OBJECTS:spliff_memory>
)
target_include_directories(test_worker_dequeue PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
target_link_libraries(test_worker_dequeue PRIVATE PkgConfig::CK pthread)
add_test(NAME worker_dequeue_tests COMMAND test_worker_dequeue)

# ============================================================================
# Lightweight Tests — direct sources, no object libraries
# ============================================================================

# Affinity + MPSC overflow tests (worker routing)
add_executable(test_affinity EXCLUDE_FROM_ALL
    test_affinity.c
    ${PROJECT_SOURCE_DIR}/src/ring/affinity.c
)
target_include_directories(test_affinity PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
target_link_libraries(test_affinity PRIVATE PkgConfig::CK pthread)
add_test(NAME affinity_tests COMMAND test_affinity)

# Backpressure state machine tests (flow control)
add_executable(test_backpressure EXCLUDE_FROM_ALL
    test_backpressure.c
    ${PROJECT_SOURCE_DIR}/src/ring/backpressure.c
)
target_include_directories(test_backpressure PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
add_test(NAME backpressure_tests COMMAND test_backpressure)

# XDP structure tests
add_executable(test_xdp EXCLUDE_FROM_ALL
    test_xdp.c
    test_common.c
    ${PROJECT_SOURCE_DIR}/src/bpf/bpf_loader.c
    ${PROJECT_SOURCE_DIR}/src/bpf/binary_scanner.c
    ${PROJECT_SOURCE_DIR}/src/util/safe_str.c
)
target_include_directories(test_xdp PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
target_link_libraries(test_xdp PRIVATE PkgConfig::LIBBPF PkgConfig::LIBELF)
add_test(NAME xdp_structure_tests COMMAND test_xdp)

# Safe string tests (security foundation)
add_executable(test_safe_str EXCLUDE_FROM_ALL
    test_safe_str.c
    ${PROJECT_SOURCE_DIR}/src/util/safe_str.c
)
target_include_directories(test_safe_str PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
add_test(NAME safe_str_tests COMMAND test_safe_str)

# Mirrored buffer tests (memory infrastructure)
add_executable(test_mirrored_buffer EXCLUDE_FROM_ALL
    test_mirrored_buffer.c
    $<TARGET_OBJECTS:spliff_memory>
    ${PROJECT_SOURCE_DIR}/src/memory/hugepage.c
)
target_include_directories(test_mirrored_buffer PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
add_test(NAME mirrored_buffer_tests COMMAND test_mirrored_buffer)

# Decompressor tests (content handling)
add_executable(test_decompressor EXCLUDE_FROM_ALL
    test_decompressor.c
    ${PROJECT_SOURCE_DIR}/src/content/decompressor.c
)
target_include_directories(test_decompressor PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
target_link_libraries(test_decompressor PRIVATE ${ZLIB_TARGET} PkgConfig::ZSTD PkgConfig::BROTLI)
add_test(NAME decompressor_tests COMMAND test_decompressor)

# Streaming decompressor tests (per-flow streaming)
add_executable(test_stream_decompressor EXCLUDE_FROM_ALL
    test_stream_decompressor.c
    ${PROJECT_SOURCE_DIR}/src/content/stream_decompressor.c
    ${PROJECT_SOURCE_DIR}/src/content/decompressor.c
)
target_include_directories(test_stream_decompressor PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
target_link_libraries(test_stream_decompressor PRIVATE ${ZLIB_TARGET} PkgConfig::ZSTD PkgConfig::BROTLI)
add_test(NAME stream_decompressor_tests COMMAND test_stream_decompressor)

# WebSocket parser tests (protocol handling)
add_executable(test_websocket EXCLUDE_FROM_ALL
    test_websocket.c
    ${PROJECT_SOURCE_DIR}/src/protocol/websocket.c
)
target_include_directories(test_websocket PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
add_test(NAME websocket_tests COMMAND test_websocket)

# Display module tests (output formatting) — stays manual to avoid pulling
# flow_context.c dependencies (LLHTTP/NGHTTP2) that test_display doesn't need
add_executable(test_display EXCLUDE_FROM_ALL
    test_display.c
    test_common.c
    test_stubs.c
    ${PROJECT_SOURCE_DIR}/src/output/display.c
    ${PROJECT_SOURCE_DIR}/src/output/logger.c
    ${PROJECT_SOURCE_DIR}/src/content/signatures.c
)
target_include_directories(test_display PRIVATE ${PROJECT_SOURCE_DIR}/src/include)
target_link_libraries(test_display PRIVATE PkgConfig::CK)
add_test(NAME display_tests COMMAND test_display)

# ============================================================================
# CTest Labels — enable module-level test filtering
# ============================================================================

set_tests_properties(
    spmc_ring_tests affinity_tests concurrent_tests
    backpressure_tests worker_dequeue_tests
    PROPERTIES LABELS "ring"
)

set_tests_properties(
    http1_parser_tests http2_parser_tests
    websocket_tests detector_tests
    PROPERTIES LABELS "protocol"
)

set_tests_properties(
    flow_context_tests flow_refcount_tests
    PROPERTIES LABELS "flow"
)

set_tests_properties(
    decompressor_tests stream_decompressor_tests
    PROPERTIES LABELS "content"
)

set_tests_properties(
    mirrored_buffer_tests
    PROPERTIES LABELS "memory"
)

set_tests_properties(
    safe_str_tests display_tests xdp_structure_tests
    PROPERTIES LABELS "util"
)

# ============================================================================
# Build Group Targets — for Makefile module-level builds
# ============================================================================

add_custom_target(build_tests DEPENDS
    test_http1 test_http2 test_xdp test_safe_str test_mirrored_buffer
    test_spmc_ring test_affinity test_concurrent test_backpressure test_worker_dequeue
    test_flow_context test_flow_refcount test_decompressor test_stream_decompressor
    test_detector test_websocket test_display
    COMMENT "Building all test executables..."
)

add_custom_target(build_tests_ring DEPENDS
    test_spmc_ring test_affinity test_concurrent
    test_backpressure test_worker_dequeue
)

add_custom_target(build_tests_protocol DEPENDS
    test_http1 test_http2 test_websocket test_detector
)

add_custom_target(build_tests_flow DEPENDS
    test_flow_context test_flow_refcount
)

add_custom_target(build_tests_content DEPENDS
    test_decompressor test_stream_decompressor
)

add_custom_target(build_tests_memory DEPENDS
    test_mirrored_buffer
)

add_custom_target(build_tests_util DEPENDS
    test_safe_str test_display test_xdp
)
