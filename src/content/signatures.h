/**
 * @file signatures.h
 * @brief File signature (magic bytes) detection for binary content identification
 *
 * @details This module provides file type detection based on magic bytes
 * (file signatures) at the beginning and optionally end of data. It supports
 * over 50 common file formats including:
 *
 * - **Images**: JPEG, PNG, GIF, WebP, BMP, ICO, TIFF, AVIF, JXL, HEIC
 * - **Video**: MP4, WebM, AVI, MKV, MOV, FLV
 * - **Audio**: MP3, OGG, FLAC, WAV, AIFF, M4A
 * - **Archives**: ZIP, GZIP, ZSTD, Brotli, XZ, BZ2, 7z, RAR, TAR
 * - **Documents**: PDF
 * - **Fonts**: WOFF, WOFF2, TTF, OTF, EOT
 * - **Executables**: WebAssembly, ELF, Mach-O
 * - **Databases**: SQLite
 * - **Containers**: ISOBMFF (MP4/MOV), RIFF (AVI/WAV)
 *
 * The detection system uses:
 * - Magic byte matching with variable offsets
 * - Longest-match-first priority (sorted by specificity)
 * - Optional trailer validation for container formats
 *
 * @par Usage Example:
 * @code
 * // Initialize once at startup
 * signatures_init();
 *
 * // Detect file type
 * signature_result_t result;
 * if (signature_detect_full(data, len, true, &result)) {
 *     printf("Detected: %s [%s]\n",
 *            result.description,
 *            signature_class_name(result.file_class));
 * }
 *
 * // Cleanup at shutdown
 * signatures_cleanup();
 * @endcode
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef SIGNATURES_H
#define SIGNATURES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * @defgroup signatures File Signature Detection
 * @brief Magic bytes-based file type identification
 * @{
 */

/**
 * @brief File classification categories
 *
 * Groups detected file types into user-friendly categories for display.
 * Used to organize and filter detected content types.
 */
typedef enum {
    FILE_CLASS_UNKNOWN = 0,  /**< Unrecognized file type */
    FILE_CLASS_IMAGE,        /**< Image files (JPEG, PNG, GIF, WebP, etc.) */
    FILE_CLASS_VIDEO,        /**< Video files (MP4, WebM, AVI, MKV, etc.) */
    FILE_CLASS_AUDIO,        /**< Audio files (MP3, OGG, FLAC, WAV, etc.) */
    FILE_CLASS_ARCHIVE,      /**< Compressed archives (ZIP, GZIP, ZSTD, etc.) */
    FILE_CLASS_DOCUMENT,     /**< Document files (PDF) */
    FILE_CLASS_FONT,         /**< Font files (WOFF, WOFF2, TTF, OTF, EOT) */
    FILE_CLASS_EXECUTABLE,   /**< Executable/binary (WASM, ELF, Mach-O) */
    FILE_CLASS_DATABASE,     /**< Database files (SQLite) */
    FILE_CLASS_CONTAINER,    /**< Generic container formats (ISOBMFF, RIFF) */
} file_class_t;

/**
 * @brief Signature detection result structure
 *
 * Contains complete information about a detected file type,
 * including classification, confidence, and validation status.
 */
typedef struct {
    const char *description;  /**< Human-readable description (e.g., "PNG image") */
    file_class_t file_class;  /**< Category for display grouping */
    bool is_binary;           /**< True if binary content (don't display as text) */
    bool trailer_valid;       /**< True if trailer bytes matched (when validated) */
    int confidence;           /**< Match confidence: magic_len (higher = more specific) */
} signature_result_t;

/**
 * @brief File signature definition structure
 *
 * Defines a single file signature for detection, including magic bytes,
 * optional trailer, and metadata. Used internally but exposed for
 * documentation purposes.
 *
 * @note Signatures with longer magic sequences are matched first
 *       for better specificity (e.g., "ftypisom" before "ftyp").
 */
typedef struct {
    const uint8_t *magic;     /**< Magic bytes to match at offset */
    int magic_len;            /**< Length of magic bytes */
    int offset;               /**< Byte offset from start (0, 4, 8, or 257 for TAR) */
    const char *description;  /**< Human-readable description */
    file_class_t file_class;  /**< Classification category */
    bool is_binary;           /**< True if binary content */
    const uint8_t *trailer;   /**< Optional trailer bytes (NULL if none) */
    int trailer_len;          /**< Length of trailer bytes */
} file_signature_t;

/**
 * @brief Initialize the signature detection system
 *
 * Builds a sorted index of signatures for efficient matching.
 * Must be called before using other signature functions.
 *
 * @return 0 on success, negative on error
 *
 * @note This function sorts signatures by magic length (longest first)
 *       to ensure the most specific match is found.
 */
int signatures_init(void);

/**
 * @brief Clean up signature detection resources
 *
 * Releases any allocated resources. Call at program shutdown.
 */
void signatures_cleanup(void);

/**
 * @brief Detect file type from data (legacy API)
 *
 * Simple detection that returns only the description string.
 * For full metadata, use signature_detect_full() instead.
 *
 * @param[in] data Data buffer to analyze
 * @param[in] len  Length of data buffer
 *
 * @return Description string if detected, NULL if no match
 *
 * @see signature_detect_full() for complete detection with metadata
 */
const char *signature_detect(const uint8_t *data, size_t len);

/**
 * @brief Full file type detection with metadata
 *
 * Analyzes data for file signatures and returns complete information
 * including file class, binary flag, and optional trailer validation.
 *
 * @param[in]  data             Data buffer to analyze
 * @param[in]  len              Length of data buffer
 * @param[in]  validate_trailer Check trailer bytes for container formats
 * @param[out] result           Detection result structure
 *
 * @return true if a signature was detected, false otherwise
 *
 * @note When validate_trailer is true and the format has a known trailer,
 *       result->trailer_valid indicates whether it matched.
 *
 * @par Example:
 * @code
 * signature_result_t result;
 * if (signature_detect_full(data, len, true, &result)) {
 *     if (!result.trailer_valid) {
 *         printf("Warning: %s trailer mismatch\n", result.description);
 *     }
 * }
 * @endcode
 */
bool signature_detect_full(const uint8_t *data, size_t len,
                           bool validate_trailer,
                           signature_result_t *result);

/**
 * @brief Get human-readable name for file class
 *
 * Converts a file_class_t enum value to a displayable string.
 *
 * @param[in] file_class The file class to name
 *
 * @return String name (e.g., "Image", "Video", "Archive")
 *
 * @note Returns "Unknown" for FILE_CLASS_UNKNOWN or invalid values
 */
const char *signature_class_name(file_class_t file_class);

/**
 * @brief Check if content type is binary
 *
 * Determines if content with the given description should be
 * treated as binary (displayed as hexdump rather than text).
 *
 * @param[in] description File type description from detection
 *
 * @return true if binary content, false if text
 *
 * @deprecated Use signature_detect_full() and check result.is_binary instead
 */
bool signature_is_binary(const char *description);

/**
 * @brief Check if content is local file I/O
 *
 * Identifies file signatures that indicate local file operations
 * rather than HTTP traffic. Used to filter out file:// protocol
 * reads and other non-HTTP activity.
 *
 * @param[in] description File type description from detection
 *
 * @return true if likely local file I/O, false if HTTP content
 *
 * @note This is a heuristic based on file types typically not
 *       transferred over HTTP (e.g., ELF binaries, system DBs).
 */
bool signature_is_local_file(const char *description);

/**
 * @name Adding New Signatures
 * @brief Guide for extending signature detection
 *
 * To add new file format signatures:
 *
 * 1. Define magic bytes as static const uint8_t array in signatures.c
 * 2. Add entry to signatures[] table with appropriate file_class
 * 3. Table is auto-sorted by magic_len (longest first) at init
 * 4. For container formats (ISOBMFF, RIFF), add to special handlers
 *
 * @par Example (adding FLAC support):
 * @code
 * static const uint8_t magic_flac[] = { 0x66, 0x4C, 0x61, 0x43 }; // "fLaC"
 *
 * // In signatures[] array:
 * { magic_flac, 4, 0, "FLAC audio", FILE_CLASS_AUDIO, true, NULL, 0 },
 * @endcode
 */

/** @} */ /* end of signatures group */

#endif /* SIGNATURES_H */
