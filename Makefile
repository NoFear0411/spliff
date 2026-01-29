# spliff Makefile - CMake wrapper
#
# This Makefile wraps CMake for convenient command-line usage.
# Default target is release build (optimized, stripped, no sanitizers).
#
# Usage:
#   make          Build release version (same as 'make release')
#   make debug    Build debug version with sanitizers
#   make tests    Build and run tests
#   make clean    Remove all build artifacts and configuration

.PHONY: all release debug relsan sanitize tests test clean distclean install \
        coverage coverage-html coverage-clean \
        package-deb package-rpm docs clean-docs help

# Build directories
BUILD_DIR_DEBUG := build-debug
BUILD_DIR_RELEASE := build-release

# Number of parallel jobs (default: number of CPUs)
JOBS := $(shell nproc 2>/dev/null || echo 4)

# ============================================================================
# Main Build Targets
# ============================================================================

# Default target: release build
all: release

# Release build (optimized, stripped, no sanitizers)
release:
	@echo "==> Configuring release build..."
	@cmake -B $(BUILD_DIR_RELEASE) \
		-DCMAKE_BUILD_TYPE=Release \
		-DENABLE_SANITIZERS=OFF
	@echo "==> Building release..."
	@cmake --build $(BUILD_DIR_RELEASE) --parallel $(JOBS)
	@ln -sf $(BUILD_DIR_RELEASE)/spliff spliff 2>/dev/null || cp $(BUILD_DIR_RELEASE)/spliff spliff
	@echo "==> Release build complete: ./spliff"

# Debug build (symbols, sanitizers enabled)
debug:
	@echo "==> Configuring debug build..."
	@cmake -B $(BUILD_DIR_DEBUG) \
		-DCMAKE_BUILD_TYPE=Debug \
		-DENABLE_SANITIZERS=ON
	@echo "==> Building debug..."
	@cmake --build $(BUILD_DIR_DEBUG) --parallel $(JOBS)
	@ln -sf $(BUILD_DIR_DEBUG)/spliff spliff 2>/dev/null || cp $(BUILD_DIR_DEBUG)/spliff spliff
	@echo "==> Debug build complete: ./spliff"

# Release build with sanitizers (for testing optimized code)
relsan:
	@echo "==> Configuring release+sanitizers build..."
	@cmake -B $(BUILD_DIR_DEBUG) \
		-DCMAKE_BUILD_TYPE=RelWithSan \
		-DENABLE_SANITIZERS=ON
	@echo "==> Building release+sanitizers..."
	@cmake --build $(BUILD_DIR_DEBUG) --parallel $(JOBS)
	@ln -sf $(BUILD_DIR_DEBUG)/spliff spliff 2>/dev/null || cp $(BUILD_DIR_DEBUG)/spliff spliff
	@echo "==> RelWithSan build complete: ./spliff"

# Sanitize build (optimized for maximum ASan/UBSan accuracy with -O1)
sanitize:
	@echo "==> Configuring sanitize build (ASan/UBSan optimized)..."
	@cmake -B $(BUILD_DIR_DEBUG) \
		-DCMAKE_BUILD_TYPE=Sanitize \
		-DENABLE_SANITIZERS=ON
	@echo "==> Building sanitize..."
	@cmake --build $(BUILD_DIR_DEBUG) --parallel $(JOBS)
	@ln -sf $(BUILD_DIR_DEBUG)/spliff spliff 2>/dev/null || cp $(BUILD_DIR_DEBUG)/spliff spliff
	@echo "==> Sanitize build complete: ./spliff"
	@echo "    Run with: ASAN_OPTIONS=check_initialization_order=1 ./spliff"

# ============================================================================
# Test Targets
# ============================================================================

# Build and run all tests (uses debug build)
tests: debug
	@echo "==> Building test executables..."
	@cmake --build $(BUILD_DIR_DEBUG) --target build_tests --parallel $(JOBS)
	@echo "==> Running tests..."
	@cd $(BUILD_DIR_DEBUG) && ctest --output-on-failure
	@echo "==> All tests passed"

# Alias for tests
test: tests

# ============================================================================
# Documentation Targets
# ============================================================================

# Generate Doxygen API documentation
docs:
	@echo "==> Configuring for documentation..."
	@cmake -B $(BUILD_DIR_DEBUG) -DCMAKE_BUILD_TYPE=Debug
	@echo "==> Generating API documentation with Doxygen..."
	@cmake --build $(BUILD_DIR_DEBUG) --target docs
	@echo "==> Documentation generated: docs/html/index.html"
	@echo "    Open with: xdg-open docs/html/index.html"

# Clean generated documentation
clean-docs:
	@echo "==> Cleaning generated documentation..."
	@rm -rf docs/html docs/man docs/latex
	@echo "==> Documentation cleaned"

# ============================================================================
# Clean Targets
# ============================================================================

# Clean all build artifacts and CMake configuration
clean:
	@echo "==> Cleaning build directories..."
	@rm -rf $(BUILD_DIR_DEBUG) $(BUILD_DIR_RELEASE)
	@rm -f spliff
	@rm -f compile_commands.json
	@echo "==> Clean complete"

# Deep clean (same as clean, for compatibility)
distclean: clean

# ============================================================================
# Code Coverage Targets
# ============================================================================

# Build with coverage instrumentation and run tests
coverage:
	@echo "==> Configuring coverage build..."
	@cmake -B $(BUILD_DIR_DEBUG) \
		-DCMAKE_BUILD_TYPE=Debug \
		-DENABLE_COVERAGE=ON \
		-DENABLE_SANITIZERS=OFF
	@echo "==> Building with coverage..."
	@cmake --build $(BUILD_DIR_DEBUG) --parallel $(JOBS)
	@echo "==> Building test executables..."
	@cmake --build $(BUILD_DIR_DEBUG) --target build_tests --parallel $(JOBS)
	@echo "==> Running tests for coverage..."
	@cd $(BUILD_DIR_DEBUG) && ctest --output-on-failure
	@echo ""
	@echo "==> Coverage data generated. Run 'make coverage-html' for HTML report."

# Generate HTML coverage report (requires lcov)
coverage-html: coverage
	@command -v lcov >/dev/null 2>&1 || { echo "Error: lcov not installed"; exit 1; }
	@command -v genhtml >/dev/null 2>&1 || { echo "Error: genhtml not installed"; exit 1; }
	@echo "==> Capturing coverage data..."
	@lcov --capture --directory $(BUILD_DIR_DEBUG) \
		--output-file $(BUILD_DIR_DEBUG)/coverage.info \
		--ignore-errors mismatch 2>/dev/null
	@lcov --remove $(BUILD_DIR_DEBUG)/coverage.info \
		'/usr/*' '*/tests/*' \
		--output-file $(BUILD_DIR_DEBUG)/coverage.info \
		--ignore-errors unused 2>/dev/null
	@echo "==> Generating HTML report..."
	@genhtml $(BUILD_DIR_DEBUG)/coverage.info \
		--output-directory $(BUILD_DIR_DEBUG)/coverage_html
	@echo ""
	@echo "==> Coverage report: $(BUILD_DIR_DEBUG)/coverage_html/index.html"

# Clean coverage data
coverage-clean:
	@find $(BUILD_DIR_DEBUG) -name "*.gcda" -delete 2>/dev/null || true
	@find $(BUILD_DIR_DEBUG) -name "*.gcno" -delete 2>/dev/null || true
	@rm -rf $(BUILD_DIR_DEBUG)/coverage.info $(BUILD_DIR_DEBUG)/coverage_html
	@echo "==> Coverage data cleaned"

# ============================================================================
# Installation Target
# ============================================================================

# Install to system (requires sudo)
install: release
	@echo "==> Installing spliff..."
	@sudo cmake --install $(BUILD_DIR_RELEASE)
	@echo "==> Installed to /usr/local/bin/spliff"

# ============================================================================
# Package Targets
# ============================================================================

# Create Debian package (.deb) - local dev build (dynamic linking)
# Production signed packages: git tag v0.9.x && git push --tags
package-deb: release
	@echo "==> Creating Debian package..."
	@cd $(BUILD_DIR_RELEASE) && cpack -G DEB
	@echo "==> Package created in $(BUILD_DIR_RELEASE)/"
	@ls -la $(BUILD_DIR_RELEASE)/*.deb 2>/dev/null || true

# Create RPM package (.rpm) - local dev build (dynamic linking)
# Production signed packages: git tag v0.9.x && git push --tags
package-rpm: release
	@echo "==> Creating RPM package..."
	@cd $(BUILD_DIR_RELEASE) && cpack -G RPM
	@echo "==> Package created in $(BUILD_DIR_RELEASE)/"
	@ls -la $(BUILD_DIR_RELEASE)/*.rpm 2>/dev/null || true

# ============================================================================
# Help
# ============================================================================

help:
	@echo "spliff - eBPF-based SSL/TLS Traffic Sniffer"
	@echo ""
	@echo "Build targets:"
	@echo "  make / make release   Build optimized, stripped binary (default)"
	@echo "  make debug            Build with debug symbols and sanitizers"
	@echo "  make relsan           Build optimized with sanitizers"
	@echo "  make sanitize         Build for ASan/UBSan accuracy (-O1, frame pointers)"
	@echo "  make tests            Build and run all tests"
	@echo "  make clean            Remove all build artifacts and configuration"
	@echo "  make install          Install to /usr/local/bin (requires sudo)"
	@echo ""
	@echo "Documentation targets:"
	@echo "  make docs             Generate Doxygen API documentation"
	@echo "  make clean-docs       Remove generated documentation"
	@echo ""
	@echo "Coverage targets:"
	@echo "  make coverage         Build with gcov and run tests"
	@echo "  make coverage-html    Generate HTML coverage report (requires lcov)"
	@echo "  make coverage-clean   Remove coverage data files"
	@echo ""
	@echo "Packaging targets:"
	@echo "  make package-deb      Create Debian package (.deb)"
	@echo "  make package-rpm      Create RPM package (.rpm)"
	@echo ""
	@echo "Build directories:"
	@echo "  build-release/        Release builds (make, make release)"
	@echo "  build-debug/          Debug builds (make debug, make tests)"
	@echo ""
	@echo "Required dependencies:"
	@echo "  Fedora:   libbpf-devel elfutils-libelf-devel zlib-ng-devel"
	@echo "            libzstd-devel brotli-devel llhttp-devel"
	@echo "            libnghttp2-devel ck-devel libxdp-devel"
	@echo "            userspace-rcu-devel jemalloc-devel vectorscan-devel"
	@echo "            clang llvm"
	@echo ""
	@echo "  Debian:   libbpf-dev libelf-dev zlib1g-ng-dev libzstd-dev"
	@echo "            libbrotli-dev libllhttp-dev libnghttp2-dev"
	@echo "            libck-dev libxdp-dev liburcu-dev libjemalloc-dev"
	@echo "            libhyperscan-dev clang llvm"
	@echo ""
	@echo "Optional performance libraries (v0.9.5+):"
	@echo "  zlib-ng:     SIMD-accelerated compression (auto-detected)"
	@echo "  vectorscan:  O(n) protocol detection (auto-detected)"
	@echo "  mimalloc:    Low-latency allocator (cmake -DUSE_MIMALLOC=ON)"
	@echo ""
	@echo "Architectures supported: x86_64, aarch64"
