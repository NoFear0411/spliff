# spliff Makefile - CMake wrapper for backward compatibility
#
# This Makefile wraps CMake for users accustomed to running 'make'.
# For full CMake functionality, use cmake directly:
#   cmake -B build -DCMAKE_BUILD_TYPE=Debug
#   cmake --build build
#
# Or use CMake presets (if defined in CMakePresets.json)

.PHONY: all debug release relsan clean install test help legacy

BUILD_DIR := build

# Default target: debug build
all: debug

# Debug build with sanitizers
debug:
	@cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
	@cmake --build $(BUILD_DIR) --parallel
	@ln -sf $(BUILD_DIR)/spliff spliff 2>/dev/null || cp $(BUILD_DIR)/spliff spliff

# Release build (optimized, stripped)
release:
	@cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release
	@cmake --build $(BUILD_DIR) --parallel
	@ln -sf $(BUILD_DIR)/spliff spliff 2>/dev/null || cp $(BUILD_DIR)/spliff spliff

# Release build with sanitizers (optimized + ASan/UBSan)
relsan:
	@cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=RelWithSan -DENABLE_SANITIZERS=ON
	@cmake --build $(BUILD_DIR) --parallel
	@ln -sf $(BUILD_DIR)/spliff spliff 2>/dev/null || cp $(BUILD_DIR)/spliff spliff

# Clean build artifacts
clean:
	@rm -rf $(BUILD_DIR) spliff
	@echo "Build directory cleaned"

# Run tests (builds test executables then runs them)
test: debug
	@cmake --build $(BUILD_DIR) --target test_http1 test_http2 test_xdp
	@cd $(BUILD_DIR) && ctest --output-on-failure

# Install to system (requires sudo)
install: release
	@sudo cmake --install $(BUILD_DIR)
	@echo "Installed to /usr/local/bin/spliff"

# Create Debian package
package-deb: release
	@cd $(BUILD_DIR) && cpack -G DEB
	@echo "Debian package created in $(BUILD_DIR)/"

# Create RPM package
package-rpm: release
	@cd $(BUILD_DIR) && cpack -G RPM
	@echo "RPM package created in $(BUILD_DIR)/"

# Use legacy Makefile (pre-CMake)
legacy:
	@echo "Using legacy Makefile..."
	@$(MAKE) -f Makefile.legacy $(filter-out legacy,$(MAKECMDGOALS))

# Help
help:
	@echo "spliff - eBPF-based SSL/TLS Traffic Sniffer"
	@echo ""
	@echo "Build targets:"
	@echo "  all          Build debug version (default)"
	@echo "  debug        Build with debug symbols and sanitizers"
	@echo "  release      Build optimized, stripped binary (no sanitizers)"
	@echo "  relsan       Build optimized with sanitizers (for testing)"
	@echo "  test         Build and run tests"
	@echo "  clean        Remove build artifacts"
	@echo "  install      Install to /usr/local/bin (requires sudo)"
	@echo ""
	@echo "Packaging targets:"
	@echo "  package-deb  Create Debian package (.deb)"
	@echo "  package-rpm  Create RPM package (.rpm)"
	@echo ""
	@echo "Other targets:"
	@echo "  legacy       Use legacy Makefile (Makefile.legacy)"
	@echo "  help         Show this help"
	@echo ""
	@echo "CMake options (pass via cmake command):"
	@echo "  -DENABLE_SANITIZERS=ON/OFF   Enable ASan/UBSan (default: ON)"
	@echo "  -DENABLE_ZSTD=ON/OFF         Enable zstd support (default: ON)"
	@echo "  -DENABLE_BROTLI=ON/OFF       Enable brotli support (default: ON)"
	@echo ""
	@echo "Direct CMake usage:"
	@echo "  cmake -B build -DCMAKE_BUILD_TYPE=Debug"
	@echo "  cmake --build build"
	@echo "  sudo cmake --install build"
