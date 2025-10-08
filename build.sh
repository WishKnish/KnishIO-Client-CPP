#!/bin/bash

# KnishIO Client C++ SDK Build Script
# This script provides easy building of the KnishIO C++ SDK using CMake

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BUILD_TYPE="${1:-Release}"
BUILD_DIR="build"
INSTALL_PREFIX=""
ENABLE_TESTS="ON"
ENABLE_DOCS="OFF"
PARALLEL_JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Help function
show_help() {
    echo "KnishIO Client C++ SDK Build Script"
    echo ""
    echo "Usage: $0 [BUILD_TYPE] [OPTIONS]"
    echo ""
    echo "BUILD_TYPE:"
    echo "  Release      - Optimized release build (default)"
    echo "  Debug        - Debug build with symbols"
    echo "  RelWithDebInfo - Release with debug info"
    echo "  MinSizeRel   - Minimum size release"
    echo ""
    echo "Environment Variables:"
    echo "  BUILD_DIR        - Build directory (default: build)"
    echo "  INSTALL_PREFIX   - Installation prefix"
    echo "  ENABLE_TESTS     - Build tests (default: ON)"
    echo "  ENABLE_DOCS      - Build documentation (default: OFF)"
    echo "  PARALLEL_JOBS    - Number of parallel jobs (default: auto-detected)"
    echo ""
    echo "Examples:"
    echo "  $0                    # Release build"
    echo "  $0 Debug              # Debug build"
    echo "  ENABLE_TESTS=OFF $0   # Release build without tests"
    echo "  BUILD_DIR=mybuild $0  # Custom build directory"
    echo ""
}

# Parse arguments
case "$1" in
    -h|--help)
        show_help
        exit 0
        ;;
    Debug|Release|RelWithDebInfo|MinSizeRel)
        BUILD_TYPE="$1"
        ;;
    "")
        # Use default
        ;;
    *)
        echo -e "${RED}Error: Unknown build type '$1'${NC}"
        echo "Use -h or --help for usage information"
        exit 1
        ;;
esac

echo -e "${BLUE}🏗️  KnishIO Client C++ SDK Build Script${NC}"
echo -e "${BLUE}=======================================${NC}"

# Check if we're in the right directory
if [[ ! -f "CMakeLists.txt" ]] || [[ ! -d "src" ]]; then
    echo -e "${RED}❌ Error: Must be run from KnishIO-Client-CPP directory${NC}"
    exit 1
fi

# Check dependencies
echo -e "${YELLOW}📋 Checking dependencies...${NC}"

# Check CMake
if ! command -v cmake &> /dev/null; then
    echo -e "${RED}❌ CMake is required but not found${NC}"
    exit 1
fi
CMAKE_VERSION=$(cmake --version | head -n1 | cut -d' ' -f3)
echo -e "${GREEN}✅ CMake ${CMAKE_VERSION}${NC}"

# Check compiler
if command -v g++ &> /dev/null; then
    GCC_VERSION=$(g++ --version | head -n1)
    echo -e "${GREEN}✅ ${GCC_VERSION}${NC}"
elif command -v clang++ &> /dev/null; then
    CLANG_VERSION=$(clang++ --version | head -n1)
    echo -e "${GREEN}✅ ${CLANG_VERSION}${NC}"
else
    echo -e "${RED}❌ No C++ compiler found (g++ or clang++)${NC}"
    exit 1
fi

# Check libsodium
if pkg-config --exists libsodium; then
    SODIUM_VERSION=$(pkg-config --modversion libsodium)
    echo -e "${GREEN}✅ libsodium ${SODIUM_VERSION}${NC}"
elif [[ -f "/opt/homebrew/lib/libsodium.dylib" ]] || [[ -f "/usr/local/lib/libsodium.so" ]]; then
    echo -e "${GREEN}✅ libsodium (detected)${NC}"
else
    echo -e "${YELLOW}⚠️  libsodium not found via pkg-config${NC}"
    echo -e "${YELLOW}   Build may fail if libsodium is not installed${NC}"
fi

# Check CURL (optional)
if pkg-config --exists libcurl; then
    CURL_VERSION=$(pkg-config --modversion libcurl)
    echo -e "${GREEN}✅ libcurl ${CURL_VERSION} (HTTP support enabled)${NC}"
else
    echo -e "${YELLOW}⚠️  libcurl not found (HTTP support disabled)${NC}"
fi

echo ""

# Create and enter build directory
echo -e "${YELLOW}📂 Preparing build directory: ${BUILD_DIR}${NC}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Configure CMake
echo -e "${YELLOW}⚙️  Configuring CMake (${BUILD_TYPE})...${NC}"
CMAKE_ARGS=(
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"
    -DKNISHIO_BUILD_TESTS="${ENABLE_TESTS}"
)

if [[ -n "${INSTALL_PREFIX}" ]]; then
    CMAKE_ARGS+=(-DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}")
fi

if command -v doxygen &> /dev/null && [[ "${ENABLE_DOCS}" == "ON" ]]; then
    CMAKE_ARGS+=(-DKNISHIO_BUILD_DOCS=ON)
    echo -e "${GREEN}📚 Documentation will be built${NC}"
fi

cmake "${CMAKE_ARGS[@]}" ..

if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}✅ Configuration successful${NC}"
else
    echo -e "${RED}❌ Configuration failed${NC}"
    exit 1
fi

echo ""

# Build
echo -e "${YELLOW}🔨 Building KnishIO C++ SDK (${PARALLEL_JOBS} parallel jobs)...${NC}"
cmake --build . --config "${BUILD_TYPE}" --parallel "${PARALLEL_JOBS}"

if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}✅ Build successful${NC}"
else
    echo -e "${RED}❌ Build failed${NC}"
    exit 1
fi

echo ""

# Run tests if enabled
if [[ "${ENABLE_TESTS}" == "ON" ]]; then
    echo -e "${YELLOW}🧪 Running tests...${NC}"
    ctest --build-config "${BUILD_TYPE}" --output-on-failure --parallel "${PARALLEL_JOBS}"
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✅ All tests passed${NC}"
    else
        echo -e "${RED}❌ Some tests failed${NC}"
        echo -e "${YELLOW}💡 Run 'ctest --verbose' for detailed output${NC}"
    fi
    echo ""
fi

# Summary
cd ..
echo -e "${BLUE}📊 Build Summary${NC}"
echo -e "${BLUE}===============${NC}"
echo -e "Build type:       ${BUILD_TYPE}"
echo -e "Build directory:  ${BUILD_DIR}/"
echo -e "Libraries built:"
echo -e "  📚 libknishio-client-cpp.so (shared)"
echo -e "  📚 libknishio-client-cpp-static.a (static)"

if [[ "${ENABLE_TESTS}" == "ON" ]]; then
    echo -e "Tests built:"
    echo -e "  🧪 shake256_validation"
fi

echo ""
echo -e "${GREEN}🎉 KnishIO C++ SDK build completed successfully!${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo -e "  • Install: sudo cmake --install ${BUILD_DIR}"
echo -e "  • Run tests: cd ${BUILD_DIR} && ctest"
echo -e "  • Use in project: find_package(KnishIOClientCPP REQUIRED)"
echo ""