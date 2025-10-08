#!/bin/bash

# KnishIO C++ SDK Self-Test Build and Run Script
# 
# This script builds the C++ SDK self-test executable and runs it,
# following the same pattern as other SDK self-test scripts.
# Uses modern C++20 features and CMake best practices.

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔨 Building KnishIO C++ SDK Self-Test...${NC}"

# Clean CMake cache to avoid absolute path issues
echo -e "${YELLOW}🧹 Cleaning CMake cache for fresh build...${NC}"
rm -rf build/
rm -rf cmake-build-*/

# Create fresh build directory
echo -e "${YELLOW}📁 Creating clean build directory...${NC}"
mkdir -p build

# Configure with CMake using modern settings
echo -e "${YELLOW}⚙️  Configuring CMake build with C++20...${NC}"
cd build
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_STANDARD=20 \
    -DCMAKE_CXX_STANDARD_REQUIRED=ON \
    -DCMAKE_CXX_EXTENSIONS=OFF \
    -DKNISHIO_BUILD_TESTS=ON \
    -DKNISHIO_BUILD_EXAMPLES=ON

# Build the self-test target
echo -e "${YELLOW}🔧 Building cpp_self_test target...${NC}"
cmake --build . --target cpp_self_test --parallel

# Check if build was successful
if [ ! -f "cpp_self_test" ]; then
    echo -e "${RED}❌ Build failed - cpp_self_test executable not found${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Build completed successfully${NC}"
echo -e "${BLUE}🚀 Running C++ SDK Self-Test (Modern C++20 Implementation)...${NC}"
echo ""

# Run the self-test
./cpp_self_test
TEST_EXIT_CODE=$?

# Report results
echo ""
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}🎉 C++ SDK Self-Test completed successfully!${NC}"
    echo -e "${CYAN}✨ Modern C++20 features: concepts, ranges, std::expected${NC}"
    echo -e "${CYAN}🔒 Security: RAII, smart pointers, type safety${NC}"
    echo -e "${CYAN}⚡ Performance: Move semantics, zero-cost abstractions${NC}"
else
    echo -e "${RED}💥 C++ SDK Self-Test failed with exit code $TEST_EXIT_CODE${NC}"
fi

# Return to original directory
cd ..

# Results directory (configurable via environment variable)
RESULTS_DIR="${KNISHIO_SHARED_RESULTS:-../shared-test-results}"
echo -e "${BLUE}📊 Results saved to $RESULTS_DIR/cpp-results.json${NC}"

exit $TEST_EXIT_CODE