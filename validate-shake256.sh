#!/bin/bash

# SHAKE256 Validation Script for KnishIO C++ SDK
# This script compiles and runs SHAKE256 validation tests against canonical test vectors

set -e  # Exit on any error

echo "🔍 KnishIO C++ SDK - SHAKE256 Validation"
echo "========================================"

# Check if we're in the right directory
if [[ ! -f "src/utility.cpp" ]]; then
    echo "❌ Error: Must be run from KnishIO-Client-CPP directory"
    exit 1
fi

# Create tests directory if it doesn't exist
mkdir -p tests

# Create a minimal build directory
mkdir -p build
cd build

echo "📦 Compiling validation test..."

# Get libsodium paths
SODIUM_PREFIX=$(brew --prefix libsodium 2>/dev/null || echo "/usr/local")

# Compile all necessary source files
g++ -std=c++17 -I../src -I../src/third_party -I${SODIUM_PREFIX}/include \
    ../tests/shake256_validation.cpp \
    ../src/utility.cpp \
    ../src/Wallet.cpp \
    ../src/crypto.cpp \
    ../src/crypto_bigint.cpp \
    ../src/third_party/BigInt/bigInt.cpp \
    ../src/third_party/Keccak/Keccak-readable-and-compact.cpp \
    -L${SODIUM_PREFIX}/lib -lsodium \
    -o shake256_validation \
    2>&1

if [[ $? -eq 0 ]]; then
    echo "✅ Compilation successful"
else
    echo "❌ Compilation failed"
    exit 1
fi

echo ""
echo "🧪 Running SHAKE256 validation tests..."
echo "========================================"

# Run the validation test
./shake256_validation

exit_code=$?

cd ..

if [[ $exit_code -eq 0 ]]; then
    echo ""
    echo "🎉 All tests passed! C++ SDK is cryptographically compatible."
else
    echo ""
    echo "🚨 Tests failed! C++ SDK has cryptographic compatibility issues."
fi

exit $exit_code