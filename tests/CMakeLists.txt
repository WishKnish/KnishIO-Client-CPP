# KnishIO Client C++ SDK Tests
# 
# This CMake file builds the test suite for the KnishIO Client C++ SDK

cmake_minimum_required(VERSION 3.20)

# Enable testing
include(CTest)

# Find dependencies for testing
find_package(Threads REQUIRED)

# Test sources
set(TEST_SOURCES
    shake256_validation.cpp
)

# Create SHAKE256 validation test
add_executable(test_shake256_validation shake256_validation.cpp)
target_link_libraries(test_shake256_validation 
    PRIVATE knishio-client-cpp
    PRIVATE Threads::Threads
)

target_compile_features(test_shake256_validation PRIVATE cxx_std_20)

# Add test properties
set_target_properties(test_shake256_validation PROPERTIES
    OUTPUT_NAME "shake256_validation"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)

# Register the test with CTest
add_test(
    NAME SHAKE256Validation
    COMMAND test_shake256_validation
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)

# Set test properties
set_tests_properties(SHAKE256Validation PROPERTIES
    LABELS "cryptography;validation;core"
    TIMEOUT 60
    # The target is `test_shake256_validation` but OUTPUT_NAME renames the binary to
    # `shake256_validation`; use the target-file genex so REQUIRED_FILES points at the
    # actual built path (a bare target name was looked up as a literal file → "Not Run").
    REQUIRED_FILES $<TARGET_FILE:test_shake256_validation>
)

# PQ-transport (Phase E): live ML-KEM CipherHash round-trip test. Gated at runtime on
# CIPHERHASH_TEST_URL (skips cleanly → CI-safe even without a reachable validator).
add_executable(cipherhash_live_test cipherhash_live_test.cpp)
target_link_libraries(cipherhash_live_test
    PRIVATE knishio-client-cpp
    PRIVATE Threads::Threads
)
target_compile_features(cipherhash_live_test PRIVATE cxx_std_20)
set_target_properties(cipherhash_live_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)
add_test(
    NAME CipherHashLive
    COMMAND cipherhash_live_test
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)
set_tests_properties(CipherHashLive PROPERTIES
    LABELS "integration;network;pq-transport"
    TIMEOUT 60
)

# Unit tests (if we add them later)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/unit_tests.cpp")
    add_executable(unit_tests unit_tests.cpp)
    target_link_libraries(unit_tests 
        PRIVATE knishio-client-cpp
        PRIVATE Threads::Threads
    )
    target_compile_features(unit_tests PRIVATE cxx_std_20)
    add_test(NAME UnitTests COMMAND unit_tests)
    set_tests_properties(UnitTests PROPERTIES
        LABELS "unit;core"
        TIMEOUT 30
    )
endif()

# Integration tests (if we add them later)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/integration_tests.cpp")
    add_executable(integration_tests integration_tests.cpp)
    target_link_libraries(integration_tests 
        PRIVATE knishio-client-cpp
        PRIVATE Threads::Threads
    )
    target_compile_features(integration_tests PRIVATE cxx_std_20)
    add_test(NAME IntegrationTests COMMAND integration_tests)
    set_tests_properties(IntegrationTests PROPERTIES
        LABELS "integration;network"
        TIMEOUT 120
    )
endif()

# Performance benchmarks (if we add them later)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks.cpp")
    add_executable(benchmarks benchmarks.cpp)
    target_link_libraries(benchmarks 
        PRIVATE knishio-client-cpp
        PRIVATE Threads::Threads
    )
    target_compile_features(benchmarks PRIVATE cxx_std_20)
    add_test(NAME Benchmarks COMMAND benchmarks)
    set_tests_properties(Benchmarks PROPERTIES
        LABELS "performance;benchmark"
        TIMEOUT 300
    )
endif()

# Custom test targets
add_custom_target(test_all
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure --parallel 4
    DEPENDS test_shake256_validation
    COMMENT "Running all KnishIO tests"
)

add_custom_target(test_crypto
    COMMAND ${CMAKE_CTEST_COMMAND} -L cryptography --output-on-failure
    DEPENDS test_shake256_validation
    COMMENT "Running cryptography validation tests"
)

add_custom_target(test_verbose
    COMMAND ${CMAKE_CTEST_COMMAND} --verbose --output-on-failure
    DEPENDS test_shake256_validation
    COMMENT "Running all KnishIO tests with verbose output"
)

# Test data files (if needed)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_data")
    file(COPY test_data DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
endif()

# Print test configuration
message(STATUS "KnishIO Test Configuration:")
message(STATUS "  SHAKE256 validation test: enabled")
message(STATUS "  Test output directory: ${CMAKE_CURRENT_BINARY_DIR}")
message(STATUS "  CTest command: ${CMAKE_CTEST_COMMAND}")
message(STATUS "")