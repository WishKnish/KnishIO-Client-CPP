cmake_minimum_required(VERSION 3.20)

# Project definition
project(KnishIOClientCPP
    VERSION 0.8.0
    DESCRIPTION "KnishIO DLT Client SDK for C++"
    HOMEPAGE_URL "https://github.com/knishio"
    LANGUAGES CXX C  # Enable C for mlkem-native integration
)

# Modern C++ standards
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# C standards for mlkem-native
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build configuration
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# Compiler-specific optimizations
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # Performance optimizations for Release builds
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -mtune=native -DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -march=native -mtune=native -DNDEBUG")
    
    # Security hardening flags
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE -fPIC")
    
    # Warning flags
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wshadow -Wconversion -Wsign-conversion")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wunused -Wformat=2")
    
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # MSVC optimizations and warnings
    set(CMAKE_CXX_FLAGS_RELEASE "/O2 /DNDEBUG")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /permissive-")
    
    # Security flags for MSVC
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /GS /DYNAMICBASE /NXCOMPAT")
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/third_party)

# mlkem-native include directories for ML-KEM768 JavaScript compatibility
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/mlkem-native/mlkem/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/mlkem-native/mlkem)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/mlkem-native/test)

# Find required dependencies
find_package(PkgConfig REQUIRED)

# Find libsodium
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
if(NOT SODIUM_FOUND)
    # Fallback for systems without pkg-config
    find_library(SODIUM_LIBRARY NAMES sodium libsodium REQUIRED)
    find_path(SODIUM_INCLUDE_DIR NAMES sodium.h REQUIRED)
    
    # Create imported target manually
    add_library(PkgConfig::SODIUM UNKNOWN IMPORTED)
    set_target_properties(PkgConfig::SODIUM PROPERTIES
        IMPORTED_LOCATION ${SODIUM_LIBRARY}
        INTERFACE_INCLUDE_DIRECTORIES ${SODIUM_INCLUDE_DIR}
    )
endif()

# Required dependencies
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

message(STATUS "Found CURL: HTTP client support enabled")
set(KNISHIO_HTTP_SUPPORT ON)

# Configure header file
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/knishio_config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/knishio_config.h"
)
include_directories("${CMAKE_CURRENT_BINARY_DIR}/include")

# mlkem-native source files for ML-KEM768 JavaScript compatibility
file(GLOB MLKEM_NATIVE_SOURCES 
    external/mlkem-native/mlkem/src/kem.c
    external/mlkem-native/mlkem/src/indcpa.c
    external/mlkem-native/mlkem/src/poly.c
    external/mlkem-native/mlkem/src/poly_k.c
    external/mlkem-native/mlkem/src/compress.c
    external/mlkem-native/mlkem/src/sampling.c
    external/mlkem-native/mlkem/src/verify.c
    external/mlkem-native/mlkem/src/fips202/fips202.c
    external/mlkem-native/mlkem/src/fips202/keccakf1600.c
    external/mlkem-native/mlkem/src/fips202/fips202x4.c
    external/mlkem-native/test/notrandombytes/notrandombytes.c
)

# Source files
set(KNISHIO_SOURCES
    src/Atom.cpp
    src/Molecule.cpp
    src/Wallet.cpp
    src/crypto.cpp
    src/crypto_bigint.cpp
    src/utility.cpp
    src/KnishIOClient.cpp
    src/http/GraphQLClient.cpp
    src/response/Response.cpp
    src/query/Query.cpp
    src/query/QueryBalance.cpp
    src/mutation/Mutation.cpp
    src/third_party/BigInt/bigInt.cpp
    src/third_party/Keccak/Keccak-readable-and-compact.cpp
    ${MLKEM_NATIVE_SOURCES}
)

# Header files
set(KNISHIO_HEADERS
    src/Atom.h
    src/Molecule.h
    src/Wallet.h
    src/crypto.h
    src/crypto_bigint.h
    src/utility.h
    src/KnishIOClient.h
    src/AtomsNotFoundException.h
    src/exception/KnishIOException.h
    include/http/GraphQLClient.h
    include/response/Response.h
    include/query/Query.h
    include/query/QueryBalance.h
    include/mutation/Mutation.h
    src/third_party/BigInt/bigInt.h
    src/third_party/Keccak/Keccak.h
    src/third_party/nlohmann/json.hpp
)

# Create the main library
add_library(knishio-client-cpp ${KNISHIO_SOURCES})

# Set library properties
set_target_properties(knishio-client-cpp PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "${KNISHIO_HEADERS}"
    OUTPUT_NAME "knishio-client-cpp"
    EXPORT_NAME "KnishIOClientCPP"
)

# Target compile features
target_compile_features(knishio-client-cpp PUBLIC cxx_std_20)

# mlkem-native configuration for ML-KEM768 JavaScript compatibility
target_compile_definitions(knishio-client-cpp PUBLIC HAVE_MLKEM_NATIVE=1)

# Configure mlkem-native source files with specific compiler definitions
foreach(MLKEM_FILE ${MLKEM_NATIVE_SOURCES})
    set_source_files_properties(${MLKEM_FILE} PROPERTIES
        COMPILE_DEFINITIONS "MLK_CONFIG_PARAMETER_SET=768;MLK_CONFIG_NAMESPACE_PREFIX=mlkem"
        LANGUAGE C  # Ensure C compilation for mlkem-native files
    )
endforeach()

# Link libraries
target_link_libraries(knishio-client-cpp 
    PUBLIC 
        PkgConfig::SODIUM
        CURL::libcurl
        Threads::Threads
)

# Include directories for the target
target_include_directories(knishio-client-cpp
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/third_party>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# HTTP client support (optional - only if source file exists)
if(KNISHIO_HTTP_SUPPORT AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/http_client.cpp")
    target_sources(knishio-client-cpp PRIVATE src/http_client.cpp)
    target_link_libraries(knishio-client-cpp PUBLIC CURL::libcurl)
    target_compile_definitions(knishio-client-cpp PUBLIC KNISHIO_HTTP_SUPPORT=1)
    message(STATUS "HTTP client implementation: enabled")
elseif(KNISHIO_HTTP_SUPPORT)
    message(STATUS "HTTP client implementation: disabled (source file not found)")
    set(KNISHIO_HTTP_SUPPORT OFF)
endif()

# Create static library variant
add_library(knishio-client-cpp-static STATIC ${KNISHIO_SOURCES})
set_target_properties(knishio-client-cpp-static PROPERTIES
    OUTPUT_NAME "knishio-client-cpp-static"
    PUBLIC_HEADER "${KNISHIO_HEADERS}"
)
target_compile_features(knishio-client-cpp-static PUBLIC cxx_std_20)

# mlkem-native configuration for static library
target_compile_definitions(knishio-client-cpp-static PUBLIC HAVE_MLKEM_NATIVE=1)

target_link_libraries(knishio-client-cpp-static 
    PUBLIC 
        PkgConfig::SODIUM
        CURL::libcurl
        Threads::Threads
)
target_include_directories(knishio-client-cpp-static
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/third_party>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

if(KNISHIO_HTTP_SUPPORT AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/http_client.cpp")
    target_sources(knishio-client-cpp-static PRIVATE src/http_client.cpp)
    target_link_libraries(knishio-client-cpp-static PUBLIC CURL::libcurl)
    target_compile_definitions(knishio-client-cpp-static PUBLIC KNISHIO_HTTP_SUPPORT=1)
endif()

# Create alias targets
add_library(KnishIO::ClientCPP ALIAS knishio-client-cpp)
add_library(KnishIO::ClientCPP::Static ALIAS knishio-client-cpp-static)

# Testing support
option(KNISHIO_BUILD_TESTS "Build KnishIO tests" ON)
if(KNISHIO_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Examples
option(KNISHIO_BUILD_EXAMPLES "Build KnishIO examples" ON)
if(KNISHIO_BUILD_EXAMPLES)
    add_executable(query_balance_example examples/query_balance.cpp)
    target_link_libraries(query_balance_example 
        PRIVATE 
            knishio-client-cpp
            CURL::libcurl
            PkgConfig::SODIUM
            Threads::Threads
    )
    target_include_directories(query_balance_example
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/src/third_party
    )
endif()

# Documentation support
find_package(Doxygen QUIET)
if(DOXYGEN_FOUND)
    option(KNISHIO_BUILD_DOCS "Build KnishIO documentation" OFF)
    if(KNISHIO_BUILD_DOCS)
        add_subdirectory(docs)
    endif()
endif()

# Installation
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# Install targets
install(TARGETS knishio-client-cpp knishio-client-cpp-static
    EXPORT KnishIOClientCPPTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/knishio
)

# Install third-party headers
install(DIRECTORY src/third_party/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/knishio/third_party
    FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
)

# Install config header
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/include/knishio_config.h"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/knishio
)

# Create and install CMake config files
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/KnishIOClientCPPConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/KnishIOClientCPPConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/KnishIOClientCPPConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/KnishIOClientCPP
    PATH_VARS CMAKE_INSTALL_INCLUDEDIR CMAKE_INSTALL_LIBDIR
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/KnishIOClientCPPConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/KnishIOClientCPPConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/KnishIOClientCPP
)

install(EXPORT KnishIOClientCPPTargets
    FILE KnishIOClientCPPTargets.cmake
    NAMESPACE KnishIO::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/KnishIOClientCPP
)

# Package configuration
set(CPACK_PACKAGE_NAME "KnishIOClientCPP")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY ${PROJECT_DESCRIPTION})
set(CPACK_PACKAGE_VENDOR "KnishIO")
set(CPACK_PACKAGE_CONTACT "support@knishio.com")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

# Platform-specific packaging
if(WIN32)
    set(CPACK_GENERATOR "ZIP;NSIS")
elseif(APPLE)
    set(CPACK_GENERATOR "ZIP;DragNDrop")
else()
    set(CPACK_GENERATOR "TGZ;DEB;RPM")
endif()

# C++ SDK Self-Test executable (follows JavaScript SDK pattern with modern C++20)
add_executable(cpp_self_test self-test-compatible.cpp)
target_link_libraries(cpp_self_test PRIVATE
    knishio-client-cpp-static
    PkgConfig::SODIUM
    Threads::Threads
)
target_include_directories(cpp_self_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Modern C++20 features and optimization
target_compile_features(cpp_self_test PRIVATE cxx_std_20)
target_compile_definitions(cpp_self_test PRIVATE
    KNISHIO_SELF_TEST_BUILD
    _GNU_SOURCE  # Enable GNU extensions for better compatibility
)

# Add compiler-specific flags for self-test
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(cpp_self_test PRIVATE
        -fconcepts-diagnostics-depth=3  # Better concepts error messages (GCC only)
        -ftemplate-backtrace-limit=50   # Better template error reporting
    )
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(cpp_self_test PRIVATE
        -ftemplate-backtrace-limit=50   # Better template error reporting
    )
endif()

# Install self-test binary
install(TARGETS cpp_self_test DESTINATION bin)

include(CPack)

# Print configuration summary
message(STATUS "")
message(STATUS "KnishIO Client C++ SDK Configuration Summary:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Compiler: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "  libsodium: ${SODIUM_LIBRARIES}")
message(STATUS "  HTTP support: ${KNISHIO_HTTP_SUPPORT}")
message(STATUS "  Build tests: ${KNISHIO_BUILD_TESTS}")
if(DOXYGEN_FOUND)
    message(STATUS "  Build docs: ${KNISHIO_BUILD_DOCS}")
endif()
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")