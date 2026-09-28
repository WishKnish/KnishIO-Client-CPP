# Release-package consumer: builds main.cpp against an installed KnishIO C++ SDK found with
# find_package, once per exported target. Configure with
#   -DCMAKE_PREFIX_PATH=<package root> -DEXPECTED_VERSION=<version>
# (packaging/check-release-package.sh does this against a relocated copy of the package).
cmake_minimum_required(VERSION 3.20)
project(knishio_consumer CXX)

find_package(KnishIOClientCPP REQUIRED)
if(NOT KnishIOClientCPP_VERSION VERSION_EQUAL EXPECTED_VERSION)
    message(FATAL_ERROR
        "KnishIOClientCPP ${KnishIOClientCPP_VERSION} found, expected '${EXPECTED_VERSION}'")
endif()

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE KnishIO::ClientCPP)

add_executable(consumer_static main.cpp)
target_link_libraries(consumer_static PRIVATE KnishIO::ClientCPPStatic)
