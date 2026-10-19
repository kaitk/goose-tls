# The package's C, which tls.build names as a CMake target: goose build builds
# it and links the program with the target's whole link line, OpenSSL's
# libraries included (docs/development.md, "OpenSSL").
cmake_minimum_required(VERSION 3.20)
project(goose_tls C)

include(${CMAKE_CURRENT_LIST_DIR}/cmake/openssl.cmake)

add_library(goose_tls STATIC shim/tls.c shim/ktls.c shim/crypto.c)
# The shim uses the OpenSSL 3.0 API and nothing it deprecates, which OpenSSL
# 3.x and 4.x both provide.
target_compile_definitions(goose_tls PRIVATE OPENSSL_API_COMPAT=30000 OPENSSL_NO_DEPRECATED)
set_target_properties(goose_tls PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
target_link_libraries(goose_tls PUBLIC OpenSSL::SSL OpenSSL::Crypto)
