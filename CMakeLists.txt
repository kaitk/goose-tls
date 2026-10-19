# The package's C, which tls.build names as a CMake target: goose build builds
# it and links the program with the target's whole link line, OpenSSL's
# libraries included (docs/development.md, "OpenSSL").
cmake_minimum_required(VERSION 3.20)
project(goose_tls C)

# FindOpenSSL looks where the system keeps libraries; Homebrew keeps OpenSSL 3
# under a prefix of its own, which differs between arm64 and x86_64.
# OPENSSL_ROOT_DIR, as a CMake or environment variable, overrides both.
if(APPLE AND NOT OPENSSL_ROOT_DIR AND NOT DEFINED ENV{OPENSSL_ROOT_DIR})
    foreach(prefix /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3)
        if(EXISTS "${prefix}/include/openssl/ssl.h")
            set(OPENSSL_ROOT_DIR "${prefix}")
            break()
        endif()
    endforeach()
endif()
find_package(OpenSSL 3.0 REQUIRED COMPONENTS SSL Crypto)

add_library(goose_tls STATIC shim/tls.c)
# The shim uses the OpenSSL 3.0 API and nothing it deprecates, which OpenSSL
# 3.x and 4.x both provide.
target_compile_definitions(goose_tls PRIVATE OPENSSL_API_COMPAT=30000 OPENSSL_NO_DEPRECATED)
set_target_properties(goose_tls PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
target_link_libraries(goose_tls PUBLIC OpenSSL::SSL OpenSSL::Crypto)
