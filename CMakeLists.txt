# The package's C, which tls.build names as a CMake target: goose build builds
# it and links the program with the target's whole link line, OpenSSL's
# libraries included (docs/development.md, "OpenSSL").
cmake_minimum_required(VERSION 3.20)
project(goose_tls C)

include(${CMAKE_CURRENT_LIST_DIR}/cmake/openssl.cmake)

# Which server tls::server makes: goose, the TLS 1.3 server in server.goose,
# or openssl, libssl's, kept for rollback (docs/decisions.md). Read from the
# environment when the package's C is first configured; a configured build
# keeps its choice until its directory is deleted (docs/development.md).
set(GOOSE_TLS_SERVER "$ENV{GOOSE_TLS_SERVER}" CACHE STRING "goose or openssl")
if(GOOSE_TLS_SERVER STREQUAL "")
    set(GOOSE_TLS_SERVER goose CACHE STRING "goose or openssl" FORCE)
endif()
if(NOT GOOSE_TLS_SERVER MATCHES "^(goose|openssl)$")
    message(FATAL_ERROR "GOOSE_TLS_SERVER must be goose or openssl, not ${GOOSE_TLS_SERVER}")
endif()

add_library(goose_tls STATIC shim/tls.c shim/ktls.c shim/crypto.c shim/server.c)
# The shim uses the OpenSSL 3.0 API and nothing it deprecates, which OpenSSL
# 3.x and 4.x both provide.
target_compile_definitions(goose_tls PRIVATE OPENSSL_API_COMPAT=30000 OPENSSL_NO_DEPRECATED)
if(GOOSE_TLS_SERVER STREQUAL "openssl")
    target_compile_definitions(goose_tls PRIVATE GOOSE_TLS_SERVER_OPENSSL)
endif()
set_target_properties(goose_tls PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
target_link_libraries(goose_tls PUBLIC OpenSSL::SSL OpenSSL::Crypto)
