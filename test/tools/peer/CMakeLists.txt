# The tests' peer (peer.c), found and linked against OpenSSL as the package is.
cmake_minimum_required(VERSION 3.20)
project(goose_tls_peer C)

include(${CMAKE_CURRENT_LIST_DIR}/../../../cmake/openssl.cmake)

add_library(goose_tls_peer STATIC peer.c)
target_compile_definitions(goose_tls_peer PRIVATE OPENSSL_API_COMPAT=30000 OPENSSL_NO_DEPRECATED)
set_target_properties(goose_tls_peer PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
target_link_libraries(goose_tls_peer PUBLIC OpenSSL::SSL OpenSSL::Crypto)
