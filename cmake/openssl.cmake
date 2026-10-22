# Finds OpenSSL 3.0 or later, for the package's CMakeLists.txt. FindOpenSSL
# looks where the system keeps libraries; Homebrew keeps OpenSSL 3 under a prefix of its own, which differs
# between arm64 and x86_64. OPENSSL_ROOT_DIR, as a CMake or environment
# variable, overrides both.
if(APPLE AND NOT OPENSSL_ROOT_DIR AND NOT DEFINED ENV{OPENSSL_ROOT_DIR})
    foreach(prefix /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3)
        if(EXISTS "${prefix}/include/openssl/ssl.h")
            set(OPENSSL_ROOT_DIR "${prefix}")
            break()
        endif()
    endforeach()
endif()
find_package(OpenSSL 3.0 REQUIRED COMPONENTS SSL Crypto)
