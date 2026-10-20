#!/bin/sh
# Builds the spike's two harnesses into build/spike-rustls/: bench-openssl,
# against the system's OpenSSL, and bench-rustls, against rustls-ffi at
# RUSTLS_FFI_TAG (default v0.15.6), fetched with git and built with cargo
# with both crypto providers, aws-lc-rs and ring. Both harnesses use the
# system's OpenSSL for the clients. Also makes the RSA-2048 certificate.
#
# Needs git, cargo (https://rustup.rs), cmake and a C compiler for aws-lc-sys,
# and OpenSSL 3's headers and libraries. CC picks the C compiler (default cc).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=$root/build/spike-rustls
tag=${RUSTLS_FFI_TAG:-v0.15.6}
cc=${CC:-cc}
mkdir -p "$out"

if [ ! -d "$out/rustls-ffi" ]; then
    git -c advice.detachedHead=false clone -q --depth 1 -b "$tag" https://github.com/rustls/rustls-ffi "$out/rustls-ffi"
fi
(cd "$out/rustls-ffi" && cargo build --release -p rustls-ffi --features aws-lc-rs,ring,prefer-post-quantum)
lib=$out/rustls-ffi/target/release

if [ ! -f "$out/cert.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=localhost \
        -keyout "$out/key.pem" -out "$out/cert.pem" 2>/dev/null
fi

flags="-O2 -g -Wall -Wextra"
$cc $flags -o "$out/bench-openssl" "$here/bench.c" "$here/srv_openssl.c" -lssl -lcrypto
$cc $flags -DDEFINE_RING -DDEFINE_AWS_LC_RS -I "$out/rustls-ffi/librustls/src" -o "$out/bench-rustls" "$here/bench.c" "$here/srv_rustls.c" \
    "$lib/librustls_ffi.a" -lssl -lcrypto -lpthread -ldl -lm
echo "built: $out/bench-openssl $out/bench-rustls"
