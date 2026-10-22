#!/bin/sh
# Builds spike 02's two harnesses into build/spike-goose/: bench-goose, spike
# 01's bench.c against the Goose server (bench_goose.goose, built with the
# pinned Goose and the package's C), and bench-openssl, against the system's
# OpenSSL as spike 01 builds it. Also makes the RSA-2048 certificate, and
# prim, which measures each libcrypto primitive's allocations.
#
# Needs the C compiler goose build uses (CC for the others, default cc), and
# OpenSSL 3's headers and libraries.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
. "$root/scripts/goose.sh"
out=$root/build/spike-goose
cc=${CC:-cc}
mkdir -p "$out"

if [ ! -f "$out/cert.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=localhost \
        -keyout "$out/key.pem" -out "$out/cert.pem" 2>/dev/null
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=localhost \
        -keyout "$out/ec-key.pem" -out "$out/ec-cert.pem" 2>/dev/null
fi

# goose build rebuilds a program's C when its sources change, and glue.c
# includes spike 01's bench.c, which it doesn't follow.
touch "$here/glue.c"
"$GOOSE" build -o "$out/bench-goose" "$here/bench_goose.goose" | grep -v '^parsed\|^typechecked\|^bce\|^wrote' || :
flags="-O2 -g -Wall -Wextra"
$cc $flags -o "$out/bench-openssl" "$root/spikes/01-rustls/bench.c" "$root/spikes/01-rustls/srv_openssl.c" -lssl -lcrypto
$cc $flags -o "$out/prim" "$here/prim.c" -lcrypto
echo "built: $out/bench-goose $out/bench-openssl $out/prim"
