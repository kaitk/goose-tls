#!/bin/sh
# Runs every measurement for every configuration, RUNS times (default 5),
# interleaved: each round runs each mode once per configuration, in an order
# that rotates by round. Each run is its own process, pinned to CPU (default
# 2). MODES replaces the list of modes and their arguments. Prints the
# system first, then one line per run; summarize.py makes the tables. Build
# first with build.sh.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
out=$(cd "$here/../.." && pwd)/build/spike-rustls
runs=${RUNS:-5}
cpu=${CPU:-2}
export CERTS=$out

echo "# $(date -u +%Y-%m-%dT%H:%MZ) $(uname -r) $(nproc) CPUs: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2)"
echo "# $(openssl version); rustls-ffi $(git -C "$out/rustls-ffi" describe --tags 2>/dev/null)," \
    "rustls $(grep -A1 'name = "rustls"$' "$out/rustls-ffi/Cargo.lock" | sed -n 's/version = "\(.*\)"/\1/p')," \
    "aws-lc-rs $(grep -A1 'name = "aws-lc-rs"$' "$out/rustls-ffi/Cargo.lock" | sed -n 's/version = "\(.*\)"/\1/p')," \
    "ring $(grep -A1 'name = "ring"$' "$out/rustls-ffi/Cargo.lock" | sed -n 's/version = "\(.*\)"/\1/p'); $(cc --version | head -1)"

configs="openssl:openssl:default openssl:openssl:x25519 rustls:aws-lc-rs:default rustls:aws-lc-rs:x25519 rustls:ring:x25519"
modes=${MODES:-idle:1000 idle:4000 inflight:1000 inflight:4000 hs:3000 enc:2048 dec:2048 json:200000:1000}
r=0
while [ "$r" -lt "$runs" ]; do
    set -- $configs
    k=0
    while [ "$k" -lt "$r" ]; do c=$1; shift; set -- "$@" "$c"; k=$((k + 1)); done
    for m in $modes; do
        for c in "$@"; do
            bin=${c%%:*}; rest=${c#*:}
            echo "run=$r $(taskset -c "$cpu" "$out/bench-$bin" ${rest%%:*} ${rest#*:} $(echo "$m" | tr : ' '))"
        done
    done
    r=$((r + 1))
done
