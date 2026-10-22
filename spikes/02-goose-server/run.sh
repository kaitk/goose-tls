#!/bin/sh
# Runs every measurement for both servers and both key exchanges, RUNS times
# (default 5), interleaved as spike 01's run.sh does: each round runs each
# mode once per configuration, in an order that rotates by round, each run its
# own process pinned to CPU (default 2). Both servers issue no session
# tickets (TICKETS=0 for OpenSSL's; the Goose server has none yet). MODES
# replaces the list of modes. Prints the system first, then one line per run;
# spike 01's summarize.py makes the tables. Build first with build.sh.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=$root/build/spike-goose
runs=${RUNS:-5}
cpu=${CPU:-2}
export CERTS=$out TICKETS=0
. "$root/scripts/goose.sh"

echo "# $(date -u +%Y-%m-%dT%H:%MZ) $(uname -r) $(nproc) CPUs: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2)"
# COMMIT names the checkout's commit where git can't read it, as in a worktree
# that Windows' git made, read from WSL (docs/development.md).
commit=${COMMIT:-$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)}
echo "# $(openssl version); Goose $(goose_version); goose-tls $commit; $(cc --version | head -1)"

configs="goose:goose:default goose:goose:x25519 openssl:openssl:default openssl:openssl:x25519"
modes=${MODES:-idle:1000 idle:4000 inflight:1000 inflight:4000 queued:1000 queued:4000 peak:1000 churn:1000 hs:3000 enc:2048 dec:2048 json:200000:1000}
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
