#!/bin/sh
# Runs tlsfuzzer's TLS 1.3 server scripts against the test server
# (test/tools/echo_server.goose), and prints each script's counts; each
# script's log goes to build/tlsfuzzer/. Which failures are expected, and
# why, is in tasks/007-goose-server/tlsfuzzer.md.
#
# TLSFUZZER names a directory holding checkouts of tlsfuzzer, tlslite-ng,
# python-ecdsa, and six (github.com/tlsfuzzer/..., and benjaminp/six), side by
# side; no install is needed. PORT (default 19443) is where the server
# listens. Arguments name scripts, with any options after a colon and '~' for
# a space (test-tls13-lengths:-n~300); without any, the list below runs.
set -u

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/goose.sh"
: "${TLSFUZZER:?TLSFUZZER names the directory of tlsfuzzer's checkouts}"
port=${PORT:-19443}
out=$root/build/tlsfuzzer
mkdir -p "$out"
export PYTHONPATH=$TLSFUZZER/tlslite-ng:$TLSFUZZER/python-ecdsa/src:$TLSFUZZER/six:$TLSFUZZER/tlsfuzzer

if [ $# -eq 0 ]; then
    set -- test-tls13-conversation test-tls13-hrr test-tls13-ccs test-tls13-multiple-ccs-messages \
        test-tls13-finished test-tls13-finished-plaintext test-tls13-0rtt-garbage test-tls13-empty-alert \
        test-tls13-invalid-ciphers test-tls13-keyshare-omitted test-tls13-keyupdate \
        test-tls13-legacy-version test-tls13-nociphers test-tls13-pkcs-signature \
        test-tls13-rsa-signatures test-tls13-shuffled-extentions test-tls13-signature-algorithms \
        test-tls13-symetric-ciphers test-tls13-unencrypted-alert test-tls13-unrecognised-groups \
        test-tls13-version-negotiation test-tls13-zero-content-type test-tls13-zero-length-data \
        test-tls13-record-padding test-tls13-large-number-of-extensions \
        test-tls13-record-layer-limits test-tls13-connection-abort \
        test-tls13-no-unknown-groups:--groups=0x001d,0x0017,0x0018 \
        test-tls13-obsolete-curves:--relaxed test-tls13-ecdhe-curves \
        test-tls13-serverhello-random:-n~40 test-tls13-lengths:-n~300
fi

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$out/server.key" -out "$out/server.crt" \
    -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
"$GOOSE" build -o "$out/echo_server" "$root/test/tools/echo_server.goose" >/dev/null || exit 1

server=
stop() {
    [ -n "$server" ] && kill "$server" 2>/dev/null
    server=
}
trap stop EXIT
# The scripts that check P-384 need it offered; test-tls13-lengths needs the
# echo, the others the HTTP answer.
start() {
    stop
    TLS_GROUPS=X25519MLKEM768:X25519:P-256:P-384 \
        "$out/echo_server" "$port" "$out/server.crt" "$out/server.key" "$1" >"$out/server.log" 2>&1 &
    server=$!
    sleep 1
}

mode=
for s in "$@"; do
    name=${s%%:*}
    args=
    [ "$name" != "$s" ] && args=$(echo "${s#*:}" | tr '~' ' ')
    want=http
    [ "$name" = test-tls13-lengths ] && want=echo
    [ "$want" = "$mode" ] && kill -0 "$server" 2>/dev/null || { start $want; mode=$want; }
    (cd "$TLSFUZZER/tlsfuzzer" && perl -e 'alarm shift; exec @ARGV' 1800 \
        python3 "scripts/$name.py" -p "$port" $args) >"$out/$name.log" 2>&1
    echo "$name: $(grep -E '^(PASS|FAIL|XFAIL):' "$out/$name.log" | tr '\n' ' ')"
done
