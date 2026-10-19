#!/bin/sh
# Handshakes against the test server (test/tools/echo_server.goose), built with
# goose build, from openssl s_client and curl: an echo, a refused TLS 1.2
# client, ALPN, HTTP/1.1 requests, and HttpArena's TLS checks (its
# scripts/validate.sh, tls_posture_probe and tls_quality_probe, at 2d85137):
# the served certificate is the one given, TLS 1.3 with one of its three
# suites, no ALPN protocol the client didn't offer, and no obsolete protocol
# or weak cipher accepted. Then a KeyUpdate from s_client each way, and the
# same over kTLS where the kernel has it (the server's kernel option); where
# it hasn't, that the server falls back to user space.
#
# The certificate is a self-signed RSA-2048 pair made for the run, as
# HttpArena mounts one. PORT (default 8081, HttpArena's HTTP/1.1 TLS port)
# is where the server listens; GOOSE names the compiler, CC the C compiler,
# OPENSSL the openssl command, and CURL the curl command.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/goose.sh"
port=${PORT:-8081}
openssl=${OPENSSL:-openssl}
curl=${CURL:-curl}
work=$root/build/handshake
rm -rf "$work"
mkdir -p "$work"

fails=0
pass() { echo "  PASS $*"; }
fail() {
    echo "  FAIL $*"
    fails=$((fails + 1))
}
# Runs a command for at most $1 seconds. Neither macOS nor every container has
# timeout(1); perl is everywhere git is.
limit() {
    s=$1
    shift
    perl -e 'alarm shift; exec @ARGV or die "$ARGV[0]: $!\n"' "$s" "$@"
}

echo "== build test/tools/echo_server.goose"
"$GOOSE" build ${CC:+--cc "$CC"} -o "$work/echo_server" "$root/test/tools/echo_server.goose" |
    grep -v '^parsed\|^typechecked\|^bce\|^wrote' || :
"$openssl" req -x509 -newkey rsa:2048 -nodes -keyout "$work/server.key" -out "$work/server.crt" \
    -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
echo "client: $("$openssl" version)"

server=
stop() {
    if [ -n "$server" ]; then
        kill "$server" 2>/dev/null || :
        wait "$server" 2>/dev/null || :
    fi
    server=
}
trap stop EXIT
# Starts the server with its mode and options; its output goes to $log.
start() {
    stop
    log="$work/server-$(echo "$*" | tr ' ' '-').log"
    "$work/echo_server" "$port" "$work/server.crt" "$work/server.key" "$@" >"$log" 2>&1 &
    server=$!
    i=0
    until grep -q "listening" "$log" 2>/dev/null; do
        i=$((i + 1))
        if [ $i -gt 50 ] || ! kill -0 "$server" 2>/dev/null; then
            cat "$log"
            echo "test-handshake.sh: the server didn't start"
            exit 1
        fi
        sleep 0.1
    done
    sed 's/^/  server: /' "$log"
}
# s_client's output for a connection to the server, with its stdin from $1.
s_client() {
    input=$1
    shift
    printf '%b' "$input" | limit 10 "$openssl" s_client -connect "127.0.0.1:$port" -servername localhost "$@" 2>&1 || :
}

echo
echo "== echo"
start echo
out=$(s_client 'hello, tls\nbye\n' -ign_eof)
if printf '%s\n' "$out" | grep -q '^hello, tls$' && printf '%s\n' "$out" | grep -q '^bye$'; then
    pass "s_client gets back what it sent"
else
    fail "s_client echo: $out"
fi
if printf '%s\n' "$out" | grep -q '^New, TLSv1.3'; then pass "TLS 1.3"; else fail "not TLS 1.3"; fi
# s_client says "closed" (OpenSSL 3.2 and later) or "DONE" after a
# close_notify, and "unexpected eof" when the socket closes without one.
if printf '%s\n' "$out" | grep -qi 'unexpected eof'; then
    fail "closed without close_notify"
elif printf '%s\n' "$out" | grep -qiE '^(closed|DONE)$|close notify'; then
    pass "closes with close_notify"
else
    fail "can't tell how it closed: $out"
fi
out=$(s_client '' -tls1_2)
if printf '%s\n' "$out" | grep -q '^New, TLSv1'; then
    fail "a TLS 1.2 client connected"
else
    pass "a TLS 1.2 client is refused ($(printf '%s\n' "$out" | grep -o 'alert [a-z ]*' | head -1))"
fi

echo
echo "== ALPN"
alpn() {
    s_client '' -alpn "$1" | grep -E '^(ALPN protocol|No ALPN)' | head -1
}
got=$(alpn http/1.1)
[ "$got" = "ALPN protocol: http/1.1" ] && pass "http/1.1 offered: $got" || fail "http/1.1 offered: $got"
got=$(alpn h2,http/1.1)
[ "$got" = "ALPN protocol: http/1.1" ] && pass "h2,http/1.1 offered: $got" || fail "h2,http/1.1 offered: $got"
got=$(alpn h2)
[ "$got" = "No ALPN negotiated" ] && pass "h2 offered: $got" || fail "h2 offered: $got"
got=$(s_client '' | grep -E '^(ALPN protocol|No ALPN)' | head -1)
[ "$got" = "No ALPN negotiated" ] && pass "none offered: $got" || fail "none offered: $got"

echo
echo "== HTTP/1.1 with curl ($("$curl" --version | head -1 | cut -d' ' -f1-2))"
start http
got=$(limit 10 "$curl" -sk --http1.1 -d 'ping over tls' "https://localhost:$port/echo" || :)
[ "$got" = "ping over tls" ] && pass "curl --http1.1 POST gets its body back" || fail "curl POST: $got"
got=$(limit 10 "$curl" -sk --http1.1 -w ' %{http_version}' "https://localhost:$port/json" || :)
[ "$got" = '{"message":"Hello, World!"} 1.1' ] && pass "curl --http1.1 GET: $got" || fail "curl GET: $got"
got=$(limit 10 "$curl" -sk -v --http1.1 "https://localhost:$port/json" 2>&1 | grep -i 'ALPN.*accepted' || :)
case $got in *http/1.1*) pass "curl: $got" ;; *) fail "curl ALPN: $got" ;; esac

echo
echo "== HttpArena's TLS checks"
out=$(s_client '' -alpn http/1.1)
want=$("$openssl" x509 -in "$work/server.crt" -noout -fingerprint -sha256 | sed 's/.*=//')
served=$(printf '%s\n' "$out" | "$openssl" x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//' || :)
[ -n "$want" ] && [ "$served" = "$want" ] && pass "serves the given certificate" ||
    fail "serves ${served:-nothing}, not $want"
line=$(printf '%s\n' "$out" | grep -m1 '^New, ' || :)
version=$(printf '%s' "$line" | awk -F', ' '{print $2}')
cipher=$(printf '%s' "$line" | sed 's/.*Cipher is //')
[ "$version" = TLSv1.3 ] && pass "negotiates TLS 1.3" || fail "negotiates ${version:-nothing}"
case $cipher in
TLS_AES_128_GCM_SHA256 | TLS_AES_256_GCM_SHA384 | TLS_CHACHA20_POLY1305_SHA256)
    pass "uses a TLS 1.3 AEAD cipher ($cipher)" ;;
*) fail "cipher ${cipher:-none}" ;;
esac
got=$(printf '%s\n' "$out" | grep -m1 '^ALPN protocol:' | sed 's/.*: *//' || :)
case $got in
"" | http/1.1) pass "ALPN names only what the client offered (${got:-none})" ;;
*) fail "ALPN chose $got, which the client didn't offer" ;;
esac
accepts() {
    proto=$1
    if ! "$openssl" s_client -help 2>&1 | grep -q -- "-$proto "; then
        echo unsupported
    elif s_client '' "-$proto" -cipher "$2" | grep -qE '^New, (TLSv1|SSLv3)'; then
        echo yes
    else
        echo no
    fi
}
old= weak= untested=
for proto in ssl3 tls1 tls1_1; do
    case $(accepts $proto 'ALL:@SECLEVEL=0') in
    yes) old="$old $proto" ;;
    unsupported) untested="$untested $proto" ;;
    esac
done
for fam in NULL aNULL EXPORT RC4 DES 3DES; do
    [ "$(accepts tls1_2 "$fam:@SECLEVEL=0")" = yes ] && weak="$weak $fam"
done
if [ -z "$old$weak" ]; then
    pass "refuses every obsolete protocol and weak cipher probed"
else
    fail "accepts${old}${weak}"
fi
[ -z "$untested" ] || echo "  NOTE this openssl can't offer$untested, so those weren't probed"

# s_client takes a line "K" as a KeyUpdate that asks for one back, and "k" as
# one that doesn't, only when the line comes in a read of its own, so the
# lines come slowly.
slowly() {
    for line in "$@"; do
        printf '%s\n' "$line"
        sleep 0.5
    done
    sleep 1
}
# Checks an echo across both KeyUpdates.
keyupdates() {
    out=$(slowly hello K 'after K' k 'after k' bye |
        limit 20 "$openssl" s_client -connect "127.0.0.1:$port" -servername localhost 2>&1 || :)
    lines=$(printf '%s\n' "$out" | grep -cE '^(hello|after K|after k|bye)$' || :)
    updates=$(printf '%s\n' "$out" | grep -c '^KEYUPDATE$' || :)
    if [ "$lines" = 4 ] && [ "$updates" = 2 ]; then
        pass "$1: s_client's two KeyUpdates, and every line echoed after them"
    else
        fail "$1: $lines of 4 lines echoed, $updates of 2 KeyUpdates sent: $out"
    fi
    if printf '%s\n' "$out" | grep -qiE '^(closed|DONE)$|close notify' &&
        ! printf '%s\n' "$out" | grep -qi 'unexpected eof'; then
        pass "$1: closes with close_notify"
    else
        fail "$1: can't tell how it closed: $out"
    fi
}

echo
echo "== KeyUpdate"
start echo
keyupdates "user space"

echo
echo "== kTLS"
start echo kernel
if grep -q '^kernel tls: yes' "$log"; then
    # Changing keys in the kernel came in Linux 6.14.
    release=$(uname -r | sed 's/[^0-9.].*//')
    major=${release%%.*}
    minor=$(echo "$release" | cut -d. -f2)
    if [ "$major" -gt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -ge 14 ]; }; then
        keyupdates "kTLS"
        grep -q '^kernel record: type 22, UPDATE_TX$' "$log" && grep -q '^kernel record: type 22, 0$' "$log" &&
            pass "both KeyUpdates went through kernel_record" ||
            fail "KeyUpdates: $(cat "$log")"
    else
        out=$(s_client 'hello, ktls\nbye\n' -ign_eof)
        printf '%s\n' "$out" | grep -q '^hello, ktls$' && pass "kTLS: s_client gets back what it sent" ||
            fail "kTLS echo: $out"
        echo "  NOTE Linux $release can't change kTLS keys (6.14 can), so KeyUpdates weren't run"
    fi
    grep -q '^kernel: RX TX$' "$log" && pass "the kernel took both directions" ||
        fail "the kernel didn't take both: $(cat "$log")"
    start http kernel
    got=$(limit 10 "$curl" -sk --http1.1 -d 'ping over ktls' "https://localhost:$port/echo" || :)
    [ "$got" = "ping over ktls" ] && pass "curl --http1.1 POST over kTLS gets its body back" ||
        fail "curl POST over kTLS: $got"
    grep -q '^kernel: RX TX$' "$log" && pass "curl's connection went to the kernel" ||
        fail "curl's connection: $(cat "$log")"
else
    out=$(s_client 'hello, tls\nbye\n' -ign_eof)
    printf '%s\n' "$out" | grep -q '^hello, tls$' && grep -q '^kernel: none' "$log" &&
        pass "no kTLS in this kernel: the server serves from user space" ||
        fail "no kTLS, and the fallback failed: $out $(cat "$log")"
    echo "  NOTE this kernel has no kTLS, so the kTLS echo, KeyUpdates, and curl weren't run"
fi

stop
echo
if [ $fails -gt 0 ]; then
    echo "test-handshake.sh: $fails failed"
    exit 1
fi
echo "test-handshake.sh: all passed"
