#!/bin/sh
# Handshakes against the test server (test/tools/echo_server.goose), built with
# goose build, from openssl s_client and curl: an echo, a refused TLS 1.2
# client, ALPN (a client offering none of the server's protocols refused with
# no_application_protocol), HTTP/1.1 requests, and HttpArena's TLS checks (its
# scripts/validate.sh, tls_posture_probe and tls_quality_probe, at 2d85137):
# the served certificate is the one given, TLS 1.3 with one of its three
# suites, no ALPN protocol the client didn't offer, and no obsolete protocol
# or weak cipher accepted. Then a context chosen per connection from the SNI
# name and ALPN offer, with TLS-ALPN-01's challenge certificate (the server's
# choose option); the package's client (test/tools/client.goose) against a
# public HTTPS server and against the test server's self-signed certificate;
# and a KeyUpdate from s_client each way.
#
# The certificate is a self-signed RSA-2048 pair made for the run, as
# HttpArena mounts one. PORT (default 8081, HttpArena's HTTP/1.1 TLS port)
# is where the server listens; GOOSE names the compiler, CC the C compiler,
# OPENSSL the openssl command, and CURL the curl command. HTTPS_HOST (default
# example.com) is the public server the client checks against, on port 443;
# HTTPS_HOST=none skips that check, on a machine without the internet.
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

for tool in echo_server client; do
    echo "== build test/tools/$tool.goose"
    "$GOOSE" build ${CC:+--cc "$CC"} -o "$work/$tool" "$root/test/tools/$tool.goose" |
        grep -v '^parsed\|^typechecked\|^bce\|^wrote' || :
done
"$openssl" req -x509 -newkey rsa:2048 -nodes -keyout "$work/server.key" -out "$work/server.crt" \
    -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
"$openssl" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$work/ec.key" \
    -out "$work/ec.crt" -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
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
# Starts the server with its mode and options, and the RSA pair, or the one
# cert_file and key_file name; its output goes to $log.
cert_file= key_file=
start() {
    stop
    log="$work/server-$(echo "$*" | tr ' ' '-').log"
    "$work/echo_server" "$port" "${cert_file:-$work/server.crt}" "${key_file:-$work/server.key}" "$@" >"$log" 2>&1 &
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
# Whether the server's log gets a line matching $1 within 5 s: the server may print
# after the client has its answer.
logged() {
    i=0
    until grep -q "$1" "$log"; do
        i=$((i + 1))
        [ $i -gt 50 ] && return 1
        sleep 0.1
    done
}
# s_client's output for a connection to the server, with its stdin from $1.
s_client() {
    input=$1
    shift
    # SNI localhost, unless the options name another.
    case " $* " in *" -servername "*) ;; *) set -- -servername localhost "$@" ;; esac
    printf '%b' "$input" | limit 10 "$openssl" s_client -connect "127.0.0.1:$port" "$@" 2>&1 || :
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
# Whether a handshake with these s_client options is refused with
# no_application_protocol, as RFC 7301, section 3.2, asks when the client's
# ALPN offers none of the server's protocols.
refused_alpn() {
    s_client '' "$@" | grep -qi 'alert no application protocol'
}
refused_alpn -alpn h2 && pass "h2 offered: refused with no_application_protocol" ||
    fail "h2 offered: not refused with no_application_protocol"
got=$(s_client '' | grep -E '^(ALPN protocol|No ALPN)' | head -1)
[ "$got" = "No ALPN negotiated" ] && pass "none offered: $got" || fail "none offered: $got"

echo
echo "== Suites, groups, signatures, and a HelloRetryRequest"
# What a connection with these s_client options negotiated, once it echoed:
# its suite, its group, the server's signature, and how many ServerHellos
# came (two after a HelloRetryRequest); or "no echo".
negotiated() {
    out=$(s_client 'ping\nbye\n' -ign_eof -msg "$@")
    if ! printf '%s\n' "$out" | grep -q '^ping$'; then
        echo "no echo"
        return
    fi
    suite=$(printf '%s\n' "$out" | grep -m1 '^New, ' | sed 's/.*Cipher is //')
    # A KEM group, such as X25519MLKEM768, is named on a line of its own; an
    # ECDHE one in "Peer Temp Key: X25519, ..." or "...: ECDH, prime256v1, ...".
    group=$(printf '%s\n' "$out" | grep -m1 'Negotiated TLS1.3 group' | sed 's/.*: *//')
    [ -n "$group" ] || group=$(printf '%s\n' "$out" | grep -m1 'Peer Temp Key' |
        sed 's/.*Temp Key: *//; s/^ECDH, *//; s/,.*//')
    sig=$(printf '%s\n' "$out" | grep -m1 'Peer signature type' | sed 's/.*: *//')
    hellos=$(printf '%s\n' "$out" | grep -c '<<< .*ServerHello' || :)
    echo "$suite $group $sig $hellos"
}
# want is a pattern for negotiated's line.
check_negotiated() {
    want=$1
    shift
    got=$(negotiated "$@")
    case $got in $want) pass "$*: $got" ;; *) fail "$*: $got, not $want" ;; esac
}
for suite in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
    check_negotiated "$suite *" -ciphersuites "$suite"
done
check_negotiated "* X25519MLKEM768 * 1" -groups X25519MLKEM768
check_negotiated "* X25519 * 1" -groups X25519
check_negotiated "* prime256v1 * 1" -groups P-256
# A group no default of either server has, shared first: a HelloRetryRequest
# for X25519.
check_negotiated "* X25519 * 2" -groups brainpoolP256r1tls13:X25519
check_negotiated "* rsa_pss_rsae_sha256 1" -sigalgs rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256
cert_file=$work/ec.crt key_file=$work/ec.key
start echo
check_negotiated "* ecdsa_secp256r1_sha256 1" -sigalgs ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256
cert_file= key_file=
start echo

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

echo
echo "== A context per connection, from SNI and ALPN"
start echo choose
# The subject and ALPN protocol a connection with these s_client options gets.
served() {
    out=$(s_client '' "$@")
    subject=$(printf '%s\n' "$out" | "$openssl" x509 -noout -subject 2>/dev/null | sed 's/.*CN *= *//' || :)
    proto=$(printf '%s\n' "$out" | grep -m1 -E '^(ALPN protocol|No ALPN)' | sed 's/ALPN protocol: //' || :)
    echo "$subject, $proto"
}
check_served() {
    want=$1
    shift
    got=$(served "$@")
    [ "$got" = "$want" ] && pass "$*: $got" || fail "$*: $got, not $want"
}
check_served "localhost, No ALPN negotiated" -servername localhost
check_served "localhost, http/1.1" -servername localhost -alpn http/1.1
refused_alpn -servername localhost -alpn acme-tls/1 &&
    pass "-servername localhost -alpn acme-tls/1: refused with no_application_protocol" ||
    fail "-servername localhost -alpn acme-tls/1: not refused with no_application_protocol"
check_served "other.test, http/1.1" -servername other.test -alpn http/1.1
check_served "localhost, http/1.1" -servername acme.test -alpn http/1.1
check_served "acme.test, acme-tls/1" -servername acme.test -alpn acme-tls/1
logged "^hello: server_name 'acme.test', acme-tls/1 true, context acme$" &&
    pass "the server saw acme.test and acme-tls/1 at the ClientHello" || fail "the server's log: $(cat "$log")"
# RFC 8737, section 3: one dNSName, and a critical acmeIdentifier extension
# whose value is an OCTET STRING of the key authorization's SHA-256.
s_client '' -servername acme.test -alpn acme-tls/1 | "$openssl" x509 -outform PEM >"$work/challenge.crt" 2>/dev/null || :
text=$("$openssl" x509 -in "$work/challenge.crt" -noout -text 2>/dev/null || :)
printf '%s\n' "$text" | grep -q '1\.3\.6\.1\.5\.5\.7\.1\.31: critical' &&
    pass "x509 -text: the challenge certificate's acmeIdentifier is critical" ||
    fail "no critical acmeIdentifier: $text"
sans=$(printf '%s\n' "$text" | grep -A1 'Subject Alternative Name' | tail -1 | tr -d ' ')
[ "$sans" = "DNS:acme.test" ] && pass "x509 -text: its only name is $sans" || fail "its names: $sans"
want=$(printf 'token.thumbprint' | "$openssl" dgst -sha256 -r | cut -d' ' -f1)
got=$("$openssl" asn1parse -in "$work/challenge.crt" 2>/dev/null |
    grep -A2 ':id-pe-acmeIdentifier\|:1\.3\.6\.1\.5\.5\.7\.1\.31' | grep -o '\[HEX DUMP\]:.*' | sed 's/.*://' |
    tr 'A-F' 'a-f' || :)
[ "$got" = "0420$want" ] && pass "its acmeIdentifier holds the key authorization's SHA-256" ||
    fail "its acmeIdentifier is ${got:-missing}, not 0420$want"
out=$(s_client 'hello, other\nbye\n' -servername other.test -ign_eof)
printf '%s\n' "$out" | grep -q '^hello, other$' && pass "other.test's connection echoes" ||
    fail "other.test's echo: $out"

echo
echo "== The package's client"
start http
if [ "${HTTPS_HOST:-example.com}" = none ]; then
    echo "  NOTE HTTPS_HOST=none: no public server checked"
else
    host=${HTTPS_HOST:-example.com}
    out=$(limit 20 "$work/client" "$host" 443 2>&1 || :)
    if printf '%s\n' "$out" | grep -q '^handshake: TLSv1.3' && printf '%s\n' "$out" | grep -q '^response: HTTP/1.1 '; then
        pass "$host: a verified handshake and $(printf '%s\n' "$out" | grep '^response:' | sed 's/response: //')"
    else
        fail "$host: $out"
    fi
fi
out=$(limit 10 "$work/client" localhost "$port" 2>&1 || :)
case $out in
*"certificate verify failed"*"self-signed certificate"* | *"certificate verify failed"*"self signed certificate"*)
    pass "the system's authorities: the self-signed server is refused" ;;
*) fail "the self-signed server: $out" ;;
esac
out=$(limit 10 "$work/client" localhost "$port" "$work/server.crt" 2>&1 || :)
printf '%s\n' "$out" | grep -q '^response: HTTP/1.1 200 OK' &&
    pass "trusting its certificate: $(printf '%s\n' "$out" | head -1)" || fail "trusting its certificate: $out"
out=$(limit 10 "$work/client" 127.0.0.1 "$port" "$work/server.crt" 2>&1 || :)
case $out in
*"IP address mismatch"*) pass "127.0.0.1, which the certificate doesn't name, is refused" ;;
*) fail "127.0.0.1: $out" ;;
esac

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

stop
echo
if [ $fails -gt 0 ]; then
    echo "test-handshake.sh: $fails failed"
    exit 1
fi
echo "test-handshake.sh: all passed"
