#!/bin/sh
# Checks the keys, signatures, and certificates for ACME against openssl:
# test/tools/crypto_files.goose writes them, from a key it generates and from
# one openssl generated (SEC 1's "EC PRIVATE KEY"), and openssl checks each:
# the key is P-256 and public_xy its point, the ES256 signature verifies
# (dgst -verify), the CSR's signature verifies and it names both names (req
# -verify), the self-signed certificate verifies against itself, and the
# challenge certificate has RFC 8737's form (x509 -text).
#
# GOOSE names the compiler, CC the C compiler, and OPENSSL the openssl command.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/goose.sh"
openssl=${OPENSSL:-openssl}
work=$root/build/crypto
rm -rf "$work"
mkdir -p "$work"

fails=0
pass() { echo "  PASS $*"; }
fail() {
    echo "  FAIL $*"
    fails=$((fails + 1))
}

echo "== build test/tools/crypto_files.goose"
"$GOOSE" build ${CC:+--cc "$CC"} -o "$work/crypto_files" "$root/test/tools/crypto_files.goose" |
    grep -v '^parsed\|^typechecked\|^bce\|^wrote' || :
[ -x "$work/crypto_files" ] || { echo "test-crypto.sh: the build failed"; exit 1; }
echo "client: $("$openssl" version)"

# Checks the files in $1, made from the key described by $2.
check() {
    d=$1
    what=$2
    "$openssl" pkey -in "$d/key.pem" -pubout -out "$d/pub.pem" 2>/dev/null
    text=$("$openssl" pkey -in "$d/key.pem" -noout -text 2>/dev/null || :)
    printf '%s\n' "$text" | grep -q 'NIST CURVE: P-256\|ASN1 OID: prime256v1' && pass "$what: key.pem is P-256" ||
        fail "$what: key.pem: $text"
    # The point, after its 04 prefix, as pkey -text prints it.
    point=$(printf '%s\n' "$text" | sed -n '/^pub:/,/^[A-Z]/p' | grep '^ ' | tr -d ' :\n')
    xy=$(od -An -v -tx1 "$d/xy.bin" | tr -d ' \n')
    [ "$point" = "04$xy" ] && pass "$what: public_xy is the key's point" || fail "$what: public_xy $xy, point $point"
    out=$("$openssl" dgst -sha256 -verify "$d/pub.pem" -signature "$d/sig.der" "$d/data.txt" 2>&1 || :)
    [ "$out" = "Verified OK" ] && pass "$what: dgst -verify: the ES256 signature $out" || fail "$what: dgst -verify: $out"
    printf 'x' >>"$d/data.txt"
    out=$("$openssl" dgst -sha256 -verify "$d/pub.pem" -signature "$d/sig.der" "$d/data.txt" 2>&1 || :)
    [ "$out" != "Verified OK" ] && pass "$what: dgst -verify: other data fails" || fail "$what: other data verified"
    out=$("$openssl" req -in "$d/csr.der" -inform DER -verify -noout -text 2>&1 || :)
    printf '%s\n' "$out" | grep -qi 'verify OK\|Certificate request self-signature verify OK' &&
        pass "$what: req -verify: the CSR's signature verifies" || fail "$what: req -verify: $out"
    printf '%s\n' "$out" | grep -q 'DNS:example.test, DNS:www.example.test' &&
        pass "$what: the CSR names example.test and www.example.test" || fail "$what: the CSR's names: $out"
    printf '%s\n' "$out" | grep -q 'Subject: CN *= *example.test' &&
        pass "$what: the CSR's subject is CN=example.test" || fail "$what: the CSR's subject: $out"
    "$openssl" req -in "$d/csr.der" -inform DER -pubkey -noout >"$d/csr-pub.pem" 2>/dev/null
    cmp -s "$d/csr-pub.pem" "$d/pub.pem" && pass "$what: the CSR carries the key" || fail "$what: the CSR's key differs"
    out=$("$openssl" verify -CAfile "$d/cert.pem" "$d/cert.pem" 2>&1 || :)
    case $out in *": OK") pass "$what: the self-signed certificate verifies against itself" ;;
    *) fail "$what: verify: $out" ;; esac
    out=$("$openssl" x509 -in "$d/challenge.pem" -noout -text 2>&1 || :)
    printf '%s\n' "$out" | grep -q '1\.3\.6\.1\.5\.5\.7\.1\.31: critical' &&
        pass "$what: x509 -text: the challenge certificate's acmeIdentifier is critical" ||
        fail "$what: x509 -text: $out"
    sans=$(printf '%s\n' "$out" | grep -A1 'Subject Alternative Name' | tail -1 | tr -d ' ')
    [ "$sans" = "DNS:example.test" ] && pass "$what: x509 -text: its only name is $sans" ||
        fail "$what: its names: $sans"
    want=$(printf 'token.thumbprint' | "$openssl" dgst -sha256 -r | cut -d' ' -f1)
    got=$("$openssl" asn1parse -in "$d/challenge.pem" 2>/dev/null |
        grep -A2 ':1\.3\.6\.1\.5\.5\.7\.1\.31\|acmeIdentifier' | grep -o '\[HEX DUMP\]:.*' | sed 's/.*://' |
        tr 'A-F' 'a-f' || :)
    [ "$got" = "0420$want" ] && pass "$what: its acmeIdentifier is an OCTET STRING of the SHA-256" ||
        fail "$what: its acmeIdentifier is ${got:-missing}, not 0420$want"
    "$openssl" x509 -in "$d/challenge.pem" -noout -pubkey >"$d/challenge-pub.pem" 2>/dev/null
    cmp -s "$d/challenge-pub.pem" "$d/pub.pem" && pass "$what: the challenge certificate carries the key" ||
        fail "$what: the challenge certificate's key differs"
}

echo
echo "== A key from key_generate"
mkdir -p "$work/generated"
"$work/crypto_files" "$work/generated"
check "$work/generated" generated

echo
echo "== A key from openssl, read with key_from_pem"
mkdir -p "$work/openssl"
"$openssl" ecparam -name prime256v1 -genkey -noout -out "$work/openssl.key" 2>/dev/null
"$work/crypto_files" "$work/openssl" "$work/openssl.key"
check "$work/openssl" "openssl's"
"$openssl" pkey -in "$work/openssl.key" -pubout -out "$work/openssl-pub.pem" 2>/dev/null
cmp -s "$work/openssl-pub.pem" "$work/openssl/pub.pem" && pass "key_pem holds openssl's key" ||
    fail "key_pem's key isn't openssl's"

echo
if [ $fails -gt 0 ]; then
    echo "test-crypto.sh: $fails failed"
    exit 1
fi
echo "test-crypto.sh: all passed"
