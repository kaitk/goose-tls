#!/bin/sh
# Runs every test this repository has, and fails on the first step that fails:
# the typecheck of tls.goose and of each program under test/tools/, the tests
# under test/<area>/ (test/run_tests.py, which reports all of its failures), the
# handshakes against openssl s_client and curl (scripts/test-handshake.sh),
# then the keys and certificates against openssl (scripts/test-crypto.sh).
#
# GOOSE or GOOSE_COMMIT names the compiler (default: the pinned release,
# scripts/goose.sh), CC the C compiler for goose build, and PORT, OPENSSL,
# CURL, and HTTPS_HOST pass through to the scripts. OPENSSL_ROOT_DIR picks the
# OpenSSL to build against (docs/development.md, "OpenSSL").
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/goose.sh"

step() {
    echo
    echo "== $*"
}

for f in "$root"/tls.goose "$root"/test/tools/*.goose; do
    step "check ${f#"$root"/}"
    "$GOOSE" check "$f"
done

step "test/run_tests.py"
python3 "$root/test/run_tests.py"

step "test-handshake.sh"
"$root/scripts/test-handshake.sh"

step "test-crypto.sh"
"$root/scripts/test-crypto.sh"

echo
echo "test.sh: all passed"
