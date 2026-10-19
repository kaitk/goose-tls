#!/bin/sh
# Runs every test this repository has, and fails on the first step that fails:
# the typecheck of the test server, the tests under test/<area>/
# (test/run_tests.py, which reports all of its failures), then the handshakes
# against openssl s_client and curl (scripts/test-handshake.sh).
#
# GOOSE or GOOSE_COMMIT names the compiler (default: the pinned release,
# scripts/goose.sh), CC the C compiler for goose build, and PORT, OPENSSL, and
# CURL pass through to test-handshake.sh. OPENSSL_ROOT_DIR picks the OpenSSL
# to build against (docs/development.md, "OpenSSL").
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/goose.sh"

step() {
    echo
    echo "== $*"
}

step "check test/tools/echo_server.goose"
"$GOOSE" check "$root/test/tools/echo_server.goose"

step "test/run_tests.py"
python3 "$root/test/run_tests.py"

step "test-handshake.sh"
"$root/scripts/test-handshake.sh"

echo
echo "test.sh: all passed"
