#!/bin/sh
# Builds fuzz.goose's targets as libFuzzer binaries with AddressSanitizer and
# UndefinedBehaviorSanitizer, into build/fuzz/: fuzz_hello, fuzz_conn, and
# fuzz_open. The Goose program's C (goose -o, --standalone, --header), the
# package's shims, and targets.c are compiled together by clang, with OpenSSL
# from the system. Needs clang with libFuzzer, and OpenSSL 3's headers.
#
# Run one with a corpus directory of its own, such as
#   build/fuzz/fuzz_conn -max_total_time=600 build/fuzz/corpus-conn
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
. "$root/scripts/goose.sh"
out=$root/build/fuzz
mkdir -p "$out"

"$GOOSE" -o "$out/fuzz.c" --standalone --header "$out/fuzz.h" "$here/fuzz.goose" |
    grep -v '^parsed\|^typechecked\|^bce\|^wrote' || :
# goose.h, which the shims include, is written beside the package's native
# part when goose build builds it (docs/development.md, "OpenSSL", finds that
# directory); a build of the smallest test makes it.
"$GOOSE" build -o "$out/probe" "$root/test/conn/hello.goose" >/dev/null
wrapper=$(grep -l "$root\"" "${GOOSE_HOME:-$HOME/.goose}"/build/pkg/local/*/*/wrapper/CMakeLists.txt | head -1)
cp "$(dirname "$(dirname "$wrapper")")/include/goose.h" "$out/goose.h"

flags="-g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined
       -DOPENSSL_API_COMPAT=30000 -DOPENSSL_NO_DEPRECATED -I$out -I$root/shim"
for target in fuzz_hello fuzz_conn fuzz_open; do
    clang $flags -DTARGET=$target -o "$out/$target" "$out/fuzz.c" "$here/targets.c" \
        "$root/shim/server.c" "$root/shim/tls.c" "$root/shim/crypto.c" -lssl -lcrypto -lm -pthread
done
echo "built: $out/fuzz_hello $out/fuzz_conn $out/fuzz_open"
