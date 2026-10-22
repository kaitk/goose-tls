#!/bin/sh
# Runs the tests under test/<area>/ with AddressSanitizer and
# UndefinedBehaviorSanitizer: each program's C (goose -o --standalone, once
# with --debug's overflow and range checks and once without) compiled by clang
# with the package's shims and OpenSSL, run, and checked against its golden
# file, as test/run_tests.py checks the goose build of it. The fixtures that
# must not compile are left to run_tests.py. Linux and macOS, with clang.
#
# GOOSE or GOOSE_COMMIT names the compiler (scripts/goose.sh).
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/goose.sh"
out=$root/build/sanitizers
mkdir -p "$out"

# goose.h, which the shims include, is written beside the package's native
# part (docs/development.md, "OpenSSL"); a build of the smallest test makes it.
"$GOOSE" build -o "$out/probe" "$root/test/conn/hello.goose" >/dev/null
wrapper=$(grep -l "$root\"" "${GOOSE_HOME:-$HOME/.goose}"/build/pkg/local/*/*/wrapper/CMakeLists.txt | head -1)
pkg=$(dirname "$(dirname "$wrapper")")
cp "$pkg/include/goose.h" "$out/goose.h"
# The OpenSSL that CMake found for that build, such as Homebrew's on macOS.
ssl_include=$(sed -n 's/^OPENSSL_INCLUDE_DIR:PATH=//p' "$pkg/cmake/CMakeCache.txt")
ssl_lib=$(dirname "$(sed -n 's/^OPENSSL_CRYPTO_LIBRARY:FILEPATH=//p' "$pkg/cmake/CMakeCache.txt")")

shims="$root/shim/server.c $root/shim/tls.c $root/shim/crypto.c"
cflags="-g -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer
        -DOPENSSL_API_COMPAT=30000 -DOPENSSL_NO_DEPRECATED -I$out -I$root/shim -I$ssl_include -L$ssl_lib"
fails=0
for test in "$root"/test/*/*.goose; do
    case $test in */tools/* | */expected/*) continue ;; esac
    grep -q '^// error: ' "$test" && continue
    name=$(basename "$test" .goose)
    for mode in debug release; do
        flag=; [ $mode = debug ] && flag=--debug
        dir=$out/$mode/$name
        mkdir -p "$dir"
        if ! "$GOOSE" -o "$dir/$name.c" --standalone $flag "$test" >"$dir/goose.log" 2>&1 ||
            ! clang $cflags -o "$dir/$name" "$dir/$name.c" $shims -lssl -lcrypto -lm -pthread \
                >"$dir/cc.log" 2>&1; then
            echo "FAIL $name ($mode): doesn't build"
            tail -5 "$dir/goose.log" "$dir/cc.log"
            fails=$((fails + 1))
            continue
        fi
        if ! (cd "$dir" && ./"$name" >out.txt 2>err.txt); then
            echo "FAIL $name ($mode): exit status"
            tail -20 "$dir/err.txt"
            fails=$((fails + 1))
        elif ! diff -q "$root/test/expected/$name.out" "$dir/out.txt" >/dev/null; then
            echo "FAIL $name ($mode): output differs"
            diff "$root/test/expected/$name.out" "$dir/out.txt" | head -10
            fails=$((fails + 1))
        else
            echo "ok   $name ($mode)"
        fi
    done
done
[ $fails -eq 0 ] && echo "test-sanitizers.sh: all passed" || { echo "test-sanitizers.sh: $fails failed"; exit 1; }
