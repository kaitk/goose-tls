# Development

## Layout

```
tls.goose           the package: namespace tls, the API over the shim
tls.build           the sidecar: the shim is the CMake target goose_tls
CMakeLists.txt      builds shim/tls.c and finds OpenSSL
shim/tls.c          the C: OpenSSL's API as handles, bytes, and status codes
test/<area>/        the tests, each a program with a golden file in test/expected/
test/certs/         a self-signed RSA-2048 pair for the tests, valid until 2125, and a
                    key that matches no certificate (other.key)
test/hellos/        ClientHellos recorded from openssl s_client 4.0.3, offering TLS 1.2
                    only and TLS 1.3, each with ALPN h2 and http/1.1
test/tools/         the handshake tests' server, with sockets of its own (net.c)
scripts/            goose.sh, test.sh, test-handshake.sh
```

## Set up the Goose compiler

The scripts use the Goose release pinned in `scripts/goose.sh` (`v2026.2`, 2026-10-16)
unless told otherwise. The first script that needs the compiler downloads the release's
archive for the platform from
[the releases page](https://github.com/aardappel/goose/releases), checks its SHA-256,
and unpacks it into `build/goose-v2026.2-<platform>/`. Run `scripts/goose.sh` to fetch it
and print the compiler's path. The release has no archive for Linux on arm64; there the
script clones the tag and builds it with CMake and a C++ compiler, which takes a few
minutes the first time.

Use another compiler only when the release can't do the job, such as a Goose fix not
yet released. `GOOSE` names a binary; `GOOSE_COMMIT` names a full 40-hex commit of
`aardappel/goose`, which the scripts clone into `build/goose-<commit>/` and build with
CMake.

The `.build` sidecar needs `exclude = ["build"]`, as goose-http's has: Goose collects a
package's JIT symbol table from every `.goose` file under its root, and the release's
stdlib under `build/` declares the runtime's `extern fn`s.

## OpenSSL

A program that imports goose-tls builds with CMake 3.20 or later, a C compiler, and
OpenSSL's headers and libraries, 3.0 or later ([decisions](decisions.md)). `goose build`
and `goose run` configure `CMakeLists.txt` the first time, and CMake's
`find_package(OpenSSL)` finds the library:

| Platform | Install | Where CMake finds it |
|---|---|---|
| Debian, Ubuntu | `apt install cmake libssl-dev` | The system's (Ubuntu 24.04: 3.0.13) |
| macOS | `brew install cmake openssl@3` | `/opt/homebrew/opt/openssl@3` on arm64, `/usr/local/opt/openssl@3` on x86_64 |
| Windows | Not tried yet | `OPENSSL_ROOT_DIR`, such as the directory of an installer's or vcpkg's OpenSSL |

macOS's own `/usr/lib/libssl` is LibreSSL, without headers, and isn't used. Homebrew's
`openssl` formula is OpenSSL 4.0; `CMakeLists.txt` takes `openssl@3` first, to match the
Linux images, and `OPENSSL_ROOT_DIR` picks another:

```sh
OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@4 scripts/test.sh
```

The program links OpenSSL's shared libraries, so the machine it runs on needs them too
(`libssl3` on Debian and Ubuntu).

Goose configures the package's CMake build once, under `~/.goose/build/pkg/`, and
CMake caches the OpenSSL it found there. After changing `OPENSSL_ROOT_DIR`, delete that
directory, `~/.goose/build/pkg/local/<hash>/`, the one whose
`<toolchain>/wrapper/CMakeLists.txt` names this checkout, so the next build finds
OpenSSL again:

```sh
grep -l "$PWD\"" ~/.goose/build/pkg/local/*/*/wrapper/CMakeLists.txt
```

## Tests

`scripts/test.sh` runs everything:

- `test/run_tests.py`: the programs under `test/<area>/`, built with `goose build` at
  `-O0` and `-O2` and checked against `test/expected/<name>.out`. They feed a context
  and a connection PEM text and recorded ClientHellos, with no sockets.
  `test/run_tests.py --bless` rewrites the golden files from a run.
- `scripts/test-handshake.sh`: builds `test/tools/echo_server.goose`, makes a fresh
  self-signed RSA-2048 pair, and checks the server on port 8081 (`PORT`) with
  `openssl s_client` and `curl`: an echo, a refused TLS 1.2 client, ALPN, HTTP/1.1
  requests, and HttpArena's TLS checks. `OPENSSL` and `CURL` name other clients.

The handshake tests need `openssl`, `curl`, and `perl` (for a time limit, since macOS has
no `timeout`). macOS's `curl` uses LibreSSL, which speaks TLS 1.3 and ALPN, so it serves.
The test server's sockets are POSIX only.

Two `goose build`s at once that both configure the package's CMake build for the first
time fail ([findings](goose-findings.md)), so `test/run_tests.py` builds its first test
alone and the rest in parallel.

### On Linux, from macOS

Docker runs the tests in an arm64 Linux container. From the repository's root, with an
image that has `build-essential cmake git curl ca-certificates python3 libssl-dev
openssl perl` on `ubuntu:24.04`:

```sh
docker run --rm -v "$PWD":/src:ro IMAGE sh -c \
    'mkdir /w && cd /src && tar --exclude=./build -cf - . | tar -xf - -C /w && cd /w && scripts/test.sh'
```

The copy leaves out `build/`, which holds the macOS compiler.
