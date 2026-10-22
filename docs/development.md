# Development

The package is Goose over a C shim and OpenSSL. Tests have run on macOS on arm64 and on
Ubuntu 24.04 on arm64 in Docker (2026-10-19). The repository's layout is in
[README.md](../README.md#layout).

## Toolchain

Use the Goose pin in [README.md](../README.md#pins). The scripts also need:

| Tool | Requirement | Purpose |
|---|---|---|
| C compiler | clang or gcc | `goose build`, the shim, and the test programs' sockets |
| CMake | 3.20 or later, with Make or Ninja | the shim's build ([OpenSSL](#openssl)) |
| OpenSSL | 3.0 or later, headers and libraries | the shim links it |
| `openssl` and `curl` | on `PATH`; any TLS 1.3 client | the handshake and crypto checks |
| Python | 3 | `test/run_tests.py` |
| POSIX shell, git, curl, perl, shasum | on `PATH` | the scripts; perl for a time limit |

## Set up the Goose compiler

The scripts use the Goose release pinned in `scripts/goose.sh` (`v2026.3`, 2026-10-21)
unless told otherwise. The first script that needs the compiler downloads the release's
archive for the platform from
[the releases page](https://github.com/aardappel/goose/releases), checks its SHA-256,
and unpacks it into `build/goose-v2026.3-<platform>/`. Run `scripts/goose.sh` to fetch it
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

### Move the pin

The pin is a Goose release. At the start of a session, check for a newer one:

```sh
gh release list -R aardappel/goose --limit 3
```

To move to a new release, update `goose_release` and the four archives' SHA-256 sums in
`scripts/goose.sh`. GitHub lists each asset's digest:

```sh
gh api repos/aardappel/goose/releases/tags/<tag> -q '.assets[] | "\(.name) \(.digest)"'
```

Then run `scripts/test.sh`, and update the pin in `README.md` and this page's release
paths, in its own commit. Packages imported by the same program must use a compatible
Goose pin, since the program builds with one compiler.

Pin a commit only when a Goose fix that this repository needs isn't in a release yet:
set `GOOSE_COMMIT` in the scripts' environment, record the commit in the README's Pins
table with the reason, and return to a release once one includes the fix.

## OpenSSL

A program that imports goose-tls builds with CMake 3.20 or later, a C compiler, and
OpenSSL's headers and libraries, 3.0 or later ([decisions](decisions.md)). `goose build`
and `goose run` configure `CMakeLists.txt` the first time, and CMake's
`find_package(OpenSSL)` finds the library:

| Platform | Install | Where CMake finds it |
|---|---|---|
| Debian, Ubuntu | `apt install cmake libssl-dev` | The system's (Ubuntu 24.04: 3.0.13) |
| macOS | `brew install cmake openssl@3` | `/opt/homebrew/opt/openssl@3` on arm64, `/usr/local/opt/openssl@3` on x86_64 (macOS 26.3: 3.6.5; `openssl`'s 4.0.3) |
| Windows | `vcpkg install openssl:x64-windows` ([Windows](#windows)) | `OPENSSL_ROOT_DIR`: vcpkg's `installed/x64-windows` |

macOS's own `/usr/lib/libssl` is LibreSSL, without headers, and isn't used. Homebrew's
`openssl` formula is OpenSSL 4.0, installed as `openssl@4`; `CMakeLists.txt` takes
`openssl@3` first, to match the Linux images, and `OPENSSL_ROOT_DIR` picks another:

```sh
OPENSSL_ROOT_DIR=$(brew --prefix openssl) scripts/test.sh
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

### The server

`tls::server` makes the TLS 1.3 server written in Goose (`server.goose`, over
`shim/server.c`), unless `GOOSE_TLS_SERVER=openssl` was in the environment when CMake
first configured the package's C; then it makes libssl's (task 007). The choice is
cached with the rest of that configuration, so to switch, delete the package's build
directory, as for `OPENSSL_ROOT_DIR`, or build with a `GOOSE_HOME` of its own, which
keeps a whole Goose cache per choice. The tests run both builds this way:

```sh
scripts/test.sh
GOOSE_TLS_SERVER=openssl GOOSE_HOME=$HOME/.goose-openssl scripts/test.sh
```

## Tests

`scripts/test.sh` runs everything:

- The typecheck of each program under `test/tools/`.
- `test/run_tests.py`: the programs under `test/<area>/`, built with `goose build` at
  `-O0` and `-O2` and checked against `test/expected/<name>.out`. They feed contexts
  and connections PEM text and recorded ClientHellos, or run a client and a server
  against each other in memory (`test/check.goose`), with no sockets.
  `test/run_tests.py --bless` rewrites the golden files from a run.
- `scripts/test-handshake.sh`: builds `test/tools/echo_server.goose` and
  `test/tools/client.goose`, makes a fresh self-signed RSA-2048 pair, and checks the
  server on port 8081 (`PORT`) with `openssl s_client` and `curl`: an echo, a refused
  TLS 1.2 client, ALPN, HTTP/1.1 requests, HttpArena's TLS checks, and a context chosen
  per connection from `-servername` and `-alpn acme-tls/1`, with the challenge
  certificate's form. Then the package's client: a verified handshake and a request to
  a public HTTPS server (`HTTPS_HOST`, default `example.com`; `none` skips it on a
  machine without the internet), and the test server's self-signed certificate refused.
  Then an echo across s_client's two KeyUpdates. `OPENSSL` and `CURL` name other
  clients.
- `scripts/test-crypto.sh`: builds `test/tools/crypto_files.goose`, which writes a key,
  a signature, a CSR, and certificates, from a key of its own and from one `openssl`
  made, and checks them with `openssl pkey`, `dgst -verify`, `req -verify`, `verify`,
  `x509 -text`, and `asn1parse`.

The handshake tests need `openssl`, `curl`, and `perl` (for a time limit, since macOS has
no `timeout`). macOS's `curl` uses LibreSSL, which speaks TLS 1.3 and ALPN, so it serves.
macOS's `/usr/bin/openssl` is LibreSSL too (3.3.6 on macOS 26.3), which can't offer
X25519MLKEM768, so `openssl` on `PATH` must be Homebrew's: `/opt/homebrew/bin/openssl`,
the `openssl` formula's OpenSSL 4, serves for both builds and both OpenSSL versions.
The test programs' sockets are POSIX only. The client's check of a public server needs
OpenSSL's trust store filled: the `ca-certificates` package on Debian and Ubuntu, and
Homebrew's `ca-certificates`, which its `openssl@3` depends on, on macOS.

Two `goose build`s at once can fail in the package's shared CMake build
([findings](goose-findings.md)), so `test/run_tests.py` runs one build at a time and
the test programs in parallel.

`scripts/test-sanitizers.sh` builds the tests under `test/<area>/` with clang's ASan and
UBSan, against the OpenSSL that CMake found for the package. On macOS it uses Apple
clang, whose ASan has no leak detection on arm64, so leaks are checked on Linux only.

macOS's `/bin/sh` is bash 3.2, which reads an apostrophe inside `"${VAR:?message}"` as
an opening quote; check a script with `/bin/sh -n` there.

### On Linux, from macOS

Docker runs the tests in an arm64 Linux container. From the repository's root, with an
image that has `build-essential cmake git curl ca-certificates python3 libssl-dev
openssl perl` on `ubuntu:24.04`:

```sh
docker run --rm -v "$PWD":/src:ro IMAGE sh -c \
    'mkdir /w && cd /src && tar --exclude=./build -cf - . | tar -xf - -C /w && cd /w && scripts/test.sh'
```

The copy leaves out `build/`, which holds the macOS compiler.

### Windows

Checked 2026-10-22 on Windows 11 Pro 10.0.26300, in Git Bash: `test/run_tests.py` and
`scripts/test-crypto.sh` pass in both builds. `scripts/test-handshake.sh` doesn't run,
since the test programs' sockets are POSIX only.

| Tool | Source | Version used |
|---|---|---|
| C compiler, CMake | Visual Studio Build Tools 2026 (18), the `VCTools` workload | clang-cl 22.1.3, which `goose build` picked; CMake 4.3.1 |
| OpenSSL | vcpkg, `openssl:x64-windows`, built from source, no installer or admin rights | 3.6.5 |
| `openssl` command | Git for Windows | 3.2.1, for `test-crypto.sh` |
| Python | on `PATH` as `python` | 3.14 |

The Build Tools' CMake isn't on Git Bash's `PATH`, and the test programs load OpenSSL's
DLLs from vcpkg's `bin`, so put both there, and give each build its own `GOOSE_HOME`:

```sh
export PATH="$PATH:/c/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin:$VCPKG/installed/x64-windows/bin"
export OPENSSL_ROOT_DIR="$VCPKG/installed/x64-windows"
python test/run_tests.py
GOOSE_TLS_SERVER=openssl GOOSE_HOME=$HOME/.goose-openssl python test/run_tests.py
```

`VCPKG` is vcpkg's checkout. `python3` in Git Bash may be the Microsoft Store's stub;
`python` is the installed one.

### On Linux, from Windows

WSL runs the tests on a checkout under `/mnt/c`. A worktree that Windows' git made has
a Windows path in its `.git` file, which WSL's git can't follow ("not a git
repository"); the tests don't need git, but `spikes/02-goose-server/run.sh` reads the
commit from it, so give it `COMMIT` there (2026-10-22).
