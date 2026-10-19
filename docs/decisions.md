# Decisions

The record of goose-tls's design decisions, for contributors and agents: each dated,
with its reason and the trade-off that matters.

## Settled

- **A package of its own.** TLS lives outside goose-http, so a program serving
  plaintext doesn't link OpenSSL, and the Goose packages' C for TLS stays in one
  repository. goose-http reaches it only from its `http.tls` module, so only a program
  that imports that module declares goose-tls in its root file (goose-http's task 014,
  2026-10-11; repository created 2026-10-19).
- **Bindings, not TLS in Goose.** Constant-time cryptography, the record layer, and
  X.509 are out of scope. HttpArena's rules also require a standard TLS stack (its
  `json-tls` implementation rules, checked at `2d85137`, 2026-10-18).
- **No I/O in the package.** A connection's state takes the bytes the program read and
  returns the bytes to send, through memory BIOs. goose-http's loops differ by platform
  (epoll, io_uring, kqueue, IOCP), and a library that read sockets itself would need a
  path per loop.
- **ACME in a package of its own, built on goose-tls (2026-10-19).** ACME needs an HTTP
  client and JSON, so an ACME module here would make goose-tls depend on what depends
  on it: goose-http's `http.tls` imports goose-tls. Other Goose HTTP servers should be
  able to use it too, without goose-http. goose-tls provides the hooks it needs: a
  certificate chosen per connection from SNI and ALPN, a certificate replaced while
  running, client TLS, and the keys, signatures, CSR, and challenge certificate
  (task 003). The package itself is goose-rest's task 049.
- **OpenSSL, through its 3.0 API (2026-10-19).** The shim is written against OpenSSL
  3.0's API with nothing it deprecates (`OPENSSL_API_COMPAT=30000` and
  `OPENSSL_NO_DEPRECATED`), and builds with any OpenSSL from 3.0 to 4.x. 3.0 is what the
  base images HttpArena's entries build on ship: Ubuntu 24.04 has 3.0.13 and Debian
  bookworm 3.0.x (`buildpack-deps:bookworm`, `debian:bookworm-slim`). 4.0 is current,
  and Homebrew's `openssl` is 4.0, but every function the shim calls is in both; the
  tests pass against 3.0.13, 3.6.5, and 4.0.3. OpenSSL is on every Linux distribution
  and in every Docker base image, and from 3.0 can hand the record layer to the kernel
  on Linux (`SSL_OP_ENABLE_KTLS`). Rejected, from goose-http's task 014: BoringSSL
  (used by h2o and other fast servers, but no stable API or releases), rustls-ffi
  (needs a Rust toolchain to build), and BearSSL (TLS 1.2 at most, so it fails
  HttpArena's TLS 1.3 check). snowtime-native uses rustls with aws-lc-rs. The trade-off:
  a function new in 3.x after 3.0 needs a version check before the shim can use it.
- **Linked through a CMake target (2026-10-19).** `tls.build` names `cmake_target =
  "goose_tls"`, and `CMakeLists.txt` finds OpenSSL with CMake's `find_package(OpenSSL
  3.0)`. A sidecar's `c_libs` only adds `-lssl`, and no sidecar key adds a library
  directory (Goose `v2026.2`), so `c_sources` and `c_libs` can't reach an OpenSSL outside
  the C compiler's own paths: Homebrew's, under `/opt/homebrew` on arm64 and
  `/usr/local` on x86_64, or Windows' anywhere. `find_package` finds the system's on
  Linux, `CMakeLists.txt` points it at Homebrew's `openssl@3` on macOS, and
  `OPENSSL_ROOT_DIR` picks any other. The trade-off: a program that imports goose-tls
  needs CMake 3.20 or later to build, as Goose's packages built with CMake do.
- **TLS 1.3 only, with its three AEAD suites, AES-128-GCM first (2026-10-19).**
  HttpArena refuses an entry that accepts an obsolete protocol or a weak cipher, and
  checks that TLS 1.3 is negotiated; refusing TLS 1.2 meets both by construction. The
  server chooses the suite, in the order `TLS_AES_128_GCM_SHA256`,
  `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`: AES-128-GCM is the cheapest
  where the CPU has AES instructions, which HttpArena's 8gbit profile scores. The
  trade-off: clients older than TLS 1.3 (before about 2018) can't connect, which a
  server behind a proxy never sees. A setting for TLS 1.2 can come when a user needs it.
- **PEM text in, files read in Goose (2026-10-19).** A context is made from the chain's
  and key's PEM bytes, and `tls::server_files` reads the files with Goose's `os` module.
  A certificate that an ACME package gets, or one that replaces another while the server
  runs, is already in memory.
