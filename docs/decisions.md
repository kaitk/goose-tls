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

## Proposed

- **OpenSSL 3.** It is available on every Linux distribution and in every Docker base
  image, and from 3.0 it hands the record layer to the kernel on Linux
  (`SSL_OP_ENABLE_KTLS`). The alternatives in goose-http's task 014: BoringSSL (used by
  h2o and other fast servers, but no stable API or releases), rustls-ffi (needs a Rust
  toolchain to build), and BearSSL (TLS 1.2 at most, so it fails HttpArena's TLS 1.3
  check). snowtime-native uses rustls with aws-lc-rs.

## Open

- How macOS and Windows get OpenSSL 3. macOS ships LibreSSL without headers; Homebrew's
  `openssl@3` sits under a prefix that differs by architecture. A `.build` sidecar takes
  libraries and flags per platform, not per machine.
- Whether ACME lives here, as a module, or in a package of its own. It needs an HTTP
  client, which goose-http doesn't have, and JSON.
