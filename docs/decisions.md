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
  path per loop. Amended for kTLS, below.
- **kTLS keeps the package off the socket's data path (2026-10-19).** This amends "No
  I/O in the package": after the handshake, the shim takes the socket's descriptor from
  the program and sets socket options on it, `TCP_ULP` "tls", then
  `setsockopt(SOL_TLS, TLS_RX)` and `TLS_TX` with the traffic keys, and again after a
  KeyUpdate. It never reads or writes the socket. The program's loop, epoll or io_uring,
  then sends and receives plaintext on it, and sends the two control records the kernel
  can't make itself (close_notify, and a KeyUpdate) with `sendmsg`. The handshake's
  bytes still move through memory BIOs and the program, so every loop keeps one path.
  Rejected: OpenSSL owning the socket through a socket BIO from the start, which turns
  kTLS on by itself (`SSL_OP_ENABLE_KTLS`) but puts the handshake's I/O in the shim and
  breaks the io_uring loop, whose reads and writes are submitted and completed by the
  ring. Nor does OpenSSL 3.0 to 4.x offer a public call that starts kTLS on an existing
  connection or exports the kernel's keys; OpenSSL 3.5's QUIC callbacks give secrets
  but replace the record layer. The trade-off: the shim follows OpenSSL's keys and
  sequence numbers itself (the next decision), and a program that moves a connection to
  the kernel handles its non-data records (`docs/architecture.md`).
- **The kernel's keys from OpenSSL's public callbacks (2026-10-19).** The shim takes the
  application traffic secrets from the keylog callback (`SSL_CTX_set_keylog_callback`,
  public since 1.1.1), counts each direction's records from the message callback's
  `SSL3_RT_HEADER` reports (`SSL_set_msg_callback`) since its keys last changed, and
  derives key, IV, and salt with RFC 8446's HKDF-Expand-Label through `EVP_KDF`'s HKDF.
  It follows a KeyUpdate the same way, on either side of the switch ("traffic upd").
  Every call is in OpenSSL 3.0's API; the tests check the result against RFC 8448's
  traces and against an OpenSSL client, on 3.0.13, 3.6.5, and 4.0.3. The callbacks are
  set only on a context that asks for kTLS (`tls::use_kernel`), so other connections
  pay nothing, and the secrets are wiped when the connection is freed. The switch
  happens only at a record boundary of the bytes fed, and only once OpenSSL holds no
  unread plaintext and no unsent bytes, so nothing read past the handshake is lost.
  Receiving moves first: then OpenSSL can still send and answer a KeyUpdate with
  `SSL_key_update`, while the other order would leave OpenSSL reading a KeyUpdate it
  must answer with keys it no longer holds. A suite or kernel the switch fails on leaves
  the connection in user space. The trade-off: the shim depends on the order in which
  OpenSSL reports records and key changes, which is behavior, not a documented contract;
  the tests catch a change on each OpenSSL the package supports.
- **Handles are raw pointers (2026-10-19).** A `tls::Context` or `tls::Conn` holds the
  address of OpenSSL's object, and using one after `tls::free` is undefined behavior,
  documented and not checked. A checked table of handles would need a lock, since
  goose-http's workers share a context across threads, and goose-http is the only
  caller, which frees each handle at one place. The trade-off: a use-after-free in a
  program is a crash or memory corruption rather than an error code. A checked table
  can come when a second user needs it.
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
- **The context is chosen in Goose, at a paused handshake (2026-10-19).** A context
  given to `tls::choose_context` pauses each handshake after the ClientHello (OpenSSL's
  client hello callback returning `SSL_CLIENT_HELLO_RETRY`), and `tls::handshake`
  returns `tls::HELLO`; the program reads the SNI name and the offered ALPN list, calls
  `tls::use_context`, and calls `tls::handshake` again, when the callback moves the
  connection with `SSL_set_SSL_CTX`, before ALPN is selected. Which certificate a name
  gets, and when a TLS-ALPN-01 challenge is live, is configuration and ACME's state,
  which the package's rules put in Goose, and a C callback can't call into Goose.
  Rejected: the servername callback (`SSL_CTX_set_tlsext_servername_callback`), which
  also runs in C inside the handshake and could only consult a table of names to
  contexts kept in the shim, putting ACME's state in C. The trade-off: the shim reads
  SNI and ALPN from the ClientHello's raw extension bytes, since OpenSSL parses them only
  after the callback, and a server that chooses makes one more call per handshake.
- **A client verifies against OpenSSL's store or the program's certificates
  (2026-10-19).** `tls::client` trusts OpenSSL's default store
  (`SSL_CTX_set_default_verify_paths`), and `tls::client_trusting` only the PEM it is
  given; both check the host name with `SSL_set1_host`, without partial wildcards.
  There is no client that skips verification: an ACME directory is a public HTTPS
  server, and a test server's own certificate can be trusted by name. Rejected: the
  platform's own store (the macOS keychain, Windows' certificate store), which OpenSSL
  doesn't read without code per platform. The trade-off: on macOS and Windows, the
  store is the one the OpenSSL install ships, such as Homebrew's `ca-certificates`, not
  the system's.
- **ACME's crypto in its protocols' forms (2026-10-19).** Keys are EC P-256 only,
  ES256 being the algorithm every ACME server accepts; signatures are JWS's raw
  `r || s`, CSRs DER for finalize's base64url, and certificates PEM, which `tls::server`
  takes. The ACME package then needs no ASN.1 of its own. Rejected: RSA account keys,
  and a general signing API with a choice of algorithm, which no user needs yet. The
  trade-off: a program that wants another key type needs a new call. Hashes are
  goose-hash's, not this package's: `tls::challenge_certificate` takes the key
  authorization's SHA-256, which the ACME package computes with goose-hash
  (2026-10-19).
- **Key and certificate calls fail through `return ... from tls::run`
  (2026-10-19).** `tls::key_generate`, `key_from_pem`, `key_pem`, `public_xy`,
  `sign_es256`, `csr`, `self_signed`, and `challenge_certificate` leave the innermost
  `tls::run` with a `tls::Error` whose message names the call and carries OpenSSL's
  reasons, as goose-sqlite's calls leave `sqlite::run`. An ACME client makes a chain of
  these calls, and one check of `run`'s result replaces a check after each, which ""
  sentinels needed and a caller could skip; a call outside `run` doesn't compile. The
  connection calls keep their statuses and "" results: `WANT_INPUT` and `HELLO` aren't
  failures, and an event loop handles each status where it happens. Each failing call
  takes an untyped parameter, so it is compiled only where a program calls it, since
  `goose check` and `goose run` reject a fully typed one ([findings](goose-findings.md));
  for `key_generate`, which has nothing else to take, that is the curve, `tls::P256`,
  the only one it accepts. The trade-off: a program that makes a key writes it into a
  variable outside `run`'s block, and `key_generate` takes an argument with one valid
  value.
