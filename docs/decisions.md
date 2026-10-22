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
  X.509 are out of scope. Superseded for the server's connections by "A TLS 1.3 server
  in Goose over libcrypto", below (2026-10-22, `v0.0.4`); cryptography and X.509 stay
  OpenSSL's. Corrected 2026-10-22: this entry said HttpArena requires a standard TLS
  stack (its `json-tls` implementation rules, read at `2d85137`, 2026-10-18). At
  HttpArena `f020b9b` that rule applies only to entries of type `standard` and
  `infrastructure`; goose-http's entry is of type `engine`, which has no specific rules
  (task 007).
- **No I/O in the package.** A connection's state takes the bytes the program read and
  returns the bytes to send, through memory BIOs. goose-http's loops differ by platform
  (epoll, io_uring, kqueue, IOCP), and a library that read sockets itself would need a
  path per loop. kTLS amended this on 2026-10-19; that amendment goes with kTLS, below.
- **kTLS is retired (2026-10-22).** The package no longer moves connections to the
  kernel: `shim/ktls.c`, the `tls::*kernel*` calls and their constants are gone, with
  goose-http's handoff, record-control, and platform-stub paths in its matching change
  (task 007, step 6). It replaces the decisions of 2026-10-19 that the kernel takes the socket's
  record layer after the handshake, with keys from OpenSSL's public callbacks (in git
  at `9f0a33b`). On the Ryzen 5 9600X (Bazzite, kernel 6.17.7, OpenSSL 3.5.9,
  AES-128-GCM, interleaved loopback h2load runs, goose-http's task 014.02), kTLS served
  small `/json` responses about 10% faster (3.16-3.19 M against 2.84-2.92 M requests/s)
  but 16 KB ones 44% slower (112-113 K against 196-202 K requests/s), the extra cost
  mainly elsewhere in the kernel's send path. It also needs a second record-processing
  path, captured secrets, handoff states, and key updates ordered across layers, which a
  server written in Goose would have to carry too. Linux decides kTLS per socket
  direction, with no way back to user space between requests, and HTTP/2 streams share
  that decision. Reconsider it only for a measured workload, such as sendfile or NIC
  offload, that warrants the cost. The kTLS tests' RFC 8448 vectors move to the Goose
  server's key-schedule tests.
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
  and in every Docker base image. Rejected, from goose-http's task 014: BoringSSL
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
- **Key exchange: OpenSSL's default groups unless the program sets them (2026-10-20).**
  A context offers what OpenSSL does, which from 3.5 puts the hybrid X25519MLKEM768
  first, so traffic recorded today stays safe from a later quantum computer.
  `tls::use_groups(ctx, names)` sets the groups and their order, and `tls::group(c)`
  reports the one negotiated. Post-quantum stays the default for real servers. A
  program can choose X25519 alone when it wants the smaller handshake and the 6 KB
  less a connection holds, as goose-http's HttpArena entry does to match the Rust
  entries, whose rustls with the `ring` provider offers X25519, P-256, and P-384.
  Rejected: X25519 by default, which would drop the post-quantum protection browsers
  now expect.
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
- **A connection keeps no buffers between records (2026-10-20).** OpenSSL frees its
  record buffers once they're empty (`SSL_MODE_RELEASE_BUFFERS`, set on every context
  since the first shim), and the shim frees each memory BIO's buffer once it's empty:
  the to-send one in `tls_drain`, the received one in `tls_read` and `tls_handshake`.
  A memory BIO's buffer otherwise keeps the size of the most it has held: on
  HttpArena's json-tls, whose largest response is 8.5 KB, the two held 11 KB a
  connection, nearly a third of what OpenSSL holds for it. The shim frees the data itself
  rather than through `BUF_MEM_free`, which cleanses the whole buffer, since the BIOs
  hold only records. Measured on goose-http's TLS server (its task 058): an idle
  connection fell from 35.8 KB to 30.4 KB, and the peak under load by about 10 MiB at
  4,096 connections. Rejected: freeing through `BUF_MEM_free`, which cost 6.7% more
  instructions a request. The trade-off: 2.6% more instructions a request, for a
  `malloc` and a `free` of each buffer, with no loss of rate beyond the runs' spread.
  What remains is OpenSSL's, with no setting to reduce it: the connection and its two
  record layers (14 KB), the client's ML-KEM key share, kept until the connection is
  freed (6 KB), and during the handshake a 21.8 KB message buffer and an 8 KB
  buffering BIO.

## Task 007's server

Agreed 2026-10-22 pending spike 02, which passed the same day; released in `v0.0.4`.

- **A TLS 1.3 server in Goose over libcrypto (2026-10-22).**
  goose-tls's server connections move from libssl to a TLS 1.3 server whose protocol
  and record layer are written in this package, Goose by default, over libcrypto's EVP
  for every cryptographic primitive: AEAD, hashes, HMAC and HKDF, key exchange,
  signatures, and random bytes. C in `shim/` stays small: it adapts EVP, and owns what
  Goose can't, such as native handles, reference counts, and buffers that outlive a
  call, where that is simpler or safer than a Goose workaround. The reason is memory:
  libssl holds 28.5 KB per idle connection and 58.6 KB per handshake in flight, with no
  setting that reduces either (spike 01, task 005), and goose-http's TLS server used the
  most memory of the json-tls entries measured (272 MiB against 152-188 MiB for the Rust
  ones, goose-http's tasks 014.02 and 058). rustls, measured at 7.8 KB and 8.3 KB, shows
  what a small TLS 1.3 server holds; the target is at most 10,000 bytes per idle
  connection and per drained-flight connection at 4,000 held, with no CPU regression
  against OpenSSL beyond the runs' spread. Spike 02 decides: if it misses the bar,
  OpenSSL stays the deployed server and task 007 records what limits it. The plan,
  the gates, and the progress are in task 007.
  - OpenSSL stays for the cold path (PEM loading, a DER chain and an `EVP_PKEY` per
    context), the client, ACME's crypto, the tests' peer, and a server alternative
    selected at build time, kept passing the common tests, for rollback: a backend
    change happens between deployments, never by retrying a connection.
  - TLS 1.3 only, with the three suites in the server's order; X25519MLKEM768 where
    libcrypto has ML-KEM (3.5 or later), X25519, and P-256, set by `tls::use_groups`;
    ECDSA P-256 and RSA keys, signing with `ecdsa_secp256r1_sha256` and
    `rsa_pss_rsae_sha256`. Left out: TLS 1.2, accepting early data, client
    certificates, PSK-only resumption, and kTLS.
  - Session tickets, stateless, with a current and a previous ticket key per context
    and a bounded key lifetime, follow the full server immediately, in both backends.
    As built: a new issuing key every 7,200 seconds of a monotonic clock, each opening
    tickets for 14,400 seconds and issuing at most 2^30, keys that live and die with
    the process, and a 7,200-second ticket lifetime. The trade-off: a restart, or a
    second server process, makes every client's ticket a full handshake; sharing keys
    across processes waits for a caller that needs it (task 007).
  - It replaces "Bindings, not TLS in Goose" for the server's connections; "The context
    is chosen in Goose, at a paused handshake" keeps its API, with the package's own
    ClientHello parser in place of OpenSSL's callback; and "Key exchange" keeps
    `use_groups` and `group`, with the package's own default groups.

  Rejected: the Rust library over rustls that task 006 designed (agreed 2026-10-20,
  dropped 2026-10-22, not merged), since the package takes no Rust dependency in its
  build: it needed cargo or prebuilt libraries per platform, and a step that hides the
  Rust standard library's symbols, which had no answer yet on Windows. And staying on
  libssl, for its memory. The trade-offs: this package now owns a TLS state machine,
  whose correctness and security rest on its narrow scope, known-answer vectors,
  tlsfuzzer, fuzzing, sanitizers, and the OpenSSL alternative rather than on a
  maintained TLS library; and its memory and speed rest on libcrypto's per-object
  costs, which spike 02 measures.
- **ALPN with no match fails the handshake (2026-10-21, kept 2026-10-22).** A client
  that offers ALPN but none of the server's protocols gets the `no_application_protocol`
  alert, as RFC 7301, section 3.2, requires, from both the Goose server and the OpenSSL
  alternative; before `v0.0.4`, the server answered such a client without ALPN. A
  client that offers no ALPN still connects, with none. The trade-off: a client that
  offers only protocols the server lacks can no longer connect; HttpArena's clients
  offer what the server speaks.
