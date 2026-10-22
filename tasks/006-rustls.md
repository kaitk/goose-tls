# 006: Connections over rustls

Status: cancelled (2026-10-22). The package takes no Rust dependency in its build;
task 007 writes the server in Goose over libcrypto instead. The library started on the
branch `rustls-lib` was never merged or pushed, and is left as it is. What follows is
the design as it stood, kept for its map of rustls's API, which task 007 reads as a
peer implementation.

goose-tls moves from OpenSSL to a small Rust library of its own over rustls, built as a
static library with the C ABI the shim has today, so that `tls.goose` changes as little
as possible. The reason is memory: OpenSSL holds about 30 KB a connection with no
setting that reduces it, and goose-http's TLS server uses the most memory of the
entries measured on HttpArena's json-tls. The decision was in
[decisions](../docs/decisions.md) until 2026-10-22 ("Connections over our own Rust
library on rustls", in git at `9f0a33b`).

## Why

goose-http's task 058 measured OpenSSL's memory per server connection on Linux
(Ubuntu 26.04 in WSL2, OpenSSL 3.5.5, 2026-10-20), with `SSL_MODE_RELEASE_BUFFERS` set
and this package's memory BIOs freed once empty (task 004):

- **Idle**, after the handshake and one request: 30.4 KB a connection in the server's
  RSS. A C program counting OpenSSL's allocations by source line put 32.8 KB in OpenSSL
  and the BIOs before task 004: the connection and its two record layers (14.4 KB), the
  client's ML-KEM key share, kept until `SSL_free` (6.4 KB), and contexts and
  references (6.8 KB).
- **A handshake in flight**, its ClientHello read and its flight sent: 62.9 KB, with
  OpenSSL's handshake message buffer grown to 21.8 KB and an 8 KB buffering BIO, neither
  of which a program can size. With 4,096 clients connecting at once, these set the
  server's peak: 53-55 KB a connection over its RSS before, 214-232 MiB in all.
- On json-tls at 4,096 connections, the Goose entry used 272 MiB against 152-188 MiB for
  the Rust entries, which use rustls (goose-http's task 014.02, "Measured").

Task 005's spike ([spike 01](../spikes/01-rustls/README.md)) drove an OpenSSL server set
up as the shim's and a rustls server through rustls-ffi with the same feed, read, write,
and drain calls, against OpenSSL clients in one process, both negotiating
X25519MLKEM768 (rustls 0.23.46 on aws-lc-rs against OpenSSL 3.5.5, medians of 5 runs):

| Per server connection | OpenSSL | rustls, aws-lc-rs | rustls, ring (X25519) |
|---|---:|---:|---:|
| Idle, 4,000 held | 28,528 B | 7,844 B | 7,648 B |
| A handshake in flight, 4,000 held | 58,626 B | 8,336 B | 8,108 B |
| Server CPU, a full handshake | 727 µs | 615 µs | 563 µs |
| Server CPU, a json-tls-like request | 3.28 µs | 2.42 µs | 1.59 µs |

That measured rustls through rustls-ffi's buffered connection. What is still open is
this library's own cost: the unbuffered connection it uses (below), its buffers, and
goose-http's server over it.

## The claims the design rests on

Checked on 2026-10-20 against the sources of the current releases on crates.io:
rustls 0.23.46, aws-lc-rs 1.18.2 (aws-lc-sys 0.46.0), ring 0.17.14, rcgen 0.14.10,
rustls-platform-verifier 0.7.1, rustls-native-certs 0.8.5, and webpki-roots 1.0.10.
Paths are in each crate's source.

| # | Claim | Holds? | Where |
|---|---|---|---|
| 1 | TLS 1.3 server and client, ALPN, and a certificate chosen per connection | Holds. A server can pause at the ClientHello, as `tls::choose_context` does: `server::Acceptor` reads it, `Accepted::client_hello()` gives `server_name()` and `alpn()`, and `Accepted::into_connection(config)` goes on with the chosen `ServerConfig`. A `ResolvesServerCert` chooses inside the handshake instead, which can't call into Goose. Two differences from the shim: the server picks the first of its own protocols the client offered, as the shim does, but when none match it fails the handshake with `no_application_protocol` (RFC 7301, section 3.2), where the shim answers without ALPN; and `Acceptor` is on the buffered connection only (see "The design") | `src/server/server_conn.rs` (`ResolvesServerCert`, `Acceptor`, `Accepted`); `src/server/hs.rs`, `process_common` |
| 2 | No sockets: bytes in and out of memory, with feed, read, write, drain, and pending kept | Holds, with limits that the shim absorbs. The buffered connection's `read_tls` refuses input while more than 16 KB of plaintext waits unread ("received plaintext buffer full", `DEFAULT_RECEIVED_PLAINTEXT_LIMIT`), and buffers at most one record of input beyond a handshake message (64 KB); its outgoing buffer is limited to 64 KB unless `set_buffer_limit(None)`. The unbuffered connection (`UnbufferedServerConnection::process_tls_records`) has no such limits: it decrypts in the caller's buffer and leaves all buffering to the caller, so `tls::feed` can take everything | `src/conn.rs` (`read_tls`, `set_buffer_limit`); `src/common_state.rs`; `src/msgs/deframer/buffers.rs`; `src/conn/unbuffered.rs` |
| 3 | Key-exchange groups set per configuration; aws-lc-rs offers X25519MLKEM768; ring only X25519, P-256, P-384 | Holds. `CryptoProvider::kx_groups` is a `Vec` the program sets. aws-lc-rs's default, with rustls's default feature `prefer-post-quantum`: X25519MLKEM768, X25519, P-256, P-384 (SECP256R1MLKEM768 is in `ALL_KX_GROUPS` only). ring: X25519, P-256, P-384 | `src/crypto/mod.rs`; `src/crypto/aws_lc_rs/mod.rs`, `DEFAULT_KX_GROUPS`; `src/crypto/ring/mod.rs`, `ALL_KX_GROUPS` |
| 4 | KeyUpdate answered and sent; close_notify sent and received | Holds. A peer's KeyUpdate that asks for one is answered (`handle_key_update`, `should_update_key`); `refresh_traffic_keys` sends one (`WriteTraffic::refresh_traffic_keys` when unbuffered). `send_close_notify`, or `WriteTraffic::queue_close_notify`; a received one is `PeerClosed` when unbuffered | `src/server/tls13.rs`; `src/common_state.rs`; `src/conn/unbuffered.rs` |
| 5 | kTLS: traffic secrets and sequence numbers exported, and KeyUpdate after the handoff | Holds, on the unbuffered connection only. `UnbufferedServerConnection::dangerous_into_kernel_connection()` (rustls 0.23.27 or later) returns `ExtractedSecrets`, the key, IV, and sequence number for each direction, and a `KernelConnection`, whose `update_rx_secret()` and `update_tx_secret()` give the next keys after a KeyUpdate. The config must set `enable_secret_extraction`, and nothing may wait to be sent. The buffered connection has only `dangerous_extract_secrets()`, with no KeyUpdate after it (deprecated on the unbuffered one for that reason). Nothing counts records for the program after the handoff, so it must refresh keys before AES-GCM's confidentiality limit. With it, `shim/ktls.c`'s HKDF and record counting are unnecessary; setting `TCP_ULP` and `TLS_RX`/`TLS_TX` stays ours | `src/conn/kernel.rs`; `src/server/server_conn.rs`; `src/conn.rs`, `dangerous_into_kernel_connection`; `src/suites.rs`, `ExtractedSecrets` |
| 6 | ACME: P-256 keys, ES256 as raw `r \|\| s`, a CSR, and a self-signed certificate with `acmeIdentifier` | Holds, with rcgen and aws-lc-rs. rcgen: `KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)`, `KeyPair::from_pem` (PKCS#8, and SEC 1 with the `aws_lc_rs` feature), `serialize_pem`, `CertificateParams::serialize_request` (a CSR as DER), `self_signed`, serial numbers and validity dates, and `CustomExtension::new_acme_identifier`, critical, as RFC 8737 asks. aws-lc-rs: `EcdsaKeyPair` with `ECDSA_P256_SHA256_FIXED_SIGNING` signs as the 64 bytes JWS takes, and its public key gives x and y | rcgen `src/key_pair.rs`, `src/certificate.rs`; aws-lc-rs `src/ec/signature.rs` |
| 7 | Security: audits, unsafe code, FIPS | Partly. rustls: one published audit, by Cure53 in May and June 2020, of rustls with ring and webpki, CNCF-funded, two low and two informational findings ([report](https://cure53.de/pentest-report_rustls.pdf); `audit/TLS-01-report.pdf` in the rustls repository); none newer was found. The crate forbids unsafe code (`#![forbid(unsafe_code)]`, `src/lib.rs`), as rcgen does; the cryptography in aws-lc-rs and ring is C and assembly behind unsafe bindings. aws-lc-rs: FIPS through its non-default `fips` feature, which binds AWS-LC-FIPS 4.x (README); AWS-LC's module holds FIPS 140-3 certificates (CMVP #4631, #4816, #5146, among others). The default build isn't the FIPS module | rustls `src/lib.rs`; aws-lc-rs `README.md` |
| 8 | Build: what each provider needs, and a static library with a C ABI linked by CMake | Holds. aws-lc-sys without FIPS needs only a C compiler on Linux x86-64 and arm64 and macOS arm64: no CMake, Go, or bindgen, since its bindings are generated ahead. Windows MSVC x86-64 needs NASM too, or the `prebuilt-nasm` feature; Windows arm64 needs clang-cl. FIPS needs CMake and Go as well ([requirements](https://aws.github.io/aws-lc-rs/requirements/index.html)). ring needs a C compiler. A `staticlib` crate exports `extern "C"` functions; CMake can call cargo itself and import the library, with no Corrosion. Prebuilt libraries need a CI job per target and a fetch with a checksum, as `scripts/goose.sh` fetches Goose ("The design") | aws-lc-rs `README.md`; aws-lc-sys `Cargo.toml` |
| 9 | A client verifying against the system's roots, or given PEM CAs | Holds. `rustls-platform-verifier` uses the macOS and Windows stores, and on Linux reads the same files OpenSSL does through `rustls-native-certs` (`SSL_CERT_FILE` and `SSL_CERT_DIR` too); it needs rustls 0.23.27 or later. Given PEM CAs: a `RootCertStore` and `WebPkiServerVerifier`. webpki accepts no partial wildcards, as the shim's `X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS` doesn't | rustls-platform-verifier `Cargo.toml`; rustls-native-certs `src/lib.rs` |

None of them fails in a way that makes the plan unsound. Three change the design: the
kernel's API is on the unbuffered connection only (5), which `Acceptor` isn't (1); and
a client offering only protocols the server lacks now fails (1).

## The design

- **A Rust crate in `rust/`**, built as a `staticlib`, that exports the C functions
  `tls.goose` declares today, by the same names and signatures. `tls.goose` keeps its
  43 externs; only `library()`'s text and the error texts change. The crate sits
  beside `shim/` until the C goes, and is named for its toolchain: cargo builds it, and
  `CMakeLists.txt` finds its `Cargo.toml` there.
- **Handles stay raw pointers** ([decisions](../docs/decisions.md), "Handles are raw
  pointers"): a context is an `Arc` whose strong count `share` and `free` move; a
  connection and a key are `Box`es.
- **The unbuffered connection** (`UnbufferedServerConnection`,
  `UnbufferedClientConnection`). The shim owns the received bytes and the bytes to
  send, two `Vec`s that it frees once empty, as the memory BIOs are freed today
  (task 004). `tls::feed` appends everything; `read`, `handshake`, and `write` run
  `process_tls_records` over the received bytes; `drain` copies out. Plaintext that a
  program doesn't take in one `read`, or that arrives while it writes, waits in a third
  `Vec`. Only this connection hands over to the kernel with KeyUpdate (claim 5), and it
  has no 16 KB input refusal (claim 2). Spike 01 sketched feed and drain over the
  buffered connection's `read_tls` and `write_tls`, which it measured; the unbuffered
  one shares its state and record layer, and the measurement checks its memory.
- **A context chosen per connection**: on a context given to `choose_context`, the
  received bytes go to a `server::Acceptor` first, which parses the ClientHello;
  `handshake` returns `HELLO`, and `server_name` and `protocols_offered` come from
  `Accepted::client_hello()`. The shim keeps the bytes it fed, and once the program has
  chosen, makes the unbuffered connection from the chosen context and processes them
  again. Only contexts that choose pay for the second parse.
- **The provider: aws-lc-rs**, with rustls's default groups: X25519MLKEM768 first, then
  X25519, P-256, and P-384 (claim 3). The same three TLS 1.3 suites in the same order,
  chosen by the server (`ignore_client_order`), and no TLS 1.2 (rustls without its
  `tls12` feature). The `use_groups` change for v0.0.3 maps onto `kx_groups` per
  context. ring is a cargo feature beside it: it has no ML-KEM, but its AES-GCM ran
  95% faster than OpenSSL's on the desktop's Zen 3, and its json-like request cost
  1.59 µs against aws-lc-rs's 2.42 µs (spike 01, not yet explained). HttpArena's Rust
  entries use ring. Agreed 2026-10-21: aws-lc-rs is the default, with ML-KEM first,
  and ring a cargo feature. The choice is made again after the measurement through
  goose-http, and before relying on ring's lead, find out why its AES-GCM was so much
  faster in spike 01: which assembly each library picks on that CPU.
- **Session tickets**: two stateless TLS 1.3 tickets from rustls's `Ticketer`, as the
  shim's OpenSSL sends them today. rustls's default, a stateful cache of 256 sessions,
  would keep state per session in the server.
- **ALPN with no match** fails the handshake with `no_application_protocol`, as RFC
  7301 asks (claim 1); agreed 2026-10-21. It's a change from the shim, which answers
  without ALPN. Keeping the shim's behavior would need a parse of every ClientHello
  before rustls sees it; HttpArena allows selecting none, and its clients offer what
  the server speaks. A test that expects the old behavior changes with the step that
  reaches it, and `docs/architecture.md`'s ALPN section changes when the switch lands.
- **kTLS** (`shim/ktls.c`, 521 lines): the HKDF, the keylog and message callbacks, and
  the record counting go; `dangerous_into_kernel_connection` gives each direction's key,
  IV, and sequence number, and `KernelConnection` the keys after each KeyUpdate. What
  stays, in Rust with the `libc` crate: `TCP_ULP`, the `crypto_info` structs, the
  `setsockopt` calls, the record-boundary check (`kernel_wants`), and `kernel_record`.
  Both directions move at once, since the handoff consumes the rustls connection:
  `to_kernel` returns `KERNEL_RX | KERNEL_TX` or 0, never `KERNEL_RX` alone. A KeyUpdate
  that asks for an answer always returns `UPDATE_TX`. `test/kernel/derive.goose`, which
  checks the shim's HKDF against RFC 8448, goes with the HKDF. Nothing counts records
  after the handoff (claim 5): the program sends a KeyUpdate before AES-GCM's limit, as
  it can today.
- **ACME's crypto** (`shim/crypto.c`, 251 lines): rcgen with its `aws_lc_rs` feature for
  keys, PEM, the CSR, and certificates, and aws-lc-rs's fixed-length ECDSA for ES256
  (claim 6). The functions and their contracts stay.
- **Client TLS**: `tls::client` verifies with `rustls-platform-verifier`, so on macOS
  and Windows it trusts the system's own store, which the decision of 2026-10-19
  rejected only for its cost with OpenSSL; on Linux it reads the same files as before.
  `tls::client_trusting` uses a `RootCertStore` of the PEM it's given. The failure
  reasons in `error_text` are rustls's.
- **Error text**: each failing call keeps rustls's error, as `Display` writes it, for
  `tls::error_text` on the same thread. The golden files that hold OpenSSL's reasons are
  blessed again, and `test/check.goose`'s `reason()` reads the new form.
- **Goose's builders.** `u8[>..]&` parameters arrive as `gs_rref`, which C appends to
  with `goose.h`'s `gs_bld_append`, a header the compiler writes for each build. The
  functions that take one stay in a small C file, `rust/glue.c`, which asks the crate
  for the bytes, so the crate never depends on the builder's layout.

### Build and distribution

- `CMakeLists.txt` runs `cargo build --release` for the crate, imports the static
  library, and links it into the `goose_tls` target with the system libraries the Rust
  standard library needs (from `cargo rustc -- --print native-static-libs`, per
  platform). `tls.build` keeps `cmake_target = "goose_tls"`. Corrosion was not needed:
  it would add a fetched CMake dependency for one crate.
- Building from source needs a Rust toolchain at the crate's minimum version and a C
  compiler; on Windows x86-64, NASM or the `prebuilt-nasm` feature. OpenSSL is no
  longer needed, except by the tests' OpenSSL peer (`test/tools/peer/`) and the
  `openssl` and `curl` command-line checks.
- So that a program needs no Rust toolchain, each release attaches the static library
  for x86-64 and arm64 Linux, built on the oldest glibc HttpArena's images ship
  (Debian bookworm), arm64 macOS, and x86-64 Windows; `CMakeLists.txt` downloads the
  one for its platform and checks its SHA-256, which the repository records, as
  `scripts/goose.sh` does for Goose, and falls back to cargo where there's none. That
  answers the reason rustls-ffi was rejected on 2026-10-19 ("needs a Rust toolchain to
  build").
- **Only the package's C functions are global** (agreed 2026-10-21). A Rust static
  library carries Rust's standard library, so two in one program, say goose-tls and one
  day goose-hash, would collide on `std`, `core`, `alloc`, `compiler_builtins`, and
  `rust_eh_personality`. After cargo builds the library, a step in `CMakeLists.txt`
  leaves only the `tls_*` symbols global, the ones `tls.goose` and `glue.c` call, and
  makes everything else local, so each Rust package links its own private copy of
  `std` beside the others:
  - Linux: `ld -r --whole-archive` into one object, then `objcopy -w
    --keep-global-symbol='tls_*'` (or a version script), and `ar` back into the
    library.
  - macOS: `ld -r -exported_symbols_list` with the same list.
  - Windows (MSVC): open. A `.lib` has no clean way to make symbols local; the likely
    answers are a DLL there, or accepting the limit on Windows.

  The prebuilt libraries in a release are the localized ones. Rejected: a `cdylib` per
  package, a shared library shipped beside every program; and one static library per
  program, combining every Rust package, made by the build, which needs Goose's package
  build to change.

## Order of work

1. The server's connections (this branch): a context from PEM with ALPN, `accept`,
   `feed`, `handshake`, `read`, `write`, `drain`, `pending`, `shutdown`, `free`,
   `error_text`, `version`, `cipher`, `alpn`, and `share`; every other export a stub
   that fails, so that `tls.goose` links. The CMake build, with the step that makes all
   but the `tls_*` symbols local, and `test/conn/hello.goose` and
   `test/context/load.goose`. A test that links two Rust static libraries, each
   exporting its own C functions, into one program.
2. A context chosen per connection (`Acceptor`); `choose.goose` and `replace.goose`.
3. The client, with both verifiers; `client.goose`, and the client part of
   `scripts/test-handshake.sh`.
4. ACME's crypto; `keys.goose`, and `scripts/test-crypto.sh`.
5. kTLS through `KernelConnection`; `switch.goose`, and the kTLS part of
   `scripts/test-handshake.sh` on a kernel with the `tls` module.
6. The measurement: spike 01's harness with a server over this library's C ABI
   (`srv_goose.c` beside `srv_rustls.c`), with aws-lc-rs and ring, and goose-http built
   against the branch on json-tls and 8gbit.
7. The C shim and OpenSSL removed from the package's build; the README, architecture,
   and development pages; prebuilt libraries in a release, and goose-http's pin moved.

## Acceptance criteria

- [ ] Same or better CPU and less memory than OpenSSL: idle connections, handshakes in
      flight, handshakes, and requests, measured with the spike's harness
      (`spikes/01-rustls/`), and through goose-http on HttpArena's json-tls and 8gbit,
      with how each was measured
- [ ] goose-tls's `scripts/test.sh` passes on Linux and macOS, with golden files that
      changed only in error texts and `library()`, each change listed in the commit
- [ ] goose-http's `scripts/test.sh` passes against it, the kTLS pass included
- [ ] Nothing goose-http uses is lost: `server`, `server_files`, `share`, `accept`,
      `feed`, `read`, `write`, `drain`, `pending`, `handshake`, `shutdown`, `free`,
      `ok`, `error_text`, the key and certificate calls, `use_kernel`, `to_kernel`,
      `kernel_wants`, `in_kernel`, `kernel_record`, `kernel_update_tx`, and the
      constants; and nothing goose-rest's task 049 or goose-http's task 053 plans on
      (the client, `choose_context` and its calls, the crypto)
- [ ] A program builds without a Rust toolchain from a release's prebuilt library on
      Linux x86-64, and from source with cargo
- [ ] Two Rust static libraries, each exporting different C functions and built as
      this one is, link into one Goose program (or one C program) and both work, on
      Linux and macOS; only their C functions are global (`nm`). Windows recorded as
      open, or solved
- [ ] The provider chosen again after the measurement through goose-http, with why
      ring's AES-GCM ran faster than aws-lc-rs's in spike 01 found first
- [ ] `docs/decisions.md` settles the decision, and the README, architecture, and
      development pages describe the library as it is
