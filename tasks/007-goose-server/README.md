# 007: A TLS 1.3 server in Goose over libcrypto

Status: in-progress (direction agreed 2026-10-22; spike 02 passed its go/no-go on
2026-10-22; the server and its session tickets merged to `main` and released in
`v0.0.4` on 2026-10-22, ahead of step 7's network benchmarks at the maintainer's
request; goose-http's client check, those benchmarks, and the resumption fuzz target
remain)

goose-tls's server connections move from OpenSSL's libssl to a TLS 1.3 server written in
Goose, with libcrypto's EVP for every cryptographic primitive. The reason is memory:
libssl holds 28.5 KB per idle connection and 58.6 KB per handshake in flight, with no
setting that reduces either, and rustls showed that 7.8 KB and 8.3 KB are possible
([spike 01](../../spikes/01-rustls/README.md), task 005). OpenSSL stays for the cold
path (PEM loading), the client, ACME's crypto, the test peer, and a build-time
alternative server for rollback. kTLS is removed. Session tickets, with ticket-key
rotation, follow the full server immediately.

The agreed plan, with its two review rounds, is [plan.md](plan.md); it replaces
task 006's Rust library. The decision is in [decisions](../../docs/decisions.md) ("A
TLS 1.3 server in Goose over libcrypto"). This file records progress against the plan,
the choices made where the plan is ambiguous, the measurements, and the questions for
the maintainer.

## Steps

The plan's order of work, with each step's acceptance criteria.

### 1. The changed direction recorded

Done 2026-10-22, on `main` at `cd5c42c`.

- [x] This task, with the plan
- [x] `docs/decisions.md`: the new server pending spike 02, the Rust decision
      dropped, kTLS retired, ALPN's no-match failure in both backends, and the
      HttpArena rule corrected
- [x] `AGENTS.md`'s rule for C, and `docs/architecture.md`'s note on the change
- [x] Task 006 closed as not merged, its branch left as it is
- [x] HttpArena's rule checked: at HttpArena `f020b9b`,
      `site/content/docs/test-profiles/h1/json-tls/implementation.md` requires a
      standard TLS stack only of entries of type `standard` and `infrastructure`.
      goose-http's entry (`bench/httparena/goose/meta.json`) is of type `engine`, whose
      rule is "No specific rules", as is sark's; actix, ntex, and axum are
      `flagship` (checked 2026-10-22)

### 2. Spike 02: ownership and build

Done 2026-10-22 ([spike 02](../../spikes/02-goose-server/README.md)).

- [x] Contexts and connections made, freed, shared across workers, and replaced, from
      Goose through C, with bounded buffer lifetimes: `test/context/replace.goose`, and
      `test/context/workers.goose`, four threads on shares of one context that main
      frees first
- [x] The OpenSSL server selected at build time through the pinned Goose release's
      package machinery, beside the retained OpenSSL client: `GOOSE_TLS_SERVER=openssl`
      when the package's C is first configured; both builds pass the package's tests
- [x] An empty connection's memory (560 B against libssl's 16,829 B), and the cost of
      a call from Goose into C (1.0 ns; 30 ns to load and store a connection's state)

### 3. Spike 02: crypto and protocol

Done 2026-10-22 ([spike 02](../../spikes/02-goose-server/README.md)).

- [x] Each primitive's allocations after setup, use, and free: AES-GCM,
      ChaCha20-Poly1305, SHA-256 and SHA-384, HMAC and HKDF, X25519, X25519MLKEM768,
      P-256
- [x] One full handshake and the record layer behind spike 01's `srv.h`, reusable in
      the server, and in it: X25519, X25519MLKEM768, P-256, and P-384; ECDSA and RSA
      certificates (`scripts/test-handshake.sh`)
- [x] The ClientHello parser under a fuzzer: `fuzz/` (`fe7cb36`), see step 4
- [x] The go/no-go measurement: passed. 2,929 B idle and 3,742 B with the flight
      drained at 4,000 held, against a bar of 10,000 B; 7.5% less CPU a handshake and
      27% less a json-like request than OpenSSL

### 4. The full server, without resumption

- [x] HelloRetryRequest, alerts, KeyUpdate, `choose_context`, `use_groups`, and the
      three record suites, checked against `openssl s_client`
- [x] The golden tests (hello, load, choose, replace, groups) pass on both builds,
      with OpenSSL peers and curl; RFC 8448's section 3 trace passes
      (`test/server/rfc8448.goose`)
- [x] RFC 8448's HelloRetryRequest trace (section 5): `test/server/rfc8448_hrr.goose`
      (`fe7cb36`)
- [x] tlsfuzzer's TLS 1.3 server scripts: [tlsfuzzer.md](tlsfuzzer.md), its six
      findings fixed in `e7704f9`, the expected failures explained
- [x] State-machine fuzzing: `fuzz/` (`fe7cb36`), libFuzzer with ASan and UBSan.
      Ten minutes each on 2026-10-22 (5800X3D, WSL2), no findings: `fuzz_hello`
      136,148,160 runs, `fuzz_conn` 2,919,257 runs, `fuzz_open` 1,375,642 runs, built
      before the tickets' commit (`d0e859a`). Then five minutes each with tickets,
      built at `9bc8238`, no findings: 66,871,105, 2,338,773, and 523,700 runs.
      Random bytes reach the PSK extension's parsing and a failed ticket opening, not
      a resumption, which needs a ticket the server sealed
- [x] Sanitizers on the shim and the generated C, debug and optimized builds:
      `scripts/test-sanitizers.sh` (`b7fe12b`), all ten tests clean in both

### 5. Session tickets

- [x] Issue, resume, binders, rotation, expiry, and sharing across workers and
      contexts: `test/server/tickets.goose`, RFC 8448's resumption master secret and
      ticket PSK in `test/server/rfc8448.goose`; `s_client -sess_out`/`-sess_in` in
      `scripts/test-handshake.sh`, resumed, resumed after a HelloRetryRequest, and
      across the keys' turn on both builds, the server's ticket clock moved by the test
- [x] tlsfuzzer's resumption scripts: [tlsfuzzer.md](tlsfuzzer.md); count-tickets and
      connection-abort pass, session-resumption fails only its TLS 1.2 and `psk_ke`
      probes, which the plan leaves out
- [ ] A fuzz target that resumes from a ticket the server sealed, which random bytes
      can't forge, so that the binder check and the resumed flight are fuzzed too
- [x] Measured with tickets on, full and resumed ([spike 02](../../spikes/02-goose-server/README.md#with-session-tickets)):
      below

### 6. kTLS removed

- [x] goose-tls's kTLS code, API, tests, and docs removed: branch `no-ktls`
      (`7ffb6f7`), whose `scripts/test.sh` passes on Linux (2026-10-22); in `v0.0.4`
- [x] goose-http's handoff, record-control, and platform-stub paths removed: branch
      `no-ktls` in goose-http (`d328c93b`), whose `scripts/test.sh` passes on Linux
      (2026-10-22), still on goose-tls `v0.0.3`, whose kTLS calls it no longer makes;
      so it can merge on its own. goose-tls's removal merges with `goose-server`
- [ ] goose-http's suites and the client check (curl, wrk, h2load, oha; Chromium and
      Firefox once by hand), with versions, suite, group, ALPN, and resumption recorded

### 7. Release

- [ ] json-tls and 8gbit in separate server and client processes over the network,
      with production ticket settings and the server process's memory
- [ ] A release and goose-http's pin moved: `v0.0.4` (2026-10-22); goose-http's pin
      in progress
- [ ] A documented rebuild and redeploy command for the OpenSSL build, in goose-http

## How the server is built

What the plan left to the spike, as built:

- **C owns the memory; Goose decides.** A context and a connection are objects
  `shim/server.c` allocates; handles are their addresses with bit 0 set, so that
  `tls.goose` sends each call to the server it belongs to, and libssl's handles stay
  even. Goose's pinned release has no heap, a resizable value can't be an array
  element, and a worker's globals are copies, so Goose can't keep per-connection state
  that crosses threads, as the API's handles do. A connection's protocol state,
  `ServerState` (180 bytes), is copied from C and back by each call.
- **Secrets stay in C.** The handshake's secrets sit in numbered slots that Goose
  names in each call (`S_EARLY`, `S_HANDSHAKE`, ...); each direction keeps its traffic
  secret beside its AEAD context for a KeyUpdate. Everything secret is cleansed when it
  is replaced or freed.
- **The transcript ends with the server's flight.** The client's Finished covers
  exactly the transcript through the server's Finished, so the server derives the
  expected Finished and both application secrets when it sends its flight, and frees
  the transcript then. A handshake in flight holds two secrets and a key, not a hash
  context.
- **Plaintext before verification stays private.** A record decrypts into the
  connection's plaintext queue and is counted there only once its tag verifies.

## Choices made where the plan is ambiguous

Each is the simplest reading that meets the plan's intent; the maintainer can reverse
any of them.

- **The plan lives in this task** ([plan.md](plan.md)), copied from the handoff
  unchanged except its status line, so that the repository holds it.
- **Task 006 stays in `tasks/`, cancelled**, rather than archived: it maps rustls's
  API, which this task reads as a peer implementation.
- **"RFC 10024"** is correct: RFC 10024 is "Post-Quantum Traditional (PQ/T) Hybrid Key
  Agreement Mechanisms for TLS 1.3", which defines X25519MLKEM768 (checked 2026-10-22).
- **The build-time switch is an environment variable read at CMake's first
  configure**, `GOOSE_TLS_SERVER=openssl`, into a cache entry: Goose's `-D` reaches
  only the program's own C, a package's sidecar can't be set from the program, and
  Goose configures a package's C once and reconfigures only when the sidecar or the
  sources change. So a configured build keeps its choice until its directory goes;
  `GOOSE_HOME` set per backend keeps both builds side by side, as the tests run them.
- **X25519MLKEM768 from two primitives**, ML-KEM-768's encapsulation and X25519, in
  RFC 10024's order, rather than OpenSSL's built-in hybrid, so that the order is
  explicit and the server provably makes no ML-KEM key.
- **P-384 key exchange is in**, though the plan defers it: `use_groups` takes it, as
  the existing groups test does ("X25519:P-256:P-384"), and it is the P-256 code with
  another curve. It isn't in the default groups.
- **Keys the server signs with:** EC P-256 (`ecdsa_secp256r1_sha256`) and RSA of
  2048 bits or more (`rsa_pss_rsae_sha256`); `tls::server` refuses any other key. With
  libssl it took any key OpenSSL could load.
- **choose_context's pause re-parses the ClientHello on resuming**, and on
  `protocols_offered`, instead of storing the parse: the message stays in the bytes
  fed until the handshake goes on, and keeping the parse would mean a second copy of
  its fields in C. The parse costs microseconds, and only a choosing context pays.
- **The second ClientHello after a HelloRetryRequest must repeat the first byte for
  byte**, but for key_share, early_data, cookie, pre_shared_key, and padding (RFC 8446,
  section 4.1.2).
- **Errors are libssl's reasons**, raised into OpenSSL's error queue, so that
  `tls::error_text` and the golden files read as before.
- **Limits:** a ClientHello of at most 4 + 65,535 bytes (rustls's; BoringSSL's
  16 KiB refused tlsfuzzer's large but valid ones); at most 256 KiB fed and not yet
  read; at most 16,384 bytes of early data skipped; and, as BoringSSL bounds them,
  32 KeyUpdates in a row without data, 32 empty records in a row, and 4 user_canceled
  alerts in a row. AES-GCM keys are updated before 2^24 records, as rustls's TLS
  suites limit them.
- **One change_cipher_spec record** in the window RFC 8446, section 5, allows, the
  single byte 1; a second is `unexpected_message`, as tlsfuzzer and OpenSSL take it.
- **Tickets:** two after a full handshake and one after a resumption, each with a
  7,200-second lifetime, a 2-byte nonce counting from 0, and no extensions. A ticket is
  an envelope of 17 bytes in the clear (version, the key's 4-byte id, a 12-byte
  AES-GCM nonce), which the AEAD authenticates, then sealed under AES-256-GCM: the
  suite, the PSK, the issue time, age_add, and the SNI name; 92 bytes for a 32-byte
  PSK and an 11-byte name. The server doesn't store tickets, so a ticket can resume
  any number of times within its lifetime, as with libssl's stateless tickets; without
  0-RTT, a replay gains nothing.
- **The ticket keys' clock is monotonic and the process's own**, so tickets don't
  outlive the process, as libssl's default keys didn't. A ticket's lifetime is checked
  against the issue time it carries, sealed, and not the client's obfuscated age.
- **libssl's server keeps the same key ring** (`ticket_key_issue` and
  `ticket_key_open` in `shim/server.c`, through libssl's
  `SSL_CTX_set_tlsext_ticket_key_evp_cb`), with libssl's own ticket format under
  AES-256-CBC and HMAC-SHA256 from each key's two halves. Its tickets' lifetime is
  still libssl's session timeout (7,200 s) on the wall clock.
- **A ticket opens only under the context that ends up serving the connection**, the
  one `choose_context` picked, in both builds; the plan's "a ticket from another
  context must not bypass selection".
- **No empty server_name in EncryptedExtensions:** RFC 6066 lets a server send one
  when it used the name; libssl without a servername callback doesn't either.

## Peers followed

From reading the peers' sources and behavior (2026-10-22); each item says where the
server differs.

- **Group choice: rustls.** The first of the server's groups for which the client
  sent a share; failing that, a HelloRetryRequest for the first of the server's groups
  the client supports.
- **Limits: BoringSSL** (`ssl/handshake.cc`, `ssl/tls_record.cc`,
  `ssl/tls13_both.cc`), as listed above. A KeyUpdate that asks for one back is
  answered once until the answer is drained, as BoringSSL's `key_update_pending`
  suppresses a second answer until the first is written (RFC 8446, section 4.6.3).
- **The key schedule and its order: RFC 8446, section 7.1, and RFC 8448's trace**,
  checked byte for byte. Freeing the transcript at the server's Finished is this
  server's own; rustls and BoringSSL keep theirs until the client's Finished.
- **The state machine:** explicit phases in code (`PH_HELLO`, `PH_RETRY`,
  `PH_FINISHED`, `PH_OPEN`, `PH_FAILED`), each with the records it takes. s2n-tls
  keeps a table of message types per handshake shape (`tls13_handshakes` in
  `tls/s2n_handshake_io.c`) because it has a dozen shapes; with one shape and an
  optional HelloRetryRequest, the five phases read more directly as code. Tickets add
  no phase: a resumed handshake skips Certificate and CertificateVerify in the flight.
- **Tickets: rustls's rotator** (`src/ticketer.rs`, rustls 0.23.46): two keys per
  context, the newer issuing and both opening, turned lazily on use with no timer, and
  a key that opens for twice its issuing period. The server differs in three ways: it
  turns the ring only when it issues, and expires keys on either call; a key's age
  comes from a monotonic clock, where rustls uses `UnixTime::now()`; and the period is
  2 hours, libssl's ticket lifetime, where rustls's default `aws_lc_rs::Ticketer`
  turns every 6 hours. The envelope is the server's own: AES-256-GCM, with the key id
  and nonce as associated data, where rustls's aws-lc-rs ticketer and libssl use
  RFC 5077's AES-256-CBC and HMAC-SHA256. Two tickets after a full handshake is the
  default in rustls (`send_tls13_tickets`) and libssl; one after a resumption is
  libssl's. s2n-tls instead takes keys from the application with explicit intro
  times, which this server has no API for.
- **Fuzzing: a server fed arbitrary bytes**, as BoringSSL's `fuzz/server.cc` and
  rustls's `fuzz/fuzzers/server.rs` do (`fuzz_conn`), and beside it a target for the
  ClientHello parser alone (`fuzz_hello`) and one for records under known keys
  (`fuzz_open`), which reaches the record layer past the handshake that random bytes
  can't complete. libFuzzer, each with a seed corpus.

## Branches and commits

| Repository | Branch | What |
|---|---|---|
| goose-tls | `main` | Step 1's documentation (`cd5c42c`); then `goose-server` and `macos-check`, fast-forwarded, and `v0.0.4` (2026-10-22) |
| goose-tls | `goose-server` | Spike 02 and the server, with `no-ktls` merged in: `95e72c5` the server, `1fe0f33` spike 02's harness and results, `e7704f9` tlsfuzzer's fixes, `fe7cb36` RFC 8448's HelloRetryRequest and the fuzz targets, `b7fe12b` the tlsfuzzer and sanitizer scripts, `d0e859a` session tickets in both servers, `9bc8238` the benchmark's resumption mode, `c87d3ac` and `3792a59` a test hook and a test, `ba1ae99` the docs and tickets' measurements |
| goose-tls | `no-ktls` | kTLS removed (`7ffb6f7`), from `main` at `cd5c42c` |
| goose-tls | `macos-check` | The scripts' fixes for macOS and its results ([macOS](#macos)), from `goose-server` |
| goose-http | `no-ktls` | kTLS's handoff removed (`d328c93b`), from its `main` |

## Measurements

Spike 02, 2026-10-22, Ryzen 7 5800X3D, Ubuntu 26.04 in WSL2 (kernel
`6.18.54.1-microsoft-standard-WSL2`), OpenSSL 3.5.5, Goose v2026.3, goose-tls `95e72c5`,
one process with in-memory OpenSSL clients, 5 interleaved runs pinned to one CPU,
tickets off on both servers, X25519MLKEM768. Medians; the method, the ranges, and
X25519's runs are in [spike 02](../../spikes/02-goose-server/README.md).

| Per server connection | Goose server | OpenSSL |
|---|---:|---:|
| Idle, 4,000 held | 2,929 B | 28,523 B |
| Handshake in flight, flight drained, 4,000 held | 3,742 B | 58,627 B |
| Handshake in flight, flight queued, 4,000 held | 6,110 B | 61,875 B |
| Most a handshake adds while answering the ClientHello | 12,530 B | 61,399 B |
| Server CPU, full handshake | 638.7 µs | 690.7 µs |
| Server CPU, json-like request | 2.42 µs | 3.32 µs |

With session tickets on in both servers, the same machine and setup, goose-tls
`9bc8238`, 5 interleaved runs ([spike 02](../../spikes/02-goose-server/README.md#with-session-tickets)),
X25519MLKEM768:

| Per server connection | Goose server | OpenSSL |
|---|---:|---:|
| Idle, 4,000 held | 2,930 B | 28,528 B |
| Handshake in flight, flight drained, 4,000 held | 3,807 B | 58,627 B |
| Server CPU, full handshake, two tickets sent | 648.8 µs | 721.4 µs |
| Server CPU, resumed handshake, one ticket sent | 150.5 µs | 207.0 µs |

Tickets add no idle memory to the Goose server and 65 B to a handshake in flight; the
full handshake costs 10 µs more with them, OpenSSL's 31 µs, from runs an hour apart.

## macOS

Both builds pass on macOS with Homebrew's OpenSSL 3 and OpenSSL 4, with no change to
the package's code (2026-10-22). Three script fixes were needed, none in the server.

Setup: macOS 26.3.1 on an Apple M1 Pro (arm64), Apple clang 21.0.0
(clang-2100.0.123.102), CMake 4.4.4, Homebrew's `openssl@3` 3.6.5 and `openssl`
(`openssl@4`) 4.0.3, Goose v2026.3, goose-tls `ffbb51d` on `goose-server` (whose code
`c134e9d` leaves unchanged). The peers were Homebrew's `openssl` 4.0.3 on `PATH` and
macOS's `curl` 8.7.1 (LibreSSL 3.3.6), with `HTTPS_HOST` at its default, example.com.

| Run | Server | OpenSSL | Result |
|---|---|---|---|
| `scripts/test.sh` | Goose | 3.6.5 | Passed: 12 golden tests at `-O0` and `-O2`, 82 handshake and crypto checks |
| `scripts/test.sh` | libssl | 3.6.5 | Passed, the same |
| `scripts/test.sh` | Goose | 4.0.3 | Passed, the same |
| `scripts/test.sh` | libssl | 4.0.3 | Passed, the same |
| `scripts/test-sanitizers.sh` | Goose | 3.6.5 | Passed after the fixes below: 11 tests, debug and release, ASan and UBSan without leak detection, which Apple clang's ASan lacks on arm64 |
| `scripts/test-sanitizers.sh` | Goose | 4.0.3 | Passed, the same |
| `scripts/test-tlsfuzzer.sh` | Goose | 3.6.5 | Every failure one of [tlsfuzzer.md](tlsfuzzer.md)'s expected ones, after the fixes below |

The only `NOTE` in each handshake run is the one Linux prints: this `openssl` can't offer
SSLv3, so those HttpArena probes weren't run. The X25519MLKEM768 checks ran against both
OpenSSL versions. The libFuzzer targets weren't run: Apple clang has no libFuzzer.

tlsfuzzer `5eebc44` and tlslite-ng `7e95ea1`, as on Linux, matched
[tlsfuzzer.md](tlsfuzzer.md)'s counts but for two scripts that run a random sample of
their probes: signature-algorithms passed 102 of 102, its sample without the
32,715-scheme probes, and version-negotiation failed 196 of 202, all fallbacks to
TLS 1.2, two of them the "legacy field" probes that expect a TLS 1.2 ServerHello.
connection-abort passed 150 of 150, session-resumption 4 of 7, and count-tickets with
`-t 2` 3 of 3.

The fixes, on the branch `macos-check`:

- `b5ea8fb`: `scripts/test-sanitizers.sh` and `scripts/test-tlsfuzzer.sh` were committed
  without the executable bit (`zsh: permission denied`).
- `708b5c0`: macOS's `/bin/sh`, bash 3.2, couldn't parse `scripts/test-tlsfuzzer.sh`
  (`line 67: unexpected EOF while looking for matching '''`): it reads the apostrophe
  in `"${TLSFUZZER:?... tlsfuzzer's checkouts}"` as a quote. The message is reworded.
- `f481efa`: `scripts/test-sanitizers.sh` linked `-lssl -lcrypto` from clang's default
  paths, which hold no OpenSSL on macOS (`shim/crypto.c:14:10: fatal error:
  'openssl/asn1.h' file not found`). It now takes the include and library directories
  from the package's CMake cache, which also makes it follow `OPENSSL_ROOT_DIR`. Checked
  again on Linux: Ubuntu 26.04 on arm64 in Docker, OpenSSL 3.5.5, all 22 clean, with
  leak detection.

## Questions for the maintainer

None blocks the work.

- **Merge `goose-server` into `main`?** Answered 2026-10-22: merged with `macos-check`'s
  fixes, and released as `v0.0.4` for goose-http's pin. Linux, Windows, and macOS
  passed first; step 7's network benchmarks follow the release.
- **Test hooks in the shipped library.** `tlsg_ks_set` (RFC 8448's tests set a
  secret) and `tlsg_ticket_clock` (the tests move the ticket clock) are exported by the
  package's C, though only tests call them. Options: keep them, documented as for
  tests; or compile them only under a test define, which the package's CMake would
  need a way to set from a test build. Recommendation: keep them; neither reveals a
  secret, and the clock only moves forward, which can only expire tickets sooner.
  Meanwhile: kept, each with a comment saying it is for the tests. `tlsg_ks_set` can
  overwrite a connection's secret, but only from code linked into the program, which
  could do anything to the connection anyway.

## Next

- goose-http on `v0.0.4`: its pin moved and its suites run.
- goose-http's client check (step 6): curl, wrk, h2load, oha, Chromium, and Firefox,
  with resumption recorded.
- The resumption fuzz target (step 5).
- Step 7: json-tls and 8gbit over the network.
