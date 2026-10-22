# 007: A TLS 1.3 server in Goose over libcrypto

Status: in-progress (direction agreed 2026-10-22; spike 02 passed its go/no-go on
2026-10-22; the full server is under way on the branch `goose-server`)

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

Done 2026-10-22, but for fuzzing ([spike 02](../../spikes/02-goose-server/README.md)).

- [x] Each primitive's allocations after setup, use, and free: AES-GCM,
      ChaCha20-Poly1305, SHA-256 and SHA-384, HMAC and HKDF, X25519, X25519MLKEM768,
      P-256
- [x] One full handshake and the record layer behind spike 01's `srv.h`, reusable in
      the server, and in it: X25519, X25519MLKEM768, P-256, and P-384; ECDSA and RSA
      certificates (`scripts/test-handshake.sh`)
- [ ] The ClientHello parser under a fuzzer
- [x] The go/no-go measurement: passed. 2,929 B idle and 3,742 B with the flight
      drained at 4,000 held, against a bar of 10,000 B; 7.5% less CPU a handshake and
      27% less a json-like request than OpenSSL

### 4. The full server, without resumption

- [x] HelloRetryRequest, alerts, KeyUpdate, `choose_context`, `use_groups`, and the
      three record suites, checked against `openssl s_client`
- [x] The golden tests (hello, load, choose, replace, groups) pass on both builds,
      with OpenSSL peers and curl; RFC 8448's section 3 trace passes
      (`test/server/rfc8448.goose`)
- [ ] RFC 8448's HelloRetryRequest trace (section 5), tlsfuzzer, and state-machine
      fuzzing
- [ ] Sanitizers on the shim and the generated C, debug and optimized builds

### 5. Session tickets

- [ ] Issue, resume, binders, rotation, expiry, and sharing across workers and
      contexts; `s_client -sess_out`/`-sess_in` and tlsfuzzer's resumption scripts
- [ ] Measured with tickets on, full and resumed

### 6. kTLS removed

- [x] goose-tls's kTLS code, API, tests, and docs removed: branch `no-ktls`
      (`7ffb6f7`), whose `scripts/test.sh` passes on Linux (2026-10-22)
- [ ] goose-http's handoff, record-control, and platform-stub paths removed: branch
      `no-ktls` in goose-http, its suites to pass
- [ ] goose-http's suites and the client check (curl, wrk, h2load, oha; Chromium and
      Firefox once by hand), with versions, suite, group, ALPN, and resumption recorded

### 7. Release

- [ ] json-tls and 8gbit in separate server and client processes over the network,
      with production ticket settings and the server process's memory
- [ ] A release, goose-http's pin moved, and a documented rebuild and redeploy command
      for the OpenSSL build

## How the server is built

What the plan left to the spike, as built on `goose-server`:

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
- **Limits:** a ClientHello of at most 4 + 16,384 bytes (BoringSSL's); at most
  256 KiB fed and not yet read; at most 16,384 bytes of early data skipped; and, as
  BoringSSL bounds them, 32 KeyUpdates in a row without data, 32 empty records in a
  row, and 4 user_canceled alerts in a row. AES-GCM keys are updated before 2^24
  records, as rustls's TLS suites limit them.
- **Any number of change_cipher_spec records** in the window RFC 8446, section 5,
  allows, each the single byte 1, as the RFC states it.
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
- Not yet compared: tickets and their key rotation (step 5), and the fuzz harness.

## Branches and commits

| Repository | Branch | What |
|---|---|---|
| goose-tls | `main` | Step 1's documentation (`cd5c42c`) |
| goose-tls | `goose-server` | Spike 02 and the server |
| goose-tls | `no-ktls` | kTLS removed (`7ffb6f7`), from `main` at `cd5c42c` |
| goose-http | `no-ktls` | kTLS's handoff removed |

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

## Questions for the maintainer

None yet.
