# 007: A TLS 1.3 server in Goose over libcrypto

Status: in-progress (direction agreed 2026-10-22; the new server is pending spike 02)

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

- [ ] Contexts and connections made, freed, shared across workers, and replaced, from
      Goose through C, with bounded buffer lifetimes
- [ ] The OpenSSL server selected at build time through the pinned Goose release's
      package machinery, beside the retained OpenSSL client
- [ ] An empty connection's memory, and the cost of a call from Goose into C

### 3. Spike 02: crypto and protocol

- [ ] Each primitive's allocations after setup, use, and free: AES-GCM,
      ChaCha20-Poly1305, SHA-256 and SHA-384, HMAC and HKDF, X25519, X25519MLKEM768,
      P-256
- [ ] One full handshake and the record layer behind spike 01's `srv.h`, reusable in
      the server: X25519, X25519MLKEM768, and P-256; ECDSA and RSA certificates
- [ ] The ClientHello parser under a fuzzer
- [ ] The go/no-go measurement (plan, "Spike measurements and go/no-go")

### 4. The full server, without resumption

- [ ] HelloRetryRequest, alerts, KeyUpdate, `choose_context`, `use_groups`, and the
      three record suites
- [ ] The golden tests (hello, load, choose, replace, groups), OpenSSL peers, curl,
      RFC 8448's vectors, tlsfuzzer, and state-machine fuzzing pass; the OpenSSL
      alternative passes the common API tests

### 5. Session tickets

- [ ] Issue, resume, binders, rotation, expiry, and sharing across workers and
      contexts; `s_client -sess_out`/`-sess_in` and tlsfuzzer's resumption scripts
- [ ] Measured with tickets on, full and resumed

### 6. kTLS removed

- [ ] goose-tls's kTLS code, API, tests, and docs removed, with goose-http's handoff,
      record-control, and platform-stub paths, in one coordinated change
- [ ] goose-http's suites and the client check (curl, wrk, h2load, oha; Chromium and
      Firefox once by hand), with versions, suite, group, ALPN, and resumption recorded

### 7. Release

- [ ] json-tls and 8gbit in separate server and client processes over the network,
      with production ticket settings and the server process's memory
- [ ] A release, goose-http's pin moved, and a documented rebuild and redeploy command
      for the OpenSSL build

## Choices made where the plan is ambiguous

Each is the simplest reading that meets the plan's intent; the maintainer can reverse
any of them.

- **The plan lives in this task** ([plan.md](plan.md)), copied from the handoff
  unchanged except its status line, so that the repository holds it.
- **Task 006 stays in `tasks/`, cancelled**, rather than archived: it maps rustls's
  API, which this task reads as a peer implementation.
- **"RFC 10024"** is correct: RFC 10024 is "Post-Quantum Traditional (PQ/T) Hybrid Key
  Agreement Mechanisms for TLS 1.3", which defines X25519MLKEM768 (checked 2026-10-22).

## Branches and commits

| Repository | Branch | What |
|---|---|---|
| goose-tls | `main` | Step 1's documentation |
| goose-tls | `goose-server` | Spike 02 and the server |

## Measurements

None yet.

## Questions for the maintainer

None yet.
