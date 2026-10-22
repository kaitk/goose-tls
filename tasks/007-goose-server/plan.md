# Plan: goose-tls's server connections in Goose, with libcrypto for the crypto

Status: agreed 2026-10-22, after review round 2 and the follow-up discussion; kept here
as agreed. Progress, the choices made where it is ambiguous, measurements, and open
questions are in [task 007](README.md). Replaces the pending decision "Connections over
our own Rust library on rustls" (goose-tls task 006). The Rust branch is not merged or
pushed; leave that branch and other work untouched. This document describes planned
work, not work already implemented or measurements already passed.

Settled direction (2026-10-22):

- Goose is the default for the server hot path. Small C helpers are also allowed where
  ownership, buffer handling, OpenSSL calls, or measured code generation make C simpler
  or safer. Do not force a Goose workaround merely to avoid C.
- No Rust dependency in the package's build. Keep OpenSSL for the cold path, the client,
  the validation peer, and an explicit alternative server backend for rollback.
- Session tickets follow the full server immediately. Include a small ticket-key
  rotation policy in that step, before release.
- ALPN with an offered list but no match fails with no_application_protocol, as
  RFC 7301 section 3.2 requires, in both server backends.
- Drop kTLS from this port and retire the existing integration with goose-http.
  Reconsider it only after a concrete workload demonstrates a worthwhile benefit.
- Aim for a performant, secure, maintainable library. Prefer a small implementation,
  precise invariants, and security testing to general frameworks or speculative
  features. Each added mechanism must prevent a named failure.

Repository paths below are relative to goose-tls unless prefixed with goose-http.
Before implementing, read AGENTS.md, README.md, docs/decisions.md,
docs/architecture.md, docs/development.md, docs/goose-findings.md, tls.goose,
shim/{tls,ktls,crypto}.c, CMakeLists.txt, tasks/004-connection-memory.md,
tasks/005-rustls-spike.md, tasks/006-rustls.md, and spikes/01-rustls/{README.md,
bench.c,srv.h,srv_openssl.c}. Read the pinned Goose release's tutorial, spec, stdlib,
and package/build documentation before choosing representations or build switches.

## Context

goose-tls is a Goose package (Goose is a compiled systems language) that wraps OpenSSL 3
through a small C shim (`shim/tls.c`, `ktls.c`, `crypto.c`) with an I/O-free API:
`feed` received bytes, `handshake`, `read`, `write`, `drain` bytes to send. The event
loop (goose-http, epoll/io_uring) owns the sockets. The Goose API is `tls.goose`
(41 externs; listed at the end).

Problem: memory. Measured on Linux (OpenSSL 3.5.5, SSL_MODE_RELEASE_BUFFERS, memory BIOs
freed when empty):

| Per server connection | OpenSSL 3.5.5 | rustls 0.23.46 (aws-lc-rs) |
|---|---:|---:|
| Idle, 4,000 held | 28.5 KB | 7.8 KB |
| Handshake in flight | 58.6 KB | 8.3 KB |
| Server CPU, full handshake (X25519MLKEM768) | 727 µs | 615 µs |
| Server CPU, json-like request (200 B in, 8.5 KB out) | 3.28 µs | 2.42 µs |

OpenSSL's cost is libssl's: the SSL object and two record layers (14.4 KB), the client's
ML-KEM key share kept until SSL_free (6.4 KB), a 21.8 KB handshake message buffer and an
8 KB buffering BIO during the handshake. This identifies libssl retention as the main
target; it does not yet prove that our EVP objects and Goose buffers will be small.

Correction to review round 1: spike 01 had session-ticket issuance enabled. Disabling
the client's session cache does not disable server tickets. srv_openssl.c:31 leaves
the server's ticket default intact, and bench.c:117 explicitly consumes the tickets.
Its in-flight measurement drains the server flight (bench.c:193). The table is a
historical baseline with those conditions, not a tickets-off or queued-flight result.
Spike 02 must label and match these conditions rather than silently comparing them.

## Approach

Write the TLS 1.3 server's hot path in Goose by default, with libcrypto (EVP) for all
cryptographic primitives. Use C for a small ownership/buffer adapter where useful,
as well as for OpenSSL calls. Do not implement cryptographic primitives in either
language. Keep the connection API I/O-free: the event loop moves all socket bytes.

The existing prohibition on implementing a record layer in AGENTS.md and the settled
"Bindings, not TLS in Goose" decision must be superseded explicitly, along with the
pending Rust decision and the kTLS decisions. Update the architecture to describe the
result. This is an authorized change of direction, not an exception to hide in code.

### API, ownership, and the OpenSSL alternative

- Keep the public feed/handshake/read/write/drain interface, status meanings,
  choose_context, context sharing/replacement, and the existing client API. The kTLS
  API is the intentional removal. Internal externs need not remain identical.
- Retain the current libssl server implementation as a build-time alternative first.
  Prove how to select it through the pinned Goose package/build machinery during the
  first spike; a CMake option alone cannot select Goose code. Avoid a general backend
  framework or a new compiler feature. Runtime selection can wait for an actual need.
- Selection happens before accepting connections. A failed handshake, bad tag, bad
  binder, or protocol error never retries through the other backend. Rollback means
  deploying the OpenSSL build for new connections; there is no live state transfer.
- Both builds run the common API and interoperability tests and enforce the agreed
  TLS-version and ALPN policies. Keep the OpenSSL alternative buildable throughout the
  port. Ticket formats and keys need not interoperate between backends: a backend
  change can cause a full handshake. This is operational rollback, not a substitute
  for validating the new server.
- Prototype connection/context lifetimes before writing the handshake. The same API
  must distinguish our server connections from retained OpenSSL client connections.
  Do not allocate an SSL object for each Goose server connection to achieve that.
  Contexts own shared certificate DER, keys, configuration, and ticket state; active
  connections hold the references needed to survive context replacement.
- Use the smallest workable ownership arrangement. A small C owner for native
  handles, reference counts, and releasable byte buffers is permitted. Keep protocol
  decisions in Goose. Prove freeing, errors, context sharing across workers, and
  choose_context replacement; do not build a general object manager or allocator.

### Our server protocol

The protocol references below are to [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)
unless another RFC is named.

- Record layer: TLSPlaintext/TLSCiphertext framing, inner content type and padding,
  nonce = IV xor seq, seq numbers, 2^14 limits, alerts, close_notify, KeyUpdate both
  ways (answer update_requested), AES-GCM record limit tracked. Plaintext content is
  at most 2^14 bytes; TLSInnerPlaintext including type and padding is at most 2^14 + 1;
  ciphertext is at most 2^14 + 256. Authenticate the complete record header as AAD.
  Maintain separate sequences per direction and epoch; reset only with new keys and
  never wrap. Refresh keys before their usage limit. Receive padding, but send no
  optional padding initially (RFC 8446 sections 5.1-5.5).
- Reassemble fragmented handshake messages within bounds and process coalesced ones.
  Enforce record boundaries at key changes, including Finished and KeyUpdate; no
  handshake message can straddle epochs or be interleaved with other content types,
  apart from the permitted compatibility CCS handling. Alerts occupy exactly one
  complete alert per record. An empty application record is legal and is not EOF
  (RFC 8446 sections 5 and 5.1).
- Explicit states and read/write key epochs decide which messages are legal. No
  application data reaches the program before client Finished is verified. Keep
  close_notify distinct from a fatal failure: preserve previously authenticated
  unread data, close the peer's sending direction, and drain our closure output in
  order (section 6.1). Never resume processing after a terminal failure. Outside the
  narrowly specified rejected-early-data path, authentication failures are terminal;
  protocol errors are terminal too. Do not continue with a different key or backend.
- Bounds: cap ClientHello/reassembly size and queued input/output per connection,
  checking lengths and arithmetic before allocation, slicing, or copying. Preserve
  feed's all-or-error contract within those limits; do not silently drop excess bytes.
  The event loop owns incomplete-handshake admission limits and deadlines, since the
  library cannot enforce elapsed time or total live sockets through its I/O-free API.
  Verify those caller limits before release rather than adding a TLS timer subsystem.
- Handshake: ClientHello parse (versions, groups, key_share, sig algs, SNI, ALPN,
  psk modes, pre_shared_key), HelloRetryRequest (with cookie-free stateful HRR,
  message_hash transcript), middlebox compat (echo legacy_session_id and send one CCS),
  ServerHello, EncryptedExtensions, Certificate,
  CertificateVerify, Finished, client Finished check. Duplicate extensions rejected,
  unknown ones and GREASE ignored, the second ClientHello checked against the first
  after HRR, early_data records skipped up to a bound only as RFC 8446 section 4.2.10
  specifies. Discard a compatibility CCS only when it is an unencrypted single byte
  0x01 in the allowed handshake window; malformed, encrypted, or out-of-window CCS
  fails (section 5). The X25519 all-zero shared secret is rejected; peer shares are
  validated. Hash the exact handshake bytes, not a reserialization or record headers.
- Key schedule (RFC 8446 7.1) over HKDF from libcrypto.
- choose_context: the ClientHello parser already yields SNI and ALPN, so pausing there
  needs no second parse. Complete selection before checking tickets or choosing
  credentials and algorithms; a ticket from another context must not bypass selection.
- Suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
  server's order. Groups: X25519MLKEM768 (only where libcrypto has ML-KEM, 3.5 or
  later), X25519, P-256, set by use_groups. P-384 later if a caller needs it.
  Check provider availability as well as the OpenSSL version. Use X25519MLKEM768's
  specified encoding and concatenation order: ML-KEM first, X25519 second, including
  the combined shared secret ([RFC 10024](https://www.rfc-editor.org/info/rfc10024/)).
  The server imports the client's ML-KEM
  encapsulation key and encapsulates; it does not generate an ML-KEM private key.
- Signatures: a scheme chosen from the client's signature_algorithms that the loaded
  key can make: ecdsa_secp256r1_sha256 and rsa_pss_rsae_sha256 (PSS, salt = hash
  length), over 64 spaces + "TLS 1.3, server CertificateVerify" + a zero separator
  byte + transcript hash (RFC 8446 section 4.4.3). TLS ECDSA signatures use DER,
  unlike ACME's raw r||s ES256 helper in crypto.c; do not reuse its output format.
  Fail clearly for unsupported loaded keys or no compatible signature scheme.
  Ed25519 later if a caller needs it.
- ALPN: first of the server's list the client offers. A client that offers ALPN but
  none of the server's protocols fails with no_application_protocol (RFC 7301 3.2);
  today's shim returns NOACK instead, so fix the retained OpenSSL backend as well as
  documenting the new behavior. A client that offers no ALPN gets none.
- Session tickets: stateless TLS 1.3 tickets as OpenSSL does today: two after a full
  handshake, one after a resumption (see below).

### C helpers and libcrypto

- AEAD: create from key+IV, seal/open in place (EVP_CIPHER_CTX, one per direction).
  Reinitialize each record correctly for its nonce, AAD, and tag. EVP decryption can
  write unauthenticated bytes before Final succeeds: decrypt into library-owned
  storage and publish nothing until verification succeeds; discard it on failure.
- Hash/transcript: EVP_MD_CTX create/update/copy-digest/free.
- HKDF extract/expand through EVP_KDF, and HMAC through EVP_MAC for Finished and
  binders. Avoid the older EVP_PKEY HKDF bridge and per-record algorithm fetches.
- Key exchange: generate share, derive secret for X25519, P-256, X25519MLKEM768
  (EVP_PKEY encapsulation for ML-KEM; server side encapsulates).
- Sign: EVP_DigestSign with the context's EVP_PKEY.
- Random bytes: RAND_bytes; constant-time comparison: CRYPTO_memcmp; guaranteed
  secret erasure: OPENSSL_cleanse. Check every fallible EVP/RNG call and propagate
  failure. Do not share mutable EVP_CIPHER_CTX or EVP_MD_CTX objects across workers.
- Ownership/buffer helpers only where they simplify the pinned Goose implementation,
  with explicit byte capacities, lengths, and lifetime contracts at the C boundary.

### Goose representation and memory

The idle target is two AEAD contexts, two traffic secrets and IVs, sequences, and
small protocol state, near rustls's 7.8 KB. Do not embed a 16 KB record buffer in every
connection. EVP/provider state has undocumented allocation costs, so measure it rather
than inferring memory from sizeof the public handles.

Language basis: the pinned [Goose spec](https://github.com/aardappel/goose/blob/v2026.3/docs/goose_spec.md),
sections 1.2, 3.4, 6.2-6.3, and 11.2, and the
[binary stdlib documentation](https://github.com/aardappel/goose/blob/v2026.3/docs/stdlib.md#binary).

- Fetch algorithms once for the relevant process/provider configuration. Share
  certificate DER and the context's EVP_PKEY. Free exchange objects as soon as the
  shared secret is derived and wipe obsolete handshake secrets at their last use.
  After verifying client Finished, derive the resumption master secret before freeing
  the transcript; retain the resumption secret only until tickets have been encoded.
- Own queued input, authenticated unread plaintext, and queued ciphertext explicitly.
  Release empty dynamic buffers. Store each queued byte once where possible, rather
  than allocating parallel record scratch space per connection. Partial feed, read,
  write, and drain calls must preserve exact ownership and ordering.
- The current pin is Goose v2026.3. It has no general-purpose heap; a resizable member
  must be the final struct field, and a resizable value cannot be an array element.
  Worker globals are copies. Do not assume arbitrary heap owners or a shared Goose
  global ticket key. Prototype the representation and worker-shared native context
  first; C allocation/refcount helpers are allowed.
- Fixed-size arrays and structs can still be copied by value. Keeping secrets in
  fixed buffers alone does not prevent copies. Use references/slices, check generated
  C for relevant copies, and wipe owned secret storage on replacement, free, and error.
  Use OPENSSL_cleanse rather than a Goose zeroing loop that may be optimized away.
  Avoid growable secret buffers and accidental secret-bearing return values.
- Write a small checked big-endian reader for TLS; std/binary's little-endian helpers
  are not a TLS parser. Widen bytes before shifts, check conversions, and account for
  Goose's integer/shift rules and debug-versus-release cast behavior. Malformed input
  must return a TLS error, not trigger an indexing trap or process-wide abort.
- Pass C only buffers whose capacity and lifetime are established. A stored pointer
  must not outlive a slice or survive its owner's reallocation. Inspect the actual
  generated ABI for fixed arrays, slices, and mutable output parameters.
- Emptying a Goose growable buffer or pool does not necessarily return its capacity
  or resident memory. Measure retained capacity and RSS after large flights, large
  records, and connection churn. bench.c:51's mallinfo2().uordblks is insufficient
  for mmap-backed storage; a lower reported malloc heap is not by itself a win.

### Stays on OpenSSL (cold path)

- PEM key and chain loading (keep the DER chain and an EVP_PKEY per context).
- `tls::client` / `client_trusting` / `connect` / `peer_certificate`: libssl, unchanged
  (few connections).
- ACME crypto (`crypto.c`): keys, ES256, CSR, self-signed with acmeIdentifier,
  unchanged.

### Left out

TLS 1.2, accepting 0-RTT/early data, client certificates, record_size_limit,
max_fragment_length, compression, post-handshake auth, PSK-only (psk_ke) mode, and
kTLS. Tickets advertise no early data; implement the bounded rejection behavior,
not early-data acceptance. Resumption always uses psk_dhe_ke. No anti-replay database
or early-data ticket-age freshness mechanism is needed for that policy.

Defer P-384 key exchange, Ed25519 and P-384 certificates, outgoing padding policy,
runtime server-backend selection, persistent/distributed ticket keys, and ticket
compatibility across backends until a caller needs them. Ticket-key rotation is in.

## Session tickets and key lifetime

Implement tickets and rotation together immediately after the full server. The
300-400-line estimate covers only the basic issue/resume path; it is not a total
estimate for rotation, ownership, OpenSSL integration, negative tests, or fuzzing.
Record the actual implementation cost rather than defending that number by omitting
required checks. Relevant protocol: RFC 8446 sections 4.2.9-4.2.11, 4.6.1, and 7.1.

- NewSessionTicket after the client Finished: PSK = HKDF-Expand-Label(resumption
  master secret, "resumption", ticket_nonce, Hash.length). Each ticket_nonce is
  distinct within the connection. Ticket envelope: version + key identifier + fresh
  random 12-byte AEAD nonce + encrypted {suite/hash, PSK, issue time, age_add, SNI} +
  authentication tag; authenticate the envelope metadata too. Use AES-256-GCM for
  ticket protection independently of the connection's negotiated suite. The ticket
  nonce on the wire and the envelope's AEAD nonce serve different purposes.
  Send two tickets after a full handshake and one after resumption, with a 7200-second
  lifetime as in today's OpenSSL default. No early_data extension.
- On ClientHello: parse psk_key_exchange_modes and pre_shared_key (must be the last
  extension); validate vector lengths and matching identity/binder counts. Finish
  choose_context first. With psk_dhe_ke offered, take the first identity whose ticket
  opens under that context and fits its lifetime, selected suite's hash, and SNI;
  answer selected_identity. Enforce lifetime from authenticated server issue time,
  not the client's obfuscated age. An unusable ticket falls back to a full handshake;
  a bad binder for the selected identity is a fatal decrypt_error. Malformed protocol
  syntax is not an unusable-ticket fallback.
- Binder: derive binder_key from the early secret with "res binder", then its
  Finished key, and HMAC the specified truncated ClientHello transcript. Keep the
  original length fields and stop before the binders vector. After HRR this is
  message_hash of the complete first ClientHello, HRR, and truncated second
  ClientHello (RFC 8446 section 4.2.11.2). Retain the parser's binder offset; do not
  reconstruct the message. Compare Finished and binders with CRYPTO_memcmp.
- Key schedule starts from the PSK; skip Certificate/CertificateVerify; still (EC)DHE.
- ALPN is negotiated again, not restored or checked against the ticket (RFC 7301
  section 3.1). The ordinary no-match failure still applies.
- Keep only a current and previous ticket key per shared context, with a small key
  identifier. Issue with the current key; accept either while valid. Proposed simple
  schedule: a new issuing key every 7200 seconds, retaining the previous key only
  through the last ticket's lifetime. A key issues for at most two hours and remains
  usable for at most four. If several periods elapsed, discard obsolete generations
  rather than extending them. Use a monotonic elapsed-time basis for this process-local
  policy so a wall-clock adjustment cannot lengthen validity.
- Rotate/check expiry lazily on ticket operations, synchronize only that shared key
  state, and wipe retired keys on eviction and context destruction. An entirely idle
  context can retain expired key bytes until its next use/free; it must never accept
  or issue under an expired key. This avoids a timer thread or new event-loop API.
  Do not continue using an expired key when RNG or rotation fails. Account for the
  ticket AEAD's nonce/key usage budget as well as elapsed time.
- Give the retained OpenSSL backend the same bounded key-lifetime policy through its
  non-deprecated SSL_CTX_set_tlsext_ticket_key_evp_cb callback; keep its wire format
  independent. Test rotation in both builds. Do not introduce distributed key
  management or cross-backend decoding.
- Memory: the key ring and its synchronization belong to the context, not each
  connection. Wipe the per-connection resumption secret once tickets are encoded;
  a slow drain then retains ciphertext only. No unbounded post-handshake ticket queue.

OpenSSL fact check: the 3.5.5 default creates ticket keys with SSL_CTX and does not
automatically rotate them on a timer. Applications can install rotation through the
[ticket-key callback](https://docs.openssl.org/3.5/man3/SSL_CTX_set_tlsext_ticket_key_cb/).
The old blog's use of s_client to test a server does not establish OpenSSL's default
server policy. Nevertheless, copying a non-rotating default is not a good reason to
omit this small mechanism: [RFC 9325 section 3.4](https://www.rfc-editor.org/rfc/rfc9325.html#section-3.4)
calls for rotation and bounded ticket validity. With TLS 1.3 psk_dhe_ke and no 0-RTT,
ticket-key theft alone does not decrypt previously recorded application traffic; do
not carry that TLS 1.2 claim into this design's rationale.

## Remove kTLS

Retire shim/ktls.c, its public offload functions/constants, build wiring, and the
corresponding goose-http handoff, record-control, and platform-stub paths together.
Update tests, docs, and consumer pins as a coordinated change; do not leave a flag,
no-op API, or compatibility framework just to preserve the experiment. Keep useful
RFC key-derivation test vectors when moving them to the new key-schedule tests.
Normal TLS KeyUpdate, alerts, and usage limits remain required in user space.

The evidence is goose-http/tasks/014-http2-tls/02-tls.md:257, on the Ryzen 5 9600X,
Bazzite kernel 6.17.7, OpenSSL 3.5.9, AES-128-GCM, with interleaved loopback h2load
runs. These are not a completed HttpArena network comparison:

| Response | User-space TLS | kTLS |
|---|---:|---:|
| Small /json | 2.84-2.92 M requests/s | 3.16-3.19 M requests/s |
| 16 KB | 196-202 K requests/s | 112-113 K requests/s |

That is about 10% higher throughput for small responses but 44% lower for 16 KB,
equivalent to about 78% longer for a fixed request count, not an 80% throughput loss
or a measured latency increase. Both paths used AVX-512 AES-GCM; the recorded extra
cost was mainly elsewhere in the kernel send path (task line 277). The
[linked gist](https://gist.github.com/kaitk/04abb5189b7eefdf3a7fa837643ee40a)
covers scheduling and h2c/HPACK and says the json-tls
rerun did not run; it is not the source of this kTLS table.

Linux configures kTLS per socket direction, with no supported switch back to user
space between requests. HTTP/2 streams share that decision. The current package
chooses per context; Linux itself permits a per-connection and per-direction choice.
OpenSSL does offer integrated kTLS, explicitly enabled at build and runtime. Rustls
offers handoff/key APIs requiring application integration. Neither enables it by
default. See the [Linux interface](https://docs.kernel.org/networking/tls.html),
[OpenSSL guide](https://docs.openssl.org/3.5/man7/ossl-guide-migration/#support-for-linux-kernel-tls),
and [rustls kernel API](https://docs.rs/rustls/latest/rustls/kernel/index.html)
(0.23.46 when checked).

The decision removes a second record-processing path, secret capture, handoff states,
and cross-layer key-update ordering. It does not claim kTLS is universally slow.
Revisit only for a measured workload, such as sendfile or NIC offload, that warrants
the maintenance cost. Keeping the OpenSSL alternative does not depend on keeping kTLS.

## Order of work

1. Record the changed direction in task 007, AGENTS.md, decisions, and architecture;
   mark the new server as pending the spike. Close task 006 as not merged, leaving
   its branch untouched. Resolve the recorded HttpArena rule before claiming this
   implementation qualifies there: docs/decisions.md:13 currently says json-tls
   requires a standard TLS stack. Check the current rules; using EVP alone does not
   prove compliance. The OpenSSL build remains available for entries requiring it.
2. Spike 02, first the ownership/build slice: construct/free/share/replace contexts
   and connections through Goose and C, exercise bounded buffer lifetimes, and prove
   the build-time OpenSSL alternative and retained client coexist cleanly. Measure
   empty-connection overhead and Goose-to-C call cost. Read the pinned language docs
   and inspect generated C before committing to a pool or native-owner design.
3. Spike 02, then the crypto/protocol slice: measure each primitive's allocations
   after setup, use, and free (AES-GCM, ChaCha20-Poly1305, SHA-256/384, HMAC/HKDF,
   X25519, X25519MLKEM768, P-256). Build one full-handshake and record-layer path behind
   spike 01's srv.h/bench.c interface, reusable in the server. Cover X25519 and hybrid
   exchange, P-256 exchange, and ECDSA and RSA certificates without first building
   HRR, resumption, or the complete option surface. Start parser fuzzing here.
   Apply the measurement and go/no-go rules below before completing the server.
4. Full server without resumption: HRR, alerts, KeyUpdate, choose_context, use_groups,
   and all three record suites. Existing golden tests (hello, load, choose, replace,
   groups), OpenSSL peers, curl, RFC vectors, tlsfuzzer, and state-machine fuzzing
   must pass. Keep the OpenSSL alternative passing the common API tests.
5. Session tickets immediately next: issue, resume, binder verification, rotation,
   expiration, and worker/context sharing. Run s_client -sess_out/-sess_in and
   tlsfuzzer's resumption scripts, then measure tickets enabled, full and resumed.
6. Finish the coordinated removal of kTLS before moving consumer pins; that cleanup
   may also land independently earlier. Run goose-http's suites and the client check
   (curl, wrk, h2load, oha; Chromium and Firefox once by hand). Record versions, TLS
   version, suite, group, ALPN, and whether resumption actually occurred. Unsupported
   old client builds must fail clearly; record their linked TLS-library versions.
7. Run json-tls and 8gbit in separate server/client processes over the network,
   subject to the benchmark's eligibility rules. Include production ticket settings
   and server-process memory. Release and move the consumer pin only after the
   functional, security, and performance gates pass. Keep an OpenSSL build and a
   documented rebuild/redeploy command as the tested rollback path.

### Spike measurements and go/no-go

- Initially disable ticket issuance explicitly on both the new and OpenSSL servers
  to compare the incomplete server fairly. Historical rustls numbers are reference
  points, not a freshly matched tickets-off baseline. After step 5, repeat the real
  tickets-on workload, including resumption. Do not add Rust to the package build to
  rerun a reference benchmark.
- Match negotiated suite/group, certificate chain, ticket mode, compiler settings,
  OpenSSL/provider version, and API call pattern. Use warmed algorithms and multiple
  interleaved runs; report medians and spread, not a single lucky measurement.
- Measure at 1,000 and 4,000 connections: idle after a request and complete drain;
  handshake in flight after the server flight has drained; and the same flight left
  queued. Also measure transient handshake peaks, partial records, unread plaintext,
  full-size records, and retained memory after a large-flight/connection-churn burst.
  Report shared context memory separately and identify queued bytes explicitly.
- Report allocator bytes, mapped allocations where relevant, and RSS. The in-process
  harness's RSS also includes its clients and allocator retention; label that limit
  and confirm server-only memory in the separate-process run. Do not claim a win
  merely by moving allocations outside mallinfo2 or into a permanently retained pool.
- Working numerical interpretation of "near rustls", proposed for this spike:
  at most 10,000 bytes per idle connection and 10,000 bytes per drained-flight
  connection at 4,000 held, with no hidden pool/mapping growth. The queued-flight
  result adds the actual queued flight and bounded bookkeeping; an arbitrarily long
  certificate chain cannot fit the drained-state budget. Publish the transient peak
  too. These are targets, not measurements already achieved.
- CPU: no repeatable regression against matched OpenSSL for full-handshake and
  json-like traffic; judge differences against measured run-to-run variation.
  Investigate larger-record behavior as well, given the kTLS result. Repeat with
  tickets on and resumed handshakes before release. If the bar fails, keep OpenSSL
  as the deployed backend and report the limiting allocations or CPU work; do not
  silently relax the target or add broad optimization machinery.

### Security and interoperability gate

Keep tests focused on failures the implementation could admit, not a new testing
framework. Existing golden tests establish API behavior; happy-path client success
alone does not validate the state machine.

- Use [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448.html) intermediate secrets,
  transcripts, Finished, record, resumption, and HRR traces for applicable supported
  paths. Force each of the three AEAD suites and both SHA-256 and SHA-384 paths;
  otherwise normal negotiation can leave substantial crypto code untested.
- Run tlsfuzzer's applicable TLS 1.3 server and resumption scripts. Cover fragments
  at record/key boundaries, coalescing, invalid ordering, CCS windows, bad Finished
  and binders, malformed lengths, wrong tags, invalid shares, padding/type errors,
  empty application records, bounded early-data rejection, alerts, and KeyUpdate.
- Fuzz the parsers and state transitions, including authenticated post-handshake
  records from a harness with known keys. Random ciphertext alone stops at the AEAD
  tag and cannot exercise Finished, KeyUpdate, or inner-message handling. Mutate feed
  fragmentation and read/drain sizes too; save failures as small regression cases.
- Run the C shims and generated C under ASan/UBSan where supported, and check both
  debug and optimized builds for parsing/conversion behavior. Exercise allocation
  and crypto failure cleanup and secret ownership, not just successful handshakes.
- Ticket tests include HRR binders, unusable versus selected-bad-binder behavior,
  hash compatibility, expired/foreign/tampered tickets, old/new key overlap, skipped
  rotation periods, cross-worker use, SNI/context replacement, and full-handshake
  fallback after a backend switch. Confirm no application data is accepted early.
- Record the client checks rather than building a permanent browser matrix. Fuzzing
  and tests are the release gate; an independent external audit remains optional.
  Passing these checks must not be described as an audit or proof of security.

## Open risks

- Writing a TLS state machine ourselves: correctness and security. Mitigation: narrow
  scope, explicit states and ownership, crypto in libcrypto, known-answer vectors,
  tlsfuzzer, authenticated state-machine fuzzing, sanitizers, and the tested OpenSSL
  alternative. Keep the new backend out of deployment until the gates pass.
- libcrypto's per-object overhead (EVP_CIPHER_CTX, EVP_MD_CTX, provider lookups per
  fetch): fetch EVP_CIPHER/EVP_MD once per process; measure in spike 02.
- Goose's representation, generated parsing code, and allocator retention: settle
  these with the ownership slice and allow concise C helpers instead of workarounds.
- HttpArena eligibility under the recorded standard-stack requirement: verify the
  current rule before treating the new backend as an eligible published entry.

## Review round 1 (Codex CLI 0.163.0, gpt-6.1-sol, medium effort, 2026-10-22)

Historical record of the first review. The corrections and changed decisions below
supersede its original dispositions; the main plan is the implementation guidance.

Taken at the time:

- Record and handshake robustness: fragmentation and coalescing with bounded
  reassembly, the 2^14 + 256 ciphertext limit, duplicate extensions rejected, GREASE
  and unknown extensions ignored, the second ClientHello checked against the first
  after HRR, early_data records skipped up to a bound, the X25519 all-zero secret
  rejected, terminal failure after any authentication error.
- Limits on ClientHello size, queued bytes, and incomplete handshakes, since `feed`
  takes everything.
- Signature scheme negotiation and the CertificateVerify input spelled out, rather
  than "whatever the key is".
- ML-KEM offered only where libcrypto has it (3.5 or later); `CMakeLists.txt` accepts
  OpenSSL 3.0 today.
- Ticket details: the PSK derivation per ticket nonce, the binder key and the HRR
  transcript, selected_identity, a versioned ticket with a random nonce, fallback to a
  full handshake for an unusable ticket against a fatal error for a bad binder. ALPN
  dropped from the ticket's checks (RFC 7301 3.1). The estimate now says the negative
  tests come on top.
- Corrections: OpenSSL sends two tickets after a full handshake but one after a
  resumption; kTLS keeps more of `ktls.c` than "only setsockopt" (the record-boundary
  checks, KeyUpdate ordering, RX-only handoff). That description of the existing code
  remains correct, but preserving kTLS is superseded by the removal decision.
- Spike 02 first measures each libcrypto primitive's allocations, since EVP objects
  hold provider state of undocumented size (AES schedule and GCM tables, ChaCha state,
  the expanded ML-KEM key); key-exchange objects are freed right after derivation; the
  memory bar is near rustls, not just under OpenSSL; in-flight memory is also measured
  with the server's flight left undrained. The accompanying claim that spike 01 had
  tickets off was wrong; see Context and the revised measurement rules.
- A recorded client check before release, and HttpArena runs in separate processes.

Not taken at the time, with current disposition:

- Ticket key rotation and identifiers: originally deferred because OpenSSL did not
  rotate by default. Reversed in round 2: that default is not a sufficient security
  rationale. A bounded two-key policy is small enough to include with tickets.
- P-384 key exchange and Ed25519 certificates: no current caller needs them.
- A formal browser matrix: Chromium and Firefox are checked once by hand; curl, wrk,
  h2load, and oha, which the benchmarks use, are checked and recorded.
- An independent external TLS review before release: tlsfuzzer, fuzzing, and the
  client check are the gate for now; the maintainer may add one.
- Wiping secrets through every Goose copy and reallocation: the plan wipes them on free
  and on error paths; keeping secrets in fixed buffers that aren't reallocated is the
  implementation rule, rather than a separate mechanism. Round 2 corrects the missing
  condition: fixed arrays/structs can still be copied by value. Use references and
  slices, inspect generated C, and cleanse owned storage at its last use.
- Moving kTLS later than tickets while keeping it in scope: superseded by the
  follow-up decision to remove it. Existing use alone does not justify its cost.

## Review round 2 and follow-up decisions (2026-10-22)

Integrated into the sections above:

- Retain an explicit OpenSSL server alternative, build-time first; never retry a
  failed connection through it. Keep the client and cold path on OpenSSL.
- Permit concise C for ownership and buffers where it is the better fit. Prototype
  Goose lifetimes, worker sharing, ABI, and backend selection before the handshake.
- Add HMAC, the CertificateVerify zero separator, TLS ECDSA DER, hybrid share order,
  explicit state/epoch boundaries, CCS validation, inner-plaintext limits, and empty
  application-record handling. Keep unauthenticated EVP output private.
- Correct the tickets-on baseline and drained-flight interpretation. Measure actual
  allocations, mapped/pool retention, RSS, queued bytes, transient peaks, and CPU
  variation; give "near rustls" a proposed numerical gate rather than an adjective.
- Include ticket rotation, context binding, cross-worker tests, and honest scope for
  the line-count estimate. ALPN remains freshly negotiated on resumption.
- Remove kTLS based on its measured trade-off and integration cost. Earlier findings
  about fragmented post-handoff KeyUpdate and kernel record counting become reasons
  not to carry that path forward, rather than additional implementation tasks.
- Add RFC vectors, authenticated state-machine fuzzing, and sanitizer coverage.
  Keep the browser check informal and an external audit optional.
- Supersede all conflicting repository decisions, not only the pending Rust one,
  and check the recorded HttpArena eligibility constraint before claiming compliance.

## tls.goose externs before this work

There are 41 today. The seven tls_kernel_* externs below are removed with kTLS;
this is an inventory of the current shim, not a requirement to retain its internals.

tls_server_new, tls_context_free, tls_accept, tls_conn_free, tls_feed, tls_pending,
tls_drain, tls_handshake, tls_read, tls_write, tls_shutdown, tls_alpn_selected,
tls_version, tls_cipher, tls_group, tls_use_groups, tls_error_text, tls_library,
tls_kernel_supported, tls_kernel_enable, tls_kernel_start, tls_kernel_wants,
tls_kernel_owned, tls_kernel_record, tls_kernel_update_tx, tls_client_new,
tls_context_share, tls_connect, tls_choose_enable, tls_use_context, tls_server_name,
tls_offered, tls_peer_certificate, tls_key_generate, tls_key_from_pem, tls_key_free,
tls_key_pem, tls_key_public, tls_sign_es256, tls_csr, tls_self_signed.
