# Spike 01: rustls against OpenSSL

Asked 2026-10-20: would rustls serve TLS 1.3 at the same or better CPU cost, and with
less memory per connection, than OpenSSL 3.5 as goose-tls uses it? A switch needs both:
the same or better CPU, and less RAM. A Rust toolchain in the build doesn't count against
rustls, since binaries can ship prebuilt. This spike measures; it doesn't port goose-tls.

**Verdict:** rustls clears the bar in every measurement, by a wide margin. rustls-ffi, its
C API, doesn't: it can't configure what goose-tls needs, so a switch goes through a small
Rust library of our own, over rustls itself.

| Per server connection | OpenSSL 3.5.5, X25519MLKEM768 | rustls 0.23.46, aws-lc-rs, X25519MLKEM768 | rustls 0.23.46, ring, X25519 |
|---|---:|---:|---:|
| Idle memory, 4,000 held | 28,528 B | 7,844 B (−73%) | 7,648 B |
| Handshake in flight, 4,000 held | 58,626 B | 8,336 B (−86%) | 8,108 B |
| Server CPU, full handshake | 727 µs | 615 µs (−15%) | 563 µs |
| json-like request, server CPU | 3.28 µs | 2.42 µs (−26%) | 1.59 µs |

## Method

`bench.c` runs a server and its clients in one process, and moves the bytes between
them in memory, with no sockets, so that only the TLS library is measured. The server
side sits behind `srv.h`, which has the shape of goose-tls's shim: feed the bytes received,
drive the handshake, read plaintext, write plaintext, and drain the bytes to send.

- `srv_openssl.c` sets up the server as goose-tls v0.0.2's `shim/tls.c` does:
  - TLS 1.3 only, with its three suites in the server's order;
  - `SSL_MODE_RELEASE_BUFFERS`;
  - ALPN http/1.1;
  - two memory BIOs, each with its buffer freed once it's empty.
- `srv_rustls.c` uses rustls-ffi v0.15.6's buffer API:
  - `rustls_connection_read_tls` and `rustls_connection_process_new_packets` to feed;
  - `rustls_connection_write_tls` to drain;
  - TLS 1.3 only, the same three suites with AES-128-GCM first, and the server's order;
  - ALPN http/1.1.
- Every server uses the same RSA-2048 self-signed certificate. All runs negotiated
  TLS 1.3, AES-128-GCM, and http/1.1.
- The clients are always the system's OpenSSL, for every server, so the client side is
  the same throughout. Times count only the server's calls.
  `GROUPS` sets what the client offers:
  - `default`: OpenSSL 3.5's default offer, X25519MLKEM768 and X25519 key shares.
  - `x25519`: X25519 only. With OpenSSL as the server, it accepts only X25519 too.
- rustls-ffi has no call that sets the groups, so a rustls server keeps its provider's
  defaults:
  - aws-lc-rs, built with `prefer-post-quantum` as rustls-ffi builds it by default:
    X25519MLKEM768, X25519, P-256, P-384.
  - ring: X25519, P-256, P-384.

The modes (`bench.c`'s header has the details):

- **Idle:** N server connections. Each completes its handshake, reads a 200 B request,
  and writes an 8,545 B response, json-tls's largest. Its client is then freed. The
  connections are held at once. Memory is glibc's in-use bytes (`mallinfo2`) and
  `VmRSS`, each as the growth over N.
- **In flight:** N server connections, each stopped after its first flight: the
  ClientHello read, and ServerHello through Finished sent.
- **Handshake:** 3,000 full handshakes, each through to the client receiving its session
  tickets, and the connection freed. The figure is the time in the server's calls.
- **Encrypt** and **decrypt:** 2 GiB of 16 KB records on one connection.
- **json:** 200,000 requests over 1,000 connections taken in turn: a 200 B request in
  and an 8,545 B response out, the time in the server's calls.

`run.sh` runs each mode once per configuration per round, in an order that rotates each
round. It runs 5 rounds, each run its own process pinned to CPU 2. `summarize.py` makes
the tables, and `results-2026-10-20.txt` is the raw output.

To repeat it:

```sh
spikes/01-rustls/build.sh
spikes/01-rustls/run.sh > results.txt
python3 spikes/01-rustls/summarize.py < results.txt
```

`build.sh` fetches rustls-ffi with git and builds it with cargo, so it needs
[rustup](https://rustup.rs), CMake and a C compiler for aws-lc-sys, and OpenSSL 3's
headers.

## Results

Measured 2026-10-20 on the desktop, idle (load 0.1, no containers):

- Ryzen 7 5800X3D (Zen 3: AES-NI, VAES, AVX2, no AVX-512)
- Ubuntu 26.04 in WSL2, kernel `6.18.54.1-microsoft-standard-WSL2`, gcc 15.2
- OpenSSL 3.5.5; rustls-ffi v0.15.6 with rustls 0.23.46, aws-lc-rs 1.18.2, and
  ring 0.17.14
- Command: `RUNS=5 run.sh`

Each cell is the median of 5 runs, with the range in parentheses.

### Memory per server connection

Idle, after a handshake, a request, and a response:

| Library | Negotiated | 1,000 held: heap | 1,000 held: RSS | 4,000 held: heap | 4,000 held: RSS |
|---|---|---:|---:|---:|---:|
| OpenSSL | X25519MLKEM768 | 28,543 B (28,543-28,543) | 28,557 B (28,557-28,557) | 28,528 B (28,528-28,528) | 28,532 B (28,532-28,532) |
| OpenSSL | X25519 | 21,949 B (21,949-21,949) | 21,950 B (21,950-21,950) | 21,948 B (21,948-21,948) | 21,951 B (21,949-21,951) |
| rustls, aws-lc-rs | X25519MLKEM768 | 7,887 B (7,879-7,911) | 7,913 B (7,901-7,930) | 7,844 B (7,844-7,845) | 7,856 B (7,856-7,865) |
| rustls, aws-lc-rs | X25519 | 7,888 B (7,884-7,916) | 8,036 B (7,999-8,069) | 7,840 B (7,840-7,841) | 8,027 B (8,011-8,038) |
| rustls, ring | X25519 | 7,716 B (7,691-7,716) | 7,778 B (7,758-7,791) | 7,648 B (7,647-7,648) | 7,724 B (7,721-7,725) |

A handshake in flight, after the server's first flight:

| Library | Negotiated | 1,000 held: heap | 1,000 held: RSS | 4,000 held: heap | 4,000 held: RSS |
|---|---|---:|---:|---:|---:|
| OpenSSL | X25519MLKEM768 | 58,618 B (58,618-58,618) | 57,184 B (57,184-57,184) | 58,626 B (58,626-58,626) | 57,246 B (57,246-57,246) |
| OpenSSL | X25519 | 52,051 B (52,051-52,051) | 50,655 B (50,655-50,659) | 52,059 B (52,059-52,059) | 50,677 B (50,677-50,677) |
| rustls, aws-lc-rs | X25519MLKEM768 | 8,334 B (8,333-8,334) | 8,311 B (8,303-8,327) | 8,336 B (8,336-8,336) | 8,337 B (8,337-8,339) |
| rustls, aws-lc-rs | X25519 | 8,336 B (8,336-8,336) | 8,307 B (8,307-8,315) | 8,336 B (8,336-8,336) | 8,333 B (8,332-8,334) |
| rustls, ring | X25519 | 8,114 B (8,114-8,114) | 8,241 B (8,241-8,241) | 8,108 B (8,108-8,108) | 8,268 B (8,268-8,268) |

OpenSSL's idle figure agrees with goose-http's task 058: 30.4 KB a connection in the
server, about 300 B of it goose-http's. Its in-flight figure agrees too: 62,854 B,
counted through `CRYPTO_set_mem_functions`.

### CPU, one core, the server's calls only

| Library | Negotiated | Handshake | Handshakes/s, server | Handshakes/s, with the client | Encrypt, 16 KB records | Decrypt, 16 KB records | json: per request | json: requests/s |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| OpenSSL | X25519MLKEM768 | 726.9 µs (724.1-728.3) | 1,376 (1,373-1,381) | 938 (936-943) | 3,701 MiB/s (3,696-3,719) | 3,802 MiB/s (3,748-3,826) | 3.28 µs | 305,166 (299,403-308,762) |
| OpenSSL | X25519 | 671.0 µs (669.7-680.6) | 1,490 (1,469-1,493) | 1,136 (1,118-1,138) | 3,706 MiB/s (3,689-3,737) | 3,848 MiB/s (3,796-3,857) | 3.27 µs | 305,558 (300,991-307,312) |
| rustls, aws-lc-rs | X25519MLKEM768 | 615.2 µs (611.3-616.4) | 1,626 (1,622-1,636) | 1,033 (1,031-1,042) | 4,464 MiB/s (4,407-4,473) | 3,805 MiB/s (3,793-3,814) | 2.42 µs | 413,882 (409,936-416,536) |
| rustls, aws-lc-rs | X25519 | 592.0 µs (590.2-594.4) | 1,689 (1,682-1,694) | 1,221 (1,214-1,226) | 4,448 MiB/s (4,432-4,472) | 3,800 MiB/s (3,787-3,821) | 2.42 µs | 413,406 (404,615-416,838) |
| rustls, ring | X25519 | 562.7 µs (561.7-565.1) | 1,777 (1,770-1,780) | 1,275 (1,269-1,278) | 7,203 MiB/s (7,176-7,232) | 5,782 MiB/s (5,696-5,832) | 1.59 µs | 628,198 (624,004-630,287) |

"With the client" counts the whole loop, the OpenSSL client's work included. The json
per-request figure is the requests/s figure inverted.

### What the numbers say

- **Memory, idle:** rustls holds 7.6-7.9 KB per idle connection, against OpenSSL's
  28.5 KB with ML-KEM and 21.9 KB without: 73% less than OpenSSL as goose-tls uses it.
  At 4,096 connections that's about 82 MiB less.
- **Memory, in flight:** a handshake in flight holds 8.1-8.3 KB with rustls, against
  OpenSSL's 52-59 KB. In goose-http's json-tls run, the handshakes in flight while
  4,096 clients connect set the peak (task 058). That's where rustls saves the most,
  up to about 200 MiB at 4,096 connections if every handshake is in flight at once.
  OpenSSL's in-flight memory includes a 16 KB handshake buffer grown to 21.8 KB, and
  an 8 KB buffering BIO; neither has a size setting.
- **ML-KEM's cost:**
  - OpenSSL keeps the client's expanded key share until the connection is freed, so
    X25519MLKEM768 costs 6.6 KB on every connection, idle or not.
  - rustls drops the key share once the handshake has used it: the two groups' memory
    is within 4 B.
  - CPU: ML-KEM adds 56 µs (8%) to OpenSSL's handshake, and 23 µs (4%) to rustls's on
    aws-lc-rs.
- **Handshakes:** rustls on aws-lc-rs takes 15% less server time with ML-KEM, and 12%
  less with X25519. The RSA-2048 signature is most of either.
- **Bulk:** on aws-lc-rs, rustls encrypts 21% faster and decrypts at the same rate.
- **json:** on aws-lc-rs, a request costs the server 26% less, 2.42 µs against 3.28 µs.
  That's below OpenSSL's 3.28 µs by far more than the runs' spread (2%).
- **ring:**
  - ring's AES-GCM ran 95% faster than OpenSSL's on encrypt and 52% faster on decrypt,
    on this Zen 3 without AVX-512. Why wasn't investigated: check the assembly each
    library picks before relying on this.
  - The json request is half OpenSSL's cost.
  - ring has no ML-KEM group (below).

Limits of the method:

- The harness measures the library, not a server. Glibc's heap under concurrent load
  (task 058's "Under load") isn't modeled.
- Every run held the connections of one library in one process, so RSS here tracks the
  heap.
- Session tickets are each library's default:
  - goose-tls's OpenSSL server sends two stateless tickets.
  - rustls's default server sends two stateful ones, kept in a cache of 256 sessions.
    The cache is shared by every connection, so it adds little per connection at
    1,000 held or more.

## The Rust entries on HttpArena use ring, so they negotiate X25519

HttpArena's actix, ntex, and axum entries (at `0720ee5`) depend on rustls with
`default-features = false` and the `ring` feature. Their `Cargo.lock` files hold
rustls 0.23.43 and ring 0.17.14, and no aws-lc-rs. ntex and axum install
`rustls::crypto::ring::default_provider()`.

rustls's ring provider has three key-exchange groups, X25519, P-256, and P-384:
`ALL_KX_GROUPS` in `src/crypto/ring/mod.rs`. X25519MLKEM768 is only in the aws-lc-rs
provider (`src/crypto/aws_lc_rs/pq`).

So against h2load's OpenSSL 3.5, which offers X25519MLKEM768 and X25519 key shares, the
Rust entries negotiate X25519, with no HelloRetryRequest. The harness agrees: the ring
server against OpenSSL's default client reports X25519. Their per-connection memory
compares with this spike's "rustls, ring, X25519" row. ML-KEM wouldn't change rustls's
memory, but it does change OpenSSL's by 6.6 KB.

## rustls-ffi's gaps

rustls-ffi v0.15.6 is a general C API. For goose-tls it lacks:

- **The key-exchange groups.** There's no call to set them. Only the provider and its
  build features choose them.
- **kTLS.** It exposes neither rustls's `dangerous_extract_secrets` nor
  `dangerous_into_kernel_connection`, and has no message callback for counting records.
  The keylog callback gives the traffic secrets, but the shim would derive keys and IVs
  itself, as `ktls.c` does through OpenSSL's `EVP_KDF`. It would also have to count
  the records sent and received under each key, and handle a KeyUpdate after the switch
  with no help from the library. rustls's own `KernelConnection` does all three
  (`update_rx_secret` and `update_tx_secret`).
- **Stateless session tickets.** There's no ticketer; tickets are stateful only.
- **ACME's crypto** (`shim/crypto.c`): EC key generation, ES256 signatures, CSRs, and
  the TLS-ALPN-01 certificate. rustls-ffi has none of these.
- **A feed that takes everything.** `read_tls` takes at most 4 KB a call, and refuses
  input while 16 KB of plaintext waits unread. goose-tls's `feed` takes all its input,
  so it would return how much it took instead.
- **A documentation error:** `rustls_certified_key_build_with_signing_key` takes
  ownership of the signing key, though `rustls.h` says it takes none of its inputs.
  Freeing the key afterwards crashed the harness.

What does map, from goose-tls's shim to rustls-ffi:

| goose-tls shim | rustls-ffi |
|---|---|
| `tls_server_new` | `rustls_crypto_provider_builder_new_with_base`, `_set_cipher_suites`, `rustls_crypto_provider_load_key`, `rustls_certified_key_build_with_signing_key`, `rustls_server_config_builder_new_custom` (TLS 1.3), `_set_alpn_protocols`, `_set_ignore_client_order`, `_set_certified_keys`, `_build` |
| `tls_client_new` | `rustls_client_config_builder_new_custom`, with `rustls_root_cert_store_builder_add_pem` and a web PKI verifier, or the platform verifier for `system`, and `_set_alpn_protocols` |
| `tls_context_share`, `tls_context_free` | The config is an immutable `Arc`, safe to share, but has no call to take another reference; free it once |
| `tls_accept` | `rustls_server_connection_new` |
| `tls_choose_enable`, `tls_use_context`, `tls_server_name`, `tls_offered` | `rustls_acceptor_read_tls` and `rustls_acceptor_accept`, `rustls_accepted_server_name` and `rustls_accepted_alpn`, then `rustls_accepted_into_connection` with the chosen config |
| `tls_connect` | `rustls_client_connection_new` with the host name; it also accepts an IP address |
| `tls_feed` | `rustls_connection_read_tls` with a callback, then `rustls_connection_process_new_packets`; it may take less than all |
| `tls_pending` | `rustls_connection_wants_write`, a yes or no rather than a count |
| `tls_drain` | `rustls_connection_write_tls` with a callback |
| `tls_handshake` | `rustls_connection_is_handshaking`, after the feed |
| `tls_read`, `tls_write` | `rustls_connection_read`, `rustls_connection_write`. A write before the handshake ends is buffered, not `WANT_INPUT` |
| `tls_shutdown` | `rustls_connection_send_close_notify` |
| KeyUpdate | `rustls_connection_refresh_traffic_keys` to send one; received ones are handled inside |
| `tls_alpn_selected`, `tls_version`, `tls_cipher` | `rustls_connection_get_alpn_protocol`, `_get_protocol_version`, `_get_negotiated_ciphersuite_name` |
| `tls_peer_certificate` | `rustls_connection_get_peer_certificate` and `rustls_certificate_get_der`; the PEM encoding would be ours |
| `tls_error_text` | `rustls_error` on the returned code; there's no error queue |
| `tls_library` | `rustls_version` |
| `ktls.c` | none (see above) |
| `crypto.c` | none |

## What a switch would take

The numbers are rustls's: its connection state, its record layer, and its crypto
providers. rustls-ffi only adds a C boundary and a `Box`.

A small Rust library of our own, a static library with a C ABI shaped like goose-tls's
shim, would get the same memory and CPU and close every gap above through rustls's Rust
API:

- `CryptoProvider::kx_groups` for the groups;
- `Acceptor` for the ClientHello pause;
- `KernelConnection` for kTLS and its KeyUpdates;
- a `Ticketer` for stateless tickets;
- feed and drain over rustls's `read_tls` and `write_tls`.

ACME's crypto would need a crate such as rcgen beside it, or would stay on OpenSSL.

Two choices remain open:

- **The provider:**
  - aws-lc-rs has ML-KEM.
  - ring was faster still on this machine's AES-GCM, but offers X25519 at best.
- **Whether ML-KEM stays offered:** with rustls it costs no memory, and 4% of a
  handshake.

That library's design is a task of its own. kTLS doesn't change the verdict: rustls's
`KernelConnection` supports it, and goose-http's kTLS ran at half the rate on 16 KB
responses (task 002).
