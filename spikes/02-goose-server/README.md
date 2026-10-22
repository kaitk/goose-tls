# Spike 02: a TLS 1.3 server in Goose over libcrypto

Asked 2026-10-22 (task 007): can goose-tls's server, written in Goose over
libcrypto's EVP, hold close to rustls's memory per connection without costing CPU
against OpenSSL? The plan's bar: at most 10,000 bytes per idle connection and per
connection with its handshake flight drained, at 4,000 held, with no hidden pool or
mapping growth; and no CPU regression against OpenSSL beyond the runs' spread.

**Verdict: go.** The Goose server clears the bar by a wide margin, in every
measurement, on the desktop below. Task 007 goes on to the full server. These are
in-process numbers on one machine; the server-only process memory and goose-http's
runs come in task 007's step 7.

| Per server connection, 4,000 held | Goose server | OpenSSL 3.5.5 | rustls 0.23.46 (spike 01) |
|---|---:|---:|---:|
| Idle | 2,929 B | 28,523 B | 7,844 B |
| Handshake in flight, flight drained | 3,742 B | 58,627 B | 8,336 B |
| Handshake in flight, flight queued | 6,110 B | 61,875 B | |
| Server CPU, full handshake | 638.7 µs | 690.7 µs | 615 µs |
| Server CPU, json-like request | 2.42 µs | 3.32 µs | 2.42 µs |

All three negotiated X25519MLKEM768 and TLS_AES_128_GCM_SHA256. The Goose server and
OpenSSL issued no session tickets here; spike 01's rustls and OpenSSL rows issued
two, so the rustls column is a reference point, not a matched comparison.

## What the spike built

The ownership and build slice (task 007, step 2) and one full-handshake and
record-layer path (step 3), written as the server, not as throwaway code:

- `shim/server.c` owns what Goose can't hold across calls and threads: a context
  (the chain as DER, the key, the ALPN list, the groups, a reference count) and a
  connection (three byte queues freed once empty, each direction's AEAD context, IV,
  sequence number, and traffic secret, and during the handshake the transcript and
  numbered secret slots). Secrets never cross to Goose. Its calls are libcrypto's
  primitives named by Goose: HKDF-Extract, HKDF-Expand-Label, Finished, the key
  exchange, the signature, seal and open.
- `server.goose`, `hello.goose`, and `wire.goose` are the protocol: the record
  framing and its limits, the ClientHello parser over a checked big-endian reader, the
  negotiation, HelloRetryRequest, the server's flight, the key schedule's order and
  labels, the client's Finished, alerts, close_notify, and KeyUpdate. Each API call
  copies the connection's `ServerState`, 180 bytes, from C and back.
- A handle has bit 0 set for the Goose server's objects, so `tls.goose` sends each
  call to the server it belongs to; libssl's objects are even addresses. The client
  stays on libssl.
- `tls::server` makes a Goose context unless the package's C was configured with
  `GOOSE_TLS_SERVER=openssl`, which CMake reads from the environment at its first
  configure (`CMakeLists.txt`). Both builds pass the package's tests: the golden
  tests, the handshake script against `openssl s_client` and `curl`, and the crypto
  checks. kTLS's own test passes only on libssl's (its removal is task 007's step 6).

## Method

Spike 01's harness (`../01-rustls/bench.c`), extended for this spike with a
`queued` mode (the flight left waiting for drain), an `empty` mode, a `peak` mode
(the most OpenSSL's allocator holds above its level while the server answers a
ClientHello, counted through `CRYPTO_set_mem_functions`), a `churn` mode (three
rounds of 1,000 connections, each given a 64 KiB response, then all freed: the heap
and RSS kept), glibc's mmapped bytes beside its heap, and `TICKETS=0` for the
OpenSSL server. Every server uses the same RSA-2048 certificate, ALPN http/1.1, and
an OpenSSL 3.5.5 client in the same process, bytes moved in memory.

- `bench_goose.goose` exports the Goose server's calls, and `glue.c` runs bench.c's
  `main` against them, so the Goose server runs as a program would build it.
- `prim.c` measures each primitive's allocations after setup, use, and free.
- `calls.goose` times a call from Goose into the package's C.
- `ALLOCS=1` makes bench.c's `hs`, `resume`, and `json` count the allocations
  OpenSSL's allocator makes inside the server's calls, per handshake or request
  (added for task 007's overhead work, 2026-10-22).
- `threads.goose` runs full handshakes on several threads on one shared context,
  the package's client against the Goose server, and prints handshakes per second;
  `goose build` it, then run `threads THREADS HANDSHAKES`. Exported Goose functions
  must stay on the main thread, so bench.c can't do this.
- `build.sh` builds them into `build/spike-goose/`; `run.sh` runs every mode for
  both servers and both key exchanges (`default`: the client's default shares,
  X25519MLKEM768 and X25519; `x25519`: X25519 only, and the servers set to it), five
  rounds interleaved as spike 01's, each run its own process pinned to CPU 2; and
  `../01-rustls/summarize.py` makes the tables.

```sh
spikes/02-goose-server/build.sh
COMMIT=$(git rev-parse --short HEAD) spikes/02-goose-server/run.sh > results.txt
python3 spikes/01-rustls/summarize.py < results.txt
```

## Results

Measured 2026-10-22 on the desktop:

- Ryzen 7 5800X3D (Zen 3: AES-NI, VAES, AVX2, no AVX-512)
- Ubuntu 26.04 in WSL2, kernel `6.18.54.1-microsoft-standard-WSL2`, gcc 15.2
- OpenSSL 3.5.5; Goose v2026.3; goose-tls `95e72c5` (branch `goose-server`), the
  harness as committed with these results
- Command: `run.sh`, 5 rounds; `results-2026-10-22.txt` is the raw output (its
  header lacks the commit, which git couldn't read from WSL in that worktree)

Each cell is the median of 5 runs, with the range in parentheses where the runs
differed.

### Memory per server connection

| Server | Groups | Idle, 1,000 | Idle, 4,000 | Drained flight, 4,000 | Queued flight, 4,000 |
|---|---|---:|---:|---:|---:|
| Goose | default | 2,930 B | 2,929 B | 3,742 B | 6,110 B |
| Goose | x25519 | 2,931 B | 2,928 B | 3,742 B | 5,022 B |
| OpenSSL | default | 28,531 B | 28,523 B | 58,627 B | 61,875 B |
| OpenSSL | x25519 | 21,945 B | 21,946 B | 52,059 B | 53,854 B |

That is glibc's in-use heap; its mmapped bytes grew by 0 in every run, and RSS per
connection was within 3% of the heap (Goose at 4,000: 3,022 B idle, 3,823 B drained,
6,190 B queued). A connection with nothing fed yet holds 560 B on the Goose server
and 16,829 B on OpenSSL (`empty 4000`, one run each).

What a Goose-server connection holds, idle: two AEAD contexts, 1,152 B each for
AES-GCM (1,040 B for ChaCha20-Poly1305, below), and the connection, 560 B with its
state. In flight, the handshake's secret slots and the client's handshake key instead
of the server's application one; queued, the flight's 2.4 KB of ciphertext with the
hybrid share, 1.3 KB with X25519.

### The handshake's transient peak and retained memory

| Server | Groups | Peak above the connection's level | Heap kept after churn | RSS kept after churn |
|---|---|---:|---:|---:|
| Goose | default | 10,732 B mean, 12,530 B most | 39,936 B | 3.2 MB |
| Goose | x25519 | 10,878 B mean, 12,676 B most | 26,848 B | 3.2 MB |
| OpenSSL | default | 61,399 B | 69,568 B | 28.7 MB |
| OpenSSL | x25519 | 53,413 B | 70,592 B | 22.1 MB |

The peak counts OpenSSL's allocator only; the Goose server's own scratch during a
handshake (the ClientHello's copy and the flight it builds, a few KB) lives on Goose's
data stacks, which keep their pages once touched, and shows in RSS rather than here.
After churn, the RSS kept is mostly glibc's arenas holding freed memory.

### CPU, one core, the server's calls only

| Server | Groups | Handshake | json-like request | Encrypt, 16 KB records | Decrypt, 16 KB records |
|---|---|---:|---:|---:|---:|
| Goose | default | 638.7 µs (638.4-651.8) | 2.42 µs (2.40-2.46) | 4,542 MiB/s (4,349-4,609) | 4,249 MiB/s (4,195-4,276) |
| Goose | x25519 | 591.3 µs (591.1-596.3) | 2.42 µs (2.41-2.44) | 4,606 MiB/s (4,531-4,613) | 4,279 MiB/s (4,212-4,298) |
| OpenSSL | default | 690.7 µs (689.0-702.1) | 3.32 µs (3.29-3.43) | 3,722 MiB/s (3,557-3,729) | 3,754 MiB/s (3,688-3,800) |
| OpenSSL | x25519 | 638.8 µs (633.8-647.7) | 3.32 µs (3.27-3.45) | 3,706 MiB/s (3,638-3,722) | 3,805 MiB/s (3,717-3,828) |

The json-like request is a 200 B request in and an 8,545 B response out, over 1,000
connections taken in turn; its time is the inverse of the median requests per
second.

### Each primitive's allocations

`prim`, OpenSSL 3.5.5, algorithms fetched once beforehand (386 KB held by the fetches
and the provider):

| Primitive | Held once set up | Most held during use | Kept after free |
|---|---:|---:|---:|
| AES-128-GCM context | 1,152 B | 1,152 B | 0 |
| AES-256-GCM context | 1,152 B | 1,152 B | 0 |
| ChaCha20-Poly1305 context | 1,040 B | 1,040 B | 0 |
| SHA-256 transcript | 184 B | 368 B (a copy to read it) | 0 |
| SHA-384 transcript | 288 B | 576 B | 0 |
| HMAC-SHA256, one call | 0 | 800 B | 0 |
| HKDF-Expand, one call | 0 | 796 B | 0 |
| X25519, a key pair and a derive | 0 | 720 B | 0 |
| P-256 ECDH, a key pair and a derive | 0 | 4,733 B | 0 |
| ML-KEM-768 encapsulation | 0 | 7,272 B | 0 |

These are the second of two runs; the first use of HMAC, X25519, and ML-KEM also
fills caches that the process keeps (7.7 KB, 3.9 KB, and 8.2 KB), once.

### A call from Goose into C

`calls.goose`, 20,000,000 calls, three runs: a call that returns a field
(`tls::pending`) costs 1.0 ns; loading and storing a connection's state costs 29.7 to
30.2 ns a pair. The generated C copies the packed 180-byte struct several times
through `load`'s return. A json-like request makes two or three loads and two stores,
about 3% of its 2.42 µs; trimming them is a possible gain, not part of the bar.

## What the numbers say

- **Memory:** an idle connection holds 2.9 KB, a tenth of OpenSSL's and 37% of
  rustls's; a handshake in flight 3.7 KB once its flight is drained. The two AEAD
  contexts are 79% of the idle figure; the rest is the connection's own 560 B and
  malloc's overhead. ML-KEM costs nothing once the handshake is over: the server
  never holds an ML-KEM key, and frees the encapsulation's objects within the call.
- **Transient:** a handshake needs about 11 KB more while the ClientHello is
  answered, against OpenSSL's 61 KB, which OpenSSL then keeps until the client's
  Finished.
- **CPU:** a full handshake costs 7.5% less than OpenSSL's, with X25519MLKEM768 and
  with X25519 alike; a json-like request 27% less; bulk encryption 22% more
  throughput and decryption 13% more. Every difference is beyond the runs' spread.
  The RSA-2048 signature is most of a handshake on either server. Against spike 01's
  rustls on aws-lc-rs, from other runs with tickets on, the Goose server's handshake is
  4% slower (638.7 against 615 µs) and its json-like request the same (2.42 µs).
- **Limits of the method:** the harness holds every connection in one process with
  its clients, as spike 01's did, so RSS includes the clients' share and glibc's
  retention; the Goose server's data stacks are per program, not per connection.
  Session tickets are off on both servers here; the next section measures them on.

## With session tickets

Measured 2026-10-22 on the same machine and system, with session tickets on in both
servers (task 007, step 5): goose-tls `9bc8238`, `TICKETS=1 RUNS=5 MODES="idle:4000
inflight:4000 queued:4000 peak:1000 hs:3000 resume:3000 json:200000:1000" run.sh`,
5 interleaved rounds pinned to CPU 2; `results-2026-10-22-tickets.txt` is the raw
output. Both servers send two tickets after a full handshake, which the client reads
inside the measured handshake. `resume` makes each client resume from the ticket the
client before it took; OpenSSL's server here is spike 01's `srv_openssl.c` with
libssl's default ticket key, not the package's rotating one. Medians, ranges where
the runs differed.

| Server | Groups | Full handshake | Resumed handshake | json-like request |
|---|---|---:|---:|---:|
| Goose | default | 648.8 µs (647.5-662.8) | 150.5 µs (149.7-154.1) | 2.42 µs (2.41-2.44) |
| Goose | x25519 | 602.1 µs (601.0-605.2) | 102.8 µs (102.3-103.4) | 2.43 µs (2.40-2.45) |
| OpenSSL | default | 721.4 µs (721.2-732.1) | 207.0 µs (204.6-208.2) | 3.32 µs (3.31-3.39) |
| OpenSSL | x25519 | 669.1 µs (667.2-696.0) | 152.4 µs (151.7-152.8) | 3.37 µs (3.33-3.40) |

| Server | Groups | Idle, 4,000 | Drained flight, 4,000 | Queued flight, 4,000 | Peak, mean and most |
|---|---|---:|---:|---:|---:|
| Goose | default | 2,930 B | 3,807 B | 6,175 B | 10,796 B, 12,594 B |
| Goose | x25519 | 2,929 B | 3,806 B | 5,086 B | 10,942 B, 12,740 B |
| OpenSSL | default | 28,528 B | 58,627 B | 61,875 B | 61,399 B |
| OpenSSL | x25519 | 21,947 B | 52,059 B | 53,854 B | 53,413 B |

- **CPU:** with tickets on, the Goose server's full handshake costs 10% less than
  OpenSSL's, with either key exchange, and a resumed one 27% less with
  X25519MLKEM768 and 33% less with X25519. A resumption costs the Goose server a
  quarter of a full handshake, or a sixth with X25519: it skips the RSA signature,
  and keeps the key exchange.
- **What tickets cost:** against the tickets-off runs above, the full handshake rose
  10 µs on the Goose server (1.6%) and 31 µs on OpenSSL's (4.4%). Those runs were an
  hour apart rather than interleaved, so treat these differences as approximate.
- **Memory:** an idle connection holds what it held without tickets: the resumption
  secret is wiped once the tickets are sealed. A handshake in flight holds 65 B more,
  and the peak 64 B more; the handshake state's two added secret slots are the likely
  cause, not traced. OpenSSL's figures didn't change.

## Not done in this spike

- A server-only process under load, and goose-http over this server (task 007,
  step 7).
