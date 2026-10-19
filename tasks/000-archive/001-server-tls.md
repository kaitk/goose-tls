# 001: Server TLS over OpenSSL 3

Status: done (2026-10-19)

The first API: a server context from a PEM certificate chain and key, and a connection
that takes the bytes the program read and returns the bytes to send. goose-http builds
HTTP/1.1 over TLS on it (its task 014, phase 2), and goose-rest's HttpArena entry
serves json-tls and 8gbit with it (goose-rest's task 047).

The API must leave room for what snowtime-native's edge does in process today
(`crates/host/src/edge/`, over rustls and rustls-acme): h2 and HTTP/1.1 chosen by ALPN,
ACME's `acme-tls/1` protocol on the same listener, and certificates replaced while the
server runs. SNI and the swap can come after this task, but the context and
connection types must not rule them out.

## What HttpArena checks

From `validate.sh`'s TLS checks (HttpArena at `2d85137`, 2026-10-18), on every TLS
profile:

- The leaf certificate is the mounted `/certs/server.crt` (RSA-2048).
- TLS 1.3 is negotiated, with `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, or
  `TLS_CHACHA20_POLY1305_SHA256`.
- ALPN never names a protocol the client didn't offer; selecting none is allowed.
- No obsolete protocol version or weak cipher is accepted.

## Steps

1. Decide OpenSSL 3 or another library (`docs/decisions.md`, "Proposed"), and how each
   platform links it ("Open").
2. The shim: `SSL_CTX` from PEM files, an `SSL` per connection over two memory BIOs,
   and functions that feed received bytes, drain bytes to send, read plaintext, and
   write plaintext, each returning a status the program can act on (want more input,
   have output, closed, error).
3. ALPN: the server's list of protocols, in its order of preference, and the
   negotiated protocol readable after the handshake.
4. Tests under `test/`: a handshake and an echo between a goose-tls server and
   `openssl s_client`, a refused TLS 1.2 client, and ALPN with `curl --http1.1`.
   `scripts/test.sh` runs them.

## Acceptance criteria

- [x] The library and the platform linking recorded in `docs/decisions.md`
- [x] The API in `README.md`, and `docs/architecture.md` describing the byte flow
- [x] `openssl s_client` and `curl` complete a TLS 1.3 handshake against a test server
      and get back what they sent, on macOS and Linux (macOS arm64 with OpenSSL 3.6.5
      and 4.0.3; Ubuntu 24.04 arm64 in Docker with 3.0.13; Windows not tried)
- [x] HttpArena's four TLS checks above pass against a test server on port 8081
      (`scripts/test-handshake.sh`)
- [x] `scripts/test.sh` passes
