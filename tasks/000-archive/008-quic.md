# 008: QUIC's handshake and packet protection

Status: done (2026-10-24), released in `v0.0.6`. QUIC's handshake is a mode of this
package's Goose server, and its packet protection is the shim's, which goose-http's
HTTP/3 (its task 067) serves with.

goose-http's task 067 serves HTTP/3, and QUIC carries TLS 1.3's handshake in CRYPTO
frames instead of records (RFC 9001). The Goose server here already runs that
handshake, so QUIC needs a mode of it, not another library
([decisions](../../docs/decisions.md#quic)); how it works is in
[architecture](../../docs/architecture.md#quic).

## What the mode changes

- Handshake bytes in and out per encryption level (Initial, Handshake, 1-RTT), not
  records: no record layer, no `change_cipher_spec`, no `EndOfEarlyData`. An alert
  becomes the QUIC error `0x100` plus its code.
- The `quic_transport_parameters` extension (`0x39`): the caller gives the server's as
  bytes for EncryptedExtensions and gets the client's back. A ClientHello without it,
  without ALPN, or with a legacy session ID (RFC 9001, section 8.4) is refused.
- Session tickets as over TCP, with no `early_data`: resumption, no 0-RTT.

## Keys and packet protection

- Initial keys from the client's Destination Connection ID and QUIC v1's salt; each
  level's keys derived with the labels `quic key`, `quic iv`, and `quic hp`, and key
  update with `quic ku`, keeping the old 1-RTT read keys until the program drops them.
- Seal and open with header protection in the shim, over libcrypto's AES-GCM and
  AES-ECB, and ChaCha20-Poly1305 with ChaCha20, in place, one packet a call. The
  proposal was a batch a call, so that goose-http crosses into C once a flush; a
  direct call costs little beside the AEAD, so the batch waits for a measurement that
  shows the crossing matters.
- goose-http counts the AEAD limits of RFC 9001 §6.6 and builds the nonce from the
  packet number, as `tlsg_quic_seal` takes it, 62 bits.
- Secrets stay in the shim's slots, as for TLS over TCP.

viltrum hands records to its own AES-NI code after mbedtls's handshake. That gain was
measured against mbedtls, whose GCM is a block at a time; libcrypto's is stitched, so
own AES code waits for a measurement that shows libcrypto is the cost.

Out of scope: Retry, which goose-http doesn't send, and with it Appendix A.4's Retry
tag.

## Measured

2026-10-24 on Tiamat: Ryzen 7 5800X3D, WSL2 Ubuntu 26.04, kernel
6.18.54.1-microsoft-standard-WSL2.

- A json-like request over TCP, task 007's measurement (spike 02, the Goose server,
  default groups, session tickets on, 200,000 requests over 1,000 connections, the
  server on CPU 2), `main` and this branch alternating over 5 rounds: 2.22 µs a request
  on `main` (2.21 to 2.23), 2.21 µs on this branch (2.19 to 2.23).
- goose-http's HTTP/1.1, h2c, and TLS paths, with this branch in the image: unchanged
  (goose-http's task 067, "Regressions").
- Packet protection under HTTP/3's load: Plod's HttpArena entry with goose-http's
  tuned HTTP/3 (its task 067, "Tuning"), 4 workers on CPUs 0-3, h2load-h3 with 64
  connections × 64 streams on CPUs 4-15, over loopback, its user instructions sampled
  with perf. On baseline-h3, libcrypto's AEAD and header protection take 4.1% and the
  shim's calls 0.2%; on static-h3, whose packets are full, 28% and 1.3%. The crossing
  into C a packet a call costs too little to batch, and AES-GCM is libcrypto's stitched
  code, so neither the batch nor own AES code is worth it yet.

## Acceptance criteria

- [x] RFC 9001 Appendix A's vectors: the client's Initial opened and its ClientHello
      answered at the Initial and Handshake levels, the server's Initial and the
      ChaCha20 short header sealed byte for byte, and a key update each way
      (`test/server/rfc9001.goose`, 2026-10-24)
- [x] QUIC handshakes against ngtcp2's client (h2load-h3) and aioquic's, through
      goose-http's task 067 (2026-10-24)
- [x] TLS over TCP unchanged: the tests and `scripts/test-handshake.sh` pass
      (2026-10-24, macOS)
- [x] Sealing measured at 1,200 bytes, a packet a call, under goose-http's h3 load: the
      share of a request it takes ("Measured", 2026-10-24)
- [x] A json-like request over TCP costs what it did before this task (task 007's
      measurement): the same within the rounds' spread ("Measured", 2026-10-24)
