# 008: QUIC's handshake and packet protection

Status: in-progress (asked for 2026-10-24). Built: QUIC's handshake is a mode of this
package's Goose server, and its packet protection is the shim's, which goose-http's
HTTP/3 (its task 066) serves with. What remains is measuring.

goose-http's task 066 serves HTTP/3, and QUIC carries TLS 1.3's handshake in CRYPTO
frames instead of records (RFC 9001). The Goose server here already runs that
handshake, so QUIC needs a mode of it, not another library
([decisions](../docs/decisions.md#quic)); how it works is in
[architecture](../docs/architecture.md#quic).

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

## Acceptance criteria

- [x] RFC 9001 Appendix A's vectors: the client's Initial opened and its ClientHello
      answered at the Initial and Handshake levels, the server's Initial and the
      ChaCha20 short header sealed byte for byte, and a key update each way
      (`test/server/rfc9001.goose`, 2026-10-24)
- [x] QUIC handshakes against ngtcp2's client (h2load-h3) and aioquic's, through
      goose-http's task 066 (2026-10-24)
- [x] TLS over TCP unchanged: the tests and `scripts/test-handshake.sh` pass
      (2026-10-24, macOS)
- [ ] Sealing measured at 1,200 bytes, a packet a call, under goose-http's h3 load: the
      share of a request it takes
- [ ] A json-like request over TCP costs what it did before this task (task 007's
      measurement)
