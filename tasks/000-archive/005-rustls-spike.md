# 005: rustls against OpenSSL

Status: done (2026-10-20)

Would rustls serve TLS 1.3 at the same or better CPU cost, and with less memory per
connection, than OpenSSL 3.5 as this package uses it? Asked 2026-10-20, after
goose-http's json-tls run used 272 MiB at 4,096 connections against 152-188 MiB for the
Rust entries (goose-http's task 058). The method, the numbers, and the API mapping are in
[spike 01](../../spikes/01-rustls/README.md).

rustls clears the bar in every measurement on the desktop (rustls 0.23.46 on
aws-lc-rs, against OpenSSL 3.5.5, both negotiating X25519MLKEM768):

- An idle connection holds 7.8 KB against 28.5 KB.
- A handshake in flight holds 8.3 KB against 58.6 KB.
- A full handshake takes 15% less server CPU.
- A json-tls-like request takes 26% less.

rustls-ffi can't configure the key-exchange groups, kTLS, or stateless tickets, so a
switch would go through a small Rust library of our own over rustls.

## Acceptance criteria

- [x] Memory per server connection, idle and with a handshake in flight, at 1,000 and
      4,000 connections, for OpenSSL and rustls, with and without ML-KEM
- [x] Handshake, 16 KB record, and json-like CPU on one core, 5 interleaved runs each,
      with their spread
- [x] Whether HttpArena's Rust entries negotiate X25519: they do, since rustls's ring
      provider has no ML-KEM group
- [x] A verdict against the bar, and what a switch would take
