# 002: kTLS on Linux

Status: todo (after task 001)

After the handshake, OpenSSL 3 can hand the record layer to the kernel
(`SSL_OP_ENABLE_KTLS`, for the ciphers the kernel supports; TLS 1.3 receive from OpenSSL
3.2). The program then sends and receives plaintext on the socket, and `sendfile` and
io_uring work again. HttpArena's 8gbit profile scores CPU per request at a pinned rate,
so the record layer's cost counts there directly.

Task 001's connections run over memory BIOs, and OpenSSL turns kTLS on only when its BIO
is a socket (`BIO_get_ktls_send`), so `SSL_OP_ENABLE_KTLS` alone does nothing there.
Either the shim takes the socket's descriptor after the handshake and installs the
traffic keys with `setsockopt(TLS_TX, TLS_RX)` itself, or a kTLS connection runs over a
socket BIO from its start, since OpenSSL turns kTLS on as it changes keys. Either one has the shim touch a socket, which
the decision "no I/O in the package" rules out today; this task revisits it in
`docs/decisions.md` (found 2026-10-19).

KeyUpdate messages and alerts still reach user space (`EKEYEXPIRED`, and control
messages through `recvmsg`); goose-http's loop must hand those back to goose-tls.

## Acceptance criteria

- [ ] goose-tls reports, per connection, whether the kernel took each direction
- [ ] goose-http serves HTTP/1.1 over kTLS on epoll and io_uring
- [ ] User-space TLS and kTLS compared on Linux, with how they were measured
- [ ] `scripts/test.sh` passes, with a test that a KeyUpdate doesn't break a kTLS
      connection
