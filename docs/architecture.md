# Architecture

How goose-tls works, for programs that use it. Why it works this way is in
[decisions](decisions.md).

## The parts

- `tls.goose`, the `tls` namespace: the API. It builds the ALPN list's wire format,
  reads PEM files, and turns the shim's results into Goose values.
- `shim/tls.c`: OpenSSL's API as handles, bytes, and status codes, and nothing else. It
  never touches a socket, and keeps no pointer into Goose memory after a call returns.
- OpenSSL, 3.0 or later: the handshake, the record layer, the ciphers, and X.509.

## Contexts and connections

A `tls::Context` is a server configuration: OpenSSL's `SSL_CTX`, with the certificate
chain and key, TLS 1.3 only, its three suites in the server's order, and the ALPN
protocols. `tls::server` makes one from PEM text, and `tls::server_files` from PEM
files.

A `tls::Conn` is one connection's state: an `SSL` between two memory BIOs, one for the
bytes received and one for the bytes to send. `tls::accept(ctx)` makes one per
accepted socket.

Both are flat structs holding a handle, the object's address, so they cross queues and
`thread_spawn`. A context serves connections on any number of threads at once; a
connection is used by one thread at a time. Each is freed by `tls::free`, once. A
handle used after it's freed is undefined behavior in the C, as in OpenSSL itself:
nothing checks it.

A connection holds its own reference to its context. Freeing a context, or replacing it
with a new one for the connections accepted from then on, leaves open connections as
they were. That is how a certificate is replaced while a server runs: make a new
context, accept from it, and free the old one.

## The byte flow

The program owns the socket and its event loop: epoll, io_uring, kqueue, or IOCP alike.
A connection only transforms bytes:

```
socket ──recv──▶ tls::feed ──▶ [received BIO] ──▶ OpenSSL ──▶ tls::read ──▶ plaintext
socket ◀──send── tls::drain ◀── [to-send BIO] ◀── OpenSSL ◀── tls::write ◀── plaintext
```

For each chunk the socket gives:

1. `tls::feed(c, bytes)` takes all of it.
2. Until the handshake is done, `tls::handshake(c)` advances it, or `tls::read` does it
   implicitly. It returns 0 when done, `tls::WANT_INPUT` while it waits on the client,
   and `tls::FAILED` when the client can't be served, such as one offering only
   TLS 1.2.
3. `tls::read(c, buf)` returns the plaintext's length, more than 0, until it returns
   `tls::WANT_INPUT`. It returns `tls::CLOSED` once the client sent close_notify.
4. `tls::write(c, data)` encrypts all of the response.
5. `tls::drain(c, buf)` copies the bytes waiting to be sent into `buf`, until it
   returns 0; `tls::pending(c)` says how many wait. Drain after every step that can
   produce output: the handshake's flights, records, session tickets, and alerts.

To close, `tls::shutdown(c)` queues close_notify, which the program drains and sends
before closing the socket. After `tls::FAILED`, drain too, since an alert may be waiting,
then close; `tls::error_text()` says what failed, in OpenSSL's words.

The to-send BIO grows as the program writes, so the program sets its own limits: it
drains as fast as the socket takes the bytes, and stops reading requests while the
socket is backed up.

## ALPN

The context holds the server's protocols in its order of preference. When a client
offers some, the server picks the first of its own that the client offered; when none
match, or the client offers no ALPN, the server answers without ALPN, and never with a
protocol the client didn't offer. `tls::alpn(c)` gives the choice after the handshake,
or "" for none.

## Planned

What the API leaves room for, and isn't built yet:

- **A context per connection, chosen from the ClientHello** (task 003). A context will
  be able to ask that the handshake pause after the ClientHello (OpenSSL's client hello
  callback). `tls::handshake` then returns a further status; the program reads the SNI
  name and the offered ALPN list from the connection, sets the context the connection
  uses, and calls `tls::handshake` again. SNI with a certificate per name, and ACME's
  TLS-ALPN-01, which answers `acme-tls/1` for one name with a challenge certificate, both
  work this way. The choice is the program's, in Goose, rather than a callback's in C.
- **Client TLS** (task 003): a client context that verifies the server's chain and
  name, and the same connection calls.
- **Keys and certificates for ACME** (task 003): an EC P-256 key, ES256 signatures for
  JWS, a CSR, and a self-signed certificate with RFC 8737's `acmeIdentifier` extension,
  for an ACME package that uses goose-tls's API alone.
- **kTLS on Linux** (task 002). OpenSSL turns kTLS on only when its BIO is a socket, so
  over the memory BIOs it never does. The shim will need either the socket's descriptor
  after the handshake, or to hand the kernel the traffic keys itself; task 002 decides
  which, and how that fits the rule that the package does no I/O.
