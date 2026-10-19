# Architecture

How goose-tls works, for programs that use it. Why it works this way is in
[decisions](decisions.md).

## The parts

- `tls.goose`, the `tls` namespace: the API. It builds the ALPN list's wire format,
  reads PEM files, and turns the shim's results into Goose values.
- `shim/tls.c`: OpenSSL's API as handles, bytes, and status codes, and nothing else. It
  never touches a socket, and keeps no pointer into Goose memory after a call returns.
- `shim/ktls.c`: kTLS on Linux. It derives the kernel's keys and sets them on a socket
  the program gives it, with `setsockopt`, and never reads or writes that socket.
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

## kTLS on Linux

After the handshake, a connection can move its record layer into the kernel: the
kernel then encrypts what the program sends and decrypts what it receives, so the
program's loop sends and receives plaintext on the socket, and `sendfile` and splice
work on it. goose-tls derives the keys and installs them with `setsockopt` on the
descriptor the program gives it; it never reads or writes the socket. The handshake
still runs in user space, through `tls::feed` and `tls::drain`.

The kernel needs the `tls` module (`CONFIG_TLS`): TLS 1.3 from Linux 5.1, with
`TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384`, and
`TLS_CHACHA20_POLY1305_SHA256` from 5.11. Changing keys after a KeyUpdate needs Linux
6.14. On every other platform, and on a kernel without the module, nothing moves and the
connection stays in user space.

### Moving a connection

1. `tls::kernel_supported()` says whether this kernel has kTLS. `tls::use_kernel(ctx)`
   makes the connections a context accepts from then on ready to move, and returns
   false, changing nothing, where the kernel has none. Call it before the context
   accepts its first connection.
2. After the handshake, read until `tls::WANT_INPUT`, drain everything, and send it.
   Data that arrived with the client's Finished and the session tickets the server
   sends are handled this way, before the switch.
3. `tls::to_kernel(c, fd)` moves the connection. It returns the directions the kernel
   took, as bits: `tls::KERNEL_RX | tls::KERNEL_TX`, `tls::KERNEL_RX` alone when the
   kernel refused sending, or 0 when it took nothing and the connection stays in user
   space (`tls::error_text()` says why). Or it returns a status, and the program calls
   it again after acting on it:
   - `tls::WANT_INPUT`: the bytes fed end inside a record, so the kernel can't start
     from the socket's next byte. Read exactly `tls::kernel_wants(c)` more bytes, feed
     them, and read the plaintext.
   - `tls::PENDING`: plaintext waits for `tls::read`, or bytes for `tls::drain`.
   - `tls::FAILED`: the handshake isn't done.
4. Bytes drained before the switch must be on the socket before the program sends
   through the kernel. `tls::in_kernel(c)` reports the directions later. Once the kernel
   holds receiving, `tls::feed` and `tls::read` fail; once it holds sending,
   `tls::write` and `tls::shutdown` fail.

Receiving moves first. With receiving in the kernel and sending in user space, the
program receives plaintext from the socket and still sends through `tls::write` and
`tls::drain`.

### Records that aren't data

The kernel decrypts every record, but passes only data through `recv`. An alert, or a
handshake message (after the handshake, only a KeyUpdate), comes as a record of its
own, whose type `recvmsg` gives in a `TLS_GET_RECORD_TYPE` control message (level
`SOL_TLS`). A plain `recv`, which has no room for the control message, fails with `EIO`
when such a record is next; the program then reads it with `recvmsg`. The program
passes each one to `tls::kernel_record(c, fd, type, body)`, which returns:

- 0: go on receiving. For a KeyUpdate, the kernel stops decrypting at it and fails
  `recv` with `EKEYEXPIRED` until it has the next keys, which `tls::kernel_record` has
  just installed. Readiness isn't reported while it waits, so receive again without
  waiting for the socket to become readable. With sending in user space, the answer
  to a KeyUpdate that asked for one is queued for `tls::drain`.
- `tls::UPDATE_TX`: the peer asked for a KeyUpdate in return. Once everything sent
  before is on the socket, send `tls::KEY_UPDATE` as a `tls::RECORD_HANDSHAKE` record
  (`sendmsg` with a `TLS_SET_RECORD_TYPE` control message), then call
  `tls::kernel_update_tx(c, fd)` before sending anything else.
- `tls::CLOSED`: the peer sent close_notify.
- `tls::FAILED`: any other alert, any other message, or a kernel before 6.14, which
  can't change keys (`EBUSY`). Close the connection.

To close a connection whose sending the kernel holds, send `tls::CLOSE_NOTIFY` as a
`tls::RECORD_ALERT` record. The same KeyUpdate record and `tls::kernel_update_tx` change
the server's own sending keys, for a connection that runs long enough to need it.

### In an event loop

With epoll, a connection's reads become `recv` on the socket; on `EIO`, one
`recvmsg` with a control buffer of `CMSG_SPACE(1)` bytes fetches the record.

With io_uring, `IORING_OP_SEND`, `IORING_OP_RECV`, multishot receive into provided
buffers, and splice all work on a kTLS socket as on a plain one, and carry plaintext.
A record that isn't data ends a `RECV` with `-EIO`, which also ends a multishot
receive; the loop fetches the record with `IORING_OP_RECVMSG` or a nonblocking
`recvmsg` call, calls `tls::kernel_record`, and arms its receive again. A receive that
was already queued can complete with `-EKEYEXPIRED` after a KeyUpdate; arm it again
after `tls::kernel_record`. The loop sends control records with `IORING_OP_SENDMSG`,
or `sendmsg`, after its earlier sends on that socket complete, and calls
`tls::kernel_update_tx` before it queues the next send. `IORING_OP_SEND_ZC` doesn't
work on a kTLS socket: setting a ULP clears the socket's zero-copy support
(`SOCK_SUPPORT_ZC`, in `net/ipv4/tcp_ulp.c`), and io_uring refuses with `EOPNOTSUPP`.

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
