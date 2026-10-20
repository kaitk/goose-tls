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
- `shim/crypto.c`: the keys, signatures, and certificates an ACME client needs.
- OpenSSL, 3.0 or later: the handshake, the record layer, the ciphers, X.509, and
  ECDSA.

## Contexts and connections

A `tls::Context` is a server's or a client's configuration: OpenSSL's `SSL_CTX`, with
TLS 1.3 only and its three suites, and the ALPN protocols. A server's holds its
certificate chain and key, and chooses the suite in its own order; `tls::server` makes
one from PEM text, and `tls::server_files` from PEM files. A client's holds the
certificates it trusts ([Client TLS](#client-tls)).

A `tls::Conn` is one connection's state: an `SSL` between two memory BIOs, one for the
bytes received and one for the bytes to send. `tls::accept(ctx)` makes a server
connection per accepted socket, and `tls::connect(ctx, host)` a client one per
connected socket.

Both are flat structs holding a handle, the object's address, so they cross queues and
`thread_spawn`. A context serves connections on any number of threads at once; a
connection is used by one thread at a time. Each is freed by `tls::free`, once. A
handle used after it's freed is undefined behavior in the C, as in OpenSSL itself:
nothing checks it. `tls::share(ctx)` gives another reference to the same context, for
a thread that frees its own: the context is freed with the last reference.

A connection holds its own reference to its context. Freeing a context, or replacing it
with a new one for the connections accepted from then on, leaves open connections as
they were. That is how a certificate is replaced while a server runs: make a new
context, accept from it, and free the old one. `test/context/replace.goose` shows it:
a connection from the old context keeps its certificate and goes on after the old
context is freed, and the next connection gets the new one.

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
   TLS 1.2. On a context that chooses per connection, it also returns `tls::HELLO`
   ([A context per connection](#a-context-per-connection)).
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
socket is backed up. Each BIO frees its buffer once it's emptied, as OpenSSL does its
record buffers, so between records a connection holds only OpenSSL's state
([decisions](decisions.md)).

## ALPN

The context holds the server's protocols in its order of preference. When a client
offers some, the server picks the first of its own that the client offered; when none
match, or the client offers no ALPN, the server answers without ALPN, and never with a
protocol the client didn't offer. `tls::alpn(c)` gives the choice after the handshake,
or "" for none.

## A context per connection

A server can pick each connection's context from its ClientHello: a certificate per
SNI name, or, for ACME's TLS-ALPN-01 (RFC 8737), a challenge certificate for a client
that sends the challenged name and offers `acme-tls/1`. The choice is the program's, in
Goose:

1. `tls::choose_context(ctx)` makes every handshake of the connections `ctx` accepts
   from then on pause after the ClientHello. Call it before `ctx` accepts its first
   connection.
2. `tls::handshake(c)`, or `tls::read`, returns `tls::HELLO` once the ClientHello is in.
   Nothing waits to be drained yet.
3. `tls::server_name(c)` gives the SNI name, or "" for none, and `tls::offers(c,
   protocol)` whether the client offered a protocol in ALPN (`tls::protocols_offered(c)`
   gives the whole list, in its wire format).
4. `tls::use_context(c, other)` moves the connection to another server context, whose
   certificate, key, and ALPN protocols it answers with; not calling it keeps the
   context the connection was accepted from. The connection holds its own reference to
   the context it moves to.
5. `tls::handshake(c)` goes on, as after any other status.

For TLS-ALPN-01, the challenge context holds the certificate from
`tls::challenge_certificate` and its key, with `acme-tls/1` as its only ALPN protocol;
the server moves a connection to it when `tls::server_name(c)` is the challenged name
and `tls::offers(c, "acme-tls/1")`, and every other connection keeps the real
certificate. `scripts/test-handshake.sh` checks such a server with `openssl s_client
-servername` and `-alpn acme-tls/1`. A verifying client refuses the challenge
certificate, since it knows no `acmeIdentifier` extension and the extension is
critical; the ACME server checks it itself.

A connection takes its protocol versions and suites from the context it was accepted
from, which every context sets alike. For kTLS, call `tls::use_kernel` on the contexts
a connection can move to as well as on the one it was accepted from: the kernel's keys
come from the context the handshake finishes on.

## Client TLS

A client context verifies the server: the chain must lead to a certificate it trusts,
and the leaf must name the host given to `tls::connect`, a DNS name, which also goes in
SNI, or an IP address. `tls::client(protocols)` trusts the system's certificate
authorities, through OpenSSL's default store: the `cert.pem` and `certs/` under its
`OPENSSLDIR` (`openssl version -d` prints it), or `SSL_CERT_FILE` and `SSL_CERT_DIR`.
Debian and Ubuntu fill it from the `ca-certificates` package, and Homebrew's OpenSSL
from its `ca-certificates` formula. `tls::client_trusting(ca, protocols)` trusts only
the certificates in `ca`, PEM text: a private CA, or a server's own self-signed
certificate.

A client connection uses the same calls as a server's, except that the client speaks
first: after `tls::connect`, call `tls::handshake` and drain the ClientHello before
feeding anything. A server that fails verification fails the handshake with
`tls::FAILED`, and `tls::error_text()` ends with the reason, such as `certificate
verify failed:self-signed certificate` or `hostname mismatch`.
`tls::peer_certificate(c)` gives the server's certificate as PEM.

## Keys and certificates

An ACME client needs keys, signatures, and certificates, and gets them here so that it
needs no C of its own:

- `tls::Key`, an EC P-256 private key: `tls::key_generate(tls::P256)`, or
  `tls::key_from_pem(pem)` from PKCS#8 or SEC 1 PEM, which refuses any other kind of
  key. `tls::key_pem(k)` writes it as unencrypted PKCS#8 PEM, which `tls::server`
  takes, and `tls::public_xy(k)` gives its point, x then y, 32 bytes each: a JWK's
  `x` and `y` before base64url. Freed by `tls::free`, once.
- `tls::sign_es256(k, data)`: an ES256 signature for JWS, the 64 bytes `r || s`, not
  the DER OpenSSL gives.
- `tls::csr(k, names)`: a certificate signing request for DNS names, as DER, signed
  with SHA-256. Its subject is the first name, when it fits a common name's 64
  characters, and every name is in subjectAltName.
- `tls::self_signed(k, names, days)`: a self-signed certificate as PEM, valid from an
  hour ago, for a server to start with.
- `tls::challenge_certificate(k, name, digest)`: TLS-ALPN-01's certificate,
  self-signed as PEM, for one name, with the critical `acmeIdentifier` extension
  (`1.3.6.1.5.5.7.1.31`) holding `digest`, the 32-byte SHA-256 of the key
  authorization, valid for 7 days.

Hashes aren't here: the ACME package takes SHA-256, for the key authorization's digest
and a JWK thumbprint, from [goose-hash](https://github.com/kaitk/goose-hash).

A call that fails leaves through `return ... from tls::run`, as goose-sqlite's calls
leave `sqlite::run`, so the calls run inside `tls::run`, or the program doesn't
compile:

```goose
var csr: u8[>..] = [];
let failed = tls::run() {
    let k = tls::key_generate(tls::P256);
    csr = tls::csr(k, ["example.com"]);
    tls::free(k);
};
for e in failed { print(e.message); }   // a tls::Error: the call, and OpenSSL's reasons
```

`tls::run` returns an empty array when its block returned, or the `tls::Error` that
ended it: the call's name and why, then OpenSSL's reasons, as `tls::error_text()` gives
them. The innermost `tls::run` catches. Each call that can fail takes an untyped
parameter, the key or the curve, so it is compiled only where a program calls it
([findings](goose-findings.md)). `tls::ok`, `tls::free`, and the connection calls never
leave this way. `scripts/test-crypto.sh` checks each call against `openssl`.

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
