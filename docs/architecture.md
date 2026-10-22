# Architecture

How goose-tls works, for programs that use it. Why it works this way is in
[decisions](decisions.md).

Since `v0.0.4` (task 007), server connections run a TLS 1.3 server written in this package, in Goose over libcrypto, and
client connections run OpenSSL's libssl. A package built with `GOOSE_TLS_SERVER=openssl`
serves with libssl instead, through the same API ([development](development.md)).
kTLS is retired ([decisions](decisions.md)): every connection's record layer runs in
user space.

## The parts

- `tls.goose`, the `tls` namespace: the API. It builds the ALPN list's wire format,
  reads PEM files, turns the shims' results into Goose values, and sends each call to
  the server or library that owns the handle.
- `server.goose`, `hello.goose`, and `wire.goose`: the server's protocol. They parse
  the ClientHello, negotiate, run the handshake's state machine and key schedule,
  frame and check records, and issue and accept session tickets. Every protocol
  decision is here.
- `shim/server.c`: what the Goose server needs from C. It owns the memory that outlives
  a call, such as contexts, connections, and their byte queues, and calls libcrypto for
  each primitive: AEAD, hashes, HKDF, key exchange, signatures, and random bytes.
  Secrets stay in C, in slots the Goose code names, and are cleansed when replaced or
  freed.
- `shim/tls.c`: libssl's API as handles, bytes, and status codes, for clients and for
  the libssl server.
- `shim/crypto.c`: the keys, signatures, and certificates an ACME client needs.
- OpenSSL, 3.0 or later: libcrypto's primitives, PEM, and X.509 for the server, and
  libssl for clients. X25519MLKEM768 needs 3.5 or later.

No shim touches a socket, and none keeps a pointer into Goose memory after a call
returns.

## Contexts and connections

A `tls::Context` is a server's or a client's configuration: TLS 1.3 only with its three
suites, the key exchange groups, and the ALPN protocols. A server's holds its
certificate chain and key, chooses the suite in its own order, and keeps its session
tickets' keys ([Session tickets](#session-tickets)). `tls::server` makes one from PEM
text, and `tls::server_files` from PEM files. The Goose server takes an EC P-256 key,
signing with `ecdsa_secp256r1_sha256`, or an RSA key of 2048 bits or more, signing
with `rsa_pss_rsae_sha256`, and refuses any other. Its default groups are
X25519MLKEM768 where libcrypto has ML-KEM, X25519, and P-256; `tls::use_groups` sets
others, P-384 among them. A client's context is libssl's `SSL_CTX`, holding the
certificates it trusts ([Client TLS](#client-tls)).

A `tls::Conn` is one connection's state. A server connection holds three byte queues
(bytes received, plaintext not yet read, and bytes to send), each direction's record
keys, and during the handshake its transcript and secrets: about 2.9 KB once idle
(task 007). A client connection is an `SSL` between two memory BIOs.
`tls::accept(ctx)` makes a server connection per accepted socket, and
`tls::connect(ctx, host)` a client one per connected socket.

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
socket ──recv──▶ tls::feed ──▶ [received] ──▶ TLS ──▶ tls::read ──▶ plaintext
socket ◀──send── tls::drain ◀── [to send] ◀── TLS ◀── tls::write ◀── plaintext
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
then close; `tls::error_text()` says what failed, in OpenSSL's words: the Goose server
raises libssl's reasons, so both servers' failures read alike.

The bytes to send grow as the program writes, so the program sets its own limits: it
drains as fast as the socket takes the bytes, and stops reading requests while the
socket is backed up. Each queue frees its buffer once it's emptied, so between records
a connection holds only its keys and protocol state ([decisions](decisions.md)). The
Goose server takes at most 256 KiB fed and not yet read; `tls::feed` refuses more.

## ALPN

The context holds the server's protocols in its order of preference. When a client
offers some, the server picks the first of its own that the client offered. When none
match, the handshake fails with `no_application_protocol`, as RFC 7301, section 3.2,
requires; a client that offers no ALPN connects without it. The server never answers
with a protocol the client didn't offer. `tls::alpn(c)` gives the choice after the
handshake, or "" for none.

## Session tickets

A server sends session tickets after the handshake: two after a full handshake and
one after a resumption, each valid for 7,200 seconds. A client that offers one back
with `psk_dhe_ke` resumes: the handshake skips the certificate and its signature, and
still runs a fresh key exchange. A ticket that doesn't open, or has expired, gets a
full handshake. Tickets carry no early data. The program drains them like any other
output; nothing else changes for it.

Tickets are stateless: the server stores nothing per ticket, and a ticket is the
resumption secret sealed under one of the context's ticket keys, with the suite, its
issue time, and the SNI name. A context keeps two keys. The current one issues tickets
for 7,200 seconds, then the next ticket issued makes a new key current, and the old
one opens tickets until 14,400 seconds after it was made. There is no timer: a new key
is made when a ticket is issued, and an expired key is dropped when a ticket is issued
or opened, or the context is freed, its bytes cleansed. They count time on a monotonic clock, so a change of the system's clock moves
no ticket's lifetime.

The keys live in the process: a restarted server, or a second process, can't open
another's tickets, and their clients get a full handshake. Shares of a context
(`tls::share`) share its keys, so every worker opens every worker's tickets. A ticket
opens only under the context that serves the connection: after `tls::use_context`,
that is the context moved to. The libssl server follows the same key lifetimes,
through libssl's ticket-key callback, in libssl's own ticket format; its tickets'
7,200 seconds count on the system's clock.

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
from, which every context sets alike.

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
