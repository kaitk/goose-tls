// TLS for a server and a client, over OpenSSL (shim/tls.c), and the keys and
// certificates an ACME client needs (shim/crypto.c). The package does no I/O:
// the program reads from its socket and feeds the bytes to a connection, and
// sends what it drains from it. The byte flow and its states are in
// docs/architecture.md. On Linux, a connection can move to the kernel after its
// handshake (to_kernel), which only sets the socket's options.
//
//   let ctx, ok = tls::server_files("server.crt", "server.key", ["http/1.1"]);
//   let c = tls::accept(ctx);                 // for each accepted socket
//   tls::feed(c, received);                   // bytes the socket gave
//   let n = tls::read(c, plain);              // plaintext, or a status
//   tls::write(c, response);
//   let m = tls::drain(c, out);               // bytes for the socket
//
// A Context, a Conn, and a Key are handles to OpenSSL's objects: flat, so they
// cross queues and thread_spawn, and freed only by tls::free. Free each once
// and don't use it after: the handle is the object's address. A Context is
// safe to use from several threads at once, and share gives each thread a
// reference of its own to free; a Conn or a Key is used from one thread at a
// time.
namespace tls;

import std;
import os;

// A server's or a client's configuration: for a server, the certificate chain
// and key; for a client, the certificates it trusts; and the protocol
// versions and suites, and the ALPN protocols. Connections take a reference
// to it, so freeing it, or replacing it with a new one for new connections,
// leaves open connections as they are.
struct Context { id: i64 = 0 }

// One TLS connection's state, over the bytes of one socket.
struct Conn { id: i64 = 0 }

// An EC P-256 private key, for ACME: an account key that signs JWS, or a
// certificate's key.
struct Key { id: i64 = 0 }

// What read, write, handshake, and feed return in place of a count.
//
// WANT_INPUT: the connection needs more bytes from the peer. Send what drain
// gives, feed what the socket gives next, and call again.
let WANT_INPUT = -1;
// CLOSED: the peer sent close_notify. Drain, then close the socket.
let CLOSED = -2;
// FAILED: a protocol error, or the peer broke off. Drain (an alert may be
// waiting), close the socket, and free the connection; error_text says why.
let FAILED = -3;
// PENDING, from to_kernel: plaintext waits for read, or bytes for drain.
// Read until WANT_INPUT, drain and send everything, and call again.
let PENDING = -4;
// UPDATE_TX, from kernel_record: the peer asked for a KeyUpdate. Once what
// was sent before is on the socket, send KEY_UPDATE in a RECORD_HANDSHAKE
// record through the kernel, call kernel_update_tx, then send on.
let UPDATE_TX = -5;
// HELLO, from handshake or read on a connection whose context was given to
// choose_context: the ClientHello came, and the handshake waits for the
// program. Read server_name and offers, call use_context to move the
// connection to another context, or don't, to keep this one, and call
// handshake again.
let HELLO = -6;

// The directions to_kernel and in_kernel report, as bits.
let KERNEL_RX = 1;
let KERNEL_TX = 2;

// The record types a kTLS socket gives and takes besides data, in recvmsg's
// TLS_GET_RECORD_TYPE and sendmsg's TLS_SET_RECORD_TYPE control messages.
let RECORD_ALERT = 21;
let RECORD_HANDSHAKE = 22;
// What the program sends in a RECORD_ALERT record to close a connection
// whose sending the kernel holds.
let CLOSE_NOTIFY = "\x01\x00";
// What it sends in a RECORD_HANDSHAKE record for UPDATE_TX, or to change its
// own sending keys: a KeyUpdate that asks the peer for none in return.
let KEY_UPDATE = "\x18\x00\x00\x01\x00";

extern "tls_server_new" fn server_new_c(chain: const u8[:], key: const u8[:], alpn: const u8[:]) -> i64;
extern "tls_context_free" fn context_free_c(id: i64);
extern "tls_accept" fn accept_c(ctx: i64) -> i64;
extern "tls_conn_free" fn conn_free_c(id: i64);
extern "tls_feed" fn feed_c(id: i64, data: const u8[:]) -> i64;
extern "tls_pending" fn pending_c(id: i64) -> i64;
extern "tls_drain" fn drain_c(id: i64, buf: u8[:]) -> i64;
extern "tls_handshake" fn handshake_c(id: i64) -> i64;
extern "tls_read" fn read_c(id: i64, buf: u8[:]) -> i64;
extern "tls_write" fn write_c(id: i64, data: const u8[:]) -> i64;
extern "tls_shutdown" fn shutdown_c(id: i64) -> i64;
extern "tls_alpn_selected" fn alpn_c(id: i64, out: u8[>..]&);
extern "tls_version" fn version_c(id: i64, out: u8[>..]&);
extern "tls_cipher" fn cipher_c(id: i64, out: u8[>..]&);
extern "tls_error_text" fn error_text_c(out: u8[>..]&);
extern "tls_library" fn library_c(out: u8[>..]&);
extern "tls_kernel_supported" fn kernel_supported_c() -> bool;
extern "tls_kernel_enable" fn kernel_enable_c(ctx: i64, anywhere: bool) -> bool;
extern "tls_kernel_start" fn kernel_start_c(id: i64, fd: i64) -> i64;
extern "tls_kernel_wants" fn kernel_wants_c(id: i64) -> i64;
extern "tls_kernel_owned" fn kernel_owned_c(id: i64) -> i64;
extern "tls_kernel_record" fn kernel_record_c(id: i64, fd: i64, kind: i64, body: const u8[:]) -> i64;
extern "tls_kernel_update_tx" fn kernel_update_tx_c(id: i64, fd: i64) -> i64;
extern "tls_client_new" fn client_new_c(ca: const u8[:], system: bool, alpn: const u8[:]) -> i64;
extern "tls_context_share" fn share_c(ctx: i64) -> i64;
extern "tls_connect" fn connect_c(ctx: i64, host: const u8[:]) -> i64;
extern "tls_choose_enable" fn choose_enable_c(ctx: i64) -> bool;
extern "tls_use_context" fn use_context_c(id: i64, ctx: i64) -> bool;
extern "tls_server_name" fn server_name_c(id: i64, out: u8[>..]&);
extern "tls_offered" fn offered_c(id: i64, out: u8[>..]&);
extern "tls_peer_certificate" fn peer_certificate_c(id: i64, out: u8[>..]&);
extern "tls_key_generate" fn key_generate_c() -> i64;
extern "tls_key_from_pem" fn key_from_pem_c(pem: const u8[:]) -> i64;
extern "tls_key_free" fn key_free_c(id: i64);
extern "tls_key_pem" fn key_pem_c(id: i64, out: u8[>..]&) -> bool;
extern "tls_key_public" fn key_public_c(id: i64, out: u8[>..]&) -> bool;
extern "tls_sign_es256" fn sign_es256_c(id: i64, data: const u8[:], out: u8[>..]&) -> bool;
extern "tls_sha256" fn sha256_c(data: const u8[:], out: u8[>..]&);
extern "tls_csr" fn csr_c(id: i64, names: const u8[:], out: u8[>..]&) -> bool;
extern "tls_self_signed" fn self_signed_c(id: i64, names: const u8[:], days: i64, acme: const u8[:], out: u8[>..]&) -> bool;

// Appends each of items to out as a length byte and the item, the wire format
// of an ALPN list: false when one is empty or longer than max bytes.
fn wire(items: const u8[:][:], max: i64, out: u8[>..]&) -> bool {
    for p in items {
        guard p.len > 0 && p.len <= max else { return false; }
        out.push(p.len as u8);
        out.append(p);
    }
    return true;
}

// A server context from PEM text: chain holds the leaf certificate, then any
// intermediates; key the leaf's private key. protocols are the ALPN names the
// server speaks, in its order of preference; a client that offers none of
// them gets no ALPN answer, and one that offers no ALPN still connects.
// TLS 1.3 only, with TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, and
// TLS_CHACHA20_POLY1305_SHA256, chosen in that order. False when the PEM
// doesn't parse, the key doesn't match the leaf, or a protocol name is empty
// or longer than 255 bytes; error_text says which.
fn server(chain: const u8[:], key: const u8[:], protocols: const u8[:][:]) -> Context, bool {
    var alpn: u8[>..] = [];
    guard wire(protocols, 255, alpn) else { return Context { .. }, false; }
    let id = server_new_c(chain, key, alpn);
    return Context { id: id }, id != 0;
}

// A client context that trusts the system's certificate authorities:
// OpenSSL's default store, which SSL_CERT_FILE and SSL_CERT_DIR override
// (docs/architecture.md, "Client TLS"). protocols are the ALPN names it
// offers, in its order of preference. TLS 1.3 only, with the same suites as
// a server. False when a protocol name is empty or longer than 255 bytes.
fn client(protocols: const u8[:][:]) -> Context, bool {
    var alpn: u8[>..] = [];
    guard wire(protocols, 255, alpn) else { return Context { .. }, false; }
    let id = client_new_c("", true, alpn);
    return Context { id: id }, id != 0;
}

// client, trusting only the certificates in ca, PEM text: a CA bundle, or a
// server's own self-signed certificate. False also when ca holds none.
fn client_trusting(ca: const u8[:], protocols: const u8[:][:]) -> Context, bool {
    var alpn: u8[>..] = [];
    guard wire(protocols, 255, alpn) else { return Context { .. }, false; }
    let id = client_new_c(ca, false, alpn);
    return Context { id: id }, id != 0;
}

// Another reference to ctx, the same context, which its holder frees with
// free(ctx) on its own: for each thread that keeps the context, so that
// whichever frees last frees it. Atomic, so any thread can share or free while
// others accept from it. Not ok when ctx isn't.
fn share(ctx: Context) -> Context { Context { id: share_c(ctx.id) } }

// server, with the chain and key read from PEM files. False also when a file
// can't be read.
fn server_files(chain_path: const u8[:], key_path: const u8[:], protocols: const u8[:][:]) -> Context, bool {
    var chain: u8[>..] = [];
    guard read_file(chain_path, chain) else { return Context { .. }, false; }
    var key: u8[>..] = [];
    guard read_file(key_path, key) else { return Context { .. }, false; }
    return server(chain, key, protocols);
}

// A new server connection, before its handshake; check ok(c).
fn accept(ctx: Context) -> Conn { Conn { id: accept_c(ctx.id) } }

// A new client connection from a client context to host, a DNS name or an IP
// address, before its handshake; check ok(c). The server's certificate must
// name host, and a DNS name is sent in SNI. The client speaks first: call
// handshake and drain before feeding anything.
fn connect(ctx: Context, host: const u8[:]) -> Conn { Conn { id: connect_c(ctx.id, host) } }

fn ok(ctx: Context) -> bool { ctx.id != 0 }
fn ok(c: Conn) -> bool { c.id != 0 }

fn free(ctx: Context) { context_free_c(ctx.id); }
fn free(c: Conn) { conn_free_c(c.id); }

// A context chosen per connection (docs/architecture.md, "A context per
// connection").

// Makes each handshake of the connections ctx accepts from now on pause after
// the ClientHello, where handshake and read return HELLO. Call it before ctx
// accepts its first connection. False when ctx isn't.
fn choose_context(ctx: Context) -> bool { choose_enable_c(ctx.id) }

// Moves a connection paused at HELLO to ctx, another server context, whose
// certificate, key, and ALPN protocols it then answers with; the next
// handshake call goes on from there. The connection holds its own reference
// to ctx. False when the connection isn't paused at HELLO.
fn use_context(c: Conn, ctx: Context) -> bool { use_context_c(c.id, ctx.id) }

// The host name the client sent in SNI, or "" for none.
fn server_name(c: Conn) -> u8[>..] {
    var s: u8[>..] = [];
    server_name_c(c.id, s);
    return s;
}

// The ALPN protocols the client offered, in its wire format: each a length
// byte and the name, in the client's order. Empty when it offered none, or
// when the connection's context isn't one choose_context was given.
fn offered(c: Conn) -> u8[>..] {
    var s: u8[>..] = [];
    offered_c(c.id, s);
    return s;
}

// Whether the client offered protocol in ALPN, as offered gives the list.
fn offers(c: Conn, protocol: const u8[:]) -> bool {
    let list = offered(c);
    var i = 0;
    while i < list.len {
        let n = list[i] as i64;
        guard i + 1 + n <= list.len else { return false; }
        if list[i + 1..i + 1 + n] == protocol { return true; }
        i += 1 + n;
    }
    return false;
}

// The peer's certificate, its leaf, as PEM once the handshake has it; "" when
// there is none, such as from a client that sent none.
fn peer_certificate(c: Conn) -> u8[>..] {
    var s: u8[>..] = [];
    peer_certificate_c(c.id, s);
    return s;
}

// Hands the connection bytes the socket received. Takes all of them: returns
// data.len, or FAILED.
fn feed(c: Conn, data: const u8[:]) -> i64 { feed_c(c.id, data) }

// How many bytes wait for drain.
fn pending(c: Conn) -> i64 { pending_c(c.id) }

// Moves up to buf.len of the bytes waiting to be sent into buf, and returns
// how many. A handshake, a write, a shutdown, or a failure can leave bytes
// waiting; drain until it returns 0.
fn drain(c: Conn, buf: u8[:]) -> i64 { drain_c(c.id, buf) }

// Advances the handshake with what was fed: 0 once it is done, else
// WANT_INPUT, HELLO, or FAILED. A read finishes the handshake too; this is
// for a program that wants the ALPN protocol before the first byte of
// plaintext. A client calls it first, to make its ClientHello.
fn handshake(c: Conn) -> i64 { handshake_c(c.id) }

// Decrypts what was fed into buf: the count, more than 0, or WANT_INPUT,
// CLOSED, or FAILED. Call it until it returns WANT_INPUT: one call reads at
// most one record.
fn read(c: Conn, buf: u8[:]) -> i64 { read_c(c.id, buf) }

// Encrypts all of data into bytes waiting for drain: data.len, or WANT_INPUT
// before the handshake is done, or FAILED.
fn write(c: Conn, data: const u8[:]) -> i64 { write_c(c.id, data) }

// Queues close_notify for drain: 0, or FAILED.
fn shutdown(c: Conn) -> i64 { shutdown_c(c.id) }

// The protocol ALPN chose, or "" for none.
fn alpn(c: Conn) -> u8[>..] {
    var s: u8[>..] = [];
    alpn_c(c.id, s);
    return s;
}

// The version once the handshake is done, "TLSv1.3"; "" before.
fn version(c: Conn) -> u8[>..] {
    var s: u8[>..] = [];
    version_c(c.id, s);
    return s;
}

// The cipher suite once the handshake is done, such as
// "TLS_AES_128_GCM_SHA256"; "" before.
fn cipher(c: Conn) -> u8[>..] {
    var s: u8[>..] = [];
    cipher_c(c.id, s);
    return s;
}

// Why the last call on this thread failed, in OpenSSL's words, one reason a
// line; "" when it gave none. Reading clears them.
fn error_text() -> u8[>..] {
    var s: u8[>..] = [];
    error_text_c(s);
    return s;
}

// The OpenSSL the program runs with, such as "OpenSSL 3.0.13 30 Jan 2024".
fn library() -> u8[>..] {
    var s: u8[>..] = [];
    library_c(s);
    return s;
}

// kTLS on Linux: after the handshake, the kernel takes the record layer, and
// the program sends and receives plaintext on the socket itself. The steps
// are in docs/architecture.md, "kTLS on Linux".

// Whether this kernel has kTLS (Linux's tls module, CONFIG_TLS). False on
// every other platform.
fn kernel_supported() -> bool { kernel_supported_c() }

// Makes the connections ctx accepts from now on ready to move to the kernel:
// true, or false where the kernel has no kTLS, and then nothing changes.
// Call it before ctx accepts its first connection.
fn use_kernel(ctx: Context) -> bool { kernel_enable_c(ctx.id, false) }

// Moves the connection to the kernel on socket fd, once the handshake is
// done: which directions the kernel took, KERNEL_RX | KERNEL_TX, KERNEL_RX
// alone, or 0, when the connection stays in user space as it was. Or a
// status, after which the program calls it again:
//
// WANT_INPUT: the bytes fed end inside a record. Read exactly kernel_wants(c)
// more bytes from the socket, feed them, and read the plaintext.
// PENDING: read until WANT_INPUT, and drain and send everything.
// FAILED: the handshake isn't done.
//
// Everything drained before must be on the socket before the program sends
// through the kernel. A connection whose context didn't use_kernel gets 0.
fn to_kernel(c: Conn, fd: i64) -> i64 { kernel_start_c(c.id, fd) }

// How many bytes complete the record the bytes fed end in, after to_kernel
// gave WANT_INPUT.
fn kernel_wants(c: Conn) -> i64 { kernel_wants_c(c.id) }

// Which directions the kernel holds, as to_kernel last reported them. Once
// it holds receiving, feed and read fail; once it holds sending, write and
// shutdown fail.
fn in_kernel(c: Conn) -> i64 { kernel_owned_c(c.id) }

// Takes a record that isn't data, which the kernel received on fd: its type,
// from recvmsg's TLS_GET_RECORD_TYPE, and its plaintext. Returns 0 when the
// connection goes on (a KeyUpdate: the kernel has the next keys, so receive
// again, without waiting for the socket to be readable), UPDATE_TX, CLOSED
// for close_notify, or FAILED: an alert, a message a client doesn't send
// after the handshake, or a kernel that can't change keys (Linux before
// 6.14). With sending still in user space, it queues the answer to a
// KeyUpdate for drain, and returns 0.
fn kernel_record(c: Conn, fd: i64, kind: i64, body: const u8[:]) -> i64 {
    kernel_record_c(c.id, fd, kind, body)
}

// Moves the kernel's sending on fd to the next keys, right after the program
// sent KEY_UPDATE through it: 0, or FAILED.
fn kernel_update_tx(c: Conn, fd: i64) -> i64 { kernel_update_tx_c(c.id, fd) }

// Keys and certificates for an ACME client, which then needs no C of its own
// (docs/architecture.md, "Keys and certificates"). names, in csr and
// self_signed, are DNS names, each 1 to 255 bytes.

// A new EC P-256 key; check ok(k).
fn key_generate() -> Key { Key { id: key_generate_c() } }

// An EC P-256 private key from PEM, PKCS#8 or SEC 1's "EC PRIVATE KEY"; check
// ok(k). Not ok for any other kind of key; error_text says why.
fn key_from_pem(pem: const u8[:]) -> Key { Key { id: key_from_pem_c(pem) } }

fn ok(k: Key) -> bool { k.id != 0 }
fn free(k: Key) { key_free_c(k.id); }

// The private key as unencrypted PKCS#8 PEM, which key_from_pem and server
// read; "" on failure.
fn key_pem(k: Key) -> u8[>..] {
    var s: u8[>..] = [];
    key_pem_c(k.id, s);
    return s;
}

// The public key's coordinates, x then y, 32 bytes each, big-endian: a JWK's
// "x" and "y" before base64url (RFC 7518, section 6.2.1); "" on failure.
fn public_xy(k: Key) -> u8[>..] {
    var s: u8[>..] = [];
    key_public_c(k.id, s);
    return s;
}

// The ES256 signature of data (RFC 7518, section 3.4): ECDSA with P-256 over
// SHA-256, as the 64 bytes r || s that JWS takes; "" on failure.
fn sign_es256(k: Key, data: const u8[:]) -> u8[>..] {
    var s: u8[>..] = [];
    sign_es256_c(k.id, data, s);
    return s;
}

// The 32-byte SHA-256 digest of data: for a JWK thumbprint (RFC 7638), and
// the key authorization's digest in a challenge certificate.
fn sha256(data: const u8[:]) -> u8[>..] {
    var s: u8[>..] = [];
    sha256_c(data, s);
    return s;
}

// A certificate signing request for names, signed by k, as DER: what RFC
// 8555's finalize takes, in base64url. The first name is the subject's common
// name, when it fits its 64 characters, and every name is in subjectAltName.
// "" when names is empty or a name is empty or too long.
fn csr(k: Key, names: const u8[:][:]) -> u8[>..] {
    var s: u8[>..] = [];
    var list: u8[>..] = [];
    guard names.len > 0 && wire(names, 255, list) else { return s; }
    csr_c(k.id, list, s);
    return s;
}

// A self-signed certificate for names and k, as PEM, valid from an hour ago
// for days days: for a server to start with before ACME gives it one. ""
// when names is empty, a name is empty or too long, or days is outside 1 to
// 36500.
fn self_signed(k: Key, names: const u8[:][:], days: i64) -> u8[>..] {
    var s: u8[>..] = [];
    var list: u8[>..] = [];
    guard names.len > 0 && wire(names, 255, list) else { return s; }
    self_signed_c(k.id, list, days, "", s);
    return s;
}

// TLS-ALPN-01's challenge certificate (RFC 8737, section 3), as PEM: self-
// signed by k, for name alone, with the critical acmeIdentifier extension
// holding the SHA-256 of key_authorization, the challenge's token and the
// account key's thumbprint. A server answers with it to a client that sends
// name in SNI and offers only "acme-tls/1" (choose_context). "" on failure.
fn challenge_certificate(k: Key, name: const u8[:], key_authorization: const u8[:]) -> u8[>..] {
    var s: u8[>..] = [];
    var list: u8[>..] = [];
    guard wire([name], 255, list) else { return s; }
    self_signed_c(k.id, list, 7, sha256(key_authorization), s);
    return s;
}
