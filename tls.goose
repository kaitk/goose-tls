// TLS for a server, over OpenSSL (shim/tls.c). The package does no I/O: the
// program reads from its socket and feeds the bytes to a connection, and sends
// what it drains from it. The byte flow and its states are in
// docs/architecture.md.
//
//   let ctx, ok = tls::server_files("server.crt", "server.key", ["http/1.1"]);
//   let c = tls::accept(ctx);                 // for each accepted socket
//   tls::feed(c, received);                   // bytes the socket gave
//   let n = tls::read(c, plain);              // plaintext, or a status
//   tls::write(c, response);
//   let m = tls::drain(c, out);               // bytes for the socket
//
// A Context and a Conn are handles to OpenSSL's objects: flat, so they cross
// queues and thread_spawn, and freed only by tls::free. Free each once and
// don't use it after: the handle is the object's address. A Context is safe
// to use from several threads at once; a Conn from one at a time.
namespace tls;

import std;
import os;

// A server configuration: the certificate chain and key, the protocol
// versions and suites, and the ALPN protocols. Connections take a reference
// to it, so freeing it, or replacing it with a new one for new connections,
// leaves open connections as they are.
struct Context { id: i64 = 0 }

// One TLS connection's state, over the bytes of one socket.
struct Conn { id: i64 = 0 }

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

// A server context from PEM text: chain holds the leaf certificate, then any
// intermediates; key the leaf's private key. protocols are the ALPN names the
// server speaks, in its order of preference; a client that offers none of
// them gets no ALPN answer, and one that offers no ALPN still connects.
// TLS 1.3 only, with TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, and
// TLS_CHACHA20_POLY1305_SHA256, chosen in that order. False when the PEM
// doesn't parse, the key doesn't match the leaf, or a protocol name is empty
// or longer than 255 bytes; error_text says which.
fn server(chain: const u8[:], key: const u8[:], protocols: const u8[:][:]) -> Context, bool {
    var wire: u8[>..] = [];
    for p in protocols {
        guard p.len > 0 && p.len < 256 else { return Context { .. }, false; }
        wire.push(p.len as u8);
        wire.append(p);
    }
    let id = server_new_c(chain, key, wire);
    return Context { id: id }, id != 0;
}

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

fn ok(ctx: Context) -> bool { ctx.id != 0 }
fn ok(c: Conn) -> bool { c.id != 0 }

fn free(ctx: Context) { context_free_c(ctx.id); }
fn free(c: Conn) { conn_free_c(c.id); }

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
// WANT_INPUT or FAILED. A read finishes the handshake too; this is for a
// program that wants the ALPN protocol before the first byte of plaintext.
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
