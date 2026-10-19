// The tests' other end (peer.c): an OpenSSL TLS 1.3 client over memory BIOs,
// and the kernel's TLS 1.3 record layer in user space, made from the
// crypto_info the shim would give setsockopt. With them a test checks the
// keys and sequence numbers kTLS gets on any platform.
namespace peer;

import std;

let WANT_INPUT = -1;
let CLOSED = -2;
let FAILED = -3;

// A client offering one suite, by its IANA name.
extern "peer_client" fn client(suite: const u8[:]) -> i64;
extern "peer_free" fn free(c: i64);
extern "peer_feed" fn feed(c: i64, data: const u8[:]);
extern "peer_drain" fn drain(c: i64, out: u8[>..]&);
extern "peer_handshake" fn handshake(c: i64) -> i64;
// Appends what the client can read to out; returns the last status.
extern "peer_read" fn read(c: i64, out: u8[>..]&) -> i64;
extern "peer_write" fn write(c: i64, data: const u8[:]) -> i64;
extern "peer_key_update" fn key_update(c: i64, requested: bool) -> i64;
extern "peer_shutdown" fn shutdown(c: i64) -> i64;
extern "peer_errors" fn errors(out: u8[>..]&);

// The kernel's side of one direction, from a crypto_info; 0 when it can't
// be read.
extern "peer_kernel" fn kernel(info: const u8[:]) -> i64;
extern "peer_kernel_free" fn kernel_free(k: i64);
// Seals data as one record of the inner type, appended to out.
extern "peer_kernel_seal" fn seal(k: i64, kind: i64, data: const u8[:], out: u8[>..]&) -> i64;
// Opens exactly one record, appending its plaintext: its inner type, or
// FAILED.
extern "peer_kernel_open" fn open(k: i64, record: const u8[:], out: u8[>..]&) -> i64;
