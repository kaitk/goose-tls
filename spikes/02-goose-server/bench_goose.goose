// Spike 01's harness (bench.c) against the Goose server: main hands the
// command line to glue.c, which runs bench.c's main, and bench.c's srv_*
// calls come back here through the exported gsrv_* functions. Everything
// runs on main's thread, as exported functions must.
import std;
import os;
import tls from "../../";

extern fn bench_run(args: const u8[:]) -> i32;

var ctx = tls::Context { .. };

fn main() {
    var all: u8[>..] = [];
    for a in args() {
        all.append(a);
        all.push(0);
    }
    exit(bench_run(all));
}

// A server context from the PEM text, offering what GROUPS asks: the
// default, or X25519 alone.
export fn gsrv_init(groups: const u8[:], chain: const u8[:], key: const u8[:]) -> bool {
    let c, ok = tls::server(chain, key, ["http/1.1"]);
    guard ok else {
        print("gsrv_init: ", tls::error_text());
        return false;
    }
    if groups == "x25519" && !tls::use_groups(c, "X25519") { return false; }
    ctx = c;
    return true;
}

export fn gsrv_new() -> i64 { tls::accept(ctx).id }

// srv.h's statuses: -1 to wait for input, -2 for a failure.
fn status(n: i64) -> i64 {
    if n >= 0 { return n; }
    if n == tls::WANT_INPUT { return -1; }
    print("gsrv: ", tls::error_text());
    return -2;
}

export fn gsrv_feed(id: i64, data: const u8[:]) -> i64 {
    if tls::feed(tls::Conn { id: id }, data) == data.len { 0 } else { -2 }
}

export fn gsrv_handshake(id: i64) -> i64 { status(tls::handshake(tls::Conn { id: id })) }
export fn gsrv_read(id: i64, buf: u8[:]) -> i64 { status(tls::read(tls::Conn { id: id }, buf)) }
export fn gsrv_write(id: i64, data: const u8[:]) -> i64 { status(tls::write(tls::Conn { id: id }, data)) }
export fn gsrv_drain(id: i64, buf: u8[:]) -> i64 { tls::drain(tls::Conn { id: id }, buf) }
export fn gsrv_free(id: i64) { tls::free(tls::Conn { id: id }); }

// The negotiated group, suite, and ALPN protocol, copied into out: their
// length.
export fn gsrv_group(id: i64, out: u8[:]) -> i64 { put(tls::group(tls::Conn { id: id }), out) }
export fn gsrv_suite(id: i64, out: u8[:]) -> i64 { put(tls::cipher(tls::Conn { id: id }), out) }
export fn gsrv_alpn(id: i64, out: u8[:]) -> i64 { put(tls::alpn(tls::Conn { id: id }), out) }

fn put(s: const u8[:], out: u8[:]) -> i64 {
    let n = min(s.len, out.len);
    for i in n { out[i] = s[i]; }
    return n;
}
