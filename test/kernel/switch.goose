// A connection moved to the kernel, with the kernel's record layer played by
// the test peer (test/tools/peer/) and an OpenSSL client at the other end,
// for each of the three suites. Before the switch: a request that arrives
// with the client's Finished, a response and the session tickets sent from
// user space, a KeyUpdate answered there, and a record fed in pieces. After
// it: data each way, a KeyUpdate that asks for one back, and close_notify.
// Then a kernel that takes receiving only, a context without kTLS, and a
// connection before its handshake.
import std;
import peer from "../tools/peer";
import tls from "../../";

let CRT = embed_file("../certs/server.crt");
let KEY = embed_file("../certs/server.key");

extern "tls_kernel_enable" fn enable(ctx: i64, anywhere: bool) -> bool;
extern "tls_kernel_info" fn info(c: i64, dir: i64, out: u8[:]) -> i64;

// The descriptors the shim takes as a kernel that takes both directions, and
// one that takes receiving only.
let BOTH = -1;
let RX_ONLY = -2;

fn status(n: i64) -> const u8[:] {
    match n {
        tls::WANT_INPUT => "WANT_INPUT",
        tls::CLOSED => "CLOSED",
        tls::FAILED => "FAILED",
        tls::PENDING => "PENDING",
        tls::UPDATE_TX => "UPDATE_TX",
        0 => "0",
        1 => "KERNEL_RX",
        3 => "KERNEL_RX | KERNEL_TX",
        _ => "a count",
    }
}

fn drained(c: tls::Conn) -> u8[>..] {
    var all: u8[>..] = [];
    var buf: u8[1000] = [0; 1000];
    loop {
        let n = tls::drain(c, buf);
        guard n > 0 else { break; }
        all.append(buf[..n]);
    }
    return all;
}

fn from_peer(p: i64) -> u8[>..] {
    var out: u8[>..] = [];
    peer::drain(p, out);
    return out;
}

// What the server reads now, until WANT_INPUT.
fn read_all(c: tls::Conn) -> u8[>..] {
    var got: u8[>..] = [];
    var buf: u8[1000] = [0; 1000];
    loop {
        let r = tls::read(c, buf);
        guard r > 0 else { break; }
        got.append(buf[..r]);
    }
    return got;
}

// What the client reads from bytes, as text.
fn client_reads(p: i64, bytes: const u8[:]) -> u8[>..] {
    peer::feed(p, bytes);
    var got: u8[>..] = [];
    peer::read(p, got);
    return got;
}

// The kernel's side of a direction, from the keys the shim gives it now.
fn kernel_of(c: tls::Conn, dir: i64) -> i64 {
    var buf: u8[64] = [0; 64];
    let n = info(c.id, dir, buf);
    guard n > 0 else { return 0; }
    return peer::kernel(buf[..n]);
}

// The records in bytes, opened by the kernel's receiving side: each one's
// type and text.
fn kernel_reads(k: i64, bytes: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var at = 0;
    while at + 5 <= bytes.len {
        let end = at + 5 + ((bytes[at + 3] as i64) << 8 | bytes[at + 4]);
        var plain: u8[>..] = [];
        let kind = peer::open(k, bytes[at..end], plain);
        if out.len > 0 { out.append(", "); }
        format(out, "type ", kind, " '", plain, "'");
        at = end;
    }
    return out;
}

fn hex(b: const u8[:]) -> u8[>..] {
    let digits = "0123456789abcdef";
    var out: u8[>..] = [];
    for c in b {
        out.push(digits[c >> 4]);
        out.push(digits[c & 15]);
    }
    return out;
}

// A client and a server connection through the handshake, with a request
// in the flight that carries the client's Finished.
fn connect(ctx: tls::Context, suite: const u8[:]) -> tls::Conn, i64 {
    let c = tls::accept(ctx);
    let p = peer::client(suite);
    peer::handshake(p);
    tls::feed(c, from_peer(p));
    tls::handshake(c);
    peer::feed(p, drained(c));
    assert(peer::handshake(p) == 0);
    peer::write(p, "a request with the Finished");
    tls::feed(c, from_peer(p));
    print("  handshake ", status(tls::handshake(c)), ", ", tls::cipher(c));
    return c, p;
}

fn run(ctx: tls::Context, suite: const u8[:]) {
    print(suite, ":");
    let c, p = connect(ctx, suite);
    print("  to_kernel with the request unread: ", status(tls::to_kernel(c, BOTH)));
    print("  read: '", read_all(c), "'");
    print("  to_kernel with the tickets undrained: ", status(tls::to_kernel(c, BOTH)));
    tls::write(c, "a response from user space");
    print("  the client reads '", client_reads(p, drained(c)), "'");

    // A KeyUpdate before the switch, which OpenSSL answers.
    peer::key_update(p, true);
    peer::write(p, "after the client's first KeyUpdate");
    tls::feed(c, from_peer(p));
    print("  read: '", read_all(c), "'");
    tls::write(c, "after the server's first KeyUpdate");
    print("  the client reads '", client_reads(p, drained(c)), "'");

    // A record fed in pieces: the switch waits for its end.
    peer::write(p, "a record in three pieces");
    let rec = from_peer(p);
    tls::feed(c, rec[..3]);
    print("  to_kernel after 3 bytes: ", status(tls::to_kernel(c, BOTH)), ", wants ", tls::kernel_wants(c));
    tls::feed(c, rec[3..5]);
    print("  after 5: ", status(tls::to_kernel(c, BOTH)), ", wants ", tls::kernel_wants(c),
          " of ", rec.len - 5);
    tls::feed(c, rec[5..]);
    print("  read: '", read_all(c), "'");
    let taken = tls::to_kernel(c, BOTH);
    print("  to_kernel: ", status(taken), ", in_kernel ", status(tls::in_kernel(c)),
          ", again: ", status(tls::to_kernel(c, BOTH)));

    var rx = kernel_of(c, tls::KERNEL_RX);
    var tx = kernel_of(c, tls::KERNEL_TX);
    var out: u8[>..] = [];
    peer::seal(tx, 23, "sent by the kernel", out);
    print("  the client reads '", client_reads(p, out), "'");
    peer::write(p, "received by the kernel");
    print("  the kernel reads ", kernel_reads(rx, from_peer(p)));
    print("  user space: write ", status(tls::write(c, "x")), ", feed ", status(tls::feed(c, "x")),
          ", shutdown ", status(tls::shutdown(c)));

    // A KeyUpdate that asks for one back, through the kernel.
    peer::key_update(p, true);
    let ku = from_peer(p);
    var body: u8[>..] = [];
    let kind = peer::open(rx, ku, body);
    print("  the kernel reads a record of type ", kind, ": ", hex(body));
    print("  kernel_record: ", status(tls::kernel_record(c, BOTH, kind, body)));
    peer::kernel_free(rx);
    rx = kernel_of(c, tls::KERNEL_RX);
    out.clear();
    peer::seal(tx, tls::RECORD_HANDSHAKE, tls::KEY_UPDATE, out);
    print("  kernel_update_tx: ", status(tls::kernel_update_tx(c, BOTH)));
    peer::kernel_free(tx);
    tx = kernel_of(c, tls::KERNEL_TX);
    peer::seal(tx, 23, "sent with the server's next keys", out);
    print("  the client reads '", client_reads(p, out), "'");
    peer::write(p, "sent with the client's next keys");
    print("  the kernel reads ", kernel_reads(rx, from_peer(p)));

    peer::shutdown(p);
    let bye = from_peer(p);
    body.clear();
    let alert = peer::open(rx, bye, body);
    print("  close_notify: kernel_record ", status(tls::kernel_record(c, BOTH, alert, body)));
    print("  another alert: ", status(tls::kernel_record(c, BOTH, tls::RECORD_ALERT, "\x02\x28")));
    print("    ", tls::error_text());
    print("  a ticket from the client: ", status(tls::kernel_record(c, BOTH, tls::RECORD_HANDSHAKE, "\x04\x00\x00\x00")));
    print("    ", tls::error_text());
    peer::kernel_free(rx);
    peer::kernel_free(tx);
    peer::free(p);
    tls::free(c);
}

// The kernel takes receiving and refuses sending: OpenSSL sends on, and
// answers a KeyUpdate itself.
fn rx_only(ctx: tls::Context) {
    print("receiving only:");
    let c, p = connect(ctx, "TLS_AES_128_GCM_SHA256");
    read_all(c);
    peer::feed(p, drained(c));
    print("  to_kernel: ", status(tls::to_kernel(c, RX_ONLY)), ", in_kernel ", status(tls::in_kernel(c)));
    print("    ", tls::error_text());
    var rx = kernel_of(c, tls::KERNEL_RX);
    peer::key_update(p, true);
    var body: u8[>..] = [];
    let kind = peer::open(rx, from_peer(p), body);
    print("  kernel_record: ", status(tls::kernel_record(c, RX_ONLY, kind, body)),
          ", update_tx ", status(tls::kernel_update_tx(c, RX_ONLY)));
    tls::write(c, "sent from user space after its KeyUpdate");
    print("  the client reads '", client_reads(p, drained(c)), "'");
    peer::kernel_free(rx);
    rx = kernel_of(c, tls::KERNEL_RX);
    peer::write(p, "received by the kernel with the next keys");
    print("  the kernel reads ", kernel_reads(rx, from_peer(p)));
    peer::kernel_free(rx);
    peer::free(p);
    tls::free(c);
}

fn main() {
    let ctx, ok = tls::server(CRT, KEY, ["http/1.1"]);
    assert(ok && enable(ctx.id, true));
    run(ctx, "TLS_AES_128_GCM_SHA256");
    run(ctx, "TLS_AES_256_GCM_SHA384");
    run(ctx, "TLS_CHACHA20_POLY1305_SHA256");
    rx_only(ctx);

    let early = tls::accept(ctx);
    print("before the handshake: to_kernel ", status(tls::to_kernel(early, BOTH)));
    print("  ", tls::error_text());
    tls::free(early);
    tls::free(ctx);

    let plain, pok = tls::server(CRT, KEY, ["http/1.1"]);
    assert(pok);
    let c, p = connect(plain, "TLS_AES_128_GCM_SHA256");
    read_all(c);
    print("a context without kTLS: to_kernel ", status(tls::to_kernel(c, BOTH)), ", in_kernel ",
          status(tls::in_kernel(c)));
    print("  ", tls::error_text());
    tls::write(c, "still in user space");
    peer::feed(p, drained(c));
    var got: u8[>..] = [];
    peer::read(p, got);
    print("  the client reads '", got, "'");
    peer::free(p);
    tls::free(c);
    tls::free(plain);
}
