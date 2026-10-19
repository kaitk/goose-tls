// A connection fed recorded ClientHellos (test/hellos/, from openssl
// s_client, offering ALPN h2 and http/1.1): a TLS 1.3 one gets a ServerHello
// to send and waits for the client's Finished; a TLS 1.2 one fails with a
// protocol_version alert to send; bytes that aren't TLS fail too. Before the
// handshake, read and write wait for input and the connection reports no
// version, cipher, or protocol.
import std;
import tls from "../../";

let CRT = embed_file("../certs/server.crt");
let KEY = embed_file("../certs/server.key");
let HELLO13 = embed_file("../hellos/tls1_3.bin");
let HELLO12 = embed_file("../hellos/tls1_2.bin");

fn status(n: i64) -> const u8[:] {
    match n {
        tls::WANT_INPUT => "WANT_INPUT",
        tls::CLOSED => "CLOSED",
        tls::FAILED => "FAILED",
        _ => "a count",
    }
}

// Drains everything waiting and describes it: its length and first record's
// header.
fn drained(c: tls::Conn) -> u8[>..] {
    var all: u8[>..] = [];
    var buf: u8[1000] = [0; 1000];
    loop {
        let n = tls::drain(c, buf);
        guard n > 0 else { break; }
        all.append(buf[..n]);
    }
    guard all.len >= 5 else { return str(all.len, " bytes"); }
    return str("record type ", all[0], ", version ", all[1], ".", all[2],
               if all.len == 7 { str(", alert ", all[5], " ", all[6]) } else { str("") });
}

fn main() {
    let ctx, ok = tls::server(CRT, KEY, ["h2", "http/1.1"]);
    assert(ok);

    let a = tls::accept(ctx);
    assert(tls::ok(a));
    var plain: u8[100] = [0; 100];
    print("fresh: read ", status(tls::read(a, plain)), ", write ", status(tls::write(a, "early")),
          ", pending ", tls::pending(a), ", version '", tls::version(a), "', alpn '", tls::alpn(a), "'");
    print("TLS 1.3 hello: feed ", tls::feed(a, HELLO13) == HELLO13.len, ", handshake ",
          status(tls::handshake(a)), ", to send: ", drained(a));
    print("  after: pending ", tls::pending(a), ", handshake ", status(tls::handshake(a)));
    tls::free(a);

    let b = tls::accept(ctx);
    tls::feed(b, HELLO12);
    print("TLS 1.2 hello: handshake ", status(tls::handshake(b)), ", to send: ", drained(b));
    print("  reason: ", tls::error_text());
    tls::free(b);

    let c = tls::accept(ctx);
    tls::feed(c, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    print("plaintext HTTP: handshake ", status(tls::handshake(c)), ", to send: ", drained(c));
    print("  reason: ", tls::error_text());
    tls::free(c);

    // Connections hold the context: one accepted before the context is freed
    // still takes a hello.
    let d = tls::accept(ctx);
    tls::free(ctx);
    tls::feed(d, HELLO13);
    print("after the context is freed: handshake ", status(tls::handshake(d)), ", to send: ", drained(d));
    tls::free(d);
}
