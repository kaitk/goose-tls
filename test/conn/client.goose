// A client's handshake verifies the server: it completes against a server
// whose certificate it trusts and that names the host, and fails, with the
// reason, against a self-signed certificate the system doesn't trust, a
// certificate for another name, or a server that offers no TLS 1.3.
import std;
import tls from "../../";
import check from "../";

let CRT = embed_file("../certs/server.crt");
let KEY = embed_file("../certs/server.key");
let HELLO12 = embed_file("../hellos/tls1_2.bin");

fn try(what: const u8[:], cctx: tls::Context, sctx: tls::Context, host: const u8[:]) {
    let c = tls::connect(cctx, host);
    check::that(str(what, ": connect"), tls::ok(c));
    let s = tls::accept(sctx);
    var cs = 0;
    let ss = check::handshake(c, s, cs);
    if cs == 0 && ss == 0 {
        print("  done: ", tls::version(c), " ", tls::cipher(c), ", alpn '", tls::alpn(c), "'");
    } else {
        print("  client ", check::status(cs), ": ", check::reason());
        tls::error_text();
    }
    tls::free(c);
    tls::free(s);
}

fn main() {
    let sctx, sok = tls::server(CRT, KEY, ["http/1.1"]);
    check::that("server context", sok);

    let trusting, tok = tls::client_trusting(CRT, ["h2", "http/1.1"]);
    check::that("a client trusting the server's certificate", tok);
    try("localhost", trusting, sctx, "localhost");
    try("127.0.0.1", trusting, sctx, "127.0.0.1");
    try("another name", trusting, sctx, "example.com");
    try("another address", trusting, sctx, "127.0.0.2");

    let system, yok = tls::client(["http/1.1"]);
    check::that("a client trusting the system's authorities", yok);
    try("a self-signed certificate", system, sctx, "localhost");

    let none, nok = tls::client_trusting("no certificates", []);
    check::that("a client trusting no certificates isn't made", !nok && !tls::ok(none));
    tls::error_text();
    let bad, bok = tls::client([""]);
    check::that("an empty ALPN name is refused", !bok);
    check::that("a host with a NUL is refused", !tls::ok(tls::connect(trusting, "a\x00b")));
    check::that("an empty host is refused", !tls::ok(tls::connect(trusting, "")));

    let c = tls::connect(trusting, "localhost");
    print("a client before its handshake: pending ", tls::pending(c), ", handshake ",
          check::status(tls::handshake(c)), ", a ClientHello to send ", tls::pending(c) > 0);
    // A ClientHello, where a ServerHello belongs, fails the handshake.
    tls::feed(c, HELLO12);
    print("  fed a ClientHello: handshake ", check::status(tls::handshake(c)));
    tls::error_text();
    tls::free(c);

    tls::free(trusting);
    tls::free(system);
    tls::free(sctx);
}
