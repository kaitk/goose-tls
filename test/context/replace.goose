// A certificate replaced while serving: connections accepted from the new
// context get the new certificate, and one opened before keeps the old one,
// and goes on, after the old context is freed.
import std;
import tls from "../../";
import check from "../";

let CRT = embed_file("../certs/server.crt");
let KEY = embed_file("../certs/server.key");

// A client connection to localhost, trusting both certificates, and its
// server's side, after their handshake.
fn open(cctx: tls::Context, sctx: tls::Context, c: tls::Conn&, s: tls::Conn&) {
    c = tls::connect(cctx, "localhost");
    s = tls::accept(sctx);
    var cs = 0;
    let ss = check::handshake(c, s, cs);
    check::that("  handshake", ss == 0 && cs == 0);
}

fn main() {
    let key = tls::key_generate();
    let new_crt = tls::self_signed(key, ["localhost"], 1);
    var both: u8[>..] = [];
    both.append(CRT);
    both.append(new_crt);
    let cctx, cok = tls::client_trusting(both, []);
    check::that("client context", cok);

    let old, ook = tls::server(CRT, KEY, ["http/1.1"]);
    check::that("old context", ook);
    print("a connection from the old context:");
    var c1 = tls::Conn { .. };
    var s1 = tls::Conn { .. };
    open(cctx, old, c1, s1);
    check::that("  it has the old certificate", tls::peer_certificate(c1) == CRT);

    let new, nok = tls::server(new_crt, tls::key_pem(key), ["http/1.1"]);
    check::that("new context", nok);
    tls::free(old);
    print("the old context freed; a connection from the new one:");
    var c2 = tls::Conn { .. };
    var s2 = tls::Conn { .. };
    open(cctx, new, c2, s2);
    check::that("  it has the new certificate", tls::peer_certificate(c2) == new_crt);

    print("the first connection:");
    check::that("  still has the old certificate", tls::peer_certificate(c1) == CRT);
    check::that("  echoes a request", check::send(c1, s1, "GET /") == "GET /");
    check::that("  and a response", check::send(s1, c1, "200 OK") == "200 OK");
    check::that("the second connection echoes too", check::send(c2, s2, "GET /") == "GET /");

    tls::free(c1);
    tls::free(s1);
    tls::free(c2);
    tls::free(s2);
    tls::free(new);
    tls::free(cctx);
    tls::free(key);
}
