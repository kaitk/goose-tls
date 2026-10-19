// A server that picks each connection's context at the ClientHello, from the
// SNI name and the offered ALPN list, as TLS-ALPN-01 needs: a client that
// sends acme.test and offers acme-tls/1 gets the challenge certificate, one
// that sends other.test gets that name's certificate, and every other keeps
// the default context.
import std;
import tls from "../../";
import check from "../";

let CRT = embed_file("../certs/server.crt");
let KEY = embed_file("../certs/server.key");

struct Contexts { default: tls::Context, other: tls::Context, acme: tls::Context }

// The server's side of the choice.
fn choose(s: tls::Conn, ctxs: Contexts) {
    let name = tls::server_name(s);
    if name == "acme.test" && tls::offers(s, "acme-tls/1") {
        check::that("  use_context(acme)", tls::use_context(s, ctxs.acme));
    } else if name == "other.test" {
        check::that("  use_context(other)", tls::use_context(s, ctxs.other));
    }
}

// A connection from a client that trusts ca, offers protocols, and connects to
// host; prints what each side saw.
fn connect(ctxs: Contexts, ca: const u8[:], protocols: const u8[:][:], host: const u8[:]) {
    print(host, " offering ", protocols.len, " protocol(s):");
    let cctx, ok = tls::client_trusting(ca, protocols);
    check::that("  client context", ok);
    let c = tls::connect(cctx, host);
    let s = tls::accept(ctxs.default);
    var cs = 0;
    var ss = check::handshake(c, s, cs);
    print("  server: ", check::status(ss), ", server_name '", tls::server_name(s), "', offers acme-tls/1 ",
          tls::offers(s, "acme-tls/1"), ", http/1.1 ", tls::offers(s, "http/1.1"));
    if ss == tls::HELLO {
        choose(s, ctxs);
        ss = check::handshake(c, s, cs);
    }
    print("  after: server ", check::status(ss), ", client ", check::status(cs), ", server alpn '",
          tls::alpn(s), "'");
    if ss == tls::FAILED { print("  server: ", tls::error_text()); }
    if cs == tls::FAILED { print("  client: ", check::reason()); }
    if cs == 0 {
        check::that("  the client got the trusted certificate", tls::peer_certificate(c) == ca);
        check::that("  data flows", check::send(c, s, "ping") == "ping");
    }
    tls::free(c);
    tls::free(s);
    tls::free(cctx);
}

fn main() {
    let dctx, dok = tls::server(CRT, KEY, ["http/1.1"]);
    check::that("default context", dok);
    check::that("choose_context", tls::choose_context(dctx));

    var other_crt: u8[>..] = [];
    var other_pem: u8[>..] = [];
    var acme_crt: u8[>..] = [];
    var acme_pem: u8[>..] = [];
    check::run() {
        let k = tls::key_generate(tls::P256);
        other_crt = tls::self_signed(k, ["other.test"], 1);
        other_pem = tls::key_pem(k);
        tls::free(k);
        let a = tls::key_generate(tls::P256);
        acme_crt = tls::challenge_certificate(a, "acme.test", check::DIGEST);
        acme_pem = tls::key_pem(a);
        tls::free(a);
    };
    let octx, ook = tls::server(other_crt, other_pem, ["http/1.1"]);
    check::that("other.test context", ook);
    let actx, aok = tls::server(acme_crt, acme_pem, ["acme-tls/1"]);
    check::that("acme.test challenge context", aok);

    let ctxs = Contexts { default: dctx, other: octx, acme: actx };

    connect(ctxs, CRT, ["http/1.1"], "localhost");
    connect(ctxs, other_crt, ["http/1.1"], "other.test");
    connect(ctxs, CRT, ["http/1.1"], "acme.test");
    // The challenge certificate's acmeIdentifier is critical, and a verifying
    // client knows no such extension: the ACME server checks it itself.
    connect(ctxs, acme_crt, ["acme-tls/1"], "acme.test");

    let s = tls::accept(dctx);
    check::that("use_context before the ClientHello fails", !tls::use_context(s, dctx));
    tls::error_text();
    tls::free(s);

    let plain, pok = tls::server(CRT, KEY, []);
    let s2 = tls::accept(plain);
    let cctx, cok = tls::client_trusting(CRT, ["h2"]);
    let c2 = tls::connect(cctx, "localhost");
    var cs = 0;
    let ss = check::handshake(c2, s2, cs);
    print("a context without choose_context: server ", check::status(ss), ", server_name '",
          tls::server_name(s2), "', protocols_offered ", tls::protocols_offered(s2).len, " bytes");
    tls::free(c2);
    tls::free(s2);
    tls::free(cctx);
    tls::free(plain);
    tls::free(octx);
    tls::free(actx);
    tls::free(dctx);
}
