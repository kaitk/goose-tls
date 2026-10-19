// Server contexts from PEM text and from files: a good pair, a key that
// doesn't match, text that isn't PEM, a missing file, and bad ALPN names.
import std;
import tls from "../../";

let CRT = embed_file("../certs/server.crt");
let KEY = embed_file("../certs/server.key");
let OTHER = embed_file("../certs/other.key");

fn show(what: const u8[:], ctx: tls::Context, ok: bool) {
    let e = tls::error_text();
    print(what, ": ", ok, " ", tls::ok(ctx), if e.len > 0 { " (an error)" } else { "" });
    tls::free(ctx);
}

fn main() {
    let a, oka = tls::server(CRT, KEY, ["h2", "http/1.1"]);
    show("good pair", a, oka);
    let b, okb = tls::server(CRT, OTHER, []);
    show("mismatched key", b, okb);
    let c, okc = tls::server("not a certificate", KEY, []);
    show("not PEM", c, okc);
    let d, okd = tls::server(CRT, KEY, ["", "http/1.1"]);
    show("empty ALPN name", d, okd);
    let e, oke = tls::server_files("no/such/server.crt", "no/such/server.key", []);
    show("missing file", e, oke);
}
