// The key exchange group: what a handshake negotiates by default, what a
// server limited by use_groups negotiates with a default client, and the
// names use_groups refuses. The default differs between OpenSSL releases, so
// only whether it names one is printed.
import std;
import tls from "../../";
import check from "../";

let CRT = embed_file("../certs/server.crt");
let KEY = embed_file("../certs/server.key");

fn group(sctx: tls::Context, cctx: tls::Context) -> u8[>..] {
    let c = tls::connect(cctx, "localhost");
    let s = tls::accept(sctx);
    var cs = 0;
    let ss = check::handshake(c, s, cs);
    check::that("handshake", cs == 0 && ss == 0);
    let g = tls::group(s);
    check::that("both sides name the same group", g == tls::group(c));
    tls::free(c);
    tls::free(s);
    return g;
}

fn main() {
    let client, cok = tls::client_trusting(CRT, ["http/1.1"]);
    check::that("client context", cok);

    let plain, pok = tls::server(CRT, KEY, ["http/1.1"]);
    check::that("server context", pok);
    print("default: names a group ", group(plain, client).len > 0);

    let limited, lok = tls::server(CRT, KEY, ["http/1.1"]);
    check::that("limited context", lok);
    print("use_groups X25519:P-256:P-384: ", tls::use_groups(limited, "X25519:P-256:P-384"));
    print("  negotiated: ", group(limited, client));

    let p256, p256ok = tls::server(CRT, KEY, ["http/1.1"]);
    check::that("P-256 context", p256ok);
    print("use_groups P-256: ", tls::use_groups(p256, "P-256"));
    print("  negotiated: ", group(p256, client));

    print("an unknown name: ", tls::use_groups(limited, "X25519:no-such-group"));
    tls::error_text();
    print("  still negotiates: ", group(limited, client));
    print("an empty list: ", tls::use_groups(limited, ""));
    print("a NUL in the list: ", tls::use_groups(limited, "X25519\x00P-256"));

    tls::free(client);
    tls::free(plain);
    tls::free(limited);
    tls::free(p256);
}
