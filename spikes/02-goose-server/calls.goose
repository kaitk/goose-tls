// What a call from Goose into the package's C costs, on one connection of
// the Goose server, in nanoseconds a call: one that returns a field
// (tls::pending), and one that copies the connection's state in and out, as
// each of the server's calls does (tls::load and tls::store).
import std;
import os;
import tls from "../../";

let CRT = embed_file("../../test/certs/server.crt");
let KEY = embed_file("../../test/certs/server.key");
let N = 20000000;

fn main() {
    let ctx, ok = tls::server(CRT, KEY, ["http/1.1"]);
    assert(ok);
    let c = tls::accept(ctx);
    var sum = 0;
    let t0 = clock_ns();
    for i in N { sum += tls::pending(c); }
    let t1 = clock_ns();
    for i in N {
        var st = tls::ServerState { .. };
        tls::load(c.id, st);
        st.updates += 1;
        tls::store(c.id, st);
    }
    let t2 = clock_ns();
    var st = tls::ServerState { .. };
    tls::load(c.id, st);
    print("calls=", N, " pending_ns=", (t1 - t0) * 1.0 / N, " load_store_ns=", (t2 - t1) * 1.0 / N,
          " check=", sum + st.updates);
    tls::free(c);
    tls::free(ctx);
}
