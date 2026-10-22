// Full handshakes on THREADS threads at once, each between the package's
// client and the Goose server in memory, every server connection from one
// context that the threads share, as goose-http's workers share one. Each
// handshake issues two session tickets under the context's lock, so a lock
// that serialized the threads would show as handshakes per second that stop
// growing with threads. The time counts both ends of each handshake.
//
// threads THREADS HANDSHAKES: HANDSHAKES on each thread.
import std;
import os;
import tls from "../../";
import check from "../../test/";

let CRT = embed_file("../../test/certs/server.crt");
let KEY = embed_file("../../test/certs/server.key");

struct Done { served: i64 }

thread_fn worker(ctx: tls::Context, n: i64) {
    let cctx, ok = tls::client_trusting(CRT, ["http/1.1"]);
    var served = 0;
    if ok {
        for i in n {
            let c = tls::connect(cctx, "localhost");
            let s = tls::accept(ctx);
            var cs = 0;
            if check::handshake(c, s, cs) == 0 && cs == 0 { served += 1; }
            tls::free(c);
            tls::free(s);
        }
        tls::free(cctx);
    }
    tls::free(ctx);
    qput(Done { served: served });
}

fn main() {
    let a = args();
    guard a.len == 3 else {
        print("usage: threads THREADS HANDSHAKES");
        exit(2);
    }
    let threads, tok = parse_int(a[1]);
    let n, nok = parse_int(a[2]);
    guard tok && nok && threads > 0 && n > 0 else {
        print("usage: threads THREADS HANDSHAKES");
        exit(2);
    }
    let ctx, ok = tls::server(CRT, KEY, ["http/1.1"]);
    assert(ok);
    let t0 = clock_ns();
    var ids: i64[>..] = [];
    for t in threads { ids.push(thread_spawn(worker, tls::share(ctx), n)); }
    var served = 0;
    for t in threads { served += qget<Done>().served; }
    for id in ids { thread_wait(id); }
    let s = (clock_ns() - t0) * 1.0e-9;
    tls::free(ctx);
    assert(served == threads * n);
    print("threads=", threads, " handshakes=", served, " wall_s=", s, " hs_per_s=", served / s,
          " hs_per_s_per_thread=", served / s / threads);
}
