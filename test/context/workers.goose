// A server context shared by worker threads, as goose-http's workers share
// one: each worker takes a reference of its own with share, and main frees
// its own before any worker is done, so the last worker to free its share
// frees the context. Each worker handshakes and echoes over connections it
// accepts from its share.
import std;
import tls from "../../";
import check from "../";

let CRT = embed_file("../certs/server.crt");
let KEY = embed_file("../certs/server.key");
let WORKERS = 4;
let CONNECTIONS = 25;

struct Done { worker: i64, served: i64 }

thread_fn worker(ctx: tls::Context, id: i64) {
    let cctx, ok = tls::client_trusting(CRT, ["http/1.1"]);
    var served = 0;
    if ok {
        for i in CONNECTIONS {
            let c = tls::connect(cctx, "localhost");
            let s = tls::accept(ctx);
            var cs = 0;
            let ss = check::handshake(c, s, cs);
            if ss == 0 && cs == 0 && check::send(c, s, "ping") == "ping" && check::send(s, c, "pong") == "pong" {
                served += 1;
            }
            tls::free(c);
            tls::free(s);
        }
        tls::free(cctx);
    }
    tls::free(ctx);
    qput(Done { worker: id, served: served });
}

fn main() {
    let ctx, ok = tls::server(CRT, KEY, ["http/1.1"]);
    check::that("server context", ok);
    var ids: i64[>..] = [];
    for w in WORKERS { ids.push(thread_spawn(worker, tls::share(ctx), w)); }
    tls::free(ctx);
    var served: i64[4] = [0; 4];
    for w in WORKERS {
        let d = qget<Done>();
        served[d.worker] = d.served;
    }
    for id in ids { thread_wait(id); }
    for w in WORKERS { check::eq(str("worker ", w, " served"), served[w], CONNECTIONS); }
}
