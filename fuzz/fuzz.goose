// Fuzz targets for the Goose server, for libFuzzer through fuzz/build.sh,
// which compiles this file's C with the package's and a C entry point for
// each target (targets.c). Each target takes the fuzzer's bytes:
//
//   fuzz_hello   the ClientHello parser, on any bytes as a whole message
//   fuzz_conn    a fresh connection fed the bytes in pieces whose sizes the
//                first bytes choose, through its handshake and reads;
//                sometimes from a context that pauses at HELLO
//   fuzz_open    records sealed under keys the harness knows, so that their
//                content reaches the server's Finished, KeyUpdate, alert, and
//                data handling: each a type byte, a 2-byte length, and that
//                much content, sealed by a second connection that holds the
//                client's keys
//
// A crash, a sanitizer report, or a failed assert is a finding.
import std;
import tls from "../";

// shim/server.c's, for the tests: a handshake secret set to known bytes.
extern "tlsg_ks_set" fn ks_set(id: i64, slot: i64, value: const u8[:]) -> bool;

let CRT = embed_file("../test/certs/server.crt");
let KEY = embed_file("../test/certs/server.key");

var plain_ctx = tls::Context { .. };
var choosing_ctx = tls::Context { .. };

fn main() {
    plain_ctx = tls::Context { id: tls::g_ctx_new(CRT, KEY) };
    choosing_ctx = tls::Context { id: tls::g_ctx_new(CRT, KEY) };
    assert(tls::ok(plain_ctx) && tls::ok(choosing_ctx));
    assert(tls::g_ctx_set_alpn(plain_ctx.id, "\x02h2\x08http/1.1"));
    assert(tls::g_ctx_set_alpn(choosing_ctx.id, "\x08http/1.1"));
    tls::g_ctx_set_choose(choosing_ctx.id);
}

export fn fuzz_hello(data: const u8[:]) -> i64 {
    var h = tls::Hello { .. };
    let r = tls::parse_hello(data, h);
    if r.alert < 0 && h.has_shares && h.has_groups {
        tls::shares_consistent(h.shares, h.groups);
        tls::share_for(h.shares, 0x001d);
    }
    return r.alert;
}

// Drains and discards what the connection has to send.
fn discard(c: tls::Conn) {
    var out: u8[4096] = [0; 4096];
    while tls::drain(c, out) > 0 {}
}

export fn fuzz_conn(data: const u8[:]) -> i64 {
    guard data.len >= 2 else { return 0; }
    let choosing = (data[0] & 1) != 0;
    var r = rng { (data[0] as u64) << 8 | data[1] | 1 };
    let c = tls::accept(if choosing { choosing_ctx } else { plain_ctx });
    var plain: u8[512] = [0; 512];
    var at = 2;
    var status = 0;
    while at < data.len && status != tls::FAILED && status != tls::CLOSED {
        let n = min(data.len - at, 1 + r.rand_int(300));
        tls::feed(c, data[at..at + n]);
        at += n;
        status = tls::handshake(c);
        if status == tls::HELLO {
            tls::server_name(c);
            if tls::offers(c, "http/1.1") { tls::use_context(c, plain_ctx); }
            status = tls::handshake(c);
        }
        while status == 0 {
            let got = tls::read(c, plain);
            guard got > 0 else {
                status = got;
                break;
            }
            tls::write(c, plain[..got]);
        }
        discard(c);
    }
    tls::free(c);
    return 0;
}

// A connection of plain_ctx past its handshake, as RFC 8448's test sets one
// up, with traffic secrets the harness chose; and a second whose sending
// holds the client's secret, to seal what the fuzzer gives.
fn known_pair(server: tls::Conn&, client: tls::Conn&, finished: bool) {
    var secret: u8[32] = [7; 32];
    server = tls::accept(plain_ctx);
    client = tls::accept(plain_ctx);
    for id in [server.id, client.id] {
        assert(tls::g_hs_begin(id, 0x1301));
        assert(ks_set(id, tls::S_CLIENT_AP, secret));
        assert(ks_set(id, tls::S_SERVER_AP, secret));
    }
    assert(tls::g_rec_keys(server.id, tls::DIR_READ, tls::S_CLIENT_AP));
    assert(tls::g_rec_keys(server.id, tls::DIR_WRITE, tls::S_SERVER_AP));
    assert(tls::g_rec_keys(client.id, tls::DIR_WRITE, tls::S_CLIENT_AP));
    var st = tls::ServerState { .. };
    tls::load(server.id, st);
    st.suite = 0x1301;
    st.group = 0x001d;
    st.sealing = true;
    if finished {
        // The client's expected Finished is 32 zero bytes, which the fuzzer
        // can find, and its application secret the same as its handshake one.
        var zero: u8[32] = [0; 32];
        assert(ks_set(server.id, tls::S_CLIENT_FINISHED, zero));
        st.phase = tls::PH_FINISHED;
    } else {
        tls::g_hs_end(server.id);
        st.phase = tls::PH_OPEN;
    }
    tls::store(server.id, st);
}

export fn fuzz_open(data: const u8[:]) -> i64 {
    guard data.len >= 1 else { return 0; }
    var server = tls::Conn { .. };
    var client = tls::Conn { .. };
    known_pair(server, client, (data[0] & 1) != 0);
    var wire: u8[>..] = [];
    var out: u8[20000] = [0; 20000];
    var plain: u8[512] = [0; 512];
    var at = 1;
    var status = 0;
    while at + 3 <= data.len && status != tls::FAILED && status != tls::CLOSED {
        let kind = data[at] as i64;
        let len = min(min((data[at + 1] as i64) << 8 | data[at + 2], data.len - at - 3), 16384);
        let content = data[at + 3..at + 3 + len];
        at += 3 + len;
        guard tls::g_seal(client.id, kind, content) >= 0 else { break; }
        // The client's Finished and KeyUpdate move its own keys too, as the
        // server's do on taking them, so that what it seals next still opens.
        if kind == tls::CT_HANDSHAKE && content.len == 36 && content[0] == 20 {
            tls::g_rec_keys(client.id, tls::DIR_WRITE, tls::S_CLIENT_AP);
        }
        if kind == tls::CT_HANDSHAKE && content.len == 5 && content[0] == 24 {
            tls::g_rec_update(client.id, tls::DIR_WRITE);
        }
        let n = tls::drain(client, out);
        tls::feed(server, out[..n]);
        status = tls::handshake(server);
        while status == 0 {
            let got = tls::read(server, plain);
            guard got > 0 else {
                status = got;
                break;
            }
        }
        discard(server);
    }
    tls::free(server);
    tls::free(client);
    return 0;
}
