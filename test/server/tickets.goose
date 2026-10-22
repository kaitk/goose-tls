// The Goose server's session tickets, issued and opened under its contexts'
// key ring: what a ticket carries, that a changed byte anywhere, a cut one,
// or another context's keys don't open it, and the keys' turn on the ticket
// clock: a key issues for one period and opens for two, so a ticket opens
// across one turn and not across two, nor after skipped periods.
import std;
import tls from "../../";
import check from "../";

extern "tlsg_ks_set" fn ks_set(id: i64, slot: i64, value: const u8[:]) -> bool;
extern "tlsg_ticket_clock" fn ticket_clock(seconds: i64);

let CRT = embed_file("../certs/server.crt");
let KEY = embed_file("../certs/server.key");
let PERIOD = 7200;

// A connection of ctx with a resumption master secret of 32 bytes of seed,
// as after a handshake under TLS_AES_128_GCM_SHA256.
fn conn(ctx: i64, seed: u8) -> i64 {
    let id = tls::g_accept(ctx);
    assert(id != 0 && tls::g_hs_begin(id, 0x1301));
    let secret: u8[32] = [seed; 32];
    assert(ks_set(id, tls::S_RESUMPTION, secret));
    return id;
}

fn issue(id: i64, nonce: const u8[:]) -> u8[>..] {
    var t: u8[>..] = [];
    check::that("issued", tls::g_ticket_issue(id, tls::S_RESUMPTION, nonce, 0x01020304, t));
    return t;
}

// Whether id opens the ticket, wiping the PSK it leaves.
fn opens(id: i64, ticket: const u8[:]) -> bool {
    var sni: u8[>..] = [];
    let f = tls::g_ticket_open(id, ticket, tls::S_PSK, sni);
    tls::g_wipe(id, tls::S_PSK);
    return f.suite != 0;
}

fn psk(id: i64) -> u8[>..] {
    var out: u8[>..] = [];
    tls::g_public(id, tls::S_PSK, out);
    tls::g_wipe(id, tls::S_PSK);
    return out;
}

fn main() {
    let ctx = tls::g_ctx_new(CRT, KEY);
    let other = tls::g_ctx_new(CRT, KEY);
    assert(ctx != 0 && other != 0);
    let shared = tls::g_ctx_share(ctx);
    let a = conn(ctx, 1);
    let b = conn(ctx, 2);
    let c = conn(shared, 3);
    let foreign = conn(other, 4);

    tls::g_set_sni(a, "example.com");
    let t = issue(a, "\x00\x00");
    print("ticket bytes: ", t.len);
    var sni: u8[>..] = [];
    let f = tls::g_ticket_open(b, t, tls::S_PSK, sni);
    check::that("another connection opens it", f.suite == 0x1301);
    check::that("  the issue time is now", f.issued == tls::g_ticket_now());
    check::that("  age_add", f.age_add == 0x01020304);
    print("  sni: ", sni);
    let p = psk(b);
    print("  psk bytes: ", p.len);
    check::that("  another nonce, another PSK", psk_of(b, issue(a, "\x00\x01")) != p);
    check::that("a shared context's connection opens it", opens(c, t));
    check::that("another context's doesn't", !opens(foreign, t));
    let u = issue(a, "\x00\x00");
    check::that("two tickets with one nonce differ", u != t);
    check::that("  and hold one PSK", psk_of(b, u) == p);

    var changed = 0;
    for i in t.len {
        var x: u8[>..] = [];
        x.append(t);
        x[i] = x[i] ^ 0x80;
        if !opens(b, x) { changed += 1; }
    }
    check::that("a ticket with any byte changed doesn't open", changed == t.len);
    check::that("cut short, it doesn't", !opens(b, t[..t.len - 1]));
    var longer: u8[>..] = [];
    longer.append(t);
    longer.push(0);
    check::that("one byte longer, it doesn't", !opens(b, longer));
    check::that("nor nothing", !opens(b, ""));

    ticket_clock(PERIOD / 2);
    let same = issue(a, "\x00\x00");
    check::that("within the period the key stays", same[1..5] == t[1..5]);
    ticket_clock(PERIOD / 2);
    let next = issue(a, "\x00\x00");
    check::that("after it a new key issues", next[1..5] != t[1..5]);
    check::that("  the old key still opens", opens(b, t));
    check::that("  the new key opens", opens(c, next));
    ticket_clock(PERIOD);
    check::that("two periods on, the first key doesn't open", !opens(b, t));
    check::that("  the second still does", opens(b, next));
    let third = issue(a, "\x00\x00");
    check::that("  a third key issues", third[1..5] != next[1..5]);
    check::that("  the second opens beside it", opens(b, next) && opens(b, third));
    ticket_clock(3 * PERIOD);
    check::that("after skipped periods nothing opens", !opens(b, next) && !opens(b, third));
    let fresh = issue(a, "\x00\x00");
    check::that("  and a new key issues", opens(b, fresh));

    for id in [a, b, c, foreign] { tls::g_conn_free(id); }
    tls::g_ctx_free(shared);
    tls::g_ctx_free(ctx);
    tls::g_ctx_free(other);
}

fn psk_of(id: i64, ticket: const u8[:]) -> u8[>..] {
    var sni: u8[>..] = [];
    tls::g_ticket_open(id, ticket, tls::S_PSK, sni);
    return psk(id);
}
