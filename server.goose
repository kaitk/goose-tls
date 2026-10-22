// The TLS 1.3 server (RFC 8446) that tls::server makes, unless the package's
// C was configured for libssl's (docs/decisions.md): the protocol written
// here, over libcrypto's primitives in shim/server.c, which also owns the
// memory that outlives a call. Each call loads the connection's
// ServerState from C, advances it, and stores it back; secrets stay in C,
// in slots this file names.
//
// Scope: TLS 1.3 only; TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, and
// TLS_CHACHA20_POLY1305_SHA256 in the server's order; X25519MLKEM768 where
// libcrypto has ML-KEM, X25519, P-256, and P-384 when named; ECDSA P-256 and
// RSA-PSS signatures. No client certificates, no early data (it is skipped
// as section 4.2.10 says), no session tickets yet.
namespace tls;

import std;

extern "tlsg_ctx_new" fn g_ctx_new(chain: const u8[:], key: const u8[:]) -> i64;
extern "tlsg_ctx_share" fn g_ctx_share(ctx: i64) -> i64;
extern "tlsg_ctx_free" fn g_ctx_free(ctx: i64);
extern "tlsg_ctx_set_alpn" fn g_ctx_set_alpn(ctx: i64, alpn: const u8[:]) -> bool;
extern "tlsg_ctx_set_groups" fn g_ctx_set_groups(ctx: i64, groups: const u8[:]) -> bool;
extern "tlsg_ctx_set_choose" fn g_ctx_set_choose(ctx: i64);
extern "tlsg_ctx_alpn" fn g_ctx_alpn(ctx: i64, out: u8[>..]&);
extern "tlsg_ctx_groups" fn g_ctx_groups(ctx: i64, out: u8[>..]&);
extern "tlsg_ctx_chain" fn g_ctx_chain(ctx: i64, out: u8[>..]&);
extern "tlsg_ctx_chooses" fn g_ctx_chooses(ctx: i64) -> bool;
extern "tlsg_ctx_scheme" fn g_ctx_scheme(ctx: i64) -> i64;
extern "tlsg_has_group" fn g_has_group(group: i64) -> bool;
extern "tlsg_accept" fn g_accept(ctx: i64) -> i64;
extern "tlsg_conn_free" fn g_conn_free(id: i64);
extern "tlsg_conn_ctx" fn g_conn_ctx(id: i64) -> i64;
extern "tlsg_conn_use" fn g_conn_use(id: i64, ctx: i64) -> bool;
// Copy the state between C and st: last is st.last, whose address marks
// the struct's end, so C needs no copy of its layout.
extern "tlsg_load" fn g_load(id: i64, st: ServerState&, last: u8&);
extern "tlsg_store" fn g_store(id: i64, st: const ServerState&, last: const u8&);
extern "tlsg_feed" fn g_feed(id: i64, data: const u8[:], max: i64) -> i64;
extern "tlsg_in_len" fn g_in_len(id: i64) -> i64;
extern "tlsg_in_peek" fn g_in_peek(id: i64, at: i64, out: u8[:]) -> i64;
extern "tlsg_in_skip" fn g_in_skip(id: i64, n: i64);
extern "tlsg_pending" fn g_pending(id: i64) -> i64;
extern "tlsg_drain" fn g_drain(id: i64, buf: u8[:]) -> i64;
extern "tlsg_out_put" fn g_out_put(id: i64, data: const u8[:]) -> bool;
extern "tlsg_plain_read" fn g_plain_read(id: i64, buf: u8[:]) -> i64;
extern "tlsg_plain_pop" fn g_plain_pop(id: i64, n: i64, buf: u8[:]) -> i64;
extern "tlsg_plain_clear" fn g_plain_clear(id: i64);
extern "tlsg_set_sni" fn g_set_sni(id: i64, name: const u8[:]);
extern "tlsg_sni" fn g_sni(id: i64, out: u8[>..]&);
extern "tlsg_hs_begin" fn g_hs_begin(id: i64, suite: i64) -> bool;
extern "tlsg_hs_drop_transcript" fn g_hs_drop_transcript(id: i64);
extern "tlsg_hs_end" fn g_hs_end(id: i64);
extern "tlsg_tr_update" fn g_tr_update(id: i64, data: const u8[:]) -> bool;
extern "tlsg_tr_hash" fn g_tr_hash(id: i64, out: u8[:]) -> i64;
extern "tlsg_tr_restart" fn g_tr_restart(id: i64) -> bool;
extern "tlsg_tr_hash_with" fn g_tr_hash_with(id: i64, extra: const u8[:], out: u8[:]) -> i64;
extern "tlsg_tr_add_finished" fn g_tr_add_finished(id: i64, slot: i64) -> bool;
extern "tlsg_ticket_issue" fn g_ticket_issue(id: i64, res: i64, nonce: const u8[:], age_add: i64, out: u8[>..]&) -> bool;
extern "tlsg_ticket_open" fn g_ticket_open(id: i64, ticket: const u8[:], psk: i64, sni: u8[>..]&) -> TicketFacts;
extern "tlsg_ticket_now" fn g_ticket_now() -> i64;
extern "tlsg_hello_keep" fn g_hello_keep(id: i64, hello: const u8[:]) -> bool;
extern "tlsg_hello_kept" fn g_hello_kept(id: i64, out: u8[>..]&);
extern "tlsg_ks_extract" fn g_extract(id: i64, dst: i64, salt: i64, ikm: i64) -> bool;
extern "tlsg_ks_expand" fn g_expand(id: i64, dst: i64, src: i64, label: const u8[:], context: const u8[:]) -> bool;
extern "tlsg_ks_finished" fn g_finished(id: i64, dst: i64, src: i64, hash: const u8[:]) -> bool;
extern "tlsg_ks_public" fn g_public(id: i64, slot: i64, out: u8[>..]&);
extern "tlsg_ks_check" fn g_check(id: i64, slot: i64, received: const u8[:]) -> bool;
extern "tlsg_ks_wipe" fn g_wipe(id: i64, slot: i64);
extern "tlsg_kx" fn g_kx(id: i64, group: i64, share: const u8[:], out: u8[>..]&, dst: i64) -> bool;
extern "tlsg_sign" fn g_sign(id: i64, content: const u8[:], out: u8[>..]&) -> bool;
extern "tlsg_random" fn g_random(out: u8[:]) -> bool;
extern "tlsg_rec_keys" fn g_rec_keys(id: i64, dir: i64, slot: i64) -> bool;
extern "tlsg_rec_update" fn g_rec_update(id: i64, dir: i64) -> bool;
extern "tlsg_rec_seal" fn g_seal(id: i64, kind: i64, data: const u8[:]) -> i64;
extern "tlsg_rec_open" fn g_open(id: i64, len: i64) -> i64;
extern "tlsg_rec_seq" fn g_seq(id: i64, dir: i64) -> i64;
extern "tlsg_fail" fn g_fail(reason: i64, text: const u8[:]);
extern "tlsg_clear_errors" fn g_clear_errors();
extern "tlsg_backend" fn g_backend() -> i64;

// Where a connection's handshake is.
let PH_HELLO = 0;      // waiting for the ClientHello
let PH_RETRY = 1;      // a HelloRetryRequest sent, waiting for the second ClientHello
let PH_FINISHED = 2;   // the server's flight sent, waiting for the client's Finished
let PH_OPEN = 3;       // the handshake done
let PH_FAILED = 4;

// Early data the server skips, never accepting it (section 4.2.10): records
// that don't decrypt under the handshake key, or after a HelloRetryRequest,
// records of type application_data. At most SKIP_MAX bytes.
let SKIP_UNDECRYPTABLE = 1;
let SKIP_ENCRYPTED = 2;
let SKIP_MAX = 16384;

// The largest ClientHello taken, its header and rustls's limit for a
// handshake message's body (MAX_HANDSHAKE_SIZE): tlsfuzzer's ClientHellos of
// thousands of extensions pass 16 KiB; and bytes fed and not yet read, which
// bounds what a peer can make a connection hold.
let MAX_HELLO = 4 + 0xffff;
let MAX_FED = 1 << 18;

// Record content types.
let CT_CCS = 20;
let CT_ALERT = 21;
let CT_HANDSHAKE = 22;
let CT_DATA = 23;

// Handshake message types.
let HS_CLIENT_HELLO = 1;
let HS_SERVER_HELLO = 2;
let HS_ENCRYPTED_EXTENSIONS = 8;
let HS_CERTIFICATE = 11;
let HS_CERTIFICATE_VERIFY = 15;
let HS_FINISHED = 20;
let HS_KEY_UPDATE = 24;

let TLS13 = 0x0304;
let SUITES = [0x1301, 0x1302, 0x1303];
let GROUP_X25519MLKEM768 = 0x11ec;
let GROUP_X25519 = 0x001d;
let GROUP_P256 = 0x0017;
let GROUP_P384 = 0x0018;

// Directions, as shim/server.c numbers them.
let DIR_READ = 0;
let DIR_WRITE = 1;

// Handshake secret slots in C.
let S_EARLY = 0;
let S_DERIVED = 1;
let S_HANDSHAKE = 2;
let S_MASTER = 3;
let S_CLIENT_HS = 4;
let S_SERVER_HS = 5;
let S_CLIENT_AP = 6;
let S_SERVER_AP = 7;
let S_SERVER_FINISHED = 8;
let S_CLIENT_FINISHED = 9;
let S_SHARED = 10;
let S_PSK = 11;
let S_RESUMPTION = 12;

// Session tickets (section 4.6.1): two after a full handshake and one after
// a resumption, as OpenSSL sends them, each for 7,200 seconds, OpenSSL's
// default lifetime; a ticket's key lives as shim/server.c's TICKET_PERIOD
// says.
let TICKET_LIFETIME = 7200;
let PSK_DHE_KE = 1;
let HS_NEW_SESSION_TICKET = 4;

// What an opened ticket holds besides its PSK, as shim/server.c's
// tlsg_ticket_open returns it; suite 0 when it didn't open.
struct TicketFacts { suite: i64, issued: i64, age_add: i64 }

// AES-GCM's confidentiality limit, as rustls's TLS suites take it: the
// server updates its keys before sealing this many records under one
// (section 5.5).
let AES_GCM_RECORDS = 1 << 24;
// As BoringSSL bounds them: KeyUpdates in a row without application data,
// empty application data records in a row, and user_canceled alerts in a
// row, each of which a peer could send without end.
let MAX_UPDATES = 32;
let MAX_EMPTY = 32;
let MAX_WARNINGS = 4;

// What a step returns besides the API's statuses: go on.
let AGAIN = 1;

// SHA-256("HelloRetryRequest"), a HelloRetryRequest's random (section 4.1.3).
let HRR_RANDOM = "\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c";
// The hash of the empty string, for Derive-Secret(., "derived", "").
let EMPTY_SHA256 = "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55";
let EMPTY_SHA384 = "\x38\xb0\x60\xa7\x51\xac\x96\x38\x4c\xd9\x32\x7e\xb1\xb1\xe3\x6a\x21\xfd\xb7\x11\x14\xbe\x07\x43\x4c\x0c\xc7\xbf\x63\xf6\xe1\xda\x27\x4e\xde\xbf\xe7\x6f\x65\xfb\xd5\x1a\xd2\xf1\x48\x98\xb9\x5b";
let CCS_RECORD = "\x14\x03\x03\x00\x01\x01";

// A connection's state between calls. Every field's default is zero, as C
// keeps it for a new connection.
struct ServerState {
    phase: i64,
    suite: i64,
    group: i64,
    // The chosen ALPN protocol's position in the context's list, plus 1.
    alpn: i64,
    // HELLO was returned, and the program may call use_context.
    paused: bool,
    // The pause is over, or the context doesn't choose.
    chosen: bool,
    ccs_sent: bool,
    ccs_seen: bool,
    // The handshake resumed a session from a ticket.
    resumed: bool,
    // The server's records are encrypted from here on.
    sealing: bool,
    skip: i64,
    skip_left: i64,
    peer_closed: bool,
    closed: bool,
    updates: i64,
    update_owed: bool,
    empties: i64,
    warnings: i64,
    // The ClientHello's records so far: where the next starts in the bytes
    // fed, the message's bytes in them, its length once known, and its
    // first four bytes.
    scan_at: i64,
    scan_have: i64,
    scan_need: i64,
    scan_head: u8[..4],
    // An encrypted handshake message that began in an earlier record.
    hs: u8[..64],
    last: u8,
}

fn load(id: i64) -> ServerState {
    var st = ServerState { .. };
    g_load(id, st, st.last);
    return st;
}

fn store(id: i64, st: ServerState&) { g_store(id, st, st.last); }

fn hash_len(suite: i64) -> i64 { if suite == 0x1302 { 48 } else { 32 } }

fn empty_hash(suite: i64) -> const u8[:] { if suite == 0x1302 { EMPTY_SHA384 } else { EMPTY_SHA256 } }

// Fails the connection: raises reason with text for error_text, queues the
// alert unless it is -1, discards what the handshake and the plaintext
// held, and returns FAILED.
fn fail(id: i64, st: ServerState&, alert: i64, reason: i64, text: const u8[:]) -> i64 {
    g_fail(reason, text);
    if alert >= 0 && !st.closed {
        if st.sealing {
            var a: u8[2] = [2, alert as! u8];
            g_seal(id, CT_ALERT, a);
        } else {
            var r: u8[7] = [21, 3, 3, 0, 2, 2, alert as! u8];
            g_out_put(id, r);
        }
    }
    st.phase = PH_FAILED;
    st.closed = true;
    g_plain_clear(id);
    g_hs_end(id);
    return FAILED;
}

fn fail_with(id: i64, st: ServerState&, why: Refusal) -> i64 { fail(id, st, why.alert, why.reason, why.text) }

// A received alert: close_notify closes the peer's side, user_canceled is
// passed over, and any other fails the connection with no alert of ours.
fn alert(id: i64, st: ServerState&, level: i64, desc: i64) -> i64 {
    if desc == ALERT_CLOSE_NOTIFY {
        st.peer_closed = true;
        return CLOSED;
    }
    if desc == ALERT_USER_CANCELED {
        st.warnings += 1;
        guard st.warnings <= MAX_WARNINGS else {
            return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_UNEXPECTED_RECORD, "too many user_canceled alerts");
        }
        return AGAIN;
    }
    return fail(id, st, -1, R_ALERT + desc, "");
}

// The header of the record at the front of the bytes fed: its type and
// length, or false when five bytes haven't arrived.
fn header(id: i64, at: i64) -> i64, i64, bool {
    var h: u8[5] = [0; 5];
    guard g_in_peek(id, at, h) == 5 else { return 0, 0, false; }
    return h[0], (h[3] as i64) << 8 | h[4], true;
}

// Advances the handshake as far as the bytes fed allow: 0 once it is done,
// or WANT_INPUT, HELLO, CLOSED, or FAILED.
fn advance(id: i64, st: ServerState&) -> i64 {
    loop {
        if st.phase == PH_OPEN { return 0; }
        if st.phase == PH_FAILED { return FAILED; }
        let s = step(id, st);
        guard s == AGAIN else { return s; }
    }
}

// Takes one unit of what was fed: a ClientHello, or a record.
fn step(id: i64, st: ServerState&) -> i64 {
    if st.peer_closed { return CLOSED; }
    if st.phase == PH_HELLO || st.phase == PH_RETRY { return hello_step(id, st); }
    return record_step(id, st);
}

// Before a ClientHello: the records that may come ahead of it, then the
// ClientHello itself.
fn hello_step(id: i64, st: ServerState&) -> i64 {
    if st.scan_at == 0 {
        let kind, len, ok = header(id, 0);
        guard ok else { return WANT_INPUT; }
        if kind != CT_HANDSHAKE { return front_record(id, st, kind, len); }
    }
    let s = scan_hello(id, st);
    guard s == AGAIN else { return s; }
    var msg: u8[>..] = [];
    copy_hello(id, st, msg);
    return serve(id, st, msg);
}

// A record ahead of a ClientHello that isn't part of it.
fn front_record(id: i64, st: ServerState&, kind: i64, len: i64) -> i64 {
    if st.phase == PH_HELLO {
        var head: u8[5] = [0; 5];
        g_in_peek(id, 0, head);
        if head[..4] == "GET " || head == "POST " || head == "HEAD " || head[..4] == "PUT " {
            return fail(id, st, -1, R_HTTP_REQUEST, "");
        }
    }
    if kind == CT_DATA && st.phase == PH_RETRY && st.skip == SKIP_ENCRYPTED {
        guard len <= 16384 + 256 else { return fail(id, st, ALERT_RECORD_OVERFLOW, R_ENCRYPTED_LENGTH_TOO_LONG, ""); }
        guard g_in_len(id) >= 5 + len else { return WANT_INPUT; }
        guard len <= st.skip_left else { return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_TOO_MUCH_EARLY_DATA, ""); }
        st.skip_left -= len;
        g_in_skip(id, 5 + len);
        return AGAIN;
    }
    guard kind == CT_CCS || kind == CT_ALERT else {
        return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_UNEXPECTED_RECORD, "a record before the ClientHello");
    }
    guard len <= 16384 else { return fail(id, st, ALERT_RECORD_OVERFLOW, R_PACKET_LENGTH_TOO_LONG, ""); }
    guard g_in_len(id) >= 5 + len else { return WANT_INPUT; }
    return plain_record(id, st, kind, len);
}

// An unencrypted change_cipher_spec or alert record, whole in the bytes fed.
// A change_cipher_spec is the single byte 1, once, between the first
// ClientHello and the client's Finished (section 5; a second fails, as
// tlsfuzzer expects).
fn plain_record(id: i64, st: ServerState&, kind: i64, len: i64) -> i64 {
    var body: u8[2] = [0; 2];
    if kind == CT_CCS {
        guard (st.phase == PH_RETRY || st.phase == PH_FINISHED) && !st.ccs_seen else {
            return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_UNEXPECTED_RECORD, "change_cipher_spec");
        }
        g_in_peek(id, 5, body[..1]);
        guard len == 1 && body[0] == 1 else {
            return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_BAD_CHANGE_CIPHER_SPEC, "");
        }
        g_in_skip(id, 6);
        st.ccs_seen = true;
        return AGAIN;
    }
    guard len > 0 else { return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_BAD_LENGTH, "an empty alert record"); }
    guard len == 2 else { return fail(id, st, ALERT_DECODE_ERROR, R_BAD_LENGTH, "an alert"); }
    g_in_peek(id, 5, body);
    g_in_skip(id, 7);
    return alert(id, st, body[0], body[1]);
}

// Counts the records of a ClientHello as they arrive, without copying them,
// and returns AGAIN once the whole message has come: one handshake message,
// alone in records of its own, which end with it (section 5.1).
fn scan_hello(id: i64, st: ServerState&) -> i64 {
    loop {
        if st.scan_need > 0 && st.scan_have == st.scan_need { return AGAIN; }
        let kind, len, ok = header(id, st.scan_at);
        guard ok else { return WANT_INPUT; }
        guard kind == CT_HANDSHAKE else {
            return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_UNEXPECTED_RECORD, "a record inside the ClientHello");
        }
        guard len > 0 else { return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_BAD_LENGTH, "an empty handshake record"); }
        guard len <= 16384 else { return fail(id, st, ALERT_RECORD_OVERFLOW, R_PACKET_LENGTH_TOO_LONG, ""); }
        guard g_in_len(id) >= st.scan_at + 5 + len else { return WANT_INPUT; }
        if st.scan_head.len < 4 {
            var head: u8[4] = [0; 4];
            let n = g_in_peek(id, st.scan_at + 5, head[..min(4 - st.scan_head.len, len)]);
            for b in head[..n] { st.scan_head.push(b); }
            if st.scan_head.len == 4 {
                guard st.scan_head[0] == HS_CLIENT_HELLO else {
                    return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_UNEXPECTED_MESSAGE, "not a ClientHello");
                }
                st.scan_need = 4 + ((st.scan_head[1] as i64) << 16 | (st.scan_head[2] as i64) << 8 | st.scan_head[3]);
                guard st.scan_need <= MAX_HELLO else {
                    return fail(id, st, ALERT_ILLEGAL_PARAMETER, R_EXCESSIVE_MESSAGE_SIZE, "ClientHello");
                }
            }
        }
        st.scan_have += len;
        st.scan_at += 5 + len;
        guard st.scan_need == 0 || st.scan_have <= st.scan_need else {
            return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_NOT_ON_RECORD_BOUNDARY, "bytes after the ClientHello");
        }
    }
}

// Copies the scanned ClientHello's bytes, without the record headers, into
// msg.
fn copy_hello(id: i64, st: ServerState&, msg: u8[>..]&) {
    var at = 0;
    while at < st.scan_at {
        let kind, len, ok = header(id, at);
        let end = msg.len;
        msg.resize(end + len, 0);
        g_in_peek(id, at + 5, msg[end..]);
        at += 5 + len;
    }
}

// Drops the scanned ClientHello from the bytes fed.
fn consume_hello(id: i64, st: ServerState&) {
    g_in_skip(id, st.scan_at);
    st.scan_at = 0;
    st.scan_have = 0;
    st.scan_need = 0;
    st.scan_head.clear();
}

// The server's groups in order of preference: the context's, or by default
// X25519MLKEM768 where libcrypto has it, X25519, and P-256.
fn server_groups(ctx: i64, out: u8[>..]&) {
    g_ctx_groups(ctx, out);
    if out.len > 0 { return; }
    if g_has_group(GROUP_X25519MLKEM768) { put16(out, GROUP_X25519MLKEM768); }
    put16(out, GROUP_X25519);
    put16(out, GROUP_P256);
}

// What a ClientHello negotiates.
struct Choice { suite: i64, group: i64, retry: bool, alpn: i64 }

// Chooses the suite, group, and ALPN protocol for h, or refuses it. The
// group is the first of the server's for which the client sent a share, or
// else the first the client supports, which needs a HelloRetryRequest.
fn negotiate(id: i64, h: Hello&, c: Choice&) -> Refusal {
    let ctx = g_conn_ctx(id);
    // legacy_version is 0x0303 in a TLS 1.3 ClientHello (section 4.1.2);
    // below it, the client is broken, as tlsfuzzer and OpenSSL take it.
    guard h.has_versions && has16(h.versions, TLS13) && h.legacy_version >= 0x0303 else {
        return refuse(ALERT_PROTOCOL_VERSION, R_UNSUPPORTED_PROTOCOL, "");
    }
    guard h.compression.len == 1 && h.compression[0] == 0 else {
        return refuse(ALERT_ILLEGAL_PARAMETER, R_INVALID_COMPRESSION, "");
    }
    guard h.has_sigalgs else { return refuse(ALERT_MISSING_EXTENSION, R_MISSING_SIGALGS, ""); }
    guard h.has_groups && h.has_shares else { return refuse(ALERT_MISSING_EXTENSION, R_MISSING_GROUPS, ""); }
    guard shares_consistent(h.shares, h.groups) else {
        return refuse(ALERT_ILLEGAL_PARAMETER, R_BAD_KEY_SHARE, "key_share against supported_groups");
    }
    c.suite = 0;
    for s in SUITES {
        if c.suite == 0 && has16(h.suites, s) { c.suite = s; }
    }
    guard c.suite != 0 else { return refuse(ALERT_HANDSHAKE_FAILURE, R_NO_SHARED_CIPHER, ""); }
    guard has16(h.sigalgs, g_ctx_scheme(ctx)) else {
        return refuse(ALERT_HANDSHAKE_FAILURE, R_NO_SUITABLE_SIGALG, "");
    }
    var groups: u8[>..] = [];
    server_groups(ctx, groups);
    c.group = 0;
    c.retry = false;
    var i = 0;
    while i < groups.len && c.group == 0 {
        let g = at16(groups, i);
        let share, has = share_for(h.shares, g);
        if has { c.group = g; }
        i += 2;
    }
    i = 0;
    while i < groups.len && c.group == 0 {
        let g = at16(groups, i);
        if has16(h.groups, g) {
            c.group = g;
            c.retry = true;
        }
        i += 2;
    }
    guard c.group != 0 else { return refuse(ALERT_HANDSHAKE_FAILURE, R_NO_SHARED_GROUPS, ""); }
    c.alpn = 0;
    if h.has_alpn {
        var ours: u8[>..] = [];
        g_ctx_alpn(ctx, ours);
        var r = reader(ours);
        var k = 0;
        while left(r) > 0 && c.alpn == 0 {
            k += 1;
            let name = vec8(ours, r);
            var o = reader(h.alpn);
            while left(o) > 0 {
                if vec8(h.alpn, o) == name { c.alpn = k; }
            }
        }
        guard c.alpn != 0 || ours.len == 0 else {
            return refuse(ALERT_NO_APPLICATION_PROTOCOL, R_NO_APPLICATION_PROTOCOL, "");
        }
    }
    return ok_hello();
}

// Whether the second ClientHello repeats the first, as section 4.1.2 asks:
// all but key_share, early_data, cookie, pre_shared_key, and padding.
fn same_hello(a: Hello&, b: Hello&) -> bool {
    guard a.random == b.random && a.session_id == b.session_id && a.suites == b.suites &&
          a.compression == b.compression else { return false; }
    var ra = reader(a.extensions);
    var rb = reader(b.extensions);
    loop {
        let ea = next_kept(a.extensions, ra);
        let eb = next_kept(b.extensions, rb);
        guard ea == eb else { return false; }
        if ea.len == 0 { return true; }
    }
}

// The next extension of d, type and body, that a retried ClientHello must
// repeat; empty at the end.
fn next_kept(d: const u8[:], r: Rd&) -> const u8[:] {
    while left(r) > 0 {
        let at = r.pos;
        let kind = get16(d, r);
        vec16(d, r);
        if r.bad { return d[..0]; }
        if kind != EXT_KEY_SHARE && kind != EXT_EARLY_DATA && kind != EXT_COOKIE &&
           kind != EXT_PRE_SHARED_KEY && kind != EXT_PADDING {
            return d[at..r.pos];
        }
    }
    return d[..0];
}

// A ClientHello has arrived whole: refuses it, pauses for the program to
// choose a context, asks for another, or answers it.
fn serve(id: i64, st: ServerState&, msg: const u8[:]) -> i64 {
    var h = Hello { .. };
    let why = parse_hello(msg, h);
    guard why.alert < 0 else { return fail_with(id, st, why); }
    if st.phase == PH_HELLO && !st.chosen && g_ctx_chooses(g_conn_ctx(id)) {
        g_set_sni(id, h.sni);
        st.chosen = true;
        st.paused = true;
        return HELLO;
    }
    st.paused = false;
    st.chosen = true;
    var c = Choice { suite: 0, group: 0, retry: false, alpn: 0 };
    let refusal = negotiate(id, h, c);
    guard refusal.alert < 0 else { return fail_with(id, st, refusal); }
    g_set_sni(id, h.sni);
    if st.phase == PH_RETRY {
        var first: u8[>..] = [];
        g_hello_kept(id, first);
        var h1 = Hello { .. };
        parse_hello(first, h1);
        guard same_hello(h1, h) && !h.early_data && !c.retry && c.group == st.group && c.suite == st.suite else {
            return fail(id, st, ALERT_ILLEGAL_PARAMETER, R_BAD_PACKET, "the second ClientHello");
        }
        let share, has = share_for(h.shares, c.group);
        guard has && h.shares.len == 4 + share.len else {
            return fail(id, st, ALERT_ILLEGAL_PARAMETER, R_BAD_KEY_SHARE, "the second ClientHello's key_share");
        }
    } else {
        guard g_hs_begin(id, c.suite) else { return fail(id, st, ALERT_INTERNAL_ERROR, R_INTERNAL, "the transcript"); }
        if h.early_data {
            st.skip = if c.retry { SKIP_ENCRYPTED } else { SKIP_UNDECRYPTABLE };
            st.skip_left = SKIP_MAX;
        }
    }
    // A ticket is taken once the context is chosen and the suite known, and
    // before the ClientHello enters the transcript, whose binder covers it
    // only up to its binders. A HelloRetryRequest leaves it to the second.
    let psk = if c.retry { -1 } else { resume(id, st, h, c.suite) };
    guard psk != FAILED else { return FAILED; }
    guard g_tr_update(id, msg) else { return fail(id, st, ALERT_INTERNAL_ERROR, R_INTERNAL, "the transcript"); }
    consume_hello(id, st);
    st.suite = c.suite;
    st.group = c.group;
    st.alpn = c.alpn;
    st.resumed = psk >= 0;
    if c.retry { return retry(id, st, h); }
    return answer(id, st, h, psk);
}

// The pre_shared_key identity the server resumes from (section 4.2.11): the
// first ticket that opens under this context and fits the suite's hash, its
// lifetime from its authenticated issue time, and the SNI name. -1 for none,
// and so a full handshake; or FAILED once the chosen ticket's binder doesn't
// verify. Leaves the early secret from its PSK in S_EARLY.
fn resume(id: i64, st: ServerState&, h: Hello&, suite: i64) -> i64 {
    guard h.has_psk else { return -1; }
    guard h.has_psk_modes else {
        return fail(id, st, ALERT_MISSING_EXTENSION, R_MISSING_PSK_KEX_MODES, "");
    }
    guard find(h.psk_modes, "\x01") >= 0 else { return -1; }
    var r = reader(h.psk);
    let ids = vec16(h.psk, r);
    let binders = vec16(h.psk, r);
    var each = reader(ids);
    let now = g_ticket_now();
    var chosen = -1;
    var k = 0;
    while left(each) > 0 && chosen < 0 {
        let ticket = vec16(ids, each);
        get32(ids, each);
        var sni: u8[>..] = [];
        let f = g_ticket_open(id, ticket, S_PSK, sni);
        if f.suite != 0 && hash_len(f.suite) == hash_len(suite) && f.issued <= now &&
           now - f.issued < TICKET_LIFETIME && sni == h.sni {
            chosen = k;
        } else {
            g_wipe(id, S_PSK);
        }
        k += 1;
    }
    guard chosen >= 0 else { return -1; }
    var b = reader(binders);
    var binder: const u8[:] = binders[..0];
    for j in chosen + 1 { binder = vec8(binders, b); }
    var hb: u8[48] = [0; 48];
    let n = g_tr_hash_with(id, h.raw[..h.binders_at], hb);
    let ok = n > 0 && g_extract(id, S_EARLY, -1, S_PSK) &&
             derive(id, S_DERIVED, S_EARLY, "res binder", empty_hash(suite)) &&
             g_finished(id, S_SERVER_FINISHED, S_DERIVED, hb[..n]) && g_check(id, S_SERVER_FINISHED, binder);
    for s in [S_PSK, S_DERIVED, S_SERVER_FINISHED] { g_wipe(id, s); }
    guard ok else { return fail(id, st, ALERT_DECRYPT_ERROR, R_BINDER_DOES_NOT_VERIFY, ""); }
    return chosen;
}

// Sends a HelloRetryRequest for st.group (section 4.1.4).
fn retry(id: i64, st: ServerState&, h: Hello&) -> i64 {
    guard g_tr_restart(id) && g_hello_keep(id, h.raw) else {
        return fail(id, st, ALERT_INTERNAL_ERROR, R_INTERNAL, "the transcript");
    }
    var m: u8[>..] = [];
    server_hello(m, HRR_RANDOM, h.session_id, st.suite, st.group, "", -1);
    g_tr_update(id, m);
    send_plain(id, CT_HANDSHAKE, m);
    if h.session_id.len > 0 && !st.ccs_sent {
        g_out_put(id, CCS_RECORD);
        st.ccs_sent = true;
    }
    st.phase = PH_RETRY;
    return AGAIN;
}

// A ServerHello, or a HelloRetryRequest when share is empty: then key_share
// names only the group. psk is the pre_shared_key identity the server
// resumes from, or -1.
fn server_hello(m: u8[>..]&, random: const u8[:], session_id: const u8[:], suite: i64, group: i64,
                share: const u8[:], psk: i64) {
    put8(m, HS_SERVER_HELLO);
    let body = begin_vec(m, 3);
    put16(m, 0x0303);
    m.append(random);
    put8(m, session_id.len);
    m.append(session_id);
    put16(m, suite);
    put8(m, 0);
    let exts = begin_vec(m, 2);
    put16(m, EXT_SUPPORTED_VERSIONS);
    put16(m, 2);
    put16(m, TLS13);
    put16(m, EXT_KEY_SHARE);
    let ks = begin_vec(m, 2);
    put16(m, group);
    if share.len > 0 {
        let k = begin_vec(m, 2);
        m.append(share);
        end_vec(m, k, 2);
    }
    end_vec(m, ks, 2);
    if psk >= 0 {
        put16(m, EXT_PRE_SHARED_KEY);
        put16(m, 2);
        put16(m, psk);
    }
    end_vec(m, exts, 2);
    end_vec(m, body, 3);
}

// Appends unencrypted records of kind holding data.
fn send_plain(id: i64, kind: i64, data: const u8[:]) {
    var at = 0;
    while at < data.len {
        let n = min(16384, data.len - at);
        var hdr: u8[5] = [kind as! u8, 3, 3, (n >> 8) as! u8, n as! u8];
        g_out_put(id, hdr);
        g_out_put(id, data[at..at + n]);
        at += n;
    }
}

// Seals data as records of kind: false when sealing fails.
fn send_sealed(id: i64, kind: i64, data: const u8[:]) -> bool {
    var at = 0;
    while at < data.len {
        let n = min(16384, data.len - at);
        guard g_seal(id, kind, data[at..at + n]) >= 0 else { return false; }
        at += n;
    }
    return true;
}

// Derive-Secret(slot[src], label, transcript hash) into slot[dst].
fn derive(id: i64, dst: i64, src: i64, label: const u8[:], hash: const u8[:]) -> bool {
    g_expand(id, dst, src, label, hash)
}

// The transcript's hash so far into buf, and its length.
fn transcript(id: i64, buf: u8[:]) -> const u8[:] {
    let n = g_tr_hash(id, buf);
    return buf[..n];
}

// Answers the ClientHello with the server's flight (section 4): ServerHello,
// then under the handshake keys EncryptedExtensions, Certificate,
// CertificateVerify, and Finished, or for a resumption from psk, the
// pre_shared_key identity, no Certificate or CertificateVerify. Then derives
// what the client's Finished needs and the application keys, so that the
// transcript can go.
fn answer(id: i64, st: ServerState&, h: Hello&, psk: i64) -> i64 {
    let ctx = g_conn_ctx(id);
    let client_share, has = share_for(h.shares, st.group);
    var share: u8[>..] = [];
    guard has && g_kx(id, st.group, client_share, share, S_SHARED) else {
        return fail(id, st, ALERT_ILLEGAL_PARAMETER, R_BAD_KEY_SHARE, "");
    }
    var random: u8[32] = [0; 32];
    guard g_random(random) else { return fail(id, st, ALERT_INTERNAL_ERROR, R_INTERNAL, "random bytes"); }
    var m: u8[>..] = [];
    server_hello(m, random, h.session_id, st.suite, st.group, share, psk);
    g_tr_update(id, m);
    send_plain(id, CT_HANDSHAKE, m);
    if h.session_id.len > 0 && !st.ccs_sent {
        g_out_put(id, CCS_RECORD);
        st.ccs_sent = true;
    }
    guard handshake_keys(id, st.suite, psk >= 0) else {
        return fail(id, st, ALERT_INTERNAL_ERROR, R_INTERNAL, "the handshake keys");
    }
    st.sealing = true;
    var hb: u8[48] = [0; 48];

    var flight: u8[>..] = [];
    let ee = flight.len;
    put8(flight, HS_ENCRYPTED_EXTENSIONS);
    let ee_body = begin_vec(flight, 3);
    let ee_exts = begin_vec(flight, 2);
    if st.alpn > 0 {
        let name = alpn_name(ctx, st.alpn);
        put16(flight, EXT_ALPN);
        let ext = begin_vec(flight, 2);
        let list = begin_vec(flight, 2);
        put8(flight, name.len);
        flight.append(name);
        end_vec(flight, list, 2);
        end_vec(flight, ext, 2);
    }
    end_vec(flight, ee_exts, 2);
    end_vec(flight, ee_body, 3);
    if psk >= 0 {
        g_tr_update(id, flight[ee..]);
    } else {
        guard certificate(id, st, flight, ee) else {
            return fail(id, st, ALERT_INTERNAL_ERROR, R_INTERNAL, "the signature");
        }
    }
    guard server_finished(id, st.suite, flight) && send_sealed(id, CT_HANDSHAKE, flight) else {
        return fail(id, st, ALERT_INTERNAL_ERROR, R_INTERNAL, "the server's Finished");
    }
    guard application_keys(id, st.suite) else {
        return fail(id, st, ALERT_INTERNAL_ERROR, R_INTERNAL, "the application keys");
    }
    st.phase = PH_FINISHED;
    return AGAIN;
}

// Appends Certificate and CertificateVerify to flight, after the
// EncryptedExtensions at ee, and the flight from ee to the transcript.
fn certificate(id: i64, st: ServerState&, flight: u8[>..]&, ee: i64) -> bool {
    let ctx = g_conn_ctx(id);
    var hb: u8[48] = [0; 48];
    put8(flight, HS_CERTIFICATE);
    let cert_body = begin_vec(flight, 3);
    put8(flight, 0);
    let list = begin_vec(flight, 3);
    var chain: u8[>..] = [];
    g_ctx_chain(ctx, chain);
    var r = reader(chain);
    while left(r) > 0 {
        let der = vec24(chain, r);
        put24(flight, der.len);
        flight.append(der);
        put16(flight, 0);
    }
    end_vec(flight, list, 3);
    end_vec(flight, cert_body, 3);
    g_tr_update(id, flight[ee..]);

    // CertificateVerify signs 64 spaces, a context string, a zero byte, and
    // the transcript's hash (section 4.4.3).
    let h2 = transcript(id, hb);
    var content: u8[>..] = [];
    for i in 64 { content.push(32); }
    content.append("TLS 1.3, server CertificateVerify");
    content.push(0);
    content.append(h2);
    let cv = flight.len;
    put8(flight, HS_CERTIFICATE_VERIFY);
    let cv_body = begin_vec(flight, 3);
    put16(flight, g_ctx_scheme(ctx));
    let sig = begin_vec(flight, 2);
    guard g_sign(id, content, flight) else { return false; }
    end_vec(flight, sig, 2);
    end_vec(flight, cv_body, 3);
    return g_tr_update(id, flight[cv..]);
}

// The key schedule (RFC 8446, section 7.1), in three steps of the server's
// flight. Each derives into C's slots and reads the transcript there.

// Once the ServerHello is in the transcript and the shared secret in
// S_SHARED: the handshake secrets, and the handshake keys each way. The
// early secret is from no PSK, unless resumed, when S_EARLY has it from the
// ticket's (resume).
fn handshake_keys(id: i64, suite: i64, resumed: bool) -> bool {
    var hb: u8[48] = [0; 48];
    let ok = (resumed || g_extract(id, S_EARLY, -1, -1)) &&
             derive(id, S_DERIVED, S_EARLY, "derived", empty_hash(suite)) &&
             g_extract(id, S_HANDSHAKE, S_DERIVED, S_SHARED);
    g_wipe(id, S_SHARED);
    g_wipe(id, S_EARLY);
    let h = transcript(id, hb);
    return ok && h.len > 0 && derive(id, S_CLIENT_HS, S_HANDSHAKE, "c hs traffic", h) &&
           derive(id, S_SERVER_HS, S_HANDSHAKE, "s hs traffic", h) &&
           g_rec_keys(id, DIR_WRITE, S_SERVER_HS) && g_rec_keys(id, DIR_READ, S_CLIENT_HS);
}

// Once the CertificateVerify is in the transcript: appends the server's
// Finished message to flight and to the transcript.
fn server_finished(id: i64, suite: i64, flight: u8[>..]&) -> bool {
    var hb: u8[48] = [0; 48];
    guard g_finished(id, S_SERVER_FINISHED, S_SERVER_HS, transcript(id, hb)) else { return false; }
    let fin = flight.len;
    put8(flight, HS_FINISHED);
    put24(flight, hash_len(suite));
    g_public(id, S_SERVER_FINISHED, flight);
    return g_tr_update(id, flight[fin..]);
}

// Once the server's Finished is in the transcript: the client's Finished
// will cover exactly this transcript, so what it must hold, and the
// application secrets, are known now, and the server sends under its
// application key. The resumption master secret covers the client's
// Finished too, which is known now as well; it waits in S_RESUMPTION for the
// tickets. Wipes the rest of the handshake's secrets and frees the
// transcript.
fn application_keys(id: i64, suite: i64) -> bool {
    var hb: u8[48] = [0; 48];
    let h = transcript(id, hb);
    var ok = h.len > 0 && derive(id, S_DERIVED, S_HANDSHAKE, "derived", empty_hash(suite)) &&
             g_extract(id, S_MASTER, S_DERIVED, -1) && derive(id, S_CLIENT_AP, S_MASTER, "c ap traffic", h) &&
             derive(id, S_SERVER_AP, S_MASTER, "s ap traffic", h) &&
             g_finished(id, S_CLIENT_FINISHED, S_CLIENT_HS, h) && g_rec_keys(id, DIR_WRITE, S_SERVER_AP);
    var hr: u8[48] = [0; 48];
    ok = ok && g_tr_add_finished(id, S_CLIENT_FINISHED);
    let with_finished = transcript(id, hr);
    ok = ok && with_finished.len > 0 && derive(id, S_RESUMPTION, S_MASTER, "res master", with_finished);
    for s in [S_DERIVED, S_HANDSHAKE, S_MASTER, S_SERVER_HS, S_CLIENT_HS, S_SERVER_AP, S_SERVER_FINISHED] {
        g_wipe(id, s);
    }
    g_hs_drop_transcript(id);
    return ok;
}

// The k-th protocol, from 1, in the context's ALPN list.
fn alpn_name(ctx: i64, k: i64) -> u8[>..] {
    var list: u8[>..] = [];
    g_ctx_alpn(ctx, list);
    var r = reader(list);
    var name: const u8[:] = list[..0];
    for i in k { name = vec8(list, r); }
    var out: u8[>..] = [];
    out.append(name);
    return out;
}

// After the server's flight: one record, encrypted unless it is a
// change_cipher_spec or an alert ahead of the client's Finished.
fn record_step(id: i64, st: ServerState&) -> i64 {
    let kind, len, ok = header(id, 0);
    guard ok else { return WANT_INPUT; }
    if kind == CT_DATA {
        guard len <= 16384 + 256 else { return fail(id, st, ALERT_RECORD_OVERFLOW, R_ENCRYPTED_LENGTH_TOO_LONG, ""); }
    } else {
        guard st.phase == PH_FINISHED && (kind == CT_CCS || kind == CT_ALERT) else {
            return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_UNEXPECTED_RECORD, "");
        }
        guard len <= 16384 else { return fail(id, st, ALERT_RECORD_OVERFLOW, R_PACKET_LENGTH_TOO_LONG, ""); }
    }
    guard g_in_len(id) >= 5 + len else { return WANT_INPUT; }
    if kind != CT_DATA { return plain_record(id, st, kind, len); }
    let r = g_open(id, len);
    if r == -1 {
        if st.skip == SKIP_UNDECRYPTABLE && len <= st.skip_left {
            st.skip_left -= len;
            g_in_skip(id, 5 + len);
            return AGAIN;
        }
        return fail(id, st, ALERT_BAD_RECORD_MAC, R_DECRYPTION_FAILED, "");
    }
    if r == -2 { return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_BAD_RECORD_TYPE, "a record with no content type"); }
    if r == -3 { return fail(id, st, ALERT_RECORD_OVERFLOW, R_DATA_LENGTH_TOO_LONG, ""); }
    st.skip = 0;
    let inner = r >> 32;
    let n = r & 0xffffffff;
    // A handshake message split across records admits no other content
    // between its pieces (section 5.1).
    guard inner == CT_HANDSHAKE || st.hs.len == 0 else {
        return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_UNEXPECTED_RECORD, "a record inside a handshake message");
    }
    if inner == CT_DATA {
        guard st.phase == PH_OPEN else {
            return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_UNEXPECTED_RECORD, "data before the client's Finished");
        }
        st.updates = 0;
        st.warnings = 0;
        st.empties = if n == 0 { st.empties + 1 } else { 0 };
        guard st.empties <= MAX_EMPTY else {
            return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_UNEXPECTED_RECORD, "too many empty records");
        }
        return AGAIN;
    }
    if inner == CT_ALERT {
        guard n > 0 else { return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_BAD_LENGTH, "an empty alert record"); }
        guard n == 2 else { return fail(id, st, ALERT_DECODE_ERROR, R_BAD_LENGTH, "an alert"); }
        var a: u8[2] = [0; 2];
        g_plain_pop(id, 2, a);
        return alert(id, st, a[0], a[1]);
    }
    guard inner == CT_HANDSHAKE else { return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_UNEXPECTED_RECORD, ""); }
    guard n > 0 else { return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_BAD_LENGTH, "an empty handshake record"); }
    var got: u8[>..] = [];
    got.resize(n, 0);
    g_plain_pop(id, n, got);
    // The messages the server takes here are at most 52 bytes; a longer one
    // is still judged by its header, as handshake_messages would.
    if st.hs.len + n > st.hs.cap {
        var head: u8[4] = [0; 4];
        for i in 4 { head[i] = if i < st.hs.len { st.hs[i] } else { got[i - st.hs.len] }; }
        let kind = head[0] as i64;
        return fail(id, st, if kind == expected(st) { ALERT_DECODE_ERROR } else { ALERT_UNEXPECTED_MESSAGE },
                    R_BAD_LENGTH, "a handshake message longer than the server takes");
    }
    for b in got { st.hs.push(b); }
    return handshake_messages(id, st);
}

// The handshake message the client may send now: its Finished, or after it,
// only a KeyUpdate.
fn expected(st: ServerState&) -> i64 { if st.phase == PH_FINISHED { HS_FINISHED } else { HS_KEY_UPDATE } }

// The encrypted handshake messages the client sends. Each changes keys, so it
// must end its record.
fn handshake_messages(id: i64, st: ServerState&) -> i64 {
    guard st.hs.len >= 4 else { return AGAIN; }
    let kind = st.hs[0] as i64;
    let len = (st.hs[1] as i64) << 16 | (st.hs[2] as i64) << 8 | st.hs[3];
    guard kind == expected(st) else { return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_UNEXPECTED_MESSAGE, ""); }
    guard len == (if kind == HS_FINISHED { hash_len(st.suite) } else { 1 }) else {
        return fail(id, st, ALERT_DECODE_ERROR, R_BAD_LENGTH, if kind == HS_FINISHED { "Finished" } else { "KeyUpdate" });
    }
    guard st.hs.len >= 4 + len else { return AGAIN; }
    guard st.hs.len == 4 + len else {
        return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_NOT_ON_RECORD_BOUNDARY, "");
    }
    var body: u8[48] = [0; 48];
    for i in len { body[i] = st.hs[4 + i]; }
    st.hs.clear();
    if kind == HS_FINISHED {
        guard g_check(id, S_CLIENT_FINISHED, body[..len]) else {
            return fail(id, st, ALERT_DECRYPT_ERROR, R_DIGEST_CHECK_FAILED, "the client's Finished");
        }
        guard g_rec_keys(id, DIR_READ, S_CLIENT_AP) else {
            return fail(id, st, ALERT_INTERNAL_ERROR, R_INTERNAL, "the client's keys");
        }
        issue_tickets(id, st);
        g_hs_end(id);
        st.phase = PH_OPEN;
        return AGAIN;
    }
    guard body[0] <= 1 else { return fail(id, st, ALERT_ILLEGAL_PARAMETER, R_BAD_KEY_UPDATE, ""); }
    st.updates += 1;
    guard st.updates <= MAX_UPDATES else {
        return fail(id, st, ALERT_UNEXPECTED_MESSAGE, R_TOO_MANY_KEY_UPDATES, "");
    }
    guard g_rec_update(id, DIR_READ) else { return fail(id, st, ALERT_INTERNAL_ERROR, R_INTERNAL, "KeyUpdate"); }
    // An update_requested is answered once, until the answer is drained.
    if body[0] == 1 && !st.closed && !(st.update_owed && g_pending(id) > 0) {
        guard update_keys(id, st) else { return fail(id, st, ALERT_INTERNAL_ERROR, R_INTERNAL, "KeyUpdate"); }
        st.update_owed = true;
    }
    return AGAIN;
}

// Sends the session tickets once the client's Finished is in (section
// 4.6.1): two after a full handshake, one after a resumption, each with a
// nonce of its own. A ticket the context's keys can't seal, such as when
// random bytes fail, isn't sent; the connection goes on without it.
fn issue_tickets(id: i64, st: ServerState&) {
    let count = if st.resumed { 1 } else { 2 };
    for i in count {
        var nonce: u8[1] = [i as! u8];
        var add: u8[4] = [0; 4];
        var ticket: u8[>..] = [];
        guard g_random(add) else { break; }
        let age_add = (add[0] as i64) << 24 | (add[1] as i64) << 16 | (add[2] as i64) << 8 | add[3];
        guard g_ticket_issue(id, S_RESUMPTION, nonce, age_add, ticket) else { break; }
        var m: u8[>..] = [];
        put8(m, HS_NEW_SESSION_TICKET);
        let body = begin_vec(m, 3);
        put32(m, TICKET_LIFETIME);
        put32(m, age_add);
        put8(m, nonce.len);
        m.append(nonce);
        let t = begin_vec(m, 2);
        m.append(ticket);
        end_vec(m, t, 2);
        put16(m, 0);
        end_vec(m, body, 3);
        guard g_seal(id, CT_HANDSHAKE, m) >= 0 else { break; }
    }
    g_wipe(id, S_RESUMPTION);
}

// Sends a KeyUpdate that asks for none in return, and moves the server's
// sending to the next keys.
fn update_keys(id: i64, st: ServerState&) -> bool {
    g_seal(id, CT_HANDSHAKE, "\x18\x00\x00\x01\x00") >= 0 && g_rec_update(id, DIR_WRITE)
}

// The API for a connection of this server (tls.goose).

fn s_accept(ctx: i64) -> i64 { g_accept(ctx) }

fn s_feed(id: i64, data: const u8[:]) -> i64 {
    let st = load(id);
    guard st.phase != PH_FAILED else { return FAILED; }
    let n = g_feed(id, data, MAX_FED);
    guard n >= 0 else {
        g_clear_errors();
        g_fail(R_PACKET_LENGTH_TOO_LONG, "more bytes fed than the connection holds");
        return FAILED;
    }
    return n;
}

fn s_handshake(id: i64) -> i64 {
    g_clear_errors();
    var st = load(id);
    let r = advance(id, st);
    store(id, st);
    return r;
}

fn s_read(id: i64, buf: u8[:]) -> i64 {
    g_clear_errors();
    guard buf.len > 0 else { return FAILED; }
    var st = load(id);
    var r = 0;
    loop {
        if st.phase == PH_FAILED {
            r = FAILED;
            break;
        }
        let n = g_plain_read(id, buf);
        if n > 0 {
            r = n;
            break;
        }
        let s = step(id, st);
        if s != AGAIN {
            r = s;
            break;
        }
    }
    store(id, st);
    return r;
}

fn s_write(id: i64, data: const u8[:]) -> i64 {
    g_clear_errors();
    var st = load(id);
    guard st.phase != PH_FAILED else { return FAILED; }
    guard st.phase == PH_OPEN else { return WANT_INPUT; }
    guard !st.closed else {
        g_fail(R_PROTOCOL_IS_SHUTDOWN, "");
        return FAILED;
    }
    var at = 0;
    var r = data.len;
    while at < data.len {
        if st.suite != 0x1303 && g_seq(id, DIR_WRITE) >= AES_GCM_RECORDS && !update_keys(id, st) {
            r = fail(id, st, ALERT_INTERNAL_ERROR, R_INTERNAL, "KeyUpdate");
            break;
        }
        let n = min(16384, data.len - at);
        if g_seal(id, CT_DATA, data[at..at + n]) < 0 {
            r = fail(id, st, ALERT_INTERNAL_ERROR, R_INTERNAL, "sealing");
            break;
        }
        at += n;
    }
    store(id, st);
    return r;
}

fn s_shutdown(id: i64) -> i64 {
    g_clear_errors();
    var st = load(id);
    guard st.phase == PH_OPEN else {
        g_fail(R_UNEXPECTED_MESSAGE, "the handshake isn't done");
        return FAILED;
    }
    if !st.closed {
        guard g_seal(id, CT_ALERT, "\x01\x00") >= 0 else { return FAILED; }
        st.closed = true;
        store(id, st);
    }
    return 0;
}

fn s_alpn(id: i64, out: u8[>..]&) {
    let st = load(id);
    if st.alpn > 0 { out.append(alpn_name(g_conn_ctx(id), st.alpn)); }
}

fn s_version(id: i64, out: u8[>..]&) {
    if load(id).phase == PH_OPEN { out.append("TLSv1.3"); }
}

fn s_cipher(id: i64, out: u8[>..]&) {
    let st = load(id);
    guard st.phase == PH_OPEN else { return; }
    out.append(match st.suite {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        _ => "TLS_CHACHA20_POLY1305_SHA256",
    });
}

fn group_name(g: i64) -> const u8[:] {
    match g {
        GROUP_X25519MLKEM768 => "X25519MLKEM768",
        GROUP_X25519 => "x25519",
        GROUP_P256 => "secp256r1",
        GROUP_P384 => "secp384r1",
        _ => "",
    }
}

fn s_group(id: i64, out: u8[>..]&) {
    let st = load(id);
    if st.phase == PH_OPEN { out.append(group_name(st.group)); }
}

// The group a name in use_groups's list means: OpenSSL's names for it.
fn group_code(name: const u8[:]) -> i64 {
    if name == "X25519MLKEM768" { return if g_has_group(GROUP_X25519MLKEM768) { GROUP_X25519MLKEM768 } else { 0 }; }
    if name == "X25519" || name == "x25519" { return GROUP_X25519; }
    if name == "P-256" || name == "prime256v1" || name == "secp256r1" { return GROUP_P256; }
    if name == "P-384" || name == "secp384r1" { return GROUP_P384; }
    return 0;
}

fn s_use_groups(ctx: i64, names: const u8[:]) -> bool {
    guard names.len > 0 && find(names, "\x00") < 0 else { return false; }
    var codes: u8[>..] = [];
    for name in split(names, ':') {
        let g = group_code(name);
        guard g != 0 && !has16(codes, g) && codes.len < 16 else {
            g_fail(R_NO_SHARED_GROUPS, str("unknown group '", name, "'"));
            return false;
        }
        put16(codes, g);
    }
    return g_ctx_set_groups(ctx, codes);
}

fn s_use_context(id: i64, ctx: i64) -> bool {
    let st = load(id);
    guard st.paused && (ctx & 1) != 0 else {
        g_fail(R_UNEXPECTED_MESSAGE, "the connection isn't paused at its ClientHello");
        return false;
    }
    return g_conn_use(id, ctx);
}

fn s_offered(id: i64, out: u8[>..]&) {
    var st = load(id);
    guard st.paused else { return; }
    var msg: u8[>..] = [];
    copy_hello(id, st, msg);
    var h = Hello { .. };
    if parse_hello(msg, h).alert < 0 { out.append(h.alpn); }
}
