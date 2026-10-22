// The Goose server's key schedule and record layer against RFC 8448's
// "Simple 1-RTT Handshake" (section 3), TLS_AES_128_GCM_SHA256 over X25519:
// from the trace's ClientHello, ServerHello, and shared secret, the server's
// Finished, its encrypted flight, the client's Finished, the resumption
// master secret and a ticket's PSK, a NewSessionTicket and data each way,
// and close_notify, byte for byte. The trace's
// CertificateVerify is an RSA-PSS signature, random, so the test feeds the
// trace's messages into the transcript rather than the server's own.
import std;
import tls from "../../";
import check from "../";

extern "tlsg_ks_set" fn ks_set(id: i64, slot: i64, value: const u8[:]) -> bool;

let CRT = embed_file("../certs/server.crt");
let KEY = embed_file("../certs/server.key");

let CLIENT_HELLO = """
    01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2
    ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65
    72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03
    01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba
    fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04
    03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d
    00 02 01 01 00 1c 00 02 40 01
    """;
let SERVER_HELLO = """
    02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1
    55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76
    2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04
    """;
let SHARED_SECRET = """
    8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49
    2d
    """;
// EncryptedExtensions, Certificate, CertificateVerify, and Finished.
let SERVER_FLIGHT = """
    08 00 00 24 00 22 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00
    1c 00 02 40 01 00 00 00 00 0b 00 01 b9 00 00 01 b5 00 01 b0 30 82 01 ac 30 82 01 15 a0 03 02
    01 02 02 01 02 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03
    13 03 72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17 0d 32 36 30 37 33 30 30
    31 32 33 35 39 5a 30 0e 31 0c 30 0a 06 03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86
    48 86 f7 0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f 82 79 30 3d 98 08 36
    39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26 d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95
    13 7a ce 6c 1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b
    63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74 80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1
    d0 3e 2b d1 93 ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03 01 00 01 a3 1a
    30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06 03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a
    86 48 86 f7 0d 01 01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a 72 67 17 06
    18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6
    c5 5b 80 f2 1a 03 01 51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be c1 fc 63
    a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b 1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9
    d9 1d 40 2d cc 0c c8 f8 96 12 29 ac 91 87 b4 2b 4d e1 00 00 0f 00 00 84 08 04 00 80 5a 74 7c
    5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a b3 ff 52 f1 fd a8 47 7b 0b 7a
    bc 90 db 78 e2 d3 3a 5c 14 1a 07 86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3
    0b be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44 5c 9e a5 8c 18 1e 81 8e 95
    b8 c3 fb 0b f3 27 84 09 d3 be 15 2a 3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74
    f3 14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee
    54 54 b7 8f 07 18
    """;
let SERVER_FLIGHT_RECORD = """
    17 03 03 02 a2 d1 ff 33 4a 56 f5 bf f6 59 4a 07 cc 87 b5 80 23 3f 50 0f 45 e4 89 e7 f3 3a f3
    5e df 78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca 07 61 2e f9 f9 45 cb 96 0b 40 68 90 51 23
    ea 78 b1 11 b4 29 ba 91 91 cd 05 d2 a3 89 28 0f 52 61 34 aa dc 7f c7 8c 4b 72 9d f8 28 b5 ec
    f7 b1 3b d9 ae fb 0e 57 f2 71 58 5b 8e a9 bb 35 5c 7c 79 02 07 16 cf b9 b1 18 3e f3 ab 20 e3
    7d 57 a6 b9 d7 47 76 09 ae e6 e1 22 a4 cf 51 42 73 25 25 0c 7d 0e 50 92 89 44 4c 9b 3a 64 8f
    1d 71 03 5d 2e d6 5b 0e 3c dd 0c ba e8 bf 2d 0b 22 78 12 cb b3 60 98 72 55 cc 74 41 10 c4 53
    ba a4 fc d6 10 92 8d 80 98 10 e4 b7 ed 1a 8f d9 91 f0 6a a6 24 82 04 79 7e 36 a6 a7 3b 70 a2
    55 9c 09 ea d6 86 94 5b a2 46 ab 66 e5 ed d8 04 4b 4c 6d e3 fc f2 a8 94 41 ac 66 27 2f d8 fb
    33 0e f8 19 05 79 b3 68 45 96 c9 60 bd 59 6e ea 52 0a 56 a8 d6 50 f5 63 aa d2 74 09 96 0d ca
    63 d3 e6 88 61 1e a5 e2 2f 44 15 cf 95 38 d5 1a 20 0c 27 03 42 72 96 8a 26 4e d6 54 0c 84 83
    8d 89 f7 2c 24 46 1a ad 6d 26 f5 9e ca ba 9a cb bb 31 7b 66 d9 02 f4 f2 92 a3 6a c1 b6 39 c6
    37 ce 34 31 17 b6 59 62 22 45 31 7b 49 ee da 0c 62 58 f1 00 d7 d9 61 ff b1 38 64 7e 92 ea 33
    0f ae ea 6d fa 31 c7 a8 4d c3 bd 7e 1b 7a 6c 71 78 af 36 87 90 18 e3 f2 52 10 7f 24 3d 24 3d
    c7 33 9d 56 84 c8 b0 37 8b f3 02 44 da 8c 87 c8 43 f5 e5 6e b4 c5 e8 28 0a 2b 48 05 2c f9 3b
    16 49 9a 66 db 7c ca 71 e4 59 94 26 f7 d4 61 e6 6f 99 88 2b d8 9f c5 08 00 be cc a6 2d 6c 74
    11 6d bd 29 72 fd a1 fa 80 f8 5d f8 81 ed be 5a 37 66 89 36 b3 35 58 3b 59 91 86 dc 5c 69 18
    a3 96 fa 48 a1 81 d6 b6 fa 4f 9d 62 d5 13 af bb 99 2f 2b 99 2f 67 f8 af e6 7f 76 91 3f a3 88
    cb 56 30 c8 ca 01 e0 c6 5d 11 c6 6a 1e 2a c4 c8 59 77 b7 c7 a6 99 9b bf 10 dc 35 ae 69 f5 51
    56 14 63 6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30 38 eb ba 42 f3 b3 8e dc 03 99 f3 a9 f2 3f
    aa 63 97 8c 31 7f c9 fa 66 a7 3f 60 f0 50 4d e9 3b 5b 84 5e 27 55 92 c1 23 35 ee 34 0b bc 4f
    dd d5 02 78 40 16 e4 b3 be 7e f0 4d da 49 f4 b4 40 a3 0c b5 d2 af 93 98 28 fd 4a e3 79 4e 44
    f9 4d f5 a6 31 ed e4 2c 17 19 bf da bf 02 53 fe 51 75 be 89 8e 75 0e dc 53 37 0d 2b
    """;
let CLIENT_FINISHED_RECORD = """
    17 03 03 00 35 75 ec 4d c2 38 cc e6 0b 29 80 44 a7 1e 21 9c 56 cc 77 b0 51 7f e9 b9 3c 7a 4b
    fc 44 d8 7f 38 f8 03 38 ac 98 fc 46 de b3 84 bd 1c ae ac ab 68 67 d7 26 c4 05 46
    """;
let TICKET = """
    04 00 00 c9 00 00 00 1e fa d6 aa c5 02 00 00 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00 00
    00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70 ad 3c 49 88 83 c9 36 7c 09 a2 be
    78 5a bc 55 cd 22 60 97 a3 a9 82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6
    1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 37 25 a6 a4 da fc d0 fc 67 d2
    ae a7 05 29 51 3e 3d a2 67 7f a5 90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97
    b5 ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d e6 50 5e 5b fb c3 88 e9 33
    43 69 40 93 93 4a e4 d3 57 00 08 00 2a 00 04 00 00 04 00
    """;
let TICKET_RECORD = """
    17 03 03 00 de 3a 6b 8f 90 41 4a 97 d6 95 9c 34 87 68 0d e5 13 4a 2b 24 0e 6c ff ac 11 6e 95
    d4 1d 6a f8 f6 b5 80 dc f3 d1 1d 63 c7 58 db 28 9a 01 59 40 25 2f 55 71 3e 06 1d c1 3e 07 88
    91 a3 8e fb cf 57 53 ad 8e f1 70 ad 3c 73 53 d1 6d 9d a7 73 b9 ca 7f 2b 9f a1 b6 c0 d4 a3 d0
    3f 75 e0 9c 30 ba 1e 62 97 2a c4 6f 75 f7 b9 81 be 63 43 9b 29 99 ce 13 06 46 15 13 98 91 d5
    e4 c5 b4 06 f1 6e 3f c1 81 a7 7c a4 75 84 00 25 db 2f 0a 77 f8 1b 5a b0 5b 94 c0 13 46 75 5f
    69 23 2c 86 51 9d 86 cb ee ac 87 aa c3 47 d1 43 f9 60 5d 64 f6 50 db 4d 02 3e 70 e9 52 ca 49
    fe 51 37 12 1c 74 bc 26 97 68 7e 24 87 46 d6 df 35 30 05 f3 bc e1 86 96 12 9c 81 53 55 6b 3b
    6c 67 79 b3 7b f1 59 85 68 4f
    """;
let CLIENT_DATA_RECORD = """
    17 03 03 00 43 a2 3f 70 54 b6 2c 94 d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab
    3f 2b 98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b 62 97 4e 1f 5a 62 92 a2 97 70 14 bd 1e 3d
    ea e6 3a ee bb 21 69 49 15 e4
    """;
let SERVER_DATA_RECORD = """
    17 03 03 00 43 2e 93 7e 11 ef 4a c7 40 e5 38 ad 36 00 5f c4 a4 69 32 fc 32 25 d0 5f 82 aa 1b
    36 e3 0e fa f9 7d 90 e6 df fc 60 2d cb 50 1a 59 a8 fc c4 9c 4b f2 e5 f0 a2 1c 00 47 c2 ab f3
    32 54 0d d0 32 e1 67 c2 95 5d
    """;
let RESUMPTION_MASTER = """
    7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf da f8 6c c8 56 23 1f 2d 5a ba 46 c4 34 ec 19 6c
    """;
// The PSK of the trace's ticket, whose nonce is 00 00.
let PSK = """
    4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c a4 c5 85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3
    """;
let SERVER_AP_SECRET = """
    a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43
    """;
let CLIENT_ALERT_RECORD ="17 03 03 00 13 c9 87 27 60 65 56 66 b7 4d 7f f1 15 3e fd 6d b6 d0 b0 e3";
let SERVER_ALERT_RECORD = "17 03 03 00 13 b5 8f d6 71 66 eb f5 99 d2 47 20 cf be 7e fa 7a 88 64 a9";

fn nibble(c: u8) -> u8 {
    if c >= 'a' { c - 'a' + 10 } else { c - '0' }
}

// Bytes from hex, skipping spaces and line breaks.
fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var digits: u8[>..] = [];
    for c in s {
        if c != ' ' && c != '\n' && c != '\r' { digits.push(c); }
    }
    for i in digits.len / 2 { out.push(nibble(digits[2 * i]) << 4 | nibble(digits[2 * i + 1])); }
    return out;
}

// How many records the bytes hold, whole.
fn records(b: const u8[:]) -> i64 {
    var n = 0;
    var at = 0;
    while at + 5 <= b.len {
        at += 5 + ((b[at + 3] as i64) << 8 | b[at + 4]);
        n += 1;
    }
    return if at == b.len { n } else { -1 };
}

// Everything waiting for drain.
fn drained(c: tls::Conn) -> u8[>..] {
    var all: u8[>..] = [];
    var buf: u8[4096] = [0; 4096];
    loop {
        let n = tls::drain(c, buf);
        guard n > 0 else { break; }
        all.append(buf[..n]);
    }
    return all;
}

fn main() {
    // The Goose server's context, which tls::server makes unless the package
    // was built for libssl's.
    let ctx = tls::Context { id: tls::g_ctx_new(CRT, KEY) };
    assert(tls::ok(ctx));
    let c = tls::accept(ctx);
    let id = c.id;
    let flight = unhex(SERVER_FLIGHT);
    let fin_at = flight.len - 36;

    assert(tls::g_hs_begin(id, 0x1301));
    tls::g_tr_update(id, unhex(CLIENT_HELLO));
    tls::g_tr_update(id, unhex(SERVER_HELLO));
    assert(ks_set(id, tls::S_SHARED, unhex(SHARED_SECRET)));
    check::that("handshake keys", tls::handshake_keys(id, 0x1301, false));
    tls::g_tr_update(id, flight[..fin_at]);
    var ours: u8[>..] = [];
    ours.append(flight[..fin_at]);
    check::that("the server's Finished", tls::server_finished(id, 0x1301, ours) && ours == flight);
    check::that("sealed", tls::send_sealed(id, tls::CT_HANDSHAKE, ours));
    check::that("the encrypted flight", drained(c) == unhex(SERVER_FLIGHT_RECORD));
    check::that("application keys", tls::application_keys(id, 0x1301));
    var secret: u8[>..] = [];
    tls::g_public(id, tls::S_RESUMPTION, secret);
    check::that("the resumption master secret", secret == unhex(RESUMPTION_MASTER));
    // A ticket with the trace's nonce holds the trace's PSK.
    var ticket: u8[>..] = [];
    var sni: u8[>..] = [];
    check::that("a ticket", tls::g_ticket_issue(id, tls::S_RESUMPTION, "\x00\x00", 0, ticket));
    check::that("  opens", tls::g_ticket_open(id, ticket, tls::S_PSK, sni).suite == 0x1301);
    var psk: u8[>..] = [];
    tls::g_public(id, tls::S_PSK, psk);
    check::that("  with the trace's PSK", psk == unhex(PSK));
    tls::g_wipe(id, tls::S_PSK);

    var st = tls::ServerState { .. };
    tls::load(id, st);
    st.phase = tls::PH_FINISHED;
    st.suite = 0x1301;
    st.group = tls::GROUP_X25519;
    st.sealing = true;
    tls::store(id, st);
    tls::feed(c, unhex(CLIENT_FINISHED_RECORD));
    check::eq("the client's Finished, then handshake", tls::handshake(c), 0);
    print("cipher ", tls::cipher(c), ", group ", tls::group(c));
    let tickets = drained(c);
    check::that("two session tickets sent", records(tickets) == 2);

    // The trace's records follow from the trace's server traffic secret,
    // with its NewSessionTicket first.
    assert(tls::g_hs_begin(id, 0x1301));
    assert(ks_set(id, tls::S_SERVER_AP, unhex(SERVER_AP_SECRET)));
    assert(tls::g_rec_keys(id, tls::DIR_WRITE, tls::S_SERVER_AP));
    tls::g_hs_end(id);
    check::that("NewSessionTicket", tls::g_seal(id, tls::CT_HANDSHAKE, unhex(TICKET)) == 1);
    check::that("  sealed as the trace's", drained(c) == unhex(TICKET_RECORD));
    var payload: u8[>..] = [];
    for i in 50 { payload.push(i as u8); }
    check::eq("the server's data", tls::write(c, payload), 50);
    check::that("  sealed as the trace's", drained(c) == unhex(SERVER_DATA_RECORD));
    tls::feed(c, unhex(CLIENT_DATA_RECORD));
    var buf: u8[100] = [0; 100];
    let n = tls::read(c, buf);
    check::that("the client's data opens", n == 50 && buf[..n] == payload);
    tls::feed(c, unhex(CLIENT_ALERT_RECORD));
    check::eq("the client's close_notify: read", tls::read(c, buf), tls::CLOSED);
    check::eq("shutdown", tls::shutdown(c), 0);
    check::that("  close_notify sealed as the trace's", drained(c) == unhex(SERVER_ALERT_RECORD));
    tls::free(c);
    tls::free(ctx);
}
