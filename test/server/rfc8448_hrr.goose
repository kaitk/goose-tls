// The Goose server's transcript across a HelloRetryRequest against RFC 8448's
// "HelloRetryRequest" trace (section 5), TLS_AES_128_GCM_SHA256 over P-256:
// the first ClientHello becomes its message_hash (RFC 8446, section 4.4.1),
// and the keys from what follows then give the server's Finished, its
// encrypted flight, and the client's Finished, byte for byte. The trace's
// HelloRetryRequest carries a cookie, which this server never sends, so the
// test feeds the trace's messages into the transcript.
import std;
import tls from "../../";
import check from "../";

extern "tlsg_ks_set" fn ks_set(id: i64, slot: i64, value: const u8[:]) -> bool;

let CRT = embed_file("../certs/server.crt");
let KEY = embed_file("../certs/server.key");

let CLIENT_HELLO_1 = """
    01 00 00 b0 03 03 b0 b1 c5 a5 aa 37 c5 91 9f 2e d1 d5 c6 ff f7 fc b7 84 97 16 94 5a 2b 8c ee
    92 58 a3 46 67 7b 6f 00 00 06 13 01 13 03 13 02 01 00 00 81 00 00 00 0b 00 09 00 00 06 73 65
    72 76 65 72 ff 01 00 01 00 00 0a 00 08 00 06 00 1d 00 17 00 18 00 33 00 26 00 24 00 1d 00 20
    e8 e8 e3 f3 b9 3a 25 ed 97 a1 4a 7d ca cb 8a 27 2c 62 88 e5 85 c6 48 4d 05 26 2f ca d0 62 ad
    1f 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05
    01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01
    """;
let RETRY = """
    02 00 00 ac 03 03 cf 21 ad 74 e5 9a 61 11 be 1d 8c 02 1e 65 b8 91 c2 a2 11 16 7a bb 8c 5e 07
    9e 09 e2 c8 a8 33 9c 00 13 01 00 00 84 00 33 00 02 00 17 00 2c 00 74 00 72 71 dc d0 4b b8 8b
    c3 18 91 19 39 8a 00 00 00 00 ee fa fc 76 c1 46 b8 23 b0 96 f8 aa ca d3 65 dd 00 30 95 3f 4e
    df 62 56 36 e5 f2 1b b2 e2 3f cc 65 4b 1b 5b 40 31 8d 10 d1 37 ab cb b8 75 74 e3 6e 8a 1f 02
    5f 7d fa 5d 6e 50 78 1b 5e da 4a a1 5b 0c 8b e7 78 25 7d 16 aa 30 30 e9 e7 84 1d d9 e4 c0 34
    22 67 e8 ca 0c af 57 1f b2 b7 cf f0 f9 34 b0 00 2b 00 02 03 04
    """;
let CLIENT_HELLO_2 = """
    01 00 01 fc 03 03 b0 b1 c5 a5 aa 37 c5 91 9f 2e d1 d5 c6 ff f7 fc b7 84 97 16 94 5a 2b 8c ee
    92 58 a3 46 67 7b 6f 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00 00 0b 00 09 00 00 06 73 65
    72 76 65 72 ff 01 00 01 00 00 0a 00 08 00 06 00 1d 00 17 00 18 00 33 00 47 00 45 00 17 00 41
    04 a6 da 73 92 ec 59 1e 17 ab fd 53 59 64 b9 98 94 d1 3b ef b2 21 b3 de f2 eb e3 83 0e ac 8f
    01 51 81 26 77 c4 d6 d2 23 7e 85 cf 01 d6 91 0c fb 83 95 4e 76 ba 73 52 83 05 34 15 98 97 e8
    06 57 80 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04
    01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2c 00 74 00 72 71 dc d0 4b b8 8b c3 18 91 19
    39 8a 00 00 00 00 ee fa fc 76 c1 46 b8 23 b0 96 f8 aa ca d3 65 dd 00 30 95 3f 4e df 62 56 36
    e5 f2 1b b2 e2 3f cc 65 4b 1b 5b 40 31 8d 10 d1 37 ab cb b8 75 74 e3 6e 8a 1f 02 5f 7d fa 5d
    6e 50 78 1b 5e da 4a a1 5b 0c 8b e7 78 25 7d 16 aa 30 30 e9 e7 84 1d d9 e4 c0 34 22 67 e8 ca
    0c af 57 1f b2 b7 cf f0 f9 34 b0 00 2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 af 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    """;
let SERVER_HELLO = """
    02 00 00 77 03 03 bb 34 1d 84 7f d7 89 c4 7c 38 71 72 dc 0c 9b f1 47 fc ca cb 50 43 d8 6c a4
    c5 98 d3 ff 57 1b 98 00 13 01 00 00 4f 00 33 00 45 00 17 00 41 04 58 3e 05 4b 7a 66 67 2a e0
    20 ad 9d 26 86 fc c8 5b 5a d4 1a 13 4a 0f 03 ee 72 b8 93 05 2b d8 5b 4c 8d e6 77 6f 5b 04 ac
    07 d8 35 40 ea b3 e3 d9 c5 47 bc 65 28 c4 31 7d 29 46 86 09 3a 6c ad 7d 00 2b 00 02 03 04
    """;
let SHARED_SECRET = """
    c1 42 ce 13 ca 11 b5 c2 23 36 52 e6 3a d3 d9 78 44 f1 62 1f bf b9 de 69 d5 47 dc 8f ed ea be
    b4
    """;
// EncryptedExtensions, Certificate, CertificateVerify, and Finished.
let SERVER_FLIGHT = """
    08 00 00 18 00 16 00 0a 00 08 00 06 00 17 00 18 00 1d 00 1c 00 02 40 01 00 00 00 00 0b 00 01
    b9 00 00 01 b5 00 01 b0 30 82 01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48
    86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03 72 73 61 30 1e 17 0d 31 36 30
    37 33 30 30 31 32 33 35 39 5a 17 0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a
    06 03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 81 8d
    00 30 81 89 02 81 81 00 b4 bb 49 8f 82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd
    b8 26 d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c 1a f1 9e aa 6a f9 8c 7c
    ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43
    08 46 74 80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93 ef f0 ab 9a 80 02 c4
    74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03 01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30
    00 30 0b 06 03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 81
    81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a 72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94
    36 54 17 f2 ea e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01 51 56 72 60 96
    fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9
    b9 eb 2b d5 20 3b 1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8 96 12 29 ac
    91 87 b4 2b 4d e1 00 00 0f 00 00 84 08 04 00 80 33 ab 13 d4 46 27 07 23 1b 5d ca e6 c8 19 0b
    63 d1 da bc 74 f2 8c 39 53 70 da 0b 07 e5 b8 30 66 d0 24 6a 31 ac d9 5d f4 75 bf d7 99 a4 a7
    0d 33 ad 93 d3 a3 17 a9 b2 c0 d2 37 a5 68 5b 21 9e 77 41 12 e3 91 a2 47 60 7d 1a ef f1 bb d0
    a3 9f 38 2e e1 a5 fe 88 ae 99 ec 59 22 8e 64 97 e4 5d 48 ce 27 5a 6d 5e f4 0d 16 9f b6 f9 d3
    3b 05 2e d3 dc dd 6b 5a 48 ba af ff bc b2 90 12 84 15 bd 38 14 00 00 20 88 63 e6 bf b0 42 0a
    92 7f a2 7f 34 33 6a 70 ae 42 6e 96 8e 3e b8 84 94 5b 96 85 6d ba 39 76 d1
    """;
let SERVER_FLIGHT_RECORD = """
    17 03 03 02 96 99 be e2 0b af 5b 7f c7 27 bf ab 62 23 92 8a 38 1e 6d 0c f9 c4 da 65 3f 9d 2a
    7b 23 f7 de 11 cc e8 42 d5 cf 75 63 17 63 45 0f fb 8b 0c c1 d2 38 e6 58 af 7a 12 ad c8 62 43
    11 4a b1 4a 1d a2 fa e4 26 21 ce 48 3f b6 24 2e ab fa ad 52 56 6b 02 b3 1d 2e dd ed ef eb 80
    e6 6a 99 00 d5 f9 73 b4 0c 4f df 74 71 9e cf 1b 68 d7 f9 c3 b6 ce b9 03 ca 13 dd 1b b8 f8 18
    7a e3 34 17 e1 d1 52 52 2c 58 22 a1 a0 3a d5 2c 83 8c 55 95 3d 61 02 22 87 4c ce 8e 17 90 b2
    29 a2 aa 0b 53 c8 d3 77 ee 72 01 82 95 1d c6 18 1d c5 d9 0b d1 f0 10 5e d1 e8 4a a5 f7 59 57
    c6 66 18 97 07 9e 5e a5 00 74 49 e3 19 7b dc 7c 9b ee ed dd ea fd d8 44 af a5 c3 15 ec fe 65
    e5 76 af e9 09 81 28 80 62 0e c7 04 8b 42 d7 f5 c7 8d 76 f2 99 d6 d8 25 34 bd d8 f5 12 fe bc
    0e d3 81 4a ca 47 0c d8 00 0d 3e 1c b9 96 2b 05 2f bb 95 0d f6 83 a5 2c 2b a7 7e d3 71 3b 12
    29 37 a6 e5 17 09 64 e2 ab 79 69 dc d9 80 b3 db 9b 45 8d a7 60 31 24 d6 dc 00 5e 4d 6e 04 b4
    d0 c4 ba f3 27 5d b8 27 db ba 0a 6d b0 96 72 17 1f c0 57 b3 85 1d 7e 02 68 41 e2 97 8f bd 23
    46 bb ef dd 03 76 bb 11 08 fe 9a cc 92 18 9f 56 50 aa 5e 85 d8 e8 c7 b6 7a c5 10 db a0 03 d3
    d7 e1 63 50 bb 66 d4 50 13 ef d4 4c 9b 60 7c 0d 31 8c 4c 7d 1a 1f 5c bc 57 e2 06 11 80 4e 37
    87 d7 b4 a4 b5 f0 8e d8 fd 70 bd ae ad e0 22 60 b1 2a b8 42 ef 69 0b 4a 3e e7 91 1e 84 1b 37
    4e cd 5e bb bc 2a 54 d0 47 b6 00 33 6d d7 d0 c8 8b 4b c1 0e 58 ee 6c b6 56 de 72 47 fa 20 d8
    e9 1d eb 84 62 86 08 cf 80 61 5b 62 e9 6c 14 91 c7 ac 37 55 eb 69 01 40 5d 34 74 fe 1a c7 9d
    10 6a 0c ee 56 c2 57 7f c8 84 80 f9 6c b6 b8 c6 81 b7 b6 8b 53 c1 46 09 39 08 f3 50 88 81 75
    bd fb 0b 1e 31 ad 61 e3 0b a0 ad fe 6d 22 3a a0 3c 07 83 b5 00 1a 57 58 7c 32 8a 9a fc fc fb
    97 8d 1c d4 32 8f 7d 9d 60 53 0e 63 0b ef d9 6c 0c 81 6e e2 0b 01 00 76 8a e2 a6 df 51 fc 68
    f1 72 74 0a 79 af 11 39 8e e3 be 12 52 49 1f a9 c6 93 47 9e 87 7f 94 ab 7c 5f 8c ad 48 02 03
    e6 ab 7b 87 dd 71 e8 a0 72 91 13 df 17 f5 ee e8 6c e1 08 d1 d7 20 07 ec 1c d1 3c 85 a6 c1 49
    62 1e 77 b7 d7 8d 80 5a 30 f0 be 03 0c 31 5e 54
    """;
let CLIENT_FINISHED_RECORD = """
    17 03 03 00 35 d7 4f 19 23 c6 62 fd 34 13 7c 6f 50 2f 3d d2 b9 3d 95 1d 1b 3b c9 7e 42 af e2
    3c 31 ab ea 92 fe 91 b4 74 99 9e 85 e3 b7 91 ce 25 2f e8 c3 e9 f9 39 a4 12 0c b2
    """;

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
    let ctx = tls::Context { id: tls::g_ctx_new(CRT, KEY) };
    assert(tls::ok(ctx));
    let c = tls::accept(ctx);
    let id = c.id;
    let flight = unhex(SERVER_FLIGHT);
    let fin_at = flight.len - 36;

    assert(tls::g_hs_begin(id, 0x1301));
    tls::g_tr_update(id, unhex(CLIENT_HELLO_1));
    check::that("the first ClientHello becomes its message_hash", tls::g_tr_restart(id));
    tls::g_tr_update(id, unhex(RETRY));
    tls::g_tr_update(id, unhex(CLIENT_HELLO_2));
    tls::g_tr_update(id, unhex(SERVER_HELLO));
    assert(ks_set(id, tls::S_SHARED, unhex(SHARED_SECRET)));
    check::that("handshake keys", tls::handshake_keys(id, 0x1301));
    tls::g_tr_update(id, flight[..fin_at]);
    var ours: u8[>..] = [];
    ours.append(flight[..fin_at]);
    check::that("the server's Finished", tls::server_finished(id, 0x1301, ours) && ours == flight);
    check::that("sealed", tls::send_sealed(id, tls::CT_HANDSHAKE, ours));
    check::that("the encrypted flight", drained(c) == unhex(SERVER_FLIGHT_RECORD));
    check::that("application keys", tls::application_keys(id, 0x1301));

    var st = tls::load(id);
    st.phase = tls::PH_FINISHED;
    st.suite = 0x1301;
    st.group = tls::GROUP_P256;
    st.sealing = true;
    tls::store(id, st);
    tls::feed(c, unhex(CLIENT_FINISHED_RECORD));
    check::eq("the client's Finished, then handshake", tls::handshake(c), 0);
    print("cipher ", tls::cipher(c), ", group ", tls::group(c));
    tls::free(c);
    tls::free(ctx);
}
