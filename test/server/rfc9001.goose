// QUIC's handshake and packet protection against RFC 9001's Appendix A: the
// client's Initial packet opens under the Initial keys from its connection
// ID (A.2), and its ClientHello starts the handshake, which answers at the
// Initial and Handshake levels; the server's Initial seals byte for byte
// (A.3); and so does the ChaCha20-Poly1305 short header packet (A.5). Then a
// key update, each way through one connection.
import std;
import tls from "../../";
import check from "../";

extern "tlsg_ks_set" fn ks_set(id: i64, slot: i64, value: const u8[:]) -> bool;

let CRT = embed_file("../certs/server.crt");
let KEY = embed_file("../certs/server.key");

let DCID = "83 94 c8 f0 3e 51 57 08";
// A transport parameter of the server's: original_destination_connection_id.
let PARAMS = "00 08 83 94 c8 f0 3e 51 57 08";

let CLIENT_INITIAL = """
    c0 00 00 00 01 08 83 94 c8 f0 3e 51 57 08 00 00 44 9e 7b 9a ec 34 d1 b1 c9 8d d7 68 9f b8 ec
    11 d2 42 b1 23 dc 9b d8 ba b9 36 b4 7d 92 ec 35 6c 0b ab 7d f5 97 6d 27 cd 44 9f 63 30 00 99
    f3 99 1c 26 0e c4 c6 0d 17 b3 1f 84 29 15 7b b3 5a 12 82 a6 43 a8 d2 26 2c ad 67 50 0c ad b8
    e7 37 8c 8e b7 53 9e c4 d4 90 5f ed 1b ee 1f c8 aa fb a1 7c 75 0e 2c 7a ce 01 e6 00 5f 80 fc
    b7 df 62 12 30 c8 37 11 b3 93 43 fa 02 8c ea 7f 7f b5 ff 89 ea c2 30 82 49 a0 22 52 15 5e 23
    47 b6 3d 58 c5 45 7a fd 84 d0 5d ff fd b2 03 92 84 4a e8 12 15 46 82 e9 cf 01 2f 90 21 a6 f0
    be 17 dd d0 c2 08 4d ce 25 ff 9b 06 cd e5 35 d0 f9 20 a2 db 1b f3 62 c2 3e 59 6d 11 a4 f5 a6
    cf 39 48 83 8a 3a ec 4e 15 da f8 50 0a 6e f6 9e c4 e3 fe b6 b1 d9 8e 61 0a c8 b7 ec 3f af 6a
    d7 60 b7 ba d1 db 4b a3 48 5e 8a 94 dc 25 0a e3 fd b4 1e d1 5f b6 a8 e5 eb a0 fc 3d d6 0b c8
    e3 0c 5c 42 87 e5 38 05 db 05 9a e0 64 8d b2 f6 42 64 ed 5e 39 be 2e 20 d8 2d f5 66 da 8d d5
    99 8c ca bd ae 05 30 60 ae 6c 7b 43 78 e8 46 d2 9f 37 ed 7b 4e a9 ec 5d 82 e7 96 1b 7f 25 a9
    32 38 51 f6 81 d5 82 36 3a a5 f8 99 37 f5 a6 72 58 bf 63 ad 6f 1a 0b 1d 96 db d4 fa dd fc ef
    c5 26 6b a6 61 17 22 39 5c 90 65 56 be 52 af e3 f5 65 63 6a d1 b1 7d 50 8b 73 d8 74 3e eb 52
    4b e2 2b 3d cb c2 c7 46 8d 54 11 9c 74 68 44 9a 13 d8 e3 b9 58 11 a1 98 f3 49 1d e3 e7 fe 94
    2b 33 04 07 ab f8 2a 4e d7 c1 b3 11 66 3a c6 98 90 f4 15 70 15 85 3d 91 e9 23 03 7c 22 7a 33
    cd d5 ec 28 1c a3 f7 9c 44 54 6b 9d 90 ca 00 f0 64 c9 9e 3d d9 79 11 d3 9f e9 c5 d0 b2 3a 22
    9a 23 4c b3 61 86 c4 81 9e 8b 9c 59 27 72 66 32 29 1d 6a 41 82 11 cc 29 62 e2 0f e4 7f eb 3e
    df 33 0f 2c 60 3a 9d 48 c0 fc b5 69 9d bf e5 89 64 25 c5 ba c4 ae e8 2e 57 a8 5a af 4e 25 13
    e4 f0 57 96 b0 7b a2 ee 47 d8 05 06 f8 d2 c2 5e 50 fd 14 de 71 e6 c4 18 55 93 02 f9 39 b0 e1
    ab d5 76 f2 79 c4 b2 e0 fe b8 5c 1f 28 ff 18 f5 88 91 ff ef 13 2e ef 2f a0 93 46 ae e3 3c 28
    eb 13 0f f2 8f 5b 76 69 53 33 41 13 21 19 96 d2 00 11 a1 98 e3 fc 43 3f 9f 25 41 01 0a e1 7c
    1b f2 02 58 0f 60 47 47 2f b3 68 57 fe 84 3b 19 f5 98 40 09 dd c3 24 04 4e 84 7a 4f 4a 0a b3
    4f 71 95 95 de 37 25 2d 62 35 36 5e 9b 84 39 2b 06 10 85 34 9d 73 20 3a 4a 13 e9 6f 54 32 ec
    0f d4 a1 ee 65 ac cd d5 e3 90 4d f5 4c 1d a5 10 b0 ff 20 dc c0 c7 7f cb 2c 0e 0e b6 05 cb 05
    04 db 87 63 2c f3 d8 b4 da e6 e7 05 76 9d 1d e3 54 27 01 23 cb 11 45 0e fc 60 ac 47 68 3d 7b
    8d 0f 81 13 65 56 5f d9 8c 4c 8e b9 36 bc ab 8d 06 9f c3 3b d8 01 b0 3a de a2 e1 fb c5 aa 46
    3d 08 ca 19 89 6d 2b f5 9a 07 1b 85 1e 6c 23 90 52 17 2f 29 6b fb 5e 72 40 47 90 a2 18 10 14
    f3 b9 4a 4e 97 d1 17 b4 38 13 03 68 cc 39 db b2 d1 98 06 5a e3 98 65 47 92 6c d2 16 2f 40 a2
    9f 0c 3c 87 45 c0 f5 0f ba 38 52 e5 66 d4 45 75 c2 9d 39 a0 3f 0c da 72 19 84 b6 f4 40 59 1f
    35 5e 12 d4 39 ff 15 0a ab 76 13 49 9d bd 49 ad ab c8 67 6e ef 02 3b 15 b6 5b fc 5c a0 69 48
    10 9f 23 f3 50 db 82 12 35 35 eb 8a 74 33 bd ab cb 90 92 71 a6 ec bc b5 8b 93 6a 88 cd 4e 8f
    2e 6f f5 80 01 75 f1 13 25 3d 8f a9 ca 88 85 c2 f5 52 e6 57 dc 60 3f 25 2e 1a 8e 30 8f 76 f0
    be 79 e2 fb 8f 5d 5f bb e2 e3 0e ca dd 22 07 23 c8 c0 ae a8 07 8c df cb 38 68 26 3f f8 f0 94
    00 54 da 48 78 18 93 a7 e4 9a d5 af f4 af 30 0c d8 04 a6 b6 27 9a b3 ff 3a fb 64 49 1c 85 19
    4a ab 76 0d 58 a6 06 65 4f 9f 44 00 e8 b3 85 91 35 6f bf 64 25 ac a2 6d c8 52 44 25 9f f2 b1
    9c 41 b9 f9 6f 3c a9 ec 1d de 43 4d a7 d2 d3 92 b9 05 dd f3 d1 f9 af 93 d1 af 59 50 bd 49 3f
    5a a7 31 b4 05 6d f3 1b d2 67 b6 b9 0a 07 98 31 aa f5 79 be 0a 39 01 31 37 aa c6 d4 04 f5 18
    cf d4 68 40 64 7e 78 bf e7 06 ca 4c f5 e9 c5 45 3e 9f 7c fd 2b 8b 4c 8d 16 9a 44 e5 5c 88 d4
    a9 a7 f9 47 42 41 e2 21 af 44 86 00 18 ab 08 56 97 2e 19 4c d9 34
    """;
// Its payload's CRYPTO frame: type, offset 0, length 241, and the ClientHello.
let CLIENT_CRYPTO = """
    06 00 40 f1 01 00 00 ed 03 03 eb f8 fa 56 f1 29 39 b9 58 4a 38 96 47 2e c4 0b b8 63 cf d3 e8 68
    04 fe 3a 47 f0 6a 2b 69 48 4c 00 00 04 13 01 13 02 01 00 00 c0 00 00 00 10 00 0e 00 00 0b 65 78
    61 6d 70 6c 65 2e 63 6f 6d ff 01 00 01 00 00 0a 00 08 00 06 00 1d 00 17 00 18 00 10 00 07 00 05
    04 61 6c 70 6e 00 05 00 05 01 00 00 00 00 00 33 00 26 00 24 00 1d 00 20 93 70 b2 c9 ca a4 7f ba
    ba f4 55 9f ed ba 75 3d e1 71 fa 71 f5 0f 1c e1 5d 43 e9 94 ec 74 d7 48 00 2b 00 03 02 03 04 00
    0d 00 10 00 0e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 00 2d 00 02 01 01 00 1c 00 02 40 01 00
    39 00 32 04 08 ff ff ff ff ff ff ff ff 05 04 80 00 ff ff 07 04 80 00 ff ff 08 01 10 01 04 80 00
    75 30 09 01 10 0f 08 83 94 c8 f0 3e 51 57 08 06 04 80 00 ff ff
    """;
// The ClientHello's quic_transport_parameters.
let CLIENT_PARAMS = """
    04 08 ff ff ff ff ff ff ff ff 05 04 80 00 ff ff 07 04 80 00 ff ff 08 01 10 01 04 80 00 75 30 09
    01 10 0f 08 83 94 c8 f0 3e 51 57 08 06 04 80 00 ff ff
    """;

let SERVER_HEADER = "c1 00 00 00 01 00 08 f0 67 a5 50 2a 42 62 b5 00 40 75 00 01";
let SERVER_PAYLOAD = """
    02 00 00 00 00 06 00 40 5a 02 00 00 56 03 03 ee fc e7 f7 b3 7b a1 d1 63 2e 96 67 78 25 dd f7 39
    88 cf c7 98 25 df 56 6d c5 43 0b 9a 04 5a 12 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 9d 3c 94
    0d 89 69 0b 84 d0 8a 60 99 3c 14 4e ca 68 4d 10 81 28 7c 83 4d 53 11 bc f3 2b b9 da 1a 00 2b 00
    02 03 04
    """;
let SERVER_INITIAL = """
    cf 00 00 00 01 00 08 f0 67 a5 50 2a 42 62 b5 00 40 75 c0 d9 5a 48 2c d0 99 1c d2 5b 0a ac 40 6a
    58 16 b6 39 41 00 f3 7a 1c 69 79 75 54 78 0b b3 8c c5 a9 9f 5e de 4c f7 3c 3e c2 49 3a 18 39 b3
    db cb a3 f6 ea 46 c5 b7 68 4d f3 54 8e 7d de b9 c3 bf 9c 73 cc 3f 3b de d7 4b 56 2b fb 19 fb 84
    02 2f 8e f4 cd d9 37 95 d7 7d 06 ed bb 7a af 2f 58 89 18 50 ab bd ca 3d 20 39 8c 27 64 56 cb c4
    21 58 40 7d d0 74 ee
    """;

let CHACHA_SECRET = """
    9a c3 12 a7 f8 77 46 8e be 69 42 27 48 ad 00 a1 54 43 f1 82 03 a0 7d 60 60 f6 88 f3 0f 21 63 2b
    """;
let CHACHA_PACKET = "4c fe 41 89 65 5e 5c d5 5c 41 f6 90 80 57 5d 79 99 c2 5a 5b fb";

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

// A short header packet of two PING frames and padding, sealed under key at
// pn in two bytes; empty when sealing fails.
fn ping(c: tls::Conn, key: i64, pn: i64) -> u8[>..] {
    var p = unhex("41 00 00 01 01 00 00");
    p[1] = (pn >> 8) as! u8;
    p[2] = pn as! u8;
    p.resize(p.len + 16, 0);
    if !tls::quic_seal(c, key, p, 3, 2, pn) { p.clear(); }
    return p;
}

// Whether a copy of packet, unprotected and opened under key, holds the
// PINGs again.
fn opens(c: tls::Conn, key: i64, packet: const u8[:], pn: i64) -> bool {
    var p: u8[>..] = [];
    p.append(packet);
    guard p.len > 0 && tls::quic_unprotect(c, key, p, 1) == 0x41 else { return false; }
    return tls::quic_open(c, key, p, 3, pn) == 4 && p[3] == 1;
}

fn main() {
    let ctx, made = tls::server(CRT, KEY, ["alpn"]);
    assert(made);

    // A.2: the client's Initial, whose packet number starts at byte 18 and
    // whose Length, 1182, covers it and the payload.
    let c = tls::quic_accept(ctx, unhex(DCID), unhex(PARAMS));
    check::that("a QUIC connection", tls::ok(c));
    var pkt = unhex(CLIENT_INITIAL);
    let first = tls::quic_unprotect(c, tls::QUIC_INITIAL, pkt[..18 + 1182], 18);
    check::eq("the client's first byte", first, 0xc3);
    let pn = (pkt[18] as i64) << 24 | (pkt[19] as i64) << 16 | (pkt[20] as i64) << 8 | pkt[21];
    check::eq("its packet number", pn, 2);
    check::eq("its payload", tls::quic_open(c, tls::QUIC_INITIAL, pkt[..18 + 1182], 22, pn), 1162);
    let crypto = unhex(CLIENT_CRYPTO);
    check::that("its CRYPTO frame", pkt[22..22 + crypto.len] == crypto);

    // The ClientHello at the Initial level: the server answers it with its
    // ServerHello at Initial, and its flight at Handshake, then waits for the
    // client's Finished.
    let r = tls::quic_crypto(c, tls::QUIC_INITIAL, crypto[4..]);
    print("the ClientHello: ", check::status(r));
    var msg: u8[>..] = [];
    check::eq("the ServerHello's level", tls::quic_take(c, msg), tls::QUIC_INITIAL);
    check::eq("  its type", msg[0], 2);
    msg.clear();
    check::eq("the flight's level", tls::quic_take(c, msg), tls::QUIC_HANDSHAKE);
    check::eq("  its first message, EncryptedExtensions", msg[0], 8);
    var ext: u8[>..] = [];
    ext.append("\x00\x39\x00\x0a");
    ext.append(unhex(PARAMS));
    check::that("  with the server's transport parameters", find(msg, ext) >= 0);
    msg.clear();
    check::eq("nothing more", tls::quic_take(c, msg), -1);
    check::that("the client's transport parameters", tls::quic_peer_params(c) == unhex(CLIENT_PARAMS));
    check::that("ALPN", tls::alpn(c) == "alpn");
    check::that("Handshake keys", tls::quic_has(c, tls::QUIC_HANDSHAKE));
    check::that("no 1-RTT keys to read yet", !tls::quic_has(c, tls::QUIC_APP));
    check::eq("CRYPTO data at the wrong level", tls::quic_crypto(c, tls::QUIC_INITIAL, "\x14"), tls::FAILED);
    check::eq("  its alert, unexpected_message", tls::quic_alert(c), 10);

    // A.3: the server's Initial, packet number 1 in two bytes.
    var s = unhex(SERVER_HEADER);
    s.append(unhex(SERVER_PAYLOAD));
    s.resize(s.len + 16, 0);
    check::that("the server's Initial", tls::quic_seal(c, tls::QUIC_INITIAL, s, 20, 2, 1) && s == unhex(SERVER_INITIAL));
    tls::quic_drop(c, tls::QUIC_INITIAL);
    check::that("Initial keys dropped", !tls::quic_has(c, tls::QUIC_INITIAL));
    tls::free(c);

    // A.5: a 1-RTT packet under ChaCha20-Poly1305, its secret put in the
    // server's application slot as the handshake would.
    let k = tls::quic_accept(ctx, unhex(DCID), "");
    assert(tls::g_hs_begin(k.id, 0x1303));
    assert(ks_set(k.id, tls::S_SERVER_AP, unhex(CHACHA_SECRET)));
    assert(tls::g_quic_keys(k.id, tls::QL_APP, tls::DIR_WRITE, tls::S_SERVER_AP));
    // The same secret to read, so that the connection opens what it seals.
    assert(tls::g_quic_keys(k.id, tls::QL_APP, tls::DIR_READ, tls::S_SERVER_AP));
    var p = unhex("42 00 bf f4 01");
    p.resize(p.len + 16, 0);
    check::that("the ChaCha20 short header packet", tls::quic_seal(k, tls::QUIC_APP, p, 4, 3, 654360564) &&
                p == unhex(CHACHA_PACKET));

    // A key update: packets of the old phase still open as QUIC_PREV once
    // the new phase is current.
    let old = ping(k, tls::QUIC_APP, 7);
    check::that("a 1-RTT round trip", opens(k, tls::QUIC_APP, old, 7));
    check::that("the next phase's keys", tls::quic_next(k));
    let next = ping(k, tls::QUIC_NEXT, 8);
    check::that("  seal what the current keys don't open", !opens(k, tls::QUIC_APP, next, 8));
    check::that("  and open it", opens(k, tls::QUIC_NEXT, next, 8));
    check::that("rotated", tls::quic_rotate(k));
    check::that("  the new phase current", opens(k, tls::QUIC_APP, next, 8));
    check::that("  the old one previous", opens(k, tls::QUIC_PREV, old, 7));
    check::that("  and sealing in the new phase", opens(k, tls::QUIC_APP, ping(k, tls::QUIC_APP, 9), 9));
    tls::free(k);
    tls::free(ctx);
}
