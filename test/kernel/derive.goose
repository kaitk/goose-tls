// The crypto_info kTLS gets, from RFC 8448's "Simple 1-RTT Handshake" (section
// 3): the server's application keys for TLS_AES_128_GCM_SHA256 from its
// traffic secret, and the records sealed and opened with them as the kernel
// would, byte for byte against the trace: the server's first data record,
// which follows a NewSessionTicket (sequence number 1), and the client's
// first data record and its close_notify (0 and 1).
import std;
import peer from "../tools/peer";
import tls from "../../";

extern "tls_kernel_info_for" fn info_for(name: const u8[:], secret: const u8[:], seq: i64, out: u8[:]) -> i64;

fn nibble(c: u8) -> u8 {
    if c >= 'a' { c - 'a' + 10 } else { c - '0' }
}

// Bytes from hex, skipping spaces.
fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var digits: u8[>..] = [];
    for c in s {
        if c != ' ' && c != '\n' { digits.push(c); }
    }
    for i in digits.len / 2 { out.push(nibble(digits[2 * i]) << 4 | nibble(digits[2 * i + 1])); }
    return out;
}

fn hex(b: const u8[:]) -> u8[>..] {
    let digits = "0123456789abcdef";
    var out: u8[>..] = [];
    for c in b {
        out.push(digits[c >> 4]);
        out.push(digits[c & 15]);
    }
    return out;
}

let SERVER_SECRET = "a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43";
let CLIENT_SECRET = "9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5";
let SERVER_RECORD = """
    17 03 03 00 43 2e 93 7e 11 ef 4a c7 40 e5 38 ad 36 00 5f c4 a4 69 32 fc 32 25 d0 5f 82 aa 1b 36 e3
    0e fa f9 7d 90 e6 df fc 60 2d cb 50 1a 59 a8 fc c4 9c 4b f2 e5 f0 a2 1c 00 47 c2 ab f3 32 54 0d d0
    32 e1 67 c2 95 5d
    """;
let CLIENT_RECORD = """
    17 03 03 00 43 a2 3f 70 54 b6 2c 94 d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab 3f 2b
    98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b 62 97 4e 1f 5a 62 92 a2 97 70 14 bd 1e 3d ea e6 3a ee
    bb 21 69 49 15 e4
    """;
let CLIENT_ALERT = "17 03 03 00 13 c9 87 27 60 65 56 66 b7 4d 7f f1 15 3e fd 6d b6 d0 b0 e3";

fn main() {
    // A program links a package it calls; info_for is the shim's, not tls's.
    assert(tls::library().len > 0);
    var payload: u8[>..] = [];
    for i in 50 { payload.push(i as u8); }
    var info: u8[64] = [0; 64];

    let n = info_for("TLS_AES_128_GCM_SHA256", unhex(SERVER_SECRET), 1, info);
    print("server crypto_info: ", n, " bytes, version ", hex(info[..2]), ", cipher ", hex(info[2..4]));
    print("  key ", hex(info[12..28]), ", salt ", hex(info[28..32]), ", iv ", hex(info[4..12]),
          ", rec_seq ", hex(info[32..40]));
    let tx = peer::kernel(info[..n]);
    var sealed: u8[>..] = [];
    peer::seal(tx, 23, payload, sealed);
    let verdict: u8[>..] = if sealed == unhex(SERVER_RECORD) { "as in RFC 8448" } else { hex(sealed) };
    print("  the server's data record: ", verdict);
    peer::kernel_free(tx);

    let m = info_for("TLS_AES_128_GCM_SHA256", unhex(CLIENT_SECRET), 0, info);
    print("client crypto_info: key ", hex(info[12..28]), ", salt ", hex(info[28..32]), ", iv ",
          hex(info[4..12]), ", rec_seq ", hex(info[32..40]));
    let rx = peer::kernel(info[..m]);
    var plain: u8[>..] = [];
    let t1 = peer::open(rx, unhex(CLIENT_RECORD), plain);
    let got: u8[>..] = if plain == payload { "the trace's payload" } else { hex(plain) };
    print("  the client's data record: type ", t1, ", ", got);
    plain.clear();
    let t2 = peer::open(rx, unhex(CLIENT_ALERT), plain);
    print("  its alert: type ", t2, ", ", hex(plain));
    peer::kernel_free(rx);

    print("SHA-384 suite with a SHA-256 secret: ", info_for("TLS_AES_256_GCM_SHA384", unhex(CLIENT_SECRET), 0, info));
    print("an unknown suite: ", info_for("TLS_AES_128_CCM_SHA256", unhex(CLIENT_SECRET), 0, info));
}
