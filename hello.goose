// The ClientHello (RFC 8446, section 4.1.2), parsed for the server: each
// field the server reads, as a slice into the message, with every length
// checked. Parsing decides nothing about what the server accepts; that is
// server.goose's.
namespace tls;

import std;

// Extension types (RFC 8446, section 4.2; RFC 6066; RFC 7301).
let EXT_SERVER_NAME = 0;
let EXT_SUPPORTED_GROUPS = 10;
let EXT_SIGNATURE_ALGORITHMS = 13;
let EXT_ALPN = 16;
let EXT_PADDING = 21;
let EXT_PRE_SHARED_KEY = 41;
let EXT_EARLY_DATA = 42;
let EXT_SUPPORTED_VERSIONS = 43;
let EXT_COOKIE = 44;
let EXT_PSK_KEY_EXCHANGE_MODES = 45;
let EXT_KEY_SHARE = 51;

// Alerts (RFC 8446, section 6).
let ALERT_CLOSE_NOTIFY = 0;
let ALERT_UNEXPECTED_MESSAGE = 10;
let ALERT_BAD_RECORD_MAC = 20;
let ALERT_RECORD_OVERFLOW = 22;
let ALERT_HANDSHAKE_FAILURE = 40;
let ALERT_ILLEGAL_PARAMETER = 47;
let ALERT_DECODE_ERROR = 50;
let ALERT_DECRYPT_ERROR = 51;
let ALERT_PROTOCOL_VERSION = 70;
let ALERT_INTERNAL_ERROR = 80;
let ALERT_USER_CANCELED = 90;
let ALERT_MISSING_EXTENSION = 109;
let ALERT_NO_APPLICATION_PROTOCOL = 120;

// What a ClientHello holds that the server reads. The has_ flags say
// whether an extension came; its slice is the extension's body, without
// the length its vector already took off.
struct Hello {
    raw: const u8[:],
    legacy_version: i64,
    random: const u8[:],
    session_id: const u8[:],
    suites: const u8[:],
    compression: const u8[:],
    extensions: const u8[:],
    has_extensions: bool,
    versions: const u8[:],
    has_versions: bool,
    groups: const u8[:],
    has_groups: bool,
    shares: const u8[:],
    has_shares: bool,
    sigalgs: const u8[:],
    has_sigalgs: bool,
    alpn: const u8[:],
    has_alpn: bool,
    sni: const u8[:],
    psk_modes: const u8[:],
    has_psk_modes: bool,
    psk: const u8[:],
    has_psk: bool,
    // Where the pre_shared_key's binders start in raw: a binder covers the
    // message before them (section 4.2.11.2).
    binders_at: i64,
    early_data: bool,
}

// Why a ClientHello was refused: the alert, and the reason for error_text.
struct Refusal { alert: i64, reason: i64, text: const u8[:] }

// OpenSSL's reasons (openssl/sslerr.h), so that error_text reads as libssl's
// does.
let R_BAD_EXTENSION = 110;
let R_BAD_KEY_SHARE = 108;
let R_BAD_LENGTH = 271;
let R_BAD_PACKET = 240;
let R_BAD_PSK = 219;
let R_BAD_KEY_UPDATE = 122;
let R_BAD_CHANGE_CIPHER_SPEC = 103;
let R_BAD_RECORD_TYPE = 443;
let R_DATA_LENGTH_TOO_LONG = 146;
let R_DECRYPTION_FAILED = 281;
let R_DIGEST_CHECK_FAILED = 149;
let R_ENCRYPTED_LENGTH_TOO_LONG = 150;
let R_EXCESSIVE_MESSAGE_SIZE = 152;
let R_HTTP_REQUEST = 156;
let R_INVALID_COMPRESSION = 341;
let R_LENGTH_MISMATCH = 159;
let R_MISSING_SIGALGS = 112;
let R_MISSING_GROUPS = 209;
let R_NO_APPLICATION_PROTOCOL = 235;
let R_NO_SHARED_CIPHER = 193;
let R_NO_SHARED_GROUPS = 410;
let R_NO_SUITABLE_KEY_SHARE = 101;
let R_NO_SUITABLE_SIGALG = 118;
let R_NOT_ON_RECORD_BOUNDARY = 182;
let R_PACKET_LENGTH_TOO_LONG = 198;
let R_PROTOCOL_IS_SHUTDOWN = 207;
let R_TOO_MANY_KEY_UPDATES = 132;
let R_TOO_MUCH_EARLY_DATA = 164;
let R_UNEXPECTED_MESSAGE = 244;
let R_UNEXPECTED_RECORD = 245;
let R_UNSUPPORTED_PROTOCOL = 258;
let R_WRONG_VERSION_NUMBER = 267;
// OpenSSL's "internal error", which shim/server.c raises for -1.
let R_INTERNAL = -1;
// A received alert's reason is SSL_AD_REASON_OFFSET plus its description.
let R_ALERT = 1000;

fn ok_hello() -> Refusal { Refusal { alert: -1, reason: 0, text: "" } }

fn refuse(alert: i64, reason: i64, text: const u8[:]) -> Refusal {
    Refusal { alert: alert, reason: reason, text: text }
}

// Parses msg, a whole ClientHello with its 4-byte header, into h. A message
// that breaks the syntax is refused with decode_error; a duplicated
// extension, or a pre_shared_key that isn't the last one, with
// illegal_parameter (RFC 8446, section 4.2).
fn parse_hello(msg: const u8[:], h: Hello&) -> Refusal {
    h.raw = msg;
    var r = reader(msg);
    take(msg, r, 4);
    h.legacy_version = get16(msg, r);
    h.random = take(msg, r, 32);
    h.session_id = vec8(msg, r);
    h.suites = vec16(msg, r);
    h.compression = vec8(msg, r);
    guard !r.bad && h.session_id.len <= 32 && h.suites.len >= 2 && h.suites.len % 2 == 0 &&
          h.compression.len >= 1 else {
        return refuse(ALERT_DECODE_ERROR, R_LENGTH_MISMATCH, "ClientHello");
    }
    // A hello without extensions is from before TLS 1.3, which needs them.
    if left(r) == 0 { return ok_hello(); }
    h.extensions = vec16(msg, r);
    h.has_extensions = true;
    let ext_at = r.pos - h.extensions.len;
    guard done(r) else { return refuse(ALERT_DECODE_ERROR, R_LENGTH_MISMATCH, "ClientHello extensions"); }
    var seen: u64[1024] = [0; 1024];
    let x = h.extensions;
    var e = reader(x);
    while left(e) > 0 {
        guard !h.has_psk else {
            return refuse(ALERT_ILLEGAL_PARAMETER, R_BAD_EXTENSION, "pre_shared_key isn't the last extension");
        }
        let kind = get16(x, e);
        let body = vec16(x, e);
        guard !e.bad else { return refuse(ALERT_DECODE_ERROR, R_BAD_EXTENSION, "an extension's length"); }
        let body_at = ext_at + e.pos - body.len;
        let bit: u64 = 1 << (kind & 63);
        guard (seen[kind >> 6] & bit) == 0 else {
            return refuse(ALERT_ILLEGAL_PARAMETER, R_BAD_EXTENSION, "a duplicated extension");
        }
        seen[kind >> 6] |= bit;
        var b = reader(body);
        let bad = match kind {
            EXT_SERVER_NAME => !parse_sni(body, h),
            EXT_SUPPORTED_GROUPS => {
                h.groups = vec16(body, b);
                h.has_groups = true;
                !done(b) || h.groups.len == 0 || h.groups.len % 2 != 0
            },
            EXT_SIGNATURE_ALGORITHMS => {
                h.sigalgs = vec16(body, b);
                h.has_sigalgs = true;
                !done(b) || h.sigalgs.len == 0 || h.sigalgs.len % 2 != 0
            },
            EXT_ALPN => {
                h.alpn = vec16(body, b);
                h.has_alpn = true;
                !done(b) || !names(h.alpn)
            },
            EXT_SUPPORTED_VERSIONS => {
                h.versions = vec8(body, b);
                h.has_versions = true;
                !done(b) || h.versions.len < 2 || h.versions.len % 2 != 0
            },
            EXT_PSK_KEY_EXCHANGE_MODES => {
                h.psk_modes = vec8(body, b);
                h.has_psk_modes = true;
                !done(b) || h.psk_modes.len == 0
            },
            EXT_KEY_SHARE => {
                // An empty list is legal: the client asks for a HelloRetryRequest.
                h.shares = vec16(body, b);
                h.has_shares = true;
                !done(b) || !shares_ok(h.shares)
            },
            EXT_PRE_SHARED_KEY => {
                h.psk = body;
                h.has_psk = true;
                !psk_ok(body, body_at, h)
            },
            EXT_EARLY_DATA => {
                h.early_data = true;
                body.len != 0
            },
            _ => false,
        };
        guard !bad else { return refuse(ALERT_DECODE_ERROR, R_BAD_EXTENSION, "a malformed extension"); }
    }
    return ok_hello();
}

// The host name of a server_name extension (RFC 6066, section 3): the one
// entry of type host_name, not empty and without a NUL.
fn parse_sni(body: const u8[:], h: Hello&) -> bool {
    var r = reader(body);
    let list = vec16(body, r);
    guard done(r) && list.len > 0 else { return false; }
    var l = reader(list);
    while left(l) > 0 {
        let kind = get8(list, l);
        let name = vec16(list, l);
        guard !l.bad else { return false; }
        if kind == 0 {
            guard h.sni.len == 0 && name.len > 0 && find(name, "\x00") < 0 else { return false; }
            h.sni = name;
        }
    }
    return true;
}

// Whether an ALPN list (RFC 7301, section 3.1) holds at least one name and
// no empty one.
fn names(list: const u8[:]) -> bool {
    var r = reader(list);
    guard left(r) > 0 else { return false; }
    while left(r) > 0 {
        guard vec8(list, r).len > 0 && !r.bad else { return false; }
    }
    return true;
}

// Whether a key_share list parses: each entry a group and a key that isn't
// empty.
fn shares_ok(list: const u8[:]) -> bool {
    var r = reader(list);
    while left(r) > 0 {
        get16(list, r);
        guard vec16(list, r).len > 0 && !r.bad else { return false; }
    }
    return true;
}

// Whether a pre_shared_key extension (section 4.2.11) parses: identities and
// as many binders, each 32 to 255 bytes. Notes where its binders start, from
// body_at, where the body starts in the message.
fn psk_ok(body: const u8[:], body_at: i64, h: Hello&) -> bool {
    var r = reader(body);
    let ids = vec16(body, r);
    let binders_at = body_at + r.pos;
    let binders = vec16(body, r);
    guard done(r) && ids.len > 0 && binders.len > 0 else { return false; }
    var n = 0;
    var i = reader(ids);
    while left(i) > 0 {
        guard vec16(ids, i).len > 0 else { return false; }
        get32(ids, i);
        guard !i.bad else { return false; }
        n += 1;
    }
    var b = reader(binders);
    while left(b) > 0 {
        let binder = vec8(binders, b);
        guard !b.bad && binder.len >= 32 else { return false; }
        n -= 1;
    }
    h.binders_at = binders_at;
    return n == 0;
}

// The key share for group in a parsed key_share list, and whether there is
// one.
fn share_for(list: const u8[:], group: i64) -> const u8[:], bool {
    var r = reader(list);
    while left(r) > 0 {
        let g = get16(list, r);
        let key = vec16(list, r);
        if g == group && !r.bad { return key, true; }
    }
    return list[..0], false;
}

// Whether a key_share list names no group twice, none that supported_groups
// doesn't (section 4.2.8), and none that is obsolete in TLS 1.3 (section
// 4.2.7: the elliptic curves before TLS 1.3 and the explicit-curve codes),
// which OpenSSL refuses too.
fn shares_consistent(list: const u8[:], groups: const u8[:]) -> bool {
    var offered: u64[1024] = [0; 1024];
    var i = 0;
    while i + 1 < groups.len {
        let g = at16(groups, i);
        offered[g >> 6] |= (1 as u64) << (g & 63);
        i += 2;
    }
    var r = reader(list);
    var seen: u64[1024] = [0; 1024];
    while left(r) > 0 {
        let g = get16(list, r);
        vec16(list, r);
        let bit: u64 = 1 << (g & 63);
        guard (offered[g >> 6] & bit) != 0 && (seen[g >> 6] & bit) == 0 && !obsolete(g) else { return false; }
        seen[g >> 6] |= bit;
    }
    return true;
}

fn obsolete(group: i64) -> bool {
    (group >= 0x0001 && group <= 0x0016) || (group >= 0x001a && group <= 0x001c) ||
    group == 0xff01 || group == 0xff02
}
