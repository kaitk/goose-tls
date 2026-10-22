// TLS's wire format (RFC 8446, section 3): big-endian integers and vectors
// whose length comes first, read from bytes the peer sent and written into
// a message the server builds.
namespace tls;

import std;

// A checked reader of d, the bytes each call is given with it: a position,
// and an end it never reads past. A read past the end returns 0 or an empty
// slice and marks the reader bad, which stays set, so that a parser reads a
// whole structure and checks bad once. Nothing it does can index out of
// range. The bytes aren't a field, since a slice kept in a struct would tie
// what the reader returns to the reader's own lifetime (spec §9.2).
struct Rd { pos: i64 = 0, end: i64 = 0, bad: bool = false }

fn reader(d: const u8[:]) -> Rd { Rd { pos: 0, end: d.len, bad: false } }

fn left(r: Rd&) -> i64 { r.end - r.pos }

fn done(r: Rd&) -> bool { !r.bad && r.pos == r.end }

fn take(d: const u8[:], r: Rd&, n: i64) -> const u8[:] {
    guard n >= 0 && n <= r.end - r.pos && r.end <= d.len else {
        r.bad = true;
        r.pos = r.end;
        return d[..0];
    }
    let s = d[r.pos..r.pos + n];
    r.pos += n;
    return s;
}

fn get8(d: const u8[:], r: Rd&) -> i64 {
    let b = take(d, r, 1);
    return if b.len == 1 { b[0] } else { 0 };
}

fn get16(d: const u8[:], r: Rd&) -> i64 {
    let b = take(d, r, 2);
    return if b.len == 2 { (b[0] as i64) << 8 | b[1] } else { 0 };
}

fn get24(d: const u8[:], r: Rd&) -> i64 {
    let b = take(d, r, 3);
    return if b.len == 3 { (b[0] as i64) << 16 | (b[1] as i64) << 8 | b[2] } else { 0 };
}

fn get32(d: const u8[:], r: Rd&) -> i64 {
    let b = take(d, r, 4);
    return if b.len == 4 { (b[0] as i64) << 24 | (b[1] as i64) << 16 | (b[2] as i64) << 8 | b[3] } else { 0 };
}

// A vector whose length takes 1, 2, or 3 bytes.
fn vec8(d: const u8[:], r: Rd&) -> const u8[:] { take(d, r, get8(d, r)) }
fn vec16(d: const u8[:], r: Rd&) -> const u8[:] { take(d, r, get16(d, r)) }
fn vec24(d: const u8[:], r: Rd&) -> const u8[:] { take(d, r, get24(d, r)) }

// The 2-byte value at i of bytes, for a list whose length is known to be
// even.
fn at16(b: const u8[:], i: i64) -> i64 { (b[i] as i64) << 8 | b[i + 1] }

// Whether a list of 2-byte values holds v.
fn has16(list: const u8[:], v: i64) -> bool {
    var i = 0;
    while i + 1 < list.len {
        if at16(list, i) == v { return true; }
        i += 2;
    }
    return false;
}

fn put8(w: u8[>..]&, v: i64) { w.push(v as! u8); }

fn put16(w: u8[>..]&, v: i64) {
    w.push((v >> 8) as! u8);
    w.push(v as! u8);
}

fn put24(w: u8[>..]&, v: i64) {
    w.push((v >> 16) as! u8);
    w.push((v >> 8) as! u8);
    w.push(v as! u8);
}

// Starts a vector whose length takes width bytes: returns where the length
// goes, which end_vec fills in once the vector's body is written.
fn begin_vec(w: u8[>..]&, width: i64) -> i64 {
    let at = w.len;
    for i in width { w.push(0); }
    return at;
}

fn end_vec(w: u8[>..]&, at: i64, width: i64) {
    let n = w.len - at - width;
    for i in width { w[at + i] = (n >> (8 * (width - 1 - i))) as! u8; }
}
