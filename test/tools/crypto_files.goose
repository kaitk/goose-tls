// Writes what the package's key and certificate calls make, for
// scripts/test-crypto.sh to check with openssl:
//
//   crypto_files DIR [KEY_PEM]
//
// The key is KEY_PEM's, read with key_from_pem, or a new one. Into DIR go
// key.pem (key_pem), xy.bin (public_xy), data.txt and sig.der (sign_es256 of
// it, its r || s put in DER for openssl), csr.der (a CSR for example.test and
// www.example.test), cert.pem (self_signed for the same names, 30 days), and
// challenge.pem (challenge_certificate for example.test, whose key
// authorization is "token.thumbprint").
import std;
import os;
import tls from "../../";

// An ASN.1 INTEGER of a 32-byte big-endian unsigned value: no leading zero
// bytes, but one where the top bit is set, so it stays positive.
fn integer(v: const u8[:], out: u8[>..]&) {
    var i = 0;
    while i < v.len - 1 && v[i] == 0 { i += 1; }
    let zero = v[i] >= 0x80;
    out.push(0x02);
    let extra = if zero { 1 } else { 0 };
    out.push((v.len - i + extra) as u8);
    if zero { out.push(0); }
    out.append(v[i..]);
}

// The DER ECDSA-Sig-Value that openssl takes for a JWS signature, r || s.
fn der_signature(rs: const u8[:]) -> u8[>..] {
    var body: u8[>..] = [];
    integer(rs[..32], body);
    integer(rs[32..], body);
    var out: u8[>..] = [];
    out.push(0x30);
    out.push(body.len as u8);
    out.append(body);
    return out;
}

fn put(dir: const u8[:], name: const u8[:], data: const u8[:]) {
    guard data.len > 0 else { print("empty: ", name, ": ", tls::error_text()); exit(1); }
    guard write_file(str(dir, "/", name), data) else { print("cannot write ", dir, "/", name); exit(1); }
}

fn main() {
    guard arg_count() == 2 || arg_count() == 3 else {
        print("usage: crypto_files DIR [KEY_PEM]");
        exit(2);
    }
    var dir: u8[>..] = [];
    arg(1, dir);
    var k = tls::Key { .. };
    if arg_count() == 3 {
        var path: u8[>..] = [];
        arg(2, path);
        var pem: u8[>..] = [];
        guard read_file(path, pem) else { print("cannot read ", path); exit(2); }
        k = tls::key_from_pem(pem);
    } else {
        k = tls::key_generate();
    }
    guard tls::ok(k) else { print("no key: ", tls::error_text()); exit(1); }

    put(dir, "key.pem", tls::key_pem(k));
    put(dir, "xy.bin", tls::public_xy(k));
    let data = "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZX0";
    put(dir, "data.txt", data);
    let sig = tls::sign_es256(k, data);
    guard sig.len == 64 else { print("sign_es256 gave ", sig.len, " bytes"); exit(1); }
    put(dir, "sig.der", der_signature(sig));
    put(dir, "csr.der", tls::csr(k, ["example.test", "www.example.test"]));
    put(dir, "cert.pem", tls::self_signed(k, ["example.test", "www.example.test"], 30));
    put(dir, "challenge.pem", tls::challenge_certificate(k, "example.test", "token.thumbprint"));
    tls::free(k);
    print("wrote ", dir);
}
