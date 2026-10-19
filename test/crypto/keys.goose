// The keys, signatures, and certificates for ACME, checked in the program:
// a P-256 key through PEM and back, signatures of 64 bytes, SHA-256 against
// FIPS 180-2's vectors, a CSR and certificates that parse as a server's, and
// what each refuses. scripts/test-crypto.sh checks the same against openssl.
import std;
import tls from "../../";
import check from "../";

let RSA = embed_file("../certs/server.key");

let DIGITS = "0123456789abcdef";

fn hex(b: const u8[:]) -> u8[>..] {
    var s: u8[>..] = [];
    for x in b {
        s.push(DIGITS[(x >> 4) as i64]);
        s.push(DIGITS[(x & 15) as i64]);
    }
    return s;
}

fn main() {
    check::that("sha256 of \"abc\"", hex(tls::sha256("abc")) ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check::that("sha256 of \"\"", hex(tls::sha256("")) ==
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    let k = tls::key_generate();
    check::that("key_generate", tls::ok(k));
    let pem = tls::key_pem(k);
    check::that("key_pem is PKCS#8", starts_with(pem, "-----BEGIN PRIVATE KEY-----\n"));
    let xy = tls::public_xy(k);
    check::eq("public_xy bytes", xy.len, 64);

    let k2 = tls::key_from_pem(pem);
    check::that("key_from_pem of key_pem", tls::ok(k2));
    check::that("  the same key", tls::public_xy(k2) == xy && tls::key_pem(k2) == pem);
    check::that("key_from_pem of an RSA key fails", !tls::ok(tls::key_from_pem(RSA)));
    print("  ", check::reason());
    check::that("key_from_pem of text that isn't PEM fails", !tls::ok(tls::key_from_pem("no key")));
    tls::error_text();

    let a = tls::sign_es256(k, "payload");
    let b = tls::sign_es256(k, "payload");
    check::eq("sign_es256 bytes", a.len, 64);
    check::that("  a fresh nonce each time", a != b);

    let csr = tls::csr(k, ["example.test", "www.example.test"]);
    check::that("csr is DER, a SEQUENCE", csr.len > 100 && csr[0] == 0x30);
    check::that("csr of no names fails", tls::csr(k, []).len == 0);
    check::that("csr of an empty name fails", tls::csr(k, ["example.test", ""]).len == 0);

    let crt = tls::self_signed(k, ["example.test"], 90);
    check::that("self_signed is PEM", starts_with(crt, "-----BEGIN CERTIFICATE-----\n"));
    let ctx, ok = tls::server(crt, pem, []);
    check::that("  a server context takes it and key_pem", ok);
    tls::free(ctx);
    check::that("self_signed for 0 days fails", tls::self_signed(k, ["example.test"], 0).len == 0);

    let challenge = tls::challenge_certificate(k2, "example.test", "token.thumbprint");
    check::that("challenge_certificate is PEM", starts_with(challenge, "-----BEGIN CERTIFICATE-----\n"));
    let cctx, cok = tls::server(challenge, pem, ["acme-tls/1"]);
    check::that("  a server context takes it", cok);
    tls::free(cctx);
    var long: u8[>..] = [];
    long.push_n('a', 256);
    check::that("challenge_certificate for a 256-byte name fails",
                tls::challenge_certificate(k, long, "x").len == 0);

    tls::free(k);
    tls::free(k2);
}
