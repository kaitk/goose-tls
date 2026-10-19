// The keys, signatures, and certificates for ACME, checked in the program:
// a P-256 key through PEM and back, signatures of 64 bytes, a CSR and
// certificates that parse as a server's, and what each refuses, through
// tls::run with OpenSSL's reason. scripts/test-crypto.sh checks the same
// against openssl.
import std;
import tls from "../../";
import check from "../";

let RSA = embed_file("../certs/server.key");

// Prints the error a failed run gave, without OpenSSL's codes: the call's
// own words, and whether OpenSSL's reasons include reason.
fn refused(label: const u8[:], failed: tls::Error[], reason: const u8[:]) {
    guard failed.len == 1 else { check::that(str(label, " fails"), false); return; }
    for e in failed {
        let m = e.message;
        let cut = find(m, ": error:");
        let own = if cut >= 0 { m[..cut] } else { m[..] };
        if reason.len > 0 {
            print(label, " fails: ", own, ", with OpenSSL's '", reason, "' ", find(m, reason) >= 0);
            assert(find(m, reason) >= 0);
        } else {
            print(label, " fails: ", own);
        }
    }
}

fn main() {
    var pem: u8[>..] = [];
    var xy: u8[>..] = [];
    check::run() {
        let k = tls::key_generate(tls::P256);
        pem = tls::key_pem(k);
        check::that("key_pem is PKCS#8", starts_with(pem, "-----BEGIN PRIVATE KEY-----\n"));
        xy = tls::public_xy(k);
        check::eq("public_xy bytes", xy.len, 64);

        let k2 = tls::key_from_pem(pem);
        check::that("key_from_pem of key_pem is the same key",
                    tls::public_xy(k2) == xy && tls::key_pem(k2) == pem);

        let a = tls::sign_es256(k, "payload");
        let b = tls::sign_es256(k, "payload");
        check::eq("sign_es256 bytes", a.len, 64);
        check::that("  a fresh nonce each time", a != b);

        let csr = tls::csr(k, ["example.test", "www.example.test"]);
        check::that("csr is DER, a SEQUENCE", csr.len > 100 && csr[0] == 0x30);

        let crt = tls::self_signed(k, ["example.test"], 90);
        check::that("self_signed is PEM", starts_with(crt, "-----BEGIN CERTIFICATE-----\n"));
        let ctx, ok = tls::server(crt, pem, []);
        check::that("  a server context takes it and key_pem", ok);
        tls::free(ctx);

        let challenge = tls::challenge_certificate(k2, "example.test", check::DIGEST);
        check::that("challenge_certificate is PEM", starts_with(challenge, "-----BEGIN CERTIFICATE-----\n"));
        let cctx, cok = tls::server(challenge, pem, ["acme-tls/1"]);
        check::that("  a server context takes it", cok);
        tls::free(cctx);
        tls::free(k);
        tls::free(k2);
    };

    refused("key_from_pem of an RSA key", tls::run() { tls::key_from_pem(RSA); }, "not an EC P-256 key");
    refused("key_from_pem of text that isn't PEM", tls::run() { tls::key_from_pem("no key"); }, "");
    var k = tls::Key { .. };
    check::run() { k = tls::key_generate(tls::P256); };
    refused("key_generate on another curve", tls::run() { tls::key_generate("P-384"); }, "");
    refused("csr of no names", tls::run() { tls::csr(k, []); }, "");
    refused("csr of an empty name", tls::run() { tls::csr(k, ["example.test", ""]); }, "");
    refused("self_signed for 0 days", tls::run() { tls::self_signed(k, ["example.test"], 0); }, "");
    var long: u8[>..] = [];
    long.push_n('a', 256);
    refused("challenge_certificate for a 256-byte name",
            tls::run() { tls::challenge_certificate(k, long, check::DIGEST); }, "");
    refused("challenge_certificate of a 31-byte digest",
            tls::run() { tls::challenge_certificate(k, "example.test", check::DIGEST[..31]); }, "");
    var after = false;
    let failed = tls::run() {
        tls::csr(k, []);
        after = true;
    };
    check::that("a failed call leaves run at once", failed.len == 1 && !after);
    tls::free(k);
}
