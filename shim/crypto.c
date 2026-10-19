/* The keys, signatures, and certificates an ACME client needs, so that it
   needs no C of its own (docs/architecture.md, "Keys and certificates"): an
   EC P-256 key, ES256 signatures in JWS's form, a CSR, and a
   self-signed certificate, with RFC 8737's acmeIdentifier extension for
   TLS-ALPN-01. Written against OpenSSL 3.0's API with nothing deprecated, as
   tls.c is.

   A key's handle is the address of an EVP_PKEY, as an int64_t; 0 is none.
   Names come as a list in the ALPN list's wire format: each a length byte and
   the name. */
#include <stdint.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "goose.h"
#include "tls.h"

/* RFC 8737, section 6.1: id-pe-acmeIdentifier. */
#define ACME_IDENTIFIER_OID "1.3.6.1.5.5.7.1.31"

static int is_p256(EVP_PKEY *k) {
    char group[32];
    size_t n = 0;
    return k && EVP_PKEY_is_a(k, "EC") &&
           EVP_PKEY_get_utf8_string_param(k, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group, &n) == 1 &&
           strcmp(group, "prime256v1") == 0;
}

static void append_bio(BIO *b, gs_rref out) {
    char *p = NULL;
    long n = BIO_get_mem_data(b, &p);
    if (n > 0) gs_bld_append(out, p, n);
}

/* A new EC P-256 key, or 0. */
int64_t tls_key_generate(void) {
    ERR_clear_error();
    return (int64_t)(intptr_t)EVP_EC_gen("P-256");
}

/* A P-256 private key from PEM (PKCS#8, or SEC 1's "EC PRIVATE KEY"), or 0. */
int64_t tls_key_from_pem(tls_bytes pem) {
    ERR_clear_error();
    if (pem.len <= 0 || pem.len > INT32_MAX) return 0;
    BIO *b = BIO_new_mem_buf(pem.data, (int)pem.len);
    EVP_PKEY *k = b ? PEM_read_bio_PrivateKey(b, NULL, NULL, NULL) : NULL;
    BIO_free(b);
    if (k && !is_p256(k)) {
        ERR_raise_data(ERR_LIB_EVP, EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM, "%s", "not an EC P-256 key");
        EVP_PKEY_free(k);
        k = NULL;
    }
    return (int64_t)(intptr_t)k;
}

void tls_key_free(int64_t h) {
    EVP_PKEY_free((EVP_PKEY *)(intptr_t)h);
}

/* The private key as unencrypted PKCS#8 PEM: 1, or 0. */
uint8_t tls_key_pem(int64_t h, gs_rref out) {
    ERR_clear_error();
    EVP_PKEY *k = (EVP_PKEY *)(intptr_t)h;
    BIO *b = k ? BIO_new(BIO_s_mem()) : NULL;
    int ok = b && PEM_write_bio_PrivateKey(b, k, NULL, NULL, 0, NULL, NULL) == 1;
    if (ok) append_bio(b, out);
    BIO_free(b);
    return (uint8_t)ok;
}

/* The public key's affine coordinates, x then y, 32 bytes each, big-endian:
   a JWK's "x" and "y" before base64url (RFC 7518, section 6.2.1). 1, or 0. */
uint8_t tls_key_public(int64_t h, gs_rref out) {
    ERR_clear_error();
    EVP_PKEY *k = (EVP_PKEY *)(intptr_t)h;
    BIGNUM *x = NULL, *y = NULL;
    unsigned char xy[64];
    int ok = is_p256(k) && EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_EC_PUB_X, &x) == 1 &&
             EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_EC_PUB_Y, &y) == 1 &&
             BN_bn2binpad(x, xy, 32) == 32 && BN_bn2binpad(y, xy + 32, 32) == 32;
    if (ok) gs_bld_append(out, xy, 64);
    BN_free(x);
    BN_free(y);
    return (uint8_t)ok;
}

/* ES256 (RFC 7518, section 3.4): ECDSA with P-256 over SHA-256 of data, as
   the 64 bytes r || s that JWS takes, not the DER OpenSSL gives. 1, or 0. */
uint8_t tls_sign_es256(int64_t h, tls_bytes data, gs_rref out) {
    ERR_clear_error();
    EVP_PKEY *k = (EVP_PKEY *)(intptr_t)h;
    if (!is_p256(k) || data.len < 0) {
        ERR_raise_data(ERR_LIB_EVP, EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM, "%s", "ES256 needs an EC P-256 key");
        return 0;
    }
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned char der[80], rs[64];
    size_t der_len = sizeof der;
    ECDSA_SIG *sig = NULL;
    int ok = md && EVP_DigestSignInit_ex(md, NULL, "SHA256", NULL, NULL, k, NULL) == 1 &&
             EVP_DigestSign(md, der, &der_len, data.data, (size_t)data.len) == 1;
    if (ok) {
        const unsigned char *p = der;
        sig = d2i_ECDSA_SIG(NULL, &p, (long)der_len);
        const BIGNUM *r = NULL, *s = NULL;
        if (sig) ECDSA_SIG_get0(sig, &r, &s);
        ok = sig && BN_bn2binpad(r, rs, 32) == 32 && BN_bn2binpad(s, rs + 32, 32) == 32;
    }
    if (ok) gs_bld_append(out, rs, 64);
    ECDSA_SIG_free(sig);
    EVP_MD_CTX_free(md);
    return (uint8_t)ok;
}

/* The names, each a DNS name in a subjectAltName extension; NULL when the
   list is empty or malformed. */
static X509_EXTENSION *alt_names(tls_bytes names) {
    GENERAL_NAMES *gens = sk_GENERAL_NAME_new_null();
    X509_EXTENSION *ext = NULL;
    if (!gens) return NULL;
    int64_t i = 0;
    while (i < names.len) {
        size_t n = names.data[i++];
        if (n == 0 || (int64_t)n > names.len - i) goto done;
        GENERAL_NAME *gn = GENERAL_NAME_new();
        ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();
        if (!gn || !ia5 || ASN1_STRING_set(ia5, names.data + i, (int)n) != 1) {
            GENERAL_NAME_free(gn);
            ASN1_IA5STRING_free(ia5);
            goto done;
        }
        GENERAL_NAME_set0_value(gn, GEN_DNS, ia5);
        if (!sk_GENERAL_NAME_push(gens, gn)) {
            GENERAL_NAME_free(gn);
            goto done;
        }
        i += (int64_t)n;
    }
    if (sk_GENERAL_NAME_num(gens) > 0) ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gens);
done:
    GENERAL_NAMES_free(gens);
    return ext;
}

/* A subject of CN=the first name, when it fits the 64 characters X.520
   allows; otherwise empty, and the names are in subjectAltName alone. NULL on
   failure. */
static X509_NAME *subject_of(tls_bytes names) {
    X509_NAME *subject = X509_NAME_new();
    if (!subject || names.len < 1) goto fail;
    size_t n = names.data[0];
    if (n > 0 && n <= 64 && (int64_t)n <= names.len - 1 &&
        X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, names.data + 1, (int)n, -1, 0) != 1)
        goto fail;
    return subject;
fail:
    X509_NAME_free(subject);
    return NULL;
}

/* A certificate signing request for the names, signed by the key with
   SHA-256, as DER (what RFC 8555's finalize takes, in base64url). 1, or 0. */
uint8_t tls_csr(int64_t h, tls_bytes names, gs_rref out) {
    ERR_clear_error();
    EVP_PKEY *k = (EVP_PKEY *)(intptr_t)h;
    X509_REQ *req = X509_REQ_new();
    X509_EXTENSION *san = alt_names(names);
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    unsigned char *der = NULL;
    if (san && exts && sk_X509_EXTENSION_push(exts, san)) san = NULL;  /* exts owns it */
    X509_NAME *subject = subject_of(names);
    int ok = k && req && subject && !san && sk_X509_EXTENSION_num(exts) == 1 &&
             X509_REQ_set_version(req, 0) == 1 && X509_REQ_set_subject_name(req, subject) == 1 &&
             X509_REQ_set_pubkey(req, k) == 1 && X509_REQ_add_extensions(req, exts) == 1 &&
             X509_REQ_sign(req, k, EVP_sha256()) > 0;
    int n = ok ? i2d_X509_REQ(req, &der) : 0;
    if (n > 0) gs_bld_append(out, der, n);
    OPENSSL_free(der);
    X509_NAME_free(subject);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    X509_EXTENSION_free(san);
    X509_REQ_free(req);
    return (uint8_t)(n > 0);
}

/* The acmeIdentifier extension, critical, whose value is the DER of an
   OCTET STRING holding the 32-byte digest (RFC 8737, section 3). */
static X509_EXTENSION *acme_identifier(tls_bytes digest) {
    ASN1_OBJECT *oid = OBJ_txt2obj(ACME_IDENTIFIER_OID, 1);
    ASN1_OCTET_STRING *value = ASN1_OCTET_STRING_new();
    X509_EXTENSION *ext = NULL;
    unsigned char inner[2 + 32];
    inner[0] = V_ASN1_OCTET_STRING;
    inner[1] = 32;
    memcpy(inner + 2, digest.data, 32);
    if (oid && value && ASN1_OCTET_STRING_set(value, inner, sizeof inner) == 1)
        ext = X509_EXTENSION_create_by_OBJ(NULL, oid, 1, value);
    ASN1_OBJECT_free(oid);
    ASN1_OCTET_STRING_free(value);
    return ext;
}

/* A self-signed certificate for the names, signed by the key with SHA-256,
   valid from an hour ago for days days, as PEM. With acme, the 32-byte
   SHA-256 of a key authorization, it carries the acmeIdentifier extension
   for TLS-ALPN-01, and must have exactly one name. 1, or 0. */
uint8_t tls_self_signed(int64_t h, tls_bytes names, int64_t days, tls_bytes acme, gs_rref out) {
    ERR_clear_error();
    EVP_PKEY *k = (EVP_PKEY *)(intptr_t)h;
    if (!k || days < 1 || days > 36500 || (acme.len != 0 && acme.len != 32) ||
        (acme.len && (names.len < 1 || names.data[0] + 1 != names.len)))
        return 0;
    X509 *x = X509_new();
    X509_EXTENSION *san = alt_names(names);
    X509_EXTENSION *id = acme.len ? acme_identifier(acme) : NULL;
    BIGNUM *serial = BN_new();
    ASN1_INTEGER *number = NULL;
    X509_NAME *subject = subject_of(names);
    BIO *b = BIO_new(BIO_s_mem());
    int ok = x && san && (!acme.len || id) && serial && subject && b && X509_set_version(x, 2) == 1 &&
             /* 127 random bits: positive, and within RFC 5280's 20 bytes. */
             BN_rand(serial, 127, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) == 1 &&
             (number = BN_to_ASN1_INTEGER(serial, NULL)) != NULL &&
             X509_set_serialNumber(x, number) == 1 && X509_set_subject_name(x, subject) == 1 &&
             X509_set_issuer_name(x, subject) == 1 &&
             X509_gmtime_adj(X509_getm_notBefore(x), -3600) &&
             X509_time_adj_ex(X509_getm_notAfter(x), (int)days, 0, NULL) &&
             X509_set_pubkey(x, k) == 1 && X509_add_ext(x, san, -1) == 1 &&
             (!id || X509_add_ext(x, id, -1) == 1) && X509_sign(x, k, EVP_sha256()) > 0 &&
             PEM_write_bio_X509(b, x) == 1;
    if (ok) append_bio(b, out);
    BIO_free(b);
    X509_NAME_free(subject);
    ASN1_INTEGER_free(number);
    BN_free(serial);
    X509_EXTENSION_free(id);
    X509_EXTENSION_free(san);
    X509_free(x);
    return (uint8_t)ok;
}
