/* The tests' other end, for checking kTLS without a kernel that has it
   (peer.goose): an OpenSSL TLS 1.3 client over memory BIOs, and the
   kernel's record layer in user space, which seals and opens TLS 1.3
   records with the crypto_info the shim would give setsockopt. */
#include <stdint.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "goose.h"

#define PEER_WANT_INPUT -1
#define PEER_CLOSED -2
#define PEER_FAILED -3

#pragma pack(push, 1)
typedef struct { const uint8_t *data; int64_t len; } peer_bytes;
typedef struct { uint8_t *data; int64_t len; } peer_buf;
#pragma pack(pop)

static int64_t status_of(SSL *ssl, int ret) {
    switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        return PEER_WANT_INPUT;
    case SSL_ERROR_ZERO_RETURN:
        return PEER_CLOSED;
    default:
        return PEER_FAILED;
    }
}

/* A client offering the one TLS 1.3 suite named, and verifying nothing. */
int64_t peer_client(peer_bytes suite) {
    char name[64];
    if (suite.len <= 0 || suite.len >= (int64_t)sizeof name) return 0;
    memcpy(name, suite.data, (size_t)suite.len);
    name[suite.len] = 0;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return 0;
    SSL *ssl = NULL;
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1 &&
        SSL_CTX_set_ciphersuites(ctx, name) == 1)
        ssl = SSL_new(ctx);
    SSL_CTX_free(ctx);
    if (!ssl) return 0;
    BIO *in = BIO_new(BIO_s_mem()), *out = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(in, -1);
    BIO_set_mem_eof_return(out, -1);
    SSL_set_bio(ssl, in, out);
    SSL_set_connect_state(ssl);
    return (int64_t)(intptr_t)ssl;
}

void peer_free(int64_t h) { SSL_free((SSL *)(intptr_t)h); }

void peer_feed(int64_t h, peer_bytes data) {
    BIO_write(SSL_get_rbio((SSL *)(intptr_t)h), data.data, (int)data.len);
}

void peer_drain(int64_t h, gs_rref out) {
    BIO *b = SSL_get_wbio((SSL *)(intptr_t)h);
    char buf[4096];
    int n;
    while ((n = BIO_read(b, buf, sizeof buf)) > 0) gs_bld_append(out, buf, n);
}

int64_t peer_handshake(int64_t h) {
    SSL *ssl = (SSL *)(intptr_t)h;
    int r = SSL_do_handshake(ssl);
    return r == 1 ? 0 : status_of(ssl, r);
}

/* Everything the client can read now, appended to out: the last status. */
int64_t peer_read(int64_t h, gs_rref out) {
    SSL *ssl = (SSL *)(intptr_t)h;
    char buf[4096];
    for (;;) {
        size_t n = 0;
        int r = SSL_read_ex(ssl, buf, sizeof buf, &n);
        if (r != 1) return status_of(ssl, r);
        gs_bld_append(out, buf, (int64_t)n);
    }
}

int64_t peer_write(int64_t h, peer_bytes data) {
    SSL *ssl = (SSL *)(intptr_t)h;
    size_t n = 0;
    int r = SSL_write_ex(ssl, data.data, (size_t)data.len, &n);
    return r == 1 ? (int64_t)n : status_of(ssl, r);
}

/* Sends a KeyUpdate, asking the server for one in return when requested. */
int64_t peer_key_update(int64_t h, uint8_t requested) {
    SSL *ssl = (SSL *)(intptr_t)h;
    if (SSL_key_update(ssl, requested ? SSL_KEY_UPDATE_REQUESTED : SSL_KEY_UPDATE_NOT_REQUESTED) != 1)
        return PEER_FAILED;
    int r = SSL_do_handshake(ssl);
    return r == 1 ? 0 : status_of(ssl, r);
}

int64_t peer_shutdown(int64_t h) {
    return SSL_shutdown((SSL *)(intptr_t)h) >= 0 ? 0 : PEER_FAILED;
}

/* The kernel's record layer for one direction, from a crypto_info. */
typedef struct {
    const EVP_CIPHER *cipher;
    uint8_t key[32], iv[12];
    uint64_t seq;
} krec;

int64_t peer_kernel(peer_bytes info) {
    if (info.len < 4) return 0;
    const uint8_t *p = info.data;
    uint16_t version, type;
    memcpy(&version, p, 2);
    memcpy(&type, p + 2, 2);
    if (version != 0x0304) return 0;
    krec *k = OPENSSL_zalloc(sizeof *k);
    if (!k) return 0;
    const uint8_t *seq;
    if (type == 51 && info.len == 40) {          /* iv[8] key[16] salt[4] rec_seq[8] */
        k->cipher = EVP_aes_128_gcm();
        memcpy(k->iv, p + 28, 4);
        memcpy(k->iv + 4, p + 4, 8);
        memcpy(k->key, p + 12, 16);
        seq = p + 32;
    } else if (type == 52 && info.len == 56) {   /* iv[8] key[32] salt[4] rec_seq[8] */
        k->cipher = EVP_aes_256_gcm();
        memcpy(k->iv, p + 44, 4);
        memcpy(k->iv + 4, p + 4, 8);
        memcpy(k->key, p + 12, 32);
        seq = p + 48;
    } else if (type == 54 && info.len == 56) {   /* iv[12] key[32] rec_seq[8] */
        k->cipher = EVP_chacha20_poly1305();
        memcpy(k->iv, p + 4, 12);
        memcpy(k->key, p + 16, 32);
        seq = p + 48;
    } else {
        OPENSSL_free(k);
        return 0;
    }
    for (int i = 0; i < 8; i++) k->seq = k->seq << 8 | seq[i];
    return (int64_t)(intptr_t)k;
}

void peer_kernel_free(int64_t h) { OPENSSL_clear_free((void *)(intptr_t)h, sizeof(krec)); }

static void nonce(const krec *k, uint8_t out[12]) {
    memcpy(out, k->iv, 12);
    for (int i = 0; i < 8; i++) out[4 + i] ^= (uint8_t)(k->seq >> (56 - 8 * i));
}

/* Seals data as one record of the type, appended to out: 0, or PEER_FAILED. */
int64_t peer_kernel_seal(int64_t h, int64_t type, peer_bytes data, gs_rref out) {
    krec *k = (krec *)(intptr_t)h;
    if (!k || data.len > 16384) return PEER_FAILED;
    uint8_t rec[5 + 16384 + 1 + 16], n12[12];
    size_t clen = (size_t)data.len + 1 + 16;
    rec[0] = 23;
    rec[1] = 3;
    rec[2] = 3;
    rec[3] = (uint8_t)(clen >> 8);
    rec[4] = (uint8_t)clen;
    uint8_t inner[16384 + 1];
    memcpy(inner, data.data, (size_t)data.len);
    inner[data.len] = (uint8_t)type;
    nonce(k, n12);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int len = 0, ok = c && EVP_EncryptInit_ex(c, k->cipher, NULL, k->key, n12) == 1 &&
                      EVP_EncryptUpdate(c, NULL, &len, rec, 5) == 1 &&
                      EVP_EncryptUpdate(c, rec + 5, &len, inner, (int)data.len + 1) == 1 &&
                      EVP_EncryptFinal_ex(c, rec + 5 + len, &len) == 1 &&
                      EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, rec + 5 + data.len + 1) == 1;
    EVP_CIPHER_CTX_free(c);
    if (!ok) return PEER_FAILED;
    k->seq++;
    gs_bld_append(out, rec, (int64_t)(5 + clen));
    return 0;
}

/* Opens record, exactly one, and appends its plaintext to out: its inner
   type, or PEER_FAILED when it doesn't authenticate. */
int64_t peer_kernel_open(int64_t h, peer_bytes record, gs_rref out) {
    krec *k = (krec *)(intptr_t)h;
    if (!k || record.len < 5 + 17 || record.len > 5 + 16384 + 256) return PEER_FAILED;
    const uint8_t *r = record.data;
    size_t clen = (size_t)r[3] << 8 | r[4];
    if (r[0] != 23 || clen + 5 != (size_t)record.len) return PEER_FAILED;
    uint8_t plain[16384 + 256], n12[12];
    nonce(k, n12);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int len = 0, fin = 0;
    int ok = c && EVP_DecryptInit_ex(c, k->cipher, NULL, k->key, n12) == 1 &&
             EVP_DecryptUpdate(c, NULL, &len, r, 5) == 1 &&
             EVP_DecryptUpdate(c, plain, &len, r + 5, (int)(clen - 16)) == 1 &&
             EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, (void *)(r + 5 + clen - 16)) == 1 &&
             EVP_DecryptFinal_ex(c, plain + len, &fin) == 1;
    EVP_CIPHER_CTX_free(c);
    if (!ok) return PEER_FAILED;
    k->seq++;
    int n = len + fin;
    while (n > 0 && plain[n - 1] == 0) n--;   /* the inner type follows any padding */
    if (n == 0) return PEER_FAILED;
    gs_bld_append(out, plain, n - 1);
    return plain[n - 1];
}

/* This thread's OpenSSL errors, cleared, for a test that failed. */
void peer_errors(gs_rref out) {
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        char line[256];
        ERR_error_string_n(e, line, sizeof line);
        gs_bld_append(out, line, (int64_t)strlen(line));
        gs_bld_append(out, "\n", 1);
    }
}
