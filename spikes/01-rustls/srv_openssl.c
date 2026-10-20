/* The server as goose-tls v0.0.2's shim makes it (shim/tls.c): TLS 1.3 only,
   its three suites with the server's preference, SSL_MODE_RELEASE_BUFFERS,
   ALPN chosen from the server's list, two memory BIOs, and a BIO's buffer
   freed once it's empty. */
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "srv.h"

static SSL_CTX *ctx;
static const unsigned char alpn_wire[] = "\x08http/1.1";

static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl, (void)arg;
    unsigned char *sel = NULL, sellen = 0;
    if (SSL_select_next_proto(&sel, &sellen, alpn_wire, sizeof alpn_wire - 1, in, inlen) !=
        OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_NOACK;
    *out = sel;
    *outlen = sellen;
    return SSL_TLSEXT_ERR_OK;
}

int srv_init(const char *provider, const char *groups, const char *chain_pem, const char *key_pem) {
    (void)provider;
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx || SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
                                      "TLS_CHACHA20_POLY1305_SHA256") != 1)
        return 0;
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    if (strcmp(groups, "x25519") == 0 && SSL_CTX_set1_groups_list(ctx, "X25519") != 1) return 0;
    BIO *cb = BIO_new_mem_buf(chain_pem, -1), *kb = BIO_new_mem_buf(key_pem, -1);
    X509 *leaf = PEM_read_bio_X509(cb, NULL, NULL, NULL);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL);
    int ok = leaf && pkey && SSL_CTX_use_certificate(ctx, leaf) == 1 &&
             SSL_CTX_use_PrivateKey(ctx, pkey) == 1 && SSL_CTX_check_private_key(ctx) == 1;
    X509_free(leaf);
    EVP_PKEY_free(pkey);
    BIO_free(cb);
    BIO_free(kb);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);
    if (!ok) ERR_print_errors_fp(stderr);
    return ok;
}

static void release_empty(BIO *b) {
    BUF_MEM *bm = NULL;
    if (BIO_ctrl_pending(b) != 0 || BIO_get_mem_ptr(b, &bm) <= 0 || !bm || bm->max == 0) return;
    OPENSSL_free(bm->data);
    bm->data = NULL;
    bm->length = bm->max = 0;
    BIO_set_close(b, BIO_NOCLOSE);
    BIO_set_mem_buf(b, bm, BIO_CLOSE);
}

void *srv_new(void) {
    SSL *ssl = SSL_new(ctx);
    BIO *in = BIO_new(BIO_s_mem()), *out = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(in, -1);
    BIO_set_mem_eof_return(out, -1);
    SSL_set_bio(ssl, in, out);
    SSL_set_accept_state(ssl);
    return ssl;
}

int64_t srv_feed(void *s, const uint8_t *data, size_t len) {
    return BIO_write(SSL_get_rbio(s), data, (int)len) == (int)len ? 0 : SRV_FAIL;
}

static int64_t status(SSL *ssl, int r) {
    int e = SSL_get_error(ssl, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return SRV_WANT;
    ERR_print_errors_fp(stderr);
    return SRV_FAIL;
}

int64_t srv_handshake(void *s) {
    int r = SSL_do_handshake(s);
    int64_t st = r == 1 ? 0 : status(s, r);
    release_empty(SSL_get_rbio(s));
    return st;
}

int64_t srv_read(void *s, uint8_t *buf, size_t cap) {
    size_t n = 0;
    int r = SSL_read_ex(s, buf, cap, &n);
    int64_t st = r == 1 ? (int64_t)n : status(s, r);
    release_empty(SSL_get_rbio(s));
    return st;
}

int64_t srv_write(void *s, const uint8_t *data, size_t len) {
    size_t n = 0;
    int r = SSL_write_ex(s, data, len, &n);
    return r == 1 ? (int64_t)n : status(s, r);
}

int64_t srv_drain(void *s, uint8_t *buf, size_t cap) {
    int r = BIO_read(SSL_get_wbio(s), buf, (int)cap);
    release_empty(SSL_get_wbio(s));
    return r > 0 ? r : 0;
}

void srv_free(void *s) { SSL_free(s); }

const char *srv_group(void *s) { return SSL_group_to_name(s, SSL_get_negotiated_group(s)); }

const char *srv_suite(void *s) { return SSL_CIPHER_standard_name(SSL_get_current_cipher(s)); }

const char *srv_alpn(void *s, size_t *len) {
    const unsigned char *p = NULL;
    unsigned int n = 0;
    SSL_get0_alpn_selected(s, &p, &n);
    *len = n;
    return (const char *)p;
}
