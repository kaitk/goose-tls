/* The C under tls.goose: OpenSSL's server API adapted to opaque handles, bytes
   in and bytes out, and status codes (docs/architecture.md). goose build
   compiles it with the CMake target in CMakeLists.txt, so it sees none of the
   generated C but goose.h.

   It is written against the OpenSSL 3.0 API with nothing deprecated
   (OPENSSL_API_COMPAT, set by CMakeLists.txt), which OpenSSL 3.x and 4.x both
   provide (docs/decisions.md).

   A handle is the address of an SSL_CTX or an SSL, as an int64_t; 0 is none.
   None of these functions keeps a pointer into Goose memory after it returns,
   and none touches a socket: a connection reads from and writes to two memory
   BIOs that tls_feed fills and tls_drain empties. Every function that can
   fail clears this thread's OpenSSL error queue first, so after a failure the
   queue holds that failure's reasons, for tls_error_text. */
#include <stdint.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "goose.h"

#define TLS_WANT_INPUT -1
#define TLS_CLOSED -2
#define TLS_FAILED -3

#pragma pack(push, 1)
typedef struct { const uint8_t *data; int64_t len; } tls_bytes;
typedef struct { uint8_t *data; int64_t len; } tls_buf;
#pragma pack(pop)
_Static_assert(sizeof(tls_bytes) == sizeof(void *) + 8, "a Goose slice is { data, len }, packed");

/* The server's ALPN list, in wire format, hangs off its SSL_CTX as ex_data, so
   that it lives exactly as long as the context: a connection holds a
   reference to its context, which can outlive tls_context_free. */
typedef struct { size_t len; unsigned char wire[]; } tls_alpn;

static int alpn_index = -1;
static CRYPTO_ONCE alpn_once = CRYPTO_ONCE_STATIC_INIT;

static void alpn_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) {
    (void)parent, (void)ad, (void)idx, (void)argl, (void)argp;
    OPENSSL_free(ptr);
}

static void alpn_init(void) {
    alpn_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, alpn_free);
}

/* Picks the first of the server's protocols that the client offered. When
   none matches, it selects nothing (SSL_TLSEXT_ERR_NOACK) rather than the
   fallback SSL_select_next_proto suggests, which is the client's first
   protocol whether or not the server has it. */
static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg) {
    (void)arg;
    tls_alpn *a = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), alpn_index);
    if (!a || a->len == 0) return SSL_TLSEXT_ERR_NOACK;
    unsigned char *sel = NULL, sellen = 0;
    if (SSL_select_next_proto(&sel, &sellen, a->wire, (unsigned int)a->len, in, inlen) !=
        OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_NOACK;
    *out = sel;
    *outlen = sellen;
    return SSL_TLSEXT_ERR_OK;
}

/* Loads the leaf and any intermediates from chain, the key from key, and
   checks that they match. */
static int use_pem(SSL_CTX *ctx, tls_bytes chain, tls_bytes key) {
    if (chain.len <= 0 || chain.len > INT32_MAX || key.len <= 0 || key.len > INT32_MAX) return 0;
    int ok = 0;
    BIO *cb = BIO_new_mem_buf(chain.data, (int)chain.len);
    BIO *kb = BIO_new_mem_buf(key.data, (int)key.len);
    X509 *leaf = NULL;
    EVP_PKEY *pkey = NULL;
    if (!cb || !kb) goto done;
    leaf = PEM_read_bio_X509(cb, NULL, NULL, NULL);
    if (!leaf || SSL_CTX_use_certificate(ctx, leaf) != 1) goto done;
    for (;;) {
        X509 *ca = PEM_read_bio_X509(cb, NULL, NULL, NULL);
        if (!ca) break;
        if (SSL_CTX_add0_chain_cert(ctx, ca) != 1) {
            X509_free(ca);
            goto done;
        }
    }
    /* The loop ends on the PEM reader's "no start line" at the end of the
       input, which isn't a failure. */
    ERR_clear_error();
    pkey = PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL);
    if (!pkey || SSL_CTX_use_PrivateKey(ctx, pkey) != 1) goto done;
    ok = SSL_CTX_check_private_key(ctx) == 1;
done:
    X509_free(leaf);
    EVP_PKEY_free(pkey);
    BIO_free(cb);
    BIO_free(kb);
    return ok;
}

/* A server context: TLS 1.3 only, its three AEAD suites, the certificate
   chain and key from PEM text, and alpn, the server's protocols in its order
   of preference in wire format (each a length byte and the name; empty for
   none). 0 when any of it fails. */
int64_t tls_server_new(tls_bytes chain, tls_bytes key, tls_bytes alpn) {
    ERR_clear_error();
    if (!CRYPTO_THREAD_run_once(&alpn_once, alpn_init) || alpn_index < 0) return 0;
    if (alpn.len < 0 || alpn.len > 65535) return 0;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return 0;
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
                                      "TLS_CHACHA20_POLY1305_SHA256") != 1 ||
        !use_pem(ctx, chain, key))
        goto fail;
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    /* A connection keeps no buffers while it's idle. */
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    if (alpn.len > 0) {
        tls_alpn *a = OPENSSL_malloc(sizeof(tls_alpn) + (size_t)alpn.len);
        if (!a) goto fail;
        a->len = (size_t)alpn.len;
        memcpy(a->wire, alpn.data, (size_t)alpn.len);
        if (!SSL_CTX_set_ex_data(ctx, alpn_index, a)) {
            OPENSSL_free(a);
            goto fail;
        }
        SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);
    }
    return (int64_t)(intptr_t)ctx;
fail:
    SSL_CTX_free(ctx);
    return 0;
}

/* Drops the program's reference; connections made from it keep theirs. */
void tls_context_free(int64_t h) {
    SSL_CTX_free((SSL_CTX *)(intptr_t)h);
}

/* A server connection from the context, with its two memory BIOs; 0 on
   failure. */
int64_t tls_accept(int64_t h) {
    ERR_clear_error();
    SSL_CTX *ctx = (SSL_CTX *)(intptr_t)h;
    if (!ctx) return 0;
    SSL *ssl = SSL_new(ctx);
    if (!ssl) return 0;
    BIO *in = BIO_new(BIO_s_mem()), *out = BIO_new(BIO_s_mem());
    if (!in || !out) {
        BIO_free(in);
        BIO_free(out);
        SSL_free(ssl);
        return 0;
    }
    /* An empty memory BIO reports "retry" rather than end of file, which
       SSL_read turns into SSL_ERROR_WANT_READ. */
    BIO_set_mem_eof_return(in, -1);
    BIO_set_mem_eof_return(out, -1);
    SSL_set_bio(ssl, in, out);
    SSL_set_accept_state(ssl);
    return (int64_t)(intptr_t)ssl;
}

void tls_conn_free(int64_t h) {
    SSL_free((SSL *)(intptr_t)h);
}

/* Takes bytes received from the peer: all of them, or TLS_FAILED. */
int64_t tls_feed(int64_t h, tls_bytes data) {
    SSL *ssl = (SSL *)(intptr_t)h;
    if (!ssl || data.len < 0) return TLS_FAILED;
    int64_t done = 0;
    while (done < data.len) {
        int64_t n = data.len - done;
        if (n > INT32_MAX) n = INT32_MAX;
        int w = BIO_write(SSL_get_rbio(ssl), data.data + done, (int)n);
        if (w <= 0) return TLS_FAILED;
        done += w;
    }
    return done;
}

/* How many bytes wait to be sent to the peer. */
int64_t tls_pending(int64_t h) {
    SSL *ssl = (SSL *)(intptr_t)h;
    return ssl ? (int64_t)BIO_ctrl_pending(SSL_get_wbio(ssl)) : 0;
}

/* Moves up to buf.len waiting bytes into buf, and returns how many. */
int64_t tls_drain(int64_t h, tls_buf buf) {
    SSL *ssl = (SSL *)(intptr_t)h;
    if (!ssl || buf.len <= 0) return 0;
    int64_t n = buf.len > INT32_MAX ? INT32_MAX : buf.len;
    int r = BIO_read(SSL_get_wbio(ssl), buf.data, (int)n);
    return r > 0 ? r : 0;
}

/* What an SSL call's failure means for the program. */
static int64_t status_of(SSL *ssl, int ret) {
    switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        return TLS_WANT_INPUT;
    case SSL_ERROR_ZERO_RETURN:
        return TLS_CLOSED;
    default:
        return TLS_FAILED;
    }
}

/* Drives the handshake: 0 once it is done, else TLS_WANT_INPUT or
   TLS_FAILED. */
int64_t tls_handshake(int64_t h) {
    ERR_clear_error();
    SSL *ssl = (SSL *)(intptr_t)h;
    if (!ssl) return TLS_FAILED;
    int r = SSL_do_handshake(ssl);
    return r == 1 ? 0 : status_of(ssl, r);
}

/* Decrypts into buf: the count, more than 0, or TLS_WANT_INPUT, TLS_CLOSED,
   or TLS_FAILED. Finishes the handshake first if it isn't done. */
int64_t tls_read(int64_t h, tls_buf buf) {
    ERR_clear_error();
    SSL *ssl = (SSL *)(intptr_t)h;
    if (!ssl || buf.len <= 0) return TLS_FAILED;
    size_t n = 0;
    int r = SSL_read_ex(ssl, buf.data, (size_t)buf.len, &n);
    return r == 1 ? (int64_t)n : status_of(ssl, r);
}

/* Encrypts all of data into the bytes to send: data.len, or TLS_WANT_INPUT
   while the handshake waits on the peer, or TLS_FAILED. */
int64_t tls_write(int64_t h, tls_bytes data) {
    ERR_clear_error();
    SSL *ssl = (SSL *)(intptr_t)h;
    if (!ssl || data.len < 0) return TLS_FAILED;
    if (data.len == 0) return 0;
    size_t n = 0;
    int r = SSL_write_ex(ssl, data.data, (size_t)data.len, &n);
    return r == 1 ? (int64_t)n : status_of(ssl, r);
}

/* Queues close_notify: 0, or TLS_FAILED. */
int64_t tls_shutdown(int64_t h) {
    ERR_clear_error();
    SSL *ssl = (SSL *)(intptr_t)h;
    if (!ssl) return TLS_FAILED;
    /* 0 means ours is sent and the peer's not yet seen, which is all a
       server that closes needs. */
    return SSL_shutdown(ssl) >= 0 ? 0 : TLS_FAILED;
}

static void append_str(gs_rref out, const char *s) {
    if (s) gs_bld_append(out, s, (int64_t)strlen(s));
}

/* The protocol ALPN chose, or nothing. */
void tls_alpn_selected(int64_t h, gs_rref out) {
    SSL *ssl = (SSL *)(intptr_t)h;
    if (!ssl) return;
    const unsigned char *p = NULL;
    unsigned int n = 0;
    SSL_get0_alpn_selected(ssl, &p, &n);
    gs_bld_append(out, p, n);
}

/* The protocol version once negotiated, such as TLSv1.3. */
void tls_version(int64_t h, gs_rref out) {
    SSL *ssl = (SSL *)(intptr_t)h;
    if (ssl && SSL_is_init_finished(ssl)) append_str(out, SSL_get_version(ssl));
}

/* The cipher suite's IANA name once negotiated, such as
   TLS_AES_256_GCM_SHA384. */
void tls_cipher(int64_t h, gs_rref out) {
    SSL *ssl = (SSL *)(intptr_t)h;
    if (ssl && SSL_is_init_finished(ssl))
        append_str(out, SSL_CIPHER_standard_name(SSL_get_current_cipher(ssl)));
}

/* This thread's OpenSSL errors, oldest first, one per line, and clears them. */
void tls_error_text(gs_rref out) {
    unsigned long e;
    int first = 1;
    while ((e = ERR_get_error()) != 0) {
        char line[256];
        ERR_error_string_n(e, line, sizeof line);
        if (!first) gs_bld_append(out, "\n", 1);
        append_str(out, line);
        first = 0;
    }
}

/* The OpenSSL the program runs with, such as "OpenSSL 3.0.13 30 Jan 2024". */
void tls_library(gs_rref out) {
    append_str(out, OpenSSL_version(OPENSSL_VERSION));
}
