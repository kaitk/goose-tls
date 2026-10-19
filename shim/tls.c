/* The C under tls.goose: OpenSSL's TLS API adapted to opaque handles, bytes
   in and bytes out, and status codes (docs/architecture.md). goose build
   compiles it with the CMake target in CMakeLists.txt, so it sees none of the
   generated C but goose.h.

   It is written against the OpenSSL 3.0 API with nothing deprecated
   (OPENSSL_API_COMPAT, set by CMakeLists.txt), which OpenSSL 3.x and 4.x both
   provide (docs/decisions.md).

   A handle is the address of an SSL_CTX or an SSL, as an int64_t; 0 is none.
   None of these functions keeps a pointer into Goose memory after it returns,
   and none touches a socket: a connection reads from and writes to two memory
   BIOs that tls_feed fills and tls_drain empties. Handing a connection to the
   kernel is ktls.c's. Every function that can
   fail clears this thread's OpenSSL error queue first, so after a failure the
   queue holds that failure's reasons, for tls_error_text. */
#include <stdint.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "goose.h"
#include "tls.h"

/* The server's ALPN list, in wire format, hangs off its SSL_CTX as ex_data, so
   that it lives exactly as long as the context: a connection holds a
   reference to its context, which can outlive tls_context_free. */
typedef struct { size_t len; unsigned char wire[]; } tls_alpn;

/* What a connection from a context that pauses at the ClientHello
   (tls_choose_enable) keeps of it, from the first call of hello_cb until the
   connection is freed: the SNI name and the offered ALPN list, as the client
   sent them, and the context tls_use_context chose, which hello_cb applies
   when the handshake resumes. */
typedef struct {
    SSL_CTX *chosen;
    int resumed;
    size_t name_len;
    char name[255];
    size_t alpn_len;
    unsigned char alpn[];
} hello_info;

static int alpn_index = -1, hello_index = -1;
static CRYPTO_ONCE index_once = CRYPTO_ONCE_STATIC_INIT;

static void alpn_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) {
    (void)parent, (void)ad, (void)idx, (void)argl, (void)argp;
    OPENSSL_free(ptr);
}

static void hello_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) {
    (void)parent, (void)ad, (void)idx, (void)argl, (void)argp;
    hello_info *h = ptr;
    if (h) SSL_CTX_free(h->chosen);
    OPENSSL_free(h);
}

static void index_init(void) {
    alpn_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, alpn_free);
    hello_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, hello_free);
}

static int indexes(void) {
    return CRYPTO_THREAD_run_once(&index_once, index_init) && alpn_index >= 0 && hello_index >= 0;
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

/* TLS 1.3 only, with its three AEAD suites in this order, for a server and a
   client alike. */
static int tls13_only(SSL_CTX *ctx) {
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
                                      "TLS_CHACHA20_POLY1305_SHA256") != 1)
        return 0;
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    /* A connection keeps no buffers while it's idle. */
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    return 1;
}

/* A server context: TLS 1.3 only, its three AEAD suites, the certificate
   chain and key from PEM text, and alpn, the server's protocols in its order
   of preference in wire format (each a length byte and the name; empty for
   none). 0 when any of it fails. */
int64_t tls_server_new(tls_bytes chain, tls_bytes key, tls_bytes alpn) {
    ERR_clear_error();
    if (!indexes()) return 0;
    if (alpn.len < 0 || alpn.len > 65535) return 0;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return 0;
    if (!tls13_only(ctx) || !use_pem(ctx, chain, key)) goto fail;
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
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

/* A client context: TLS 1.3 only, verifying the server's chain against the
   certificates in ca, PEM text, or with system set, against OpenSSL's default
   trust store (its OPENSSLDIR, or SSL_CERT_FILE and SSL_CERT_DIR), and
   offering alpn, in wire format. 0 when any of it fails. */
int64_t tls_client_new(tls_bytes ca, uint8_t system, tls_bytes alpn) {
    ERR_clear_error();
    if (alpn.len < 0 || alpn.len > 65535 || ca.len < 0 || ca.len > INT32_MAX) return 0;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    BIO *b = NULL;
    if (!ctx) return 0;
    if (!tls13_only(ctx)) goto fail;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (system) {
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) goto fail;
    } else {
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        b = BIO_new_mem_buf(ca.data, (int)ca.len);
        if (!b) goto fail;
        int n = 0;
        for (X509 *x; (x = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL; n++) {
            int ok = X509_STORE_add_cert(store, x);
            X509_free(x);
            if (ok != 1) goto fail;
        }
        if (n == 0) goto fail;
        ERR_clear_error();
    }
    /* SSL_CTX_set_alpn_protos returns 0 on success. */
    if (alpn.len > 0 && SSL_CTX_set_alpn_protos(ctx, alpn.data, (unsigned int)alpn.len) != 0) goto fail;
    BIO_free(b);
    return (int64_t)(intptr_t)ctx;
fail:
    BIO_free(b);
    SSL_CTX_free(ctx);
    return 0;
}

/* Another reference to the context, for a thread that frees its own: the
   same handle, or 0. */
int64_t tls_context_share(int64_t h) {
    SSL_CTX *ctx = (SSL_CTX *)(intptr_t)h;
    return ctx && SSL_CTX_up_ref(ctx) == 1 ? h : 0;
}

/* Drops one reference; connections made from it keep theirs. */
void tls_context_free(int64_t h) {
    SSL_CTX_free((SSL_CTX *)(intptr_t)h);
}

/* A connection from the context, with its two memory BIOs; NULL on
   failure. */
static SSL *conn_new(int64_t h) {
    SSL_CTX *ctx = (SSL_CTX *)(intptr_t)h;
    if (!ctx) return NULL;
    SSL *ssl = SSL_new(ctx);
    if (!ssl) return NULL;
    BIO *in = BIO_new(BIO_s_mem()), *out = BIO_new(BIO_s_mem());
    if (!in || !out) {
        BIO_free(in);
        BIO_free(out);
        SSL_free(ssl);
        return NULL;
    }
    /* An empty memory BIO reports "retry" rather than end of file, which
       SSL_read turns into SSL_ERROR_WANT_READ. */
    BIO_set_mem_eof_return(in, -1);
    BIO_set_mem_eof_return(out, -1);
    SSL_set_bio(ssl, in, out);
    return ssl;
}

/* A server connection from the context; 0 on failure. */
int64_t tls_accept(int64_t h) {
    ERR_clear_error();
    SSL *ssl = conn_new(h);
    if (!ssl) return 0;
    SSL_set_accept_state(ssl);
    if (!ktls_attach(ssl)) {
        SSL_free(ssl);
        return 0;
    }
    return (int64_t)(intptr_t)ssl;
}

/* A client connection from a client context to host, a DNS name or an IP
   address: the server's certificate must name it. A DNS name also goes in
   SNI; an address doesn't (RFC 6066, section 3). 0 on failure. */
int64_t tls_connect(int64_t h, tls_bytes host) {
    ERR_clear_error();
    char name[256];
    if (host.len <= 0 || host.len >= (int64_t)sizeof name || memchr(host.data, 0, (size_t)host.len))
        return 0;
    memcpy(name, host.data, (size_t)host.len);
    name[host.len] = 0;
    SSL *ssl = conn_new(h);
    if (!ssl) return 0;
    SSL_set_connect_state(ssl);
    if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), name) != 1) {
        ERR_clear_error();
        SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (SSL_set1_host(ssl, name) != 1 || SSL_set_tlsext_host_name(ssl, name) != 1) {
            SSL_free(ssl);
            return 0;
        }
    }
    return (int64_t)(intptr_t)ssl;
}

/* Pauses each handshake of the context's connections at the ClientHello: the
   first call reads what the program chooses by and returns
   SSL_CLIENT_HELLO_RETRY, which SSL_do_handshake reports as
   SSL_ERROR_WANT_CLIENT_HELLO_CB; the next, when the program resumes the
   handshake, moves the connection to the context it chose. SNI and ALPN are
   parsed from the extensions' raw bytes, since OpenSSL processes them only
   after this callback. */
static int hello_cb(SSL *ssl, int *al, void *arg) {
    (void)arg;
    hello_info *h = SSL_get_ex_data(ssl, hello_index);
    if (h) {
        h->resumed = 1;
        if (h->chosen) {
            SSL_CTX *ctx = h->chosen;
            h->chosen = NULL;
            int ok = SSL_set_SSL_CTX(ssl, ctx) == ctx;
            SSL_CTX_free(ctx);
            if (!ok) {
                *al = SSL_AD_INTERNAL_ERROR;
                return SSL_CLIENT_HELLO_ERROR;
            }
        }
        return SSL_CLIENT_HELLO_SUCCESS;
    }
    const unsigned char *alpn = NULL, *sni = NULL;
    size_t alpn_len = 0, sni_len = 0;
    /* An ALPN extension is a 2-byte length and the list. */
    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_application_layer_protocol_negotiation, &alpn,
                                  &alpn_len) == 1 && alpn_len >= 2 &&
        (size_t)(alpn[0] << 8 | alpn[1]) == alpn_len - 2) {
        alpn += 2;
        alpn_len -= 2;
    } else {
        alpn_len = 0;
    }
    h = OPENSSL_zalloc(sizeof *h + alpn_len);
    if (!h) {
        *al = SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }
    memcpy(h->alpn, alpn, alpn_len);
    h->alpn_len = alpn_len;
    /* A server_name extension is a 2-byte list length, then entries of a
       type, 0 for a host name, and a 2-byte length; the first is the one. */
    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &sni, &sni_len) == 1 && sni_len >= 5 &&
        (size_t)(sni[0] << 8 | sni[1]) == sni_len - 2 && sni[2] == TLSEXT_NAMETYPE_host_name) {
        size_t n = (size_t)(sni[3] << 8 | sni[4]);
        if (n > 0 && n <= sizeof h->name && n <= sni_len - 5 && !memchr(sni + 5, 0, n)) {
            memcpy(h->name, sni + 5, n);
            h->name_len = n;
        }
    }
    if (!SSL_set_ex_data(ssl, hello_index, h)) {
        OPENSSL_free(h);
        *al = SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }
    return SSL_CLIENT_HELLO_RETRY;
}

/* Makes the context's connections pause at the ClientHello. Call it before
   the context accepts a connection. */
uint8_t tls_choose_enable(int64_t h) {
    ERR_clear_error();
    SSL_CTX *ctx = (SSL_CTX *)(intptr_t)h;
    if (!ctx || !indexes()) return 0;
    SSL_CTX_set_client_hello_cb(ctx, hello_cb, NULL);
    return 1;
}

/* Sets the context a connection paused at its ClientHello resumes with: 1,
   or 0 when the connection isn't paused there. The connection holds a
   reference to it until the handshake resumes. */
uint8_t tls_use_context(int64_t h, int64_t ctx_h) {
    ERR_clear_error();
    SSL *ssl = (SSL *)(intptr_t)h;
    SSL_CTX *ctx = (SSL_CTX *)(intptr_t)ctx_h;
    hello_info *h_info = ssl && hello_index >= 0 ? SSL_get_ex_data(ssl, hello_index) : NULL;
    if (!h_info || h_info->resumed || !ctx) {
        ERR_raise_data(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, "%s", "the connection isn't paused at its ClientHello");
        return 0;
    }
    if (SSL_CTX_up_ref(ctx) != 1) return 0;
    SSL_CTX_free(h_info->chosen);
    h_info->chosen = ctx;
    return 1;
}

/* The name the client sent in SNI, or nothing. */
void tls_server_name(int64_t h, gs_rref out) {
    SSL *ssl = (SSL *)(intptr_t)h;
    if (!ssl) return;
    hello_info *info = hello_index >= 0 ? SSL_get_ex_data(ssl, hello_index) : NULL;
    if (info) {
        gs_bld_append(out, info->name, (int64_t)info->name_len);
        return;
    }
    const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (name) gs_bld_append(out, name, (int64_t)strlen(name));
}

/* The ALPN protocols the client offered, in wire format, as the ClientHello
   pause saw them; nothing for a context that doesn't pause. */
void tls_offered(int64_t h, gs_rref out) {
    SSL *ssl = (SSL *)(intptr_t)h;
    hello_info *info = ssl && hello_index >= 0 ? SSL_get_ex_data(ssl, hello_index) : NULL;
    if (info) gs_bld_append(out, info->alpn, (int64_t)info->alpn_len);
}

void tls_conn_free(int64_t h) {
    SSL_free((SSL *)(intptr_t)h);
}

/* Takes bytes received from the peer: all of them, or TLS_FAILED. */
int64_t tls_feed(int64_t h, tls_bytes data) {
    SSL *ssl = (SSL *)(intptr_t)h;
    if (!ssl || data.len < 0 || ktls_owns(ssl, KTLS_RX)) return TLS_FAILED;
    ktls_frame(ssl, data.data, data.len);
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

/* What an SSL call's failure means for the program. A client whose
   verification failed gets the reason added to the error queue, which says
   only "certificate verify failed". */
static int64_t status_of(SSL *ssl, int ret) {
    switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        return TLS_WANT_INPUT;
    case SSL_ERROR_WANT_CLIENT_HELLO_CB:
        return TLS_HELLO;
    case SSL_ERROR_ZERO_RETURN:
        return TLS_CLOSED;
    default:
        if (!SSL_is_server(ssl)) {
            long v = SSL_get_verify_result(ssl);
            if (v != X509_V_OK)
                ERR_raise_data(ERR_LIB_SSL, SSL_R_CERTIFICATE_VERIFY_FAILED, "%s",
                               X509_verify_cert_error_string(v));
        }
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
    if (!ssl || buf.len <= 0 || ktls_owns(ssl, KTLS_RX)) return TLS_FAILED;
    size_t n = 0;
    int r = SSL_read_ex(ssl, buf.data, (size_t)buf.len, &n);
    return r == 1 ? (int64_t)n : status_of(ssl, r);
}

/* Encrypts all of data into the bytes to send: data.len, or TLS_WANT_INPUT
   while the handshake waits on the peer, or TLS_FAILED. */
int64_t tls_write(int64_t h, tls_bytes data) {
    ERR_clear_error();
    SSL *ssl = (SSL *)(intptr_t)h;
    if (!ssl || data.len < 0 || ktls_owns(ssl, KTLS_TX)) return TLS_FAILED;
    if (data.len == 0) return 0;
    size_t n = 0;
    int r = SSL_write_ex(ssl, data.data, (size_t)data.len, &n);
    return r == 1 ? (int64_t)n : status_of(ssl, r);
}

/* Queues close_notify: 0, or TLS_FAILED. */
int64_t tls_shutdown(int64_t h) {
    ERR_clear_error();
    SSL *ssl = (SSL *)(intptr_t)h;
    if (!ssl || ktls_owns(ssl, KTLS_TX)) return TLS_FAILED;
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

/* The peer's certificate, its leaf, as PEM, once the handshake has it. */
void tls_peer_certificate(int64_t h, gs_rref out) {
    SSL *ssl = (SSL *)(intptr_t)h;
    X509 *x = ssl ? SSL_get0_peer_certificate(ssl) : NULL;
    if (!x) return;
    BIO *b = BIO_new(BIO_s_mem());
    if (b && PEM_write_bio_X509(b, x) == 1) {
        char *p = NULL;
        long n = BIO_get_mem_data(b, &p);
        if (n > 0) gs_bld_append(out, p, n);
    }
    BIO_free(b);
}

/* This thread's OpenSSL errors, oldest first, one per line, each with the
   text its raiser added after a colon, and clears them. */
void tls_error_text(gs_rref out) {
    unsigned long e;
    const char *data = NULL;
    int flags = 0;
    int first = 1;
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        char line[256];
        ERR_error_string_n(e, line, sizeof line);
        if (!first) gs_bld_append(out, "\n", 1);
        append_str(out, line);
        if ((flags & ERR_TXT_STRING) && data && *data) {
            gs_bld_append(out, ": ", 2);
            append_str(out, data);
        }
        first = 0;
    }
}

/* The OpenSSL the program runs with, such as "OpenSSL 3.0.13 30 Jan 2024". */
void tls_library(gs_rref out) {
    append_str(out, OpenSSL_version(OPENSSL_VERSION));
}
