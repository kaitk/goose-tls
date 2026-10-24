/* The C under the TLS 1.3 server written in Goose (server.goose,
   docs/architecture.md): libcrypto's primitives as calls on a connection,
   and the memory Goose can't own across calls and threads. The protocol's
   decisions are all Goose's: which message comes next, what is checked, the
   key schedule's order and labels. This file only does what it is told.

   - A context: the certificate chain as DER, the key, and the settings a
     handshake reads, shared by every connection and thread that holds a
     reference to it.
   - A connection: two byte queues (bytes fed and not yet read, among them
     the record whose plaintext is being read, and bytes waiting for drain),
     each freed once empty; the record keys and sequence numbers of each
     direction; during the handshake, its transcript and its secrets; and a
     copy of the Goose server's state, which each call loads and stores.

   Secrets never cross to Goose. A handshake's secrets sit in numbered slots
   that Goose names; a direction's traffic secret sits beside its keys for a
   KeyUpdate; everything secret is cleansed when it is replaced or freed.

   A handle is the object's address with bit 0 set, as an int64_t, so that
   tls.goose tells these from libssl's objects, whose handles are even. 0 is
   none. Written against OpenSSL 3.0's API with nothing deprecated; ML-KEM
   is used only where the provider has it (3.5 or later). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "goose.h"
#include "tls.h"

/* The Goose server's state, opaque here: tlsg_load and tlsg_store copy it,
   and Goose passes the address of its last byte so that its size needs no
   mirror in C. */
#define STATE_CAP 256

/* Handshake secret slots: room for the largest secret, a hybrid group's
   64-byte shared secret. */
#define SLOTS 13
#define SLOT_CAP 64

/* A session ticket's envelope: its version, its key's id, and its AES-GCM
   nonce, which the AEAD also authenticates. */
#define TICKET_VERSION 1
#define TICKET_HEAD (1 + 4 + 12)

/* Signature schemes (RFC 8446, section 4.2.3) and groups (section 4.2.7;
   RFC 10024 for X25519MLKEM768), as server.goose names them. */
#define SCHEME_ECDSA_P256_SHA256 0x0403
#define SCHEME_RSA_PSS_RSAE_SHA256 0x0804
#define GROUP_P256 0x0017
#define GROUP_P384 0x0018
#define GROUP_X25519 0x001d
#define GROUP_X25519MLKEM768 0x11ec

#define MLKEM768_EK 1184
#define MLKEM768_CT 1088

typedef struct {
    uint16_t code;
    EVP_CIPHER *cipher;
    /* QUIC's header protection (RFC 9001, section 5.4): AES-ECB under the
       suite's key length, or ChaCha20. */
    EVP_CIPHER *hp;
    EVP_MD *md;
    size_t key_len, hash_len;
} suite_t;

/* Algorithms fetched once for the process, as the plan asks: none is
   fetched per record or per handshake. */
static struct {
    suite_t suites[3];
    EVP_MAC *hmac;
    int mlkem;
} alg;
static int alg_ok;
static CRYPTO_ONCE alg_once = CRYPTO_ONCE_STATIC_INIT;

static void alg_init(void) {
    /* The server raises libssl's reasons (tlsg_fail), whose text libssl
       loads only when it starts. */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
    static const struct { uint16_t code; const char *cipher, *hp, *md; size_t key_len; } defs[3] = {
        { 0x1301, "AES-128-GCM", "AES-128-ECB", "SHA256", 16 },
        { 0x1302, "AES-256-GCM", "AES-256-ECB", "SHA384", 32 },
        { 0x1303, "ChaCha20-Poly1305", "ChaCha20", "SHA256", 32 },
    };
    for (int i = 0; i < 3; i++) {
        suite_t *s = &alg.suites[i];
        s->code = defs[i].code;
        s->cipher = EVP_CIPHER_fetch(NULL, defs[i].cipher, NULL);
        s->hp = EVP_CIPHER_fetch(NULL, defs[i].hp, NULL);
        s->md = EVP_MD_fetch(NULL, defs[i].md, NULL);
        s->key_len = defs[i].key_len;
        s->hash_len = s->md ? (size_t)EVP_MD_get_size(s->md) : 0;
        if (!s->cipher || !s->hp || !s->md) return;
    }
    alg.hmac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);
    EVP_KEM *kem = EVP_KEM_fetch(NULL, "ML-KEM-768", NULL);
    alg.mlkem = kem != NULL;
    EVP_KEM_free(kem);
    ERR_clear_error();
    alg_ok = alg.hmac != NULL;
}

static int algs(void) { return CRYPTO_THREAD_run_once(&alg_once, alg_init) && alg_ok; }

static const suite_t *suite_of(int64_t code) {
    for (int i = 0; i < 3; i++)
        if (alg.suites[i].code == code) return &alg.suites[i];
    return NULL;
}

/* ---- Contexts ---- */

typedef struct {
    int refs;
    /* Guards refs and the ticket keys, which every thread holding a
       reference to the context reads and turns. */
    CRYPTO_RWLOCK *lock;
    ticket_key keys[2];
    EVP_PKEY *key;
    uint16_t scheme;
    /* The chain, leaf first: each certificate's DER after a 3-byte length,
       as RFC 8446's CertificateEntry has it. */
    uint8_t *chain;
    size_t chain_len;
    uint8_t *alpn;
    size_t alpn_len;
    uint8_t groups[16];
    size_t groups_len;
    uint8_t choose;
} gctx;

#define CTX(h) ((gctx *)(intptr_t)((h) & ~(int64_t)1))
#define HANDLE(p) ((int64_t)(intptr_t)(p) | 1)

static void ctx_release(gctx *c) {
    int refs = 0;
    if (!c || !CRYPTO_atomic_add(&c->refs, -1, &refs, c->lock) || refs > 0) return;
    OPENSSL_cleanse(c->keys, sizeof c->keys);
    EVP_PKEY_free(c->key);
    OPENSSL_free(c->chain);
    OPENSSL_free(c->alpn);
    CRYPTO_THREAD_lock_free(c->lock);
    OPENSSL_free(c);
}

static int ctx_retain(gctx *c) {
    int refs = 0;
    return c && CRYPTO_atomic_add(&c->refs, 1, &refs, c->lock) && refs > 1;
}

/* The scheme the key signs with: ECDSA for a P-256 key, RSA-PSS for an RSA
   key of 2048 bits or more; 0 for any other. */
static uint16_t scheme_of(EVP_PKEY *k) {
    char group[32];
    size_t n = 0;
    if (EVP_PKEY_is_a(k, "EC") &&
        EVP_PKEY_get_utf8_string_param(k, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group, &n) == 1 &&
        strcmp(group, "prime256v1") == 0)
        return SCHEME_ECDSA_P256_SHA256;
    if (EVP_PKEY_is_a(k, "RSA") && EVP_PKEY_get_bits(k) >= 2048) return SCHEME_RSA_PSS_RSAE_SHA256;
    return 0;
}

static int chain_add(gctx *c, X509 *x) {
    int n = i2d_X509(x, NULL);
    if (n <= 0 || n > 0xffffff) return 0;
    uint8_t *p = OPENSSL_realloc(c->chain, c->chain_len + 3 + (size_t)n);
    if (!p) return 0;
    c->chain = p;
    p += c->chain_len;
    p[0] = (uint8_t)(n >> 16), p[1] = (uint8_t)(n >> 8), p[2] = (uint8_t)n;
    uint8_t *q = p + 3;
    if (i2d_X509(x, &q) != n) return 0;
    c->chain_len += 3 + (size_t)n;
    return 1;
}

/* A server context from PEM text: the leaf and any intermediates, and the
   leaf's key, which must match it and be one the server signs with. 0 when
   any of it fails, with the reason in OpenSSL's error queue. */
int64_t tlsg_ctx_new(tls_bytes chain, tls_bytes key) {
    ERR_clear_error();
    if (!algs()) return 0;
    if (chain.len <= 0 || chain.len > INT32_MAX || key.len <= 0 || key.len > INT32_MAX) return 0;
    gctx *c = OPENSSL_zalloc(sizeof *c);
    if (!c) return 0;
    c->refs = 1;
    c->lock = CRYPTO_THREAD_lock_new();
    BIO *cb = BIO_new_mem_buf(chain.data, (int)chain.len);
    BIO *kb = BIO_new_mem_buf(key.data, (int)key.len);
    X509 *leaf = cb ? PEM_read_bio_X509(cb, NULL, NULL, NULL) : NULL;
    int ok = c->lock && kb && leaf && chain_add(c, leaf);
    while (ok) {
        X509 *ca = PEM_read_bio_X509(cb, NULL, NULL, NULL);
        if (!ca) break;
        ok = chain_add(c, ca);
        X509_free(ca);
    }
    if (ok) {
        /* The loop ends on the PEM reader's "no start line" at the end. */
        ERR_clear_error();
        c->key = PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL);
        ok = c->key && X509_check_private_key(leaf, c->key) == 1;
    }
    if (ok) {
        c->scheme = scheme_of(c->key);
        if (!c->scheme) {
            ERR_raise_data(ERR_LIB_SSL, SSL_R_UNKNOWN_CERTIFICATE_TYPE, "%s",
                           "the key must be EC P-256, or RSA of 2048 bits or more");
            ok = 0;
        }
    }
    X509_free(leaf);
    BIO_free(cb);
    BIO_free(kb);
    if (!ok) {
        ctx_release(c);
        return 0;
    }
    return HANDLE(c);
}

int64_t tlsg_ctx_share(int64_t h) { return ctx_retain(CTX(h)) ? h : 0; }

void tlsg_ctx_free(int64_t h) { ctx_release(CTX(h)); }

/* Sets the context's ALPN protocols, in wire format, before it accepts. */
uint8_t tlsg_ctx_set_alpn(int64_t h, tls_bytes alpn) {
    gctx *c = CTX(h);
    if (!c || alpn.len < 0 || alpn.len > 65535) return 0;
    uint8_t *p = alpn.len ? OPENSSL_memdup(alpn.data, (size_t)alpn.len) : NULL;
    if (alpn.len && !p) return 0;
    OPENSSL_free(c->alpn);
    c->alpn = p;
    c->alpn_len = (size_t)alpn.len;
    return 1;
}

/* Sets the context's groups, 2-byte codes in order of preference, before it
   accepts. */
uint8_t tlsg_ctx_set_groups(int64_t h, tls_bytes groups) {
    gctx *c = CTX(h);
    if (!c || groups.len <= 0 || groups.len > (int64_t)sizeof c->groups || groups.len % 2) return 0;
    memcpy(c->groups, groups.data, (size_t)groups.len);
    c->groups_len = (size_t)groups.len;
    return 1;
}

void tlsg_ctx_set_choose(int64_t h) {
    if (CTX(h)) CTX(h)->choose = 1;
}

void tlsg_ctx_alpn(int64_t h, gs_rref out) {
    if (CTX(h) && CTX(h)->alpn_len) gs_bld_append(out, CTX(h)->alpn, (int64_t)CTX(h)->alpn_len);
}

void tlsg_ctx_groups(int64_t h, gs_rref out) {
    if (CTX(h)) gs_bld_append(out, CTX(h)->groups, (int64_t)CTX(h)->groups_len);
}

void tlsg_ctx_chain(int64_t h, gs_rref out) {
    if (CTX(h)) gs_bld_append(out, CTX(h)->chain, (int64_t)CTX(h)->chain_len);
}

uint8_t tlsg_ctx_chooses(int64_t h) { return CTX(h) && CTX(h)->choose; }

int64_t tlsg_ctx_scheme(int64_t h) { return CTX(h) ? CTX(h)->scheme : 0; }

/* Whether the provider has what a group needs. */
uint8_t tlsg_has_group(int64_t group) {
    if (!algs()) return 0;
    switch (group) {
    case GROUP_X25519:
    case GROUP_P256:
    case GROUP_P384:
        return 1;
    case GROUP_X25519MLKEM768:
        return (uint8_t)alg.mlkem;
    default:
        return 0;
    }
}

/* ---- Connections ---- */

/* Bytes p[off..off + len), in a buffer of cap bytes, freed once empty. */
typedef struct {
    uint8_t *p;
    size_t off, len, cap;
} queue;

typedef struct {
    EVP_CIPHER_CTX *c;
    uint8_t iv[12];
    uint64_t seq;
    uint8_t secret[48];
} direction;

typedef struct {
    EVP_MD_CTX *md;
    /* HMAC under the suite's hash for the key schedule, made on first use and
       freed with the transcript, so that a handshake waiting for the client
       holds none. */
    EVP_MAC_CTX *mac;
    uint8_t slot[SLOTS][SLOT_CAP];
    uint8_t slot_len[SLOTS];
    uint8_t *hello;
    size_t hello_len;
} handshake;

typedef struct {
    gctx *ctx;
    const suite_t *suite;
    queue in, out;
    /* A record decrypts in place, and stays at the front of in, held bytes
       long, until its content, plain_len bytes from plain_off, is read; the
       bytes fed that Goose sees start after it. */
    uint16_t held, plain_off, plain_len;
    direction rd, wr;
    handshake *hs;
    /* A QUIC connection's packet keys and transport parameters (the QUIC
       section below); NULL for TLS over a stream. */
    struct quic *q;
    char *sni;
    uint8_t sni_len;
    uint8_t state[STATE_CAP];
} gconn;

#define CONN(h) ((gconn *)(intptr_t)((h) & ~(int64_t)1))

static void q_free(queue *q) {
    OPENSSL_free(q->p);
    memset(q, 0, sizeof *q);
}

/* Room for n more bytes at the end; 0 when the allocation fails. */
static uint8_t *q_room(queue *q, size_t n) {
    if (q->off + q->len + n <= q->cap) return q->p + q->off + q->len;
    if (q->off) {
        memmove(q->p, q->p + q->off, q->len);
        q->off = 0;
        if (q->len + n <= q->cap) return q->p + q->len;
    }
    size_t cap = q->len + n;
    uint8_t *p = OPENSSL_realloc(q->p, cap);
    if (!p) return NULL;
    q->p = p;
    q->cap = cap;
    return q->p + q->len;
}

static int q_put(queue *q, const void *data, size_t n) {
    uint8_t *p = q_room(q, n);
    if (!p) return 0;
    memcpy(p, data, n);
    q->len += n;
    return 1;
}

static void q_drop(queue *q, size_t n) {
    if (n >= q->len) {
        q_free(q);
        return;
    }
    q->off += n;
    q->len -= n;
}

static void dir_clear(direction *d) {
    EVP_CIPHER_CTX_free(d->c);
    OPENSSL_cleanse(d, sizeof *d);
}

static void mac_free(handshake *hs) {
    EVP_MAC_CTX_free(hs->mac);
    hs->mac = NULL;
}

static void hs_free(gconn *c) {
    if (!c->hs) return;
    EVP_MD_CTX_free(c->hs->md);
    mac_free(c->hs);
    OPENSSL_free(c->hs->hello);
    OPENSSL_clear_free(c->hs, sizeof *c->hs);
    c->hs = NULL;
}

int64_t tlsg_accept(int64_t ctx) {
    ERR_clear_error();
    if (!ctx_retain(CTX(ctx))) return 0;
    gconn *c = OPENSSL_zalloc(sizeof *c);
    if (!c) {
        ctx_release(CTX(ctx));
        return 0;
    }
    c->ctx = CTX(ctx);
    return HANDLE(c);
}

static void quic_free(gconn *c);

void tlsg_conn_free(int64_t h) {
    gconn *c = CONN(h);
    if (!c) return;
    quic_free(c);
    ctx_release(c->ctx);
    if (c->in.p) OPENSSL_cleanse(c->in.p, c->in.cap);
    q_free(&c->in);
    q_free(&c->out);
    dir_clear(&c->rd);
    dir_clear(&c->wr);
    hs_free(c);
    OPENSSL_free(c->sni);
    OPENSSL_free(c);
}

/* The context the connection holds now. */
int64_t tlsg_conn_ctx(int64_t h) { return CONN(h) ? HANDLE(CONN(h)->ctx) : 0; }

/* Moves the connection to another context: the connection takes a
   reference to it and drops its old one. */
uint8_t tlsg_conn_use(int64_t h, int64_t ctx) {
    gconn *c = CONN(h);
    if (!c || !ctx_retain(CTX(ctx))) return 0;
    ctx_release(c->ctx);
    c->ctx = CTX(ctx);
    return 1;
}

static size_t state_size(const uint8_t *st, const uint8_t *last) {
    size_t n = (size_t)(last - st) + 1;
    if (last < st || n > STATE_CAP) abort();
    return n;
}

void tlsg_load(int64_t h, uint8_t *st, const uint8_t *last) {
    memcpy(st, CONN(h)->state, state_size(st, last));
}

void tlsg_store(int64_t h, const uint8_t *st, const uint8_t *last) {
    memcpy(CONN(h)->state, st, state_size(st, last));
}

/* Appends data to the bytes fed: data.len, or -1 when the queue would pass
   max bytes or the allocation fails, with nothing appended. */
int64_t tlsg_feed(int64_t h, tls_bytes data, int64_t max) {
    gconn *c = CONN(h);
    if (!c || data.len < 0 || max < 0 || (uint64_t)max < c->in.len ||
        (uint64_t)data.len > (uint64_t)max - c->in.len)
        return -1;
    if (data.len && !q_put(&c->in, data.data, (size_t)data.len)) return -1;
    return data.len;
}

int64_t tlsg_in_len(int64_t h) { return (int64_t)(CONN(h)->in.len - CONN(h)->held); }

/* Copies up to out.len of the bytes fed, from offset at, into out. */
int64_t tlsg_in_peek(int64_t h, int64_t at, tls_buf out) {
    gconn *c = CONN(h);
    queue *q = &c->in;
    if (at < 0 || out.len <= 0 || (size_t)at >= q->len - c->held) return 0;
    size_t n = q->len - c->held - (size_t)at;
    if (n > (size_t)out.len) n = (size_t)out.len;
    memcpy(out.data, q->p + q->off + c->held + at, n);
    return (int64_t)n;
}

void tlsg_in_skip(int64_t h, int64_t n) {
    gconn *c = CONN(h);
    queue *q = &c->in;
    if (n <= 0) return;
    if (!c->held) {
        q_drop(q, (size_t)n);
        return;
    }
    size_t after = q->len - c->held, k = (size_t)n < after ? (size_t)n : after;
    uint8_t *p = q->p + q->off + c->held;
    memmove(p, p + k, after - k);
    q->len -= k;
}

int64_t tlsg_pending(int64_t h) { return CONN(h) ? (int64_t)CONN(h)->out.len : 0; }

int64_t tlsg_drain(int64_t h, tls_buf buf) {
    gconn *c = CONN(h);
    if (!c || buf.len <= 0) return 0;
    size_t n = c->out.len < (size_t)buf.len ? c->out.len : (size_t)buf.len;
    if (!n) return 0;
    memcpy(buf.data, c->out.p + c->out.off, n);
    q_drop(&c->out, n);
    return (int64_t)n;
}

/* Appends bytes the server sends as they are: a plaintext record. */
uint8_t tlsg_out_put(int64_t h, tls_bytes data) {
    return data.len >= 0 && q_put(&CONN(h)->out, data.data, (size_t)data.len);
}

int64_t tlsg_plain_len(int64_t h) { return CONN(h)->plain_len; }

static uint8_t *plain_at(gconn *c) { return c->in.p + c->in.off + 5 + c->plain_off; }

/* Drops the held record, its content read or discarded. */
static void plain_done(gconn *c) {
    q_drop(&c->in, c->held);
    c->held = c->plain_off = c->plain_len = 0;
}

/* Moves up to buf.len bytes of plaintext from the front into buf. */
int64_t tlsg_plain_read(int64_t h, tls_buf buf) {
    gconn *c = CONN(h);
    if (buf.len <= 0 || !c->plain_len) return 0;
    size_t n = c->plain_len < (size_t)buf.len ? c->plain_len : (size_t)buf.len;
    memcpy(buf.data, plain_at(c), n);
    c->plain_off += (uint16_t)n;
    c->plain_len -= (uint16_t)n;
    if (!c->plain_len) plain_done(c);
    return (int64_t)n;
}

/* Moves the last n bytes of plaintext, a record's content that isn't
   application data, into buf, which must hold them. */
int64_t tlsg_plain_pop(int64_t h, int64_t n, tls_buf buf) {
    gconn *c = CONN(h);
    if (n < 0 || (size_t)n > c->plain_len || n > buf.len) return -1;
    memcpy(buf.data, plain_at(c) + c->plain_len - (size_t)n, (size_t)n);
    c->plain_len -= (uint16_t)n;
    if (!c->plain_len) plain_done(c);
    return n;
}

/* Discards the plaintext not yet read, after a failure. */
void tlsg_plain_clear(int64_t h) {
    gconn *c = CONN(h);
    if (!c->held) return;
    OPENSSL_cleanse(c->in.p + c->in.off, c->held);
    plain_done(c);
}

void tlsg_set_sni(int64_t h, tls_bytes name) {
    gconn *c = CONN(h);
    OPENSSL_free(c->sni);
    c->sni = NULL;
    c->sni_len = 0;
    if (name.len <= 0 || name.len > 255) return;
    c->sni = OPENSSL_memdup(name.data, (size_t)name.len);
    if (c->sni) c->sni_len = (uint8_t)name.len;
}

void tlsg_sni(int64_t h, gs_rref out) {
    gconn *c = CONN(h);
    if (c && c->sni_len) gs_bld_append(out, c->sni, c->sni_len);
}

/* ---- The handshake: transcript and secrets ---- */

/* Starts the handshake's transcript and secrets once the suite is chosen. */
uint8_t tlsg_hs_begin(int64_t h, int64_t suite) {
    gconn *c = CONN(h);
    const suite_t *s = suite_of(suite);
    if (!s) return 0;
    c->suite = s;
    if (!c->hs) {
        c->hs = OPENSSL_zalloc(sizeof *c->hs);
        if (!c->hs) return 0;
    }
    mac_free(c->hs);
    if (!c->hs->md && !(c->hs->md = EVP_MD_CTX_new())) return 0;
    return EVP_DigestInit_ex2(c->hs->md, s->md, NULL) == 1;
}

/* Frees the transcript, which the handshake no longer needs once the
   server's Finished is sent. */
void tlsg_hs_drop_transcript(int64_t h) {
    gconn *c = CONN(h);
    if (c->hs) {
        EVP_MD_CTX_free(c->hs->md);
        c->hs->md = NULL;
        mac_free(c->hs);
        OPENSSL_free(c->hs->hello);
        c->hs->hello = NULL;
        c->hs->hello_len = 0;
    }
}

/* Cleanses and frees everything the handshake held. */
void tlsg_hs_end(int64_t h) { hs_free(CONN(h)); }

uint8_t tlsg_tr_update(int64_t h, tls_bytes data) {
    handshake *hs = CONN(h)->hs;
    return hs && hs->md && data.len >= 0 && EVP_DigestUpdate(hs->md, data.data, (size_t)data.len) == 1;
}

/* The transcript's hash so far, into out: its length, or 0. */
int64_t tlsg_tr_hash(int64_t h, tls_buf out) {
    handshake *hs = CONN(h)->hs;
    if (!hs || !hs->md || out.len < (int64_t)CONN(h)->suite->hash_len) return 0;
    EVP_MD_CTX *copy = EVP_MD_CTX_new();
    unsigned int n = 0;
    int ok = copy && EVP_MD_CTX_copy_ex(copy, hs->md) == 1 && EVP_DigestFinal_ex(copy, out.data, &n) == 1;
    EVP_MD_CTX_free(copy);
    return ok ? (int64_t)n : 0;
}

/* After a HelloRetryRequest: the transcript becomes the message_hash
   message of the first ClientHello's hash (RFC 8446, section 4.4.1). */
uint8_t tlsg_tr_restart(int64_t h) {
    gconn *c = CONN(h);
    uint8_t m[4 + EVP_MAX_MD_SIZE];
    tls_buf out = { m + 4, EVP_MAX_MD_SIZE };
    int64_t n = tlsg_tr_hash(h, out);
    if (!n) return 0;
    m[0] = 254, m[1] = 0, m[2] = 0, m[3] = (uint8_t)n;
    return EVP_DigestInit_ex2(c->hs->md, c->suite->md, NULL) == 1 &&
           EVP_DigestUpdate(c->hs->md, m, 4 + (size_t)n) == 1;
}

/* The transcript's hash as if extra followed what it holds, into out: its
   length, or 0. For a PSK binder, over a ClientHello cut before its binders
   (section 4.2.11.2). */
int64_t tlsg_tr_hash_with(int64_t h, tls_bytes extra, tls_buf out) {
    handshake *hs = CONN(h)->hs;
    if (!hs || !hs->md || extra.len < 0 || out.len < (int64_t)CONN(h)->suite->hash_len) return 0;
    EVP_MD_CTX *copy = EVP_MD_CTX_new();
    unsigned int n = 0;
    int ok = copy && EVP_MD_CTX_copy_ex(copy, hs->md) == 1 &&
             EVP_DigestUpdate(copy, extra.data, (size_t)extra.len) == 1 &&
             EVP_DigestFinal_ex(copy, out.data, &n) == 1;
    EVP_MD_CTX_free(copy);
    return ok ? (int64_t)n : 0;
}

static int slot_ok(gconn *c, int64_t s);

/* Adds the Finished message whose verify_data is slot[s] to the transcript:
   the client's, before it arrives, for the resumption master secret. */
uint8_t tlsg_tr_add_finished(int64_t h, int64_t s) {
    gconn *c = CONN(h);
    if (!slot_ok(c, s) || !c->hs->md) return 0;
    uint8_t m[4] = { 20, 0, 0, c->hs->slot_len[s] };
    return EVP_DigestUpdate(c->hs->md, m, 4) == 1 &&
           EVP_DigestUpdate(c->hs->md, c->hs->slot[s], c->hs->slot_len[s]) == 1;
}

/* Keeps the first ClientHello, which the second must repeat after a
   HelloRetryRequest. */
uint8_t tlsg_hello_keep(int64_t h, tls_bytes hello) {
    handshake *hs = CONN(h)->hs;
    if (!hs || hello.len <= 0) return 0;
    OPENSSL_free(hs->hello);
    hs->hello = OPENSSL_memdup(hello.data, (size_t)hello.len);
    hs->hello_len = hs->hello ? (size_t)hello.len : 0;
    return hs->hello != NULL;
}

void tlsg_hello_kept(int64_t h, gs_rref out) {
    handshake *hs = CONN(h)->hs;
    if (hs && hs->hello) gs_bld_append(out, hs->hello, (int64_t)hs->hello_len);
}

static int slot_ok(gconn *c, int64_t s) { return c->hs && s >= 0 && s < SLOTS; }

/* The key schedule's HKDF (RFC 5869) is HMAC under the suite's hash, on one
   context per handshake, rather than OpenSSL's HKDF, which makes an HMAC
   context for each derivation: Extract is HMAC(salt, IKM), and Expand, for
   the at most Hash.length bytes that TLS 1.3 asks of it, is the first n
   bytes of HMAC(PRK, info || 0x01). */
static EVP_MAC_CTX *mac_new(const suite_t *s) {
    EVP_MAC_CTX *m = EVP_MAC_CTX_new(alg.hmac);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)EVP_MD_get0_name(s->md), 0),
        OSSL_PARAM_construct_end(),
    };
    if (m && EVP_MAC_CTX_set_params(m, params) != 1) {
        EVP_MAC_CTX_free(m);
        return NULL;
    }
    return m;
}

static EVP_MAC_CTX *hs_mac(gconn *c) {
    if (!c->hs->mac) c->hs->mac = mac_new(c->suite);
    return c->hs->mac;
}

/* out = the first n bytes, at most Hash.length, of HMAC(key, a || b). */
static int hmac(EVP_MAC_CTX *m, const suite_t *s, const uint8_t *key, size_t key_len, const uint8_t *a,
                size_t a_len, const uint8_t *b, size_t b_len, uint8_t *out, size_t n) {
    uint8_t full[EVP_MAX_MD_SIZE];
    size_t len = 0;
    int ok = m && n <= s->hash_len && EVP_MAC_init(m, key, key_len, NULL) == 1 &&
             EVP_MAC_update(m, a, a_len) == 1 && (!b_len || EVP_MAC_update(m, b, b_len) == 1) &&
             EVP_MAC_final(m, full, &len, sizeof full) == 1 && len == s->hash_len;
    if (ok) memcpy(out, full, n);
    OPENSSL_cleanse(full, sizeof full);
    return ok;
}

/* RFC 8446, section 7.1: HKDF-Expand-Label(secret, label, context, n). */
static int expand_label(EVP_MAC_CTX *m, const suite_t *s, const uint8_t *secret, size_t secret_len,
                        const char *label, size_t label_len, const uint8_t *context, size_t context_len,
                        uint8_t *out, size_t n) {
    static const uint8_t one = 1;
    uint8_t info[2 + 1 + 255 + 1 + 255];
    if (label_len > 249 || context_len > 255) return 0;
    size_t k = 0;
    info[k++] = (uint8_t)(n >> 8);
    info[k++] = (uint8_t)n;
    info[k++] = (uint8_t)(6 + label_len);
    memcpy(info + k, "tls13 ", 6);
    k += 6;
    memcpy(info + k, label, label_len);
    k += label_len;
    info[k++] = (uint8_t)context_len;
    if (context_len) memcpy(info + k, context, context_len);
    k += context_len;
    return hmac(m, s, secret, secret_len, info, k, &one, 1, out, n);
}

/* slot[dst] = HKDF-Extract(salt, ikm), where -1 for either means Hash.length
   zero bytes (RFC 8446, section 7.1). */
uint8_t tlsg_ks_extract(int64_t h, int64_t dst, int64_t salt, int64_t ikm) {
    gconn *c = CONN(h);
    if (!slot_ok(c, dst) || (salt != -1 && !slot_ok(c, salt)) || (ikm != -1 && !slot_ok(c, ikm))) return 0;
    handshake *hs = c->hs;
    size_t hl = c->suite->hash_len;
    static const uint8_t zeros[SLOT_CAP];
    const uint8_t *sp = salt == -1 ? zeros : hs->slot[salt];
    size_t sl = salt == -1 ? hl : hs->slot_len[salt];
    const uint8_t *ip = ikm == -1 ? zeros : hs->slot[ikm];
    size_t il = ikm == -1 ? hl : hs->slot_len[ikm];
    uint8_t out[SLOT_CAP];
    int ok = hmac(hs_mac(c), c->suite, sp, sl, ip, il, NULL, 0, out, hl);
    if (ok) {
        memcpy(hs->slot[dst], out, hl);
        hs->slot_len[dst] = (uint8_t)hl;
    }
    OPENSSL_cleanse(out, sizeof out);
    return (uint8_t)ok;
}

/* slot[dst] = HKDF-Expand-Label(slot[src], label, context, Hash.length):
   Derive-Secret when context is a transcript hash. */
uint8_t tlsg_ks_expand(int64_t h, int64_t dst, int64_t src, tls_bytes label, tls_bytes context) {
    gconn *c = CONN(h);
    if (!slot_ok(c, dst) || !slot_ok(c, src) || label.len < 0 || context.len < 0) return 0;
    handshake *hs = c->hs;
    size_t hl = c->suite->hash_len;
    uint8_t out[SLOT_CAP];
    int ok = expand_label(hs_mac(c), c->suite, hs->slot[src], hs->slot_len[src], (const char *)label.data,
                          (size_t)label.len, context.data, (size_t)context.len, out, hl);
    if (ok) {
        memcpy(hs->slot[dst], out, hl);
        hs->slot_len[dst] = (uint8_t)hl;
    }
    OPENSSL_cleanse(out, sizeof out);
    return (uint8_t)ok;
}

/* slot[dst] = the Finished verify_data for the base key slot[src] over the
   transcript hash (RFC 8446, section 4.4.4). */
uint8_t tlsg_ks_finished(int64_t h, int64_t dst, int64_t src, tls_bytes hash) {
    gconn *c = CONN(h);
    if (!slot_ok(c, dst) || !slot_ok(c, src) || hash.len < 0) return 0;
    handshake *hs = c->hs;
    size_t hl = c->suite->hash_len;
    EVP_MAC_CTX *m = hs_mac(c);
    uint8_t key[SLOT_CAP], out[SLOT_CAP];
    int ok = expand_label(m, c->suite, hs->slot[src], hs->slot_len[src], "finished", 8, NULL, 0, key, hl) &&
             hmac(m, c->suite, key, hl, hash.data, (size_t)hash.len, NULL, 0, out, hl);
    if (ok) {
        memcpy(hs->slot[dst], out, hl);
        hs->slot_len[dst] = (uint8_t)hl;
    }
    OPENSSL_cleanse(key, sizeof key);
    OPENSSL_cleanse(out, sizeof out);
    return (uint8_t)ok;
}

/* Copies a slot that is about to be sent, the server's verify_data. */
void tlsg_ks_public(int64_t h, int64_t s, gs_rref out) {
    gconn *c = CONN(h);
    if (slot_ok(c, s)) gs_bld_append(out, c->hs->slot[s], c->hs->slot_len[s]);
}

/* Whether received equals slot[s], in constant time. */
uint8_t tlsg_ks_check(int64_t h, int64_t s, tls_bytes received) {
    gconn *c = CONN(h);
    return slot_ok(c, s) && received.len == c->hs->slot_len[s] && c->hs->slot_len[s] > 0 &&
           CRYPTO_memcmp(received.data, c->hs->slot[s], (size_t)received.len) == 0;
}

/* Sets slot[s] to known bytes, for test/server/rfc8448.goose, which takes
   the shared secret from RFC 8448's trace. */
uint8_t tlsg_ks_set(int64_t h, int64_t s, tls_bytes value) {
    gconn *c = CONN(h);
    if (!slot_ok(c, s) || value.len <= 0 || value.len > SLOT_CAP) return 0;
    memcpy(c->hs->slot[s], value.data, (size_t)value.len);
    c->hs->slot_len[s] = (uint8_t)value.len;
    return 1;
}

void tlsg_ks_wipe(int64_t h, int64_t s) {
    gconn *c = CONN(h);
    if (!slot_ok(c, s)) return;
    OPENSSL_cleanse(c->hs->slot[s], SLOT_CAP);
    c->hs->slot_len[s] = 0;
}

/* ---- Key exchange and signatures ---- */

static int x25519_pair(EVP_PKEY **ours, uint8_t pub[32]) {
    size_t n = 32;
    *ours = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    return *ours && EVP_PKEY_get_raw_public_key(*ours, pub, &n) == 1 && n == 32;
}

static int derive(EVP_PKEY *ours, EVP_PKEY *peer, uint8_t *out, size_t want) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ours, NULL);
    size_t n = want;
    int ok = ctx && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer_ex(ctx, peer, 1) == 1 &&
             EVP_PKEY_derive(ctx, out, &n) == 1 && n == want;
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

/* X25519 with the client's 32-byte share: our share into pub, the secret
   into ss. Rejects the all-zero secret (RFC 8446, section 7.4.2). */
static int kx_x25519(const uint8_t *share, uint8_t pub[32], uint8_t ss[32]) {
    EVP_PKEY *ours = NULL;
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key_ex(NULL, "X25519", NULL, share, 32);
    int ok = peer && x25519_pair(&ours, pub) && derive(ours, peer, ss, 32);
    EVP_PKEY_free(ours);
    EVP_PKEY_free(peer);
    static const uint8_t zero[32];
    return ok && CRYPTO_memcmp(ss, zero, 32) != 0;
}

/* ECDHE on a NIST curve with the client's uncompressed point: our point
   into pub, the x-coordinate into ss. Importing the point checks that it is
   on the curve. */
static int kx_ec(const char *curve, size_t field, const uint8_t *share, size_t share_len, uint8_t *pub,
                 uint8_t *ss) {
    if (share_len != 1 + 2 * field || share[0] != 4) return 0;
    EVP_PKEY *ours = EVP_PKEY_Q_keygen(NULL, NULL, "EC", curve), *peer = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)curve, 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)share, share_len),
        OSSL_PARAM_construct_end(),
    };
    size_t n = 0;
    int ok = ours && pctx && EVP_PKEY_fromdata_init(pctx) == 1 &&
             EVP_PKEY_fromdata(pctx, &peer, EVP_PKEY_PUBLIC_KEY, params) == 1 &&
             EVP_PKEY_get_octet_string_param(ours, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pub, share_len, &n) == 1 &&
             n == share_len && derive(ours, peer, ss, field);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(ours);
    EVP_PKEY_free(peer);
    return ok;
}

/* X25519MLKEM768 (RFC 10024): the client's share is ML-KEM-768's
   encapsulation key then X25519's share; ours is the ciphertext then our
   X25519 share; the secret is ML-KEM's then X25519's. The server only
   encapsulates: it makes no ML-KEM key of its own. */
static int kx_hybrid(const uint8_t *share, uint8_t *pub, uint8_t ss[64]) {
    EVP_PKEY *ek = EVP_PKEY_new_raw_public_key_ex(NULL, "ML-KEM-768", NULL, share, MLKEM768_EK);
    EVP_PKEY_CTX *ctx = ek ? EVP_PKEY_CTX_new_from_pkey(NULL, ek, NULL) : NULL;
    size_t ct = MLKEM768_CT, sl = 32;
    int ok = ctx && EVP_PKEY_encapsulate_init(ctx, NULL) == 1 &&
             EVP_PKEY_encapsulate(ctx, pub, &ct, ss, &sl) == 1 && ct == MLKEM768_CT && sl == 32;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(ek);
    return ok && kx_x25519(share + MLKEM768_EK, pub + MLKEM768_CT, ss + 32);
}

/* The server's side of the key exchange for group with the client's share:
   our share appended to out, the shared secret into slot[dst]. 0 when the
   share is malformed or invalid, or the provider lacks the group. */
uint8_t tlsg_kx(int64_t h, int64_t group, tls_bytes share, gs_rref out, int64_t dst) {
    gconn *c = CONN(h);
    if (!slot_ok(c, dst) || share.len <= 0) return 0;
    uint8_t pub[MLKEM768_CT + 32], ss[64];
    size_t pub_len = 0, ss_len = 0;
    int ok = 0;
    switch (group) {
    case GROUP_X25519:
        ok = share.len == 32 && kx_x25519(share.data, pub, ss);
        pub_len = ss_len = 32;
        break;
    case GROUP_P256:
        ok = kx_ec("P-256", 32, share.data, (size_t)share.len, pub, ss);
        pub_len = 65, ss_len = 32;
        break;
    case GROUP_P384:
        ok = kx_ec("P-384", 48, share.data, (size_t)share.len, pub, ss);
        pub_len = 97, ss_len = 48;
        break;
    case GROUP_X25519MLKEM768:
        ok = alg.mlkem && share.len == MLKEM768_EK + 32 && kx_hybrid(share.data, pub, ss);
        pub_len = MLKEM768_CT + 32, ss_len = 64;
        break;
    }
    if (ok) {
        memcpy(c->hs->slot[dst], ss, ss_len);
        c->hs->slot_len[dst] = (uint8_t)ss_len;
        gs_bld_append(out, pub, (int64_t)pub_len);
    }
    OPENSSL_cleanse(ss, sizeof ss);
    return (uint8_t)ok;
}

/* Signs content with the context's key in its scheme, appending the
   signature as TLS carries it: DER for ECDSA. */
uint8_t tlsg_sign(int64_t h, tls_bytes content, gs_rref out) {
    gconn *c = CONN(h);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY_CTX *p = NULL;
    uint8_t sig[1024];
    size_t n = sizeof sig;
    int pss = c->ctx->scheme == SCHEME_RSA_PSS_RSAE_SHA256;
    if (pss && (size_t)EVP_PKEY_get_size(c->ctx->key) > sizeof sig) {
        EVP_MD_CTX_free(m);
        return 0;
    }
    int ok = m && EVP_DigestSignInit_ex(m, &p, "SHA256", NULL, NULL, c->ctx->key, NULL) == 1 &&
             (!pss || (EVP_PKEY_CTX_set_rsa_padding(p, RSA_PKCS1_PSS_PADDING) == 1 &&
                       EVP_PKEY_CTX_set_rsa_pss_saltlen(p, RSA_PSS_SALTLEN_DIGEST) == 1)) &&
             EVP_DigestSign(m, sig, &n, content.data, (size_t)content.len) == 1;
    EVP_MD_CTX_free(m);
    if (ok) gs_bld_append(out, sig, (int64_t)n);
    return (uint8_t)ok;
}

uint8_t tlsg_random(tls_buf out) { return out.len >= 0 && RAND_bytes(out.data, (int)out.len) == 1; }

/* ---- Records ---- */

#define DIR_READ 0
#define DIR_WRITE 1

static direction *dir_of(gconn *c, int64_t d) { return d == DIR_READ ? &c->rd : &c->wr; }

static int dir_keys(EVP_MAC_CTX *m, gconn *c, direction *d, int enc) {
    const suite_t *s = c->suite;
    uint8_t key[32];
    int ok = expand_label(m, s, d->secret, s->hash_len, "key", 3, NULL, 0, key, s->key_len) &&
             expand_label(m, s, d->secret, s->hash_len, "iv", 2, NULL, 0, d->iv, 12);
    if (ok && !d->c) ok = (d->c = EVP_CIPHER_CTX_new()) != NULL;
    ok = ok && EVP_CipherInit_ex2(d->c, s->cipher, key, NULL, enc, NULL) == 1;
    OPENSSL_cleanse(key, sizeof key);
    d->seq = 0;
    return ok;
}

/* Gives a direction the traffic secret in slot[s], and its key and IV. */
uint8_t tlsg_rec_keys(int64_t h, int64_t d, int64_t s) {
    gconn *c = CONN(h);
    if (!slot_ok(c, s) || c->hs->slot_len[s] != c->suite->hash_len) return 0;
    direction *dir = dir_of(c, d);
    memcpy(dir->secret, c->hs->slot[s], c->suite->hash_len);
    return (uint8_t)dir_keys(hs_mac(c), c, dir, d == DIR_WRITE);
}

/* A KeyUpdate: the direction's next secret (RFC 8446, section 7.2), and its
   key and IV. */
uint8_t tlsg_rec_update(int64_t h, int64_t d) {
    gconn *c = CONN(h);
    direction *dir = dir_of(c, d);
    size_t hl = c->suite->hash_len;
    uint8_t next[48];
    EVP_MAC_CTX *m = c->hs ? hs_mac(c) : mac_new(c->suite);
    int ok = dir->c && expand_label(m, c->suite, dir->secret, hl, "traffic upd", 11, NULL, 0, next, hl);
    if (ok) memcpy(dir->secret, next, hl);
    OPENSSL_cleanse(next, sizeof next);
    ok = ok && dir_keys(m, c, dir, d == DIR_WRITE);
    if (!c->hs) EVP_MAC_CTX_free(m);
    return (uint8_t)ok;
}

static void nonce(const direction *d, uint8_t out[12]) {
    memcpy(out, d->iv, 12);
    for (int i = 0; i < 8; i++) out[11 - i] ^= (uint8_t)(d->seq >> (8 * i));
}

/* Encrypts data as one record of the inner type kind and appends it: the
   direction's sequence number after it, or -1. data is at most 2^14 bytes,
   which Goose checks. */
int64_t tlsg_rec_seal(int64_t h, int64_t kind, tls_bytes data) {
    gconn *c = CONN(h);
    direction *d = &c->wr;
    if (!d->c || data.len < 0 || data.len > 16384 || d->seq == UINT64_MAX) return -1;
    size_t n = (size_t)data.len, len = n + 1 + 16;
    uint8_t *p = q_room(&c->out, 5 + len);
    if (!p) return -1;
    p[0] = 23, p[1] = 3, p[2] = 3, p[3] = (uint8_t)(len >> 8), p[4] = (uint8_t)len;
    uint8_t iv[12], type = (uint8_t)kind;
    nonce(d, iv);
    int a = 0, b = 0, f = 0;
    int ok = EVP_CipherInit_ex2(d->c, NULL, NULL, iv, 1, NULL) == 1 &&
             EVP_EncryptUpdate(d->c, NULL, &a, p, 5) == 1 &&
             (n == 0 || EVP_EncryptUpdate(d->c, p + 5, &a, data.data, (int)n) == 1) &&
             EVP_EncryptUpdate(d->c, p + 5 + n, &b, &type, 1) == 1 &&
             EVP_EncryptFinal_ex(d->c, p + 5 + n + 1, &f) == 1 &&
             EVP_CIPHER_CTX_ctrl(d->c, EVP_CTRL_AEAD_GET_TAG, 16, p + 5 + n + 1) == 1;
    if (!ok) return -1;
    c->out.len += 5 + len;
    d->seq++;
    return (int64_t)d->seq;
}

/* Decrypts, in place, the record at the front of the bytes fed, whose
   header Goose has checked and whose len bytes have all arrived, once the
   content read before it is gone. Its content becomes the plaintext only
   once its tag verifies, and the result is its inner type << 32 | its
   length; or -1 for a record that fails to decrypt, whose bytes are wiped
   but stay in the bytes fed, -2 for one with no inner type, or -3 for one
   whose TLSInnerPlaintext passes 2^14 + 1 bytes (RFC 8446, section 5.4). */
int64_t tlsg_rec_open(int64_t h, int64_t len) {
    gconn *c = CONN(h);
    direction *d = &c->rd;
    if (!d->c || c->held || len < 17 || (size_t)len + 5 > c->in.len || d->seq == UINT64_MAX) return -1;
    size_t n = (size_t)len - 16;
    uint8_t *hdr = c->in.p + c->in.off, *p = hdr + 5;
    uint8_t iv[12];
    nonce(d, iv);
    int a = 0, f = 0;
    int ok = EVP_CipherInit_ex2(d->c, NULL, NULL, iv, 0, NULL) == 1 &&
             EVP_DecryptUpdate(d->c, NULL, &a, hdr, 5) == 1 && EVP_DecryptUpdate(d->c, p, &a, p, (int)n) == 1 &&
             EVP_CIPHER_CTX_ctrl(d->c, EVP_CTRL_AEAD_SET_TAG, 16, p + n) == 1 &&
             EVP_DecryptFinal_ex(d->c, p + a, &f) == 1;
    if (!ok) {
        OPENSSL_cleanse(p, n);
        return -1;
    }
    d->seq++;
    size_t k = n;
    while (k > 0 && p[k - 1] == 0) k--;
    if (k == 0 || n > 16385) {
        OPENSSL_cleanse(p, n);
        q_drop(&c->in, 5 + (size_t)len);
        return k == 0 ? -2 : -3;
    }
    uint8_t type = p[k - 1];
    c->held = (uint16_t)(5 + len);
    c->plain_len = (uint16_t)(k - 1);
    if (!c->plain_len) plain_done(c);
    return (int64_t)type << 32 | (int64_t)(k - 1);
}

/* The sequence number a direction is at. */
int64_t tlsg_rec_seq(int64_t h, int64_t d) { return (int64_t)dir_of(CONN(h), d)->seq; }

/* ---- QUIC (RFC 9001) ----

   A QUIC connection carries the handshake's messages in CRYPTO frames, not
   records, and protects each packet itself: the keys below, one set per
   encryption level and direction. Goose builds and parses the packets and
   decides which keys apply; this file seals, opens, and masks them in place
   in Goose's buffer, and derives the keys from the secrets it holds.

   Keys, as Goose numbers them: 0 Initial, 2 Handshake, 3 1-RTT in its
   current phase, 4 1-RTT in the next phase, 5 1-RTT in the phase before
   (kept for packets that arrive late across a key update). A 1-RTT key
   update leaves header protection as it was (section 6). */

#define QK_INITIAL 0
#define QK_HANDSHAKE 2
#define QK_APP 3
#define QK_NEXT 4
#define QK_PREV 5
#define QK_COUNT 6

typedef struct {
    EVP_CIPHER_CTX *aead;
    uint8_t iv[12];
    uint8_t secret[48];
} qkey;

typedef struct {
    const suite_t *suite;
    qkey rd, wr;
    EVP_CIPHER_CTX *hp_rd, *hp_wr;
    uint8_t hp_rd_key[32], hp_wr_key[32];
} qlevel;

struct quic {
    qlevel level[QK_COUNT];
    /* The transport parameters: the server's, which EncryptedExtensions
       carries, and the client's from its ClientHello. */
    uint8_t *ours, *peer;
    size_t ours_len, peer_len;
};

static void qkey_clear(qkey *k) {
    EVP_CIPHER_CTX_free(k->aead);
    OPENSSL_cleanse(k, sizeof *k);
}

static void qlevel_clear(qlevel *l) {
    qkey_clear(&l->rd);
    qkey_clear(&l->wr);
    EVP_CIPHER_CTX_free(l->hp_rd);
    EVP_CIPHER_CTX_free(l->hp_wr);
    OPENSSL_cleanse(l, sizeof *l);
}

static void quic_free(gconn *c) {
    if (!c->q) return;
    for (int i = 0; i < QK_COUNT; i++) qlevel_clear(&c->q->level[i]);
    OPENSSL_free(c->q->ours);
    OPENSSL_free(c->q->peer);
    OPENSSL_clear_free(c->q, sizeof *c->q);
    c->q = NULL;
}

/* Makes the connection a QUIC one: 1, or 0 when the allocation fails. */
uint8_t tlsg_quic_begin(int64_t h) {
    gconn *c = CONN(h);
    if (!c) return 0;
    if (!c->q) c->q = OPENSSL_zalloc(sizeof *c->q);
    return c->q != NULL;
}

/* The packet key and IV of a direction from its secret ("quic key", "quic
   iv"), keyed into its AEAD context. */
static int qkey_set(EVP_MAC_CTX *m, const suite_t *s, qkey *k, const uint8_t *secret, int enc) {
    uint8_t key[32];
    memcpy(k->secret, secret, s->hash_len);
    int ok = expand_label(m, s, secret, s->hash_len, "quic key", 8, NULL, 0, key, s->key_len) &&
             expand_label(m, s, secret, s->hash_len, "quic iv", 7, NULL, 0, k->iv, 12);
    if (ok && !k->aead) ok = (k->aead = EVP_CIPHER_CTX_new()) != NULL;
    ok = ok && EVP_CipherInit_ex2(k->aead, s->cipher, key, NULL, enc, NULL) == 1;
    OPENSSL_cleanse(key, sizeof key);
    return ok;
}

/* The header protection key ("quic hp") from a secret. AES-ECB keys a
   context once; ChaCha20 takes its key with each sample's counter and
   nonce, so the key is kept. */
static int hp_set(EVP_MAC_CTX *m, const suite_t *s, EVP_CIPHER_CTX **ctx, uint8_t key[32],
                  const uint8_t *secret) {
    int ok = expand_label(m, s, secret, s->hash_len, "quic hp", 7, NULL, 0, key, s->key_len);
    if (ok && !*ctx) ok = (*ctx = EVP_CIPHER_CTX_new()) != NULL;
    if (ok && s->code != 0x1303)
        ok = EVP_EncryptInit_ex2(*ctx, s->hp, key, NULL, NULL) == 1 && EVP_CIPHER_CTX_set_padding(*ctx, 0) == 1;
    return ok;
}

/* One direction of a level from a secret: its packet keys, and its header
   protection unless keep_hp (a key update's next phase). */
static int qlevel_dir(EVP_MAC_CTX *m, const suite_t *s, qlevel *l, int write, const uint8_t *secret,
                      int keep_hp) {
    l->suite = s;
    return qkey_set(m, s, write ? &l->wr : &l->rd, secret, write) &&
           (keep_hp || hp_set(m, s, write ? &l->hp_wr : &l->hp_rd, write ? l->hp_wr_key : l->hp_rd_key, secret));
}

/* QUIC version 1's salt for the Initial secrets (section 5.2). */
static const uint8_t initial_salt[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

/* The Initial keys each way from the Destination Connection ID of the
   client's first Initial packet (section 5.2): the server reads under the
   client's and writes under its own. */
uint8_t tlsg_quic_initial(int64_t h, tls_bytes dcid) {
    gconn *c = CONN(h);
    if (!c || !c->q || !algs() || dcid.len < 0 || dcid.len > 20) return 0;
    const suite_t *s = suite_of(0x1301);
    EVP_MAC_CTX *m = mac_new(s);
    uint8_t initial[32], client[32], server[32];
    qlevel *l = &c->q->level[QK_INITIAL];
    int ok = hmac(m, s, initial_salt, sizeof initial_salt, dcid.data, (size_t)dcid.len, NULL, 0, initial, 32) &&
             expand_label(m, s, initial, 32, "client in", 9, NULL, 0, client, 32) &&
             expand_label(m, s, initial, 32, "server in", 9, NULL, 0, server, 32) &&
             qlevel_dir(m, s, l, 0, client, 0) && qlevel_dir(m, s, l, 1, server, 0);
    OPENSSL_cleanse(initial, sizeof initial);
    OPENSSL_cleanse(client, sizeof client);
    OPENSSL_cleanse(server, sizeof server);
    EVP_MAC_CTX_free(m);
    return (uint8_t)ok;
}

/* Gives a level's direction the traffic secret in the handshake's slot[s]
   (dir 0 reads, 1 writes): the Handshake keys from the handshake traffic
   secrets, and the 1-RTT keys from the application traffic secrets. */
uint8_t tlsg_quic_keys(int64_t h, int64_t level, int64_t d, int64_t s) {
    gconn *c = CONN(h);
    if (!c->q || (level != QK_HANDSHAKE && level != QK_APP) || !slot_ok(c, s) ||
        c->hs->slot_len[s] != c->suite->hash_len)
        return 0;
    return (uint8_t)qlevel_dir(hs_mac(c), c->suite, &c->q->level[level], d == DIR_WRITE, c->hs->slot[s], 0);
}

/* The next phase's 1-RTT keys each way from the current ones ("quic ku",
   section 6.1), unless they are there already. */
uint8_t tlsg_quic_next(int64_t h) {
    gconn *c = CONN(h);
    if (!c->q || !c->q->level[QK_APP].rd.aead) return 0;
    qlevel *cur = &c->q->level[QK_APP], *next = &c->q->level[QK_NEXT];
    if (next->rd.aead) return 1;
    const suite_t *s = cur->suite;
    EVP_MAC_CTX *m = mac_new(s);
    uint8_t rd[48], wr[48];
    int ok = expand_label(m, s, cur->rd.secret, s->hash_len, "quic ku", 7, NULL, 0, rd, s->hash_len) &&
             expand_label(m, s, cur->wr.secret, s->hash_len, "quic ku", 7, NULL, 0, wr, s->hash_len) &&
             qlevel_dir(m, s, next, 0, rd, 1) && qlevel_dir(m, s, next, 1, wr, 1);
    OPENSSL_cleanse(rd, sizeof rd);
    OPENSSL_cleanse(wr, sizeof wr);
    EVP_MAC_CTX_free(m);
    return (uint8_t)ok;
}

/* Moves 1-RTT to the next phase, which tlsg_quic_next made: the current
   keys become the previous phase's, for reading late packets only. */
uint8_t tlsg_quic_rotate(int64_t h) {
    gconn *c = CONN(h);
    if (!c->q || !c->q->level[QK_NEXT].rd.aead) return 0;
    qlevel *cur = &c->q->level[QK_APP], *next = &c->q->level[QK_NEXT], *prev = &c->q->level[QK_PREV];
    qkey_clear(&prev->rd);
    qkey_clear(&prev->wr);
    prev->suite = cur->suite;
    prev->rd = cur->rd;
    qkey_clear(&cur->wr);
    cur->rd = next->rd;
    cur->wr = next->wr;
    memset(&next->rd, 0, sizeof next->rd);
    memset(&next->wr, 0, sizeof next->wr);
    return 1;
}

/* Discards a level's keys, or a phase's. */
void tlsg_quic_drop(int64_t h, int64_t key) {
    gconn *c = CONN(h);
    if (c && c->q && key >= 0 && key < QK_COUNT) qlevel_clear(&c->q->level[key]);
}

/* Whether a level has keys to read with, or with write, to seal with. */
uint8_t tlsg_quic_has(int64_t h, int64_t key, uint8_t write) {
    gconn *c = CONN(h);
    if (!c || !c->q || key < 0 || key >= QK_COUNT) return 0;
    return (write ? c->q->level[key].wr.aead : c->q->level[key].rd.aead) != NULL;
}

/* The header protection mask for a 16-byte sample (section 5.4). */
static int hp_mask(const suite_t *s, EVP_CIPHER_CTX *ctx, const uint8_t key[32], const uint8_t *sample,
                   uint8_t mask[5]) {
    uint8_t out[16];
    int n = 0;
    int ok;
    if (s->code == 0x1303) {
        static const uint8_t zeros[5];
        ok = EVP_EncryptInit_ex2(ctx, s->hp, key, sample, NULL) == 1 &&
             EVP_EncryptUpdate(ctx, out, &n, zeros, 5) == 1;
    } else {
        ok = EVP_EncryptUpdate(ctx, out, &n, sample, 16) == 1;
    }
    memcpy(mask, out, 5);
    return ok;
}

static qlevel *level_of(gconn *c, int64_t key) {
    if (!c || !c->q || key < 0 || key >= QK_COUNT) return NULL;
    return &c->q->level[key];
}

/* The header-protection level for a packet key: a key update's phases share
   1-RTT's. */
static qlevel *hp_level_of(gconn *c, int64_t key) {
    return level_of(c, key == QK_NEXT || key == QK_PREV ? QK_APP : key);
}

static void quic_nonce(const qkey *k, uint64_t pn, uint8_t out[12]) {
    memcpy(out, k->iv, 12);
    for (int i = 0; i < 8; i++) out[11 - i] ^= (uint8_t)(pn >> (8 * i));
}

/* Seals a packet in place (sections 5.3 and 5.4): pkt holds its header,
   hdr_len bytes ending in the packet number's pn_len bytes, then the
   payload, then 16 bytes for the tag, which pkt.len counts. Encrypts the
   payload under the key's write keys with the header as associated data,
   then masks the first byte's low bits and the packet number. The payload
   and the packet number together must give the 20 bytes the sample needs
   (section 5.4.2), which Goose pads for. 0, or -1. */
int64_t tlsg_quic_seal(int64_t h, int64_t key, tls_buf pkt, int64_t hdr_len, int64_t pn_len, int64_t pn) {
    gconn *c = CONN(h);
    qlevel *l = level_of(c, key), *hl = hp_level_of(c, key);
    if (!l || !hl || !l->wr.aead || !hl->hp_wr || pn_len < 1 || pn_len > 4 || hdr_len < 1 + pn_len ||
        pkt.len < hdr_len + 16 || hdr_len - pn_len + 4 + 16 > pkt.len)
        return -1;
    size_t n = (size_t)(pkt.len - hdr_len - 16);
    uint8_t *p = pkt.data, iv[12];
    quic_nonce(&l->wr, (uint64_t)pn, iv);
    int a = 0, f = 0;
    int ok = EVP_CipherInit_ex2(l->wr.aead, NULL, NULL, iv, 1, NULL) == 1 &&
             EVP_EncryptUpdate(l->wr.aead, NULL, &a, p, (int)hdr_len) == 1 &&
             (n == 0 || EVP_EncryptUpdate(l->wr.aead, p + hdr_len, &a, p + hdr_len, (int)n) == 1) &&
             EVP_EncryptFinal_ex(l->wr.aead, p + hdr_len + n, &f) == 1 &&
             EVP_CIPHER_CTX_ctrl(l->wr.aead, EVP_CTRL_AEAD_GET_TAG, 16, p + hdr_len + n) == 1;
    uint8_t mask[5];
    ok = ok && hp_mask(hl->suite, hl->hp_wr, hl->hp_wr_key, p + hdr_len - pn_len + 4, mask);
    if (!ok) return -1;
    p[0] ^= mask[0] & ((p[0] & 0x80) ? 0x0f : 0x1f);
    for (int64_t i = 0; i < pn_len; i++) p[hdr_len - pn_len + i] ^= mask[1 + i];
    return 0;
}

/* Removes header protection in place from a received packet, all of pkt,
   whose packet number starts at pn_at (section 5.4.2): the first byte as
   it was sent, from which Goose reads the packet number's length and the
   key phase, or -1 when the packet is too short to sample or the level has
   no keys. */
int64_t tlsg_quic_unprotect(int64_t h, int64_t key, tls_buf pkt, int64_t pn_at) {
    gconn *c = CONN(h);
    qlevel *hl = hp_level_of(c, key);
    if (!hl || !hl->hp_rd || pn_at < 1 || pn_at + 4 + 16 > pkt.len) return -1;
    uint8_t *p = pkt.data, mask[5];
    if (!hp_mask(hl->suite, hl->hp_rd, hl->hp_rd_key, p + pn_at + 4, mask)) return -1;
    p[0] ^= mask[0] & ((p[0] & 0x80) ? 0x0f : 0x1f);
    int pn_len = (p[0] & 3) + 1;
    for (int i = 0; i < pn_len; i++) p[pn_at + i] ^= mask[1 + i];
    return p[0];
}

/* Opens a packet in place whose header protection is off: hdr_len bytes of
   header, then the payload and its tag, to pkt's end, under the key's read
   keys and the full packet number pn. The plaintext's length, or -1 when it
   fails to authenticate, and then the payload is wiped. */
int64_t tlsg_quic_open(int64_t h, int64_t key, tls_buf pkt, int64_t hdr_len, int64_t pn) {
    gconn *c = CONN(h);
    qlevel *l = level_of(c, key);
    if (!l || !l->rd.aead || hdr_len < 1 || pkt.len < hdr_len + 16) return -1;
    size_t n = (size_t)(pkt.len - hdr_len - 16);
    uint8_t *p = pkt.data, iv[12];
    quic_nonce(&l->rd, (uint64_t)pn, iv);
    int a = 0, f = 0;
    int ok = EVP_CipherInit_ex2(l->rd.aead, NULL, NULL, iv, 0, NULL) == 1 &&
             EVP_DecryptUpdate(l->rd.aead, NULL, &a, p, (int)hdr_len) == 1 &&
             (n == 0 || EVP_DecryptUpdate(l->rd.aead, p + hdr_len, &a, p + hdr_len, (int)n) == 1) &&
             EVP_CIPHER_CTX_ctrl(l->rd.aead, EVP_CTRL_AEAD_SET_TAG, 16, p + hdr_len + n) == 1 &&
             EVP_DecryptFinal_ex(l->rd.aead, p + hdr_len + n, &f) == 1;
    if (!ok) {
        OPENSSL_cleanse(p + hdr_len, n);
        return -1;
    }
    return (int64_t)n;
}

/* Sets the server's transport parameters (which 0) or keeps the client's
   (which 1), as their encoded bytes. */
uint8_t tlsg_quic_params_set(int64_t h, int64_t which, tls_bytes params) {
    gconn *c = CONN(h);
    if (!c || !c->q || params.len < 0) return 0;
    uint8_t **p = which ? &c->q->peer : &c->q->ours;
    size_t *n = which ? &c->q->peer_len : &c->q->ours_len;
    OPENSSL_free(*p);
    *p = NULL;
    *n = 0;
    if (!params.len) return 1;
    if (!(*p = OPENSSL_memdup(params.data, (size_t)params.len))) return 0;
    *n = (size_t)params.len;
    return 1;
}

void tlsg_quic_params(int64_t h, int64_t which, gs_rref out) {
    gconn *c = CONN(h);
    if (!c || !c->q) return;
    if (which ? c->q->peer_len : c->q->ours_len)
        gs_bld_append(out, which ? c->q->peer : c->q->ours, (int64_t)(which ? c->q->peer_len : c->q->ours_len));
}

/* Appends a handshake message the server sends at level: framed for
   tlsg_quic_take as the level's byte and a 3-byte length. */
uint8_t tlsg_quic_out(int64_t h, int64_t level, tls_bytes data) {
    gconn *c = CONN(h);
    if (data.len < 0 || data.len > 0xffffff) return 0;
    uint8_t head[4] = { (uint8_t)level, (uint8_t)(data.len >> 16), (uint8_t)(data.len >> 8), (uint8_t)data.len };
    return q_put(&c->out, head, 4) && q_put(&c->out, data.data, (size_t)data.len);
}

/* Moves the first message tlsg_quic_out queued onto out: its level, or -1
   when none is queued. */
int64_t tlsg_quic_take(int64_t h, gs_rref out) {
    gconn *c = CONN(h);
    if (!c || c->out.len < 4) return -1;
    const uint8_t *p = c->out.p + c->out.off;
    size_t n = (size_t)p[1] << 16 | (size_t)p[2] << 8 | p[3];
    if (c->out.len < 4 + n) return -1;
    int64_t level = p[0];
    gs_bld_append(out, p + 4, (int64_t)n);
    q_drop(&c->out, 4 + n);
    return level;
}

/* ---- Session tickets ---- */

/* Seconds on a clock that a change of the wall clock can't move, which the
   ticket keys' lifetimes and the tickets' issue times count on: tickets are
   this process's alone, as their keys are. clock_offset moves it for the
   tests (tlsg_ticket_clock). */
static int64_t clock_offset;

int64_t tlsg_ticket_now(void) {
#ifdef _WIN32
    return (int64_t)(GetTickCount64() / 1000) + clock_offset;
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec + clock_offset;
#endif
}

/* For the tests (test/server/tickets.goose, and the echo server's "clock"
   line): moves the ticket clock forward by seconds, never back, so that it
   can only expire keys and tickets sooner. */
void tlsg_ticket_clock(int64_t seconds) {
    if (seconds > 0) clock_offset += seconds;
}

/* Wipes the keys past opening tickets. */
static void keys_expire(ticket_key ring[2], int64_t now) {
    for (int i = 0; i < 2; i++)
        if (ring[i].live && now >= ring[i].created + 2 * TICKET_PERIOD) OPENSSL_cleanse(&ring[i], sizeof ring[i]);
}

/* A spent ring[0] moves to ring[1] while it may still open tickets, and a
   new key takes its place, unless its random bytes fail; then none goes on
   past its time. */
int ticket_key_issue(ticket_key ring[2], int64_t now, uint8_t id[4], uint8_t key[64]) {
    keys_expire(ring, now);
    ticket_key *cur = &ring[0];
    if (!cur->live || now >= cur->created + TICKET_PERIOD || cur->uses >= TICKET_MAX_USES) {
        ticket_key next;
        memset(&next, 0, sizeof next);
        int ok = RAND_bytes(next.id, sizeof next.id) == 1 && RAND_bytes(next.key, sizeof next.key) == 1;
        if (cur->live) {
            OPENSSL_cleanse(&ring[1], sizeof ring[1]);
            ring[1] = *cur;
            OPENSSL_cleanse(cur, sizeof *cur);
        }
        if (ok) {
            if (ring[1].live && memcmp(next.id, ring[1].id, sizeof next.id) == 0) next.id[0] ^= 1;
            next.live = 1;
            next.created = now;
            *cur = next;
        }
        OPENSSL_cleanse(&next, sizeof next);
        if (!ok) return 0;
    }
    memcpy(id, cur->id, sizeof cur->id);
    memcpy(key, cur->key, sizeof cur->key);
    cur->uses++;
    return 1;
}

int ticket_key_open(ticket_key ring[2], int64_t now, const uint8_t id[4], uint8_t key[64]) {
    keys_expire(ring, now);
    for (int i = 0; i < 2; i++) {
        if (ring[i].live && memcmp(ring[i].id, id, sizeof ring[i].id) == 0) {
            memcpy(key, ring[i].key, sizeof ring[i].key);
            return 1;
        }
    }
    return 0;
}

/* AES-256-GCM over a ticket's plaintext: seal into out, which holds
   in_len + 16, or open in_len bytes and their tag into out. */
static int ticket_aead(const uint8_t key[32], const uint8_t *head, const uint8_t *in, size_t in_len,
                       uint8_t *out, int enc) {
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int a = 0, f = 0;
    int ok = x && EVP_CipherInit_ex2(x, alg.suites[1].cipher, key, head + 5, enc, NULL) == 1 &&
             EVP_CipherUpdate(x, NULL, &a, head, TICKET_HEAD) == 1;
    if (ok && enc)
        ok = EVP_CipherUpdate(x, out, &a, in, (int)in_len) == 1 && EVP_CipherFinal_ex(x, out + a, &f) == 1 &&
             EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_GET_TAG, 16, out + in_len) == 1;
    else if (ok)
        ok = EVP_CipherUpdate(x, out, &a, in, (int)in_len) == 1 &&
             EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_SET_TAG, 16, (void *)(in + in_len)) == 1 &&
             EVP_CipherFinal_ex(x, out + a, &f) == 1;
    EVP_CIPHER_CTX_free(x);
    return ok;
}

/* A session ticket for the connection, appended to out: version, the
   issuing key's id, a fresh nonce, and sealed under that key with them as
   additional data, the suite, the PSK that
   HKDF-Expand-Label(slot[res], "resumption", nonce, Hash.length) gives
   (section 4.6.1), the issue time, age_add, and the SNI name. 0 when no key
   can issue one. */
uint8_t tlsg_ticket_issue(int64_t h, int64_t res, tls_bytes nonce, int64_t age_add, gs_rref out) {
    gconn *c = CONN(h);
    if (!slot_ok(c, res) || c->hs->slot_len[res] != c->suite->hash_len || nonce.len < 0 || nonce.len > 255)
        return 0;
    const suite_t *s = c->suite;
    size_t hl = s->hash_len, n = 0;
    int64_t now = tlsg_ticket_now();
    uint8_t pt[2 + 1 + 48 + 8 + 4 + 1 + 255], sealed[sizeof pt + 16], head[TICKET_HEAD], key[64];
    pt[n++] = (uint8_t)(s->code >> 8), pt[n++] = (uint8_t)s->code, pt[n++] = (uint8_t)hl;
    int ok =
        expand_label(hs_mac(c), s, c->hs->slot[res], hl, "resumption", 10, nonce.data, (size_t)nonce.len, pt + n, hl);
    n += hl;
    for (int i = 7; i >= 0; i--) pt[n++] = (uint8_t)(now >> (8 * i));
    for (int i = 3; i >= 0; i--) pt[n++] = (uint8_t)(age_add >> (8 * i));
    pt[n++] = c->sni_len;
    if (c->sni_len) memcpy(pt + n, c->sni, c->sni_len);
    n += c->sni_len;
    head[0] = TICKET_VERSION;
    ok = ok && RAND_bytes(head + 5, 12) == 1 && CRYPTO_THREAD_write_lock(c->ctx->lock);
    if (ok) {
        ok = ticket_key_issue(c->ctx->keys, now, head + 1, key);
        CRYPTO_THREAD_unlock(c->ctx->lock);
    }
    ok = ok && ticket_aead(key, head, pt, n, sealed, 1);
    if (ok) {
        gs_bld_append(out, head, TICKET_HEAD);
        gs_bld_append(out, sealed, (int64_t)(n + 16));
    }
    OPENSSL_cleanse(pt, sizeof pt);
    OPENSSL_cleanse(key, sizeof key);
    return (uint8_t)ok;
}

#pragma pack(push, 1)
/* What a ticket that opens holds besides its PSK; suite 0 when it doesn't
   open. Goose's tls::TicketFacts. */
typedef struct { int64_t suite, issued, age_add; } ticket_facts;
#pragma pack(pop)

/* Opens a ticket under the context's keys: its facts, its PSK into
   slot[psk], and its SNI name appended to sni. A ticket under a key that
   expired, or that isn't one of the context's, doesn't open. */
ticket_facts tlsg_ticket_open(int64_t h, tls_bytes ticket, int64_t psk, gs_rref sni) {
    gconn *c = CONN(h);
    ticket_facts facts = { 0, 0, 0 };
    uint8_t pt[2 + 1 + 48 + 8 + 4 + 1 + 255], key[64];
    if (!slot_ok(c, psk) || ticket.len < TICKET_HEAD + 16 + 2 + 1 + 32 + 8 + 4 + 1 ||
        ticket.len > TICKET_HEAD + 16 + (int64_t)sizeof pt || ticket.data[0] != TICKET_VERSION)
        return facts;
    if (!CRYPTO_THREAD_write_lock(c->ctx->lock)) return facts;
    int found = ticket_key_open(c->ctx->keys, tlsg_ticket_now(), ticket.data + 1, key);
    CRYPTO_THREAD_unlock(c->ctx->lock);
    size_t n = (size_t)ticket.len - TICKET_HEAD - 16;
    if (found && ticket_aead(key, ticket.data, ticket.data + TICKET_HEAD, n, pt, 0)) {
        size_t hl = pt[2];
        const suite_t *s = suite_of((int64_t)pt[0] << 8 | pt[1]);
        if (s && hl == s->hash_len && n >= 3 + hl + 8 + 4 + 1 && n == 3 + hl + 8 + 4 + 1 + pt[3 + hl + 12]) {
            memcpy(c->hs->slot[psk], pt + 3, hl);
            c->hs->slot_len[psk] = (uint8_t)hl;
            facts.suite = s->code;
            for (int i = 0; i < 8; i++) facts.issued = facts.issued << 8 | pt[3 + hl + i];
            for (int i = 0; i < 4; i++) facts.age_add = facts.age_add << 8 | pt[3 + hl + 8 + i];
            gs_bld_append(sni, pt + 3 + hl + 13, pt[3 + hl + 12]);
        }
    }
    OPENSSL_cleanse(pt, sizeof pt);
    OPENSSL_cleanse(key, sizeof key);
    return facts;
}

/* ---- Failures ---- */

/* Raises a failure on this thread's OpenSSL error queue, for
   tls::error_text: one of libssl's reasons, so that its text is OpenSSL's,
   and what the server adds. */
void tlsg_fail(int64_t reason, tls_bytes text) {
    if (reason < 0) reason = ERR_R_INTERNAL_ERROR;
    if (text.len > 0)
        ERR_raise_data(ERR_LIB_SSL, (int)reason, "%.*s", (int)(text.len > 200 ? 200 : text.len),
                       (const char *)text.data);
    else
        ERR_raise(ERR_LIB_SSL, (int)reason);
}

/* ERR_clear_error sweeps every slot of the queue; reading it first skips
   that on the calls that find it empty, nearly all of them. */
void tlsg_clear_errors(void) {
    if (ERR_peek_error()) ERR_clear_error();
}

/* Which server new contexts are: 1 for libssl's, chosen when the package's
   C is configured (CMakeLists.txt, GOOSE_TLS_SERVER), else 0 for Goose's. */
int64_t tlsg_backend(void) {
#ifdef GOOSE_TLS_SERVER_OPENSSL
    return 1;
#else
    return 0;
#endif
}
