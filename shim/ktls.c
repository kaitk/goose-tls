/* kTLS on Linux: after the handshake, a connection's record layer moves into
   the kernel, and the program's loop sends and receives plaintext on its
   socket (docs/architecture.md, "kTLS on Linux").

   The shim installs the traffic keys with setsockopt on the descriptor the
   program gives it and never reads or writes the socket. OpenSSL starts kTLS
   only over a socket BIO, so the shim derives what the kernel needs itself,
   from OpenSSL's public API at 3.0:

   - The application traffic secrets, from the keylog callback
     (SSL_CTX_set_keylog_callback), which OpenSSL calls as it derives them.
   - The record sequence numbers, by counting the record headers the message
     callback (SSL_set_msg_callback, SSL3_RT_HEADER) reports in each
     direction since its keys changed: on the server's side, its write keys
     change as the keylog callback gets SERVER_TRAFFIC_SECRET_0, its read keys
     after the client's Finished, and either after a KeyUpdate.
   - The key and IV, by RFC 8446's HKDF-Expand-Label through EVP_KDF's HKDF,
     and the next secret after a KeyUpdate the same way ("traffic upd").

   The kernel's structures are defined here, with the values of
   include/uapi/linux/tls.h, so that the derivation builds and is tested on
   every platform; on Linux they are checked against the system's header. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/ssl.h>

#ifdef __linux__
#include <linux/tls.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "goose.h"
#include "tls.h"

#define K_SOL_TLS 282
#define K_TCP_ULP 31
#define K_TLS_TX 1
#define K_TLS_RX 2
#define K_TLS_1_3_VERSION 0x0304
#define K_AES_GCM_128 51
#define K_AES_GCM_256 52
#define K_CHACHA20_POLY1305 54

typedef struct { uint16_t version, cipher_type; } k_info;
typedef struct { k_info info; uint8_t iv[8], key[16], salt[4], rec_seq[8]; } k_aes_gcm_128;
typedef struct { k_info info; uint8_t iv[8], key[32], salt[4], rec_seq[8]; } k_aes_gcm_256;
typedef struct { k_info info; uint8_t iv[12], key[32], rec_seq[8]; } k_chacha20_poly1305;

#ifdef __linux__
_Static_assert(SOL_TLS == K_SOL_TLS && TCP_ULP == K_TCP_ULP && TLS_TX == K_TLS_TX &&
               TLS_RX == K_TLS_RX && TLS_1_3_VERSION == K_TLS_1_3_VERSION,
               "the kernel's kTLS constants");
_Static_assert(TLS_CIPHER_AES_GCM_128 == K_AES_GCM_128 && TLS_CIPHER_AES_GCM_256 == K_AES_GCM_256 &&
               TLS_CIPHER_CHACHA20_POLY1305 == K_CHACHA20_POLY1305, "the kernel's cipher numbers");
_Static_assert(sizeof(k_aes_gcm_128) == sizeof(struct tls12_crypto_info_aes_gcm_128) &&
               sizeof(k_aes_gcm_256) == sizeof(struct tls12_crypto_info_aes_gcm_256) &&
               sizeof(k_chacha20_poly1305) == sizeof(struct tls12_crypto_info_chacha20_poly1305),
               "the kernel's crypto_info layouts");
#define KTLS_LINUX 1
#else
#define KTLS_LINUX 0
#endif

/* Stand-ins for a descriptor, for the tests: the shim acts as if the kernel
   took both directions, or only receiving, and sets no socket option. */
#define KTLS_TEST_BOTH -1
#define KTLS_TEST_RX_ONLY -2

typedef struct {
    uint16_t id;          /* the suite's TLS code point */
    const char *digest;   /* its HKDF hash */
    size_t hash_len, key_len;
    uint16_t kernel;      /* the kernel's cipher_type */
} suite;

static const suite suites[] = {
    { 0x1301, "SHA256", 32, 16, K_AES_GCM_128 },
    { 0x1302, "SHA384", 48, 32, K_AES_GCM_256 },
    { 0x1303, "SHA256", 32, 32, K_CHACHA20_POLY1305 },
};

static const suite *suite_of(uint16_t id) {
    for (size_t i = 0; i < sizeof suites / sizeof suites[0]; i++)
        if (suites[i].id == id) return &suites[i];
    return NULL;
}

/* Index 0 is receiving (the client's secrets), 1 sending (the server's). */
typedef struct {
    uint8_t secret[2][48];
    size_t secret_len;
    uint64_t seq[2];
    uint8_t have;      /* KTLS_RX, KTLS_TX: the secret is captured */
    uint8_t counting;  /* KTLS_RX, KTLS_TX: seq counts records under it */
    uint8_t owned;     /* KTLS_RX, KTLS_TX: the kernel holds it */
    uint8_t declined;  /* the kernel refused, so the connection stays */
    /* The framing of the bytes fed: a partial header, or a body's rest. */
    uint8_t hdr[5];
    uint8_t hdr_len;
    uint32_t body_left;
} ktls_state;

static int dir_index(int dir) { return dir == KTLS_RX ? 0 : 1; }

static int state_index = -1;
static EVP_KDF *hkdf;
static CRYPTO_ONCE state_once = CRYPTO_ONCE_STATIC_INIT;

static void state_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) {
    (void)parent, (void)ad, (void)idx, (void)argl, (void)argp;
    OPENSSL_clear_free(ptr, sizeof(ktls_state));
}

static void state_init(void) {
    state_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, state_free);
    hkdf = EVP_KDF_fetch(NULL, OSSL_KDF_NAME_HKDF, NULL);
}

static int ready(void) {
    return CRYPTO_THREAD_run_once(&state_once, state_init) && state_index >= 0 && hkdf;
}

static ktls_state *state_of(const SSL *ssl) {
    return ssl && state_index >= 0 ? SSL_get_ex_data(ssl, state_index) : NULL;
}

/* RFC 8446, section 7.1: HKDF-Expand-Label(secret, label, "", out_len). */
static int expand_label(const char *digest, const uint8_t *secret, size_t secret_len,
                        const char *label, uint8_t *out, size_t out_len) {
    uint8_t info[2 + 1 + 6 + 32 + 1];
    size_t label_len = strlen(label);
    if (label_len > 32 || out_len > 255) return 0;
    info[0] = 0;
    info[1] = (uint8_t)out_len;
    info[2] = (uint8_t)(6 + label_len);
    memcpy(info + 3, "tls13 ", 6);
    memcpy(info + 9, label, label_len);
    info[9 + label_len] = 0;
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(hkdf);
    if (!kctx) return 0;
    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)digest, 0),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)secret, secret_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, 10 + label_len),
        OSSL_PARAM_construct_end(),
    };
    int ok = EVP_KDF_derive(kctx, out, out_len, params) == 1;
    EVP_KDF_CTX_free(kctx);
    return ok;
}

/* The kernel's crypto_info for a suite, a traffic secret, and the sequence
   number of the next record: its length in out, or 0. */
static size_t crypto_info(const suite *s, const uint8_t *secret, uint64_t seq, uint8_t out[64]) {
    uint8_t key[32], iv[12], rec_seq[8];
    size_t n = 0;
    if (!expand_label(s->digest, secret, s->hash_len, "key", key, s->key_len) ||
        !expand_label(s->digest, secret, s->hash_len, "iv", iv, sizeof iv))
        goto done;
    for (int i = 0; i < 8; i++) rec_seq[i] = (uint8_t)(seq >> (56 - 8 * i));
    k_info info = { K_TLS_1_3_VERSION, s->kernel };
    /* For AES-GCM the kernel takes TLS 1.3's 12-byte IV as a 4-byte salt
       and an 8-byte rest. */
    if (s->kernel == K_CHACHA20_POLY1305) {
        k_chacha20_poly1305 c = { info, {0}, {0}, {0} };
        memcpy(c.iv, iv, 12);
        memcpy(c.key, key, 32);
        memcpy(c.rec_seq, rec_seq, 8);
        memcpy(out, &c, n = sizeof c);
        OPENSSL_cleanse(&c, sizeof c);
    } else if (s->kernel == K_AES_GCM_256) {
        k_aes_gcm_256 c = { info, {0}, {0}, {0}, {0} };
        memcpy(c.salt, iv, 4);
        memcpy(c.iv, iv + 4, 8);
        memcpy(c.key, key, 32);
        memcpy(c.rec_seq, rec_seq, 8);
        memcpy(out, &c, n = sizeof c);
        OPENSSL_cleanse(&c, sizeof c);
    } else {
        k_aes_gcm_128 c = { info, {0}, {0}, {0}, {0} };
        memcpy(c.salt, iv, 4);
        memcpy(c.iv, iv + 4, 8);
        memcpy(c.key, key, 16);
        memcpy(c.rec_seq, rec_seq, 8);
        memcpy(out, &c, n = sizeof c);
        OPENSSL_cleanse(&c, sizeof c);
    }
done:
    OPENSSL_cleanse(key, sizeof key);
    OPENSSL_cleanse(iv, sizeof iv);
    return n;
}

static void sys_reason(int err, const char *what) {
    ERR_raise_data(ERR_LIB_SYS, err, "%s", what);
}

static void tls_reason(int reason, const char *what) {
    ERR_raise_data(ERR_LIB_SSL, reason, "%s", what);
}

static const suite *suite_of_conn(SSL *ssl) {
    const SSL_CIPHER *c = SSL_get_current_cipher(ssl);
    return c ? suite_of(SSL_CIPHER_get_protocol_id(c)) : NULL;
}

/* Gives the kernel a direction's keys as they stand: 1, or 0 with the
   reason queued. */
static int install(SSL *ssl, ktls_state *k, int64_t fd, int dir) {
    const suite *s = suite_of_conn(ssl);
    int d = dir_index(dir);
    uint8_t info[64];
    size_t n = s ? crypto_info(s, k->secret[d], k->seq[d], info) : 0;
    if (n == 0) {
        tls_reason(SSL_R_UNKNOWN_CIPHER_TYPE, "no kTLS keys for this suite");
        return 0;
    }
    int ok = 1, err = 0;
    if (fd == KTLS_TEST_RX_ONLY && dir == KTLS_TX) {
        ok = 0;
        err = EINVAL;
    } else if (fd >= 0) {
#ifdef __linux__
        ok = setsockopt((int)fd, SOL_TLS, dir == KTLS_RX ? TLS_RX : TLS_TX, info, (socklen_t)n) == 0;
        err = errno;
#else
        ok = 0;
        err = ENOTSUP;
#endif
    }
    OPENSSL_cleanse(info, sizeof info);
    if (!ok) sys_reason(err, dir == KTLS_RX ? "setsockopt(SOL_TLS, TLS_RX)" : "setsockopt(SOL_TLS, TLS_TX)");
    return ok;
}

/* The secret after a KeyUpdate, which also restarts the sequence numbers. */
static int next_secret(SSL *ssl, ktls_state *k, int dir) {
    const suite *s = suite_of_conn(ssl);
    int d = dir_index(dir);
    uint8_t next[48];
    if (!s || s->hash_len != k->secret_len ||
        !expand_label(s->digest, k->secret[d], k->secret_len, "traffic upd", next, k->secret_len))
        return 0;
    memcpy(k->secret[d], next, k->secret_len);
    OPENSSL_cleanse(next, sizeof next);
    k->seq[d] = 0;
    return 1;
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* A keylog line is "LABEL <client random> <secret>", in hex. The server's
   write keys change to its application secret as OpenSSL logs it. */
static void keylog(const SSL *ssl, const char *line) {
    ktls_state *k = state_of(ssl);
    if (!k) return;
    int d;
    if (strncmp(line, "CLIENT_TRAFFIC_SECRET_0 ", 24) == 0) d = 0;
    else if (strncmp(line, "SERVER_TRAFFIC_SECRET_0 ", 24) == 0) d = 1;
    else return;
    const char *hex = strrchr(line, ' ') + 1;
    size_t len = strlen(hex);
    while (len > 0 && (hex[len - 1] == '\n' || hex[len - 1] == '\r')) len--;
    if (len % 2 || len / 2 > sizeof k->secret[d]) return;
    for (size_t i = 0; i < len / 2; i++) {
        int hi = hex_digit(hex[2 * i]), lo = hex_digit(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return;
        k->secret[d][i] = (uint8_t)(hi << 4 | lo);
    }
    k->secret_len = len / 2;
    k->have |= d ? KTLS_TX : KTLS_RX;
    if (d == 1) {
        k->counting |= KTLS_TX;
        k->seq[1] = 0;
    }
}

/* Counts each direction's records, and follows its key changes. OpenSSL
   reports a record's header as it reads or writes the record, then the
   handshake messages in it, so a reset on a message counts the records after
   the one that carried it. */
static void message(int write_p, int version, int content_type, const void *buf, size_t len,
                    SSL *ssl, void *arg) {
    (void)version, (void)arg;
    ktls_state *k = state_of(ssl);
    if (!k) return;
    int dir = write_p ? KTLS_TX : KTLS_RX, d = dir_index(dir);
    if (content_type == SSL3_RT_HEADER) {
        if (k->counting & dir) k->seq[d]++;
        return;
    }
    if (content_type != SSL3_RT_HANDSHAKE || len < 1) return;
    uint8_t type = ((const uint8_t *)buf)[0];
    if (type == SSL3_MT_FINISHED && !write_p) {
        k->counting |= KTLS_RX;
        k->seq[0] = 0;
    } else if (type == SSL3_MT_KEY_UPDATE && (k->have & dir)) {
        if (!next_secret(ssl, k, dir)) k->have &= (uint8_t)~dir;
    }
}

int ktls_attach(SSL *ssl) {
    if (SSL_CTX_get_keylog_callback(SSL_get_SSL_CTX(ssl)) != keylog) return 1;
    if (!ready()) return 0;
    ktls_state *k = OPENSSL_zalloc(sizeof *k);
    if (!k) return 0;
    if (!SSL_set_ex_data(ssl, state_index, k)) {
        OPENSSL_free(k);
        return 0;
    }
    SSL_set_msg_callback(ssl, message);
    return 1;
}

void ktls_frame(SSL *ssl, const uint8_t *data, int64_t len) {
    ktls_state *k = state_of(ssl);
    if (!k) return;
    while (len > 0) {
        if (k->body_left > 0) {
            uint32_t n = len < k->body_left ? (uint32_t)len : k->body_left;
            k->body_left -= n;
            data += n;
            len -= n;
            continue;
        }
        k->hdr[k->hdr_len++] = *data++;
        len--;
        if (k->hdr_len == 5) {
            k->body_left = (uint32_t)k->hdr[3] << 8 | k->hdr[4];
            k->hdr_len = 0;
        }
    }
}

int ktls_owns(SSL *ssl, int dir) {
    ktls_state *k = state_of(ssl);
    return k && (k->owned & dir);
}

/* Whether this kernel has kTLS: the tls ULP, built in or as a module, which
   a TCP socket that isn't connected refuses with ENOTCONN once it is found
   (loading the module), and with ENOENT when there is none. */
uint8_t tls_kernel_supported(void) {
#ifdef __linux__
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
    int r = setsockopt(s, IPPROTO_TCP, TCP_ULP, "tls", sizeof "tls");
    int err = errno;
    close(s);
    return r == 0 || err == ENOTCONN;
#else
    return 0;
#endif
}

/* Makes the context's connections ready for the kernel: 1, or 0 when this
   kernel has no kTLS and anywhere isn't set. The tests set it, to check the
   keys on any platform. Call it before the context accepts a connection:
   OpenSSL's callbacks on a context aren't set safely while others use it. */
uint8_t tls_kernel_enable(int64_t h, uint8_t anywhere) {
    ERR_clear_error();
    SSL_CTX *ctx = (SSL_CTX *)(intptr_t)h;
    if (!ctx || !ready()) return 0;
    if (!anywhere && !tls_kernel_supported()) return 0;
    SSL_CTX_set_keylog_callback(ctx, keylog);
    return 1;
}

/* Moves the connection to the kernel on socket fd: which directions the
   kernel took (KTLS_RX, then KTLS_TX only with it), or TLS_WANT_INPUT while
   the bytes fed end inside a record, TLS_PENDING while plaintext waits for
   tls_read or bytes for tls_drain, or TLS_FAILED before the handshake is
   done. Once it has given an answer of 0 or more, it gives the same again. */
int64_t tls_kernel_start(int64_t h, int64_t fd) {
    ERR_clear_error();
    SSL *ssl = (SSL *)(intptr_t)h;
    if (!ssl) return TLS_FAILED;
    ktls_state *k = state_of(ssl);
    if (!k) {
        tls_reason(SSL_R_UNINITIALIZED, "kTLS is not enabled on the connection's context");
        return 0;
    }
    if (k->owned || k->declined) return k->owned;
    if (!SSL_is_init_finished(ssl)) {
        tls_reason(SSL_R_UNEXPECTED_MESSAGE, "the handshake is not done");
        return TLS_FAILED;
    }
    if (k->hdr_len > 0 || k->body_left > 0) return TLS_WANT_INPUT;
    if (SSL_has_pending(ssl) || BIO_ctrl_pending(SSL_get_rbio(ssl)) > 0 ||
        BIO_ctrl_pending(SSL_get_wbio(ssl)) > 0)
        return TLS_PENDING;
    k->declined = 1;
    if (fd >= 0 && !KTLS_LINUX) {
        sys_reason(ENOTSUP, "kTLS is Linux's");
        return 0;
    }
    const suite *s = suite_of_conn(ssl);
    if (!s || (k->have & (KTLS_RX | KTLS_TX)) != (KTLS_RX | KTLS_TX) || !(k->counting & KTLS_RX) ||
        k->secret_len != s->hash_len) {
        tls_reason(SSL_R_UNKNOWN_CIPHER_TYPE, "no kTLS keys for this connection");
        return 0;
    }
#ifdef __linux__
    if (fd >= 0 && setsockopt((int)fd, IPPROTO_TCP, TCP_ULP, "tls", sizeof "tls") != 0 && errno != EEXIST) {
        sys_reason(errno, "setsockopt(TCP_ULP, tls)");
        return 0;
    }
#endif
    /* Receiving first: with the kernel receiving, OpenSSL can still send,
       and answer a KeyUpdate with SSL_key_update; the other way round, a
       KeyUpdate OpenSSL read would have it send with keys it no longer
       holds. */
    if (!install(ssl, k, fd, KTLS_RX)) return 0;
    k->declined = 0;
    k->owned = KTLS_RX;
    if (install(ssl, k, fd, KTLS_TX)) k->owned |= KTLS_TX;
    return k->owned;
}

/* How many more bytes complete the record the bytes fed end in: what the
   program reads, and no more, before tls_kernel_start can switch. */
int64_t tls_kernel_wants(int64_t h) {
    ktls_state *k = state_of((SSL *)(intptr_t)h);
    if (!k) return 0;
    return k->hdr_len > 0 ? 5 - k->hdr_len : k->body_left;
}

int64_t tls_kernel_owned(int64_t h) {
    ktls_state *k = state_of((SSL *)(intptr_t)h);
    return k ? k->owned : 0;
}

/* A record the kernel received that isn't data: its type, from recvmsg's
   TLS_GET_RECORD_TYPE, and its plaintext. 0 when the connection goes on,
   TLS_UPDATE_TX when the peer asked for a KeyUpdate that the program sends
   (then tls_kernel_update_tx), TLS_CLOSED for close_notify, or TLS_FAILED. */
int64_t tls_kernel_record(int64_t h, int64_t fd, int64_t type, tls_bytes body) {
    ERR_clear_error();
    SSL *ssl = (SSL *)(intptr_t)h;
    ktls_state *k = state_of(ssl);
    if (!k || !(k->owned & KTLS_RX) || body.len < 0) return TLS_FAILED;
    const uint8_t *p = body.data;
    if (type == SSL3_RT_ALERT) {
        if (body.len == 2 && p[1] == SSL_AD_CLOSE_NOTIFY) return TLS_CLOSED;
        char what[64];
        snprintf(what, sizeof what, "the peer sent alert %d", body.len == 2 ? p[1] : -1);
        tls_reason(SSL_R_UNEXPECTED_MESSAGE, what);
        return TLS_FAILED;
    }
    /* A KeyUpdate ends its record (RFC 8446, section 5.1), and is the only
       handshake message a client sends after the handshake. */
    if (type != SSL3_RT_HANDSHAKE || body.len != 5 || p[0] != SSL3_MT_KEY_UPDATE || p[1] != 0 ||
        p[2] != 0 || p[3] != 1 || p[4] > 1) {
        tls_reason(SSL_R_UNEXPECTED_MESSAGE, "a record after the handshake that isn't data or a KeyUpdate");
        return TLS_FAILED;
    }
    if (!next_secret(ssl, k, KTLS_RX) || !install(ssl, k, fd, KTLS_RX)) return TLS_FAILED;
    if (p[4] == 0) return 0;
    if (k->owned & KTLS_TX) return TLS_UPDATE_TX;
    if (SSL_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED) != 1 || SSL_do_handshake(ssl) != 1)
        return TLS_FAILED;
    return 0;
}

/* Moves the kernel's sending to the next keys, after the program sent a
   KeyUpdate through it: 0, or TLS_FAILED. */
int64_t tls_kernel_update_tx(int64_t h, int64_t fd) {
    ERR_clear_error();
    SSL *ssl = (SSL *)(intptr_t)h;
    ktls_state *k = state_of(ssl);
    if (!k || !(k->owned & KTLS_TX)) return TLS_FAILED;
    return next_secret(ssl, k, KTLS_TX) && install(ssl, k, fd, KTLS_TX) ? 0 : TLS_FAILED;
}

/* For the tests: the crypto_info a direction's keys give the kernel now, its
   length, or TLS_FAILED. */
int64_t tls_kernel_info(int64_t h, int64_t dir, tls_buf out) {
    SSL *ssl = (SSL *)(intptr_t)h;
    ktls_state *k = state_of(ssl);
    const suite *s = ssl ? suite_of_conn(ssl) : NULL;
    if (!k || !s || (dir != KTLS_RX && dir != KTLS_TX) || !(k->have & dir) || out.len < 64)
        return TLS_FAILED;
    int d = dir_index((int)dir);
    size_t n = crypto_info(s, k->secret[d], k->seq[d], out.data);
    return n ? (int64_t)n : TLS_FAILED;
}

/* For the tests: the crypto_info for a suite's IANA name, a secret, and a
   sequence number, as RFC 8448's traces give them. */
int64_t tls_kernel_info_for(tls_bytes name, tls_bytes secret, int64_t seq, tls_buf out) {
    static const char *names[] = { "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
                                   "TLS_CHACHA20_POLY1305_SHA256" };
    if (!ready() || out.len < 64) return TLS_FAILED;
    for (size_t i = 0; i < 3; i++) {
        if ((size_t)name.len == strlen(names[i]) && memcmp(name.data, names[i], (size_t)name.len) == 0 &&
            (size_t)secret.len == suites[i].hash_len) {
            size_t n = crypto_info(&suites[i], secret.data, (uint64_t)seq, out.data);
            return n ? (int64_t)n : TLS_FAILED;
        }
    }
    return TLS_FAILED;
}
