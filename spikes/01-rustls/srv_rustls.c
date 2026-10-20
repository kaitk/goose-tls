/* The server through rustls-ffi's buffer API, set up as close to goose-tls's
   as rustls-ffi allows: TLS 1.3 only, the three suites with AES-128-GCM first
   and the server's order, ALPN http/1.1. rustls-ffi has no call that sets
   the key exchange groups: the provider's defaults stand (aws-lc-rs:
   X25519MLKEM768, X25519, P-256, P-384; ring: X25519, P-256, P-384), and
   the client's offer picks among them. Session tickets stay at rustls's
   defaults, as OpenSSL's do in goose-tls. */
#include <stdio.h>
#include <string.h>

#include "rustls.h"
#include "srv.h"

static const struct rustls_server_config *config;
static char group_name[64], suite_name[64];

static int check(rustls_result r, const char *what) {
    if (r == RUSTLS_RESULT_OK) return 1;
    char msg[256];
    size_t n = 0;
    rustls_error(r, msg, sizeof msg, &n);
    fprintf(stderr, "%s: %.*s\n", what, (int)n, msg);
    return 0;
}

int srv_init(const char *provider, const char *groups, const char *chain_pem, const char *key_pem) {
    (void)groups;
    const struct rustls_crypto_provider *base =
        strcmp(provider, "ring") == 0 ? rustls_ring_crypto_provider() : rustls_aws_lc_rs_crypto_provider();
    if (!base) return 0;
    const struct rustls_supported_ciphersuite *suites[3];
    static const uint16_t order[3] = {0x1301, 0x1302, 0x1303};
    size_t found = 0;
    for (int k = 0; k < 3; k++)
        for (size_t i = 0; i < rustls_crypto_provider_ciphersuites_len(base); i++) {
            const struct rustls_supported_ciphersuite *cs = rustls_crypto_provider_ciphersuites_get(base, i);
            if (rustls_supported_ciphersuite_get_suite(cs) == order[k]) suites[found++] = cs;
        }
    struct rustls_crypto_provider_builder *pb = rustls_crypto_provider_builder_new_with_base(base);
    const struct rustls_crypto_provider *prov = NULL;
    if (found != 3 || !check(rustls_crypto_provider_builder_set_cipher_suites(pb, suites, 3), "suites") ||
        !check(rustls_crypto_provider_builder_build(pb, &prov), "provider"))
        return 0;
    rustls_crypto_provider_builder_free(pb);
    rustls_crypto_provider_free(base);

    /* With both providers built in there's no process default, so the key
       is loaded through the chosen one. Building the certified key takes the
       signing key, though rustls.h says it takes nothing (v0.15.6). */
    struct rustls_signing_key *sk = NULL;
    const struct rustls_certified_key *ck = NULL;
    if (!check(rustls_crypto_provider_load_key(prov, (const uint8_t *)key_pem, strlen(key_pem), &sk), "key") ||
        !check(rustls_certified_key_build_with_signing_key((const uint8_t *)chain_pem, strlen(chain_pem), sk, &ck),
               "certified key"))
        return 0;
    uint16_t versions[1] = {RUSTLS_TLS_VERSION_TLSV1_3};
    struct rustls_server_config_builder *b = NULL;
    if (!check(rustls_server_config_builder_new_custom(prov, versions, 1, &b), "config builder")) return 0;
    struct rustls_slice_bytes alpn = {(const uint8_t *)"http/1.1", 8};
    if (!check(rustls_server_config_builder_set_alpn_protocols(b, &alpn, 1), "alpn") ||
        !check(rustls_server_config_builder_set_ignore_client_order(b, true), "order") ||
        !check(rustls_server_config_builder_set_certified_keys(b, &ck, 1), "keys") ||
        !check(rustls_server_config_builder_build(b, &config), "build"))
        return 0;
    rustls_certified_key_free(ck);
    rustls_crypto_provider_free(prov);
    return 1;
}

void *srv_new(void) {
    struct rustls_connection *c = NULL;
    return check(rustls_server_connection_new(config, &c), "connection") ? c : NULL;
}

typedef struct { const uint8_t *p; size_t n; } cursor;

static rustls_io_result from_cursor(void *ud, uint8_t *buf, size_t n, size_t *out_n) {
    cursor *c = ud;
    size_t k = n < c->n ? n : c->n;
    memcpy(buf, c->p, k);
    c->p += k;
    c->n -= k;
    *out_n = k;
    return 0;
}

/* read_tls takes at most 4 KB a call, and refuses more while 16 KB of
   plaintext waits unread: goose-tls's feed, which takes everything, would
   have to stop there and say how much it took. */
int64_t srv_feed(void *s, const uint8_t *data, size_t len) {
    cursor c = {data, len};
    while (c.n > 0) {
        size_t n = 0;
        if (rustls_connection_read_tls(s, from_cursor, &c, &n) != 0 || n == 0) return SRV_FAIL;
        if (!check(rustls_connection_process_new_packets(s), "process")) return SRV_FAIL;
    }
    return 0;
}

int64_t srv_handshake(void *s) {
    return rustls_connection_is_handshaking(s) ? SRV_WANT : 0;
}

int64_t srv_read(void *s, uint8_t *buf, size_t cap) {
    size_t n = 0;
    rustls_result r = rustls_connection_read(s, buf, cap, &n);
    if (r == RUSTLS_RESULT_PLAINTEXT_EMPTY || (r == RUSTLS_RESULT_OK && n == 0)) return SRV_WANT;
    return check(r, "read") ? (int64_t)n : SRV_FAIL;
}

int64_t srv_write(void *s, const uint8_t *data, size_t len) {
    size_t n = 0;
    return check(rustls_connection_write(s, data, len, &n), "write") ? (int64_t)n : SRV_FAIL;
}

typedef struct { uint8_t *p; size_t cap, n; } sink;

static rustls_io_result to_sink(void *ud, const uint8_t *buf, size_t n, size_t *out_n) {
    sink *k = ud;
    size_t m = n < k->cap - k->n ? n : k->cap - k->n;
    memcpy(k->p + k->n, buf, m);
    k->n += m;
    *out_n = m;
    return 0;
}

int64_t srv_drain(void *s, uint8_t *buf, size_t cap) {
    sink k = {buf, cap, 0};
    while (k.n < cap && rustls_connection_wants_write(s)) {
        size_t n = 0;
        if (rustls_connection_write_tls(s, to_sink, &k, &n) != 0 || n == 0) break;
    }
    return (int64_t)k.n;
}

void srv_free(void *s) { rustls_connection_free(s); }

const char *srv_group(void *s) {
    struct rustls_str g = rustls_connection_get_negotiated_key_exchange_group_name(s);
    snprintf(group_name, sizeof group_name, "%.*s", (int)g.len, g.data);
    return group_name;
}

const char *srv_suite(void *s) {
    struct rustls_str g = rustls_connection_get_negotiated_ciphersuite_name(s);
    snprintf(suite_name, sizeof suite_name, "%.*s", (int)g.len, g.data);
    return suite_name;
}

const char *srv_alpn(void *s, size_t *len) {
    const uint8_t *p = NULL;
    rustls_connection_get_alpn_protocol(s, &p, len);
    return (const char *)p;
}
