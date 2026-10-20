/* bench PROVIDER GROUPS MODE [ARGS]: one TLS server library (srv.h) against
   OpenSSL clients in the same process, bytes moved in memory, no sockets.

   PROVIDER is openssl, aws-lc-rs, or ring (which server srv_*.c was linked
   in says which library), GROUPS default or x25519: what the client offers,
   and for OpenSSL what the server accepts too. The client is always the
   system's OpenSSL, so its share of the work is the same for every server.
   Each mode prints one line of key=value pairs.

     check          one handshake and request: the group, suite, and ALPN
     idle N         N server connections, each handshaken, given a 200 B
                    request and an 8,545 B response, then its client freed:
                    the heap (glibc's in-use bytes) and VmRSS they hold
     inflight N     N server connections stopped after their first flight:
                    ClientHello read, ServerHello to Finished sent
     hs N           N full handshakes: the time in server calls
     enc MIB        16 KB records encrypted by the server
     dec MIB        16 KB records decrypted by the server
     json N K       N requests over K connections in turn: 200 B in, 8,545 B
                    out, the time in server calls

   Times count only the server's calls, each between two CLOCK_MONOTONIC
   reads; the clients' work is left out. */
#define _GNU_SOURCE
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "srv.h"

static uint64_t t_srv;
static uint64_t now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}
#define S(expr) __extension__({ uint64_t t0_ = now(); __auto_type r_ = (expr); t_srv += now() - t0_; r_; })
#define SV(expr) do { uint64_t t0_ = now(); expr; t_srv += now() - t0_; } while (0)

static void die(const char *what) {
    fprintf(stderr, "bench: %s\n", what);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static size_t heap(void) { return mallinfo2().uordblks; }
static long rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long kb = -1;
    while (f && fgets(line, sizeof line, f))
        if (sscanf(line, "VmRSS: %ld", &kb) == 1) break;
    if (f) fclose(f);
    return kb;
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) die(path);
    static char *p;
    p = malloc(1 << 16);
    size_t n = fread(p, 1, (1 << 16) - 1, f);
    p[n] = 0;
    fclose(f);
    return p;
}

static SSL_CTX *cctx;
static void client_init(const char *groups) {
    cctx = SSL_CTX_new(TLS_client_method());
    if (!cctx || SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_alpn_protos(cctx, (const unsigned char *)"\x08http/1.1", 9) != 0)
        die("client context");
    if (strcmp(groups, "x25519") == 0 && SSL_CTX_set1_groups_list(cctx, "X25519") != 1) die("client groups");
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_OFF);
}
static SSL *client_new(void) {
    SSL *c = SSL_new(cctx);
    BIO *in = BIO_new(BIO_s_mem()), *out = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(in, -1);
    BIO_set_mem_eof_return(out, -1);
    SSL_set_bio(c, in, out);
    SSL_set_connect_state(c);
    return c;
}

static uint8_t wire[1 << 18], plain[1 << 17];

static void to_server(SSL *c, void *s) {
    int n;
    while ((n = BIO_read(SSL_get_wbio(c), wire, sizeof wire)) > 0)
        if (S(srv_feed(s, wire, (size_t)n)) != 0) die("feed");
}
static void to_client(void *s, SSL *c) {
    int64_t n;
    while ((n = S(srv_drain(s, wire, sizeof wire))) > 0) BIO_write(SSL_get_rbio(c), wire, (int)n);
}
static void discard(void *s) {
    while (S(srv_drain(s, wire, sizeof wire)) > 0) {}
}

static void handshake(void *s, SSL *c) {
    int64_t st = SRV_WANT;
    for (int r = 0; r < 10 && !(st == 0 && SSL_is_init_finished(c)); r++) {
        SSL_do_handshake(c);
        to_server(c, s);
        st = S(srv_handshake(s));
        if (st == SRV_FAIL) die("server handshake");
        to_client(s, c);
    }
    if (st != 0 || !SSL_is_init_finished(c)) die("no handshake");
    /* The client takes the session tickets. */
    char b[64];
    if (SSL_read(c, b, sizeof b) > 0) die("unexpected data");
}

static char request[200], response[8545];

static void exchange(void *s, SSL *c, int client_reads) {
    if (SSL_write(c, request, sizeof request) != (int)sizeof request) die("client write");
    to_server(c, s);
    int64_t got = 0;
    while (got < (int64_t)sizeof request) {
        int64_t n = S(srv_read(s, plain, sizeof plain));
        if (n <= 0) die("server read");
        got += n;
    }
    if (S(srv_write(s, (const uint8_t *)response, sizeof response)) != (int64_t)sizeof response) die("server write");
    if (!client_reads) {
        discard(s);
        return;
    }
    to_client(s, c);
    int left = sizeof response, n;
    while (left > 0 && (n = SSL_read(c, plain, sizeof plain)) > 0) left -= n;
    if (left) die("client read");
}

static void *server_new(void) {
    void *s = S(srv_new());
    if (!s) die("server connection");
    return s;
}

int main(int argc, char **argv) {
    if (argc < 4) die("usage: bench PROVIDER GROUPS MODE [ARGS]");
    const char *provider = argv[1], *groups = argv[2], *mode = argv[3];
    long a = argc > 4 ? atol(argv[4]) : 1000, b = argc > 5 ? atol(argv[5]) : 1;
    const char *dir = getenv("CERTS") ? getenv("CERTS") : ".";
    char path[1024];
    snprintf(path, sizeof path, "%s/cert.pem", dir);
    char *chain = slurp(path);
    snprintf(path, sizeof path, "%s/key.pem", dir);
    char *key = slurp(path);
    if (!srv_init(provider, groups, chain, key)) die("server config");
    client_init(groups);
    memset(request, 'q', sizeof request);
    memcpy(request, "GET /json/10?m=3 HTTP/1.1\r\n", 27);
    memset(response, 'r', sizeof response);
    printf("provider=%s groups=%s mode=%s", provider, groups, mode);

    /* One connection first, so one-time setup isn't counted. */
    void *s0 = server_new();
    SSL *c0 = client_new();
    handshake(s0, c0);
    exchange(s0, c0, 1);
    size_t alen = 0;
    const char *alpn = srv_alpn(s0, &alen);
    char g[64], suite[64];
    snprintf(g, sizeof g, "%s", srv_group(s0));
    snprintf(suite, sizeof suite, "%s", srv_suite(s0));
    if (strcmp(mode, "check") == 0) {
        printf(" group=%s suite=%s alpn=%.*s\n", g, suite, (int)alen, alpn ? alpn : "");
        return 0;
    }
    SSL_free(c0);
    srv_free(s0);
    t_srv = 0;

    if (strcmp(mode, "idle") == 0 || strcmp(mode, "inflight") == 0) {
        int inflight = mode[0] == 'i' && mode[1] == 'n';
        void **s = calloc((size_t)a, sizeof *s);
        size_t h0 = heap();
        long r0 = rss_kb();
        for (long i = 0; i < a; i++) {
            s[i] = server_new();
            SSL *c = client_new();
            if (inflight) {
                SSL_do_handshake(c);
                to_server(c, s[i]);
                if (S(srv_handshake(s[i])) != SRV_WANT) die("handshake ended early");
                discard(s[i]);
            } else {
                handshake(s[i], c);
                exchange(s[i], c, 1);
            }
            SSL_free(c);
        }
        size_t h1 = heap();
        long r1 = rss_kb();
        printf(" n=%ld heap_per_conn=%.0f rss_per_conn=%.0f\n", a, (double)(h1 - h0) / a,
               (double)(r1 - r0) * 1024 / a);
        return 0;
    }
    if (strcmp(mode, "hs") == 0) {
        uint64_t w0 = now();
        for (long i = 0; i < a; i++) {
            void *s = server_new();
            SSL *c = client_new();
            handshake(s, c);
            SV(srv_free(s));
            SSL_free(c);
        }
        double wall = (double)(now() - w0) / 1e9, srv = (double)t_srv / 1e9;
        printf(" n=%ld group=%s server_us_per_hs=%.1f server_hs_per_s=%.0f wall_hs_per_s=%.0f\n", a, g,
               srv * 1e6 / a, a / srv, a / wall);
        return 0;
    }
    if (strcmp(mode, "enc") == 0 || strcmp(mode, "dec") == 0) {
        void *s = server_new();
        SSL *c = client_new();
        handshake(s, c);
        static uint8_t rec[16384];
        memset(rec, 'b', sizeof rec);
        long recs = a * 64;
        t_srv = 0;
        for (long i = 0; i < recs; i++) {
            if (mode[0] == 'e') {
                if (S(srv_write(s, rec, sizeof rec)) != (int64_t)sizeof rec) die("server write");
                discard(s);
            } else {
                if (SSL_write(c, rec, sizeof rec) != (int)sizeof rec) die("client write");
                to_server(c, s);
                int64_t got = 0;
                while (got < (int64_t)sizeof rec) {
                    int64_t n = S(srv_read(s, plain, sizeof plain));
                    if (n <= 0) die("server read");
                    got += n;
                }
            }
        }
        printf(" mib=%ld suite=%s mib_per_s=%.0f\n", a, suite, (double)a / ((double)t_srv / 1e9));
        return 0;
    }
    if (strcmp(mode, "json") == 0) {
        void **s = calloc((size_t)b, sizeof *s);
        SSL **c = calloc((size_t)b, sizeof *c);
        for (long k = 0; k < b; k++) {
            s[k] = server_new();
            c[k] = client_new();
            handshake(s[k], c[k]);
        }
        t_srv = 0;
        for (long i = 0; i < a; i++) exchange(s[i % b], c[i % b], 0);
        double srv = (double)t_srv / 1e9;
        printf(" n=%ld conns=%ld server_us_per_req=%.2f server_req_per_s=%.0f\n", a, b, srv * 1e6 / a, a / srv);
        return 0;
    }
    die("unknown mode");
}
