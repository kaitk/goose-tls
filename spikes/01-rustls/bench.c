/* bench PROVIDER GROUPS MODE [ARGS]: one TLS server library (srv.h) against
   OpenSSL clients in the same process, bytes moved in memory, no sockets.

   PROVIDER is openssl, aws-lc-rs, or ring (which server srv_*.c was linked
   in says which library; goose for spike 02's), GROUPS default or x25519:
   what the client offers, and for OpenSSL what the server accepts too. The
   client is always the system's OpenSSL, so its share of the work is the
   same for every server. Each mode prints one line of key=value pairs.

     check          one handshake and request: the group, suite, and ALPN
     idle N         N server connections, each handshaken, given a 200 B
                    request and an 8,545 B response, then its client freed:
                    the heap (glibc's in-use bytes), glibc's mmapped bytes,
                    and VmRSS they hold
     inflight N     N server connections stopped after their first flight:
                    ClientHello read, ServerHello to Finished sent and drained
     queued N       the same, with the flight left waiting for drain
     empty N        N server connections, before any byte is fed
     peak N         N handshakes: the most OpenSSL's allocator holds above its
                    level while the server answers a ClientHello
     churn N        three rounds of N connections, each given a 64 KiB
                    response and freed: the heap and RSS kept after them
     hs N           N full handshakes: the time in server calls
     enc MIB        16 KB records encrypted by the server
     dec MIB        16 KB records decrypted by the server
     json N K       N requests over K connections in turn: 200 B in, 8,545 B
                    out, the time in server calls

   Times count only the server's calls, each between two CLOCK_MONOTONIC
   reads; the clients' work is left out. With ALLOCS=1 in the environment,
   hs, resume, and json also count the allocations OpenSSL's allocator makes
   inside the server's calls, per handshake or request, which covers the
   Goose server's shim and libcrypto but not rustls's own; counting slows
   the calls, so take times from runs without it. */
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
/* Inside a server call, and with ALLOCS=1 the allocations made there. */
static int in_srv, counting;
static long n_alloc, n_realloc, n_free;
static uint64_t now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}
#define S(expr) __extension__({ uint64_t t0_ = now(); in_srv = 1; __auto_type r_ = (expr); in_srv = 0; t_srv += now() - t0_; r_; })
#define SV(expr) do { uint64_t t0_ = now(); in_srv = 1; expr; in_srv = 0; t_srv += now() - t0_; } while (0)

static void reset(void) { t_srv = 0, n_alloc = n_realloc = n_free = 0; }

/* With ALLOCS=1: the allocations per op. */
static void print_allocs(long ops) {
    if (counting)
        printf(" server_allocs_per_op=%.2f server_reallocs_per_op=%.2f server_frees_per_op=%.2f",
               (double)n_alloc / ops, (double)n_realloc / ops, (double)n_free / ops);
}

static void die(const char *what) {
    fprintf(stderr, "bench: %s\n", what);
    ERR_print_errors_fp(stderr);
    exit(1);
}

/* OpenSSL's allocations, counted in peak mode through CRYPTO_set_mem_functions:
   what is held now, and the most held since the last reset. */
static size_t mem_now, mem_peak;
static void *track_malloc(size_t n, const char *file, int line) {
    (void)file, (void)line;
    size_t *p = malloc(n + 16);
    if (!p) return NULL;
    *p = n;
    n_alloc += in_srv;
    mem_now += n;
    if (mem_now > mem_peak) mem_peak = mem_now;
    return (char *)p + 16;
}
static void *track_realloc(void *q, size_t n, const char *file, int line) {
    if (!q) return track_malloc(n, file, line);
    size_t *p = (size_t *)((char *)q - 16), old = *p;
    p = realloc(p, n + 16);
    if (!p) return NULL;
    *p = n;
    n_realloc += in_srv;
    mem_now = mem_now - old + n;
    if (mem_now > mem_peak) mem_peak = mem_now;
    return (char *)p + 16;
}
static void track_free(void *q, const char *file, int line) {
    (void)file, (void)line;
    if (!q) return;
    size_t *p = (size_t *)((char *)q - 16);
    n_free += in_srv;
    mem_now -= *p;
    free(p);
}

static size_t heap(void) { return mallinfo2().uordblks; }
static size_t mapped(void) { return mallinfo2().hblkhd; }
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
/* The session from the last ticket a client took, in resume mode. */
static SSL_SESSION *sess;
static int keep_session(SSL *c, SSL_SESSION *s) {
    (void)c;
    SSL_SESSION_free(sess);
    sess = s;
    return 1;
}
static void client_init(const char *groups, int resume) {
    cctx = SSL_CTX_new(TLS_client_method());
    if (!cctx || SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_alpn_protos(cctx, (const unsigned char *)"\x08http/1.1", 9) != 0)
        die("client context");
    if (strcmp(groups, "x25519") == 0 && SSL_CTX_set1_groups_list(cctx, "X25519") != 1) die("client groups");
    /* OpenSSL hands a client its TLS 1.3 sessions only through the new
       session callback, which a client cache turns on. */
    SSL_CTX_set_session_cache_mode(cctx, resume ? SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE
                                                : SSL_SESS_CACHE_OFF);
    if (resume) SSL_CTX_sess_set_new_cb(cctx, keep_session);
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
    counting = getenv("ALLOCS") && strcmp(getenv("ALLOCS"), "1") == 0;
    if ((strcmp(mode, "peak") == 0 || counting) && !CRYPTO_set_mem_functions(track_malloc, track_realloc, track_free))
        die("OpenSSL allocated before its allocator could be counted");
    long a = argc > 4 ? atol(argv[4]) : 1000, b = argc > 5 ? atol(argv[5]) : 1;
    const char *dir = getenv("CERTS") ? getenv("CERTS") : ".";
    char path[1024];
    snprintf(path, sizeof path, "%s/cert.pem", dir);
    char *chain = slurp(path);
    snprintf(path, sizeof path, "%s/key.pem", dir);
    char *key = slurp(path);
    if (!srv_init(provider, groups, chain, key)) die("server config");
    client_init(groups, strcmp(mode, "resume") == 0);
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
    /* A client freed without a shutdown marks its session not resumable. */
    SSL_set_shutdown(c0, SSL_SENT_SHUTDOWN);
    SSL_free(c0);
    srv_free(s0);
    reset();

    if (strcmp(mode, "idle") == 0 || strcmp(mode, "inflight") == 0 || strcmp(mode, "queued") == 0 ||
        strcmp(mode, "empty") == 0) {
        int inflight = mode[0] == 'i' && mode[1] == 'n', queued = mode[0] == 'q', empty = mode[0] == 'e';
        void **s = calloc((size_t)a, sizeof *s);
        size_t h0 = heap(), m0 = mapped();
        long r0 = rss_kb();
        for (long i = 0; i < a; i++) {
            s[i] = server_new();
            if (empty) continue;
            SSL *c = client_new();
            if (inflight || queued) {
                SSL_do_handshake(c);
                to_server(c, s[i]);
                if (S(srv_handshake(s[i])) != SRV_WANT) die("handshake ended early");
                if (inflight) discard(s[i]);
            } else {
                handshake(s[i], c);
                exchange(s[i], c, 1);
            }
            SSL_free(c);
        }
        size_t h1 = heap(), m1 = mapped();
        long r1 = rss_kb();
        printf(" n=%ld heap_per_conn=%.0f mmap_per_conn=%.0f rss_per_conn=%.0f\n", a, (double)(h1 - h0) / a,
               ((double)m1 - (double)m0) / a, (double)(r1 - r0) * 1024 / a);
        return 0;
    }
    if (strcmp(mode, "peak") == 0) {
        /* The most OpenSSL's allocator holds above its level before the
           server's call that answers the ClientHello, while that call runs:
           the transient a handshake adds. */
        size_t most = 0, total = 0;
        for (long i = 0; i < a; i++) {
            void *s = server_new();
            SSL *c = client_new();
            SSL_do_handshake(c);
            to_server(c, s);
            size_t before = mem_now;
            mem_peak = mem_now;
            if (S(srv_handshake(s)) != SRV_WANT) die("handshake ended early");
            size_t rise = mem_peak - before;
            total += rise;
            if (rise > most) most = rise;
            srv_free(s);
            SSL_free(c);
        }
        printf(" n=%ld peak_mean=%.0f peak_max=%zu\n", a, (double)total / a, most);
        return 0;
    }
    if (strcmp(mode, "churn") == 0) {
        /* Rounds of N connections held at once, each given a request and a
           64 KiB response, then all freed: what the heap and RSS keep after
           the last round, against before the first. */
        static uint8_t big[65536];
        memset(big, 'b', sizeof big);
        void **s = calloc((size_t)a, sizeof *s);
        size_t h0 = heap();
        long r0 = rss_kb();
        for (int round = 0; round < 3; round++) {
            for (long i = 0; i < a; i++) {
                s[i] = server_new();
                SSL *c = client_new();
                handshake(s[i], c);
                exchange(s[i], c, 1);
                if (S(srv_write(s[i], big, sizeof big)) != (int64_t)sizeof big) die("server write");
                to_client(s[i], c);
                SSL_free(c);
            }
            for (long i = 0; i < a; i++) srv_free(s[i]);
        }
        size_t h1 = heap();
        long r1 = rss_kb();
        printf(" n=%ld heap_kept=%zd rss_kept=%ld\n", a, (ssize_t)(h1 - h0), (r1 - r0) * 1024);
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
        printf(" n=%ld group=%s server_us_per_hs=%.1f server_hs_per_s=%.0f wall_hs_per_s=%.0f", a, g,
               srv * 1e6 / a, a / srv, a / wall);
        print_allocs(a);
        printf("\n");
        return 0;
    }
    if (strcmp(mode, "resume") == 0) {
        /* As hs, each client resuming from the ticket the one before it
           took, as a client that keeps its latest ticket does. */
        if (!sess) die("no ticket to resume from");
        uint64_t w0 = now();
        for (long i = 0; i < a; i++) {
            void *s = server_new();
            SSL *c = client_new();
            if (SSL_set_session(c, sess) != 1) die("client session");
            handshake(s, c);
            if (!SSL_session_reused(c)) die("not resumed");
            SV(srv_free(s));
            SSL_set_shutdown(c, SSL_SENT_SHUTDOWN);
            SSL_free(c);
        }
        double wall = (double)(now() - w0) / 1e9, srv = (double)t_srv / 1e9;
        printf(" n=%ld group=%s server_us_per_hs=%.1f server_hs_per_s=%.0f wall_hs_per_s=%.0f", a, g,
               srv * 1e6 / a, a / srv, a / wall);
        print_allocs(a);
        printf("\n");
        return 0;
    }
    if (strcmp(mode, "enc") == 0 || strcmp(mode, "dec") == 0) {
        void *s = server_new();
        SSL *c = client_new();
        handshake(s, c);
        static uint8_t rec[16384];
        memset(rec, 'b', sizeof rec);
        long recs = a * 64;
        reset();
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
        reset();
        for (long i = 0; i < a; i++) exchange(s[i % b], c[i % b], 0);
        double srv = (double)t_srv / 1e9;
        printf(" n=%ld conns=%ld server_us_per_req=%.2f server_req_per_s=%.0f", a, b, srv * 1e6 / a, a / srv);
        print_allocs(a);
        printf("\n");
        return 0;
    }
    die("unknown mode");
}
