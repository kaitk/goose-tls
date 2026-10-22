/* srv.h over the Goose server's exports (bench_goose.goose), and bench.c
   itself, whose main runs as bench_run's. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../01-rustls/srv.h"

#define main bench_main
#include "../01-rustls/bench.c"
#undef main

#pragma pack(push, 1)
typedef struct { const uint8_t *data; int64_t len; } gbytes;
typedef struct { uint8_t *data; int64_t len; } gbuf;
#pragma pack(pop)

uint8_t gsrv_init(gbytes groups, gbytes chain, gbytes key);
int64_t gsrv_new(void);
int64_t gsrv_feed(int64_t id, gbytes data);
int64_t gsrv_handshake(int64_t id);
int64_t gsrv_read(int64_t id, gbuf buf);
int64_t gsrv_write(int64_t id, gbytes data);
int64_t gsrv_drain(int64_t id, gbuf buf);
void gsrv_free(int64_t id);
int64_t gsrv_group(int64_t id, gbuf out);
int64_t gsrv_suite(int64_t id, gbuf out);
int64_t gsrv_alpn(int64_t id, gbuf out);

static gbytes text(const char *s) { return (gbytes){ (const uint8_t *)s, (int64_t)strlen(s) }; }

int srv_init(const char *provider, const char *groups, const char *chain_pem, const char *key_pem) {
    (void)provider;
    return gsrv_init(text(groups), text(chain_pem), text(key_pem));
}

/* A connection is its handle; 0 isn't one, so it passes as a pointer. */
void *srv_new(void) { return (void *)(intptr_t)gsrv_new(); }

int64_t srv_feed(void *s, const uint8_t *data, size_t len) {
    return gsrv_feed((int64_t)(intptr_t)s, (gbytes){ data, (int64_t)len });
}

int64_t srv_handshake(void *s) { return gsrv_handshake((int64_t)(intptr_t)s); }

int64_t srv_read(void *s, uint8_t *buf, size_t cap) {
    return gsrv_read((int64_t)(intptr_t)s, (gbuf){ buf, (int64_t)cap });
}

int64_t srv_write(void *s, const uint8_t *data, size_t len) {
    return gsrv_write((int64_t)(intptr_t)s, (gbytes){ data, (int64_t)len });
}

int64_t srv_drain(void *s, uint8_t *buf, size_t cap) {
    return gsrv_drain((int64_t)(intptr_t)s, (gbuf){ buf, (int64_t)cap });
}

void srv_free(void *s) { gsrv_free((int64_t)(intptr_t)s); }

static char name[3][64];

const char *srv_group(void *s) {
    int64_t n = gsrv_group((int64_t)(intptr_t)s, (gbuf){ (uint8_t *)name[0], 63 });
    name[0][n] = 0;
    return name[0];
}

const char *srv_suite(void *s) {
    int64_t n = gsrv_suite((int64_t)(intptr_t)s, (gbuf){ (uint8_t *)name[1], 63 });
    name[1][n] = 0;
    return name[1];
}

const char *srv_alpn(void *s, size_t *len) {
    *len = (size_t)gsrv_alpn((int64_t)(intptr_t)s, (gbuf){ (uint8_t *)name[2], 63 });
    return name[2];
}

/* Splits the NUL-separated arguments bench_goose.goose gives into argv. */
int32_t bench_run(gbytes args) {
    char *copy = malloc((size_t)args.len + 1);
    char *argv[16];
    int argc = 0;
    memcpy(copy, args.data, (size_t)args.len);
    copy[args.len] = 0;
    for (int64_t i = 0; i < args.len && argc < 15; i += (int64_t)strlen(copy + i) + 1) argv[argc++] = copy + i;
    argv[argc] = NULL;
    return bench_main(argc, argv);
}
