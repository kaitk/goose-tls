/* What tls.c and crypto.c share: the status codes tls.goose names, and Goose's
   slice layouts. */
#ifndef GOOSE_TLS_H
#define GOOSE_TLS_H

#include <stdint.h>

#include <openssl/ssl.h>

#define TLS_WANT_INPUT -1
#define TLS_CLOSED -2
#define TLS_FAILED -3
#define TLS_HELLO -6

#pragma pack(push, 1)
typedef struct { const uint8_t *data; int64_t len; } tls_bytes;
typedef struct { uint8_t *data; int64_t len; } tls_buf;
#pragma pack(pop)
_Static_assert(sizeof(tls_bytes) == sizeof(void *) + 8, "a Goose slice is { data, len }, packed");

#endif
