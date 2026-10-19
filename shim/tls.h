/* What tls.c and ktls.c share: the status codes tls.goose names, Goose's
   slice layouts, and the hooks through which a connection's kTLS state
   follows the connection. */
#ifndef GOOSE_TLS_H
#define GOOSE_TLS_H

#include <stdint.h>

#include <openssl/ssl.h>

#define TLS_WANT_INPUT -1
#define TLS_CLOSED -2
#define TLS_FAILED -3
#define TLS_PENDING -4
#define TLS_UPDATE_TX -5
#define TLS_HELLO -6

/* The directions in_kernel reports. */
#define KTLS_RX 1
#define KTLS_TX 2

#pragma pack(push, 1)
typedef struct { const uint8_t *data; int64_t len; } tls_bytes;
typedef struct { uint8_t *data; int64_t len; } tls_buf;
#pragma pack(pop)
_Static_assert(sizeof(tls_bytes) == sizeof(void *) + 8, "a Goose slice is { data, len }, packed");

/* Gives a connection made from a context with kTLS enabled its kTLS state;
   0 when that fails. A connection from any other context needs none. */
int ktls_attach(SSL *ssl);

/* Follows the record framing of the bytes fed to the connection, so that the
   switch to the kernel happens only at a record's boundary. */
void ktls_frame(SSL *ssl, const uint8_t *data, int64_t len);

/* Whether the kernel holds the direction, KTLS_RX or KTLS_TX. */
int ktls_owns(SSL *ssl, int dir);

#endif
