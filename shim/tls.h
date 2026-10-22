/* What tls.c, crypto.c, and server.c share: the status codes tls.goose
   names, Goose's slice layouts, and the session tickets' keys. */
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

/* Session tickets' keys (RFC 8446, section 4.6.1; RFC 9325, section 3.4),
   which either server keeps per context, two at a time: ring[0] issues
   tickets, and ring[1], the one before it, still opens them until it
   expires. A key issues for at most TICKET_PERIOD seconds of
   tlsg_ticket_now, and opens for at most twice that, the last ticket's
   lifetime after it stopped issuing; and it issues at most TICKET_MAX_USES
   tickets, well inside AES-GCM's 2^32 random nonces under one key. server.c
   keeps the ring; its callers hold the context's lock. */
#define TICKET_PERIOD 7200
#define TICKET_MAX_USES ((uint64_t)1 << 30)

typedef struct {
    uint8_t live;
    uint8_t id[4];
    /* Random: the Goose server's AES-256-GCM key is the first half, libssl's
       AES-256-CBC key and HMAC-SHA256 key the two halves. */
    uint8_t key[64];
    int64_t created;
    uint64_t uses;
} ticket_key;

int64_t tlsg_ticket_now(void);
/* The key to issue a ticket under now, its id and bytes copied out, turning
   the ring when ring[0] is spent: 0 when a new key's random bytes fail, and
   then no key issues. */
int ticket_key_issue(ticket_key ring[2], int64_t now, uint8_t id[4], uint8_t key[64]);
/* The key with id that may still open a ticket now, its bytes copied out:
   0 for none. */
int ticket_key_open(ticket_key ring[2], int64_t now, const uint8_t id[4], uint8_t key[64]);

#endif
