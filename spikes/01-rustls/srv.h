/* The server side the harness drives, shaped as goose-tls's shim is: bytes
   received go in (srv_feed), plaintext comes out (srv_read), plaintext goes in
   (srv_write), and the bytes to send come out (srv_drain). srv_openssl.c and
   srv_rustls.c each implement it. */
#include <stddef.h>
#include <stdint.h>

#define SRV_WANT (-1)
#define SRV_FAIL (-2)

/* provider: "openssl", "aws-lc-rs", or "ring"; groups: "default" or
   "x25519". rustls-ffi has no call that sets the groups, so for rustls the
   client's offer decides. */
int srv_init(const char *provider, const char *groups, const char *chain_pem, const char *key_pem);
void *srv_new(void);
/* Takes all of data and processes it: 0, or SRV_FAIL. */
int64_t srv_feed(void *s, const uint8_t *data, size_t len);
/* 0 once the handshake is done, else SRV_WANT or SRV_FAIL. */
int64_t srv_handshake(void *s);
int64_t srv_read(void *s, uint8_t *buf, size_t cap);
int64_t srv_write(void *s, const uint8_t *data, size_t len);
int64_t srv_drain(void *s, uint8_t *buf, size_t cap);
void srv_free(void *s);
const char *srv_group(void *s);
const char *srv_suite(void *s);
const char *srv_alpn(void *s, size_t *len);
