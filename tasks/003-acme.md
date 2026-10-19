# 003: ACME in the process

Status: todo (after task 001 and goose-http's task 051, outbound connections)

A server built on goose-tls gets and renews its own certificates, so one binary can face
the internet without Caddy or nginx. snowtime-native does this today with rustls-acme:
TLS-ALPN-01 on port 443, Let's Encrypt production or staging, and a cache of account and
certificate keys in a private directory (`crates/host/src/edge/`, and its `README.md`,
"ACME"). This task matches that.

## What it needs

- TLS-ALPN-01 (RFC 8737): during a challenge, the listener answers ALPN `acme-tls/1`
  with a self-signed certificate that carries the challenge's `acmeIdentifier`
  extension, for that server name only. Other connections keep the real certificate.
- Client TLS in this package, to reach the ACME directory over HTTPS, and an HTTP client
  over goose-http's outbound connections.
- JWS signing with the account key (ES256), a CSR for the domains, and JSON.
- A certificate swap while running (task 001's API leaves room for it): new
  connections take the new certificate.
- Renewal before expiry, and a cache directory created 0700 with files 0600.

Out of scope, as in snowtime-native: wildcard certificates (TLS-ALPN-01 can't issue
them) and HTTP-01 and DNS-01 challenges.

## Open

- Where ACME lives: a module of this package, or a package of its own
  (`docs/decisions.md`, "Open").

## Acceptance criteria

- [ ] Where ACME lives recorded in `docs/decisions.md`
- [ ] A certificate issued by Let's Encrypt's staging service to a test server, and
      renewed while it serves, without a restart
- [ ] The cache's directory and file modes checked by a test
- [ ] `scripts/test.sh` passes, with a test against a local ACME server (Pebble)
