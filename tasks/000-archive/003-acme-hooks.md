# 003: Hooks for an outside ACME package

Status: todo (after task 001; rewritten 2026-10-19, when ACME moved to a package of its
own)

ACME lives in a package of its own, built on goose-tls ([decisions](../docs/decisions.md)).
That package, its protocol, its cache, and its tests are goose-rest's task 049. It is
proposed with no I/O, so it depends on goose-tls alone, and goose-tls's API is all it can
use. This task adds what it needs from that API: the hooks below, through which an ACME
package does TLS-ALPN-01 (RFC 8737) and reaches the ACME directory over HTTPS.

## What it needs

- **A certificate chosen per connection.** Before the handshake answers, the program
  sees the client's SNI name and offered ALPN list and picks the context for that
  connection. During a challenge, a connection that offers `acme-tls/1` for the
  challenged name gets a self-signed certificate that carries the challenge's
  `acmeIdentifier` extension, and every other connection keeps the real certificate.
  The planned shape is a status that pauses the handshake after the ClientHello
  (OpenSSL's client hello callback), calls that read the name and the protocols, and a
  call that sets the connection's context before the handshake resumes
  (`docs/architecture.md`, "Planned").
- **A certificate replaced while running.** New connections take the new certificate;
  open ones keep theirs. Task 001's contexts already allow it: a program makes a new
  context and accepts new connections from it, and a connection holds its own reference
  to the old one. This task adds a test that shows it; HttpArena's opt-in `tls_check`
  rotation probes are a check to run against it.
- **Client TLS**, for the ACME directory's HTTPS: a client context that verifies the
  server's chain against the system's trust store and checks its name, with the same
  connection calls as a server's.
- **The crypto**, so that the ACME package needs no C of its own: an EC P-256 key,
  generated or read from PEM and written as PEM; ES256 signatures for JWS, in the raw
  64-byte `r || s` form JWS uses rather than DER; a CSR for a list of names; and a
  self-signed certificate with the `acmeIdentifier` extension.

## Acceptance criteria

- [ ] A test server that picks a context per connection from the SNI name and the
      offered ALPN list, checked with `openssl s_client -servername` and `-alpn
      acme-tls/1`
- [ ] A test that a context replaced while serving reaches new connections and leaves
      open ones as they were
- [ ] Client TLS that completes a verified handshake with a public HTTPS server and
      refuses a self-signed one
- [ ] Key generation, ES256 signing, a CSR, and the challenge certificate, each checked
      against `openssl` (`dgst -verify`, `req -verify`, `x509 -text`)
- [ ] `scripts/test.sh` passes
