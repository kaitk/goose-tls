# 003: Hooks for an outside ACME package

Status: done (2026-10-19; tested on macOS against OpenSSL 3.6.5 and 4.0.3, and on
Ubuntu 24.04 against 3.0.13)

ACME lives in a package of its own, built on goose-tls ([decisions](../../docs/decisions.md)).
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
  call that sets the connection's context before the handshake resumes.
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

## What was built

- `tls::choose_context`, the `tls::HELLO` status, `tls::server_name`, `tls::offers`
  and `tls::offered`, and `tls::use_context`: OpenSSL's client hello callback pauses
  the handshake, and the shim reads SNI and ALPN from the raw extensions.
- `tls::client`, `tls::client_trusting`, `tls::connect`, `tls::peer_certificate`, and
  `tls::share`, with the verification failure's reason in `tls::error_text`.
- `tls::Key`, `tls::key_generate`, `tls::key_from_pem`, `tls::key_pem`,
  `tls::public_xy`, `tls::sign_es256`, `tls::sha256`, `tls::csr`, `tls::self_signed`,
  and `tls::challenge_certificate`, in `shim/crypto.c`.
- Tests: `test/conn/choose.goose`, `test/conn/client.goose`,
  `test/context/replace.goose`, and `test/crypto/keys.goose` in memory;
  `scripts/test-handshake.sh`'s server with its `choose` option and the client
  `test/tools/client.goose`; and `scripts/test-crypto.sh`.

HttpArena's opt-in `tls_check` rotation probes weren't run: they need a server that
reloads its certificate while it runs, which the test server doesn't.

## Acceptance criteria

- [x] A test server that picks a context per connection from the SNI name and the
      offered ALPN list, checked with `openssl s_client -servername` and `-alpn
      acme-tls/1`
- [x] A test that a context replaced while serving reaches new connections and leaves
      open ones as they were
- [x] Client TLS that completes a verified handshake with a public HTTPS server and
      refuses a self-signed one
- [x] Key generation, ES256 signing, a CSR, and the challenge certificate, each checked
      against `openssl` (`dgst -verify`, `req -verify`, `x509 -text`)
- [x] `scripts/test.sh` passes
