# goose-tls

TLS for [Goose](https://github.com/aardappel/goose): a Goose API over OpenSSL 3, with
opaque handles and a handshake that takes bytes in and gives bytes out, so the
program's event loop moves the bytes. Its first user is
[goose-http](https://github.com/kaitk/goose-http), which serves HTTPS with it from its
`http.tls` module.

Nothing is built yet. The plan is in [tasks](tasks/README.md), and the choices so far
are in [decisions](docs/decisions.md).

## Status

🟢 works · 🟡 partial or next · 🔴 not yet

| | Feature | Notes |
|---|---|---|
| 🟡 | Server TLS 1.3 | A certificate chain and key from PEM files, ALPN chosen by the server. |
| 🔴 | SNI | A certificate per connection, from the server name and the offered ALPN protocols. |
| 🔴 | Certificates swapped while running | New connections get the new certificate; open ones keep theirs. |
| 🔴 | kTLS on Linux | The kernel takes the record layer after the handshake. |
| 🔴 | Client TLS | For an ACME directory, and for databases that ask for TLS. |
| 🔴 | Keys, signatures, and certificates for ACME | An EC P-256 key, ES256 signing, a CSR, and the TLS-ALPN-01 challenge certificate. |

A server built on goose-tls is meant to be its own reverse proxy: one binary that gets
its certificates, terminates TLS, and serves, as well as running behind Caddy or nginx.
ACME itself, which gets and renews the certificates, is a package of its own on top of
goose-tls; the last four rows are what it needs from this one.

## Pins

The Goose release in `scripts/goose.sh` (`v2026.2`). OpenSSL's version and where each
platform gets it are in [development](docs/development.md).
