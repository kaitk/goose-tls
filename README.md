# goose-tls

TLS for [Goose](https://github.com/aardappel/goose): a Goose API over OpenSSL 3.0 or
later, with opaque handles and a connection that takes bytes in and gives bytes out, so
the program's event loop moves the bytes. Its first user is
[goose-http](https://github.com/kaitk/goose-http), which serves HTTPS with it from its
`http.tls` module.

How it works is in [architecture](docs/architecture.md), the choices behind it in
[decisions](docs/decisions.md), and the plan in [tasks](tasks/README.md).

## Status

🟢 works · 🟡 partial or next · 🔴 not yet

| | Feature | Notes |
|---|---|---|
| 🟢 | Server TLS 1.3 | A certificate chain and key from PEM, ALPN chosen by the server. Tested on macOS and Linux against OpenSSL 3.0, 3.6, and 4.0. |
| 🔴 | SNI | A certificate per connection, from the server name and the offered ALPN protocols. |
| 🟡 | Certificates swapped while running | Accept new connections from a new context; open ones keep theirs. Not yet tested under load. |
| 🔴 | kTLS on Linux | The kernel takes the record layer after the handshake. |
| 🔴 | Client TLS | For an ACME directory, and for databases that ask for TLS. |
| 🔴 | Keys, signatures, and certificates for ACME | An EC P-256 key, ES256 signing, a CSR, and the TLS-ALPN-01 challenge certificate. |

A server built on goose-tls is meant to be its own reverse proxy: one binary that gets
its certificates, terminates TLS, and serves, as well as running behind Caddy or nginx.
ACME itself, which gets and renews the certificates, is a package of its own on top of
goose-tls; the last four rows are what it needs from this one.

## Quick start

A program declares the package in its root file, here from a checkout beside it, and
builds with CMake and OpenSSL's headers and libraries installed
([development](docs/development.md#openssl)):

```goose
import std;
import tls from "../goose-tls";

fn main() {
    let ctx, ok = tls::server_files("server.crt", "server.key", ["h2", "http/1.1"]);
    guard ok else { print("no context: ", tls::error_text()); exit(1); }
    // For each accepted socket: a connection, fed what the socket receives.
    let c = tls::accept(ctx);
    var buf: u8[16384] = [0; 16384];
    let n = recv_from_socket(buf);       // the program's own I/O
    tls::feed(c, buf[..n]);
    let r = tls::read(c, buf);           // plaintext, or a status
    if r > 0 { tls::write(c, buf[..r]); }
    var out: u8[16384] = [0; 16384];
    loop {
        let m = tls::drain(c, out);      // what to send back
        guard m > 0 else { break; }
        send_to_socket(out[..m]);
    }
    tls::free(c);
}
```

`test/tools/echo_server.goose` is a whole server, over blocking sockets of its own.

## API

All of it is in `tls.goose`, in the `tls` namespace.

| Function | Does |
|---|---|
| `server(chain, key, protocols) -> Context, bool` | A server context from PEM text: the leaf and any intermediates, its key, and the ALPN protocols in the server's order of preference |
| `server_files(chain_path, key_path, protocols) -> Context, bool` | The same, from PEM files |
| `accept(ctx) -> Conn` | A server connection, before its handshake |
| `ok(ctx)`, `ok(c)` | Whether a context or a connection was made |
| `free(ctx)`, `free(c)` | Frees one, once; connections keep their context alive |
| `feed(c, bytes) -> i64` | Takes bytes the socket received: all of them, or `FAILED` |
| `handshake(c) -> i64` | Advances the handshake: 0 once done, or `WANT_INPUT`, `FAILED` |
| `read(c, buf) -> i64` | Plaintext into `buf`: its length, or `WANT_INPUT`, `CLOSED`, `FAILED` |
| `write(c, data) -> i64` | Encrypts all of `data`: its length, or `WANT_INPUT` before the handshake, `FAILED` |
| `drain(c, buf) -> i64` | Copies bytes to send into `buf`, and returns how many; 0 when none wait |
| `pending(c) -> i64` | How many bytes wait for `drain` |
| `shutdown(c) -> i64` | Queues close_notify for `drain`: 0, or `FAILED` |
| `alpn(c)`, `version(c)`, `cipher(c)` | The negotiated protocol, version, and suite; "" before the handshake |
| `error_text()` | Why the last call on this thread failed, in OpenSSL's words |
| `library()` | The OpenSSL the program runs with |

The statuses are negative, so a count is never mistaken for one: `WANT_INPUT` (feed
more of what the socket gives), `CLOSED` (the peer sent close_notify), and `FAILED`
(drain any alert, close the socket, and free the connection).

A context speaks TLS 1.3 only, with `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
and `TLS_CHACHA20_POLY1305_SHA256`, chosen by the server in that order. It passes
HttpArena's TLS checks: its served certificate, TLS 1.3 with an AEAD suite, ALPN, and no
obsolete protocol or weak cipher.

## Pins

The Goose release in `scripts/goose.sh` (`v2026.2`). OpenSSL's version and where each
platform gets it are in [development](docs/development.md).
