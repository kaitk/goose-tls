# goose-tls

TLS for [Goose](https://github.com/aardappel/goose): a Goose API over OpenSSL 3.0 or
later, with opaque handles and a connection that takes bytes in and gives bytes out, so
the program's event loop moves the bytes. Its first user is
[goose-http](https://github.com/kaitk/goose-http), which serves HTTPS with it from its
`http.tls` module.

A server built on goose-tls is meant to be its own reverse proxy: one binary that gets
its certificates, terminates TLS, and serves, as well as running behind Caddy or nginx.
ACME itself, which gets and renews the certificates, is a package of its own on top of
goose-tls; the last four rows below are what it needs from this one.

How it works is in [architecture](docs/architecture.md), the choices behind it in
[decisions](docs/decisions.md), and the plan in [tasks](tasks/README.md).

## Status

🟢 works · 🟡 partial or next · 🔴 not yet

| | Feature | Notes |
|---|---|---|
| 🟢 | Server TLS 1.3 | A certificate chain and key from PEM, ALPN chosen by the server. Tested on macOS and Linux against OpenSSL 3.0, 3.6, and 4.0. |
| 🟡 | kTLS on Linux | To be removed (task 007). The kernel takes the record layer after the handshake, for all three suites, with KeyUpdate and close_notify. The keys are tested against RFC 8448 and an OpenSSL client on OpenSSL 3.0, 3.6, and 4.0, and the fallback to user space on macOS and on a Linux kernel without kTLS; not yet run on a kernel that has it. |
| 🟢 | A context per connection | Chosen by the program at the ClientHello, from the SNI name and the offered ALPN protocols: a certificate per name, and TLS-ALPN-01's challenge certificate for `acme-tls/1`. |
| 🟢 | Certificates replaced while running | Accept new connections from a new context; open ones keep theirs. |
| 🟢 | Client TLS 1.3 | Verifies the server's chain against OpenSSL's trust store, or given certificates, and its name. |
| 🟢 | Keys, signatures, and certificates for ACME | An EC P-256 key, ES256 signatures for JWS, a CSR, and the TLS-ALPN-01 challenge certificate, checked against `openssl`. |

## Quick start

A program declares the package in its root file at a tag, and builds with CMake and
OpenSSL's headers and libraries installed ([development](docs/development.md#openssl)):

```goose
import std;
import tls from "github.com/kaitk/goose-tls@v0.0.3";

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

```sh
goose build server.goose
```

The tag `v0.0.3` has everything in the table above.

`test/tools/echo_server.goose` is a whole server, and `test/tools/client.goose` a whole
client, over blocking sockets of their own.

## API

All of it is in `tls.goose`, in the `tls` namespace.

| Function | Does |
|---|---|
| `server(chain, key, protocols) -> Context, bool` | A server context from PEM text: the leaf and any intermediates, its key, and the ALPN protocols in the server's order of preference |
| `server_files(chain_path, key_path, protocols) -> Context, bool` | The same, from PEM files |
| `client(protocols) -> Context, bool` | A client context that trusts OpenSSL's store of certificate authorities |
| `client_trusting(ca, protocols) -> Context, bool` | A client context that trusts only the certificates in `ca`, PEM text |
| `share(ctx) -> Context` | Another reference to the context, for a thread that frees its own |
| `accept(ctx) -> Conn` | A server connection, before its handshake |
| `connect(ctx, host) -> Conn` | A client connection to `host`, which the server's certificate must name |
| `ok(ctx)`, `ok(c)`, `ok(k)` | Whether a context, a connection, or a key was made |
| `free(ctx)`, `free(c)`, `free(k)` | Frees one, once; connections keep their context alive |
| `feed(c, bytes) -> i64` | Takes bytes the socket received: all of them, or `FAILED` |
| `handshake(c) -> i64` | Advances the handshake: 0 once done, or `WANT_INPUT`, `HELLO`, `FAILED` |
| `read(c, buf) -> i64` | Plaintext into `buf`: its length, or `WANT_INPUT`, `CLOSED`, `FAILED` |
| `write(c, data) -> i64` | Encrypts all of `data`: its length, or `WANT_INPUT` before the handshake, `FAILED` |
| `drain(c, buf) -> i64` | Copies bytes to send into `buf`, and returns how many; 0 when none wait |
| `pending(c) -> i64` | How many bytes wait for `drain` |
| `shutdown(c) -> i64` | Queues close_notify for `drain`: 0, or `FAILED` |
| `alpn(c)`, `version(c)`, `cipher(c)`, `group(c)` | The negotiated protocol, version, suite, and key exchange group; "" before the handshake |
| `use_groups(ctx, names) -> bool` | Sets the key exchange groups, such as `"X25519:P-256:P-384"`, before the context's first connection; OpenSSL's default otherwise, X25519MLKEM768 first from 3.5 |
| `peer_certificate(c)` | The peer's certificate as PEM; "" for none |
| `error_text()` | Why the last call on this thread failed, in OpenSSL's words |
| `library()` | The OpenSSL the program runs with |
| `choose_context(ctx) -> bool` | Makes the context's handshakes pause at the ClientHello, with `HELLO` |
| `server_name(c)` | The SNI name the client sent; "" for none |
| `offers(c, protocol) -> bool`, `protocols_offered(c)` | Whether the client offered a protocol in ALPN; the whole list, in its wire format |
| `use_context(c, ctx) -> bool` | Moves a connection paused at `HELLO` to another server context |
| `run() { ... } -> Error[]` | Runs the key and certificate calls below: no error, or the `Error` one left with, OpenSSL's reason in its `message` |
| `key_generate(P256) -> Key`, `key_from_pem(pem) -> Key` | An EC P-256 key, new or from PEM |
| `key_pem(k)`, `public_xy(k)` | The key as PKCS#8 PEM; its public point, x then y, 32 bytes each |
| `sign_es256(k, data)` | An ES256 signature, the 64 bytes `r \|\| s` JWS takes |
| `csr(k, names)` | A certificate signing request for DNS names, as DER |
| `self_signed(k, names, days)` | A self-signed certificate, as PEM |
| `challenge_certificate(k, name, digest)` | TLS-ALPN-01's certificate, whose `acmeIdentifier` extension holds `digest`, the key authorization's SHA-256, as PEM |
| `kernel_supported() -> bool` | Whether this kernel has kTLS; false off Linux |
| `use_kernel(ctx) -> bool` | Makes the context's new connections ready to move to the kernel; false where it has no kTLS |
| `to_kernel(c, fd) -> i64` | Moves a connection to kTLS on its socket: the directions taken, `KERNEL_RX` and `KERNEL_TX` as bits, or `WANT_INPUT`, `PENDING`, `FAILED` |
| `kernel_wants(c) -> i64` | After `WANT_INPUT` from `to_kernel`: how many bytes complete the record |
| `in_kernel(c) -> i64` | The directions the kernel holds |
| `kernel_record(c, fd, type, body) -> i64` | Takes a record the kernel received that isn't data: 0, `UPDATE_TX`, `CLOSED`, or `FAILED` |
| `kernel_update_tx(c, fd) -> i64` | Moves the kernel's sending to the next keys, after a KeyUpdate sent through it |

The statuses are negative, so a count is never mistaken for one: `WANT_INPUT` (feed
more of what the socket gives), `CLOSED` (the peer sent close_notify), and `FAILED`
(drain any alert, close the socket, and free the connection). A context that chooses
per connection adds `HELLO` (read the ClientHello and choose); its steps are in
[architecture](docs/architecture.md#a-context-per-connection). kTLS adds `PENDING`
(read and drain first) and `UPDATE_TX` (send a KeyUpdate); its steps, and the records
a program sends through the kernel (`CLOSE_NOTIFY`, `KEY_UPDATE`), are in
[architecture](docs/architecture.md#ktls-on-linux).

The key and certificate calls have no statuses: one that fails leaves through `return
... from tls::run`, so they run inside `tls::run`, or the program doesn't compile
([architecture](docs/architecture.md#keys-and-certificates)). SHA-256, for the key
authorization's digest, is [goose-hash](https://github.com/kaitk/goose-hash)'s.

A context speaks TLS 1.3 only, with `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
and `TLS_CHACHA20_POLY1305_SHA256`, chosen by the server in that order. It passes
HttpArena's TLS checks: its served certificate, TLS 1.3 with an AEAD suite, ALPN, and no
obsolete protocol or weak cipher.

## Layout

```text
tls.goose            the package: namespace tls, the API over the shim
tls.build            the sidecar: the shim is the CMake target goose_tls
CMakeLists.txt       builds the shim
cmake/openssl.cmake  finds OpenSSL, for the package and the test peer
shim/tls.c           the C: OpenSSL's TLS API as handles, bytes, and status codes
shim/ktls.c          kTLS: the kernel's keys, set on the program's socket
shim/crypto.c        keys, signatures, and certificates for ACME
shim/tls.h           what the three share
test/                the tests by area, each a program with a golden file in
                     test/expected/, and check.goose, what they share
test/certs/          a self-signed RSA-2048 pair for the tests, valid until 2125, and a
                     key that matches no certificate (other.key)
test/hellos/         ClientHellos recorded from openssl s_client 4.0.3, offering TLS 1.2
                     only and TLS 1.3, each with ALPN h2 and http/1.1
test/tools/          the scripts' programs: a server and a client with sockets of their
                     own (net.c), and crypto_files, which writes keys and certificates
test/tools/peer/     a package for the kTLS tests: an OpenSSL client over memory BIOs,
                     and the kernel's TLS 1.3 record layer in user space
scripts/             goose.sh, and the test scripts
docs/                architecture, decisions, development setup, Goose findings
tasks/               task tracking (tasks/README.md)
```

## Pins

| What | Pin | Why |
|---|---|---|
| Goose compiler | `aardappel/goose` release `v2026.3` (`8511ae3`), which the scripts fetch ([setup](docs/development.md#set-up-the-goose-compiler)) | An official release builds the same on every platform; a commit is pinned only for a fix not yet released |
| OpenSSL | 3.0 or later: the system's on Linux, Homebrew's `openssl@3` on macOS ([development](docs/development.md#openssl)) | 3.0 is what HttpArena's base images ship ([decisions](docs/decisions.md)) |

Move the pin in its own commit, with the tests that still hold
([development](docs/development.md#move-the-pin)).
