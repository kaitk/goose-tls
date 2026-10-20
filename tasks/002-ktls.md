# 002: kTLS on Linux

Status: in-progress (the package's side is built, 2026-10-19, and passes on a kernel
with kTLS, 2026-10-20; goose-http's loops and the measurements are open)

After the handshake, the kernel takes the record layer, so the program sends and
receives plaintext on the socket, and `sendfile`, splice, and io_uring work again.
HttpArena's 8gbit profile scores CPU per request over TLS at a pinned rate, so the
record layer's cost counts there directly (goose-rest's task 047; goose-http's task 014,
phase 3).

## Design

Recorded in [decisions](../docs/decisions.md) (2026-10-19) and described for users in
[architecture](../docs/architecture.md#ktls-on-linux):

- **Who touches the socket.** The shim sets `TCP_ULP` "tls" and
  `setsockopt(SOL_TLS, TLS_RX/TLS_TX)` on the program's descriptor and never reads or
  writes it, an amendment to "No I/O in the package". OpenSSL has no public call, 3.0 to
  4.x, that starts kTLS on an existing connection or exports the kernel's keys; its own
  kTLS needs a socket BIO from the start, which was rejected.
- **The keys.** The traffic secrets come from the keylog callback, the record sequence
  numbers from counting the message callback's `SSL3_RT_HEADER` reports since each
  direction's keys changed, and key, IV, and salt from HKDF-Expand-Label through
  `EVP_KDF`. For AES-GCM the kernel takes TLS 1.3's 12-byte IV as a 4-byte salt and an
  8-byte IV; for ChaCha20-Poly1305 the whole 12 bytes as its IV, with no salt. All three
  suites map to kernel ciphers; a kernel that refuses one leaves the connection in user
  space.
- **The switch.** Only at a record boundary of the bytes fed (`WANT_INPUT` and
  `kernel_wants` otherwise), and only once OpenSSL holds no unread plaintext and no
  unsent bytes (`PENDING`), so the request that arrived with the client's Finished and
  the session tickets are handled first. Receiving moves first, then sending.
- **After it.** `kernel_record` takes the records the kernel passes up that aren't data:
  close_notify, other alerts, and a KeyUpdate, whose next receive keys it installs. It
  answers a request for a KeyUpdate back through OpenSSL when sending stayed in user
  space, or returns `UPDATE_TX` for the program to send `KEY_UPDATE` and call
  `kernel_update_tx`. Changing keys needs Linux 6.14; before it, a KeyUpdate fails the
  connection.
- **io_uring.** `SEND`, `RECV`, multishot receive, and splice carry plaintext; a
  non-data record ends a `RECV` with `-EIO` and is fetched with `RECVMSG` or `recvmsg`;
  control records go out with `SENDMSG`. `SEND_ZC` doesn't work on a kTLS socket.
- **Off Linux**, `use_kernel` returns false and `to_kernel` 0.

## What goose-http's loops will need

- epoll: after the handshake, `tls::to_kernel`; then `recv` and `send` plaintext,
  `recvmsg` with a control buffer on `EIO`, and `sendmsg` with `TLS_SET_RECORD_TYPE`
  for close_notify and a KeyUpdate. `sendfile` works for static files.
- io_uring: on `-EIO` from the multishot receive, fetch the record, call
  `tls::kernel_record`, and rearm; on `-EKEYEXPIRED`, rearm after the KeyUpdate is
  handled; order the KeyUpdate's `SENDMSG` after the socket's earlier sends, and call
  `tls::kernel_update_tx` before the next send.
- Both: a receive of exactly `tls::kernel_wants(c)` bytes while the switch waits for a
  record's end, and a send of everything drained before the switch.

## Next: a kernel with kTLS

Asked for 2026-10-19: check whether the Linux benchmark desktop's kernel (WSL2) has
kTLS, and if it does, run the open kernel criteria there. On that machine:

1. `uname -r`, and `zcat /proc/config.gz | grep CONFIG_TLS` (WSL2 kernels publish
   their configuration there). `CONFIG_TLS=y` or `=m` is needed; with `=m`, run
   `sudo modprobe tls` and check that `/proc/net/tls_stat` exists.
2. With kTLS, `scripts/test.sh`. `scripts/test-handshake.sh` then runs the kTLS echo
   and curl, and from Linux 6.14 the KeyUpdates. Record the kernel, the OpenSSL, and the
   result in the criteria below and in `docs/development.md`.
3. Without it, record the kernel and its `CONFIG_TLS` line here, and find another
   machine: a Linux VM or a cloud instance on 6.14 or later.

### On the desktop (2026-10-20)

The kernel has kTLS as a module: Ryzen 7 5800X3D, Ubuntu 26.04.1 LTS under WSL2,
kernel `6.18.54.1-microsoft-standard-WSL2` with `CONFIG_TLS=m` (`# CONFIG_TLS_DEVICE
is not set`). After `sudo modprobe tls`, `/proc/net/tls_stat` exists and
`tcp_available_ulp` lists `tls`. `scripts/test.sh` at `1200d82`, Goose `v2026.2`,
OpenSSL 3.5.5: every step passes. `scripts/test-handshake.sh` runs the kTLS part for the
first time on a kernel that has it ("server: kernel tls: yes"):

- s_client's two KeyUpdates, and every line echoed after them, both in user space and
  over kTLS
- over kTLS: the close with close_notify, both KeyUpdates through `kernel_record`, and
  both directions taken by the kernel
- curl `--http1.1` POST over kTLS gets its body back, and its connection went to the
  kernel

The shim's `setsockopt` calls, the keys, and the test server's `recvmsg` and `sendmsg`
now run on a kernel, not only compile.

## Acceptance criteria

- [x] goose-tls reports, per connection, whether the kernel took each direction
      (`to_kernel`, `in_kernel`)
- [x] The kernel's keys checked without a kernel: against RFC 8448's traces, and for all
      three suites against an OpenSSL client, across KeyUpdates before and after the
      switch, on OpenSSL 3.0.13 (Ubuntu 24.04), 3.6.5, and 4.0.3 (`test/kernel/`)
- [x] Off Linux, and on a Linux kernel without kTLS, connections stay in user space
      (`scripts/test-handshake.sh`)
- [x] A kTLS echo against `openssl s_client` and `curl` on a kernel with the `tls`
      module, with a KeyUpdate each way from s_client and a close
      (`scripts/test-handshake.sh`, 2026-10-20, "On the desktop" below)
- [ ] User-space TLS and kTLS compared on the echo on Linux, with how they were
      measured
- [ ] goose-http serves HTTP/1.1 over kTLS on epoll and io_uring: on epoll since
      2026-10-20 (goose-http `9a6b652b`, its task 014.02); io_uring remains
- [x] User-space TLS and kTLS compared through goose-http on Linux, with how they were
      measured (goose-http's task 014.02, item 3, 2026-10-20: even on `/json`, kTLS
      at half the rate on 16 KB responses, where the kernel's AES-GCM costs more)
- [x] `scripts/test.sh` passes on macOS and in the Linux container, with a test that a
      KeyUpdate doesn't break a kTLS connection (`test/kernel/switch.goose`)
