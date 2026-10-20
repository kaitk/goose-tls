# 004: A connection's memory

Status: in-progress (the change is on `main`, 2026-10-20; a release is open)

goose-http's TLS server used 272 MiB on HttpArena's json-tls at 4,096 connections,
the most of the entries measured, against 152-188 MiB for the Rust ones (goose-http's
task 058). Its measurement, by OpenSSL's allocation sites, put the memory in OpenSSL
and in this package's memory BIOs, whose buffers kept the size of the largest response
for as long as a connection lived. The shim now frees each BIO's buffer once it's
empty ([decisions](../docs/decisions.md)). The numbers, and how they were measured,
are in goose-http's task 058.

## Acceptance criteria

- [x] Each memory BIO's buffer freed once it's empty, with no cost in json-tls's rate
      beyond the runs' spread (goose-http's task 058, 2026-10-20)
- [x] `scripts/test.sh` passes on Linux, the kTLS steps included (Ubuntu 26.04 in
      WSL2, OpenSSL 3.5.5, 2026-10-20)
- [ ] A release with the change, which goose-http's pin then moves to
