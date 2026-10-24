# Tasks

Markdown-based task tracking. One file per task, or one folder for a task with
several subtasks or its own supporting files.

## Naming

`NNN-short-slug.md` — zero-padded, sequential number plus a kebab-case slug,
e.g. `001-server-tls.md`.

A task with subtasks or supporting files is a folder with the same name,
`NNN-short-slug/`, holding the task itself as `README.md` and one file per
subtask as `NN-short-slug.md`, numbered within the folder. Subtasks use the same format
as tasks.

## Format

```markdown
# NNN: Title

Status: todo | in-progress | done | cancelled

Short description of what and why.

## Acceptance criteria

- [ ] Concrete, verifiable outcome
- [ ] ...
```

Update the status line as work progresses; tick criteria as they are met. A cancelled task
says when it was cancelled and why. A task that measures something links to the
numbers and their method in `docs/results.md` or `docs/results-history.md`.

## Archive

When a task is done and nothing still builds on its file, move it to `000-archive/` with
`git mv`, keeping its name. The main folder then lists only open work. Numbers stay
unique across both folders: pick the next number after the highest in either. Refer to
tasks by number ("task 001"), not by path, so a move breaks no reference.

Archived tasks describe the implementation at completion. Use the README and
`docs/architecture.md` for current behavior, `docs/decisions.md` for why, and results
for the latest measurements.

## Order

Open: task 007, a TLS 1.3 server in Goose over libcrypto, with session tickets, kTLS
removed, and OpenSSL kept as a build-time alternative. The server and its tickets are
released in `v0.0.4`, which goose-http's pin took, and its overhead cut in `v0.0.5`;
goose-http's client check, the network benchmarks, and a resumption fuzz target remain.

Archived: task 001, server TLS, done, which goose-http's HTTP/1.1 over TLS (its task
014) and HttpArena's TLS profiles (goose-rest's task 047) build on. Task 002, kTLS,
cancelled, its code removed by task 007. Task 003, done: the hooks an outside ACME
package needs (goose-rest's task 049). Task 004, done: a connection's memory BIO
buffers freed once empty (goose-http's task 058), released in `v0.0.4`. Task 005, done:
rustls measured against OpenSSL (spike 01). Task 006, a Rust library over rustls,
cancelled on 2026-10-22: rustls won't be used. Task 008, done: QUIC's handshake and
packet protection for goose-http's HTTP/3 (its task 067), released in `v0.0.6`
(2026-10-24).

