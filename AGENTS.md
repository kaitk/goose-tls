# Agent rules

This file holds what every session needs. `agents/` holds the rules for particular work:
read the file a task touches before starting it.

## Project context

- What this is, its API, and its pin: `README.md`
- The decisions, each dated with its reason and trade-off: `docs/decisions.md`. A new
  decision goes there. `docs/architecture.md`, written with the first code, describes
  how the package works for its users and changes with each decision that changes it
- Toolchain, local setup, and tests: `docs/development.md`
- Goose compiler and stdlib gaps found here: `docs/goose-findings.md`
- Task tracking: `tasks/` (see `tasks/README.md`)
- The protocols: RFC 8446 (TLS 1.3), RFC 7301 (ALPN), RFC 6066 (SNI), RFC 8555 (ACME),
  and RFC 8737 (TLS-ALPN-01).
- The library: OpenSSL 3's manual pages, for the version `docs/development.md` names.
- Its first users: goose-http, from its `http.tls` module (goose-http's task 014), and
  goose-rest's HttpArena entry (goose-rest's task 047).
- The language: the pinned Goose release's `docs/tutorial.md`, `docs/goose_spec.md`,
  `docs/stdlib.md`, and `docs/packages.md` (C sources and libraries in a `.build`
  sidecar). Read the tutorial before writing Goose; check the spec before assuming a
  feature exists.
- Rules for particular work: `agents/goose.md` (writing Goose, and recording what it
  lacks), and `agents/writing.md` (docs, tasks, and prose reviews)

Follow the recorded decisions; if a change contradicts one, update the doc in the same
change or ask first. Record setup facts and environment traps you find (paths, shell
quirks, library versions, where a platform keeps OpenSSL) in `docs/development.md`, not
in agent memory, so the next agent finds them. Docs and commits name no people: date a
decision or a request (`(2026-10-19)`), and describe the setup without anyone's machine,
checkouts, or home directory. What only one machine needs, such as where its Goose
checkout is, goes in `CLAUDE.local.md`, which git ignores. Benchmark results still name
their machine.

## Keep changes small

Agreed 2026-10-20.

- Meet the requirement's intent with the least machinery. Before building around an
  obstacle, ask whether the requirement needs it at all.
- When a fix starts to need a new public API, a change in another repository, or a
  workaround, stop. Say so in a sentence or two, and propose the simpler reading of the
  requirement.
- A feature's cost falls on the programs that use it: no fields in shared structs and no
  code on shared paths for one feature.
- When a design makes other code compensate (a fallback, a rescan, a special case
  elsewhere), change the design rather than add the compensation.
- Add a setting, a check, or a script option only for a failure that isn't visible
  already.

## Working beside other agents

Several agents work in these repositories at once (2026-10-20).

- Work in a worktree of your own, on a branch from `origin/main`:
  `git worktree add ../<repository>-<topic> -b <topic> origin/main`. Remove it once
  the branch is merged.
- Leave alone a branch, a commit, or an uncommitted change that isn't yours, in any
  checkout. Ask if it's in your way.
- Keep logs, exports, and scratch files in a directory of your own.
- Problems with your own sandbox, such as no network or no SSH, go in your report,
  not in the docs.

## Goose

- Build with the official Goose release that `scripts/goose.sh` pins. Check for a newer
  release at the start of a session and move the pin to it. Pin a commit
  (`GOOSE_COMMIT`) only when a fix this repository needs isn't released yet, and return
  to a release once one has it (2026-10-15).
- Don't edit a Goose checkout. Work around a compiler or stdlib gap here, record it in
  `docs/goose-findings.md` as `agents/goose.md` says, and report blockers to the
  maintainer.

## C, and only for the library

This package is where the Goose packages keep TLS's C ([decisions](docs/decisions.md)).

- Cryptographic primitives and X.509 are OpenSSL's: libcrypto's EVP for ciphers,
  hashes, HMAC and HKDF, key exchange, signatures, and random bytes. Don't write them in
  Goose or in the shim.
- The TLS 1.3 server's protocol and record layer are this package's own, written in
  Goose by default (agreed 2026-10-22, pending spike 02; task 007). Until spike 02
  passes and the server lands, connections run on libssl, which also keeps the client,
  PEM loading, and the server alternative selected at build time.
- The C in `shim/` adapts OpenSSL's API to Goose: opaque handles, bytes in and bytes
  out, and error codes. It may also own what Goose can't hold, such as native handles,
  reference counts, and byte buffers that outlive a call, where that is simpler or
  safer than a Goose workaround. Protocol decisions, configuration, certificate
  selection, and ACME's protocol are Goose.
- The package does no I/O of its own on a connection. The program's event loop moves
  the bytes; the shim never touches a socket, so the same code serves epoll, io_uring,
  kqueue, and IOCP.

## Code conventions

- Comment only where the code is hard to follow without it, and say only what a reader
  of that code needs: why, a constraint, or a contract the code can't show. Don't restate
  the next line, and don't describe earlier versions or the task that added the code;
  history belongs in git.
- Edit files with the Edit tool, not with `sed` or a Python or PowerShell script. On
  Windows, line endings differ by file type and a shell adds a layer of escaping, and
  scripted edits break on both.
- Tests follow Goose's own convention: a top-level `test/` by area, each test a small
  program whose printed output a golden file in `test/expected/` checks, `// error:`
  fixtures for code that must not compile, and a runner that batches them with
  `goose --multi-test`. Handshakes are checked against `openssl s_client` and
  `curl`; the Goose server also against RFC 8448's traces, tlsfuzzer, and fuzzing
  (task 007).

## Commits

- One lean sentence in imperative mood, at most 72 characters.
- No body, no `Co-Authored-By` or any other trailers.
- Fetch and rebase before pushing a finished commit to `origin`.
