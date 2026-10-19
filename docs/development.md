# Development

Nothing builds yet. Task 001 adds the shim, the tests, and `scripts/test.sh`, and records
here where each platform gets OpenSSL 3.

## Set up the Goose compiler

The scripts use the Goose release pinned in `scripts/goose.sh` (`v2026.2`, 2026-10-16)
unless told otherwise. The first script that needs the compiler downloads the release's
archive for the platform from
[the releases page](https://github.com/aardappel/goose/releases), checks its SHA-256,
and unpacks it into `build/goose-v2026.2-<platform>/`. Run `scripts/goose.sh` to fetch it
and print the compiler's path.

Use another compiler only when the release can't do the job, such as a Goose fix not
yet released. `GOOSE` names a binary; `GOOSE_COMMIT` names a full 40-hex commit of
`aardappel/goose`, which the scripts clone into `build/goose-<commit>/` and build with
CMake.

The `.build` sidecar needs `exclude = ["build"]`, as goose-http's has: Goose collects a
package's JIT symbol table from every `.goose` file under its root, and the release's
stdlib under `build/` declares the runtime's `extern fn`s.
