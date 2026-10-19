# Goose findings

Gaps, bugs, and surprises in the pinned Goose compiler and stdlib, found while building
this package. Each entry has a minimal program that shows it, the Goose commit it was
found on, the workaround used here, and whether it has been reported upstream.

The entries come in two parts: [bugs](#bugs), where Goose does something wrong or other
than its spec says, then [feature requests](#feature-requests), for what it lacks. Each
part runs from the least work a fix is expected to take to the most, so the cheap fixes
come first. The order is an estimate from reading the compiler. Place a new entry where
its expected work puts it, and delete an entry once the pin has its fix: git keeps it.

## Bugs

### Two builds of a CMake package at once can fail

Found on `v2026.2` (`3ee3871`), 2026-10-19; still in `dcc2747`. Not reported yet.

Two `goose build`s that run at once, for two programs importing the same package with a
`cmake_target`, share the package's CMake build directory under `~/.goose/build/pkg/`,
and one or both can fail:

- From a cold cache, both configure it. Five runs out of five failed on macOS.
- Once it is built, each build still rewrites `goose_linkprobe.c` and
  `goose_symbols.c` there (`src/native.h`), so each recompiles and relinks the probe,
  and one can link the object the other is writing. With Make, on Ubuntu 24.04 in
  Docker, 3 of 40 builds failed, four at a time from a warm cache, with `undefined
  reference to 'main'` or `file not recognized` linking `goose_linkprobe`. On macOS,
  also with Make, `test/run_tests.py`'s parallel builds hadn't failed.

From a cold cache:

```sh
mkdir lib a b
printf 'cmake_minimum_required(VERSION 3.20)\nproject(lib C)\nadd_library(lib_c STATIC one.c)\n' > lib/CMakeLists.txt
echo 'int one(void) { return 1; }' > lib/one.c
echo 'cmake_target = "lib_c";' > lib/lib.build
printf 'namespace lib;\nextern fn one() -> i32;\n' > lib/lib.goose
for d in a b; do
    printf 'import std;\nimport lib from "../lib";\nfn main() { print(lib::one()); }\n' > $d/$d.goose
done
goose build -o a/a a/a.goose & goose build -o b/b b/b.goose; wait
```

```
configuring the package lib with CMake failed (exit 1):
CMake Error at .../CMakeDetermineSystem.cmake:231 (configure_file):
  No such file or directory
```

From a warm cache, build `a` once, then build `a`, `b`, and two more like them at once,
ten times.

Writing the two files only when their contents change, and a lock on the package's
build directory while it builds, would fix it. Workaround: `test/run_tests.py` runs one
`goose build` at a time, and the test programs in parallel.

### A typed library function that can fail breaks every program that imports it

Found on `v2026.2` (`3ee3871`), 2026-10-19. Not reported yet; goose-sqlite records the
`goose check` side of it.

A fully typed function of an imported module that reaches `return ... from run` is
checked as if called with nothing around it, even when no program calls it: `goose
check`, `goose run`, and `goose build` of any program that imports the module fail
with "return from run: no enclosing call of run on this compile-time call path". A
generic function is checked only where it's called, and passes. Expected: a function
no program calls isn't checked against a call path no program has.

```sh
mkdir lib app
printf 'namespace lib;\nfn run<F>() -> i64 { F(); return 0; }\nfn fail() { return 1 from run; }\nfn rejected(x: i64) { if x < 0 { fail(); } }\nfn plain() -> i64 { 7 }\n' > lib/lib.goose
printf 'import std;\nimport lib from "../lib";\nfn main() { print(lib::plain()); }\n' > app/app.goose
goose run app/app.goose      # error: return from run: no enclosing call of run ...
```

Workaround: each function in `tls.goose` that can fail takes an untyped parameter,
such as `key_pem(k)`; `key_generate`, which has nothing else to take, takes the curve,
`key_generate(tls::P256)`.

## Feature requests

### A package's C is linked only when the program calls the package

Found on `v2026.2` (`3ee3871`), 2026-10-19. Not reported yet.

A program that imports a package but calls none of its functions isn't linked with the
package's C, so the program's own `extern fn` naming a function in that C fails to
link. With one call into the package, it links:

```sh
mkdir lib a
printf 'int one(void) { return 1; }\nint two(void) { return 2; }\n' > lib/one.c
echo 'c_sources = ["one.c"];' > lib/lib.build
printf 'namespace lib;\nextern fn one() -> i32;\n' > lib/lib.goose
printf 'import std;\nimport lib from "../lib";\nextern fn two() -> i32;\nfn main() { print(two()); }\n' > a/a.goose
cd a && goose build -o a a.goose      # Undefined symbols: "_two"
```

The tests reach the shim's test-only functions this way (`test/kernel/`). Linking every
imported package's native part, or saying in `docs/packages.md` that only a called
package is linked, would do. Workaround: `test/kernel/derive.goose`, which calls only
test-only functions, also calls `tls::library()`.

### A sidecar can't name a library directory

Found on `v2026.2` (`3ee3871`), 2026-10-19. Not reported yet.

A sidecar's `c_libs` becomes `-l<name>`, and `c_include` takes absolute paths, but no
key adds a library search path (`-L`, or `/LIBPATH` for MSVC), and `c_flags_cc` reaches
only the compile. A library outside the C compiler's own paths, such as Homebrew's
OpenSSL under `/opt/homebrew/opt/openssl@3/lib`, can't be linked through `c_sources`
and `c_libs`:

```goose
// tls.build
c_sources = ["shim/tls.c"];
c_include_macos = ["/opt/homebrew/opt/openssl@3/include"];  // compiles
c_libs = ["ssl", "crypto"];       // ld: library 'ssl' not found, on macOS
```

A `c_libdirs` key with platform suffixes, as `c_include` has, or `pkg-config` names,
would do. Workaround: the shim is a CMake target, and `find_package(OpenSSL)` finds the
library ([decisions](decisions.md)), at the cost of CMake as a build dependency.
