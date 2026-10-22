/* libFuzzer's entry points for fuzz.goose's targets: one binary per target,
   chosen by TARGET when build.sh compiles it. */
#include <stddef.h>
#include <stdint.h>

#include "fuzz.h"

#ifndef TARGET
#error "build.sh names the target: -DTARGET=fuzz_hello, fuzz_conn, or fuzz_open"
#endif

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    goose_init(*argc, *argv);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    sl_u8 bytes = { (uint8_t *)data, (int64_t)size };
    TARGET(bytes);
    return 0;
}
