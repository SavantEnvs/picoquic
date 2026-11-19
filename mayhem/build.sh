#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

PTLS=$(echo /opt/toolchains/deps/picotls-*)
[ -d "$PTLS/lib" ] || { echo "picotls dependency missing under /opt/toolchains/deps" >&2; exit 1; }
PTLS_OPTS=(-DWITH_OPENSSL=ON -DPTLS_PREFIX="$PTLS" -DPTLS_INCLUDE_DIR="$PTLS/include"
           -DBUILD_DEMO=OFF -DBUILD_HTTP=ON -DBUILD_LOGLIB=ON -DBUILD_LOGREADER=OFF -DBUILD_PICO_SIM=OFF -DBUILD_PQBENCH=OFF)

# No CMAKE_BUILD_TYPE: upstream adds -O3 itself, and Release would only add -DNDEBUG and hide its asserts.
# No CMAKE_C_COMPILER either: CMake takes $CC/$CXX from the environment, so a re-run keeps its cache.
# 1) Tests first: the project's NORMAL flags, in build/tests (gitignored by upstream's /build/).
cmake -S . -B build/tests -G Ninja \
      -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
      -Dpicoquic_BUILD_TESTS=ON "${PTLS_OPTS[@]}"
cmake --build build/tests -j"$MAYHEM_JOBS" --target picoquic_ct picohttp_ct

# 2) The library under test, sanitized, with DWARF 3, in build/fuzz.
cmake -S . -B build/fuzz -G Ninja \
      -DCMAKE_C_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS" -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS" \
      -Dpicoquic_BUILD_TESTS=OFF "${PTLS_OPTS[@]}"
cmake --build build/fuzz -j"$MAYHEM_JOBS" --target picoquic-core picohttp-core

# 3) Harnesses: fuzzer binary and standalone reproducer each, with LSan switched off at build time.
INCS=(-I"$SRC/picoquic" -I"$SRC/picohttp" -I"$SRC/mayhem/harnesses" -I"$PTLS/include")
LIBS=(build/fuzz/libpicohttp-core.a build/fuzz/libpicoquic-core.a
      "$PTLS/lib/libpicotls-openssl.a" "$PTLS/lib/libpicotls-minicrypto.a" "$PTLS/lib/libpicotls-core.a"
      -lssl -lcrypto -lpthread -lm)
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build/fuzz/lsan_off.o
for h in mayhem/harnesses/fuzz_*.c; do
  name=$(basename "$h" .c)
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 "${INCS[@]}" "$h" build/fuzz/lsan_off.o "${LIBS[@]}" $LIB_FUZZING_ENGINE -o "/mayhem/$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 "${INCS[@]}" "$h" "$STANDALONE_FUZZ_MAIN" build/fuzz/lsan_off.o "${LIBS[@]}" -o "/mayhem/$name-standalone"
done
