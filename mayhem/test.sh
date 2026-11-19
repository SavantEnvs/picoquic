#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's own assertion suites (picoquic_ct, picohttp_ct), built by build.sh with normal flags, run the
# way upstream CI runs them (`-S <src> -n -r`, no test list): every registered test, none excluded, since
# all of them pass in this image (746 + 170, ~25s). The tests check known-answer values internally: frame
# encode/decode round trips, header and transport-parameter parsing, packet protection vectors, simulated
# handshakes and transfers (single and multipath) that compare the received bytes, retry, stateless reset,
# version negotiation, sockloop, HTTP/3, QPACK and WebTransport.
# A suite of fewer tests than this is a gutted test table, not a pass (upstream only ever adds tests).
QUIC_MIN=700
HTTP_MIN=150

passed=0
failed=0
work=$(mktemp -d)
cd "$work"

# run_suite <runner> <minimum test count>
run_suite() {
  local runner="$1" min="$2"
  local out ok started tried fails summary
  if [ ! -x "$runner" ]; then
    echo "missing test runner $runner (mayhem/build.sh builds it)" >&2
    failed=$(( failed + min ))
    return
  fi
  out=$("$runner" -S "$SRC" -n -r 2>&1)
  printf '%s\n' "$out" | tail -n 3
  ok=$(printf '%s\n' "$out" | grep -c '^    Success\.')
  started=$(printf '%s\n' "$out" | grep -c '^Starting test number ')
  # picoquic prints "N fails." for 0 or 1 failure and "N fail." for more (its plural is inverted).
  summary=$(printf '%s\n' "$out" | grep -E '^Tried [0-9]+ tests, [0-9]+ fails?\.$' | tail -n 1)
  tried=$(printf '%s\n' "$summary" | sed -nE 's/^Tried ([0-9]+) tests, ([0-9]+) fails?\.$/\1/p')
  fails=$(printf '%s\n' "$summary" | sed -nE 's/^Tried ([0-9]+) tests, ([0-9]+) fails?\.$/\2/p')
  if [ -z "$tried" ] || [ -z "$fails" ] || [ "$tried" -lt "$min" ] || [ "$started" -lt "$tried" ]; then
    # no (or a short) summary: the runner did not do its job, so none of its tests count as passed
    echo "$runner: bad summary '${summary}' (started $started, need >= $min tests)" >&2
    if [ "${tried:-0}" -gt "$min" ]; then failed=$(( failed + tried )); else failed=$(( failed + min )); fi
    return
  fi
  # a pass needs both the runner's own verdict and a printed Success line per test
  [ "$ok" -le $(( tried - fails )) ] || ok=$(( tried - fails ))
  passed=$(( passed + ok ))
  failed=$(( failed + tried - ok ))
}

run_suite "$SRC/build/tests/picoquic_ct" "$QUIC_MIN"
run_suite "$SRC/build/tests/picohttp_ct" "$HTTP_MIN"
cd "$SRC"
rm -rf "$work"

emit_ctrf "picoquic_ct+picohttp_ct" "$passed" "$failed" 0
