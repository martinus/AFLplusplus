#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Test for the map summary of afl-fuzz (see AFL_NO_MAP_SUMMARY in
# docs/env_variables.md).
#
# afl-fuzz marks the chunks of the map that are not 0 and clears only these
# chunks before the next run. AFL_MAP_SUMMARY_VERIFY=1 compares the summary
# with the full map before each run, so afl-fuzz stops if the summary is
# wrong.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

if ! [ -x "$AFL_DIR/afl-clang-fast" -a -x "$AFL_DIR/afl-showmap" -a \
       -x "$AFL_DIR/afl-fuzz" ]; then

  echo "SKIP: afl-clang-fast, afl-showmap or afl-fuzz not built"
  exit 0

fi

case "$(uname -s)" in
  Linux | Darwin) ;;
  *)
    echo "SKIP: the map summary needs Linux or macOS"
    exit 0
    ;;
esac

# 16 functions with 1024 branches each give about 32000 edges, so the map has
# many chunks. The volatile operand stops the compiler from merging them.
cat > "$TEMP_DIR/funcs.c" << 'EOF'
volatile int sink;

#define B1 if (x == sink) sink++;
#define B4 B1 B1 B1 B1
#define B16 B4 B4 B4 B4
#define B64 B16 B16 B16 B16
#define B256 B64 B64 B64 B64
#define B1K B256 B256 B256 B256

#define F(n) void n(int x) { B1K }
#define F4(p) F(p##0) F(p##1) F(p##2) F(p##3)

F4(f0) F4(f1) F4(f2) F4(f3)

void (*const funcs[16])(int) = {f00, f01, f02, f03, f10, f11, f12, f13,
                                f20, f21, f22, f23, f30, f31, f32, f33};
EOF

# The fuzz target. It calls one of the functions.
cat > "$TEMP_DIR/main.c" << 'EOF'
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern void (*const funcs[16])(int);

__AFL_FUZZ_INIT();

int main(void) {

  __AFL_INIT();
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(1000)) {

    int len = __AFL_FUZZ_TESTCASE_LEN;
    if (len < 2) continue;
    if (len > 5 && !memcmp(buf, "CRASH", 5)) abort();
    if (len > 4 && !memcmp(buf, "HANG", 4)) for (;;) usleep(1000);

    funcs[buf[0] & 15](buf[1]);

  }

  return 0;

}
EOF

if ! AFL_QUIET=1 AFL_LLVM_INSTRUMENT=PCGUARD AFL_DONT_OPTIMIZE=1 \
     "$AFL_DIR/afl-clang-fast" -O0 -o "$TEMP_DIR/plain" "$TEMP_DIR/main.c" \
     "$TEMP_DIR/funcs.c"; then

  echo "FAIL: afl-clang-fast could not build the test target"
  exit 1

fi

# The inputs are one step away from the abort() and from the endless loop in
# main.c, so afl-fuzz also handles crashes and timeouts.
mkdir "$TEMP_DIR/in"
printf 'A1' > "$TEMP_DIR/in/a"
printf 'CRASI_' > "$TEMP_DIR/in/b"
printf 'HANF_' > "$TEMP_DIR/in/c"

# stat <target> <name of a value in fuzzer_stats>
stat() {

  sed -n "s/^$2 *: *//p" "$TEMP_DIR/out-$1/default/fuzzer_stats" 2> /dev/null

}

# fuzz <target>
# Runs afl-fuzz for some seconds. The test fails if afl-fuzz fails or finds
# too few edges. The output goes to $TEMP_DIR/log-<target>.
fuzz() {

  if ! AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 \
       AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
       "$AFL_DIR/afl-fuzz" -V 6 -t 500 -i "$TEMP_DIR/in" \
       -o "$TEMP_DIR/out-$1" -- "$TEMP_DIR/$1" > "$TEMP_DIR/log-$1" 2>&1; then

    tail -20 "$TEMP_DIR/log-$1"
    echo "FAIL: afl-fuzz failed for target '$1' (wrong map summary?)"
    exit 1

  fi

  local edges
  edges=$(stat "$1" edges_found)
  if ! [ "$edges" -gt 100 ] 2> /dev/null; then

    echo "FAIL: afl-fuzz found only '$edges' edges for target '$1'"
    exit 1

  fi

}

AFL_MAP_SUMMARY_VERIFY=1 fuzz plain

echo "OK: map summary (edges: $(stat plain edges_found))"
exit 0
