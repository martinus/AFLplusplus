#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Test for the map summary (AFL_LLVM_MAP_SUMMARY, see docs/env_variables.md).
#
# 1. A target with summary marks has the same coverage as a target without.
# 2. afl-fuzz uses the summary of such a target, and the summary is correct:
#    AFL_MAP_SUMMARY_VERIFY=1 compares it with the full map before each run.
# 3. afl-fuzz also keeps a correct summary for a target without marks.
# 4. If one module of the target has no marks, the target does not tell
#    afl-fuzz to trust the summary.
# 5. A target with marks starts a helper program without marks. The helper
#    tells afl-fuzz not to trust the marks, and afl-fuzz sees its coverage.
# 6. A target with marks loads a library without marks after the forkserver
#    is up. This must not stop the target.
# 7. As 5, but the helper does not know the summary (as a helper from an
#    older afl-cc). The audit of afl-fuzz finds the counters without marks.

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

# The fuzz target. It calls one of the functions:
# - directly (default),
# - in a helper program that it starts for each input (HELPER), or
# - in a library that it loads in the first run (PLUGIN).
# In all cases it links funcs.c, so its map is not smaller than the map of the
# helper program or the library.
cat > "$TEMP_DIR/main.c" << 'EOF'
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
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

#if defined(HELPER)
    char  arg[3] = {(char)(buf[0] | 1), (char)(buf[1] | 1), 0};
    pid_t pid = fork();
    if (!pid) {

  #ifdef HELPER_NO_SUMMARY
      unsetenv("AFL_MAP_SUMMARY_SHM");
  #endif
      execl(HELPER, HELPER, arg, (char *)NULL);
      _exit(1);

    }

    waitpid(pid, NULL, 0);
    if (!funcs[0]) abort();                        /* keep funcs.c linked */
#elif defined(PLUGIN)
    static void (*call)(int, int);
    if (!call) {

      void *lib = dlopen(PLUGIN, RTLD_NOW);
      if (!lib) abort();
      call = (void (*)(int, int))dlsym(lib, "call");
      if (!call) abort();

    }

    call(buf[0], buf[1]);
    if (!funcs[0]) abort();                        /* keep funcs.c linked */
#else
    funcs[buf[0] & 15](buf[1]);
#endif

  }

  return 0;

}
EOF

# The helper program and the library. They have less code than main.c.
cat > "$TEMP_DIR/helper.c" << 'EOF'
extern void (*const funcs[16])(int);

void call(int a, int b) {

  funcs[a & 15](b);

}

#ifndef LIBRARY
int main(int argc, char **argv) {

  if (argc > 1 && argv[1][0] && argv[1][1]) call(argv[1][0], argv[1][1]);
  return 0;

}

#endif
EOF

# compile <marks: 0 or 1> <afl-clang-fast arguments>
# AFL_LLVM_MAP_SUMMARY counts as set with any value, so "0" must unset it.
compile() {

  local marks=$1
  shift
  (
    if [ "$marks" = 1 ]; then
      export AFL_LLVM_MAP_SUMMARY=1
    else
      unset AFL_LLVM_MAP_SUMMARY
    fi
    AFL_QUIET=1 AFL_LLVM_INSTRUMENT=PCGUARD AFL_DONT_OPTIMIZE=1 \
      "$AFL_DIR/afl-clang-fast" -O0 "$@"
  )

}

# build_target <name> <marks in funcs.c> <marks in main.c> [more arguments]
build_target() {

  local name=$1 funcs=$2 main=$3
  shift 3
  compile "$funcs" -c -o "$TEMP_DIR/funcs-$name.o" "$TEMP_DIR/funcs.c" &&
    compile "$main" "$@" -o "$TEMP_DIR/$name" "$TEMP_DIR/main.c" \
      "$TEMP_DIR/funcs-$name.o"

}

unset AFL_LLVM_MAP_SUMMARY AFL_NO_MAP_SUMMARY AFL_MAP_SUMMARY_VERIFY
unset AFL_LLVM_THREADSAFE_INST

H="$TEMP_DIR/helper-program"
L="$TEMP_DIR/late-library.so"

if ! build_target plain 0 0 || ! build_target marks 1 1 ||
   ! build_target mixed 0 1 ||
   ! AFL_LLVM_THREADSAFE_INST=1 build_target marks-threadsafe 1 1 ||
   ! compile 0 -o "$H" "$TEMP_DIR/helper.c" "$TEMP_DIR/funcs-plain.o" ||
   ! compile 0 -fPIC -shared -DLIBRARY -o "$L" "$TEMP_DIR/helper.c" \
       "$TEMP_DIR/funcs.c" ||
   ! build_target helper 1 1 -DHELPER="\"$H\"" ||
   ! build_target helper-unknown 1 1 -DHELPER="\"$H\"" -DHELPER_NO_SUMMARY ||
   ! build_target library 1 1 -DPLUGIN="\"$L\"" -ldl; then

  echo "FAIL: afl-clang-fast could not build the test targets"
  exit 1

fi

# 1. The same coverage with and without marks.
for input in "A1" "Bz" "Pq" "0000"; do

  for t in plain marks; do

    if ! printf '%s' "$input" | "$AFL_DIR/afl-showmap" -q -o \
         "$TEMP_DIR/map-$t" -- "$TEMP_DIR/$t" > /dev/null 2>&1; then

      echo "FAIL: afl-showmap failed for target '$t'"
      exit 1

    fi

  done

  if ! cmp -s "$TEMP_DIR/map-plain" "$TEMP_DIR/map-marks"; then

    echo "FAIL: input '$input' gives different coverage with summary marks"
    exit 1

  fi

  if ! [ -s "$TEMP_DIR/map-marks" ]; then

    echo "FAIL: no coverage for input '$input', the test is not valid"
    exit 1

  fi

done

# The inputs in "in" are one step away from the abort() and from the endless
# loop in main.c, so afl-fuzz also handles crashes and timeouts. The input in
# "in-safe" is not.
mkdir "$TEMP_DIR/in" "$TEMP_DIR/in-safe"
printf 'A1' > "$TEMP_DIR/in/a"
printf 'CRASI_' > "$TEMP_DIR/in/b"
printf 'HANF_' > "$TEMP_DIR/in/c"
printf 'A1' > "$TEMP_DIR/in-safe/a"

# stat <target> <name of a value in fuzzer_stats>
stat() {

  sed -n "s/^$2 *: *//p" "$TEMP_DIR/out-$1/default/fuzzer_stats" 2> /dev/null

}

# fuzz <target> [input directory]
# Runs afl-fuzz for some seconds. The test fails if afl-fuzz fails or finds
# too few edges, and with the directory "in-safe" also if the target crashes.
# The output goes to $TEMP_DIR/log-<target>. With AFL_MAP_SUMMARY_VERIFY=1
# from the caller, afl-fuzz stops at the first counter that the summary does
# not cover.
fuzz() {

  local in=${2:-in}

  if ! AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 \
       AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
       "$AFL_DIR/afl-fuzz" -V 6 -t 500 -i "$TEMP_DIR/$in" \
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

  if [ "$in" = in-safe -a "$(stat "$1" saved_crashes)" != 0 ]; then

    echo "FAIL: target '$1' crashed"
    exit 1

  fi

}

# expect <target> <yes or no> <text> <message>
# The test fails if the log of afl-fuzz has / does not have the text.
expect() {

  local found=no
  grep -q "$3" "$TEMP_DIR/log-$1" && found=yes

  if [ "$found" != "$2" ]; then

    echo "FAIL: target '$1': $4"
    exit 1

  fi

}

TRUSTED="Target marks the map summary"
REVOKED="does not mark the map summary"
AUDIT="without a mark in the map summary"

export AFL_MAP_SUMMARY_VERIFY=1

# 2. Targets with marks tell afl-fuzz to use their summary.
for t in marks marks-threadsafe; do

  fuzz $t
  expect $t yes "$TRUSTED" "afl-fuzz does not use the summary"

done

# 3. and 4. These targets must not do that.
for t in plain mixed; do

  fuzz $t
  expect $t no "$TRUSTED" "afl-fuzz trusts a summary that is not complete"

done

# 5. The helper program has no marks, but its runtime knows the summary.
fuzz helper
expect helper yes "$REVOKED" "the helper program did not revoke the summary"

# 6. A library without marks that is loaded late. AFL_IGNORE_PROBLEMS lets the
#    runtime accept such a library.
AFL_IGNORE_PROBLEMS=1 fuzz library in-safe
expect library yes "$REVOKED" "the library did not revoke the summary"

# 7. Only the audit can find the counters of this helper program. The verify
#    check must be off, because it would stop afl-fuzz first.
unset AFL_MAP_SUMMARY_VERIFY
fuzz helper-unknown
expect helper-unknown yes "$AUDIT" "the audit did not find the counters"

echo "OK: map summary (edges: marks $(stat marks edges_found)," \
  "plain $(stat plain edges_found), mixed $(stat mixed edges_found)," \
  "helper $(stat helper edges_found), library $(stat library edges_found)," \
  "audit $(stat helper-unknown edges_found))"
exit 0
