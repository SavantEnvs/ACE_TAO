#!/usr/bin/env bash
#
# mayhem/build.sh — build the ACE fuzz harnesses and the ACE functional tests.
#
#  1) ACE, ACE_ETCL(_Parser), ACEXML(_Parser), ACE_INet and ASNMP as static libraries with
#     upstream's own build (MPC -> GNU make), instrumented with $SANITIZER_FLAGS + SanCov +
#     $DEBUG_FLAGS, in the source tree (ACE/lib, ACE/**/.obj — all gitignored upstream).
#  2) each harness in mayhem/harnesses twice: libFuzzer binary + -standalone reproducer, in /mayhem.
#  3) a separate, uninstrumented copy of ACE (mayhem/build-tests, gitignored) with normal flags,
#     plus a selection of upstream's ACE/tests programs that mayhem/test.sh runs.
#
# MPC (upstream's build tool, not in this repo) is pinned in the image at $MPC_ROOT.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${MPC_ROOT:=/opt/toolchains/deps/MPC-61b5e0a9/src}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS MPC_ROOT
cd "$SRC"

# SanCov on the library too (not only the harness), so coverage reflects the ACE code.
LIB_COV_FLAGS=""
# UBSan nonnull-attribute is relaxed for the whole build (a deliberate, recorded decision). With it
# on, it reports at two sites:
#  - ACE_OS::memcpy (ACE/ace/OS_NS_string.inl:32) called by ACE_Data_Block::size
#    (ACE/ace/Message_Block.cpp:224) with base_ = NULL and cur_size_ = 0: a benign 0-byte copy
#    from an empty block (via ACE_CDR::consolidate <- ACE_InputCDR::reset). It fires on most
#    tao-cdr and tao-ior inputs (e.g. tao-ior seeds ior_1/3/4/short), so the targets could not fuzz.
#  - ACEXML_Parser::parse_processing_instruction (ACEXML/parser/parser/Parser.cpp:2834) passing a
#    NULL parse_name() to ACE_OS::strcasecmp: a real defect, and ASan's strcasecmp interceptor
#    still reports it (acexml), so relaxing the check does not hide it.
# It cannot be scoped to one file: ACE is built with inline=1, so ACE_OS::memcpy is an inline
# function emitted as a COMDAT copy in every TU, and the linker may keep a checked copy (relaxing
# only Message_Block.o was tried and had no effect). A per-function -fsanitize-ignorelist= is
# banned by the fleet rules (ccache does not hash the list file).
# ASan and every other UBSan check stay on and halting.
case "$SANITIZER_FLAGS" in *undefined*) SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=nonnull-attribute" ;; esac
case "$LIB_FUZZING_ENGINE" in *-fsanitize=fuzzer*) LIB_COV_FLAGS="-fsanitize=fuzzer-no-link" ;; esac

# configure_ace <ACE_ROOT> <extra compile flags> <extra link flags>
configure_ace() {
  local root="$1" cflags="$2" ldflags="$3"
  echo '#include "ace/config-linux.h"' > "$root/ace/config.h.new"
  cmp -s "$root/ace/config.h.new" "$root/ace/config.h" 2>/dev/null \
    && rm -f "$root/ace/config.h.new" || mv -f "$root/ace/config.h.new" "$root/ace/config.h"
  cat > "$root/include/makeinclude/platform_macros.GNU.new" <<MK
static_libs_only = 1
debug = 1
optimize = 0
inline = 1
zlib = 0
zzip = 0
ssl = 0
include \$(ACE_ROOT)/include/makeinclude/platform_linux_clang.GNU
CC = $CC
CXX = $CXX
CCFLAGS += $cflags
CFLAGS += $cflags
LDFLAGS += $ldflags
MK
  cmp -s "$root/include/makeinclude/platform_macros.GNU.new" "$root/include/makeinclude/platform_macros.GNU" 2>/dev/null \
    && rm -f "$root/include/makeinclude/platform_macros.GNU.new" \
    || mv -f "$root/include/makeinclude/platform_macros.GNU.new" "$root/include/makeinclude/platform_macros.GNU"
}

# ---- 1) sanitized libraries + tao_idl -----------------------------------------------------
export ACE_ROOT="$SRC/ACE" TAO_ROOT="$SRC/TAO"
mkdir -p "$SRC/mayhem/fuzz-bin"
# lsan_off.o goes into every MPC-linked program too (tao_idl, ace_gperf), which run during the build.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$SRC/mayhem/fuzz-bin/lsan_off.o"
configure_ace "$ACE_ROOT" "-O1 $SANITIZER_FLAGS $LIB_COV_FLAGS $DEBUG_FLAGS" \
  "$SANITIZER_FLAGS $LIB_COV_FLAGS $SRC/mayhem/fuzz-bin/lsan_off.o"
( cd "$SRC/mayhem" && perl "$ACE_ROOT/bin/mwc.pl" -type gnuace -static fuzz.mwc )
make -C "$SRC/mayhem" -j"$MAYHEM_JOBS"

# ---- 1b) tao_idl again, AFL-instrumented, for the tao-idl (afl: true) target ----------------
# tao_idl is a CLI that exits on errors and forks a preprocessor, so it stays a file-input target.
# Mayhem only gets coverage from it when it is AFL-instrumented, so the IDL front end, back end
# and driver are rebuilt with afl-clang-fast++ (+ $SANITIZER_FLAGS) in a separate tree
# (mayhem/build-afl, gitignored) against the sanitized libACE.a from step 1. The runtime
# preprocessor stays plain clang++ (TAO_IDL_PREPROCESSOR), as in the step-1 tao_idl.
A="$SRC/mayhem/build-afl"
mkdir -p "$A/ACE/lib" "$A/TAO"
( cd "$SRC" && find ACE/ace ACE/include ACE/bin TAO/TAO_IDL TAO/MPC -type d -name .obj -prune -o -type f \
    ! -name 'GNUmakefile*' ! -name 'lib*.a' ! -name config.h ! -name platform_macros.GNU ! -name '*.log' \
    ! -path 'ACE/bin/tao_idl*' ! -path 'ACE/bin/ace_gperf*' -print0 | xargs -0 cp -pu --parents -t "$A" )
( cd "$SRC" && cp -pu --parents ACE/VERSION.txt TAO/VERSION.txt TAO/rules.tao.GNU TAO/tao/Version.h \
    TAO/tao/idl_features.h "$A" )
cp -pu "$SRC/ACE/lib/libACE.a" "$A/ACE/lib/libACE.a"
export ACE_ROOT="$A/ACE" TAO_ROOT="$A/TAO"
CC_SAVE="$CC" CXX_SAVE="$CXX"
CC=afl-clang-fast CXX=afl-clang-fast++
configure_ace "$ACE_ROOT" "-O1 $SANITIZER_FLAGS $DEBUG_FLAGS" "$SANITIZER_FLAGS $SRC/mayhem/fuzz-bin/lsan_off.o"
CC="$CC_SAVE" CXX="$CXX_SAVE"
printf 'workspace {\n  TAO_IDL/tao_idl_fe.mpc\n  TAO_IDL/tao_idl_be.mpc\n  TAO_IDL/tao_idl.mpc\n}\n' > "$A/TAO/afl.mwc.new"
cmp -s "$A/TAO/afl.mwc.new" "$A/TAO/afl.mwc" 2>/dev/null && rm -f "$A/TAO/afl.mwc.new" || mv -f "$A/TAO/afl.mwc.new" "$A/TAO/afl.mwc"
( cd "$A/TAO" && perl "$ACE_ROOT/bin/mwc.pl" -type gnuace -static afl.mwc )
# Only the IDL front end (lexer, parser, AST — incl. ast_expression.cpp) and the driver main get
# AFL edges: instrumenting the whole C++ back end too gives ~320k edges, far past AFL's 64k map
# (afl-showmap aborts "required size is very large"). The back end is still ASan/UBSan-built.
printf 'src: */TAO_IDL/fe/*\nsrc: */TAO_IDL/ast/*\nsrc: */TAO_IDL/tao_idl.cpp\n' > "$A/afl-allowlist.txt"
AFL_QUIET=1 AFL_LLVM_ALLOWLIST="$A/afl-allowlist.txt" \
  make -C "$A/TAO" -j"$MAYHEM_JOBS" TAO_IDL_PREPROCESSOR=clang++
test -x "$A/TAO/TAO_IDL/tao_idl"
export ACE_ROOT="$SRC/ACE" TAO_ROOT="$SRC/TAO"

# ---- 2) harnesses -----------------------------------------------------------------------
INC=(-I"$ACE_ROOT" -I"$TAO_ROOT" -DTAO_AS_STATIC_LIBS -I"$ACE_ROOT/protocols" -I"$ACE_ROOT/ASNMP" -I"$SRC/mayhem/harnesses"
     -DACE_AS_STATIC_LIBS -D__ACE_INLINE__ -DACE_HAS_EXCEPTIONS)
L="$ACE_ROOT/lib"
declare -A LIBS=(
  [fuzz_cdr]="$L/libACE.a"
  [fuzz_strings]="$L/libACE.a"
  [fuzz_svcconf]="$L/libACE.a"
  [fuzz_config_import]="$L/libACE.a"
  [fuzz_acexml]="$L/libACEXML_Parser.a $L/libACEXML.a $L/libACE.a"
  [fuzz_http]="$L/libACE_INet.a $L/libACE.a"
  [fuzz_url]="$L/libACE_INet.a $L/libACE.a"
  [fuzz_ftp_response]="$L/libACE_INet.a $L/libACE.a"
  [fuzz_asnmp]="$L/libasnmp.a $L/libACE.a"
  [fuzz_tao_cdr]="$L/libTAO_AnyTypeCode.a $L/libTAO.a $L/libACE.a"
  [fuzz_tao_ior]="$L/libTAO_AnyTypeCode.a $L/libTAO.a $L/libACE.a"
  [fuzz_etcl]="$L/libACE_ETCL_Parser.a $L/libACE_ETCL.a $L/libACE.a"
)
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/mayhem/fuzz-bin/standalone_main.o"
for h in "${!LIBS[@]}"; do
  obj="$SRC/mayhem/fuzz-bin/$h.o"
  $CXX -std=c++17 $SANITIZER_FLAGS $LIB_COV_FLAGS $DEBUG_FLAGS -O1 "${INC[@]}" -c "$SRC/mayhem/harnesses/$h.cpp" -o "$obj"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$obj" "$SRC/mayhem/fuzz-bin/lsan_off.o" \
       ${LIBS[$h]} -lpthread -ldl -lrt -o "$SRC/$h"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$obj" "$SRC/mayhem/fuzz-bin/standalone_main.o" \
       "$SRC/mayhem/fuzz-bin/lsan_off.o" ${LIBS[$h]} -lpthread -ldl -lrt -o "$SRC/$h-standalone"
done

# ---- 3) functional tests, normal flags, separate tree ------------------------------------
T="$SRC/mayhem/build-tests"
mkdir -p "$T"
( cd "$SRC" && find ACE/ace ACE/include ACE/bin ACE/tests -type d -name .obj -prune -o -type f \
    ! -name 'GNUmakefile*' ! -name 'lib*.a' ! -name config.h ! -name platform_macros.GNU ! -name '*.log' \
    -print0 | xargs -0 cp -pu --parents -t "$T" )
cp -pu "$SRC/ACE/VERSION.txt" "$T/ACE/VERSION.txt"
export ACE_ROOT="$T/ACE"
configure_ace "$ACE_ROOT" "-O2 $COVERAGE_FLAGS" "$COVERAGE_FLAGS"
printf 'workspace {\n  ace/ace.mpc\n}\n' > "$T/ACE/tests_lib.mwc"
( cd "$T/ACE" && perl "$ACE_ROOT/bin/mwc.pl" -type gnuace -static tests_lib.mwc )
make -C "$T/ACE" -j"$MAYHEM_JOBS"
TESTS=(CDR_Test CDR_Fixed_Test CDR_Array_Test Codecs_Test UUID_Test Config_Test ARGV_Test SString_Test)
mkdir -p "$T/bin"
for t in "${TESTS[@]}"; do
  echo "$t.cpp"
done | xargs -P"$MAYHEM_JOBS" -I{} sh -c '
  t=$(basename {} .cpp)
  '"$CXX"' -std=c++17 -O1 '"$COVERAGE_FLAGS"' -I"'"$T"'/ACE" -I"'"$T"'/ACE/tests" -DACE_AS_STATIC_LIBS -D__ACE_INLINE__ \
    "'"$T"'/ACE/tests/$t.cpp" "'"$T"'/ACE/tests/Main.cpp" "'"$T"'/ACE/tests/Test_Output.cpp" \
    "'"$T"'/ACE/lib/libACE.a" -lpthread -ldl -lrt -o "'"$T"'/bin/$t"'
printf '%s\n' "${TESTS[@]}" > "$T/bin/TESTS"
echo "build.sh: done"
