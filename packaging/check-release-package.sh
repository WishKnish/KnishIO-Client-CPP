#!/usr/bin/env bash
# Consumer build gate for a KnishIO C++ SDK release package (a `cmake --install` staging tree).
#
# usage: packaging/check-release-package.sh <stage-dir> <version>
#
# Proves that every consumer path works once the package is extracted somewhere else:
#   no-host-paths  lib/cmake (and lib/pkgconfig, if present) name no absolute build-host path
#   relocate       the package is copied to a fresh temp dir; every later check uses the copy
#   headers        every installed header outside third_party/ compiles on its own
#                  (packaging/header-check-exclusions.txt lists skipped ones: `knishio/<rel>  # reason`)
#   direct         packaging/consumer/main.cpp builds with plain -I/-L flags and runs
#   find_package   packaging/consumer builds with find_package(KnishIOClientCPP), linking
#                  KnishIO::ClientCPP (consumer) and KnishIO::ClientCPPStatic (consumer_static)
# Each consumer prints the bundle hash of "knishio-consumer-smoke", which must equal
# SHAKE256-256 of that secret. Prints `PASS <check>` or `FAIL <check>: <detail>` per check and
# exits 1 if any check failed. The stage dir is only read, never written.
set -uo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $0 <stage-dir> <version>" >&2
    exit 2
fi
if [ ! -d "$1" ]; then
    echo "FAIL args: not a directory: $1"
    exit 1
fi
STAGE=$(cd "$1" && pwd -P)
STAGE_LOGICAL=$(cd "$1" && pwd)
VERSION=$2
PACKAGING=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
CONSUMER="$PACKAGING/consumer"
EXCLUSIONS="$PACKAGING/header-check-exclusions.txt"

E=$(python3 -c "import hashlib;print(hashlib.shake_256(b'knishio-consumer-smoke').hexdigest(32))")
W=$(cd "$(mktemp -d)" && pwd -P)
trap 'rm -rf "$W"' EXIT
FAILED=0

pass() { echo "PASS $*"; }
fail() {
    echo "FAIL $1: $2"
    FAILED=1
}
# The first error of a log on one line: a compiler `error:` line, or a `CMake Error` line
# joined with the next three message lines; else the log's last non-empty line. Paths inside
# the relocated copy are shown relative to it.
first_error() {
    awk -v pre="$W/relocated/pkg/" '
        function strip(s,   i) {
            while ((i = index(s, pre)) > 0) s = substr(s, 1, i - 1) substr(s, i + length(pre))
            return s
        }
        function out(s) { print strip(s); done = 1; exit }
        NF { last = $0 }
        /CMake Error/ && !grab { msg = $0; grab = 1; n = 0; next }
        grab && NF { sub(/^[ \t]+/, ""); msg = msg " | " $0; if (++n == 3) out(msg); next }
        /error:/ && !grab { out($0) }
        END { if (!done) print strip(grab ? msg : last) }
    ' "$1"
}
jobs_n() { nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2; }

# 1. no-host-paths ---------------------------------------------------------------------------
if [ ! -d "$STAGE/lib/cmake" ]; then
    fail no-host-paths "no lib/cmake directory in $STAGE"
else
    hits=$(
        for d in "$STAGE/lib/cmake" "$STAGE/lib/pkgconfig"; do
            [ -d "$d" ] || continue
            grep -rnE '(^|[[:space:]";=])/(usr|opt|Users|home|private|var|tmp|Volumes)/' "$d"
            grep -rnF -e "$STAGE" -e "$STAGE_LOGICAL" "$d"
        done | LC_ALL=C sort -u
    )
    if [ -z "$hits" ]; then
        pass no-host-paths
    else
        while IFS= read -r hit; do
            fail no-host-paths "${hit#"$STAGE/"}"
        done <<<"$hits"
    fi
fi

# 2. relocate -------------------------------------------------------------------------------
mkdir -p "$W/relocated"
if ! cp -R "$STAGE" "$W/relocated/pkg"; then
    fail relocate "cp -R $STAGE $W/relocated/pkg failed"
    exit 1
fi
R="$W/relocated/pkg"
pass relocate

INC=(-I"$R/include" -I"$R/include/knishio")
DEPS_OK=1
if ! DEP_CFLAGS_STR=$(pkg-config --cflags libsodium openssl libcurl 2>"$W/pc.err"); then
    DEPS_OK=0
    DEPS_ERR="pkg-config --cflags libsodium openssl libcurl: $(tr '\n' ' ' <"$W/pc.err")"
fi
read -r -a DEP_CFLAGS <<<"${DEP_CFLAGS_STR:-}"
if ! DEP_LIBS_STR=$(pkg-config --libs libsodium libcurl 2>"$W/pc.err"); then
    DEPS_OK=0
    DEPS_ERR="pkg-config --libs libsodium libcurl: $(tr '\n' ' ' <"$W/pc.err")"
fi
read -r -a DEP_LIBS <<<"${DEP_LIBS_STR:-}"

# 3. headers --------------------------------------------------------------------------------
if [ "$DEPS_OK" -eq 0 ]; then
    fail headers "$DEPS_ERR"
elif [ ! -d "$R/include/knishio" ]; then
    fail headers "no include/knishio directory"
else
    excluded=()
    if [ -f "$EXCLUSIONS" ]; then
        while IFS= read -r line; do
            line=${line%%#*}
            read -r path _ <<<"$line"
            [ -n "${path:-}" ] && excluded+=("$path")
        done <"$EXCLUSIONS"
    fi
    total=0 skipped=0 bad=0
    while IFS= read -r header; do
        rel=${header#"$R/include/"}
        skip=0
        for x in ${excluded[@]+"${excluded[@]}"}; do
            [ "$x" = "$rel" ] && skip=1
        done
        if [ "$skip" -eq 1 ]; then
            skipped=$((skipped + 1))
            continue
        fi
        total=$((total + 1))
        printf '#include <%s>\n' "$rel" >"$W/header.cpp"
        if ! c++ -std=c++20 -fsyntax-only "${INC[@]}" ${DEP_CFLAGS[@]+"${DEP_CFLAGS[@]}"} "$W/header.cpp" >"$W/header.log" 2>&1; then
            bad=$((bad + 1))
            fail headers "$rel: $(first_error "$W/header.log")"
        fi
    done < <(find "$R/include/knishio" -type f -name '*.h' -not -path "$R/include/knishio/third_party/*" | LC_ALL=C sort)
    if [ "$total" -eq 0 ]; then
        fail headers "no headers found under include/knishio"
    elif [ "$bad" -eq 0 ]; then
        if [ "$skipped" -gt 0 ]; then
            pass "headers ($total headers, SKIP $skipped)"
        else
            pass "headers ($total headers)"
        fi
    fi
fi

# 4. direct (plain -I/-L) -------------------------------------------------------------------
if [ "$DEPS_OK" -eq 0 ]; then
    fail direct "$DEPS_ERR"
else
    mkdir -p "$W/direct"
    if c++ -std=c++20 "${INC[@]}" ${DEP_CFLAGS[@]+"${DEP_CFLAGS[@]}"} "$CONSUMER/main.cpp" -o "$W/direct/consumer" \
        -L"$R/lib" -lknishio-client-cpp -Wl,-rpath,"$R/lib" ${DEP_LIBS[@]+"${DEP_LIBS[@]}"} >"$W/direct.log" 2>&1; then
        out=$("$W/direct/consumer" 2>"$W/direct.err")
        rc=$?
        if [ "$rc" -eq 0 ] && [ "$out" = "$E" ]; then
            pass direct
        else
            fail direct "consumer exit=$rc output='$out' (expected $E) $(tr '\n' ' ' <"$W/direct.err")"
        fi
    else
        fail direct "build: $(first_error "$W/direct.log")"
    fi
fi

# 5. find_package ---------------------------------------------------------------------------
cmake_args=(-S "$CONSUMER" -B "$W/cmake" -DCMAKE_PREFIX_PATH="$R" -DEXPECTED_VERSION="$VERSION" -DCMAKE_BUILD_TYPE=Release)
note=""
configured=0
if cmake "${cmake_args[@]}" >"$W/configure.log" 2>&1; then
    configured=1
elif grep -q 'Could NOT find OpenSSL' "$W/configure.log" && command -v brew >/dev/null 2>&1; then
    ossl=$(brew --prefix openssl@3)
    rm -rf "$W/cmake"
    note=" (configure retried with -DOPENSSL_ROOT_DIR=$ossl)"
    if cmake "${cmake_args[@]}" -DOPENSSL_ROOT_DIR="$ossl" >"$W/configure.log" 2>&1; then
        configured=1
    fi
fi
if [ "$configured" -eq 0 ]; then
    fail find_package "configure$note: $(first_error "$W/configure.log")"
else
    found_dir=$(sed -n 's/^KnishIOClientCPP_DIR:PATH=//p' "$W/cmake/CMakeCache.txt")
    if [ "$found_dir" != "$R/lib/cmake/KnishIOClientCPP" ]; then
        fail find_package "found the package at '$found_dir', not in the relocated copy$note"
    elif ! cmake --build "$W/cmake" -j "$(jobs_n)" >"$W/build.log" 2>&1; then
        fail find_package "build$note: $(first_error "$W/build.log")"
    else
        fp_ok=1
        for exe in consumer consumer_static; do
            out=$("$W/cmake/$exe" 2>"$W/$exe.err")
            rc=$?
            if [ "$rc" -ne 0 ] || [ "$out" != "$E" ]; then
                fp_ok=0
                fail find_package "$exe exit=$rc output='$out' (expected $E)$note $(tr '\n' ' ' <"$W/$exe.err")"
            fi
        done
        [ "$fp_ok" -eq 1 ] && pass "find_package (consumer, consumer_static)$note"
    fi
fi

exit "$FAILED"
