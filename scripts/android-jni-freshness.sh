#!/usr/bin/env bash
# Stamp and verify that committed/copied Android jniLibs match the current
# Cargo-affecting source. Direct Gradle packaging must fail when this stamp
# is missing or stale.
#
# The source stamp hashes every tracked input that can change the Android
# native graph or how it is produced. Host rustc/cargo/NDK/JDK/linker
# versions are not hashed: the same stamp can produce non-bit-identical
# .so files across toolchains. rust-toolchain / rust-toolchain.toml are
# included when those files are tracked; this repo currently has neither.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ABIS=(armeabi-v7a arm64-v8a x86 x86_64)

jni_libs_dir() {
    printf '%s' "${JNI_FRESHNESS_JNILIBS:-paykit-ffi/bindings/android/lib/src/main/jniLibs}"
}

provenance_path() {
    printf '%s' "${JNI_FRESHNESS_PROVENANCE:-$(jni_libs_dir)/PROVENANCE}"
}

CONFIG_BACKUP=""
CONFIG_PATH=""
BUILD_BACKUP=""
BUILD_PATH=""
SELFTEST_TMP=""

cleanup() {
    if [[ -n "${CONFIG_PATH:-}" && -n "${CONFIG_BACKUP:-}" && -f "$CONFIG_BACKUP" ]]; then
        cp "$CONFIG_BACKUP" "$CONFIG_PATH"
        rm -f "$CONFIG_BACKUP"
    fi
    if [[ -n "${BUILD_PATH:-}" && -n "${BUILD_BACKUP:-}" && -f "$BUILD_BACKUP" ]]; then
        cp "$BUILD_BACKUP" "$BUILD_PATH"
        rm -f "$BUILD_BACKUP"
    fi
    if [[ -n "${SELFTEST_TMP:-}" && -d "$SELFTEST_TMP" ]]; then
        rm -rf "$SELFTEST_TMP"
    fi
}
trap cleanup EXIT

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

source_stamp() {
    # Lockfile plus every tracked path that changes the Android native graph
    # or the scripts/config that produce it. Missing rust-toolchain files
    # are omitted by git ls-files (none are tracked today).
    {
        git ls-files -z -- \
            Cargo.lock \
            Cargo.toml \
            .cargo/config.toml \
            paykit-ffi/Cargo.toml \
            paykit-ffi/src \
            paykit-ffi/uniffi-android.toml \
            paykit-ffi/uniffi.toml \
            paykit-ffi/build.sh \
            paykit-ffi/build_android.sh \
            paykit-lib \
            paykit-sdk \
            scripts/android-jni-freshness.sh \
            scripts/verify-vendor-integrity.sh \
            rust-toolchain \
            rust-toolchain.toml \
            vendor/pubky \
            vendor/pkarr \
            vendor/snow \
            vendor/rustls-platform-verifier-android \
            | sort -z \
            | xargs -0 shasum -a 256
    } | shasum -a 256 | awk '{print $1}'
}

assert_elf() {
    local lib="$1"
    if [[ ! -f "$lib" ]]; then
        echo "jni-freshness: missing $lib" >&2
        return 1
    fi
    if head -c 32 "$lib" | grep -q 'git-lfs'; then
        echo "jni-freshness: $lib is a Git LFS pointer, not a built ELF" >&2
        return 1
    fi
    if [[ "$(head -c 4 "$lib")" != $'\x7fELF' ]]; then
        echo "jni-freshness: $lib is not an ELF shared object" >&2
        return 1
    fi
}

write_provenance() {
    local stamp lib abi hash size jnilibs provenance
    jnilibs="$(jni_libs_dir)"
    provenance="$(provenance_path)"
    stamp="$(source_stamp)"
    {
        echo "source_sha256=$stamp"
        echo "toolchain_note=host rustc/cargo/NDK/JDK/linker versions are not hashed; same source stamp may yield non-bit-identical .so files across toolchains"
        for abi in "${ABIS[@]}"; do
            lib="$jnilibs/$abi/libpaykit.so"
            assert_elf "$lib"
            hash="$(sha256_file "$lib")"
            size="$(wc -c < "$lib" | tr -d ' ')"
            echo "$abi sha256=$hash size=$size"
        done
    } > "$provenance"
    echo "jni-freshness: wrote $provenance"
}

verify_provenance() {
    local stamp expected_stamp lib abi hash size line jnilibs provenance
    jnilibs="$(jni_libs_dir)"
    provenance="$(provenance_path)"
    if [[ ! -f "$provenance" ]]; then
        echo "jni-freshness: missing $provenance; run paykit-ffi/build_android.sh" >&2
        return 1
    fi
    stamp="$(source_stamp)"
    expected_stamp="$(sed -n 's/^source_sha256=//p' "$provenance" | head -n 1)"
    if [[ -z "$expected_stamp" || "$stamp" != "$expected_stamp" ]]; then
        echo "jni-freshness: jniLibs do not match current Cargo-affecting source" >&2
        echo "  provenance $expected_stamp" >&2
        echo "  current    $stamp" >&2
        echo "  rebuild with paykit-ffi/build_android.sh" >&2
        return 1
    fi
    for abi in "${ABIS[@]}"; do
        lib="$jnilibs/$abi/libpaykit.so"
        if ! assert_elf "$lib"; then
            return 1
        fi
        hash="$(sha256_file "$lib")"
        size="$(wc -c < "$lib" | tr -d ' ')"
        line="$(grep -E "^$abi sha256=" "$provenance" || true)"
        if [[ "$line" != "$abi sha256=$hash size=$size" ]]; then
            echo "jni-freshness: $lib does not match $provenance" >&2
            echo "  expected $line" >&2
            echo "  actual   $abi sha256=$hash size=$size" >&2
            return 1
        fi
    done
    echo "jni-freshness: four ABI libpaykit.so files match current source stamp"
}

expect_fail() {
    local label="$1"
    shift
    if "$@"; then
        echo "jni-freshness: $label unexpectedly succeeded" >&2
        exit 1
    fi
    echo "jni-freshness: $label failed closed"
}

self_test() {
    local stamp tampered
    # T1: current tree verify — may fail if stamp is stale after source edits.
    # Self-test still exercises the fail-closed cases against a copy.
    SELFTEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/paykit-jni-freshness-XXXXXXXX")"
    mkdir -p "$SELFTEST_TMP/jniLibs"
    cp -R "$ROOT/paykit-ffi/bindings/android/lib/src/main/jniLibs/." "$SELFTEST_TMP/jniLibs/"
    export JNI_FRESHNESS_JNILIBS="$SELFTEST_TMP/jniLibs"
    export JNI_FRESHNESS_PROVENANCE="$SELFTEST_TMP/jniLibs/PROVENANCE"

    # Refresh the copy's stamp to the current source so T1 can pass during
    # in-progress edits, then mutate only the copy for T2-T6.
    write_provenance
    verify_provenance
    echo "jni-freshness: T1 verify succeeded on matching stamp"

    mv "$JNI_FRESHNESS_PROVENANCE" "$SELFTEST_TMP/PROVENANCE.bak"
    expect_fail "T2 missing PROVENANCE" verify_provenance
    mv "$SELFTEST_TMP/PROVENANCE.bak" "$JNI_FRESHNESS_PROVENANCE"

    cp "$JNI_FRESHNESS_PROVENANCE" "$SELFTEST_TMP/PROVENANCE.bak"
    sed -i.bak 's/^source_sha256=.*/source_sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef/' \
        "$JNI_FRESHNESS_PROVENANCE"
    rm -f "$JNI_FRESHNESS_PROVENANCE.bak"
    expect_fail "T3 stale source stamp" verify_provenance
    mv "$SELFTEST_TMP/PROVENANCE.bak" "$JNI_FRESHNESS_PROVENANCE"

    mv "$JNI_FRESHNESS_JNILIBS/x86/libpaykit.so" "$SELFTEST_TMP/libpaykit.so.bak"
    expect_fail "T4 missing ABI library" verify_provenance
    mv "$SELFTEST_TMP/libpaykit.so.bak" "$JNI_FRESHNESS_JNILIBS/x86/libpaykit.so"

    cp "$JNI_FRESHNESS_JNILIBS/x86/libpaykit.so" "$SELFTEST_TMP/libpaykit.so.bak"
    printf 'version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize 1\n' \
        "$(printf '0%.0s' {1..64})" > "$JNI_FRESHNESS_JNILIBS/x86/libpaykit.so"
    expect_fail "T5 LFS pointer" verify_provenance
    mv "$SELFTEST_TMP/libpaykit.so.bak" "$JNI_FRESHNESS_JNILIBS/x86/libpaykit.so"

    cp "$JNI_FRESHNESS_JNILIBS/x86/libpaykit.so" "$SELFTEST_TMP/libpaykit.so.bak"
    printf 'x' >> "$JNI_FRESHNESS_JNILIBS/x86/libpaykit.so"
    expect_fail "T6 ABI hash mismatch" verify_provenance
    mv "$SELFTEST_TMP/libpaykit.so.bak" "$JNI_FRESHNESS_JNILIBS/x86/libpaykit.so"

    unset JNI_FRESHNESS_JNILIBS JNI_FRESHNESS_PROVENANCE
    echo "jni-freshness: T7 live verify is the real jniLibs/PROVENANCE path (Gradle gate)"

    stamp="$(source_stamp)"
    CONFIG_PATH="$ROOT/.cargo/config.toml"
    CONFIG_BACKUP="$(mktemp)"
    cp "$CONFIG_PATH" "$CONFIG_BACKUP"
    printf '\n# jni-freshness config tamper\n' >> "$CONFIG_PATH"
    tampered="$(source_stamp)"
    cp "$CONFIG_BACKUP" "$CONFIG_PATH"
    rm -f "$CONFIG_BACKUP"
    CONFIG_BACKUP=""
    CONFIG_PATH=""
    if [[ "$tampered" == "$stamp" ]]; then
        echo "jni-freshness: T8 .cargo/config.toml change did not invalidate stamp" >&2
        exit 1
    fi
    echo "jni-freshness: T8 .cargo/config.toml change invalidated stamp"

    stamp="$(source_stamp)"
    BUILD_PATH="$ROOT/paykit-ffi/build_android.sh"
    BUILD_BACKUP="$(mktemp)"
    cp "$BUILD_PATH" "$BUILD_BACKUP"
    printf '\n# jni-freshness build script tamper\n' >> "$BUILD_PATH"
    tampered="$(source_stamp)"
    cp "$BUILD_BACKUP" "$BUILD_PATH"
    rm -f "$BUILD_BACKUP"
    BUILD_BACKUP=""
    BUILD_PATH=""
    if [[ "$tampered" == "$stamp" ]]; then
        echo "jni-freshness: T9 build_android.sh change did not invalidate stamp" >&2
        exit 1
    fi
    echo "jni-freshness: T9 build_android.sh change invalidated stamp"

    echo "jni-freshness: self-test T1-T9 passed"
}

case "${1:-verify}" in
    write) write_provenance ;;
    verify) verify_provenance ;;
    --self-test) self_test ;;
    *)
        echo "usage: $0 write|verify|--self-test" >&2
        exit 2
        ;;
esac
