#!/usr/bin/env bash
# Stamp and verify that committed/copied Android jniLibs match the current
# Cargo-affecting source. Direct Gradle packaging must fail when this stamp
# is missing or stale.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

JNILIBS="paykit-ffi/bindings/android/lib/src/main/jniLibs"
PROVENANCE="$JNILIBS/PROVENANCE"
ABIS=(armeabi-v7a arm64-v8a x86 x86_64)

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

source_stamp() {
    # Lockfile plus every path that changes the Android native graph.
    {
        git ls-files -z -- \
            Cargo.lock \
            Cargo.toml \
            paykit-ffi/Cargo.toml \
            paykit-ffi/src \
            paykit-ffi/uniffi-android.toml \
            paykit-lib \
            paykit-sdk \
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
    local stamp lib abi hash size
    stamp="$(source_stamp)"
    {
        echo "source_sha256=$stamp"
        for abi in "${ABIS[@]}"; do
            lib="$JNILIBS/$abi/libpaykit.so"
            assert_elf "$lib"
            hash="$(sha256_file "$lib")"
            size="$(wc -c < "$lib" | tr -d ' ')"
            echo "$abi sha256=$hash size=$size"
        done
    } > "$PROVENANCE"
    echo "jni-freshness: wrote $PROVENANCE"
}

verify_provenance() {
    local stamp expected_stamp lib abi hash size line
    if [[ ! -f "$PROVENANCE" ]]; then
        echo "jni-freshness: missing $PROVENANCE; run paykit-ffi/build_android.sh" >&2
        exit 1
    fi
    stamp="$(source_stamp)"
    expected_stamp="$(sed -n 's/^source_sha256=//p' "$PROVENANCE" | head -n 1)"
    if [[ -z "$expected_stamp" || "$stamp" != "$expected_stamp" ]]; then
        echo "jni-freshness: jniLibs do not match current Cargo-affecting source" >&2
        echo "  provenance $expected_stamp" >&2
        echo "  current    $stamp" >&2
        echo "  rebuild with paykit-ffi/build_android.sh" >&2
        exit 1
    fi
    for abi in "${ABIS[@]}"; do
        lib="$JNILIBS/$abi/libpaykit.so"
        assert_elf "$lib"
        hash="$(sha256_file "$lib")"
        size="$(wc -c < "$lib" | tr -d ' ')"
        line="$(grep -E "^$abi sha256=" "$PROVENANCE" || true)"
        if [[ "$line" != "$abi sha256=$hash size=$size" ]]; then
            echo "jni-freshness: $lib does not match $PROVENANCE" >&2
            echo "  expected $line" >&2
            echo "  actual   $abi sha256=$hash size=$size" >&2
            exit 1
        fi
    done
    echo "jni-freshness: four ABI libpaykit.so files match current source stamp"
}

case "${1:-verify}" in
    write) write_provenance ;;
    verify) verify_provenance ;;
    *)
        echo "usage: $0 write|verify" >&2
        exit 2
        ;;
esac
