#!/usr/bin/env bash
# Compare vendored pubky/pkarr trees to the crates.io sources named in
# vendor/*/PATCHES.md. Only documented deltas may differ.
#
# Before using an extracted registry tree, this script hashes the cached
# `.crate` archive and requires it to match the pinned crates.io checksum
# documented in PATCHES.md / Cargo.lock.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# crates.io package checksums (sha256 of the `.crate` archive).
PINNED_PUBKY_CRATE_SHA256="25d85fdb77a0ee17213b1885f7d5c5d0536fa3ab11f93d395b4b5975c885467d"
PINNED_PKARR_CRATE_SHA256="997d5cbd9be48de01468085ecb82e951b82a04496cd76b1b3a1ea20b2fa84107"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

find_registry_src() {
    local found=""
    for candidate in "$HOME"/.cargo/registry/src/index.crates.io-*; do
        if [[ -d "$candidate" ]]; then
            found="$candidate"
        fi
    done
    printf '%s' "$found"
}

find_registry_cache() {
    local found=""
    for candidate in "$HOME"/.cargo/registry/cache/index.crates.io-*; do
        if [[ -d "$candidate" ]]; then
            found="$candidate"
        fi
    done
    printf '%s' "$found"
}

ensure_registry() {
    local src cache
    src="$(find_registry_src)"
    cache="$(find_registry_cache)"
    if [[ -z "$src" || -z "$cache" \
        || ! -d "$src/pubky-0.8.0" \
        || ! -d "$src/pkarr-6.0.0" \
        || ! -f "$cache/pubky-0.8.0.crate" \
        || ! -f "$cache/pkarr-6.0.0.crate" ]]; then
        cargo fetch --locked
    fi
}

crate_archive_path() {
    local name="$1"
    local version="$2"
    local override=""
    case "$name" in
        pubky) override="${VENDOR_INTEGRITY_PUBKY_CRATE:-}" ;;
        pkarr) override="${VENDOR_INTEGRITY_PKARR_CRATE:-}" ;;
    esac
    if [[ -n "$override" ]]; then
        printf '%s' "$override"
        return
    fi
    printf '%s/%s-%s.crate' "$(find_registry_cache)" "$name" "$version"
}

verify_crate_archive() {
    local name="$1"
    local version="$2"
    local expected="$3"
    local crate actual
    crate="$(crate_archive_path "$name" "$version")"
    if [[ ! -f "$crate" ]]; then
        echo "vendor-integrity: missing crates.io archive $crate" >&2
        return 1
    fi
    actual="$(sha256_file "$crate")"
    if [[ "$actual" != "$expected" ]]; then
        echo "vendor-integrity: $name $version crate sha256 mismatch" >&2
        echo "  expected $expected" >&2
        echo "  actual   $actual" >&2
        echo "  file     $crate" >&2
        return 1
    fi
    echo "vendor-integrity: $name $version crate sha256 ok"
}

fail=0

is_in_list() {
    local needle="$1"
    shift
    local item
    for item in "$@"; do
        if [[ "$item" == "$needle" ]]; then
            return 0
        fi
    done
    return 1
}

verify_crate_tree() {
    local name="$1"
    local version="$2"
    local vendor_rel="$3"
    shift 3
    local allowlist=("$@")
    local src_only_ignore=(".cargo-ok" ".cargo_vcs_info.json")
    local src vendor

    src="$(find_registry_src)/${name}-${version}"
    vendor="$ROOT/$vendor_rel"

    if [[ ! -d "$src" ]]; then
        echo "vendor-integrity: missing crates.io source $src" >&2
        fail=1
        return
    fi
    if [[ ! -d "$vendor" ]]; then
        echo "vendor-integrity: missing vendor tree $vendor" >&2
        fail=1
        return
    fi

    while IFS= read -r -d '' file; do
        local rel="${file#"$src"/}"
        if is_in_list "$rel" "${src_only_ignore[@]}"; then
            continue
        fi
        if [[ ! -e "$vendor/$rel" ]]; then
            if is_in_list "$rel" "${allowlist[@]}"; then
                continue
            fi
            echo "vendor-integrity: $name: crates.io file missing from vendor: $rel" >&2
            fail=1
        fi
    done < <(find "$src" -type f -print0)

    while IFS= read -r -d '' file; do
        local rel="${file#"$vendor"/}"
        if [[ ! -e "$src/$rel" ]]; then
            if is_in_list "$rel" "${allowlist[@]}"; then
                continue
            fi
            echo "vendor-integrity: $name: unexpected vendor file: $rel" >&2
            fail=1
        fi
    done < <(find "$vendor" -type f -print0)

    while IFS= read -r -d '' file; do
        local rel="${file#"$src"/}"
        if is_in_list "$rel" "${src_only_ignore[@]}"; then
            continue
        fi
        if [[ ! -f "$vendor/$rel" ]]; then
            continue
        fi
        if cmp -s "$src/$rel" "$vendor/$rel"; then
            continue
        fi
        if is_in_list "$rel" "${allowlist[@]}"; then
            continue
        fi
        echo "vendor-integrity: $name: undocumented content delta: $rel" >&2
        fail=1
    done < <(find "$src" -type f -print0)
}

self_test_tamper() {
    ensure_registry
    local cache crate tmp
    cache="$(find_registry_cache)"
    crate="$cache/pkarr-6.0.0.crate"
    if [[ ! -f "$crate" ]]; then
        echo "vendor-integrity: tamper test missing $crate" >&2
        exit 1
    fi
    tmp="$(mktemp)"
    cp "$crate" "$tmp"
    # Append one byte so the archive hash cannot match the pin.
    printf 'x' >> "$tmp"
    if [[ "$(sha256_file "$tmp")" == "$PINNED_PKARR_CRATE_SHA256" ]]; then
        rm -f "$tmp"
        echo "vendor-integrity: tamper test failed to change crate hash" >&2
        exit 1
    fi
    if VENDOR_INTEGRITY_PKARR_CRATE="$tmp" verify_crate_archive pkarr 6.0.0 "$PINNED_PKARR_CRATE_SHA256"; then
        rm -f "$tmp"
        echo "vendor-integrity: tamper test unexpectedly accepted a corrupt archive" >&2
        exit 1
    fi
    rm -f "$tmp"
    if verify_crate_archive pkarr 6.0.0 "$PINNED_PKARR_CRATE_SHA256"; then
        echo "vendor-integrity: tamper self-test passed (corrupt archive rejected, pin still matches cache)"
        exit 0
    fi
    echo "vendor-integrity: tamper test left the real cache pin failing" >&2
    exit 1
}

if [[ "${1:-}" == "--self-test-tamper" ]]; then
    self_test_tamper
fi

ensure_registry

if ! verify_crate_archive pubky 0.8.0 "$PINNED_PUBKY_CRATE_SHA256"; then
    fail=1
fi
if ! verify_crate_archive pkarr 6.0.0 "$PINNED_PKARR_CRATE_SHA256"; then
    fail=1
fi

# Allowlisted deltas must match vendor/*/PATCHES.md.
verify_crate_tree pubky 0.8.0 vendor/pubky \
    PATCHES.md \
    Cargo.toml \
    Cargo.toml.orig \
    src/client/core.rs \
    Cargo.lock

verify_crate_tree pkarr 6.0.0 vendor/pkarr \
    PATCHES.md \
    Cargo.toml \
    Cargo.toml.orig \
    src/lib.rs \
    src/client.rs \
    src/client/relays.rs \
    src/android_webpki_https.rs \
    src/extra/lmdb_cache.rs

if [[ "$fail" -ne 0 ]]; then
    echo "vendor-integrity: FAILED" >&2
    exit 1
fi

echo "vendor-integrity: pubky 0.8.0 and pkarr 6.0.0 match crates.io except documented deltas"
