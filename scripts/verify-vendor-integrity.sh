#!/usr/bin/env bash
# Compare vendored pubky/pkarr trees to the crates.io sources named in
# vendor/*/PATCHES.md. Only documented deltas may differ.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REGISTRY=""
for candidate in "$HOME"/.cargo/registry/src/index.crates.io-*; do
    if [[ -d "$candidate" ]]; then
        REGISTRY="$candidate"
    fi
done

need_fetch=0
if [[ -z "$REGISTRY" \
    || ! -d "$REGISTRY/pubky-0.8.0" \
    || ! -d "$REGISTRY/pkarr-6.0.0" ]]; then
    need_fetch=1
fi

if [[ "$need_fetch" -eq 1 ]]; then
    cargo fetch --locked
    for candidate in "$HOME"/.cargo/registry/src/index.crates.io-*; do
        if [[ -d "$candidate" ]]; then
            REGISTRY="$candidate"
        fi
    done
fi

if [[ -z "$REGISTRY" ]]; then
    echo "vendor-integrity: no crates.io registry checkout" >&2
    exit 1
fi

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

verify_crate() {
    local name="$1"
    local version="$2"
    local vendor_rel="$3"
    shift 3
    local allowlist=("$@")
    local src_only_ignore=(".cargo-ok" ".cargo_vcs_info.json")

    local src="$REGISTRY/${name}-${version}"
    local vendor="$ROOT/$vendor_rel"

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

# Allowlisted deltas must match vendor/*/PATCHES.md.
verify_crate pubky 0.8.0 vendor/pubky \
    PATCHES.md \
    Cargo.toml \
    Cargo.toml.orig \
    src/client/core.rs \
    Cargo.lock

verify_crate pkarr 6.0.0 vendor/pkarr \
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
