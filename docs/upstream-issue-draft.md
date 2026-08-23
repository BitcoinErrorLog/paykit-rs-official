# [DRAFT — not filed] Proposal: first-class wasm32 support and a browser binding for the Encrypted Link messaging surface

Target repository: `pubky/paykit-rs` (with one dependency-level item for
`pubky/pubky-noise` and one observation for `pubky/pubky-core`).

Status: **draft prepared in the fork
[`BitcoinErrorLog/paykit-rs-official`](https://github.com/BitcoinErrorLog/paykit-rs-official)
(branch `feat/wasm-binding`), not filed as an upstream issue.** Everything
below was verified against master commit
`c8892f638951f033acbcd12804a31667a81ddc14` with a working proof-of-packaging
binding in that branch (`paykit-wasm/`).

---

## Motivation

Web applications in the Pubky ecosystem (concretely: marketplace private
messaging between buyers and sellers) need an end-to-end-encrypted transport
whose keys the site operator does not hold. Paykit Encrypted Links are the
reviewed transport for this — `send_private_application_message_json` even
accepts application-defined kinds by contract — and the key architecture is
already browser-compatible:

- the link crypto uses a random receiver-scoped Noise key
  (`ReceiverNoiseSecretKey::random()`), never the Pubky identity secret;
- `PubkySessionAccess.local_secret_key` is `Option` — the SDK runs without
  the identity key;
- the homeserver session can come from a signer-approved `pubkyauth` grant,
  which is exactly how browser apps already authenticate.

But today the only bindings are UniFFI Swift/Kotlin (`paykit-ffi`). Without a
JS/WASM binding, a web app's fallback is a server-side Rust adapter that holds
users' receiver keys — i.e. **an operator-readable "encrypted" messenger**,
which defeats the purpose. A browser WASM binding is the topology that
actually delivers "operator cannot read", and `@synonymdev/pubky` proves the
underlying pubky stack already ships as browser WASM.

We attempted the binding in a fork. It works: the messaging surface compiles
to `wasm32-unknown-unknown`, packages with `wasm-pack`, and passes a
real-crypto smoke test in Node (module instantiation, receiver key
generation, full Noise XX handshake between two in-memory parties via
`pubky_noise::snow_crypto::DataLinkContext`, encrypted roundtrips both
directions, AEAD tamper rejection, 1000-byte limit enforcement). **Every
blocker we hit was packaging-class, not API-shape.** Details and exact fixes
below — the diff is small and additive.

## Blockers hit and how we solved them

### 1. `getrandom` backend configuration (build error out of the box)

`getrandom` 0.3 (reached via `pubky-noise`, `snow`, `rand` 0.9) requires an
explicit WASM backend. Fix (binding crate + one cfg):

```toml
# binding crate, wasm32 target deps
getrandom_03 = { package = "getrandom", version = "0.3", features = ["wasm_js"] }
getrandom_02 = { package = "getrandom", version = "0.2", features = ["js"] }
```

```toml
# .cargo/config.toml
[target.wasm32-unknown-unknown]
rustflags = ['--cfg', 'getrandom_backend="wasm_js"']
```

`getrandom` 0.2 is also in the graph (via `pkarr`/`ntimestamp` and
`flume`/`nanorand`) and needs its `js` feature.

### 2. `ring` gets built because of a `snow` 0.10.0 manifest bug

`cargo tree -e normal,build -i ring --target wasm32-unknown-unknown` shows
`ring ← snow ← pubky-noise ← paykit-lib`. But snow's default resolver (which
pubky-noise uses, `Noise_XX_25519_ChaChaPoly_SHA256`) never calls ring: ring
is an *optional* dependency of snow, force-enabled by an incorrect feature
declaration in snow 0.10.0:

```toml
std = ["getrandom/std", "subtle/std", "ring/std", ...]   # activates ring!
```

The correct spelling is the weak-dependency form `"ring?/std"`. Because ring
builds C with a wasm-capable clang (stock Apple clang fails with "No
available targets are compatible with triple wasm32-unknown-unknown"), this
one line makes the whole build require a special C toolchain for code that is
never executed.

Our fix: vendor snow 0.10.0 byte-identical except that one manifest line,
wired via `[patch.crates-io]`. Suggested upstream actions (either works):

- get the one-line fix released in snow (report/PR to `mcginty/snow`) and
  bump, or
- carry the same `[patch.crates-io]` vendoring that this repo already uses
  for `rustls-platform-verifier-android`.

Note this also removes a pointless C-code build from **native** targets;
behavior is unchanged everywhere.

### 3. `uuid` needs an RNG source on wasm32

`paykit-lib` uses `uuid` with `v4`; on wasm32 uuid demands an explicit
randomness feature. Fix: enable `uuid/js` (or `rng-getrandom`) from the
binding crate.

### 4. `pubky` 0.8.0 misses `reqwest/stream` in its own wasm32 declaration

`pubky`'s `event_stream.rs` calls `Response::bytes_stream()`, which reqwest
only provides with its `stream` feature. pubky's non-wasm reqwest declaration
enables `stream`; its wasm32 declaration does not, so `pubky` 0.8.0 does not
compile for wasm32 standalone — any consumer (including, presumably, the
`@synonymdev/pubky` binding itself) must enable `reqwest/stream` and rely on
feature unification. Fix on our side is exactly that; the real fix belongs in
`pubky-core`'s wasm32 dependency declaration.

## What we would like upstream to own

1. **A wasm binding crate for the messaging surface** (or adopt/review the
   fork's `paykit-wasm`): receiver Noise keys, `pubkyauth` session
   acquisition, receiver markers, Encrypted Link handshake/messaging/
   snapshots, `clear_encrypted_link_outbox`. Payments surface can follow
   later; messaging alone unlocks browser clients that hold their own keys.
2. **A wasm32 CI target** (`cargo check --target wasm32-unknown-unknown` at
   minimum; ideally `wasm-pack build` + a Node smoke test like the fork's
   `paykit-wasm/scripts/smoke.mjs`) so wasm support cannot silently regress.
   Neither this repo nor pubky-noise has any wasm target in CI today.
3. **A published npm package** (à la `@synonymdev/pubky`) with pinned-commit
   provenance and checksums, so downstream apps stop vendoring ad-hoc builds.
4. **Browser e2e coverage** for the homeserver-backed flows (two browser
   contexts, ephemeral testnet, handshake + message roundtrip + snapshot
   restore). The fork's smoke test proves the compiled crypto in-memory; the
   outbox transport paths compile but need a live homeserver to exercise.
5. **(pubky-noise) Close the snapshot-encryption TODO** (`persist_snapshot`
   stores serialized session state unencrypted; `pubky-noise/src/lib.rs`
   "TODO: encrypt serialized bytes"). Browser deployments make this more
   pressing: snapshots will live in IndexedDB and backup blobs.
6. **(question) Is a `marketplace.*` kind namespace over
   `send_private_application_message_json` the intended extension pattern?**
   The API docs say unknown kinds are accepted and preserved; a short
   statement (or a registry file in `specs/`) would let applications define
   kinds without fearing future collisions with Paykit's closed-world kinds.

## Evidence / reproduction

From the fork branch `feat/wasm-binding`:

```bash
rustup target add wasm32-unknown-unknown
wasm-pack build paykit-wasm --target web --out-dir pkg --release
node paykit-wasm/scripts/smoke.mjs   # 11/11 real-crypto checks pass
```

Toolchain used: rustc 1.93.1, wasm-pack 0.13.1 (wasm-bindgen 0.2.115),
Node 22.14.0, macOS arm64. Artifact: ~1.45 MB wasm. Full provenance,
checksums, and known limitations: `paykit-wasm/README.md` in the branch.
