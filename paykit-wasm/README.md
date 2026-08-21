# paykit-wasm

Browser WASM binding for the **Paykit Encrypted Link messaging surface**.

This crate compiles `paykit-lib`'s Encrypted Link APIs (and the `pubky`
session/auth machinery they ride on) to `wasm32-unknown-unknown` and packages
them with `wasm-pack` for browser use. It exists so a web client can hold a
receiver-scoped Noise key and run the reviewed Paykit crypto locally — i.e.
end-to-end-encrypted user↔user messaging where no service operator ever holds
the keys — without a native app and **without the Pubky identity secret ever
entering the browser** (sessions come from the Ring-approved `pubkyauth` flow;
link crypto uses an independent random receiver Noise key).

Status: **experiment — packaging proven, and the homeserver-backed messaging
flows are now proven end to end in real browsers** (Chromium, Firefox, WebKit
via Playwright) against a live Pubky testnet homeserver: browser sessions,
receiver marker publish/discovery/removal, the Noise XX handshake over
homeserver outbox transport with converging link ids, Private Application
Message exchange in both directions with intact payloads, and link
snapshot/restore across a destroyed-and-recreated browser context. See
`docs/browser-e2e.md` for the exact environment, assertions, and what remains
uncovered (notably the `startAuthFlow` signer path and mid-handshake restore).
Built on a fork of `pubky/paykit-rs`; upstream is pre-1.0 and unreviewed — see
"Provenance" and "Known limitations" before using it for anything real.

## What is bound (messaging only)

| Area | JS API |
| --- | --- |
| Receiver Noise keys | `generateNoiseSecretKey()`, `noisePublicKeyFromSecret()` (mirror `paykit_sdk::ReceiverNoiseSecretKey`) |
| Client / sessions | `PubkyClient` (`new`, `testnet`), `startAuthFlow(caps)` → `AuthFlowHandle.authorizationUrl()` / `awaitApproval()`; `SessionHandle.exportSession()` (secret-free metadata) + `PubkyClient.restoreSession()` (revalidates via the browser's HTTP-only session cookie) for reload survival; `signinWithSecret` / `signupWithSecret` (dev/test only) |
| Receiver discovery | `publishReceiverMarker`, `getReceiverMarker`, `removeReceiverMarker` |
| Handshake | `initiateEncryptedLink`, `acceptEncryptedLink`, `LinkHandshakeHandle.advance()/snapshot()/setMaxRecoveryAttempts()`, `restoreEncryptedLinkHandshake` |
| Messaging | `EncryptedLinkHandle.sendPrivateApplicationMessageJson()` (accepts unknown kinds by contract), `receivePrivateApplicationMessages()`, `snapshot()`, `setMaxSendRetries()`, `close()`, `restoreEncryptedLink`, `clearEncryptedLinkOutbox` |
| Constants | `maxNoiseMessageLen()` (1000), `noiseTagLen()` (16) |
| Test/vector surface | `MemoryNoiseSession` — the same `pubky_noise::snow_crypto::DataLinkContext` crypto (Noise `XX_25519_ChaChaPoly_SHA256`) with caller-shuttled packets instead of homeserver outboxes; used by the smoke test |

**Not bound (deliberately):** the entire payments surface of paykit-lib
(payment requests/acceptance/rejection/cancellation/proof, receipts, private
payment lists, payment endpoints, pubky routing beyond receiver markers), and
the `paykit-sdk` stateful runtime including `SdkBackupState`.

## Quickstart (browser)

```js
import init, {
  PubkyClient,
  generateNoiseSecretKey,
  noisePublicKeyFromSecret,
  publishReceiverMarker,
  getReceiverMarker,
  initiateEncryptedLink,
} from "paykit-wasm";

await init(); // loads paykit_wasm_bg.wasm

const client = new PubkyClient();

// Homeserver session via signer approval (Pubky Ring). The identity secret
// key never enters this runtime.
const flow = client.startAuthFlow("/pub/paykit/:rw");
showQrCode(flow.authorizationUrl());
const session = await flow.awaitApproval();

// One-time receiver provisioning.
const noiseSecret = generateNoiseSecretKey(); // store as a secret (IndexedDB)
await publishReceiverMarker(
  session, "marketplace/web", noisePublicKeyFromSecret(noiseSecret),
  /* privatePayments */ true, false, false, false,
);

// Open a link toward a counterparty.
const marker = await getReceiverMarker(client, counterpartyPubky, "marketplace/web");
const handshake = initiateEncryptedLink(
  session, noiseSecret, counterpartyPubky, marker.noisePublicKey,
  "marketplace/web", marker.receiverPath, client,
);
let result;
do {
  result = await handshake.advance();
  if (result.status === "pending") await sleep(1500);
} while (result.status !== "complete");
const link = result.link;

await link.sendPrivateApplicationMessageJson(JSON.stringify({
  version: 1,
  kind: "marketplace.chat_message.v0",
  body: "hello over a Paykit Encrypted Link",
}));
const inbound = await link.receivePrivateApplicationMessages();
// Persist inbound messages BEFORE persisting link.snapshot() — the read
// checkpoint advances past returned messages.
```

## Building

```bash
rustup target add wasm32-unknown-unknown
wasm-pack build paykit-wasm --target web --out-dir pkg --release
node paykit-wasm/scripts/smoke.mjs   # requires Node >= 20
```

No C toolchain is required (see "Packaging fixes" — `ring` is out of the wasm
graph).

## Packaging fixes applied (the upstreamable diff)

Compiling the unmodified workspace for `wasm32-unknown-unknown` fails on four
packaging-class issues. None are API-shape problems. This crate fixes them
additively:

1. **getrandom backends.** `getrandom` 0.3 (used by `pubky-noise`, `snow`,
   `rand` 0.9) selects its WASM entropy backend at compile time:
   `paykit-wasm` enables its `wasm_js` feature and `.cargo/config.toml` sets
   `--cfg getrandom_backend="wasm_js"` for the wasm32 target only.
   `getrandom` 0.2 (via `pkarr`/`ntimestamp`, `flume`/`nanorand`) needs its
   `js` feature. Both route entropy to `crypto.getRandomValues`.
2. **`ring` via a `snow` manifest bug.** `snow` 0.10.0's default `std`
   feature writes `"ring/std"`, which force-enables the optional `ring`
   dependency (C code, no stock-Apple-clang wasm32 support) even though the
   default resolver never calls ring. The correct spelling is the weak
   dependency `"ring?/std"`. `vendor/snow` is byte-identical to crates.io
   snow 0.10.0 except that one manifest line, wired via `[patch.crates-io]`.
   This also removes an unused C crypto build from native targets; behavior
   is unchanged on all targets.
3. **`uuid` RNG.** `uuid` (paykit-lib event ids, `v4` feature) requires an
   explicit randomness source on wasm32; `paykit-wasm` enables its `js`
   feature.
4. **`reqwest/stream` on wasm.** `pubky` 0.8.0's event-stream code calls
   `Response::bytes_stream()`, which reqwest only provides with its `stream`
   feature — but pubky's own wasm32 dependency declaration omits it (the
   published `@synonymdev/pubky` package must enable it the same way).
   `paykit-wasm` enables `reqwest/stream`; cargo feature unification applies
   it to the whole wasm graph.

## Provenance

| Field | Value |
| --- | --- |
| Upstream repository | `https://github.com/pubky/paykit-rs` |
| Pinned upstream commit | `c8892f638951f033acbcd12804a31667a81ddc14` (master, tag anchor v0.1.0-rc43) |
| Fork | `https://github.com/BitcoinErrorLog/paykit-rs-official`, branch `feat/wasm-binding` |
| `pubky` | 0.8.0 (crates.io) |
| `pubky-noise` | 0.1.0-rc5 (crates.io) |
| `snow` | 0.10.0 (crates.io source, vendored with one-line manifest fix, see above) |
| `rustc` | 1.93.1 (01f6ddf75 2026-02-11) |
| `wasm-pack` | 0.13.1 (bundled binaryen `wasm-opt`) |
| `wasm-bindgen` | 0.2.115 |
| Rust target | `wasm32-unknown-unknown` |
| Node (smoke test) | v22.14.0 |
| Build command | `wasm-pack build paykit-wasm --target web --out-dir pkg --release` |

### Artifact checksums (SHA-256, this build)

| File | SHA-256 |
| --- | --- |
| `pkg/paykit_wasm_bg.wasm` | `6a58b5f76270510b092d540a32073d50e4fd5a08c111ce7f79ebe1c2d816ffc1` |
| `pkg/paykit_wasm.js` | `3e6986e8a049ba768980f3712286c306be2896ca1ef2a98a12813dcb9af80a9f` |
| `pkg/paykit_wasm.d.ts` | `23f537a22812a2413deb3d0ec0b233fd12ae9846f9ef41b632e94b56b42ef97b` |
| `pkg/paykit_wasm_bg.wasm.d.ts` | `08941c45f148698bf19860e67b0fb1052cd707ffdfb7e6d60befd8b1f0b3b669` |
| `pkg/package.json` | `4ef84587b4aed173786a1beb771b4619c4d296886134d9b5c5847052e24af425` |

Generated `pkg/` size: ~1.5 MB (wasm ~1.45 MB). `wasm-opt` output is not
guaranteed bit-identical across platforms/toolchains; treat these checksums as
a record of this build and re-record when the pin or toolchain changes.
Consumers should vendor `pkg/` verbatim with a `file:` dependency and a
smoke-test gate, following the Locks SDK precedent.

## Smoke test

`scripts/smoke.mjs` runs against the actual compiled artifact and proves with
real crypto (no mocks): module instantiation, API surface, key generation
(entropy through the wasm getrandom backend), a complete Noise XX handshake
between two in-memory parties with converging link ids, encrypted message
roundtrips in both directions, nonce sequencing across messages, AEAD
rejection of tampered ciphertext (without burning the receiving nonce),
enforcement of the 1000-byte message limit, and `pubkyauth` URL construction.

The in-memory parties use `MemoryNoiseSession`, which drives the exact
`DataLinkContext` state machine Encrypted Links use, with the caller shuttling
the same length-prefixed packets that would otherwise sit in homeserver
outbox slots.

## Browser e2e (homeserver flows)

`e2e/run.mjs` is a Playwright-driven end-to-end test that serves `pkg/` to
real browser engines (Chromium/Firefox/WebKit) and drives two isolated
browser contexts against a live Pubky testnet homeserver: dev-keypair signup
sessions, receiver marker publish/discovery/removal, the full Noise XX
handshake over homeserver outbox slots (asserting both sides derive the same
link id), Private Application Message exchange in both directions with
payload-integrity assertions, snapshot → context destruction →
`restoreEncryptedLink` in a fresh context that still receives and sends, and
session `exportSession()` → page reload → `restoreSession()` reload survival
(16/16 checks on all three engines). Setup, port-bridging rationale, CORS
findings, observed reliability, and the honest not-covered list are in
`docs/browser-e2e.md`.

## Known limitations

- **1000-byte message limit.** `PUBKY_NOISE_MSG_LEN` bounds each Private
  Application Message (JSON envelope included). Larger payloads and
  attachments need the receipt-access pattern (encrypted blob at a homeserver
  path + a small access message), which is not bound here.
- **Snapshots serialize unencrypted and contain key material.**
  `pubky-noise` has an open TODO to encrypt persisted snapshots; Paykit
  documents caller-managed encryption for snapshots and backup state. Treat
  `snapshot()` bytes as secrets. Do not ship them anywhere unencrypted.
- **Backup/multi-device key handling is the caller's.** `SdkBackupState` is
  not bound; what encrypts persisted state (passphrase, recovery-file-derived
  key, signer-mediated wrap) is an open product decision upstream of this
  binding. A device without the receiver key and snapshots starts a fresh
  receiver with no history.
- **Homeserver flows are proven against a local testnet, not mainnet.** The
  session/marker/handshake/link/snapshot surfaces passed a two-browser-context
  e2e against a live pinned testnet homeserver (see `docs/browser-e2e.md`),
  but public pkarr relays, real DHT latency, HTTPS homeservers, and
  write-failure recovery branches remain unexercised. The production
  `startAuthFlow` signer path and `restoreEncryptedLinkHandshake` are also
  not e2e-covered. The e2e should eventually live upstream next to
  pubky-noise's e2e crate and run in CI against an ephemeral testnet.
- **Testnet port topology is fixed on WASM.** `PubkyClient.testnet()`
  hardcodes `localhost:15411` (pkarr relay) and honors the HTTP_PORT the
  homeserver record advertises (6286 on the stock testnet). The binding
  exposes no relay/host overrides, so remapped-port environments (e.g.
  Docker) need host-side port bridges (the e2e does this) until a
  configurable constructor is added.
- **Concurrency model.** Link and handshake handles reject overlapping
  operations ("operation in flight") instead of queueing; callers serialize
  sends/receives per link.
- **Upstream review.** paykit-rs is pre-1.0 (`rc43`, "WIP - not for
  production") and claims no independent security review. This binding
  inherits that status.

## Security notes

- The receiver Noise secret key is generated in the browser and never leaves
  it. Anyone holding it plus link snapshots can decrypt the conversation.
- Messages persist as ciphertext on both homeservers under unguessable
  DH-derived `/pub/` paths; content privacy comes from Noise
  (`ChaChaPoly_SHA256`), path privacy from the DH derivation.
- The identity secret key APIs (`signinWithSecret`, `signupWithSecret`) exist
  for tests against ephemeral testnets. Production browser code must use
  `startAuthFlow` and never hold the identity secret.
