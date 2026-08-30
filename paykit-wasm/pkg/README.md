# paykit-wasm

Browser WASM binding for the **Paykit Encrypted Link messaging surface** and
**public Payment Endpoints**.

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

## What is bound

| Area | JS API |
| --- | --- |
| Receiver Noise keys | `generateNoiseSecretKey()`, `noisePublicKeyFromSecret()` (mirror `paykit_sdk::ReceiverNoiseSecretKey`) |
| Client / sessions | `PubkyClient` (`new`, `testnet`), `startAuthFlow(caps)` → `AuthFlowHandle.authorizationUrl()` / `awaitApproval()`; `SessionHandle.exportSession()` (secret-free metadata) + `PubkyClient.restoreSession()` (revalidates via the browser's HTTP-only session cookie) for reload survival; `PubkyClient.resumeSessionFromCookie(pubky)` — zero-approval session resume purely from the browser's existing cookie when the sign-in grant already covers `/pub/paykit/:rw`, with typed rejections (`SessionResumeUnauthorized` / `SessionResumePubkyMismatch` / `SessionResumeScopeMissing` via `Error.name`); `signinWithSecret` / `signupWithSecret` (dev/test only) |
| Receiver discovery | `publishReceiverMarker`, `getReceiverMarker`, `removeReceiverMarker`, `listPaykitReceiverPaths` |
| Handshake | `initiateEncryptedLink`, `acceptEncryptedLink`, `LinkHandshakeHandle.advance()/snapshot()/setMaxRecoveryAttempts()`, `restoreEncryptedLinkHandshake` |
| Messaging | `EncryptedLinkHandle.sendPrivateApplicationMessageJson()` (accepts unknown kinds by contract), `receivePrivateApplicationMessages()`, `snapshot()`, `setMaxSendRetries()`, `close()`, `restoreEncryptedLink`, `clearEncryptedLinkOutbox` |
| Public Payment Endpoints | `setPaymentEndpoint`, `removePaymentEndpoint`, `getPaymentEndpoint` (404 → `undefined`), `getPaymentList` / `listPaymentMethods` (404 → empty). Paths are built inside paykit-lib (`PAYKIT_PATH_PREFIX`, `/pub/paykit/v0`) — callers do not supply homeserver paths. |
| Private Payment Lists | `serializePrivatePaymentListJson`, `parsePrivatePaymentListJson`, `EncryptedLinkHandle.sendPrivatePaymentList()` (`set_private_payment_list`). There is no homeserver GET for private endpoints; inbound lists arrive as Encrypted Link messages. |
| Constants | `maxNoiseMessageLen()` (1000), `noiseTagLen()` (16) |
| Test/vector surface | `MemoryNoiseSession` — the same `pubky_noise::snow_crypto::DataLinkContext` crypto (Noise `XX_25519_ChaChaPoly_SHA256`) with caller-shuttled packets instead of homeserver outboxes; used by the smoke test |

**Not bound (deliberately):** Payment Requests (request/accept/reject/cancel/proof),
receipts, and the `paykit-sdk` stateful runtime (`SdkBackupState`, adapter-driven
`sync_public_endpoints`, `resolve_*_contact_payment`). Those need the SDK
session/store/adapter loop this crate does not host. Private endpoints are
Noise messages, not a second encrypted homeserver document type.

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
| `pkg/paykit_wasm_bg.wasm` | `a33b944c81b1661047b4d6f50ee41aab9342eef664a4e4f1470fcd94790949b5` |
| `pkg/paykit_wasm.js` | `9e0520f8f357d9c186828c9fefa4cceb52aa28389a05312fe359d7219a417507` |
| `pkg/paykit_wasm.d.ts` | `6196e530c54dd210d39235ad424c42ae26a9e6aa2bae120ee1a1366253c13c21` |
| `pkg/paykit_wasm_bg.wasm.d.ts` | `4489b880773d5fbab7cf1aec9ac77c7d39b4def6a235af45cf054340c0afe055` |
| `pkg/package.json` | `ecfde395fb97cdeec3cc22768601c483059a7e5b02a842eab260c83e2ef0c60f` |

Generated `pkg/` size: ~1.8 MB (wasm ~1.7 MB). `wasm-opt` output is not
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
enforcement of the 1000-byte message limit, `pubkyauth` URL construction, and
`resumeSessionFromCookie` input validation (an invalid pubky rejects before
any I/O).

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
`restoreEncryptedLink` in a fresh context that still receives and sends,
session `exportSession()` → page reload → `restoreSession()` reload survival,
and cookie-ONLY resume — exported metadata discarded across a second reload,
`resumeSessionFromCookie()` rebuilding the session from the browser cookie
alone, with a typed rejection for a cookieless pubky
(19/19 checks on all three engines). Setup, port-bridging rationale, CORS
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
