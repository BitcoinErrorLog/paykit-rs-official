# paykit-wasm browser e2e: homeserver-backed Encrypted Link flows

This document records what the Playwright browser e2e (`paykit-wasm/e2e/`)
proves, the exact environment it was proven against, how to re-run it, and
what it deliberately does not cover.

## What is proven

The e2e drives the actual `wasm-pack --target web` artifact (`paykit-wasm/pkg/`)
in real browser engines — **Chromium 151.0.7922.34, Firefox 153.0, and
WebKit 26.5** (Playwright 1.62.1) — against a **live Pubky testnet homeserver**
(pubky-core `f68014c1`, running in Docker). Two isolated browser contexts play
Alice (initiator) and Bob (responder). All 16 checks passed on all three
engines:

1. **Preflight** — the pkarr relay serves the homeserver's record; the
   homeserver HTTP root is reachable from the host.
2. **Sessions** — both contexts sign up fresh random Ed25519 identities on
   the homeserver with `signupWithSecret` (the dev/test keypair helper) and
   get authenticated sessions. Session cookies are browser-managed
   (`credentials: include`); `http://localhost:<static>` and
   `http://localhost:6286` are same-site, so cookies flow in all three
   engines.
3. **Session reload survival** — Alice calls `exportSession()` (secret-free
   base64 `SessionInfo` metadata), her page is RELOADED (wiping all wasm
   state but keeping the browser's HTTP-only session cookie), and
   `PubkyClient.restoreSession()` rehydrates a working session with the
   same pubky, no re-approval. Every subsequent Alice check in this suite —
   marker publish, handshake, message exchange — runs on the RESTORED
   session, proving it is fully functional, not merely present.
4. **Restore input validation** — `restoreSession()` with malformed input
   rejects with a clear `session restore failed` error instead of yielding
   a broken handle.
5. **Marker publish** — both contexts publish receiver markers at
   `marketplace/wallet` with `privatePayments = true`.
6. **Marker discovery** — each side fetches the *other* identity's marker
   through pkarr resolution + public storage read; noise public keys,
   receiver paths, and capability flags round-trip exactly.
7. **Clean None** — reading an unpublished marker path
   (`otherapp/wallet`) resolves to `undefined`, not an error.
8. **Handshake over homeserver transport** — `initiateEncryptedLink` /
   `acceptEncryptedLink` driven by alternating `advance()` calls complete the
   Noise XX handshake through homeserver outbox slots in 3 advance rounds
   per side.
9. **Link id convergence** — both sides' link snapshots contain the same
   32-byte link id (extracted from the snapshot wire format: the JSON
   `SnapshotWire.state` field is `PubkyNoiseSessionState`'s fixed binary
   layout, byte 108 = has_link_id, bytes 109..141 = link id). Identical ids
   prove the handshake transcripts converged.
10. **Alice → Bob message** — `sendPrivateApplicationMessageJson` with a
    marketplace-shaped kind (`marketplace.chat_message.v0`);
    `receivePrivateApplicationMessages` polling delivers it with the payload
    byte-for-byte intact (`JSON.parse(rawJson)` deep-equals the sent object;
    `version`/`kind` envelope fields decoded).
11. **Bob → Alice message** — same, opposite direction.
12. **Marker removal** — `removeReceiverMarker` on Bob's session; Alice's
    context then reads `undefined`.
13. **Snapshot** — Bob serializes the established link and his browser
    context is destroyed.
14. **Restore** — a brand-new context signs back in with `signinWithSecret`
    (homeserver resolved from the identity's pkarr record) and
    `restoreEncryptedLink` rebuilds the link from snapshot bytes.
15. **Multi-device survival (receive)** — the restored context receives a
    NEW message Alice sent after the original context was destroyed
    (`marketplace.order_update.v0`), payload intact.
16. **Multi-device survival (send)** — the restored context sends a message
    Alice receives, proving the outbound nonce/slot counters also survived
    the snapshot/restore cycle.

Fresh random identities are generated per run; the e2e is re-runnable
against a long-lived testnet without cleanup.

### Observed reliability

Across 10 recorded Chromium runs of the original 14-check suite, 9 passed
14/14 (~6–7 s each); one run failed transiently inside `signupWithSecret`
at session establishment and passed on immediate re-run. Firefox and WebKit
passed on their first attempts. After adding the session reload-survival
checks (16-check suite): the first Chromium run hit the same transient
pkarr-resolution failure — this time at the fresh-context `signinWithSecret`
in check 14, with the new checks 3/4 already passing — and the immediate
re-run plus first Firefox and WebKit runs passed 16/16. Treat isolated
signin/signup-time pkarr failures as environmental (relay/DHT publish
timing), not binding regressions.

## Exact environment

| Component | Value |
| --- | --- |
| Homeserver | pubky-core `f68014c111af0458e6a321e2d87a12479bfb3218` testnet image (`payments-env` compose project) |
| Homeserver public key | `8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo` |
| Signup | open (no signup token) |
| pkarr relay (host) | `127.0.0.1:25411` → container `15411` |
| Homeserver HTTP (host) | `127.0.0.1:16286` → container `6286` |
| Playwright | 1.62.1 (Chromium 151.0.7922.34, Firefox 153.0, WebKit 26.5) |
| Node | v22.14.0 |
| wasm artifact | `paykit-wasm/pkg/` (checksums in `paykit-wasm/README.md`) |

## Networking: why the port bridges exist

`PubkyClient.testnet()` (pubky 0.8.0) hardcodes the fixed local-testnet
topology on WASM:

- pkarr relay at `http://localhost:15411`
  (`pubky_common::constants::testnet_ports::PKARR_RELAY`);
- after resolving a `_pubky.<pk>` host through the relay, endpoints whose
  SVCB target is `localhost` are rewritten to
  `http://localhost:<HTTP_PORT>` where `HTTP_PORT` is the reserved SVC
  param (65280) from the pkarr record. The testnet homeserver's record
  advertises target `localhost`, HTTP_PORT `6286`, ipv4hint `127.0.0.1`.

The binding exposes no relay/port configuration (`new()` and `testnet()`
only), so when the testnet's ports are remapped by Docker (as in
payments-env: `25411`, `16286`), a browser client cannot be pointed at them
directly. `run.mjs` therefore opens two host-local TCP bridges before
launching the browsers:

- `127.0.0.1:15411` → `127.0.0.1:25411` (pkarr relay)
- `127.0.0.1:6286` → `127.0.0.1:16286` (homeserver HTTP)

If a natively running testnet already occupies those fixed ports, the
bridges detect `EADDRINUSE` and pass through. If you want the binding to
target arbitrary hosts/ports without bridges, it needs a constructor
accepting relay/host overrides (pubky 0.8.0's builder has
`testnet_with_host`; not currently exposed) — a candidate upstream change.

### CORS findings

No CORS obstacles: both the pkarr relay and the homeserver respond with
`access-control-allow-origin: <requesting origin>` and
`access-control-allow-credentials: true`, and preflights for
`POST /signup` (and other verbs) are accepted. Homeserver session cookies
work in all three engines because the harness origin and the homeserver are
both `http://localhost` (same-site; port differences don't matter for
SameSite).

The `404` console errors visible during a run are expected protocol
behavior: outbox polling and marker probes GET paths that don't exist yet
(pending handshake slots, unread message slots, removed/unpublished
markers), and the homeserver answers 404 for the clean "nothing there" case.

## How to re-run

```bash
# 1. Have a Pubky testnet running. Default configuration matches the
#    payments-env docker stack (host ports 25411 / 16286). Override with:
#      E2E_PKARR_RELAY_PORT, E2E_HOMESERVER_HTTP_PORT,
#      E2E_HOMESERVER_PUBKY, E2E_SIGNUP_TOKEN, E2E_STATIC_PORT
#
# 2. Have the wasm artifact built:
wasm-pack build paykit-wasm --target web --out-dir pkg --release

# 3. Run:
cd paykit-wasm/e2e
npm install
npx playwright install chromium        # + firefox webkit for the full matrix
node run.mjs                           # chromium (default)
E2E_BROWSER=firefox node run.mjs
E2E_BROWSER=webkit  node run.mjs
E2E_HEADED=1 node run.mjs              # watch it
```

The script exits 0 with `16/16 browser e2e checks passed` on success and
exits 1 with the failing assertion otherwise.

## What this e2e does NOT cover

- **`startAuthFlow` / `awaitApproval`** — the production session path
  requires a signer (Pubky Ring) approving a `pubkyauth:` URL. Only URL
  construction is covered (Node smoke test). The e2e uses the explicitly
  dev/test-only keypair helpers.
- **`restoreEncryptedLinkHandshake`** — mid-handshake snapshot/restore is
  compiled and bound but not e2e-exercised (the e2e restores an
  *established* link).
- **`clearEncryptedLinkOutbox`**, `setMaxSendRetries`,
  `setMaxRecoveryAttempts` — not exercised.
- **Write-failure recovery paths** — the testnet never produced transient
  homeserver write failures, so retry/recovery branches ran zero times.
- **Mainnet / public-relay topology** — this is the local pinned testnet;
  public pkarr relays, real DHT propagation latency, and HTTPS homeservers
  are untested from this binding.
- **Security review** — none. Upstream paykit-rs is pre-1.0 ("WIP - not for
  production"); this e2e proves functional behavior, not security.
