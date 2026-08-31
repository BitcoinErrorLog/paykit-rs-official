# Vendored pubky 0.8.0 (homeserver migration)

Source: crates.io `pubky` 0.8.0.

This is not the BitcoinErrorLog `pubky-core` main tree (still 0.6.0-rc.6).
paykit-wasm depends on the 0.8.0 API (`Keypair::from_secret`, reqwest 0.13,
pkarr 6). The same first three fixes landed in the `pubky-core-migration`
worktree on `fix/homeserver-migration`.

Patches relative to crates.io 0.8.0:

1. `publish_with_retries` re-resolves the latest signed packet after a pkarr
   CAS/concurrency failure, restores the CAS baseline in the pkarr cache
   (pkarr puts the new packet in cache before the remote PUT confirms),
   sleeps on WASM via `setTimeout`, and on the last force attempt omits
   If-Match so a stuck CAS cannot loop.
2. `PubkySigner::migrate_homeserver` plus signup HTTP 409 → sign-in at that
   host. Transport errors on `/signup` and `/session` retry with backoff.
   The hydrated session pubky is checked against the signer. Host-local
   data is not copied.
3. WASM endpoint selection prefers ICANN/HTTP (`HTTP_PORT`) over Pubky TLS
   for every host, not only `localhost`. That is required: browsers cannot
   speak Pubky TLS. `HTTP_PORT` rewrites the scheme to `http` for any host
   that advertises it.
4. WASM homeserver writes (`SessionStorage::put` / `delete`, JSON PUT,
   auth-relay POST/DELETE) consume the HTTP response body before returning
   `Ok`. reqwest's wasm `AbortGuard` aborts `fetch` when `Response` is
   dropped; discarding an unread 2xx write cancelled the request
   (`net::ERR_ABORTED`, `canceled=true`) before the homeserver committed.
   `Ok` now means the write completed. Remaining pkarr HTTPS SVCB records
   after browser endpoint selection are drained so stream `Drop` cannot sit
   on the same turn as the write. Resolver racing (pkarr GETs) is unchanged.
