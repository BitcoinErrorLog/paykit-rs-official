# Vendored pubky 0.8.0 (homeserver migration)

Source: crates.io `pubky` 0.8.0.

This is not the BitcoinErrorLog `pubky-core` main tree (still 0.6.0-rc.6).
paykit-wasm depends on the 0.8.0 API (`Keypair::from_secret`, reqwest 0.13,
pkarr 6). The same three fixes landed in the `pubky-core-migration` worktree
on `fix/homeserver-migration`.

Patches relative to crates.io 0.8.0:

1. `publish_with_retries` re-resolves the latest signed packet after a pkarr
   CAS/concurrency failure, with bounded backoff.
2. `PubkySigner::migrate_homeserver` plus signup HTTP 409 → sign-in at that
   host. Host-local data is not copied.
3. WASM endpoint selection prefers ICANN/HTTP (`HTTP_PORT`) over Pubky TLS
   for every host, not only `localhost`.
