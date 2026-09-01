# Vendored pkarr 6.0.0

Source: crates.io `pkarr` 6.0.0 (`997d5cbd9be48de01468085ecb82e951b82a04496cd76b1b3a1ea20b2fa84107`).

This tree is byte-identical to that crate except:

1. `Cargo.toml` / `Cargo.toml.orig` add optional native `webpki-roots` 1 to the `tls` feature, `rcgen` 0.14 as a dev-dependency for TLS fixture tests, and an unused `internal-relay-tests` feature (see item 5).
2. `src/android_webpki_https.rs` (new) builds rustls + Mozilla/`webpki` HTTPS for Android ICANN hosts.
3. `src/lib.rs` exports `android_webpki_https` when `tls` is enabled on native targets.
4. `src/client/relays.rs` uses that config for `RelaysClient` HTTPS on Android.
5. `src/client.rs` does not compile the upstream `pkarr-relay` path-crate integration tests (`internal-relay-tests` feature, not enabled). Those tests are unpublished on crates.io.
6. `src/extra/lmdb_cache.rs` caps `MAX_MAP_SIZE` with `usize::MAX` on 32-bit targets so `armeabi-v7a` / `x86` Android builds do not fail `overflowing_literals`. 64-bit keeps the upstream 10 TB cap.

## Why

`RelaysClient` built `reqwest::Client::builder()` with no TLS backend override. reqwest 0.13 rustls defaults to `rustls-platform-verifier`. On Android that PKIX path hard-fails Let's Encrypt YE1 leaves that omit an OCSP responder (`Certificate does not specify OCSP responder` → `UnknownIssuer`). Default relays are `https://pkarr.pubky.app` and `https://pkarr.pubky.org`, which present that profile.

There is no upstream custom-client injection on pkarr 6.0.0. This vendor installs rustls + `webpki-roots` on Android only.

## Security posture

- Hostname, validity, signature, EKU/KU, and chain-to-Mozilla-root checks remain enabled via rustls `WebPkiServerVerifier`.
- **No revocation checking.** A revoked-but-unexpired certificate that still chains to a Mozilla root is accepted. This matches browser/`WebPKI`-root posture and pubky-homeserver PR 456.
- Verification is not disabled, certificates are not pinned, cleartext is not permitted, and there is no host allowlist bypass.
- Non-Android native builds keep reqwest's default rustls-platform-verifier for `RelaysClient`.
- PubkyTLS raw-public-key homeserver verification (`src/extra/tls.rs`, `reqwest-builder`) is unchanged.
- Signed-packet verification is unchanged.
- ALPN is `http/1.1` only: Paykit/pubky reqwest is built without `http2`. Advertising `h2` would risk a protocol mismatch.

`PaykitAndroid.initializeOrThrow` remains the initializer for any remaining default-verifier clients. Android `RelaysClient` HTTPS no longer consults that verifier.
