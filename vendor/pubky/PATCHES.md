# Vendored pubky 0.8.0

Source: crates.io `pubky` 0.8.0 (`25d85fdb77a0ee17213b1885f7d5c5d0536fa3ab11f93d395b4b5975c885467d`).

This tree is byte-identical to that crate except:

1. `Cargo.toml` / `Cargo.toml.orig` disable doctests that need `pubky-testnet`. `Cargo.toml` also sets crates.io `clippy::pedantic` and `clippy::cargo` groups to `allow` so Paykit workspace `clippy -- -D warnings` still compiles this crate without treating upstream pedantic findings or sibling-package cargo metadata as errors.
2. `src/client/core.rs` configures Android `icann_http` with the shared pkarr Android WebPKI helper (`pkarr::android_webpki_https::apply_mozilla_webpki_https`) instead of `rustls-platform-verifier`.
3. `Cargo.lock` from the crates.io package is omitted. The published crate ships that lockfile; this vendor does not track it. The integrity allowlist entry `Cargo.lock` is that deletion only — the file is not rewritten or replaced.

## Why

Paykit Android `ChatAuthFlow` polls the pubkyauth HTTP relay over ICANN HTTPS (`PubkyHttpClient::icann_http`). reqwest 0.13's default rustls backend uses `rustls-platform-verifier`, which on Android runs PKIX with revocation checking. Let's Encrypt YE1 leaves that omit an OCSP responder fail with `CertPathValidatorException: Certificate does not specify OCSP responder`, mapped to rustls `UnknownIssuer`. Relay polling then fails (`auth_flow_failed`) even though the chain is a valid public WebPKI chain.

The Paykit-specific `rustls-platform-verifier-android` missing-CRL soft-fail does not cover the OCSP-responder-absent error.

This follows pubky-homeserver PR 456 and the vendored pkarr 6.0.0 Android WebPKI helper: rustls with `webpki-roots`, no Android PKIX revocation hard-fail.

## Security posture

- Hostname, validity, signature, EKU/KU, and chain-to-Mozilla-root checks remain enabled.
- **No revocation checking.** A revoked-but-unexpired certificate that still chains to a Mozilla root is accepted. This matches browser/`WebPKI`-root posture and pubky-homeserver PR 456.
- Verification is not disabled, certificates are not pinned, and cleartext is not permitted.
- Non-Android native builds keep `rustls-platform-verifier` for `icann_http`.
- PubkyTLS raw-public-key (`http`, from pkarr `reqwest-builder`) is unchanged.
- ALPN is `http/1.1` only because these reqwest clients are built without `http2`.

`PaykitAndroid.initializeOrThrow` remains required for any remaining default-verifier clients. ChatAuthFlow ICANN HTTP and (via vendored pkarr) RelaysClient HTTPS do not consult that verifier.
