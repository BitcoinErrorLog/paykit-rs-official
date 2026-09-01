# Vendored pubky 0.8.0

Source: crates.io `pubky` 0.8.0 (`25d85fdb77a0ee17213b1885f7d5c5d0536fa3ab11f93d395b4b5975c885467d`).

This tree is byte-identical to that crate except:

1. `Cargo.toml` / `Cargo.toml.orig` add native `rustls` 0.23 and `webpki-roots` 1, and disable doctests that need `pubky-testnet`.
2. `src/client/core.rs` configures Android `icann_http` with rustls + Mozilla/webpki roots instead of `rustls-platform-verifier`.

## Why

Paykit Android `ChatAuthFlow` polls the pubkyauth HTTP relay over ICANN HTTPS (`PubkyHttpClient::icann_http`). reqwest 0.13's default rustls backend uses `rustls-platform-verifier`, which on Android runs PKIX with revocation checking. Let's Encrypt YE1 leaves that omit an OCSP responder fail with `CertPathValidatorException: Certificate does not specify OCSP responder`, mapped to rustls `UnknownIssuer`. Relay polling then fails (`auth_flow_failed`) even though the chain is a valid public WebPKI chain.

The Paykit-specific `rustls-platform-verifier-android` missing-CRL soft-fail does not cover the OCSP-responder-absent error.

This follows pubky-homeserver PR 456: rustls with `webpki-roots`, no Android PKIX revocation hard-fail. Hostname, validity, signature, and chain validation remain enabled. Verification is not disabled, certificates are not pinned, and cleartext is not permitted. Non-Android native builds keep `rustls-platform-verifier`. PubkyTLS raw-public-key (`http`) is unchanged.

`PaykitAndroid.initializeOrThrow` remains required: pkarr relay HTTPS and other default-verifier clients still use the platform TrustManager.
