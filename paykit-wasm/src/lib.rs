//! Browser WASM binding for the Paykit Encrypted Link messaging surface
//! and public Payment Endpoint routing.
//!
//! This crate binds
//! - receiver-scoped Noise key generation (no Pubky identity key required),
//! - homeserver session acquisition (pubkyauth flow, plus signer helpers for
//!   dev/testnet use, including `migrateHomeserverWithSecret`),
//! - Paykit Receiver Marker publish/fetch/remove (counterparty discovery),
//! - Encrypted Link handshake (initiate/accept/advance/restore),
//! - Private Application Message send/receive
//!   (`send_private_application_message_json` accepts unknown kinds),
//! - link/handshake snapshot serialization for caller-managed persistence,
//! - an in-memory Noise session (`MemoryNoiseSession`) exposing the same
//!   `pubky_noise` crypto without homeserver I/O, used by the package smoke
//!   test to prove the compiled crypto end to end.
//! - SB2 encrypt/sign/verify/decrypt, inbox_kid, and X25519 key generation
//!   (`pubky-crypto`, no crypto reimplemented here),
//! - UKD AppCert signature verification (`verifyAppCert`),
//! - session-scoped public PUT/DELETE, unauthenticated public GET, and
//!   homeserver sign-out,
//! - public Payment Endpoint publish/fetch/list/remove (paykit-lib writers;
//!   paths stay inside `PAYKIT_PATH_PREFIX`),
//! - Private Payment List serialize/parse and send over an established
//!   Encrypted Link (`set_private_payment_list`).
//!
//! Not bound: Payment Requests, receipts, and the paykit-sdk adapter
//! runtime (those need stateful SDK machinery this crate does not host).

mod app_cert;
mod error;
mod keys;
mod link;
mod marker;
mod memory;
mod payments;
mod sb2;
mod session;

pub use app_cert::*;
pub use keys::*;
pub use link::*;
pub use marker::*;
pub use memory::*;
pub use payments::*;
pub use sb2::*;
pub use session::*;

use wasm_bindgen::prelude::*;

/// Maximum plaintext size of one Private Application Message, in bytes.
///
/// This is `pubky_noise`'s fixed message buffer (1000 bytes). JSON envelope
/// bytes count against it; callers should budget payloads accordingly.
#[wasm_bindgen(js_name = maxNoiseMessageLen)]
pub fn max_noise_message_len() -> usize {
    pubky_noise::snow_crypto::PUBKY_NOISE_MSG_LEN
}

/// AEAD tag overhead per encrypted Noise message, in bytes.
#[wasm_bindgen(js_name = noiseTagLen)]
pub fn noise_tag_len() -> usize {
    pubky_noise::snow_crypto::PUBKY_NOISE_TAG_LEN
}
