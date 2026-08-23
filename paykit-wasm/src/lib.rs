//! Browser WASM binding for the Paykit Encrypted Link messaging surface.
//!
//! Scope: messaging only. This crate binds
//! - receiver-scoped Noise key generation (no Pubky identity key required),
//! - homeserver session acquisition (pubkyauth flow, plus signer helpers for
//!   dev/testnet use),
//! - Paykit Receiver Marker publish/fetch/remove (counterparty discovery),
//! - Encrypted Link handshake (initiate/accept/advance/restore),
//! - Private Application Message send/receive
//!   (`send_private_application_message_json` accepts unknown kinds),
//! - link/handshake snapshot serialization for caller-managed persistence,
//! - an in-memory Noise session (`MemoryNoiseSession`) exposing the same
//!   `pubky_noise` crypto without homeserver I/O, used by the package smoke
//!   test to prove the compiled crypto end to end.
//!
//! The payments surface of paykit-lib (payment requests, receipts, private
//! payment lists, endpoint routing) is intentionally not bound.

mod error;
mod keys;
mod link;
mod marker;
mod memory;
mod session;

pub use keys::*;
pub use link::*;
pub use marker::*;
pub use memory::*;
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
