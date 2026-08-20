use wasm_bindgen::prelude::*;

use crate::error::{js_err, js_err_msg};

/// Generate a random receiver-scoped Noise secret key (32 bytes).
///
/// Mirrors `paykit_sdk::ReceiverNoiseSecretKey::random()`: the key is an
/// independent random Ed25519 secret, never the Pubky identity secret. Store
/// it as a secret (e.g. account-scoped IndexedDB); it is required to restore
/// Encrypted Links and to derive private message paths.
#[wasm_bindgen(js_name = generateNoiseSecretKey)]
pub fn generate_noise_secret_key() -> Vec<u8> {
    pubky::Keypair::random().secret().to_vec()
}

pub(crate) fn secret_key_from_slice(bytes: &[u8]) -> Result<[u8; 32], JsValue> {
    bytes
        .try_into()
        .map_err(|_| js_err_msg("noise secret key must be exactly 32 bytes"))
}

/// Derive the public key published in a Receiver Marker from a receiver
/// Noise secret key. Returns the z-base-32 encoding.
///
/// Mirrors `paykit_sdk::ReceiverNoiseSecretKey::public_key()`.
#[wasm_bindgen(js_name = noisePublicKeyFromSecret)]
pub fn noise_public_key_from_secret(secret: &[u8]) -> Result<String, JsValue> {
    let bytes = secret_key_from_slice(secret)?;
    Ok(pubky::Keypair::from_secret(&bytes).public_key().z32())
}

pub(crate) fn public_key_from_z32(z32: &str, what: &str) -> Result<pubky::PublicKey, JsValue> {
    pubky::PublicKey::try_from(z32)
        .map_err(|err| js_err(&format!("invalid {what} public key"), err))
}
