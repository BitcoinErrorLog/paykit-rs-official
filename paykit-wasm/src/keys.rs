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

/// Encode bytes as lowercase hex. Used by `x25519GenerateKeypair` and tests.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn is_64_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| hex_nibble(b).is_some())
}

pub(crate) fn hex_decode_32(value: &str) -> Result<[u8; 32], String> {
    if !is_64_hex(value) {
        return Err("expected 64 hex characters".to_string());
    }
    let bytes = value.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(bytes[i * 2]).expect("is_64_hex");
        let lo = hex_nibble(bytes[i * 2 + 1]).expect("is_64_hex");
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Parse an owner pubky as z-base-32 (or `pubky`+z32) **or** 64-hex, then
/// normalize to a `PublicKey`. Hex is the form mobile's SB2 wrapper passes;
/// z32 is what Ring's callback emits. String errors so native tests can
/// assert without constructing `js_sys::Error`.
pub(crate) fn parse_public_key_z32_or_hex(
    value: &str,
    what: &str,
) -> Result<pubky::PublicKey, String> {
    let value = value.trim();
    if is_64_hex(value) {
        let bytes = hex_decode_32(value)?;
        let inner = pubky::pkarr::PublicKey::try_from(bytes.as_slice())
            .map_err(|err| format!("invalid {what} public key: {err}"))?;
        return Ok(pubky::PublicKey::from(inner));
    }
    pubky::PublicKey::try_from(value).map_err(|err| format!("invalid {what} public key: {err}"))
}

pub(crate) fn public_key_from_z32_or_hex(
    value: &str,
    what: &str,
) -> Result<pubky::PublicKey, JsValue> {
    parse_public_key_z32_or_hex(value, what).map_err(|err| js_err_msg(&err))
}

pub(crate) fn owner_peerid_bytes(owner_pubky: &str) -> Result<[u8; 32], String> {
    Ok(*parse_public_key_z32_or_hex(owner_pubky, "owner")?.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_Z32: &str = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo";

    #[test]
    fn owner_accepts_z32_and_matching_64_hex() {
        let from_z32 = public_key_from_z32_or_hex(KNOWN_Z32, "owner").expect("z32");
        let hex = hex_encode(from_z32.as_bytes());
        assert_eq!(hex.len(), 64);
        let from_hex = public_key_from_z32_or_hex(&hex, "owner").expect("hex");
        assert_eq!(from_z32.as_bytes(), from_hex.as_bytes());
        let from_upper =
            public_key_from_z32_or_hex(&hex.to_ascii_uppercase(), "owner").expect("HEX");
        assert_eq!(from_z32.as_bytes(), from_upper.as_bytes());
    }

    #[test]
    fn owner_rejects_neither_z32_nor_hex() {
        assert!(parse_public_key_z32_or_hex("not-a-key", "owner").is_err());
        assert!(parse_public_key_z32_or_hex("zz", "owner").is_err());
    }

    #[test]
    fn hex_round_trip_32_bytes() {
        let bytes = [0x0fu8; 32];
        let encoded = hex_encode(&bytes);
        assert_eq!(encoded, "0f".repeat(32));
        assert_eq!(hex_decode_32(&encoded).expect("decode"), bytes);
    }
}
