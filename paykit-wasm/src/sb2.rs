use wasm_bindgen::prelude::*;

use crate::error::js_err_msg;
use crate::keys::{hex_encode, owner_peerid_bytes};

fn set(obj: &js_sys::Object, key: &str, value: &JsValue) {
    let _ = js_sys::Reflect::set(obj, &JsValue::from_str(key), value);
}

/// Generate a random X25519 keypair.
///
/// Returns `{ publicKey, secretKey }` as lowercase 64-character hex strings.
/// This is **not** `generateNoiseSecretKey` (that is an Ed25519 seed).
///
/// Binds `pubky_crypto::sealed_blob::x25519_generate_keypair`.
#[wasm_bindgen(js_name = x25519GenerateKeypair)]
pub fn x25519_generate_keypair_js() -> js_sys::Object {
    let (public_key, secret_key) = x25519_generate_keypair_hex();
    let obj = js_sys::Object::new();
    set(&obj, "publicKey", &JsValue::from_str(&public_key));
    set(&obj, "secretKey", &JsValue::from_str(&secret_key));
    obj
}

pub(crate) fn x25519_generate_keypair_hex() -> (String, String) {
    let (secret, public) = pubky_crypto::sealed_blob::x25519_generate_keypair();
    (hex_encode(&public), hex_encode(&secret))
}

/// Verify the Ed25519 signature on an SB2 envelope.
///
/// Returns `true` when a signature is present and valid, `false` when no
/// signature is present. Rejects when a signature is present but invalid
/// (mirrors `pubky_noise` UniFFI `sb2_verify_signature`).
///
/// `ownerPubky` accepts z-base-32 or 64-hex and is normalized to 32 bytes.
#[wasm_bindgen(js_name = sb2VerifySignature)]
pub fn sb2_verify_signature_js(
    envelope: &[u8],
    owner_pubky: &str,
    canonical_path: &str,
) -> Result<bool, JsValue> {
    sb2_verify_signature(envelope, owner_pubky, canonical_path).map_err(|err| js_err_msg(&err))
}

pub(crate) fn sb2_verify_signature(
    envelope: &[u8],
    owner_pubky: &str,
    canonical_path: &str,
) -> Result<bool, String> {
    let owner = owner_peerid_bytes(owner_pubky)?;
    let sb2 = pubky_crypto::sealed_blob_v2::Sb2::decode(envelope)
        .map_err(|err| format!("sb2 decode failed: {err}"))?;
    sb2.verify_signature(&owner, canonical_path)
        .map_err(|err| format!("sb2 signature verification failed: {err}"))
}

/// Decrypt an SB2 envelope for the recipient X25519 secret key.
///
/// Binds `Sb2::decode` + `Sb2::decrypt`. `ownerPubky` accepts z-base-32 or
/// 64-hex. `canonicalPath` must match the path bound into the AAD at encrypt.
#[wasm_bindgen(js_name = sb2Decrypt)]
pub fn sb2_decrypt_js(
    envelope: &[u8],
    recipient_sk: &[u8],
    owner_pubky: &str,
    canonical_path: &str,
) -> Result<Vec<u8>, JsValue> {
    sb2_decrypt(envelope, recipient_sk, owner_pubky, canonical_path).map_err(|err| js_err_msg(&err))
}

pub(crate) fn sb2_decrypt(
    envelope: &[u8],
    recipient_sk: &[u8],
    owner_pubky: &str,
    canonical_path: &str,
) -> Result<Vec<u8>, String> {
    let recipient: [u8; 32] = recipient_sk
        .try_into()
        .map_err(|_| "recipient secret key must be exactly 32 bytes".to_string())?;
    let owner = owner_peerid_bytes(owner_pubky)?;
    let sb2 = pubky_crypto::sealed_blob_v2::Sb2::decode(envelope)
        .map_err(|err| format!("sb2 decode failed: {err}"))?;
    sb2.decrypt(&recipient, &owner, canonical_path)
        .map_err(|err| format!("sb2 decrypt failed: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{hex_encode, public_key_from_z32_or_hex};
    use ed25519_dalek::SigningKey;
    use pubky_crypto::sealed_blob::x25519_generate_keypair;
    use pubky_crypto::sealed_blob_v2::Sb2;

    fn random_32() -> [u8; 32] {
        pubky::Keypair::random().secret()
    }

    fn owner_identity() -> (SigningKey, [u8; 32], String, String) {
        let secret = random_32();
        let signing_key = SigningKey::from_bytes(&secret);
        let peerid = signing_key.verifying_key().to_bytes();
        let pubky = pubky::PublicKey::from(
            pubky::pkarr::PublicKey::try_from(peerid.as_slice()).expect("ed25519 public key"),
        );
        (signing_key, peerid, pubky.z32(), hex_encode(&peerid))
    }

    fn encrypt_sb2(
        recipient_pk: &[u8; 32],
        plaintext: &[u8],
        owner_peerid: &[u8; 32],
        sender_peerid: &[u8; 32],
        path: &str,
    ) -> Sb2 {
        Sb2::encrypt(
            recipient_pk,
            plaintext,
            random_32(),
            Some("req_001".into()),
            Some("request".into()),
            owner_peerid,
            sender_peerid,
            &random_32(),
            path,
            Some(1_704_067_200),
            Some(1_704_153_600),
        )
        .expect("encrypt")
    }

    #[test]
    fn x25519_keypair_is_hex_and_not_an_ed25519_noise_key() {
        let (public_key, secret_key) = x25519_generate_keypair_hex();
        assert_eq!(public_key.len(), 64);
        assert_eq!(secret_key.len(), 64);
        assert!(public_key.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(secret_key.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(public_key, secret_key);

        let (sk, pk) = x25519_generate_keypair();
        let derived = pubky_crypto::sealed_blob::x25519_public_from_secret(&sk);
        assert_eq!(derived, pk);
        let noise = crate::generate_noise_secret_key();
        assert_eq!(noise.len(), 32);
        assert_ne!(hex_encode(&sk), hex_encode(&noise));
    }

    #[test]
    fn sb2_unsigned_round_trip_verify_false_then_decrypt() {
        let (recipient_sk, recipient_pk) = x25519_generate_keypair();
        let (_, owner_peerid, owner_z32, owner_hex) = owner_identity();
        let path = "/pub/paykit.app/v0/handoff/abc";
        let plaintext = b"Hello, SB2!";
        let encoded =
            encrypt_sb2(&recipient_pk, plaintext, &owner_peerid, &owner_peerid, path).encode();

        assert_eq!(
            sb2_verify_signature(&encoded, &owner_z32, path).expect("verify z32"),
            false
        );
        assert_eq!(
            sb2_verify_signature(&encoded, &owner_hex, path).expect("verify hex"),
            false
        );
        assert_eq!(
            sb2_decrypt(&encoded, &recipient_sk, &owner_z32, path).expect("decrypt z32"),
            plaintext
        );
        assert_eq!(
            sb2_decrypt(&encoded, &recipient_sk, &owner_hex, path).expect("decrypt hex"),
            plaintext
        );
    }

    #[test]
    fn sb2_signed_round_trip_verify_and_decrypt() {
        let (recipient_sk, recipient_pk) = x25519_generate_keypair();
        let (signing_key, owner_peerid, owner_z32, owner_hex) = owner_identity();
        let path = "/pub/paykit.app/v0/requests/abc/req_002";
        let plaintext = b"Signed message";
        let mut sb2 = encrypt_sb2(&recipient_pk, plaintext, &owner_peerid, &owner_peerid, path);
        sb2.sign(&signing_key, &owner_peerid, path);
        let encoded = sb2.encode();

        assert!(sb2_verify_signature(&encoded, &owner_z32, path).expect("verify z32"));
        assert!(sb2_verify_signature(&encoded, &owner_hex, path).expect("verify hex"));
        assert_eq!(
            sb2_decrypt(&encoded, &recipient_sk, &owner_z32, path).expect("decrypt"),
            plaintext
        );
        let _ = public_key_from_z32_or_hex(&owner_z32, "owner").expect("z32 still parses");
    }

    #[test]
    fn sb2_present_but_invalid_signature_is_an_error() {
        let (_, recipient_pk) = x25519_generate_keypair();
        let (signing_key, owner_peerid, owner_z32, _) = owner_identity();
        let path = "/pub/paykit.app/v0/handoff/req";
        let mut sb2 = encrypt_sb2(&recipient_pk, b"signed", &owner_peerid, &owner_peerid, path);
        sb2.sign(&signing_key, &owner_peerid, path);
        let encoded = sb2.encode();

        let err =
            sb2_verify_signature(&encoded, &owner_z32, "/pub/other/path").expect_err("wrong path");
        assert!(
            err.contains("sb2 signature verification failed"),
            "got: {err}"
        );
    }

    #[test]
    fn sb2_decode_rejects_garbage() {
        let (_, _, owner_z32, _) = owner_identity();
        assert!(sb2_verify_signature(b"not-sb2", &owner_z32, "/pub/x").is_err());
        assert!(sb2_decrypt(b"JSON", &[0u8; 32], &owner_z32, "/p").is_err());
        assert!(sb2_decrypt(&[0u8; 16], &[0u8; 16], &owner_z32, "/p").is_err());
    }
}
