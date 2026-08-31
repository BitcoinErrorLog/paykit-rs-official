use wasm_bindgen::prelude::*;

use crate::error::js_err_msg;
use crate::keys::{hex_decode_32, hex_encode, owner_peerid_bytes, parse_public_key_z32_or_hex};

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

/// Compute `inbox_kid` for a recipient InboxKey X25519 public key.
///
/// `inbox_kid = first_16_bytes(SHA256(x25519_pub))`, returned as lowercase
/// 32-character hex. `x25519PubHex` is a 64-character hex public key (the
/// form returned by `x25519GenerateKeypair`).
///
/// Binds `pubky_crypto::sealed_blob_v2::Sb2Header::compute_inbox_kid`.
#[wasm_bindgen(js_name = computeInboxKid)]
pub fn compute_inbox_kid_js(x25519_pub_hex: &str) -> Result<String, JsValue> {
    compute_inbox_kid(x25519_pub_hex).map_err(|err| js_err_msg(&err))
}

pub(crate) fn compute_inbox_kid(x25519_pub_hex: &str) -> Result<String, String> {
    let pk = hex_decode_32(x25519_pub_hex.trim())
        .map_err(|err| format!("invalid X25519 public key: {err}"))?;
    let kid = pubky_crypto::sealed_blob_v2::Sb2Header::compute_inbox_kid(&pk);
    Ok(hex_encode(&kid))
}

fn bytes_32(value: &[u8], what: &str) -> Result<[u8; 32], String> {
    value
        .try_into()
        .map_err(|_| format!("{what} must be exactly 32 bytes"))
}

fn bytes_16(value: &[u8], what: &str) -> Result<[u8; 16], String> {
    value
        .try_into()
        .map_err(|_| format!("{what} must be exactly 16 bytes"))
}

fn peerid_bytes(value: &str, what: &str) -> Result<[u8; 32], String> {
    Ok(*parse_public_key_z32_or_hex(value, what)?.as_bytes())
}

/// Encrypt plaintext to an unsigned SB2 binary envelope.
///
/// Binds `Sb2::encrypt_with_cert_id` + `Sb2::encode`. Does not reimplement
/// the cipher. Plaintext is capped at 64 KiB and `msg_id` at 128 ASCII
/// characters by the encoder. `ownerPubky`, `senderPeerid`, and
/// `recipientPeerid` accept z-base-32 or 64-hex.
///
/// Call `sb2Sign` afterwards when the envelope must authenticate the sender.
#[wasm_bindgen(js_name = sb2Encrypt)]
#[allow(clippy::too_many_arguments)]
pub fn sb2_encrypt_js(
    recipient_inbox_pk: &[u8],
    plaintext: &[u8],
    context_id: &[u8],
    msg_id: Option<String>,
    purpose: Option<String>,
    owner_pubky: &str,
    sender_peerid: &str,
    recipient_peerid: &str,
    canonical_path: &str,
    created_at: Option<u64>,
    expires_at: Option<u64>,
    cert_id: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    sb2_encrypt(
        recipient_inbox_pk,
        plaintext,
        context_id,
        msg_id,
        purpose,
        owner_pubky,
        sender_peerid,
        recipient_peerid,
        canonical_path,
        created_at,
        expires_at,
        cert_id.as_deref(),
    )
    .map_err(|err| js_err_msg(&err))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sb2_encrypt(
    recipient_inbox_pk: &[u8],
    plaintext: &[u8],
    context_id: &[u8],
    msg_id: Option<String>,
    purpose: Option<String>,
    owner_pubky: &str,
    sender_peerid: &str,
    recipient_peerid: &str,
    canonical_path: &str,
    created_at: Option<u64>,
    expires_at: Option<u64>,
    cert_id: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let recipient_pk = bytes_32(recipient_inbox_pk, "recipient inbox public key")?;
    let context = bytes_32(context_id, "context id")?;
    let owner = owner_peerid_bytes(owner_pubky)?;
    let sender = peerid_bytes(sender_peerid, "sender")?;
    let recipient = peerid_bytes(recipient_peerid, "recipient")?;
    let cert = match cert_id {
        Some(bytes) => Some(bytes_16(bytes, "cert id")?),
        None => None,
    };
    let sb2 = pubky_crypto::sealed_blob_v2::Sb2::encrypt_with_cert_id(
        &recipient_pk,
        plaintext,
        context,
        msg_id,
        purpose,
        &owner,
        &sender,
        &recipient,
        canonical_path,
        created_at,
        expires_at,
        cert,
    )
    .map_err(|err| format!("sb2 encrypt failed: {err}"))?;
    Ok(sb2.encode())
}

/// Sign an SB2 envelope with the sender's Ed25519 secret key.
///
/// Binds `Sb2::decode` + `Sb2::sign` + `Sb2::encode`. `ownerPubky` accepts
/// z-base-32 or 64-hex and must match the path bound into the AAD at encrypt.
#[wasm_bindgen(js_name = sb2Sign)]
pub fn sb2_sign_js(
    envelope: &[u8],
    sender_ed25519_sk: &[u8],
    owner_pubky: &str,
    canonical_path: &str,
) -> Result<Vec<u8>, JsValue> {
    sb2_sign(envelope, sender_ed25519_sk, owner_pubky, canonical_path)
        .map_err(|err| js_err_msg(&err))
}

pub(crate) fn sb2_sign(
    envelope: &[u8],
    sender_ed25519_sk: &[u8],
    owner_pubky: &str,
    canonical_path: &str,
) -> Result<Vec<u8>, String> {
    let sender_sk = bytes_32(sender_ed25519_sk, "sender Ed25519 secret key")?;
    let owner = owner_peerid_bytes(owner_pubky)?;
    let mut sb2 = pubky_crypto::sealed_blob_v2::Sb2::decode(envelope)
        .map_err(|err| format!("sb2 decode failed: {err}"))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sender_sk);
    sb2.sign(&signing_key, &owner, canonical_path);
    Ok(sb2.encode())
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

        assert!(!sb2_verify_signature(&encoded, &owner_z32, path).expect("verify z32"));
        assert!(!sb2_verify_signature(&encoded, &owner_hex, path).expect("verify hex"));
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

    fn encrypt_via_export(
        recipient_pk: &[u8; 32],
        plaintext: &[u8],
        owner: &str,
        sender: &str,
        recipient_peerid: &str,
        path: &str,
        msg_id: Option<String>,
    ) -> Result<Vec<u8>, String> {
        sb2_encrypt(
            recipient_pk,
            plaintext,
            &random_32(),
            msg_id,
            Some("request".into()),
            owner,
            sender,
            recipient_peerid,
            path,
            Some(1_704_067_200),
            Some(1_704_153_600),
            None,
        )
    }

    #[test]
    fn compute_inbox_kid_matches_header_and_rejects_bad_hex() {
        let (_, recipient_pk) = x25519_generate_keypair();
        let expected = hex_encode(&pubky_crypto::sealed_blob_v2::Sb2Header::compute_inbox_kid(
            &recipient_pk,
        ));
        assert_eq!(
            compute_inbox_kid(&hex_encode(&recipient_pk)).expect("kid"),
            expected
        );
        assert!(compute_inbox_kid("zz").is_err());
        assert!(compute_inbox_kid(&"ab".repeat(16)).is_err());
    }

    #[test]
    fn sb2_encrypt_round_trips_unsigned_then_signed() {
        let (recipient_sk, recipient_pk) = x25519_generate_keypair();
        let (signing_key, _, owner_z32, owner_hex) = owner_identity();
        let path = "/pub/paykit.app/v0/handoff/export";
        let plaintext = b"wasm export plaintext";

        let unsigned = encrypt_via_export(
            &recipient_pk,
            plaintext,
            &owner_z32,
            &owner_z32,
            &owner_z32,
            path,
            Some("req_export".into()),
        )
        .expect("encrypt z32");
        assert!(!sb2_verify_signature(&unsigned, &owner_z32, path).expect("verify unsigned"));
        assert_eq!(
            sb2_decrypt(&unsigned, &recipient_sk, &owner_z32, path).expect("decrypt unsigned"),
            plaintext
        );

        let signed = sb2_sign(&unsigned, signing_key.as_bytes(), &owner_hex, path).expect("sign");
        assert!(sb2_verify_signature(&signed, &owner_z32, path).expect("verify signed z32"));
        assert!(sb2_verify_signature(&signed, &owner_hex, path).expect("verify signed hex"));
        assert_eq!(
            sb2_decrypt(&signed, &recipient_sk, &owner_hex, path).expect("decrypt signed"),
            plaintext
        );
    }

    #[test]
    fn sb2_encrypt_rejects_wrong_recipient_key() {
        let (_, recipient_pk) = x25519_generate_keypair();
        let (other_sk, _) = x25519_generate_keypair();
        let (_, _, owner_z32, _) = owner_identity();
        let path = "/pub/paykit.app/v0/handoff/wrong-recipient";
        let encoded = encrypt_via_export(
            &recipient_pk,
            b"secret",
            &owner_z32,
            &owner_z32,
            &owner_z32,
            path,
            Some("req_wrong_rk".into()),
        )
        .expect("encrypt");
        let err = sb2_decrypt(&encoded, &other_sk, &owner_z32, path).expect_err("wrong sk");
        assert!(err.contains("sb2 decrypt failed"), "got: {err}");
    }

    #[test]
    fn sb2_encrypt_rejects_wrong_canonical_path() {
        let (recipient_sk, recipient_pk) = x25519_generate_keypair();
        let (_, _, owner_z32, _) = owner_identity();
        let path = "/pub/paykit.app/v0/handoff/correct";
        let encoded = encrypt_via_export(
            &recipient_pk,
            b"bound-path",
            &owner_z32,
            &owner_z32,
            &owner_z32,
            path,
            Some("req_wrong_path".into()),
        )
        .expect("encrypt");
        let err = sb2_decrypt(
            &encoded,
            &recipient_sk,
            &owner_z32,
            "/pub/paykit.app/v0/handoff/other",
        )
        .expect_err("wrong path");
        assert!(err.contains("sb2 decrypt failed"), "got: {err}");
    }

    #[test]
    fn sb2_encrypt_rejects_tampered_ciphertext() {
        let (recipient_sk, recipient_pk) = x25519_generate_keypair();
        let (_, _, owner_z32, _) = owner_identity();
        let path = "/pub/paykit.app/v0/handoff/tamper";
        let mut encoded = encrypt_via_export(
            &recipient_pk,
            b"do not flip",
            &owner_z32,
            &owner_z32,
            &owner_z32,
            path,
            Some("req_tamper".into()),
        )
        .expect("encrypt");
        let last = encoded.len() - 1;
        encoded[last] ^= 0x01;
        let err = sb2_decrypt(&encoded, &recipient_sk, &owner_z32, path).expect_err("tamper");
        assert!(err.contains("sb2 decrypt failed"), "got: {err}");
    }

    #[test]
    fn sb2_encrypt_rejects_oversized_plaintext() {
        let (_, recipient_pk) = x25519_generate_keypair();
        let (_, _, owner_z32, _) = owner_identity();
        let too_big = vec![0u8; pubky_crypto::sealed_blob::MAX_PLAINTEXT_SIZE + 1];
        let err = encrypt_via_export(
            &recipient_pk,
            &too_big,
            &owner_z32,
            &owner_z32,
            &owner_z32,
            "/pub/paykit.app/v0/handoff/big",
            Some("req_big".into()),
        )
        .expect_err("oversized plaintext");
        assert!(
            err.contains("exceeds max") || err.contains("sb2 encrypt failed"),
            "got: {err}"
        );
    }

    #[test]
    fn sb2_encrypt_rejects_oversized_msg_id() {
        let (_, recipient_pk) = x25519_generate_keypair();
        let (_, _, owner_z32, _) = owner_identity();
        let too_long = "a".repeat(pubky_crypto::sealed_blob_v2::MAX_MSG_ID_LEN + 1);
        let err = encrypt_via_export(
            &recipient_pk,
            b"ok",
            &owner_z32,
            &owner_z32,
            &owner_z32,
            "/pub/paykit.app/v0/handoff/msgid",
            Some(too_long),
        )
        .expect_err("oversized msg_id");
        assert!(
            err.contains("msg_id exceeds") || err.contains("sb2 encrypt failed"),
            "got: {err}"
        );
    }
}
