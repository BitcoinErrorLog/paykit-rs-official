//! Standalone XChaCha20-Poly1305 AEAD for arbitrary attachment bytes.
//!
//! This is a general-purpose symmetric AEAD: a random 32-byte key encrypts a
//! blob, the ciphertext can be stored anywhere (including a world-readable
//! homeserver), and the key is delivered separately. It is not tied to
//! receipts or payments.
//!
//! Encoding matches [`crate::ReceiptDecryptionKey`]: base64url without padding.

use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{PaykitError, Result};

/// Algorithm label written into [`AttachmentCiphertext::algorithm`].
pub const ATTACHMENT_ENCRYPTION_ALGORITHM: &str = "XChaCha20Poly1305";

const ATTACHMENT_KEY_LEN: usize = 32;
const ATTACHMENT_NONCE_LEN: usize = 24;

/// Symmetric key used to encrypt and decrypt an attachment blob.
///
/// The key material is intentionally redacted from [`Debug`](std::fmt::Debug)
/// and [`Display`](std::fmt::Display). Use [`as_str`](Self::as_str) only when
/// serializing the key for an Encrypted Link or storing it securely.
///
/// The in-memory key bytes are zeroized on drop as defense-in-depth.
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentKey(String);

impl AttachmentKey {
    /// Generate a fresh 256-bit attachment key encoded as base64url (no padding).
    pub fn generate() -> Self {
        let mut key = XChaCha20Poly1305::generate_key(&mut OsRng);
        let encoded = URL_SAFE_NO_PAD.encode(key.as_slice());
        // Scrub the raw key bytes from the transient buffer; the base64url form
        // is the only surviving copy, guarded by this type's Drop impl.
        key.as_mut_slice().zeroize();
        Self(encoded)
    }

    /// Validate and construct an attachment key from base64url text.
    pub fn new(key: impl Into<String>) -> Result<Self> {
        // AUDITOR NOTE (defense-in-depth for candidate key material): both the
        // input candidate `String` and the decode buffer are scrubbed on every
        // return path, not just on success. `Self` is only constructed on
        // success, so this type's Drop-based zeroization does not cover the
        // error paths; we scrub `key` explicitly before each early return. The
        // decoded bytes live in a `Zeroizing` buffer, so any partial prefix a
        // failing `decode_vec` writes before erroring is scrubbed on drop.
        let mut key = key.into();
        let mut decoded: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        // The base64 DecodeError can render an offending byte of the candidate
        // key text; this is key material, so the error carries no decode
        // detail at all, only static messages.
        if URL_SAFE_NO_PAD.decode_vec(&key, &mut decoded).is_err() {
            key.zeroize();
            return Err(PaykitError::Validation(
                "attachment key must be base64url".into(),
            ));
        }
        if decoded.len() != ATTACHMENT_KEY_LEN {
            key.zeroize();
            return Err(PaykitError::Validation(
                "attachment key must decode to 32 bytes".into(),
            ));
        }
        Ok(Self(key))
    }

    /// Access the raw base64url key material.
    ///
    /// Treat this value as secret; do not log it or include it in telemetry.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn bytes(&self) -> Result<[u8; ATTACHMENT_KEY_LEN]> {
        let mut decoded =
            URL_SAFE_NO_PAD
                .decode(&self.0)
                .map_err(|_| PaykitError::InvalidData {
                    context: "attachment key is not valid base64url".into(),
                    source: None,
                })?;
        let key_bytes = <[u8; ATTACHMENT_KEY_LEN]>::try_from(decoded.as_slice()).map_err(|_| {
            PaykitError::InvalidData {
                context: "attachment key must decode to 32 bytes".into(),
                source: None,
            }
        });
        decoded.zeroize();
        key_bytes
    }
}

impl AsRef<str> for AttachmentKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AttachmentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AttachmentKey([redacted])")
    }
}

impl fmt::Display for AttachmentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted attachment key]")
    }
}

impl Drop for AttachmentKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Encrypted attachment blob: a fresh 24-byte nonce and the AEAD ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentCiphertext {
    /// Fresh XChaCha20-Poly1305 nonce, base64url (no padding).
    pub nonce_b64: String,
    /// Authenticated ciphertext (ciphertext || tag), base64url (no padding).
    pub ciphertext_b64: String,
    /// Algorithm label. Always [`ATTACHMENT_ENCRYPTION_ALGORITHM`].
    pub algorithm: String,
}

impl fmt::Debug for AttachmentCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentCiphertext")
            .field("algorithm", &self.algorithm)
            .field(
                "nonce_b64",
                &format_args!("<redacted:{} chars>", self.nonce_b64.len()),
            )
            .field(
                "ciphertext_b64",
                &format_args!("<redacted:{} chars>", self.ciphertext_b64.len()),
            )
            .finish()
    }
}

/// Generate a fresh 256-bit attachment key encoded as base64url (no padding).
pub fn generate_attachment_key() -> AttachmentKey {
    AttachmentKey::generate()
}

/// Encrypt `plaintext_b64` (base64url, no padding) with `key`.
///
/// A fresh random 24-byte nonce is generated for every call. When `aad` is
/// `Some`, those UTF-8 bytes are bound as associated data; `None` uses empty
/// associated data.
pub fn encrypt_attachment(
    plaintext_b64: &str,
    key: &AttachmentKey,
    aad: Option<&str>,
) -> Result<AttachmentCiphertext> {
    let mut plaintext =
        decode_b64url(plaintext_b64, "attachment plaintext is not valid base64url")?;
    let encrypted = encrypt_bytes(&plaintext, key, aad_bytes(aad))?;
    plaintext.zeroize();
    Ok(encrypted)
}

/// Decrypt `ciphertext_b64` with `key` and `nonce_b64`.
///
/// `aad` must match the associated data used at encrypt time. Returns the
/// plaintext encoded as base64url (no padding).
pub fn decrypt_attachment(
    ciphertext_b64: &str,
    key: &AttachmentKey,
    nonce_b64: &str,
    aad: Option<&str>,
) -> Result<String> {
    let ciphertext = decode_b64url(
        ciphertext_b64,
        "attachment ciphertext is not valid base64url",
    )?;
    let nonce = decode_nonce(nonce_b64)?;
    let mut plaintext = decrypt_bytes(&ciphertext, key, &nonce, aad_bytes(aad))?;
    let encoded = URL_SAFE_NO_PAD.encode(plaintext.as_slice());
    plaintext.zeroize();
    Ok(encoded)
}

fn aad_bytes(aad: Option<&str>) -> &[u8] {
    aad.unwrap_or("").as_bytes()
}

fn decode_b64url(value: &str, invalid_msg: &'static str) -> Result<Zeroizing<Vec<u8>>> {
    let mut decoded = Zeroizing::new(Vec::new());
    URL_SAFE_NO_PAD
        .decode_vec(value, &mut decoded)
        .map_err(|_| PaykitError::Validation(invalid_msg.into()))?;
    Ok(decoded)
}

fn decode_nonce(nonce_b64: &str) -> Result<Zeroizing<Vec<u8>>> {
    let decoded = decode_b64url(nonce_b64, "attachment nonce must be base64url")?;
    if decoded.len() != ATTACHMENT_NONCE_LEN {
        return Err(PaykitError::Validation(
            "attachment nonce must decode to 24 bytes".into(),
        ));
    }
    Ok(decoded)
}

fn cipher_from_key(key: &AttachmentKey) -> Result<XChaCha20Poly1305> {
    let mut key_bytes = key.bytes()?;
    let cipher = XChaCha20Poly1305::new((&key_bytes).into());
    key_bytes.zeroize();
    Ok(cipher)
}

fn encrypt_bytes(
    plaintext: &[u8],
    key: &AttachmentKey,
    aad: &[u8],
) -> Result<AttachmentCiphertext> {
    let cipher = cipher_from_key(key)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| PaykitError::InvalidData {
            context: "failed to encrypt attachment".into(),
            source: None,
        })?;
    Ok(AttachmentCiphertext {
        nonce_b64: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext_b64: URL_SAFE_NO_PAD.encode(ciphertext),
        algorithm: ATTACHMENT_ENCRYPTION_ALGORITHM.to_string(),
    })
}

fn decrypt_bytes(
    ciphertext: &[u8],
    key: &AttachmentKey,
    nonce: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let nonce: [u8; ATTACHMENT_NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| PaykitError::Validation("attachment nonce must decode to 24 bytes".into()))?;
    let cipher = cipher_from_key(key)?;
    let plaintext = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| PaykitError::InvalidData {
            context: "failed to decrypt attachment".into(),
            source: None,
        })?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn assert_roundtrip(plaintext: &[u8], aad: Option<&str>) {
        let key = generate_attachment_key();
        let encrypted = encrypt_attachment(&b64(plaintext), &key, aad).unwrap();
        assert_eq!(encrypted.algorithm, ATTACHMENT_ENCRYPTION_ALGORITHM);
        let decrypted =
            decrypt_attachment(&encrypted.ciphertext_b64, &key, &encrypted.nonce_b64, aad).unwrap();
        assert_eq!(decrypted, b64(plaintext));
    }

    #[test]
    fn test_generate_attachment_key_is_32_bytes_and_distinct() {
        let first = generate_attachment_key();
        let second = generate_attachment_key();
        let first_bytes = URL_SAFE_NO_PAD.decode(first.as_str()).unwrap();
        let second_bytes = URL_SAFE_NO_PAD.decode(second.as_str()).unwrap();
        assert_eq!(first_bytes.len(), ATTACHMENT_KEY_LEN);
        assert_eq!(second_bytes.len(), ATTACHMENT_KEY_LEN);
        assert_ne!(first.as_str(), second.as_str());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_empty() {
        assert_roundtrip(&[], None);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_one_byte() {
        assert_roundtrip(&[0x7f], None);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_1kb() {
        assert_roundtrip(&pattern(1024), None);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_1mb() {
        assert_roundtrip(&pattern(1024 * 1024), None);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = generate_attachment_key();
        let other = generate_attachment_key();
        let encrypted = encrypt_attachment(&b64(b"secret-bytes"), &key, None).unwrap();
        let err = decrypt_attachment(
            &encrypted.ciphertext_b64,
            &other,
            &encrypted.nonce_b64,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                PaykitError::InvalidData { ref context, .. }
                    if context == "failed to decrypt attachment"
            ),
            "expected typed decrypt failure, got: {err:?}"
        );
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let key = generate_attachment_key();
        let encrypted = encrypt_attachment(&b64(b"hello"), &key, None).unwrap();
        let mut ciphertext = URL_SAFE_NO_PAD.decode(&encrypted.ciphertext_b64).unwrap();
        let last = ciphertext.last_mut().expect("ciphertext is non-empty");
        *last ^= 0x01;
        let tampered = b64(&ciphertext);
        let err = decrypt_attachment(&tampered, &key, &encrypted.nonce_b64, None).unwrap_err();
        assert!(matches!(
            err,
            PaykitError::InvalidData { ref context, .. }
                if context == "failed to decrypt attachment"
        ));
    }

    #[test]
    fn test_aad_mismatch_fails_and_match_succeeds() {
        let key = generate_attachment_key();
        let path = "/pub/paykit/v0/private/chat/wallet/attachments/1";
        let encrypted = encrypt_attachment(&b64(b"photo"), &key, Some(path)).unwrap();
        let err = decrypt_attachment(
            &encrypted.ciphertext_b64,
            &key,
            &encrypted.nonce_b64,
            Some("/pub/paykit/v0/private/chat/wallet/attachments/2"),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PaykitError::InvalidData { ref context, .. }
                if context == "failed to decrypt attachment"
        ));
        let missing =
            decrypt_attachment(&encrypted.ciphertext_b64, &key, &encrypted.nonce_b64, None)
                .unwrap_err();
        assert!(matches!(missing, PaykitError::InvalidData { .. }));
        let decrypted = decrypt_attachment(
            &encrypted.ciphertext_b64,
            &key,
            &encrypted.nonce_b64,
            Some(path),
        )
        .unwrap();
        assert_eq!(decrypted, b64(b"photo"));
    }

    #[test]
    fn test_absent_aad_matches_empty_associated_data() {
        let key = generate_attachment_key();
        let encrypted = encrypt_attachment(&b64(b"x"), &key, None).unwrap();
        let decrypted = decrypt_attachment(
            &encrypted.ciphertext_b64,
            &key,
            &encrypted.nonce_b64,
            Some(""),
        )
        .unwrap();
        assert_eq!(decrypted, b64(b"x"));
    }

    #[test]
    fn test_attachment_key_new_rejects_wrong_length() {
        let short = b64(&[7u8; 16]);
        assert!(matches!(
            AttachmentKey::new(short).unwrap_err(),
            PaykitError::Validation(ref msg) if msg == "attachment key must decode to 32 bytes"
        ));
        let long = b64(&[9u8; 33]);
        assert!(matches!(
            AttachmentKey::new(long).unwrap_err(),
            PaykitError::Validation(_)
        ));
    }

    #[test]
    fn test_attachment_key_new_rejects_non_base64url() {
        assert!(matches!(
            AttachmentKey::new("not valid base64!!").unwrap_err(),
            PaykitError::Validation(ref msg) if msg == "attachment key must be base64url"
        ));
    }

    #[test]
    fn test_encrypt_rejects_invalid_plaintext_b64() {
        let key = generate_attachment_key();
        let err = encrypt_attachment("%%%", &key, None).unwrap_err();
        assert!(matches!(
            err,
            PaykitError::Validation(ref msg)
                if msg == "attachment plaintext is not valid base64url"
        ));
    }

    #[test]
    fn test_decrypt_rejects_wrong_length_nonce() {
        let key = generate_attachment_key();
        let encrypted = encrypt_attachment(&b64(b"n"), &key, None).unwrap();
        let short = b64(&[1u8; 12]);
        let err = decrypt_attachment(&encrypted.ciphertext_b64, &key, &short, None).unwrap_err();
        assert!(matches!(
            err,
            PaykitError::Validation(ref msg)
                if msg == "attachment nonce must decode to 24 bytes"
        ));
    }

    #[test]
    fn test_decrypt_rejects_invalid_nonce_b64() {
        let key = generate_attachment_key();
        let encrypted = encrypt_attachment(&b64(b"n"), &key, None).unwrap();
        let err = decrypt_attachment(&encrypted.ciphertext_b64, &key, "%%%%", None).unwrap_err();
        assert!(matches!(
            err,
            PaykitError::Validation(ref msg) if msg == "attachment nonce must be base64url"
        ));
    }

    #[test]
    fn test_encrypt_nonces_are_distinct() {
        let key = generate_attachment_key();
        let first = encrypt_attachment(&b64(b"same"), &key, None).unwrap();
        let second = encrypt_attachment(&b64(b"same"), &key, None).unwrap();
        assert_ne!(first.nonce_b64, second.nonce_b64);
        assert_ne!(first.ciphertext_b64, second.ciphertext_b64);
    }

    #[test]
    fn test_attachment_key_debug_redacts_material() {
        let key = generate_attachment_key();
        let debug = format!("{key:?}");
        let display = format!("{key}");
        assert!(!debug.contains(key.as_str()));
        assert!(!display.contains(key.as_str()));
        assert_eq!(debug, "AttachmentKey([redacted])");
        assert_eq!(display, "[redacted attachment key]");
    }

    #[test]
    fn test_attachment_ciphertext_debug_does_not_contain_key() {
        let key = generate_attachment_key();
        let encrypted = encrypt_attachment(&b64(b"blob"), &key, None).unwrap();
        let debug = format!("{encrypted:?}");
        assert!(!debug.contains(key.as_str()));
        assert!(!debug.contains(&encrypted.nonce_b64));
        assert!(!debug.contains(&encrypted.ciphertext_b64));
        assert!(debug.contains(ATTACHMENT_ENCRYPTION_ALGORITHM));
    }

    #[test]
    fn test_attachment_key_clone_survives_dropped_original() {
        let expected;
        let clone;
        {
            let original = generate_attachment_key();
            expected = original.as_str().to_string();
            clone = original.clone();
        }
        assert_eq!(clone.as_str(), expected);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(clone.as_str()).unwrap().len(),
            ATTACHMENT_KEY_LEN
        );
    }
}
