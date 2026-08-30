//! Standalone XChaCha20-Poly1305 AEAD for chat attachment blobs.
//!
//! Thin UniFFI surface over `paykit-lib::attachment_aead`. The blob is
//! encrypted with a random 32-byte key; ciphertext can live on a world-readable
//! homeserver and the key is delivered separately over an Encrypted Link.
//! This is not tied to receipts or payments.

use std::fmt;

use paykit_lib::{
    decrypt_attachment, encrypt_attachment, generate_attachment_key as generate_lib_attachment_key,
    AttachmentCiphertext, AttachmentKey, PaykitError,
};

use crate::errors::{protocol_error, validation_error, PaykitFfiError};

/// Encrypted attachment blob returned by [`attachment_encrypt`].
#[derive(uniffi::Record, Clone, PartialEq, Eq)]
pub struct FfiAttachmentCiphertext {
    /// Fresh 24-byte XChaCha20-Poly1305 nonce, base64url (no padding).
    pub nonce_b64: String,
    /// Authenticated ciphertext (ciphertext || tag), base64url (no padding).
    pub ciphertext_b64: String,
    /// Algorithm label. Always `XChaCha20Poly1305`.
    pub algorithm: String,
}

impl fmt::Debug for FfiAttachmentCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FfiAttachmentCiphertext")
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

impl From<AttachmentCiphertext> for FfiAttachmentCiphertext {
    fn from(value: AttachmentCiphertext) -> Self {
        Self {
            nonce_b64: value.nonce_b64,
            ciphertext_b64: value.ciphertext_b64,
            algorithm: value.algorithm,
        }
    }
}

/// Generate a random 32-byte attachment key, encoded as base64url (no padding).
///
/// Store it in platform secure storage. The platform caller must minimize its
/// own copies of the returned key.
#[uniffi::export]
pub fn generate_attachment_key() -> String {
    let key = generate_lib_attachment_key();
    key.as_str().to_owned()
}

/// Encrypt `plaintext_b64` (base64url, no padding) with `key_b64`.
///
/// A fresh random 24-byte nonce is generated for every call. When `aad` is
/// `Some`, those UTF-8 bytes are bound as associated data (the app should pass
/// the canonical homeserver path); `None` uses empty associated data.
///
/// The platform caller must minimize its own copies of `key_b64`.
#[uniffi::export]
pub fn attachment_encrypt(
    plaintext_b64: String,
    key_b64: String,
    aad: Option<String>,
) -> Result<FfiAttachmentCiphertext, PaykitFfiError> {
    let key = AttachmentKey::new(key_b64).map_err(map_attachment_lib_error)?;
    let encrypted = encrypt_attachment(&plaintext_b64, &key, aad.as_deref())
        .map_err(map_attachment_lib_error)?;
    Ok(encrypted.into())
}

/// Decrypt `ciphertext_b64` with `key_b64` and `nonce_b64`.
///
/// `aad` must match the associated data used at encrypt time. Returns the
/// plaintext encoded as base64url (no padding). Authentication failure maps to
/// `protocol/decrypt_failed` with a fixed redacted context.
///
/// The platform caller must minimize its own copies of `key_b64`.
#[uniffi::export]
pub fn attachment_decrypt(
    ciphertext_b64: String,
    key_b64: String,
    nonce_b64: String,
    aad: Option<String>,
) -> Result<String, PaykitFfiError> {
    let key = AttachmentKey::new(key_b64).map_err(map_attachment_lib_error)?;
    decrypt_attachment(&ciphertext_b64, &key, &nonce_b64, aad.as_deref())
        .map_err(map_attachment_lib_error)
}

/// Map paykit-lib attachment AEAD errors to the FFI surface. Validation
/// contexts are a closed allowlist; decrypt authentication failures use a
/// fixed `decrypt_failed` code and never forward raw AEAD payloads.
fn map_attachment_lib_error(err: PaykitError) -> PaykitFfiError {
    match err {
        PaykitError::Validation(msg) => validation_error(attachment_validation_context(&msg)),
        PaykitError::InvalidData { context, source: _ }
            if context == "failed to decrypt attachment" =>
        {
            protocol_error("decrypt_failed", "authenticated decryption failed")
        }
        PaykitError::InvalidData { .. } => {
            protocol_error("protocol_error", "attachment encryption failed")
        }
        PaykitError::Transport { .. } | PaykitError::NotFound(_) => {
            protocol_error("protocol_error", "attachment aead failed")
        }
    }
}

fn attachment_validation_context(msg: &str) -> &'static str {
    if msg.contains("key") && msg.contains("base64url") {
        "attachment key must be base64url"
    } else if msg.contains("key") && msg.contains("32") {
        "attachment key must decode to 32 bytes"
    } else if msg.contains("nonce") && msg.contains("base64url") {
        "attachment nonce must be base64url"
    } else if msg.contains("nonce") {
        "attachment nonce must decode to 24 bytes"
    } else if msg.contains("plaintext") {
        "attachment plaintext is not valid base64url"
    } else if msg.contains("ciphertext") {
        "attachment ciphertext is not valid base64url"
    } else {
        "attachment validation failed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use paykit_lib::ATTACHMENT_ENCRYPTION_ALGORITHM;

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn assert_protocol(err: PaykitFfiError, code: &str) {
        match err {
            PaykitFfiError::Protocol {
                code: ref got,
                ref context,
            } => {
                assert_eq!(got, code, "context={context}");
            }
            other => panic!("expected protocol/{code}, got {other:?}"),
        }
    }

    fn assert_roundtrip(plaintext: &[u8], aad: Option<String>) {
        let key = generate_attachment_key();
        let encrypted = attachment_encrypt(b64(plaintext), key.clone(), aad.clone()).unwrap();
        assert_eq!(encrypted.algorithm, ATTACHMENT_ENCRYPTION_ALGORITHM);
        let decrypted = attachment_decrypt(
            encrypted.ciphertext_b64.clone(),
            key,
            encrypted.nonce_b64.clone(),
            aad,
        )
        .unwrap();
        assert_eq!(decrypted, b64(plaintext));
    }

    #[test]
    fn test_generate_attachment_key_is_32_bytes_and_distinct() {
        let first = generate_attachment_key();
        let second = generate_attachment_key();
        AttachmentKey::new(first.clone()).expect("generated key must be valid");
        AttachmentKey::new(second.clone()).expect("generated key must be valid");
        assert_eq!(URL_SAFE_NO_PAD.decode(&first).unwrap().len(), 32);
        assert_eq!(URL_SAFE_NO_PAD.decode(&second).unwrap().len(), 32);
        assert_ne!(first, second);
    }

    #[test]
    fn test_attachment_encrypt_decrypt_roundtrip_empty() {
        assert_roundtrip(&[], None);
    }

    #[test]
    fn test_attachment_encrypt_decrypt_roundtrip_one_byte() {
        assert_roundtrip(&[0x01], None);
    }

    #[test]
    fn test_attachment_encrypt_decrypt_roundtrip_1kb() {
        assert_roundtrip(&pattern(1024), None);
    }

    #[test]
    fn test_attachment_encrypt_decrypt_roundtrip_1mb() {
        assert_roundtrip(&pattern(1024 * 1024), None);
    }

    #[test]
    fn test_attachment_decrypt_wrong_key_is_decrypt_failed() {
        let key = generate_attachment_key();
        let other = generate_attachment_key();
        let encrypted = attachment_encrypt(b64(b"secret-bytes"), key, None).unwrap();
        let err = attachment_decrypt(
            encrypted.ciphertext_b64,
            other.clone(),
            encrypted.nonce_b64,
            None,
        )
        .unwrap_err();
        let rendered = format!("{err}");
        assert!(!rendered.contains(&other));
        match err {
            PaykitFfiError::Protocol { code, context } => {
                assert_eq!(code, "decrypt_failed");
                assert_eq!(context, "authenticated decryption failed");
            }
            other => panic!("expected protocol/decrypt_failed, got {other:?}"),
        }
    }

    #[test]
    fn test_attachment_decrypt_tampered_ciphertext_fails() {
        let key = generate_attachment_key();
        let encrypted = attachment_encrypt(b64(b"hello"), key.clone(), None).unwrap();
        let mut ciphertext = URL_SAFE_NO_PAD.decode(&encrypted.ciphertext_b64).unwrap();
        let last = ciphertext.last_mut().expect("ciphertext is non-empty");
        *last ^= 0x01;
        let err = attachment_decrypt(b64(&ciphertext), key, encrypted.nonce_b64, None).unwrap_err();
        assert_protocol(err, "decrypt_failed");
    }

    #[test]
    fn test_attachment_aad_mismatch_fails_and_match_succeeds() {
        let key = generate_attachment_key();
        let path = "/pub/paykit/v0/private/chat/wallet/attachments/1".to_string();
        let encrypted = attachment_encrypt(b64(b"photo"), key.clone(), Some(path.clone())).unwrap();
        let mismatch = attachment_decrypt(
            encrypted.ciphertext_b64.clone(),
            key.clone(),
            encrypted.nonce_b64.clone(),
            Some("/pub/paykit/v0/private/chat/wallet/attachments/2".into()),
        )
        .unwrap_err();
        assert_protocol(mismatch, "decrypt_failed");
        let missing = attachment_decrypt(
            encrypted.ciphertext_b64.clone(),
            key.clone(),
            encrypted.nonce_b64.clone(),
            None,
        )
        .unwrap_err();
        assert_protocol(missing, "decrypt_failed");
        let decrypted = attachment_decrypt(
            encrypted.ciphertext_b64,
            key,
            encrypted.nonce_b64,
            Some(path),
        )
        .unwrap();
        assert_eq!(decrypted, b64(b"photo"));
    }

    #[test]
    fn test_attachment_wrong_length_key_is_validation() {
        let short = b64(&[7u8; 16]);
        let err = attachment_encrypt(b64(b"x"), short.clone(), None).unwrap_err();
        let rendered = format!("{err}");
        assert!(!rendered.contains(&short));
        match err {
            PaykitFfiError::Protocol { code, context } => {
                assert_eq!(code, "validation");
                assert_eq!(context, "attachment key must decode to 32 bytes");
            }
            other => panic!("expected protocol/validation, got {other:?}"),
        }
    }

    #[test]
    fn test_attachment_invalid_key_b64_is_validation() {
        let err = attachment_encrypt(b64(b"x"), "not valid base64!!".into(), None).unwrap_err();
        match err {
            PaykitFfiError::Protocol { code, context } => {
                assert_eq!(code, "validation");
                assert_eq!(context, "attachment key must be base64url");
            }
            other => panic!("expected protocol/validation, got {other:?}"),
        }
    }

    #[test]
    fn test_attachment_wrong_length_nonce_is_validation() {
        let key = generate_attachment_key();
        let encrypted = attachment_encrypt(b64(b"n"), key.clone(), None).unwrap();
        let err =
            attachment_decrypt(encrypted.ciphertext_b64, key, b64(&[1u8; 12]), None).unwrap_err();
        match err {
            PaykitFfiError::Protocol { code, context } => {
                assert_eq!(code, "validation");
                assert_eq!(context, "attachment nonce must decode to 24 bytes");
            }
            other => panic!("expected protocol/validation, got {other:?}"),
        }
    }

    #[test]
    fn test_attachment_encrypt_nonces_are_distinct() {
        let key = generate_attachment_key();
        let first = attachment_encrypt(b64(b"same"), key.clone(), None).unwrap();
        let second = attachment_encrypt(b64(b"same"), key, None).unwrap();
        assert_ne!(first.nonce_b64, second.nonce_b64);
        assert_ne!(first.ciphertext_b64, second.ciphertext_b64);
    }

    #[test]
    fn test_ffi_attachment_ciphertext_debug_does_not_contain_key() {
        let key = generate_attachment_key();
        let encrypted = attachment_encrypt(b64(b"blob"), key.clone(), None).unwrap();
        let debug = format!("{encrypted:?}");
        assert!(!debug.contains(&key));
        assert!(!debug.contains(&encrypted.nonce_b64));
        assert!(!debug.contains(&encrypted.ciphertext_b64));
        assert!(debug.contains(ATTACHMENT_ENCRYPTION_ALGORITHM));
    }
}
