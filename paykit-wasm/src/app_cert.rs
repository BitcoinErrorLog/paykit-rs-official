use wasm_bindgen::prelude::*;

use crate::error::js_err_msg;
use crate::keys::{hex_encode, owner_peerid_bytes};

fn hex_decode_64(value: &str, what: &str) -> Result<[u8; 64], String> {
    let trimmed = value.trim();
    if trimmed.len() != 128
        || !trimmed
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'))
    {
        return Err(format!("{what} must be 128 hex characters"));
    }
    let bytes = trimmed.as_bytes();
    let mut out = [0u8; 64];
    for i in 0..64 {
        let hi = match bytes[i * 2] {
            b'0'..=b'9' => bytes[i * 2] - b'0',
            b'a'..=b'f' => bytes[i * 2] - b'a' + 10,
            b'A'..=b'F' => bytes[i * 2] - b'A' + 10,
            _ => unreachable!(),
        };
        let lo = match bytes[i * 2 + 1] {
            b'0'..=b'9' => bytes[i * 2 + 1] - b'0',
            b'a'..=b'f' => bytes[i * 2 + 1] - b'a' + 10,
            b'A'..=b'F' => bytes[i * 2 + 1] - b'A' + 10,
            _ => unreachable!(),
        };
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_decode_bytes(value: &str, what: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !trimmed.len().is_multiple_of(2) {
        return Err(format!("{what} must be non-empty even-length hex"));
    }
    if !trimmed
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'))
    {
        return Err(format!("{what} must be hex"));
    }
    let bytes = trimmed.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = match chunk[0] {
            b'0'..=b'9' => chunk[0] - b'0',
            b'a'..=b'f' => chunk[0] - b'a' + 10,
            b'A'..=b'F' => chunk[0] - b'A' + 10,
            _ => unreachable!(),
        };
        let lo = match chunk[1] {
            b'0'..=b'9' => chunk[1] - b'0',
            b'a'..=b'f' => chunk[1] - b'a' + 10,
            b'A'..=b'F' => chunk[1] - b'A' + 10,
            _ => unreachable!(),
        };
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Verify a UKD AppCert signature.
///
/// Binds `pubky_crypto::ukd::verify_app_cert`. `issuerPubky` accepts z-base-32
/// or 64-hex (the root PKARR identity that signed the cert). Returns the
/// lowercase 32-character `cert_id` hex on success.
#[wasm_bindgen(js_name = verifyAppCert)]
pub fn verify_app_cert_js(
    issuer_pubky: &str,
    cert_body_hex: &str,
    sig_hex: &str,
) -> Result<String, JsValue> {
    verify_app_cert(issuer_pubky, cert_body_hex, sig_hex).map_err(|err| js_err_msg(&err))
}

pub(crate) fn verify_app_cert(
    issuer_pubky: &str,
    cert_body_hex: &str,
    sig_hex: &str,
) -> Result<String, String> {
    let issuer = owner_peerid_bytes(issuer_pubky)?;
    let cert_body = hex_decode_bytes(cert_body_hex, "cert body")?;
    let sig = hex_decode_64(sig_hex, "signature")?;
    let cert_id = pubky_crypto::ukd::verify_app_cert(&issuer, &cert_body, &sig)
        .map_err(|err| format!("app cert verification failed: {err}"))?;
    Ok(hex_encode(&cert_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pubky_crypto::ukd::{issue_app_cert, AppCertInput};

    fn random_32() -> [u8; 32] {
        pubky::Keypair::random().secret()
    }

    #[test]
    fn verify_app_cert_accepts_valid_cert_z32_and_hex() {
        let root_sk = random_32();
        let signing_key = SigningKey::from_bytes(&root_sk);
        let issuer = signing_key.verifying_key().to_bytes();
        let (_, transport_pk) = pubky_crypto::sealed_blob::x25519_generate_keypair();
        let (_, inbox_pk) = pubky_crypto::sealed_blob::x25519_generate_keypair();
        let app_pk = random_32();
        let cert = issue_app_cert(
            &root_sk,
            &AppCertInput {
                issuer_peerid: issuer,
                app_id: "hypercolor.app".into(),
                device_id: None,
                app_ed25519_pub: app_pk,
                transport_x25519_pub: transport_pk,
                inbox_x25519_pub: inbox_pk,
                scopes: None,
                not_before: None,
                expires_at: None,
                flags: None,
            },
        )
        .expect("issue");
        let pubky = pubky::PublicKey::from(
            pubky::pkarr::PublicKey::try_from(issuer.as_slice()).expect("issuer"),
        );
        let z32 = pubky.z32();
        let hex = hex_encode(&issuer);
        let body = hex_encode(&cert.cert_body);
        let sig = hex_encode(&cert.sig);
        let expected = hex_encode(&cert.cert_id);
        assert_eq!(verify_app_cert(&z32, &body, &sig).expect("z32"), expected);
        assert_eq!(verify_app_cert(&hex, &body, &sig).expect("hex"), expected);
    }

    #[test]
    fn verify_app_cert_rejects_bad_signature() {
        let root_sk = random_32();
        let signing_key = SigningKey::from_bytes(&root_sk);
        let issuer = signing_key.verifying_key().to_bytes();
        let (_, transport_pk) = pubky_crypto::sealed_blob::x25519_generate_keypair();
        let (_, inbox_pk) = pubky_crypto::sealed_blob::x25519_generate_keypair();
        let app_pk = random_32();
        let cert = issue_app_cert(
            &root_sk,
            &AppCertInput {
                issuer_peerid: issuer,
                app_id: "hypercolor.app".into(),
                device_id: None,
                app_ed25519_pub: app_pk,
                transport_x25519_pub: transport_pk,
                inbox_x25519_pub: inbox_pk,
                scopes: None,
                not_before: None,
                expires_at: None,
                flags: None,
            },
        )
        .expect("issue");
        let pubky = pubky::PublicKey::from(
            pubky::pkarr::PublicKey::try_from(issuer.as_slice()).expect("issuer"),
        );
        let mut sig = cert.sig;
        sig[0] ^= 0x01;
        let err = verify_app_cert(
            &pubky.z32(),
            &hex_encode(&cert.cert_body),
            &hex_encode(&sig),
        )
        .expect_err("bad sig");
        assert!(err.contains("app cert verification failed"), "got: {err}");
    }
}
