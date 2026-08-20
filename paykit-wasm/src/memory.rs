use pubky_noise::snow_crypto::{
    ContextError, DataLinkContext, HandshakePattern, PUBKY_NOISE_CIPHERTEXT_LEN,
    PUBKY_NOISE_MSG_LEN, PUBKY_NOISE_TAG_LEN,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::error::js_err_msg;
use crate::keys::{public_key_from_z32, secret_key_from_slice};

fn context_error(context: &str, err: ContextError) -> JsValue {
    let detail = match err {
        ContextError::Init => "initialization failed",
        ContextError::OngoingHandshake => "handshake still in progress",
        ContextError::InternalSnowTransitionErr => "snow transport transition failed",
        ContextError::InternalSnowWriteErr => "snow write (encrypt) failed",
        ContextError::InternalSnowReadErr => "snow read (decrypt/authenticate) failed",
        ContextError::CounterOverflow => "message slot counter exhausted",
        ContextError::NonceOverflow => "nonce space exhausted",
    };
    js_sys::Error::new(&format!("{context}: {detail}")).into()
}

/// Wire framing used by pubky-noise homeserver slots:
/// `[len_hi, len_lo, ciphertext…]`, zero-padded to a fixed packet size.
fn encode_packet(data: &[u8; PUBKY_NOISE_CIPHERTEXT_LEN], len: usize) -> Vec<u8> {
    let mut packet = vec![0u8; PUBKY_NOISE_CIPHERTEXT_LEN + 2];
    packet[0..2].copy_from_slice(&(len as u16).to_be_bytes());
    packet[2..len + 2].copy_from_slice(&data[..len]);
    packet
}

fn decode_packet(packet: &[u8]) -> Result<([u8; PUBKY_NOISE_CIPHERTEXT_LEN], usize), JsValue> {
    if packet.len() < 2 || packet.len() > PUBKY_NOISE_CIPHERTEXT_LEN + 2 {
        return Err(js_err_msg("malformed packet: bad length"));
    }
    let len = u16::from_be_bytes([packet[0], packet[1]]) as usize;
    if len > PUBKY_NOISE_CIPHERTEXT_LEN || len + 2 > packet.len() {
        return Err(js_err_msg("malformed packet: length prefix out of range"));
    }
    let mut message = [0u8; PUBKY_NOISE_CIPHERTEXT_LEN];
    message[..len].copy_from_slice(&packet[2..len + 2]);
    Ok((message, len))
}

/// An in-memory Noise XX session using the exact crypto stack of Paykit
/// Encrypted Links (`pubky_noise::snow_crypto::DataLinkContext`,
/// `Noise_XX_25519_ChaChaPoly_SHA256`, 1000-byte messages, explicit nonces)
/// with the caller shuttling packets instead of homeserver outboxes.
///
/// Purpose: smoke tests and vector checks of the compiled WASM crypto. It is
/// NOT the Paykit messaging protocol — it has no homeserver transport, no
/// private path derivation, no Private Application Message envelope, and no
/// snapshots. Use the `EncryptedLink` surface for real messaging.
#[wasm_bindgen]
pub struct MemoryNoiseSession {
    context: DataLinkContext,
    link_id: Option<[u8; 32]>,
}

#[wasm_bindgen]
impl MemoryNoiseSession {
    /// Create one side of an in-memory Noise XX session.
    ///
    /// `localStaticSecret` is a 32-byte Noise static secret (e.g. from
    /// `generateNoiseSecretKey()`). `remoteIdentityPubky` is the
    /// counterparty's identity public key (z-base-32); it labels the endpoint
    /// exactly as `PubkyNoiseEncryptor::new` does and plays no role in the
    /// XX key exchange itself.
    #[wasm_bindgen(constructor)]
    pub fn new(
        initiator: bool,
        local_static_secret: &[u8],
        remote_identity_pubky: &str,
    ) -> Result<MemoryNoiseSession, JsValue> {
        let mut secret = secret_key_from_slice(local_static_secret)?;
        let endpoint = public_key_from_z32(remote_identity_pubky, "remote identity")?;
        let context = DataLinkContext::new(
            HandshakePattern::PatternXX,
            initiator,
            Some(secret),
            endpoint,
        )
        .map_err(|err| context_error("failed to build Noise context", err))?;
        secret.zeroize();
        Ok(Self {
            context,
            link_id: None,
        })
    }

    /// True once all handshake messages have been processed on this side.
    #[wasm_bindgen(js_name = isHandshakeComplete)]
    pub fn is_handshake_complete(&self) -> bool {
        !self.context.is_handshake()
    }

    /// True once the session has transitioned to transport mode.
    #[wasm_bindgen(js_name = isTransport)]
    pub fn is_transport(&self) -> bool {
        self.context.is_transport()
    }

    /// Produce the next outbound handshake packet.
    #[wasm_bindgen(js_name = writeHandshakeMessage)]
    pub fn write_handshake_message(&mut self) -> Result<Vec<u8>, JsValue> {
        if self.context.is_transport() {
            return Err(js_err_msg("handshake already transitioned to transport"));
        }
        let mut message = [0u8; PUBKY_NOISE_CIPHERTEXT_LEN];
        let len = self
            .context
            .write_act(&[], &mut message)
            .map_err(|err| context_error("handshake write failed", err))?;
        Ok(encode_packet(&message, len))
    }

    /// Consume an inbound handshake packet from the counterparty.
    #[wasm_bindgen(js_name = readHandshakeMessage)]
    pub fn read_handshake_message(&mut self, packet: &[u8]) -> Result<(), JsValue> {
        if self.context.is_transport() {
            return Err(js_err_msg("handshake already transitioned to transport"));
        }
        let (mut message, len) = decode_packet(packet)?;
        let mut payload = [0u8; PUBKY_NOISE_MSG_LEN];
        self.context
            .read_act(&mut message, &mut payload, len)
            .map_err(|err| context_error("handshake read failed", err))?;
        Ok(())
    }

    /// Transition a completed handshake to transport mode. Mirrors
    /// `PubkyNoiseEncryptor::transition_transport`, including deriving the
    /// link id from the handshake transcript hash.
    #[wasm_bindgen(js_name = transitionTransport)]
    pub fn transition_transport(&mut self) -> Result<(), JsValue> {
        let hash = self
            .context
            .get_handshake_hash()
            .ok_or_else(|| js_err_msg("handshake hash unavailable"))?;
        self.context
            .to_transport()
            .map_err(|err| context_error("transport transition failed", err))?;
        self.link_id = Some(hash);
        Ok(())
    }

    /// The 32-byte link id (hex) derived from the handshake transcript hash.
    /// Available after `transitionTransport()`. Both parties derive the same
    /// value — comparing them proves the handshakes converged.
    #[wasm_bindgen(js_name = linkIdHex)]
    pub fn link_id_hex(&self) -> Option<String> {
        self.link_id
            .map(|id| id.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    /// Encrypt one transport message (max `maxNoiseMessageLen()` bytes).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
        if !self.context.is_transport() {
            return Err(js_err_msg("session is not in transport mode"));
        }
        if plaintext.len() > PUBKY_NOISE_MSG_LEN {
            return Err(js_err_msg("plaintext exceeds max Noise message size"));
        }
        self.context
            .ensure_can_advance_sending_nonce()
            .map_err(|err| context_error("encrypt failed", err))?;
        let mut message = [0u8; PUBKY_NOISE_CIPHERTEXT_LEN];
        let len = self
            .context
            .write_act(plaintext, &mut message)
            .map_err(|err| context_error("encrypt failed", err))?;
        self.context
            .increment_sending_nonce()
            .map_err(|err| context_error("encrypt failed", err))?;
        self.context
            .increment_write_counter()
            .map_err(|err| context_error("encrypt failed", err))?;
        Ok(encode_packet(&message, len))
    }

    /// Decrypt and authenticate one transport packet from the counterparty.
    pub fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>, JsValue> {
        if !self.context.is_transport() {
            return Err(js_err_msg("session is not in transport mode"));
        }
        let (mut message, len) = decode_packet(packet)?;
        if len < PUBKY_NOISE_TAG_LEN {
            return Err(js_err_msg("malformed packet: shorter than AEAD tag"));
        }
        let mut payload = [0u8; PUBKY_NOISE_MSG_LEN];
        self.context
            .read_act(&mut message, &mut payload, len)
            .map_err(|err| context_error("decrypt failed", err))?;
        self.context
            .increment_read_counter()
            .map_err(|err| context_error("decrypt failed", err))?;
        Ok(payload[..len - PUBKY_NOISE_TAG_LEN].to_vec())
    }

    /// Zeroize key material held by this session.
    pub fn close(&mut self) {
        self.context.delete();
    }
}
