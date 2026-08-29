//! Link-level encrypted-messaging bindings for chat-style apps.
//!
//! Mirrors the `paykit-wasm` Encrypted Link surface (`link.rs`, `marker.rs`,
//! `session.rs`, `keys.rs`) over `paykit-lib` for iOS/Android: receiver Noise
//! key management, Pubky session bootstrap, Receiver Marker discovery, the
//! Encrypted Link Handshake lifecycle, and raw-JSON Private Application
//! Message exchange with app-defined kinds (e.g. `chat.message.v0`).
//!
//! Snapshots cross the boundary as opaque JSON strings produced by
//! paykit-lib's snapshot wire format. They contain sensitive key material and
//! must be persisted as secrets.

use std::{fmt, sync::Arc};

use paykit_lib::{
    EncryptedLink, EncryptedLinkHandshake, EncryptedLinkHandshakeSnapshot, EncryptedLinkSnapshot,
    HandshakeProgress, PaykitReceiverCapabilities, PaykitReceiverMarker, PrivateApplicationMessage,
};
use pubky::{AuthFlowKind, Capabilities, Pubky, PubkyAuthFlow, PubkySession};
use tokio::sync::Mutex as AsyncMutex;
use zeroize::Zeroizing;

use crate::config::{default_pubky_client_config, FfiPubkyClientConfig};
use crate::errors::{identity_error, validation_error, PaykitFfiError};
use crate::session::{parse_public_key, parse_receiver_path, pubky_from_config};

/// Generate a random receiver-scoped Noise secret key, hex encoded (32 bytes).
///
/// Mirrors `paykit-wasm`'s `generateNoiseSecretKey`: the key is an independent
/// random secret, never the Pubky identity secret. Store it in platform secure
/// storage; it is required to restore Encrypted Links and to derive private
/// message paths.
#[uniffi::export]
pub fn generate_receiver_noise_secret_key_hex() -> String {
    hex::encode(pubky::Keypair::random().secret())
}

/// Derive the z-base-32 public key published in a Receiver Marker from a hex
/// receiver Noise secret key.
///
/// Mirrors `paykit-wasm`'s `noisePublicKeyFromSecret`.
#[uniffi::export]
pub fn receiver_noise_public_key_from_secret_hex(
    secret_key_hex: String,
) -> Result<String, PaykitFfiError> {
    let secret = secret_key_from_hex(&secret_key_hex, "receiver Noise")?;
    Ok(pubky::Keypair::from_secret(&secret).public_key().z32())
}

/// Public capabilities advertised by a Paykit Receiver Marker.
///
/// A messaging-only receiver typically sets `private_payments` (the Encrypted
/// Link capability) to true and the payment capabilities to false.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiChatReceiverCapabilities {
    /// Receiver can participate in private Encrypted Link workflows.
    pub private_payments: bool,
    /// Receiver can send or receive Payment Request messages.
    pub payment_requests: bool,
    /// Receiver can issue or retrieve Paykit Receipts.
    pub receipts: bool,
    /// Receiver can execute outgoing payments itself.
    pub outgoing_payments: bool,
}

/// Public Paykit Receiver Marker for one app/runtime receiver path.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiChatReceiverMarker {
    /// Receiver path this marker belongs to.
    pub receiver_path: String,
    /// Receiver Noise public key (z-base-32) used for Encrypted Link path
    /// derivation.
    pub noise_public_key: String,
    /// Public receiver capabilities.
    pub capabilities: FfiChatReceiverCapabilities,
}

/// One received Private Application Message.
///
/// Generated platform record descriptions may include the raw JSON, which is
/// decrypted plaintext. Apps must not log or otherwise stringify this record.
#[derive(uniffi::Record, Clone, PartialEq, Eq)]
pub struct FfiChatMessage {
    /// Message version from the JSON `version` field, when present and
    /// representable as a `u8`.
    pub version: Option<u8>,
    /// Message kind string from the JSON `kind` field, when present.
    pub kind: Option<String>,
    /// Raw plaintext JSON received over the Encrypted Link.
    pub raw_json: String,
}

impl fmt::Debug for FfiChatMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FfiChatMessage")
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field(
                "raw_json",
                &format_args!("<redacted:{} bytes>", self.raw_json.len()),
            )
            .finish()
    }
}

/// Result of one Encrypted Link Handshake step.
#[derive(uniffi::Record, Clone)]
pub struct FfiChatHandshakeStep {
    /// True when the handshake completed and `link` is set. False means the
    /// counterparty has not written their next message yet; poll `advance`
    /// again after a delay.
    pub complete: bool,
    /// Established Encrypted Link, present exactly when `complete` is true.
    pub link: Option<Arc<FfiChatLink>>,
}

/// Pubky client facade for the chat surface. Construct once and reuse.
#[derive(uniffi::Object)]
pub struct FfiChatClient {
    inner: Pubky,
}

#[cfg(test)]
impl FfiChatClient {
    /// Test-only seam wrapping an existing Pubky client (e.g. one wired to an
    /// ephemeral local testnet). All protocol code stays real.
    pub(crate) fn from_pubky(pubky: Pubky) -> Self {
        Self { inner: pubky }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiChatClient {
    /// Construct with production Pubky network defaults.
    #[uniffi::constructor]
    pub fn new() -> Result<Self, PaykitFfiError> {
        Self::with_pubky_client_config(default_pubky_client_config())
    }

    /// Construct with explicit Pubky client configuration (timeouts, local
    /// testnet host).
    #[uniffi::constructor]
    pub fn with_pubky_client_config(
        pubky_client: FfiPubkyClientConfig,
    ) -> Result<Self, PaykitFfiError> {
        Ok(Self {
            inner: pubky_from_config(&pubky_client)?,
        })
    }

    /// Sign in with a raw identity secret key (hex, 32 bytes).
    ///
    /// Suitable for apps that hold the identity key in platform secure
    /// storage. Apps that keep the identity key in an external signer (Pubky
    /// Ring) should use `start_auth_flow` instead.
    pub async fn signin_with_secret(
        &self,
        identity_secret_key_hex: String,
    ) -> Result<Arc<FfiChatSession>, PaykitFfiError> {
        let secret = secret_key_from_hex(&identity_secret_key_hex, "identity")?;
        let signer = self.inner.signer(pubky::Keypair::from_secret(&secret));
        let session = signer
            .signin()
            .await
            .map_err(|err| pubky_error("signin_failed", "Pubky signin failed", err))?;
        Ok(Arc::new(self.session(session)))
    }

    /// Sign up a new account on a homeserver with a raw identity secret key
    /// (hex, 32 bytes).
    pub async fn signup_with_secret(
        &self,
        identity_secret_key_hex: String,
        homeserver_public_key: String,
        signup_token: Option<String>,
    ) -> Result<Arc<FfiChatSession>, PaykitFfiError> {
        let secret = secret_key_from_hex(&identity_secret_key_hex, "identity")?;
        let homeserver = to_public_key(homeserver_public_key)?;
        let signer = self.inner.signer(pubky::Keypair::from_secret(&secret));
        let session = signer
            .signup(&homeserver, signup_token.as_deref())
            .await
            .map_err(|err| pubky_error("signup_failed", "Pubky signup failed", err))?;
        Ok(Arc::new(self.session(session)))
    }

    /// Restore a homeserver session from a token previously produced by
    /// `FfiChatSession.export_session()`, without a new signer approval.
    ///
    /// Performs a `/session` round-trip to revalidate; it rejects if the
    /// token is malformed, expired, or revoked.
    pub async fn restore_session(
        &self,
        exported_session: String,
    ) -> Result<Arc<FfiChatSession>, PaykitFfiError> {
        let session =
            PubkySession::import_secret(&exported_session, Some(self.inner.client().clone()))
                .await
                .map_err(|err| {
                    pubky_error(
                        "session_restore_failed",
                        "Pubky session restore failed",
                        err,
                    )
                })?;
        Ok(Arc::new(self.session(session)))
    }

    /// Start a pubkyauth sign-in flow for the given capabilities
    /// (e.g. `"/pub/paykit/:rw"`). Present `authorization_url()` to the
    /// signer (Pubky Ring), then call `await_approval()`.
    ///
    /// `relay_url` overrides the default public HTTP relay inbox; pass `None`
    /// in production (matching the wasm binding), or a local relay inbox URL
    /// against a testnet.
    pub async fn start_auth_flow(
        &self,
        capabilities: String,
        relay_url: Option<String>,
    ) -> Result<Arc<FfiChatAuthFlow>, PaykitFfiError> {
        let caps: Capabilities = capabilities
            .as_str()
            .try_into()
            .map_err(|err| validation_error(format!("invalid capabilities: {err}")))?;
        let flow = match relay_url {
            None => self.inner.start_auth_flow(&caps, AuthFlowKind::signin()),
            Some(relay_url) => {
                let relay_url = url::Url::parse(&relay_url)
                    .map_err(|err| validation_error(format!("invalid auth relay URL: {err}")))?;
                PubkyAuthFlow::builder(&caps, AuthFlowKind::signin())
                    .client(self.inner.client().clone())
                    .relay(relay_url)
                    .start()
            }
        }
        .map_err(|err| pubky_error("auth_flow_failed", "start Pubky auth flow failed", err))?;
        Ok(Arc::new(FfiChatAuthFlow {
            url: flow.authorization_url().to_string(),
            pubky: self.inner.clone(),
            inner: AsyncMutex::new(Some(flow)),
        }))
    }

    /// Fetch a counterparty's public Paykit Receiver Marker, or `None` when
    /// the owner has not published one at that path.
    pub async fn get_receiver_marker(
        &self,
        owner_public_key: String,
        receiver_path: String,
    ) -> Result<Option<FfiChatReceiverMarker>, PaykitFfiError> {
        let owner = to_public_key(owner_public_key)?;
        let path = parse_receiver_path(receiver_path)?;
        let storage = self.inner.public_storage();
        let marker = paykit_lib::get_paykit_receiver_marker(&storage, &owner, &path)
            .await
            .map_err(lib_error)?;
        Ok(marker.map(Into::into))
    }
}

impl FfiChatClient {
    fn session(&self, session: PubkySession) -> FfiChatSession {
        FfiChatSession {
            session,
            pubky: self.inner.clone(),
        }
    }
}

/// An in-progress pubkyauth flow.
#[derive(uniffi::Object)]
pub struct FfiChatAuthFlow {
    url: String,
    pubky: Pubky,
    inner: AsyncMutex<Option<PubkyAuthFlow>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiChatAuthFlow {
    /// The `pubkyauth:` URL to present to the signer (QR code / deep link).
    pub fn authorization_url(&self) -> String {
        self.url.clone()
    }

    /// Wait until the signer approves and return the session. Consumes the
    /// flow; subsequent calls fail.
    pub async fn await_approval(&self) -> Result<Arc<FfiChatSession>, PaykitFfiError> {
        let flow = self
            .inner
            .lock()
            .await
            .take()
            .ok_or_else(|| validation_error("auth flow already consumed"))?;
        let session = flow
            .await_approval()
            .await
            .map_err(|err| pubky_error("auth_flow_failed", "Pubky auth flow failed", err))?;
        Ok(Arc::new(FfiChatSession {
            session,
            pubky: self.pubky.clone(),
        }))
    }
}

/// An authenticated homeserver session for one Pubky identity, retaining the
/// client it was created with for Encrypted Link outbox operations.
#[derive(uniffi::Object)]
pub struct FfiChatSession {
    session: PubkySession,
    pubky: Pubky,
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiChatSession {
    /// The session owner's public key (z-base-32).
    pub fn pubky(&self) -> String {
        self.session.info().public_key().z32()
    }

    /// Export a compact session token for rehydrating via
    /// `FfiChatClient.restore_session()` after an app restart.
    ///
    /// Unlike the browser binding (where the credential lives in an HTTP-only
    /// cookie), the returned token is itself the **bearer secret** for this
    /// session. Do not log it; store it in platform secure storage.
    pub fn export_session(&self) -> String {
        self.session.export_secret()
    }

    /// Publish a public Paykit Receiver Marker for the session owner, making
    /// the receiver path discoverable and advertising the receiver Noise
    /// public key used for Encrypted Link path derivation.
    pub async fn publish_receiver_marker(
        &self,
        receiver_path: String,
        noise_public_key: String,
        capabilities: FfiChatReceiverCapabilities,
    ) -> Result<(), PaykitFfiError> {
        let path = parse_receiver_path(receiver_path)?;
        let noise = to_public_key(noise_public_key)?;
        let marker = PaykitReceiverMarker::new(path, capabilities.into(), noise);
        paykit_lib::publish_paykit_receiver_marker(&self.session, &marker)
            .await
            .map_err(lib_error)
    }

    /// Remove the session owner's public Paykit Receiver Marker at a path.
    pub async fn remove_receiver_marker(
        &self,
        receiver_path: String,
    ) -> Result<(), PaykitFfiError> {
        let path = parse_receiver_path(receiver_path)?;
        paykit_lib::remove_paykit_receiver_marker(&self.session, &path)
            .await
            .map_err(lib_error)
    }

    /// Initiate a Noise XX Encrypted Link Handshake toward a counterparty
    /// (initiator role).
    ///
    /// `receiver_noise_public_key` comes from the counterparty's Receiver
    /// Marker (see `FfiChatClient.get_receiver_marker`). Drive the returned
    /// handshake with `advance()` until it completes.
    pub fn initiate_encrypted_link(
        &self,
        sender_noise_secret_key_hex: String,
        receiver_public_key: String,
        receiver_noise_public_key: String,
        local_receiver_path: String,
        remote_receiver_path: String,
    ) -> Result<Arc<FfiChatLinkHandshake>, PaykitFfiError> {
        let secret = secret_key_from_hex(&sender_noise_secret_key_hex, "sender Noise")?;
        let receiver = to_public_key(receiver_public_key)?;
        let receiver_noise = to_public_key(receiver_noise_public_key)?;
        let local_path = parse_receiver_path(local_receiver_path)?;
        let remote_path = parse_receiver_path(remote_receiver_path)?;
        let handshake = paykit_lib::initiate_encrypted_link(
            self.session.clone(),
            *secret,
            &receiver,
            &receiver_noise,
            &local_path,
            &remote_path,
            self.pubky.clone(),
        )
        .map_err(lib_error)?;
        Ok(Arc::new(FfiChatLinkHandshake::new(handshake)))
    }

    /// Accept a Noise XX Encrypted Link Handshake from a counterparty
    /// (responder role).
    pub fn accept_encrypted_link(
        &self,
        receiver_noise_secret_key_hex: String,
        sender_public_key: String,
        sender_noise_public_key: String,
        local_receiver_path: String,
        remote_receiver_path: String,
    ) -> Result<Arc<FfiChatLinkHandshake>, PaykitFfiError> {
        let secret = secret_key_from_hex(&receiver_noise_secret_key_hex, "receiver Noise")?;
        let sender = to_public_key(sender_public_key)?;
        let sender_noise = to_public_key(sender_noise_public_key)?;
        let local_path = parse_receiver_path(local_receiver_path)?;
        let remote_path = parse_receiver_path(remote_receiver_path)?;
        let handshake = paykit_lib::accept_encrypted_link(
            self.session.clone(),
            *secret,
            &sender,
            &sender_noise,
            &local_path,
            &remote_path,
            self.pubky.clone(),
        )
        .map_err(lib_error)?;
        Ok(Arc::new(FfiChatLinkHandshake::new(handshake)))
    }

    /// Restore an in-progress handshake from a snapshot JSON string
    /// previously produced by `FfiChatLinkHandshake.snapshot()`.
    pub async fn restore_encrypted_link_handshake(
        &self,
        noise_secret_key_hex: String,
        remote_public_key: String,
        local_receiver_path: String,
        remote_receiver_path: String,
        snapshot_json: String,
    ) -> Result<Arc<FfiChatLinkHandshake>, PaykitFfiError> {
        let secret = secret_key_from_hex(&noise_secret_key_hex, "local Noise")?;
        let remote = to_public_key(remote_public_key)?;
        let local_path = parse_receiver_path(local_receiver_path)?;
        let remote_path = parse_receiver_path(remote_receiver_path)?;
        let snapshot = EncryptedLinkHandshakeSnapshot::deserialize(snapshot_json.as_bytes())
            .map_err(lib_error)?;
        let handshake = paykit_lib::restore_encrypted_link_handshake(
            self.session.clone(),
            *secret,
            &remote,
            &local_path,
            &remote_path,
            self.pubky.clone(),
            snapshot,
        )
        .await
        .map_err(lib_error)?;
        Ok(Arc::new(FfiChatLinkHandshake::new(handshake)))
    }

    /// Restore an established Encrypted Link from a snapshot JSON string
    /// previously produced by `FfiChatLink.snapshot()`.
    pub async fn restore_encrypted_link(
        &self,
        noise_secret_key_hex: String,
        remote_public_key: String,
        local_receiver_path: String,
        remote_receiver_path: String,
        snapshot_json: String,
    ) -> Result<Arc<FfiChatLink>, PaykitFfiError> {
        let secret = secret_key_from_hex(&noise_secret_key_hex, "local Noise")?;
        let remote = to_public_key(remote_public_key)?;
        let local_path = parse_receiver_path(local_receiver_path)?;
        let remote_path = parse_receiver_path(remote_receiver_path)?;
        let snapshot =
            EncryptedLinkSnapshot::deserialize(snapshot_json.as_bytes()).map_err(lib_error)?;
        let link = paykit_lib::restore_encrypted_link(
            self.session.clone(),
            *secret,
            &remote,
            &local_path,
            &remote_path,
            self.pubky.clone(),
            snapshot,
        )
        .await
        .map_err(lib_error)?;
        Ok(Arc::new(FfiChatLink::new(link)))
    }

    /// Delete all encrypted stream slots written by the local identity for
    /// one counterparty (recovery before a fresh handshake). Returns the
    /// number of deleted slots.
    pub async fn clear_encrypted_link_outbox(
        &self,
        local_noise_secret_key_hex: String,
        remote_public_key: String,
        remote_noise_public_key: String,
        local_receiver_path: String,
        remote_receiver_path: String,
    ) -> Result<u64, PaykitFfiError> {
        let secret = secret_key_from_hex(&local_noise_secret_key_hex, "local Noise")?;
        let remote = to_public_key(remote_public_key)?;
        let remote_noise = to_public_key(remote_noise_public_key)?;
        let local_path = parse_receiver_path(local_receiver_path)?;
        let remote_path = parse_receiver_path(remote_receiver_path)?;
        let deleted = paykit_lib::clear_encrypted_link_outbox(
            &self.session,
            &secret,
            &remote,
            &remote_noise,
            &local_path,
            &remote_path,
        )
        .await
        .map_err(lib_error)?;
        Ok(deleted as u64)
    }
}

/// Handle to an in-progress Encrypted Link Handshake.
#[derive(uniffi::Object)]
pub struct FfiChatLinkHandshake {
    inner: AsyncMutex<Option<EncryptedLinkHandshake>>,
}

impl FfiChatLinkHandshake {
    fn new(handshake: EncryptedLinkHandshake) -> Self {
        Self {
            inner: AsyncMutex::new(Some(handshake)),
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiChatLinkHandshake {
    /// Advance the handshake by one step.
    ///
    /// Returns `complete = false` when the counterparty has not written their
    /// next message yet (poll again after a delay) and `complete = true` with
    /// the established link when the handshake finished.
    ///
    /// If the step errors, the in-memory handshake is consumed (matching the
    /// paykit-lib ownership model); recover via
    /// `FfiChatSession.restore_encrypted_link_handshake` with a persisted
    /// snapshot.
    pub async fn advance(&self) -> Result<FfiChatHandshakeStep, PaykitFfiError> {
        let mut guard = self.inner.lock().await;
        let handshake = guard
            .take()
            .ok_or_else(|| validation_error("handshake consumed (completed or failed)"))?;
        match paykit_lib::advance_handshake(handshake).await {
            Ok(HandshakeProgress::Pending(handshake)) => {
                guard.replace(handshake);
                Ok(FfiChatHandshakeStep {
                    complete: false,
                    link: None,
                })
            }
            Ok(HandshakeProgress::Complete(link)) => Ok(FfiChatHandshakeStep {
                complete: true,
                link: Some(Arc::new(FfiChatLink::new(link))),
            }),
            Err(err) => Err(lib_error(err)),
        }
    }

    /// Serialize the current handshake state as an opaque JSON string. The
    /// snapshot contains key material — store it as a secret.
    pub async fn snapshot(&self) -> Result<String, PaykitFfiError> {
        let guard = self.inner.lock().await;
        let handshake = guard
            .as_ref()
            .ok_or_else(|| validation_error("handshake consumed (completed or failed)"))?;
        snapshot_json(handshake.serialize())
    }

    /// Override the automatic write-failure recovery attempt limit.
    pub async fn set_max_recovery_attempts(&self, max: u32) -> Result<(), PaykitFfiError> {
        let mut guard = self.inner.lock().await;
        let handshake = guard
            .as_mut()
            .ok_or_else(|| validation_error("handshake consumed (completed or failed)"))?;
        handshake.set_max_recovery_attempts(max);
        Ok(())
    }
}

/// Handle to an established Encrypted Link.
#[derive(uniffi::Object)]
pub struct FfiChatLink {
    recipient: String,
    remote_noise_public_key: String,
    local_receiver_path: String,
    remote_receiver_path: String,
    inner: AsyncMutex<Option<EncryptedLink>>,
}

impl FfiChatLink {
    fn new(link: EncryptedLink) -> Self {
        let snapshot = link.snapshot();
        Self {
            recipient: link.recipient().z32(),
            remote_noise_public_key: link.remote_noise_public_key().z32(),
            local_receiver_path: link.local_receiver_path().to_string(),
            remote_receiver_path: snapshot.remote_receiver_path().to_string(),
            inner: AsyncMutex::new(Some(link)),
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiChatLink {
    /// Counterparty Pubky identity public key (z-base-32).
    pub fn recipient(&self) -> String {
        self.recipient.clone()
    }

    /// Counterparty receiver Noise public key (z-base-32).
    pub fn remote_noise_public_key(&self) -> String {
        self.remote_noise_public_key.clone()
    }

    /// Local Paykit receiver path.
    pub fn local_receiver_path(&self) -> String {
        self.local_receiver_path.clone()
    }

    /// Counterparty Paykit receiver path.
    pub fn remote_receiver_path(&self) -> String {
        self.remote_receiver_path.clone()
    }

    /// Send one raw JSON Private Application Message. The JSON must carry a
    /// `version` (u8) and `kind` (string) envelope; unknown kinds such as
    /// `chat.message.v0` are allowed by contract.
    ///
    /// Persist the exact JSON before sending when retrying the same message
    /// matters.
    pub async fn send_private_application_message_json(
        &self,
        raw_json: String,
    ) -> Result<(), PaykitFfiError> {
        let mut guard = self.inner.lock().await;
        let link = guard
            .as_mut()
            .ok_or_else(|| validation_error("link is closed"))?;
        link.send_private_application_message_json(&raw_json)
            .await
            .map_err(lib_error)
    }

    /// Receive available Private Application Messages in stream order.
    ///
    /// Persist returned messages before replacing a stored link snapshot: the
    /// read checkpoint advances past them.
    pub async fn receive_private_application_messages(
        &self,
    ) -> Result<Vec<FfiChatMessage>, PaykitFfiError> {
        let mut guard = self.inner.lock().await;
        let link = guard
            .as_mut()
            .ok_or_else(|| validation_error("link is closed"))?;
        let messages = link
            .receive_private_application_messages()
            .await
            .map_err(lib_error)?;
        Ok(messages.into_iter().map(Into::into).collect())
    }

    /// Serialize the current link state as an opaque JSON string for
    /// persistence. Take a fresh snapshot after sending/receiving when
    /// persisted counters must catch up. The snapshot contains key material —
    /// store it as a secret.
    pub async fn snapshot(&self) -> Result<String, PaykitFfiError> {
        let guard = self.inner.lock().await;
        let link = guard
            .as_ref()
            .ok_or_else(|| validation_error("link is closed"))?;
        snapshot_json(link.serialize())
    }

    /// Override the automatic send retry limit for transient homeserver
    /// write failures.
    pub async fn set_max_send_retries(&self, max: u32) -> Result<(), PaykitFfiError> {
        let mut guard = self.inner.lock().await;
        let link = guard
            .as_mut()
            .ok_or_else(|| validation_error("link is closed"))?;
        link.set_max_send_retries(max);
        Ok(())
    }

    /// Close the link and clean up Noise session state. The handle becomes
    /// unusable afterwards.
    pub async fn close(&self) -> Result<(), PaykitFfiError> {
        let link = self
            .inner
            .lock()
            .await
            .take()
            .ok_or_else(|| validation_error("link already closed"))?;
        paykit_lib::close_encrypted_link(link)
            .await
            .map_err(lib_error)
    }
}

impl From<FfiChatReceiverCapabilities> for PaykitReceiverCapabilities {
    fn from(value: FfiChatReceiverCapabilities) -> Self {
        Self {
            private_payments: value.private_payments,
            payment_requests: value.payment_requests,
            receipts: value.receipts,
            outgoing_payments: value.outgoing_payments,
        }
    }
}

impl From<PaykitReceiverCapabilities> for FfiChatReceiverCapabilities {
    fn from(value: PaykitReceiverCapabilities) -> Self {
        Self {
            private_payments: value.private_payments,
            payment_requests: value.payment_requests,
            receipts: value.receipts,
            outgoing_payments: value.outgoing_payments,
        }
    }
}

impl From<PaykitReceiverMarker> for FfiChatReceiverMarker {
    fn from(value: PaykitReceiverMarker) -> Self {
        Self {
            receiver_path: value.receiver_path.to_string(),
            noise_public_key: value.noise_public_key.z32(),
            capabilities: value.capabilities.into(),
        }
    }
}

impl From<PrivateApplicationMessage> for FfiChatMessage {
    fn from(value: PrivateApplicationMessage) -> Self {
        Self {
            version: value.version,
            kind: value.kind,
            raw_json: value.raw_json,
        }
    }
}

fn to_public_key(value: String) -> Result<pubky::PublicKey, PaykitFfiError> {
    Ok(parse_public_key(value)?.to_public_key()?)
}

fn secret_key_from_hex(value: &str, what: &str) -> Result<Zeroizing<[u8; 32]>, PaykitFfiError> {
    let bytes = Zeroizing::new(
        hex::decode(value.trim())
            .map_err(|_| validation_error(format!("{what} secret key hex is invalid")))?,
    );
    let bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        validation_error(format!(
            "{what} secret key must be 32 bytes, got {}",
            bytes.len()
        ))
    })?;
    Ok(Zeroizing::new(bytes))
}

// SECURITY / REDACTION: like `map_pubky_identity_error` in paykit-sdk and the
// `PaykitSdkError` conversion in `errors.rs`, the raw pubky cause is dropped
// entirely — it can carry request URLs and response bodies — and only the
// fixed code/context pair crosses the FFI boundary into exception text.
fn pubky_error(code: &'static str, context: &'static str, _err: pubky::Error) -> PaykitFfiError {
    identity_error(code, context)
}

fn lib_error(err: paykit_lib::PaykitError) -> PaykitFfiError {
    PaykitFfiError::from(paykit_sdk::PaykitSdkError::from(err))
}

fn snapshot_json(bytes: Vec<u8>) -> Result<String, PaykitFfiError> {
    String::from_utf8(bytes)
        .map_err(|_| validation_error("snapshot serialization produced non-UTF-8 bytes"))
}

#[cfg(test)]
mod tests;
