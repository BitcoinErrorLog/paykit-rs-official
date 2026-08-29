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

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

use paykit_lib::{
    EncryptedLink, EncryptedLinkHandshake, EncryptedLinkHandshakeSnapshot, EncryptedLinkSnapshot,
    HandshakeProgress, PaykitReceiverCapabilities, PaykitReceiverMarker, PaykitReceiverPath,
    PrivateApplicationMessage, PAYKIT_PRIVATE_PATH_PREFIX,
};
use pubky::{
    errors::RequestError, AuthFlowKind, Capabilities, Capability, Pubky, PubkyAuthFlow,
    PubkySession, PublicKey, StatusCode,
};
use tokio::sync::{Mutex as AsyncMutex, Notify};
use zeroize::Zeroizing;

use crate::config::{default_pubky_client_config, FfiPubkyClientConfig};
use crate::errors::{
    consumed_error, identity_error, in_flight_error, protocol_error, transport_error,
    validation_error, PaykitFfiError,
};
use crate::session::{parse_public_key, parse_receiver_path, pubky_from_config};

/// Domain separator copied from paykit-lib's private path derivation
/// (`encrypted_link/paths.rs`). Must stay in lockstep with that crate.
const PAYKIT_PATH_DOMAIN: &[u8] = b"paykit-path-v0";

/// Scope that an auth-flow capability grant must cover with read+write.
const PAYKIT_SCOPE: &str = "/pub/paykit/";

/// Generate a random receiver-scoped Noise secret key, hex encoded (32 bytes).
///
/// Mirrors `paykit-wasm`'s `generateNoiseSecretKey`: the key is an independent
/// random secret, never the Pubky identity secret. Store it in platform secure
/// storage; it is required to restore Encrypted Links and to derive private
/// message paths. The platform caller must minimize its own copies of the
/// returned hex.
#[uniffi::export]
pub fn generate_receiver_noise_secret_key_hex() -> String {
    let secret = Zeroizing::new(pubky::Keypair::random().secret());
    hex::encode(secret.as_slice())
}

/// Derive the z-base-32 public key published in a Receiver Marker from a hex
/// receiver Noise secret key.
///
/// Mirrors `paykit-wasm`'s `noisePublicKeyFromSecret`.
///
/// The platform caller must minimize its own copies of `secret_key_hex`.
#[uniffi::export]
pub fn receiver_noise_public_key_from_secret_hex(
    secret_key_hex: String,
) -> Result<String, PaykitFfiError> {
    let secret_key_hex = Zeroizing::new(secret_key_hex);
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
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiChatHandshakeStep {
    /// True when the handshake completed and `link` is set. False means the
    /// counterparty has not written their next message yet; poll `advance`
    /// again after a delay.
    pub complete: bool,
    /// Established Encrypted Link, present exactly when `complete` is true.
    pub link: Option<Arc<FfiChatLink>>,
}

/// Result of an atomic inbound Encrypted Link Handshake probe.
///
/// Distinguishes "no handshake message exists" from transport and protocol
/// failures. `NoInbound` is a successful observation, not an error.
#[derive(uniffi::Enum, Clone)]
pub enum FfiChatProbeResult {
    /// No inbound handshake message is present on the derived read slot.
    NoInbound,
    /// An inbound handshake message was consumed and a response written; more
    /// `advance` steps are required.
    Pending {
        /// Responder handshake that consumed the inbound message.
        handshake: Arc<FfiChatLinkHandshake>,
    },
    /// The handshake completed in this probe step.
    Established {
        /// Established Encrypted Link.
        link: Arc<FfiChatLink>,
    },
}

/// Pubky client facade for the chat surface. Construct once and reuse.
#[derive(uniffi::Object)]
pub struct FfiChatClient {
    inner: Pubky,
}

impl fmt::Debug for FfiChatClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FfiChatClient").finish_non_exhaustive()
    }
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
    ///
    /// The platform caller must minimize its own copies of
    /// `identity_secret_key_hex`.
    pub async fn signin_with_secret(
        &self,
        identity_secret_key_hex: String,
    ) -> Result<Arc<FfiChatSession>, PaykitFfiError> {
        let identity_secret_key_hex = Zeroizing::new(identity_secret_key_hex);
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
    ///
    /// The platform caller must minimize its own copies of
    /// `identity_secret_key_hex`.
    pub async fn signup_with_secret(
        &self,
        identity_secret_key_hex: String,
        homeserver_public_key: String,
        signup_token: Option<String>,
    ) -> Result<Arc<FfiChatSession>, PaykitFfiError> {
        let identity_secret_key_hex = Zeroizing::new(identity_secret_key_hex);
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
    ///
    /// The platform caller must minimize its own copies of `exported_session`.
    pub async fn restore_session(
        &self,
        exported_session: String,
    ) -> Result<Arc<FfiChatSession>, PaykitFfiError> {
        let exported_session = Zeroizing::new(exported_session);
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
    ///
    /// Rejects unless the capabilities grant read+write over `/pub/paykit/`
    /// (exact tree, a directory prefix, or `/`).
    ///
    /// This method stays `async` even though the wrapper itself does not
    /// `.await`: `PubkyAuthFlow` construction starts a relay subscription and
    /// requires a Tokio reactor. A sync export panics outside that runtime
    /// (`there is no reactor running`).
    pub async fn start_auth_flow(
        &self,
        capabilities: String,
        relay_url: Option<String>,
    ) -> Result<Arc<FfiChatAuthFlow>, PaykitFfiError> {
        let caps: Capabilities = capabilities
            .as_str()
            .try_into()
            .map_err(|err| validation_error(format!("invalid capabilities: {err}")))?;
        if !capabilities_cover_paykit(caps.as_slice()) {
            return Err(identity_error(
                "capabilities_missing",
                "capabilities must grant /pub/paykit/ read+write",
            ));
        }
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
            inner: Arc::new(AuthFlowShared {
                cell: AsyncMutex::new(AuthFlowCell::Ready(flow)),
                notify: Notify::new(),
                #[cfg(test)]
                hold: TestOpHold::new(),
            }),
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
            .map_err(map_chat_lib_error)?;
        Ok(marker.map(Into::into))
    }
}

impl FfiChatClient {
    fn session(&self, session: PubkySession) -> FfiChatSession {
        FfiChatSession {
            session,
            pubky: self.inner.clone(),
            probe_park: Arc::new(ProbePark::new()),
        }
    }
}

/// An in-progress pubkyauth flow.
#[derive(uniffi::Object)]
pub struct FfiChatAuthFlow {
    url: String,
    pubky: Pubky,
    inner: Arc<AuthFlowShared>,
}

struct AuthFlowShared {
    cell: AsyncMutex<AuthFlowCell>,
    notify: Notify,
    #[cfg(test)]
    hold: TestOpHold,
}

enum AuthFlowCell {
    Ready(PubkyAuthFlow),
    InFlight,
    ReadySession(Result<PubkySession, PaykitFfiError>),
    Consumed,
}

impl fmt::Debug for FfiChatAuthFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The authorization URL embeds the flow's client secret; redact it.
        f.debug_struct("FfiChatAuthFlow")
            .field("url", &format_args!("<redacted:{} bytes>", self.url.len()))
            .finish_non_exhaustive()
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiChatAuthFlow {
    /// The `pubkyauth:` URL to present to the signer (QR code / deep link).
    pub fn authorization_url(&self) -> String {
        self.url.clone()
    }

    /// Wait until the signer approves and return the session. Consumes the
    /// flow; subsequent calls fail.
    ///
    /// The approval wait is spawned onto the Tokio runtime so cancelling this
    /// FFI future cannot drop the underlying `PubkyAuthFlow`. A later call
    /// resumes the in-flight wait or returns its settled result.
    pub async fn await_approval(&self) -> Result<Arc<FfiChatSession>, PaykitFfiError> {
        loop {
            let mut guard = self.inner.cell.lock().await;
            match std::mem::replace(&mut *guard, AuthFlowCell::Consumed) {
                AuthFlowCell::Ready(flow) => {
                    *guard = AuthFlowCell::InFlight;
                    drop(guard);
                    let shared = Arc::clone(&self.inner);
                    tokio::spawn(async move {
                        #[cfg(test)]
                        shared.hold.wait_if_armed().await;
                        let result = flow.await_approval().await.map_err(|err| {
                            pubky_error("auth_flow_failed", "Pubky auth flow failed", err)
                        });
                        let mut cell = shared.cell.lock().await;
                        *cell = AuthFlowCell::ReadySession(result);
                        shared.notify.notify_waiters();
                    });
                    wait_while(&self.inner.notify, || async {
                        matches!(&*self.inner.cell.lock().await, AuthFlowCell::InFlight)
                    })
                    .await;
                }
                AuthFlowCell::InFlight => {
                    *guard = AuthFlowCell::InFlight;
                    drop(guard);
                    wait_while(&self.inner.notify, || async {
                        matches!(&*self.inner.cell.lock().await, AuthFlowCell::InFlight)
                    })
                    .await;
                }
                AuthFlowCell::ReadySession(result) => {
                    *guard = AuthFlowCell::Consumed;
                    let session = result?;
                    return Ok(Arc::new(FfiChatSession {
                        session,
                        pubky: self.pubky.clone(),
                        probe_park: Arc::new(ProbePark::new()),
                    }));
                }
                AuthFlowCell::Consumed => {
                    return Err(consumed_error("auth flow already consumed"));
                }
            }
        }
    }
}

/// An authenticated homeserver session for one Pubky identity, retaining the
/// client it was created with for Encrypted Link outbox operations.
#[derive(uniffi::Object)]
pub struct FfiChatSession {
    session: PubkySession,
    pubky: Pubky,
    probe_park: Arc<ProbePark>,
}

struct ProbePark {
    cell: AsyncMutex<ProbeCell>,
    notify: Notify,
}

impl ProbePark {
    fn new() -> Self {
        Self {
            cell: AsyncMutex::new(ProbeCell::Idle),
            notify: Notify::new(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ProbeKey {
    sender: String,
    sender_noise: String,
    local_path: String,
    remote_path: String,
}

enum ProbeCell {
    Idle,
    InFlight {
        key: ProbeKey,
    },
    Ready {
        key: ProbeKey,
        result: Result<FfiChatProbeResult, PaykitFfiError>,
    },
}

impl fmt::Debug for FfiChatSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FfiChatSession")
            .field("pubky", &self.session.info().public_key().z32())
            .finish_non_exhaustive()
    }
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
    /// session. Do not log it; store it in platform secure storage. The
    /// platform caller must minimize its own copies of the returned token.
    /// UniFFI requires a `String` return, so this binding cannot wipe the
    /// caller's copy after the call returns.
    pub fn export_session(&self) -> String {
        let token = Zeroizing::new(self.session.export_secret());
        token.as_str().to_owned()
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
            .map_err(map_chat_lib_error)
    }

    /// Remove the session owner's public Paykit Receiver Marker at a path.
    pub async fn remove_receiver_marker(
        &self,
        receiver_path: String,
    ) -> Result<(), PaykitFfiError> {
        let path = parse_receiver_path(receiver_path)?;
        paykit_lib::remove_paykit_receiver_marker(&self.session, &path)
            .await
            .map_err(map_chat_lib_error)
    }

    /// Initiate a Noise XX Encrypted Link Handshake toward a counterparty
    /// (initiator role).
    ///
    /// `receiver_noise_public_key` comes from the counterparty's Receiver
    /// Marker (see `FfiChatClient.get_receiver_marker`). Drive the returned
    /// handshake with `advance()` until it completes.
    ///
    /// The platform caller must minimize its own copies of
    /// `sender_noise_secret_key_hex`.
    pub fn initiate_encrypted_link(
        &self,
        sender_noise_secret_key_hex: String,
        receiver_public_key: String,
        receiver_noise_public_key: String,
        local_receiver_path: String,
        remote_receiver_path: String,
    ) -> Result<Arc<FfiChatLinkHandshake>, PaykitFfiError> {
        let sender_noise_secret_key_hex = Zeroizing::new(sender_noise_secret_key_hex);
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
        .map_err(map_chat_lib_error)?;
        Ok(Arc::new(FfiChatLinkHandshake::new(handshake)))
    }

    /// Accept a Noise XX Encrypted Link Handshake from a counterparty
    /// (responder role).
    ///
    /// Prefer `probe_inbound_encrypted_link` when the app must distinguish
    /// "no inbound handshake exists" from transport or protocol failure.
    /// Calling `accept_encrypted_link` then `advance` when nothing is inbound
    /// yields a pending empty responder and can deadlock a crossed initiate.
    ///
    /// The platform caller must minimize its own copies of
    /// `receiver_noise_secret_key_hex`.
    pub fn accept_encrypted_link(
        &self,
        receiver_noise_secret_key_hex: String,
        sender_public_key: String,
        sender_noise_public_key: String,
        local_receiver_path: String,
        remote_receiver_path: String,
    ) -> Result<Arc<FfiChatLinkHandshake>, PaykitFfiError> {
        let receiver_noise_secret_key_hex = Zeroizing::new(receiver_noise_secret_key_hex);
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
        .map_err(map_chat_lib_error)?;
        Ok(Arc::new(FfiChatLinkHandshake::new(handshake)))
    }

    /// Atomically probe for an inbound Encrypted Link Handshake.
    ///
    /// Performs an explicit public-storage GET of the first inbound handshake
    /// slot before creating a responder. That GET is what distinguishes:
    /// - `NoInbound` — 404/GONE / empty slot (not an error)
    /// - `transport/transport_error` — network or non-404 homeserver failure
    /// - `Pending` / `Established` — inbound consumed via `accept` + one
    ///   `advance` (response written when the step proceeds)
    /// - `protocol/handshake_failed` — inbound existed but the protocol step
    ///   failed (unrecoverable for this handle)
    ///
    /// Use this instead of blindly `accept`+`advance` when both peers may
    /// initiate at once: `NoInbound` means no inbound was observed at probe
    /// time; when racing is possible, re-probe before initiating. A
    /// `Pending`/`Established` result means this side should be the responder.
    ///
    /// The whole probe is spawned onto the Tokio runtime so cancelling the
    /// FFI future cannot drop a responder that already consumed inbound. A
    /// later call with the same peer key resumes or returns the settled
    /// result.
    ///
    /// The platform caller must minimize its own copies of
    /// `receiver_noise_secret_key_hex`.
    pub async fn probe_inbound_encrypted_link(
        &self,
        receiver_noise_secret_key_hex: String,
        sender_public_key: String,
        sender_noise_public_key: String,
        local_receiver_path: String,
        remote_receiver_path: String,
    ) -> Result<FfiChatProbeResult, PaykitFfiError> {
        let receiver_noise_secret_key_hex = Zeroizing::new(receiver_noise_secret_key_hex);
        let secret = secret_key_from_hex(&receiver_noise_secret_key_hex, "receiver Noise")?;
        let sender = to_public_key(sender_public_key.clone())?;
        let sender_noise = to_public_key(sender_noise_public_key.clone())?;
        let local_path = parse_receiver_path(local_receiver_path.clone())?;
        let remote_path = parse_receiver_path(remote_receiver_path.clone())?;
        let key = ProbeKey {
            sender: sender_public_key,
            sender_noise: sender_noise_public_key,
            local_path: local_receiver_path,
            remote_path: remote_receiver_path,
        };

        loop {
            let mut guard = self.probe_park.cell.lock().await;
            match std::mem::replace(&mut *guard, ProbeCell::Idle) {
                ProbeCell::Ready {
                    key: parked_key,
                    result,
                } if parked_key == key => {
                    return result;
                }
                ProbeCell::InFlight { key: parked_key } if parked_key == key => {
                    *guard = ProbeCell::InFlight { key: parked_key };
                    drop(guard);
                    wait_while(&self.probe_park.notify, || async {
                        matches!(
                            &*self.probe_park.cell.lock().await,
                            ProbeCell::InFlight { .. }
                        )
                    })
                    .await;
                }
                ProbeCell::InFlight { key: parked_key } => {
                    *guard = ProbeCell::InFlight { key: parked_key };
                    drop(guard);
                    wait_while(&self.probe_park.notify, || async {
                        matches!(
                            &*self.probe_park.cell.lock().await,
                            ProbeCell::InFlight { .. }
                        )
                    })
                    .await;
                }
                ProbeCell::Ready { .. } | ProbeCell::Idle => {
                    *guard = ProbeCell::InFlight { key: key.clone() };
                    drop(guard);
                    let session = self.session.clone();
                    let pubky = self.pubky.clone();
                    let park = Arc::clone(&self.probe_park);
                    let spawn_key = key.clone();
                    let secret = secret.clone();
                    let sender = sender.clone();
                    let sender_noise = sender_noise.clone();
                    let local_path = local_path.clone();
                    let remote_path = remote_path.clone();
                    tokio::spawn(async move {
                        let result = run_inbound_probe(
                            session,
                            pubky,
                            secret,
                            sender,
                            sender_noise,
                            local_path,
                            remote_path,
                        )
                        .await;
                        let mut cell = park.cell.lock().await;
                        *cell = ProbeCell::Ready {
                            key: spawn_key,
                            result,
                        };
                        park.notify.notify_waiters();
                    });
                    wait_while(&self.probe_park.notify, || async {
                        matches!(
                            &*self.probe_park.cell.lock().await,
                            ProbeCell::InFlight { .. }
                        )
                    })
                    .await;
                }
            }
        }
    }

    /// Restore an in-progress handshake from a snapshot JSON string
    /// previously produced by `FfiChatLinkHandshake.snapshot()`.
    ///
    /// The platform caller must minimize its own copies of
    /// `noise_secret_key_hex`.
    pub async fn restore_encrypted_link_handshake(
        &self,
        noise_secret_key_hex: String,
        remote_public_key: String,
        local_receiver_path: String,
        remote_receiver_path: String,
        snapshot_json: String,
    ) -> Result<Arc<FfiChatLinkHandshake>, PaykitFfiError> {
        let noise_secret_key_hex = Zeroizing::new(noise_secret_key_hex);
        let secret = secret_key_from_hex(&noise_secret_key_hex, "local Noise")?;
        let remote = to_public_key(remote_public_key)?;
        let local_path = parse_receiver_path(local_receiver_path)?;
        let remote_path = parse_receiver_path(remote_receiver_path)?;
        let snapshot = EncryptedLinkHandshakeSnapshot::deserialize(snapshot_json.as_bytes())
            .map_err(map_chat_lib_error)?;
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
        .map_err(map_chat_lib_error)?;
        Ok(Arc::new(FfiChatLinkHandshake::new(handshake)))
    }

    /// Restore an established Encrypted Link from a snapshot JSON string
    /// previously produced by `FfiChatLink.snapshot()`.
    ///
    /// The platform caller must minimize its own copies of
    /// `noise_secret_key_hex`.
    pub async fn restore_encrypted_link(
        &self,
        noise_secret_key_hex: String,
        remote_public_key: String,
        local_receiver_path: String,
        remote_receiver_path: String,
        snapshot_json: String,
    ) -> Result<Arc<FfiChatLink>, PaykitFfiError> {
        let noise_secret_key_hex = Zeroizing::new(noise_secret_key_hex);
        let secret = secret_key_from_hex(&noise_secret_key_hex, "local Noise")?;
        let remote = to_public_key(remote_public_key)?;
        let local_path = parse_receiver_path(local_receiver_path)?;
        let remote_path = parse_receiver_path(remote_receiver_path)?;
        let snapshot = EncryptedLinkSnapshot::deserialize(snapshot_json.as_bytes())
            .map_err(map_chat_lib_error)?;
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
        .map_err(map_chat_lib_error)?;
        Ok(Arc::new(FfiChatLink::new(link)))
    }

    /// Delete all encrypted stream slots written by the local identity for
    /// one counterparty (recovery before a fresh handshake). Returns the
    /// number of deleted slots.
    ///
    /// The platform caller must minimize its own copies of
    /// `local_noise_secret_key_hex`.
    pub async fn clear_encrypted_link_outbox(
        &self,
        local_noise_secret_key_hex: String,
        remote_public_key: String,
        remote_noise_public_key: String,
        local_receiver_path: String,
        remote_receiver_path: String,
    ) -> Result<u64, PaykitFfiError> {
        let local_noise_secret_key_hex = Zeroizing::new(local_noise_secret_key_hex);
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
        .map_err(map_chat_lib_error)?;
        Ok(deleted as u64)
    }
}

/// Handle to an in-progress Encrypted Link Handshake.
#[derive(uniffi::Object)]
pub struct FfiChatLinkHandshake {
    inner: Arc<HandshakeShared>,
}

struct HandshakeShared {
    cell: AsyncMutex<HandshakeCell>,
    notify: Notify,
    #[cfg(test)]
    hold: TestOpHold,
}

enum HandshakeCell {
    Ready(EncryptedLinkHandshake),
    InFlight,
    AdvanceReady(Result<HandshakeOutcome, PaykitFfiError>),
    Consumed,
}

enum HandshakeOutcome {
    Pending(EncryptedLinkHandshake),
    Complete(EncryptedLink),
}

impl fmt::Debug for FfiChatLinkHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FfiChatLinkHandshake")
            .finish_non_exhaustive()
    }
}

impl FfiChatLinkHandshake {
    fn new(handshake: EncryptedLinkHandshake) -> Self {
        Self {
            inner: Arc::new(HandshakeShared {
                cell: AsyncMutex::new(HandshakeCell::Ready(handshake)),
                notify: Notify::new(),
                #[cfg(test)]
                hold: TestOpHold::new(),
            }),
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
    /// The step is spawned onto the Tokio runtime so cancelling this FFI
    /// future cannot drop the `EncryptedLinkHandshake`. A later `advance`
    /// resumes the in-flight step or returns its settled result.
    ///
    /// If the step errors, the in-memory handshake is consumed (matching the
    /// paykit-lib ownership model); recover via
    /// `FfiChatSession.restore_encrypted_link_handshake` with a persisted
    /// snapshot.
    pub async fn advance(&self) -> Result<FfiChatHandshakeStep, PaykitFfiError> {
        loop {
            let mut guard = self.inner.cell.lock().await;
            match std::mem::replace(&mut *guard, HandshakeCell::Consumed) {
                HandshakeCell::Ready(handshake) => {
                    *guard = HandshakeCell::InFlight;
                    drop(guard);
                    let shared = Arc::clone(&self.inner);
                    tokio::spawn(async move {
                        #[cfg(test)]
                        shared.hold.wait_if_armed().await;
                        let outcome = match paykit_lib::advance_handshake(handshake).await {
                            Ok(HandshakeProgress::Pending(handshake)) => {
                                Ok(HandshakeOutcome::Pending(handshake))
                            }
                            Ok(HandshakeProgress::Complete(link)) => {
                                Ok(HandshakeOutcome::Complete(link))
                            }
                            Err(err) => Err(map_chat_lib_error(err)),
                        };
                        let mut cell = shared.cell.lock().await;
                        *cell = HandshakeCell::AdvanceReady(outcome);
                        shared.notify.notify_waiters();
                    });
                    wait_while(&self.inner.notify, || async {
                        matches!(&*self.inner.cell.lock().await, HandshakeCell::InFlight)
                    })
                    .await;
                }
                HandshakeCell::InFlight => {
                    *guard = HandshakeCell::InFlight;
                    drop(guard);
                    wait_while(&self.inner.notify, || async {
                        matches!(&*self.inner.cell.lock().await, HandshakeCell::InFlight)
                    })
                    .await;
                }
                HandshakeCell::AdvanceReady(outcome) => match outcome {
                    Ok(HandshakeOutcome::Pending(handshake)) => {
                        *guard = HandshakeCell::Ready(handshake);
                        return Ok(FfiChatHandshakeStep {
                            complete: false,
                            link: None,
                        });
                    }
                    Ok(HandshakeOutcome::Complete(link)) => {
                        *guard = HandshakeCell::Consumed;
                        return Ok(FfiChatHandshakeStep {
                            complete: true,
                            link: Some(Arc::new(FfiChatLink::new(link))),
                        });
                    }
                    Err(err) => {
                        *guard = HandshakeCell::Consumed;
                        return Err(err);
                    }
                },
                HandshakeCell::Consumed => {
                    return Err(consumed_error("handshake consumed (completed or failed)"));
                }
            }
        }
    }

    /// Serialize the current handshake state as an opaque JSON string. The
    /// snapshot contains key material — store it as a secret.
    ///
    /// Fail-fast (does not wait for an in-flight `advance`), matching the
    /// wasm `LinkHandshakeHandle.snapshot` semantics.
    pub async fn snapshot(&self) -> Result<String, PaykitFfiError> {
        let guard = self.inner.cell.lock().await;
        match &*guard {
            HandshakeCell::Ready(handshake) => snapshot_json(handshake.serialize()),
            HandshakeCell::AdvanceReady(Ok(HandshakeOutcome::Pending(handshake))) => {
                snapshot_json(handshake.serialize())
            }
            HandshakeCell::InFlight => Err(in_flight_error(
                "handshake operation in flight; snapshot refused",
            )),
            HandshakeCell::AdvanceReady(Ok(HandshakeOutcome::Complete(_)))
            | HandshakeCell::AdvanceReady(Err(_))
            | HandshakeCell::Consumed => {
                Err(consumed_error("handshake consumed (completed or failed)"))
            }
        }
    }

    /// Override the automatic write-failure recovery attempt limit.
    ///
    /// Fail-fast while `advance` is in flight, matching wasm
    /// `setMaxRecoveryAttempts`.
    pub async fn set_max_recovery_attempts(&self, max: u32) -> Result<(), PaykitFfiError> {
        let mut guard = self.inner.cell.lock().await;
        match &mut *guard {
            HandshakeCell::Ready(handshake)
            | HandshakeCell::AdvanceReady(Ok(HandshakeOutcome::Pending(handshake))) => {
                handshake.set_max_recovery_attempts(max);
                Ok(())
            }
            HandshakeCell::InFlight => Err(in_flight_error(
                "handshake operation in flight; set_max_recovery_attempts refused",
            )),
            HandshakeCell::AdvanceReady(Ok(HandshakeOutcome::Complete(_)))
            | HandshakeCell::AdvanceReady(Err(_))
            | HandshakeCell::Consumed => {
                Err(consumed_error("handshake consumed (completed or failed)"))
            }
        }
    }
}

/// Handle to an established Encrypted Link.
#[derive(uniffi::Object)]
pub struct FfiChatLink {
    recipient: String,
    remote_noise_public_key: String,
    local_receiver_path: String,
    remote_receiver_path: String,
    inner: Arc<LinkShared>,
}

struct LinkShared {
    cell: AsyncMutex<LinkInner>,
    notify: Notify,
    #[cfg(test)]
    hold: TestOpHold,
}

struct LinkInner {
    occupancy: LinkOccupancy,
    parked_send: Option<ParkedSend>,
    parked_receive: Option<Result<Vec<FfiChatMessage>, PaykitFfiError>>,
    parked_close: Option<Result<(), PaykitFfiError>>,
}

/// Settled result of a spawned send, keyed to the JSON that was actually sent.
struct ParkedSend {
    raw_json: String,
    result: Result<(), PaykitFfiError>,
}

enum LinkOccupancy {
    Ready(Box<EncryptedLink>),
    InFlight(LinkOp),
    Closed,
}

#[derive(Clone, PartialEq, Eq)]
enum LinkOp {
    Send { raw_json: String },
    Receive,
    Close,
}

impl fmt::Debug for FfiChatLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FfiChatLink")
            .field("recipient", &self.recipient)
            .field("remote_noise_public_key", &self.remote_noise_public_key)
            .field("local_receiver_path", &self.local_receiver_path)
            .field("remote_receiver_path", &self.remote_receiver_path)
            .finish_non_exhaustive()
    }
}

impl FfiChatLink {
    fn new(link: EncryptedLink) -> Self {
        let snapshot = link.snapshot();
        Self {
            recipient: link.recipient().z32(),
            remote_noise_public_key: link.remote_noise_public_key().z32(),
            local_receiver_path: link.local_receiver_path().to_string(),
            remote_receiver_path: snapshot.remote_receiver_path().to_string(),
            inner: Arc::new(LinkShared {
                cell: AsyncMutex::new(LinkInner {
                    occupancy: LinkOccupancy::Ready(Box::new(link)),
                    parked_send: None,
                    parked_receive: None,
                    parked_close: None,
                }),
                notify: Notify::new(),
                #[cfg(test)]
                hold: TestOpHold::new(),
            }),
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
    ///
    /// The send is spawned onto the Tokio runtime so cancelling this FFI
    /// future cannot drop the `EncryptedLink`. A later `send` of the **same**
    /// `raw_json` resumes or returns the settled result. A later `send` of a
    /// **different** payload drains a settled parked result and starts a
    /// fresh send; if a send of another payload is still in flight, this
    /// returns `protocol/parked_result_conflict` so the new message is not
    /// silently dropped.
    pub async fn send_private_application_message_json(
        &self,
        raw_json: String,
    ) -> Result<(), PaykitFfiError> {
        loop {
            let mut guard = self.inner.cell.lock().await;
            if let Some(parked) = guard.parked_send.take() {
                if parked.raw_json == raw_json {
                    return parked.result;
                }
                // Different payload, settled: drain the parked result and
                // fall through to send this payload.
            }
            match &mut guard.occupancy {
                LinkOccupancy::InFlight(LinkOp::Send {
                    raw_json: in_flight,
                }) if in_flight == &raw_json => {
                    drop(guard);
                    wait_while(&self.inner.notify, || async {
                        matches!(
                            &self.inner.cell.lock().await.occupancy,
                            LinkOccupancy::InFlight(LinkOp::Send { .. })
                        )
                    })
                    .await;
                }
                LinkOccupancy::InFlight(LinkOp::Send { .. }) => {
                    return Err(protocol_error(
                        "parked_result_conflict",
                        "in-flight send is for a different payload",
                    ));
                }
                LinkOccupancy::InFlight(_) => {
                    return Err(in_flight_error("link operation in flight; send refused"));
                }
                LinkOccupancy::Closed => return Err(consumed_error("link is closed")),
                LinkOccupancy::Ready(_) => {
                    let LinkOccupancy::Ready(mut link) = std::mem::replace(
                        &mut guard.occupancy,
                        LinkOccupancy::InFlight(LinkOp::Send {
                            raw_json: raw_json.clone(),
                        }),
                    ) else {
                        unreachable!("occupancy was Ready");
                    };
                    drop(guard);
                    let shared = Arc::clone(&self.inner);
                    let raw_json = raw_json.clone();
                    tokio::spawn(async move {
                        #[cfg(test)]
                        shared.hold.wait_if_armed().await;
                        let result = link
                            .send_private_application_message_json(&raw_json)
                            .await
                            .map_err(map_chat_lib_error);
                        let mut cell = shared.cell.lock().await;
                        cell.occupancy = LinkOccupancy::Ready(link);
                        cell.parked_send = Some(ParkedSend { raw_json, result });
                        shared.notify.notify_waiters();
                    });
                    wait_while(&self.inner.notify, || async {
                        matches!(
                            &self.inner.cell.lock().await.occupancy,
                            LinkOccupancy::InFlight(LinkOp::Send { .. })
                        )
                    })
                    .await;
                }
            }
        }
    }

    /// Receive available Private Application Messages in stream order.
    ///
    /// Persist returned messages before replacing a stored link snapshot: the
    /// read checkpoint advances past them.
    ///
    /// The receive is spawned onto the Tokio runtime so cancelling this FFI
    /// future cannot drop the `EncryptedLink`. A later `receive` resumes or
    /// returns the settled result.
    pub async fn receive_private_application_messages(
        &self,
    ) -> Result<Vec<FfiChatMessage>, PaykitFfiError> {
        loop {
            let mut guard = self.inner.cell.lock().await;
            if let Some(parked) = guard.parked_receive.take() {
                return parked;
            }
            match &mut guard.occupancy {
                LinkOccupancy::InFlight(LinkOp::Receive) => {
                    drop(guard);
                    wait_while(&self.inner.notify, || async {
                        matches!(
                            &self.inner.cell.lock().await.occupancy,
                            LinkOccupancy::InFlight(LinkOp::Receive)
                        )
                    })
                    .await;
                }
                LinkOccupancy::InFlight(_) => {
                    return Err(in_flight_error("link operation in flight; receive refused"));
                }
                LinkOccupancy::Closed => return Err(consumed_error("link is closed")),
                LinkOccupancy::Ready(_) => {
                    let LinkOccupancy::Ready(mut link) = std::mem::replace(
                        &mut guard.occupancy,
                        LinkOccupancy::InFlight(LinkOp::Receive),
                    ) else {
                        unreachable!("occupancy was Ready");
                    };
                    drop(guard);
                    let shared = Arc::clone(&self.inner);
                    tokio::spawn(async move {
                        let result = link
                            .receive_private_application_messages()
                            .await
                            .map_err(map_chat_lib_error)
                            .map(|messages| messages.into_iter().map(Into::into).collect());
                        let mut cell = shared.cell.lock().await;
                        cell.occupancy = LinkOccupancy::Ready(link);
                        cell.parked_receive = Some(result);
                        shared.notify.notify_waiters();
                    });
                    wait_while(&self.inner.notify, || async {
                        matches!(
                            &self.inner.cell.lock().await.occupancy,
                            LinkOccupancy::InFlight(LinkOp::Receive)
                        )
                    })
                    .await;
                }
            }
        }
    }

    /// Serialize the current link state as an opaque JSON string for
    /// persistence. Take a fresh snapshot after sending/receiving when
    /// persisted counters must catch up. The snapshot contains key material —
    /// store it as a secret.
    ///
    /// Fail-fast while send/receive/close is in flight, matching wasm
    /// `EncryptedLinkHandle.snapshot`.
    pub async fn snapshot(&self) -> Result<String, PaykitFfiError> {
        let guard = self.inner.cell.lock().await;
        match &guard.occupancy {
            LinkOccupancy::Ready(link) => snapshot_json(link.serialize()),
            LinkOccupancy::InFlight(_) => Err(in_flight_error(
                "link operation in flight; snapshot refused",
            )),
            LinkOccupancy::Closed => Err(consumed_error("link is closed")),
        }
    }

    /// Override the automatic send retry limit for transient homeserver
    /// write failures.
    ///
    /// Fail-fast while send/receive/close is in flight, matching wasm
    /// `setMaxSendRetries`.
    pub async fn set_max_send_retries(&self, max: u32) -> Result<(), PaykitFfiError> {
        let mut guard = self.inner.cell.lock().await;
        match &mut guard.occupancy {
            LinkOccupancy::Ready(link) => {
                link.set_max_send_retries(max);
                Ok(())
            }
            LinkOccupancy::InFlight(_) => Err(in_flight_error(
                "link operation in flight; set_max_send_retries refused",
            )),
            LinkOccupancy::Closed => Err(consumed_error("link is closed")),
        }
    }

    /// Close the link and clean up Noise session state. The handle becomes
    /// unusable afterwards.
    ///
    /// Close is spawned onto the Tokio runtime so cancelling this FFI future
    /// cannot drop the `EncryptedLink` before cleanup. A later `close_link`
    /// resumes or returns the settled result.
    ///
    /// Named `close_link` (not `close`) because UniFFI's Kotlin codegen adds a
    /// non-suspend `close()` via `Disposable` to every object, and a suspend
    /// `close()` here creates conflicting overloads that fail compilation.
    pub async fn close_link(&self) -> Result<(), PaykitFfiError> {
        loop {
            let mut guard = self.inner.cell.lock().await;
            if let Some(parked) = guard.parked_close.take() {
                return parked;
            }
            match &mut guard.occupancy {
                LinkOccupancy::InFlight(LinkOp::Close) => {
                    drop(guard);
                    wait_while(&self.inner.notify, || async {
                        matches!(
                            &self.inner.cell.lock().await.occupancy,
                            LinkOccupancy::InFlight(LinkOp::Close)
                        )
                    })
                    .await;
                }
                LinkOccupancy::InFlight(_) => {
                    return Err(in_flight_error("link operation in flight; close refused"));
                }
                LinkOccupancy::Closed => {
                    return Err(consumed_error("link already closed"));
                }
                LinkOccupancy::Ready(_) => {
                    let LinkOccupancy::Ready(link) = std::mem::replace(
                        &mut guard.occupancy,
                        LinkOccupancy::InFlight(LinkOp::Close),
                    ) else {
                        unreachable!("occupancy was Ready");
                    };
                    drop(guard);
                    let shared = Arc::clone(&self.inner);
                    tokio::spawn(async move {
                        let result = paykit_lib::close_encrypted_link(*link)
                            .await
                            .map_err(map_chat_lib_error);
                        let mut cell = shared.cell.lock().await;
                        cell.occupancy = LinkOccupancy::Closed;
                        cell.parked_close = Some(result);
                        shared.notify.notify_waiters();
                    });
                    wait_while(&self.inner.notify, || async {
                        matches!(
                            &self.inner.cell.lock().await.occupancy,
                            LinkOccupancy::InFlight(LinkOp::Close)
                        )
                    })
                    .await;
                }
            }
        }
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

async fn run_inbound_probe(
    session: PubkySession,
    pubky: Pubky,
    secret: Zeroizing<[u8; 32]>,
    sender: PublicKey,
    sender_noise: PublicKey,
    local_path: PaykitReceiverPath,
    remote_path: PaykitReceiverPath,
) -> Result<FfiChatProbeResult, PaykitFfiError> {
    let local_identity = session.info().public_key().clone();
    let addr = inbound_handshake_slot_addr(
        &secret,
        &local_identity,
        &sender,
        &sender_noise,
        &local_path,
        &remote_path,
    );
    match pubky.public_storage().get(&addr).await {
        Ok(response) => {
            match response.status() {
                StatusCode::NOT_FOUND | StatusCode::GONE => {
                    return Ok(FfiChatProbeResult::NoInbound);
                }
                status if status.is_success() => {}
                _ => {
                    return Err(transport_error(
                        "transport_error",
                        "inbound handshake probe failed",
                    ));
                }
            }
            let bytes = response.bytes().await.map_err(|_| {
                transport_error("transport_error", "inbound handshake probe failed")
            })?;
            if bytes.is_empty() {
                return Ok(FfiChatProbeResult::NoInbound);
            }
        }
        Err(err) if is_not_found(&err) => return Ok(FfiChatProbeResult::NoInbound),
        Err(_) => {
            return Err(transport_error(
                "transport_error",
                "inbound handshake probe failed",
            ));
        }
    }

    let handshake = paykit_lib::accept_encrypted_link(
        session,
        *secret,
        &sender,
        &sender_noise,
        &local_path,
        &remote_path,
        pubky,
    )
    .map_err(map_chat_lib_error)?;
    match paykit_lib::advance_handshake(handshake).await {
        Ok(HandshakeProgress::Pending(handshake)) => Ok(FfiChatProbeResult::Pending {
            handshake: Arc::new(FfiChatLinkHandshake::new(handshake)),
        }),
        Ok(HandshakeProgress::Complete(link)) => Ok(FfiChatProbeResult::Established {
            link: Arc::new(FfiChatLink::new(link)),
        }),
        Err(err) => Err(map_chat_lib_error(err)),
    }
}

fn inbound_handshake_slot_addr(
    local_noise_secret: &[u8; 32],
    local_identity: &PublicKey,
    remote_identity: &PublicKey,
    remote_noise: &PublicKey,
    local_path: &PaykitReceiverPath,
    remote_path: &PaykitReceiverPath,
) -> String {
    let (_, read_path) = derived_write_read_paths(
        local_noise_secret,
        local_identity,
        remote_identity,
        remote_noise,
        local_path,
        remote_path,
    );
    format!("{remote_identity}{read_path}/0")
}

fn derived_write_read_paths(
    local_noise_secret: &[u8; 32],
    local_identity: &PublicKey,
    remote_identity: &PublicKey,
    remote_noise: &PublicKey,
    local_path: &PaykitReceiverPath,
    remote_path: &PaykitReceiverPath,
) -> (String, String) {
    let domain = receiver_pair_path_domain(
        PAYKIT_PATH_DOMAIN,
        local_identity,
        local_path,
        remote_identity,
        remote_path,
    );
    let local_base = format!("{PAYKIT_PRIVATE_PATH_PREFIX}/{local_path}/messages");
    let remote_base = format!("{PAYKIT_PRIVATE_PATH_PREFIX}/{remote_path}/messages");
    let (write_path, _) = paykit_lib::pubky_noise::path_derivation::derive_asymmetric_paths(
        local_noise_secret,
        remote_noise,
        &domain,
        &local_base,
    );
    let (_, read_path) = paykit_lib::pubky_noise::path_derivation::derive_asymmetric_paths(
        local_noise_secret,
        remote_noise,
        &domain,
        &remote_base,
    );
    (write_path, read_path)
}

fn receiver_pair_path_domain(
    base_domain: &[u8],
    local_public_key: &PublicKey,
    local_receiver_path: &PaykitReceiverPath,
    remote_public_key: &PublicKey,
    remote_receiver_path: &PaykitReceiverPath,
) -> Vec<u8> {
    let mut endpoints = [
        (
            local_public_key.z32(),
            local_receiver_path.as_str().to_owned(),
        ),
        (
            remote_public_key.z32(),
            remote_receiver_path.as_str().to_owned(),
        ),
    ];
    endpoints.sort();

    let mut domain = Vec::with_capacity(
        base_domain.len()
            + endpoints
                .iter()
                .map(|(public_key, receiver_path)| public_key.len() + receiver_path.len() + 2)
                .sum::<usize>()
            + 1,
    );
    domain.extend_from_slice(base_domain);
    for (public_key, receiver_path) in endpoints {
        domain.push(0);
        domain.extend_from_slice(public_key.as_bytes());
        domain.push(0);
        domain.extend_from_slice(receiver_path.as_bytes());
    }
    domain
}

/// True when one capability grants read+write over the `/pub/paykit/` tree.
/// Scope semantics mirror the homeserver's (`pubky_common`): a scope covers
/// the tree when it is the tree itself or a directory prefix of it
/// (`/pub/paykit/`, `/pub/`, `/`); a non-directory scope covers only itself.
fn capabilities_cover_paykit(capabilities: &[Capability]) -> bool {
    capabilities.iter().any(|capability| {
        scope_covers(&capability.scope, PAYKIT_SCOPE) && capability_has_read_write(capability)
    })
}

fn capability_has_read_write(capability: &Capability) -> bool {
    let rendered = capability.to_string();
    let actions = rendered
        .rsplit_once(':')
        .map(|(_, actions)| actions)
        .unwrap_or("");
    actions.contains('r') && actions.contains('w')
}

fn scope_covers(scope: &str, target: &str) -> bool {
    scope == target || (scope.ends_with('/') && target.starts_with(scope))
}

fn is_not_found(err: &pubky::Error) -> bool {
    matches!(
        err,
        pubky::Error::Request(RequestError::Server { status, .. })
            if *status == StatusCode::NOT_FOUND || *status == StatusCode::GONE
    )
}

async fn wait_while<F, Fut>(notify: &Notify, mut is_waiting: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    loop {
        let wait = notify.notified();
        tokio::pin!(wait);
        if !is_waiting().await {
            return;
        }
        wait.await;
    }
}

/// Test-only gate: when armed, a spawned op parks here before its network
/// call so a retry can observe `InFlight` deterministically.
#[cfg(test)]
struct TestOpHold {
    armed: AtomicBool,
    entered: AtomicBool,
    entered_notify: Notify,
    release: Notify,
}

#[cfg(test)]
impl TestOpHold {
    fn new() -> Self {
        Self {
            armed: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            entered_notify: Notify::new(),
            release: Notify::new(),
        }
    }

    fn arm(&self) {
        self.entered.store(false, Ordering::SeqCst);
        self.armed.store(true, Ordering::SeqCst);
    }

    fn release(&self) {
        self.armed.store(false, Ordering::SeqCst);
        self.release.notify_waiters();
    }

    async fn wait_if_armed(&self) {
        if !self.armed.load(Ordering::SeqCst) {
            return;
        }
        self.entered.store(true, Ordering::SeqCst);
        self.entered_notify.notify_waiters();
        wait_while(&self.release, || async {
            self.armed.load(Ordering::SeqCst)
        })
        .await;
    }

    async fn wait_until_entered(&self) {
        wait_while(&self.entered_notify, || async {
            !self.entered.load(Ordering::SeqCst)
        })
        .await;
    }
}

#[cfg(test)]
impl FfiChatAuthFlow {
    pub(crate) fn arm_test_hold(&self) {
        self.inner.hold.arm();
    }

    pub(crate) fn release_test_hold(&self) {
        self.inner.hold.release();
    }

    pub(crate) async fn wait_until_test_hold_entered(&self) {
        self.inner.hold.wait_until_entered().await;
    }
}

#[cfg(test)]
impl FfiChatLinkHandshake {
    pub(crate) fn arm_test_hold(&self) {
        self.inner.hold.arm();
    }

    pub(crate) fn release_test_hold(&self) {
        self.inner.hold.release();
    }

    pub(crate) async fn wait_until_test_hold_entered(&self) {
        self.inner.hold.wait_until_entered().await;
    }
}

#[cfg(test)]
impl FfiChatLink {
    pub(crate) fn arm_test_hold(&self) {
        self.inner.hold.arm();
    }

    pub(crate) fn release_test_hold(&self) {
        self.inner.hold.release();
    }

    pub(crate) async fn wait_until_test_hold_entered(&self) {
        self.inner.hold.wait_until_entered().await;
    }
}

fn to_public_key(value: String) -> Result<pubky::PublicKey, PaykitFfiError> {
    Ok(parse_public_key(value)?.to_public_key()?)
}

fn secret_key_from_hex(
    value: &Zeroizing<String>,
    what: &str,
) -> Result<Zeroizing<[u8; 32]>, PaykitFfiError> {
    let bytes = Zeroizing::new(
        hex::decode(value.trim())
            .map_err(|_| validation_error(format!("{what} secret key hex is invalid")))?,
    );
    Ok(Zeroizing::new(
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
            validation_error(format!(
                "{what} secret key must be 32 bytes, got {}",
                bytes.len()
            ))
        })?,
    ))
}

// SECURITY / REDACTION: like `map_pubky_identity_error` in paykit-sdk and the
// `PaykitSdkError` conversion in `errors.rs`, the raw pubky cause is dropped
// entirely — it can carry request URLs and response bodies — and only the
// fixed code/context pair crosses the FFI boundary into exception text.
fn pubky_error(code: &'static str, context: &'static str, _err: pubky::Error) -> PaykitFfiError {
    identity_error(code, context)
}

/// Map a paykit-lib error to the chat FFI surface with a closed context
/// allowlist. Lib paths embed `{err:?}`; that is only safe while
/// `PubkyNoiseError` is fieldless. This mapper never forwards raw `:?`
/// payloads, URLs, or response bodies.
pub(crate) fn map_chat_lib_error(err: paykit_lib::PaykitError) -> PaykitFfiError {
    match err {
        paykit_lib::PaykitError::Transport { context, source: _ } => {
            if context.contains("handshake recovery exhausted") {
                transport_error("transport_error", "handshake recovery exhausted")
            } else if context.contains("failed to transition") {
                protocol_error("handshake_failed", "handshake failed to enter transport")
            } else if context.contains("failed to restore Encrypted Link handshake")
                || context.contains("handshake restore")
            {
                transport_error(
                    "transport_error",
                    "failed to restore encrypted link handshake",
                )
            } else if context.contains("failed to restore Encrypted Link") {
                transport_error("transport_error", "failed to restore encrypted link")
            } else if context.contains("failed to initialize")
                || context.contains("failed to create encryptor")
            {
                transport_error("transport_error", "failed to create encrypted link")
            } else if context.contains("handshake") {
                protocol_error("handshake_failed", "handshake step failed")
            } else if context.contains("failed to send") {
                transport_error("send_failed", "failed to send Private Application Message")
            } else if context.contains("failed to receive") {
                transport_error(
                    "receive_failed",
                    "failed to receive Private Application Messages",
                )
            } else if context.contains("close") {
                transport_error("transport_error", "failed to close Encrypted Link")
            } else {
                transport_error("transport_error", "encrypted link transport failed")
            }
        }
        paykit_lib::PaykitError::NotFound(_) => PaykitFfiError::NotFound {
            code: "not_found".into(),
            context: "resource not found".into(),
        },
        paykit_lib::PaykitError::InvalidData {
            context: _,
            source: _,
        } => protocol_error("protocol_error", "invalid encrypted link data"),
        paykit_lib::PaykitError::Validation(msg) => {
            protocol_error("validation", validation_chat_context(&msg))
        }
    }
}

/// Closed allowlist for Validation contexts. Known envelope/size/restore
/// phrases stay distinguishable for callers; anything that looks like a
/// storage path or is otherwise unsafe falls back to a fixed string.
fn validation_chat_context(msg: &str) -> String {
    if msg.contains("exceeds") || msg.contains("max message size") {
        "payload exceeds max message size".into()
    } else if msg.contains("kind must be a string")
        || (msg.contains("kind") && !msg.contains("version"))
    {
        "Private Application Message kind must be a string".into()
    } else if msg.contains("version must be") || (msg.contains("version") && !msg.contains("kind"))
    {
        "Private Application Message version must be a u8 integer".into()
    } else if msg.contains("recipient") || msg.contains("does not match snapshot") {
        "restore recipient does not match snapshot".into()
    } else {
        sanitize_chat_context(msg, "encrypted link validation failed")
    }
}

const CHAT_CONTEXT_MAX_LEN: usize = 96;

fn sanitize_chat_context(context: &str, fallback: &str) -> String {
    if context.contains("://")
        || context.contains('{')
        || context.contains('}')
        || context.contains('<')
        || context.contains('\n')
        || context.contains('/')
        || context.len() > CHAT_CONTEXT_MAX_LEN
    {
        fallback.to_string()
    } else {
        context.to_string()
    }
}

fn snapshot_json(bytes: Vec<u8>) -> Result<String, PaykitFfiError> {
    String::from_utf8(bytes)
        .map_err(|_| validation_error("snapshot serialization produced non-UTF-8 bytes"))
}

#[cfg(test)]
pub(crate) fn first_local_handshake_slot(
    local_noise_secret: &[u8; 32],
    local_identity: &PublicKey,
    remote_identity: &PublicKey,
    remote_noise: &PublicKey,
    local_path: &PaykitReceiverPath,
    remote_path: &PaykitReceiverPath,
) -> String {
    let (write_path, _) = derived_write_read_paths(
        local_noise_secret,
        local_identity,
        remote_identity,
        remote_noise,
        local_path,
        remote_path,
    );
    format!("{write_path}/0")
}

#[cfg(test)]
mod tests;
