use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use paykit_sdk::storage::LinkedPeerRecord;
use paykit_sdk::{
    EncryptedLinkHandshakeRole, EncryptedLinkRecoveryMarkerReport, InitializationReport,
    LinkedPeerHandshakeReport, LinkedPeerState, PaykitReceiverPath, PaykitSdk, PaykitSdkConfig,
    PaykitSdkError, PaymentAdapter, PubkyPublicKey, PubkySessionAccess, PubkySessionProvider,
    ReceiverNoiseSecretKey,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::{
    error::js_err,
    keys::secret_key_from_slice,
    sdk_storage::{IndexedDbBlobStore, WasmSdkStorage},
    session::{PubkyClient, SessionHandle},
};

type WasmSdkRuntime = PaykitSdk<WasmSdkStorage, WasmSessionProvider, WasmNoopPaymentAdapter>;

/// Browser session boundary for the managed SDK runtime.
///
/// This deliberately holds a live `SessionHandle` in memory only. The
/// browser's HTTP-only cookie remains the credential; IndexedDB stores only
/// opaque SDK link state and never session or receiver-key material.
#[derive(Clone)]
struct WasmSessionProvider {
    access: Arc<Mutex<Option<PubkySessionAccess>>>,
}

impl WasmSessionProvider {
    fn new(access: PubkySessionAccess) -> Self {
        Self {
            access: Arc::new(Mutex::new(Some(access))),
        }
    }
}

#[async_trait]
impl PubkySessionProvider for WasmSessionProvider {
    async fn load_session_access(&self) -> paykit_sdk::Result<Option<PubkySessionAccess>> {
        Ok(self
            .access
            .lock()
            .map_err(|_| provider_error("load browser session"))?
            .clone())
    }

    async fn load_public_storage(&self) -> paykit_sdk::Result<Option<pubky::PublicStorage>> {
        Ok(self
            .access
            .lock()
            .map_err(|_| provider_error("load browser public storage"))?
            .as_ref()
            .map(|access| access.outbox_client.public_storage()))
    }

    async fn clear_session_access(&self) -> paykit_sdk::Result<()> {
        *self
            .access
            .lock()
            .map_err(|_| provider_error("clear browser session"))? = None;
        Ok(())
    }
}

/// Chat-only managed-link runtime. Payment methods are intentionally absent;
/// its default `PaymentAdapter` methods fail closed if a caller accidentally
/// requests payment processing from this binding.
#[derive(Clone, Default)]
struct WasmNoopPaymentAdapter;

impl PaymentAdapter for WasmNoopPaymentAdapter {}

/// Stateful Paykit SDK lifecycle binding for one browser identity.
///
/// The handle owns the same Rust `ensure_link_with_peer` and recovery-marker
/// state machine used by the mobile FFI. Its durable state is one
/// revision-checked IndexedDB blob keyed by the authenticated Pubky owner.
#[wasm_bindgen]
pub struct PaykitSdkHandle {
    runtime: Arc<WasmSdkRuntime>,
    blob_store: IndexedDbBlobStore,
}

#[wasm_bindgen]
impl PaykitSdkHandle {
    /// Construct a managed-link runtime for `session.pubky()`.
    ///
    /// `receiverNoiseSecretKey` is supplied from the app KeyStore on each
    /// construction and is never written to IndexedDB. A restored browser
    /// session should be passed after `PubkyClient.restoreSession()` or
    /// `resumeSessionFromCookie()`.
    #[wasm_bindgen(constructor)]
    pub fn new(
        session: &SessionHandle,
        client: &PubkyClient,
        receiver_noise_secret_key: &[u8],
        receiver_path: &str,
    ) -> Result<PaykitSdkHandle, JsValue> {
        let receiver_path = PaykitReceiverPath::new(receiver_path)
            .map_err(|err| js_err("invalid local receiver path", err))?;
        let receiver_noise_secret_key =
            ReceiverNoiseSecretKey::new(secret_key_from_slice(receiver_noise_secret_key)?);
        let access = PubkySessionAccess {
            session: session.inner.clone(),
            outbox_client: client.inner.clone(),
            local_secret_key: None,
            receiver_noise_secret_key,
        };
        let owner = access
            .public_key()
            .map_err(|err| js_err("invalid session identity", err))?
            .to_string();
        let blob_store = IndexedDbBlobStore::new(owner);
        let runtime = PaykitSdk::new(
            WasmSdkStorage::new(blob_store.clone()),
            WasmSessionProvider::new(access),
            WasmNoopPaymentAdapter,
            PaykitSdkConfig::new(receiver_path),
        )
        .map_err(|err| js_err("create managed Paykit SDK", err))?;

        Ok(Self {
            runtime: Arc::new(runtime),
            blob_store,
        })
    }

    /// Initialize or refresh the persisted SDK identity state.
    pub fn initialize(&self) -> js_sys::Promise {
        let runtime = Arc::clone(&self.runtime);
        future_to_promise(async move {
            let report = runtime
                .initialize()
                .await
                .map_err(|err| js_err("initialize managed Paykit SDK", err))?;
            Ok(initialization_report_value(report))
        })
    }

    /// Start or advance the deterministic Encrypted Link lifecycle.
    ///
    /// Apps call this with `maxAdvanceSteps = 2`, then schedule another call
    /// while the returned state is `"Linking"`. It does not poll remote
    /// recovery markers; call `observeEncryptedLinkRecoveryMarker` on thread
    /// open and inbox sync even while a peer is `"Linked"`.
    #[wasm_bindgen(js_name = ensureLinkWithPeer)]
    pub fn ensure_link_with_peer(
        &self,
        counterparty: &str,
        counterparty_receiver_path: &str,
        max_advance_steps: u32,
    ) -> Result<js_sys::Promise, JsValue> {
        let counterparty = parse_public_key(counterparty)?;
        let counterparty_receiver_path = parse_receiver_path(counterparty_receiver_path)?;
        let runtime = Arc::clone(&self.runtime);
        Ok(future_to_promise(async move {
            let report = runtime
                .ensure_link_with_peer(counterparty, counterparty_receiver_path, max_advance_steps)
                .await
                .map_err(|err| js_err("ensure managed Encrypted Link", err))?;
            Ok(handshake_report_value(report))
        }))
    }

    /// Observe a counterparty recovery marker.
    ///
    /// This is intentionally separate from `ensureLinkWithPeer`: polling on
    /// every outbound drain would add a homeserver GET to the hot path.
    #[wasm_bindgen(js_name = observeEncryptedLinkRecoveryMarker)]
    pub fn observe_encrypted_link_recovery_marker(
        &self,
        counterparty: &str,
        counterparty_receiver_path: &str,
    ) -> Result<js_sys::Promise, JsValue> {
        let counterparty = parse_public_key(counterparty)?;
        let counterparty_receiver_path = parse_receiver_path(counterparty_receiver_path)?;
        let runtime = Arc::clone(&self.runtime);
        Ok(future_to_promise(async move {
            let report = runtime
                .observe_encrypted_link_recovery_marker(counterparty, counterparty_receiver_path)
                .await
                .map_err(|err| js_err("observe Encrypted Link recovery marker", err))?;
            Ok(recovery_marker_report_value(report))
        }))
    }

    /// Publish a local recovery marker for an explicit user retry.
    #[wasm_bindgen(js_name = publishEncryptedLinkRecoveryMarker)]
    pub fn publish_encrypted_link_recovery_marker(
        &self,
        counterparty: &str,
        counterparty_receiver_path: &str,
    ) -> Result<js_sys::Promise, JsValue> {
        let counterparty = parse_public_key(counterparty)?;
        let counterparty_receiver_path = parse_receiver_path(counterparty_receiver_path)?;
        let runtime = Arc::clone(&self.runtime);
        Ok(future_to_promise(async move {
            let report = runtime
                .publish_encrypted_link_recovery_marker(counterparty, counterparty_receiver_path)
                .await
                .map_err(|err| js_err("publish Encrypted Link recovery marker", err))?;
            Ok(recovery_marker_report_value(report))
        }))
    }

    /// Return the tracked recovery-marker state, if this peer is known.
    #[wasm_bindgen(js_name = encryptedLinkRecoveryMarkerStatus)]
    pub fn encrypted_link_recovery_marker_status(
        &self,
        counterparty: &str,
        counterparty_receiver_path: &str,
    ) -> Result<js_sys::Promise, JsValue> {
        let counterparty = parse_public_key(counterparty)?;
        let counterparty_receiver_path = parse_receiver_path(counterparty_receiver_path)?;
        let runtime = Arc::clone(&self.runtime);
        Ok(future_to_promise(async move {
            let report = runtime
                .encrypted_link_recovery_marker_status(&counterparty, &counterparty_receiver_path)
                .await
                .map_err(|err| js_err("read Encrypted Link recovery marker status", err))?;
            Ok(report
                .map(recovery_marker_report_value)
                .unwrap_or(JsValue::UNDEFINED))
        }))
    }

    /// List SDK-managed peer lifecycle records for UI state mapping.
    #[wasm_bindgen(js_name = linkedPeers)]
    pub fn linked_peers(&self) -> js_sys::Promise {
        let runtime = Arc::clone(&self.runtime);
        future_to_promise(async move {
            let peers = runtime
                .linked_peers()
                .await
                .map_err(|err| js_err("list managed Encrypted Link peers", err))?;
            let values = js_sys::Array::new();
            for peer in peers {
                values.push(&linked_peer_value(peer));
            }
            Ok(values.into())
        })
    }

    /// Delete the owner-scoped IndexedDB state blob after app sign-out.
    ///
    /// This is local-only and does not delete an Encrypted Link outbox or any
    /// remote history. Call it only after the app has completed its explicit
    /// sign-out/wipe transaction.
    #[wasm_bindgen(js_name = deletePersistedState)]
    pub fn delete_persisted_state(&self) -> js_sys::Promise {
        let blob_store = self.blob_store.clone();
        future_to_promise(async move {
            blob_store
                .delete()
                .await
                .map_err(|err| js_err("delete managed Paykit SDK state", err))?;
            Ok(JsValue::UNDEFINED)
        })
    }
}

fn parse_public_key(value: &str) -> Result<PubkyPublicKey, JsValue> {
    PubkyPublicKey::new(value).map_err(|err| js_err("invalid counterparty Pubky", err))
}

fn parse_receiver_path(value: &str) -> Result<PaykitReceiverPath, JsValue> {
    PaykitReceiverPath::new(value).map_err(|err| js_err("invalid counterparty receiver path", err))
}

fn provider_error(context: &str) -> PaykitSdkError {
    PaykitSdkError::Storage {
        context: context.into(),
        source: None,
    }
}

fn set(object: &js_sys::Object, key: &str, value: &JsValue) {
    let _ = js_sys::Reflect::set(object, &JsValue::from_str(key), value);
}

fn initialization_report_value(report: InitializationReport) -> JsValue {
    let object = js_sys::Object::new();
    set(
        &object,
        "publicKey",
        &report
            .identity
            .public_key
            .as_ref()
            .map(|value| JsValue::from_str(&value.to_string()))
            .unwrap_or(JsValue::UNDEFINED),
    );
    set(
        &object,
        "liveSessionAvailable",
        &JsValue::from_bool(report.identity.live_session_available),
    );
    object.into()
}

fn handshake_report_value(report: LinkedPeerHandshakeReport) -> JsValue {
    let object = js_sys::Object::new();
    set(
        &object,
        "counterparty",
        &JsValue::from_str(&report.counterparty.to_string()),
    );
    set(
        &object,
        "counterpartyReceiverPath",
        &JsValue::from_str(&report.counterparty_receiver_path.to_string()),
    );
    set(
        &object,
        "state",
        &JsValue::from_str(linked_peer_state_name(&report.state)),
    );
    set(
        &object,
        "generation",
        &JsValue::from_f64(report.generation as f64),
    );
    set(
        &object,
        "handshakeRole",
        &report
            .handshake_role
            .as_ref()
            .map(handshake_role_name)
            .map(JsValue::from_str)
            .unwrap_or(JsValue::UNDEFINED),
    );
    object.into()
}

fn recovery_marker_report_value(report: EncryptedLinkRecoveryMarkerReport) -> JsValue {
    let object = js_sys::Object::new();
    set(
        &object,
        "counterparty",
        &JsValue::from_str(&report.counterparty.to_string()),
    );
    set(
        &object,
        "counterpartyReceiverPath",
        &JsValue::from_str(&report.counterparty_receiver_path.to_string()),
    );
    set(
        &object,
        "state",
        &JsValue::from_str(linked_peer_state_name(&report.state)),
    );
    set(
        &object,
        "localAttemptId",
        &report
            .local_attempt_id
            .as_deref()
            .map(JsValue::from_str)
            .unwrap_or(JsValue::UNDEFINED),
    );
    set(
        &object,
        "localMarkerCreatedAt",
        &report
            .local_marker_created_at
            .map(|value| JsValue::from_str(&value.to_rfc3339()))
            .unwrap_or(JsValue::UNDEFINED),
    );
    set(
        &object,
        "localMarkerHasError",
        &JsValue::from_bool(report.local_marker_last_error.is_some()),
    );
    set(
        &object,
        "remoteAttemptId",
        &report
            .remote_attempt_id
            .as_deref()
            .map(JsValue::from_str)
            .unwrap_or(JsValue::UNDEFINED),
    );
    set(
        &object,
        "remoteMarkerObservedAt",
        &report
            .remote_marker_observed_at
            .map(|value| JsValue::from_str(&value.to_rfc3339()))
            .unwrap_or(JsValue::UNDEFINED),
    );
    set(
        &object,
        "remoteMarkerChanged",
        &JsValue::from_bool(report.remote_marker_changed),
    );
    object.into()
}

fn linked_peer_value(peer: LinkedPeerRecord) -> JsValue {
    let object = js_sys::Object::new();
    set(
        &object,
        "counterparty",
        &JsValue::from_str(&peer.counterparty.to_string()),
    );
    set(
        &object,
        "counterpartyReceiverPath",
        &JsValue::from_str(&peer.counterparty_receiver_path.to_string()),
    );
    set(
        &object,
        "state",
        &JsValue::from_str(linked_peer_state_name(&peer.state)),
    );
    set(
        &object,
        "failureCount",
        &JsValue::from_f64(peer.failure_count as f64),
    );
    object.into()
}

fn linked_peer_state_name(value: &LinkedPeerState) -> &'static str {
    match value {
        LinkedPeerState::NotLinked => "NotLinked",
        LinkedPeerState::Linking => "Linking",
        LinkedPeerState::Linked => "Linked",
        LinkedPeerState::RecoveryRequired => "RecoveryRequired",
        LinkedPeerState::Blocked => "Blocked",
        _ => "Unknown",
    }
}

fn handshake_role_name(value: &EncryptedLinkHandshakeRole) -> &'static str {
    match value {
        EncryptedLinkHandshakeRole::Initiator => "Initiator",
        EncryptedLinkHandshakeRole::Responder => "Responder",
        _ => "Unknown",
    }
}
