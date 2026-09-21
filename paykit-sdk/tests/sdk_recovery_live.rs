use async_trait::async_trait;
use chrono::Utc;
use paykit_sdk::storage::{
    EncryptedLinkStateRecord, EventDedupRecord, LinkedPeerRecord, OutboundPrivateMessageRecord,
    PaymentEndpointReservationRecord, PeerLinkOperationLease, PrivateStreamItemRecord,
    PublicEndpointRecord, StorageState,
};
use paykit_sdk::{
    InMemoryStorage, LinkedPeerState, PaykitReceiverCapabilities, PaykitReceiverPath, PaykitSdk,
    PaykitSdkConfig, PaymentAdapter, PaymentTarget, PrivatePaymentEndpointCandidate,
    PrivatePaymentEndpointSelectionRequest, PrivateReceivingDetail, PubkyLocalSecretKey,
    PubkyPublicKey, PubkySessionAccess, PubkySessionBootstrap, PubkySessionProvider,
    PublicPaymentEndpointCandidate, PublicPaymentEndpointSelectionRequest, PublicReceivingDetail,
    ReceiverNoiseSecretKey, SdkBackupState, StorageAdapter,
};
use pubky::Keypair;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::sleep;

const HOMESERVER: &str = "ufibwbmed6jeq9k4p583go95wofakh9fwpp4k734trq79pd9u1uy";
const HOMESERVER_HTTP: &str = "https://homeserver.staging.pubky.app";
const RECEIVER: &str = "hypercolor/wallet";

#[derive(Serialize, Deserialize)]
struct StorageStateWire {
    identity_state: Option<paykit_sdk::IdentityState>,
    linked_peers: Vec<(PubkyPublicKey, PaykitReceiverPath, LinkedPeerRecord)>,
    contact_records: Vec<(PubkyPublicKey, paykit_sdk::ContactRecord)>,
    public_endpoint_records: Vec<(String, PublicEndpointRecord)>,
    payment_endpoint_reservations: Vec<(
        PubkyPublicKey,
        PaykitReceiverPath,
        String,
        PaymentEndpointReservationRecord,
    )>,
    encrypted_link_states: Vec<(PubkyPublicKey, PaykitReceiverPath, EncryptedLinkStateRecord)>,
    peer_link_operation_leases: Vec<(PubkyPublicKey, PaykitReceiverPath, PeerLinkOperationLease)>,
    next_peer_link_operation_lease_id: u64,
    outbound_private_messages: Vec<OutboundPrivateMessageRecord>,
    next_outbound_private_message_id: u64,
    private_stream_items: Vec<PrivateStreamItemRecord>,
    next_receive_batch_id: u64,
    next_private_stream_item_id: u64,
    event_dedup_records: Vec<(PubkyPublicKey, PaykitReceiverPath, String, EventDedupRecord)>,
    receipt_access_records: Vec<(
        PubkyPublicKey,
        PaykitReceiverPath,
        String,
        serde_json::Value,
    )>,
    receipt_records: Vec<(
        PubkyPublicKey,
        PaykitReceiverPath,
        String,
        paykit_sdk::ReceiptRecord,
    )>,
    receipt_issuance_records: Vec<(
        PubkyPublicKey,
        PaykitReceiverPath,
        String,
        serde_json::Value,
    )>,
}

impl From<StorageState> for StorageStateWire {
    fn from(state: StorageState) -> Self {
        Self {
            identity_state: state.identity_state,
            linked_peers: state
                .linked_peers
                .into_iter()
                .map(|((key, path), value)| (key, path, value))
                .collect(),
            contact_records: state.contact_records.into_iter().collect(),
            public_endpoint_records: state.public_endpoint_records.into_iter().collect(),
            payment_endpoint_reservations: state
                .payment_endpoint_reservations
                .into_iter()
                .map(|((key, path, id), value)| (key, path, id, value))
                .collect(),
            encrypted_link_states: state
                .encrypted_link_states
                .into_iter()
                .map(|((key, path), value)| (key, path, value))
                .collect(),
            peer_link_operation_leases: state
                .peer_link_operation_leases
                .into_iter()
                .map(|((key, path), value)| (key, path, value))
                .collect(),
            next_peer_link_operation_lease_id: state.next_peer_link_operation_lease_id,
            outbound_private_messages: state.outbound_private_messages,
            next_outbound_private_message_id: state.next_outbound_private_message_id,
            private_stream_items: state.private_stream_items,
            next_receive_batch_id: state.next_receive_batch_id,
            next_private_stream_item_id: state.next_private_stream_item_id,
            event_dedup_records: state
                .event_dedup_records
                .into_iter()
                .map(|((key, path, id), value)| (key, path, id, value))
                .collect(),
            receipt_access_records: state
                .receipt_access_records
                .into_iter()
                .map(|((key, path, id), value)| {
                    (key, path, id, serde_json::to_value(value).unwrap())
                })
                .collect(),
            receipt_records: state
                .receipt_records
                .into_iter()
                .map(|((key, path, id), value)| (key, path, id, value))
                .collect(),
            receipt_issuance_records: state
                .receipt_issuance_records
                .into_iter()
                .map(|((key, path, id), value)| {
                    (key, path, id, serde_json::to_value(value).unwrap())
                })
                .collect(),
        }
    }
}

impl From<StorageStateWire> for StorageState {
    fn from(wire: StorageStateWire) -> Self {
        Self {
            identity_state: wire.identity_state,
            linked_peers: wire
                .linked_peers
                .into_iter()
                .map(|(key, path, value)| ((key, path), value))
                .collect::<HashMap<_, _>>(),
            contact_records: wire.contact_records.into_iter().collect(),
            public_endpoint_records: wire.public_endpoint_records.into_iter().collect(),
            payment_endpoint_reservations: wire
                .payment_endpoint_reservations
                .into_iter()
                .map(|(key, path, id, value)| ((key, path, id), value))
                .collect(),
            encrypted_link_states: wire
                .encrypted_link_states
                .into_iter()
                .map(|(key, path, value)| ((key, path), value))
                .collect(),
            peer_link_operation_leases: wire
                .peer_link_operation_leases
                .into_iter()
                .map(|(key, path, value)| ((key, path), value))
                .collect(),
            next_peer_link_operation_lease_id: wire.next_peer_link_operation_lease_id,
            outbound_private_messages: wire.outbound_private_messages,
            next_outbound_private_message_id: wire.next_outbound_private_message_id,
            private_stream_items: wire.private_stream_items,
            next_receive_batch_id: wire.next_receive_batch_id,
            next_private_stream_item_id: wire.next_private_stream_item_id,
            event_dedup_records: wire
                .event_dedup_records
                .into_iter()
                .map(|(key, path, id, value)| ((key, path, id), value))
                .collect(),
            receipt_access_records: wire
                .receipt_access_records
                .into_iter()
                .map(|(key, path, id, value)| {
                    ((key, path, id), serde_json::from_value(value).unwrap())
                })
                .collect(),
            receipt_records: wire
                .receipt_records
                .into_iter()
                .map(|(key, path, id, value)| ((key, path, id), value))
                .collect(),
            receipt_issuance_records: wire
                .receipt_issuance_records
                .into_iter()
                .map(|(key, path, id, value)| {
                    ((key, path, id), serde_json::from_value(value).unwrap())
                })
                .collect(),
        }
    }
}

#[test]
fn storage_state_json_roundtrip_preserves_full_state_shape() {
    let state = StorageState::default();
    let json = serde_json::to_vec(&StorageStateWire::from(state.clone())).unwrap();
    let restored: StorageState = serde_json::from_slice::<StorageStateWire>(&json)
        .unwrap()
        .into();
    assert_eq!(restored, state);
}

#[derive(Clone)]
struct DurableStorage {
    inner: InMemoryStorage,
    path: Arc<PathBuf>,
}

impl DurableStorage {
    fn open(path: impl Into<PathBuf>) -> (Self, Option<StorageState>) {
        let path = path.into();
        let loaded = fs::read(&path).ok().and_then(|bytes| {
            serde_json::from_slice::<StorageStateWire>(&bytes)
                .ok()
                .map(StorageState::from)
        });
        (
            Self {
                inner: InMemoryStorage::new(),
                path: Arc::new(path),
            },
            loaded,
        )
    }

    fn persist(&self) -> paykit_sdk::Result<()> {
        let state = self.inner.snapshot()?;
        let bytes = serde_json::to_vec_pretty(&StorageStateWire::from(state)).map_err(|err| {
            paykit_sdk::PaykitSdkError::Storage {
                context: "serialize durable recovery state".into(),
                source: Some(anyhow::anyhow!(err)),
            }
        })?;
        fs::write(self.path.as_ref(), bytes).map_err(|err| paykit_sdk::PaykitSdkError::Storage {
            context: "write durable recovery state".into(),
            source: Some(anyhow::anyhow!(err)),
        })
    }
}

#[async_trait]
impl StorageAdapter for DurableStorage {
    async fn transaction_erased<'a>(
        &self,
        f: paykit_sdk::storage::StorageTransactionCallback<'a>,
    ) -> paykit_sdk::Result<Box<dyn std::any::Any + Send>> {
        let result = self.inner.transaction_erased(f).await?;
        self.persist()?;
        Ok(result)
    }
}

#[derive(Clone)]
struct Provider {
    access: Arc<Mutex<Option<PubkySessionAccess>>>,
}

#[async_trait]
impl PubkySessionProvider for Provider {
    async fn load_session_access(&self) -> paykit_sdk::Result<Option<PubkySessionAccess>> {
        Ok(self.access.lock().expect("provider lock").clone())
    }

    async fn load_public_storage(&self) -> paykit_sdk::Result<Option<pubky::PublicStorage>> {
        Ok(self
            .access
            .lock()
            .expect("provider lock")
            .as_ref()
            .map(|access| access.outbox_client.public_storage()))
    }

    async fn clear_session_access(&self) -> paykit_sdk::Result<()> {
        *self.access.lock().expect("provider lock") = None;
        Ok(())
    }
}

#[derive(Clone, Default)]
struct Adapter {
    private: Arc<Mutex<Vec<PrivateReceivingDetail>>>,
}

#[async_trait]
impl PaymentAdapter for Adapter {
    async fn current_public_receiving_details(
        &self,
    ) -> paykit_sdk::Result<Vec<PublicReceivingDetail>> {
        Ok(Vec::new())
    }

    async fn current_private_receiving_details(
        &self,
        _: &PubkyPublicKey,
        _: &PaykitReceiverPath,
    ) -> paykit_sdk::Result<Vec<PrivateReceivingDetail>> {
        Ok(self.private.lock().expect("adapter lock").clone())
    }

    async fn select_public_payment_endpoints(
        &self,
        request: &PublicPaymentEndpointSelectionRequest,
    ) -> paykit_sdk::Result<Vec<PublicPaymentEndpointCandidate>> {
        Ok(request.candidates.clone())
    }

    async fn build_public_payment_target(
        &self,
        endpoint: &PublicPaymentEndpointCandidate,
    ) -> paykit_sdk::Result<PaymentTarget> {
        Ok(PaymentTarget {
            payload: endpoint.payload.clone(),
        })
    }

    async fn select_private_payment_endpoints(
        &self,
        request: &PrivatePaymentEndpointSelectionRequest,
    ) -> paykit_sdk::Result<Vec<PrivatePaymentEndpointCandidate>> {
        Ok(request.candidates.clone())
    }

    async fn build_private_payment_target(
        &self,
        endpoint: &PrivatePaymentEndpointCandidate,
    ) -> paykit_sdk::Result<PaymentTarget> {
        Ok(PaymentTarget {
            payload: endpoint.payload.clone(),
        })
    }
}

struct Runtime {
    sdk: PaykitSdk<DurableStorage, Provider, Adapter>,
    access: PubkySessionAccess,
    public_key: PubkyPublicKey,
    receiver_path: PaykitReceiverPath,
}

async fn new_runtime(
    access: PubkySessionAccess,
    path: &Path,
    loaded: Option<StorageState>,
) -> Runtime {
    let public_key = PubkyPublicKey::from_public_key(access.session.info().public_key());
    let receiver_path = PaykitReceiverPath::new(RECEIVER).unwrap();
    let storage = DurableStorage::open(path).0;
    let provider = Provider {
        access: Arc::new(Mutex::new(Some(access.clone()))),
    };
    let adapter = Adapter {
        private: Arc::new(Mutex::new(vec![PrivateReceivingDetail {
            identifier: "hypercolor-recovery".into(),
            payload: "live-recovery-payload".into(),
        }])),
    };
    let config = PaykitSdkConfig::new(receiver_path.clone());
    let sdk = PaykitSdk::new(storage.clone(), provider, adapter, config).unwrap();
    sdk.initialize().await.unwrap();
    if let Some(state) = loaded {
        sdk.restore_backup_state(backup_from_state(state, receiver_path.clone()))
            .await
            .unwrap();
    }
    sdk.publish_paykit_receiver_marker(PaykitReceiverCapabilities {
        private_payments: true,
        payment_requests: true,
        receipts: true,
        outgoing_payments: true,
    })
    .await
    .unwrap();
    Runtime {
        sdk,
        access,
        public_key,
        receiver_path,
    }
}

fn backup_from_state(state: StorageState, receiver_path: PaykitReceiverPath) -> SdkBackupState {
    SdkBackupState {
        version: paykit_sdk::SDK_BACKUP_VERSION,
        local_receiver_path: receiver_path,
        identity_state: state.identity_state,
        linked_peers: state.linked_peers.into_values().collect(),
        contact_records: state.contact_records.into_values().collect(),
        public_endpoint_records: state.public_endpoint_records.into_values().collect(),
        payment_endpoint_reservations: state.payment_endpoint_reservations.into_values().collect(),
        encrypted_link_states: state.encrypted_link_states.into_values().collect(),
        outbound_private_messages: state.outbound_private_messages,
        private_stream_items: state.private_stream_items,
        event_dedup_records: state.event_dedup_records.into_values().collect(),
        receipt_access_records: state.receipt_access_records.into_values().collect(),
        receipt_records: state.receipt_records.into_values().collect(),
        receipt_issuance_records: state.receipt_issuance_records.into_values().collect(),
        next_outbound_private_message_id: state.next_outbound_private_message_id,
        next_receive_batch_id: state.next_receive_batch_id,
        next_private_stream_item_id: state.next_private_stream_item_id,
    }
}

fn token(path: &Path) -> String {
    fs::read_to_string(path).unwrap().trim().to_owned()
}

#[derive(Serialize, Deserialize)]
struct PersistedIdentity {
    public_key: PubkyPublicKey,
    secret_key: [u8; 32],
    receiver_noise_secret_key: [u8; 32],
}

async fn sign_in(identity_path: &Path) -> (PubkySessionAccess, PubkyPublicKey) {
    let identity: PersistedIdentity =
        serde_json::from_slice(&fs::read(identity_path).unwrap()).unwrap();
    let bootstrap = PubkySessionBootstrap::new().unwrap();
    let config = PaykitSdkConfig::new(PaykitReceiverPath::new(RECEIVER).unwrap());
    let result = bootstrap
        .sign_in(
            &PubkyLocalSecretKey::new(identity.secret_key),
            ReceiverNoiseSecretKey::from(identity.receiver_noise_secret_key),
            &config.required_session_capabilities(),
        )
        .await
        .unwrap();
    assert_eq!(result.public_key, identity.public_key);
    (result.access, result.public_key)
}

async fn signup_or_resume(
    token_path: &Path,
    identity_path: &Path,
) -> (PubkySessionAccess, PubkyPublicKey) {
    if identity_path.exists() {
        return sign_in(identity_path).await;
    }
    let token_value = token(token_path);
    let secret = PubkyLocalSecretKey::new(Keypair::random().secret_key());
    let receiver = ReceiverNoiseSecretKey::random();
    let bootstrap = PubkySessionBootstrap::new().unwrap();
    let homeserver = PubkyPublicKey::new(HOMESERVER).unwrap();
    let config = PaykitSdkConfig::new(PaykitReceiverPath::new(RECEIVER).unwrap());
    let result = bootstrap
        .sign_up(
            &secret,
            receiver.clone(),
            &homeserver,
            Some(&token_value),
            &config.required_session_capabilities(),
        )
        .await
        .unwrap();
    let persisted = PersistedIdentity {
        public_key: result.public_key.clone(),
        secret_key: *secret.as_bytes(),
        receiver_noise_secret_key: *receiver.as_bytes(),
    };
    fs::write(
        identity_path,
        serde_json::to_vec_pretty(&persisted).unwrap(),
    )
    .unwrap();
    fs::remove_file(token_path).unwrap();
    (result.access, result.public_key)
}

fn curl(path: &str, owner: &PubkyPublicKey) -> String {
    let url = format!("{HOMESERVER_HTTP}{path}?pubky-host={owner}");
    let output = Command::new("curl")
        .args(["-sS", "-w", "\nHTTP %{http_code}\n", &url])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn recovery_marker_write_path(local: &Runtime, remote: &Runtime) -> String {
    paykit_lib::encrypted_link_recovery_marker_paths(
        local.access.receiver_noise_secret_key.as_bytes(),
        local.access.session.info().public_key(),
        &remote.public_key.to_public_key().unwrap(),
        &remote.access.receiver_noise_secret_key.public_key(),
        &local.receiver_path,
        &remote.receiver_path,
    )
    .0
}

async fn list_owned(access: &PubkySessionAccess, path: &str) -> Vec<String> {
    let path = path.trim_end_matches('/');
    let result = access
        .session
        .storage()
        .list(format!("{path}/"))
        .unwrap()
        .shallow(true)
        .limit(100)
        .send()
        .await;
    let page = match result {
        Ok(page) => page,
        Err(err) if err.to_string().contains("Directory Not Found") => return Vec::new(),
        Err(err) => panic!("listing {path} failed: {err}"),
    };
    page.into_iter()
        .map(|resource| resource.path.as_str().to_owned())
        .collect()
}

async fn delete_tree(access: &PubkySessionAccess, path: &str) {
    loop {
        let slots = list_owned(access, path).await;
        if slots.is_empty() {
            return;
        }
        for slot in slots {
            access.session.storage().delete(slot).await.unwrap();
        }
    }
}

async fn drive_link(g: &Runtime, h: &Runtime, log: &mut String) {
    let mut last_g = None;
    let mut last_h = None;
    for i in 0..30 {
        let _ = g
            .sdk
            .observe_encrypted_link_recovery_marker(h.public_key.clone(), h.receiver_path.clone())
            .await;
        let _ = h
            .sdk
            .observe_encrypted_link_recovery_marker(g.public_key.clone(), g.receiver_path.clone())
            .await;
        let rg = g
            .sdk
            .ensure_link_with_peer(h.public_key.clone(), h.receiver_path.clone(), 2)
            .await;
        let rh = h
            .sdk
            .ensure_link_with_peer(g.public_key.clone(), g.receiver_path.clone(), 2)
            .await;
        let sg = rg.as_ref().ok().map(|r| r.state.clone());
        let sh = rh.as_ref().ok().map(|r| r.state.clone());
        if i == 0 || sg != last_g || sh != last_h {
            log.push_str(&format!(
                "{} G={sg:?} H={sh:?} errors={:?}/{:?}\n",
                Utc::now().to_rfc3339(),
                rg.as_ref().err(),
                rh.as_ref().err()
            ));
            last_g = sg.clone();
            last_h = sh.clone();
        }
        if sg == Some(LinkedPeerState::Linked) && sh == Some(LinkedPeerState::Linked) {
            log.push_str(&format!("linked after iteration {i}\n"));
            return;
        }
        sleep(Duration::from_millis(250)).await;
    }
    panic!("link did not converge: {log}");
}

#[tokio::test]
#[ignore = "live staging verification; run explicitly"]
async fn sdk_recovery_live_staging() {
    let evidence = PathBuf::from(
        std::env::var("PAYKIT_RECOVERY_EVIDENCE")
            .expect("PAYKIT_RECOVERY_EVIDENCE must point to the evidence directory"),
    );
    fs::create_dir_all(&evidence).unwrap();
    let g_token = evidence.join("token-J.txt");
    let h_token = evidence.join("token-K.txt");
    let g_state = evidence.join("g-storage.json");
    let h_state = evidence.join("h-storage.json");
    let (g_access, _) = signup_or_resume(&g_token, &evidence.join("j-identity.json")).await;
    let (h_access, _) = signup_or_resume(&h_token, &evidence.join("k-identity.json")).await;
    let mut report = format!(
        "# Hypercolor W63 SDK Recovery Verification\n\nG={} H={}\n\n",
        PubkyPublicKey::from_public_key(g_access.session.info().public_key()),
        PubkyPublicKey::from_public_key(h_access.session.info().public_key())
    );
    let g = new_runtime(g_access.clone(), &g_state, None).await;
    let h = new_runtime(h_access.clone(), &h_state, None).await;
    report.push_str("## Initial marker publication\n");
    report.push_str(&format!(
        "G marker: {}\nH marker: {}\n",
        curl(
            "/pub/paykit/v0/hypercolor/wallet/receiver.json",
            &g.public_key
        ),
        curl(
            "/pub/paykit/v0/hypercolor/wallet/receiver.json",
            &h.public_key
        )
    ));
    let mut transitions = String::new();
    drive_link(&g, &h, &mut transitions).await;
    report.push_str("## Initial link transitions\n");
    report.push_str(&transitions);

    g.sdk
        .enqueue_private_payment_list_with_receiving_details(
            h.public_key.clone(),
            h.receiver_path.clone(),
            vec![PrivateReceivingDetail {
                identifier: "g-before-damage".into(),
                payload: "g-before-damage-payload".into(),
            }],
        )
        .await
        .unwrap();
    g.sdk
        .process_outbound_private_messages(h.public_key.clone(), h.receiver_path.clone())
        .await
        .unwrap();
    let h_inbox_before = h
        .sdk
        .receive_private_messages(g.public_key.clone(), g.receiver_path.clone())
        .await
        .unwrap();
    report.push_str(&format!("Initial G->H receipt: {h_inbox_before:?}\n"));
    g.sdk
        .enqueue_private_payment_list_with_receiving_details(
            h.public_key.clone(),
            h.receiver_path.clone(),
            vec![PrivateReceivingDetail {
                identifier: "g-undelivered-before-damage".into(),
                payload: "g-undelivered-before-damage-payload".into(),
            }],
        )
        .await
        .unwrap();
    g.sdk
        .process_outbound_private_messages(h.public_key.clone(), h.receiver_path.clone())
        .await
        .unwrap();
    report.push_str("Undelivered inbound staged before damage: G->H sent, H not read\n");

    let g_base = "/pub/paykit/v0/private/hypercolor/wallet/messages";
    let h_base = "/pub/paykit/v0/private/hypercolor/wallet/messages";
    report.push_str(&format!(
        "G outbox listing:\n{}\n",
        curl(g_base, &g.public_key)
    ));
    report.push_str(&format!(
        "H outbox listing:\n{}\n",
        curl(h_base, &h.public_key)
    ));
    let h_dirs = list_owned(&h.access, h_base).await;
    let g_dirs = list_owned(&g.access, g_base).await;
    assert!(!h_dirs.is_empty(), "H outbox directory was not created");
    assert!(!g_dirs.is_empty(), "G outbox directory was not created");
    let g_slots = list_owned(&g.access, &g_dirs[0]).await;
    assert!(!g_slots.is_empty(), "G link directory has no slots");
    let g_slot_zero = g_slots
        .iter()
        .find(|path| path.ends_with("/0"))
        .cloned()
        .unwrap_or_else(|| g_slots[0].clone());
    report.push_str(&format!("Damage H dirs={h_dirs:?}, G slots={g_slots:?}\n"));
    for dir in &h_dirs {
        delete_tree(&h.access, dir).await;
    }
    g.access
        .session
        .storage()
        .delete(g_slot_zero.clone())
        .await
        .unwrap();
    report.push_str(&format!(
        "After damage H={}\nG slot={}\n",
        curl(&h_dirs[0], &h.public_key),
        curl(&g_slot_zero, &g.public_key)
    ));

    drop(g);
    drop(h);
    let (g_access, _) = (g_access, ());
    let (h_access, _) = (h_access, ());
    let (_, g_loaded) = DurableStorage::open(&g_state);
    let (_, h_loaded) = DurableStorage::open(&h_state);
    let g = new_runtime(g_access.clone(), &g_state, g_loaded).await;
    let h = new_runtime(h_access.clone(), &h_state, h_loaded).await;
    report.push_str("## Restart recovery transitions\n");
    let g_restore_probe = g
        .sdk
        .receive_private_messages(h.public_key.clone(), h.receiver_path.clone())
        .await;
    report.push_str(&format!("G restore probe: {g_restore_probe:?}\n"));
    let g_ensure = g
        .sdk
        .ensure_link_with_peer(h.public_key.clone(), h.receiver_path.clone(), 2)
        .await;
    report.push_str(&format!("G ensure after recovery probe: {g_ensure:?}\n"));
    let h_marker_observation = h
        .sdk
        .observe_encrypted_link_recovery_marker(g.public_key.clone(), g.receiver_path.clone())
        .await;
    report.push_str(&format!("H marker observation: {h_marker_observation:?}\n"));
    let g_marker_path = recovery_marker_write_path(&g, &h);
    report.push_str(&format!(
        "G marker path/body before H observation:\n{}\n",
        curl(&g_marker_path, &g.public_key)
    ));
    let mut recovery_transitions = String::new();
    drive_link(&g, &h, &mut recovery_transitions).await;
    report.push_str(&recovery_transitions);
    report.push_str(&format!(
        "G marker path probe: {}\nH marker path probe: {}\n",
        curl(
            "/pub/paykit/v0/private/hypercolor/wallet/recovery",
            &g.public_key
        ),
        curl(
            "/pub/paykit/v0/private/hypercolor/wallet/recovery",
            &h.public_key
        )
    ));
    g.sdk
        .enqueue_private_payment_list(h.public_key.clone(), h.receiver_path.clone())
        .await
        .unwrap();
    g.sdk
        .process_outbound_private_messages(h.public_key.clone(), h.receiver_path.clone())
        .await
        .unwrap();
    let recovered_receive = h
        .sdk
        .receive_private_messages(g.public_key.clone(), g.receiver_path.clone())
        .await;
    report.push_str(&format!(
        "Recovered G->H message receipt: {recovered_receive:?}\n"
    ));
    h.sdk
        .enqueue_private_payment_list_with_receiving_details(
            g.public_key.clone(),
            g.receiver_path.clone(),
            vec![PrivateReceivingDetail {
                identifier: "h-after-recovery".into(),
                payload: "h-after-recovery-payload".into(),
            }],
        )
        .await
        .unwrap();
    h.sdk
        .process_outbound_private_messages(g.public_key.clone(), g.receiver_path.clone())
        .await
        .unwrap();
    let recovered_reverse = g
        .sdk
        .receive_private_messages(h.public_key.clone(), h.receiver_path.clone())
        .await
        .unwrap();
    report.push_str(&format!(
        "Recovered H->G message receipt: {recovered_reverse:?}\n"
    ));

    let h_dirs_again = list_owned(&h.access, h_base).await;
    let g_dirs_again = list_owned(&g.access, g_base).await;
    for dir in &h_dirs_again {
        delete_tree(&h.access, dir).await;
    }
    let g_slots_again = if let Some(dir) = g_dirs_again.first() {
        list_owned(&g.access, dir).await
    } else {
        Vec::new()
    };
    for slot in g_slots_again
        .into_iter()
        .filter(|path| path.ends_with("/0"))
    {
        g.access.session.storage().delete(slot).await.unwrap();
    }
    report.push_str("## Simultaneous recovery\n");
    drop(g);
    drop(h);
    let (_, g_loaded) = DurableStorage::open(&g_state);
    let (_, h_loaded) = DurableStorage::open(&h_state);
    let g = new_runtime(g_access.clone(), &g_state, g_loaded).await;
    let h = new_runtime(h_access.clone(), &h_state, h_loaded).await;
    let (g_probe, h_probe) = tokio::join!(
        g.sdk
            .receive_private_messages(h.public_key.clone(), h.receiver_path.clone()),
        h.sdk
            .receive_private_messages(g.public_key.clone(), g.receiver_path.clone())
    );
    report.push_str(&format!(
        "Concurrent restore probes: G={g_probe:?} H={h_probe:?}\n"
    ));
    let (g_concurrent, h_concurrent) = tokio::join!(
        g.sdk
            .ensure_link_with_peer(h.public_key.clone(), h.receiver_path.clone(), 2),
        h.sdk
            .ensure_link_with_peer(g.public_key.clone(), g.receiver_path.clone(), 2)
    );
    report.push_str(&format!(
        "Concurrent ensure results: G={g_concurrent:?} H={h_concurrent:?}\n"
    ));
    let mut simultaneous_transitions = String::new();
    drive_link(&g, &h, &mut simultaneous_transitions).await;
    report.push_str(&simultaneous_transitions);

    report.push_str("## No-damage restart calibration\n");
    drop(g);
    drop(h);
    let (_, g_loaded) = DurableStorage::open(&g_state);
    let (_, h_loaded) = DurableStorage::open(&h_state);
    let g = new_runtime(g_access, &g_state, g_loaded).await;
    let h = new_runtime(h_access, &h_state, h_loaded).await;
    let (g_clean, h_clean) = tokio::join!(
        g.sdk
            .ensure_link_with_peer(h.public_key.clone(), h.receiver_path.clone(), 2),
        h.sdk
            .ensure_link_with_peer(g.public_key.clone(), g.receiver_path.clone(), 2)
    );
    report.push_str(&format!(
        "No-damage ensure results: G={g_clean:?} H={h_clean:?}\n"
    ));
    report.push_str(&format!(
        "No-damage marker probe: {}\n",
        curl(&recovery_marker_write_path(&g, &h), &g.public_key)
    ));
    fs::write(evidence.join("REPORT.md"), report).unwrap();
    recovered_receive.unwrap();
}
