//! End-to-end tests for the chat Encrypted Link FFI surface.
//!
//! Mirrors the embedded-testnet pattern from paykit-lib's test suite: one
//! embedded Postgres instance shared across the test binary, one ephemeral
//! Pubky testnet (homeserver) per test, and two real signed-up peers driving
//! the actual FFI handles end to end — no mocks and no protocol bypasses.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pubky_testnet::{embedded_postgres::EmbeddedPostgres, EphemeralTestnet};
use tokio::sync::{Mutex as TokioMutex, OnceCell};

use super::*;

const RECEIVER_PATH: &str = "chat/wallet";
const CHAT_KIND: &str = "chat.message.v0";

static SHARED_POSTGRES: OnceCell<EmbeddedPostgres> = OnceCell::const_new();
static TESTNET_BUILD_LOCK: TokioMutex<()> = TokioMutex::const_new(());

async fn shared_postgres() -> &'static EmbeddedPostgres {
    SHARED_POSTGRES
        .get_or_init(|| async {
            EmbeddedPostgres::start()
                .await
                .expect("failed to start embedded postgres")
        })
        .await
}

async fn build_testnet_with(http_relay: bool) -> EphemeralTestnet {
    let _guard = TESTNET_BUILD_LOCK.lock().await;

    let mut builder = if std::env::var_os("TEST_PUBKY_CONNECTION_STRING").is_some() {
        EphemeralTestnet::builder()
    } else {
        let postgres = shared_postgres()
            .await
            .connection_string()
            .expect("embedded postgres connection string should be valid");
        EphemeralTestnet::builder().postgres(postgres)
    };
    if http_relay {
        builder = builder.with_http_relay();
    }

    builder.build().await.unwrap()
}

async fn build_testnet() -> EphemeralTestnet {
    build_testnet_with(false).await
}

struct ChatPeer {
    client: Arc<FfiChatClient>,
    session: Arc<FfiChatSession>,
    identity_secret_hex: String,
    noise_secret_hex: String,
    noise_public_key: String,
}

impl ChatPeer {
    /// Sign up a fresh identity on the testnet homeserver through the FFI
    /// surface and publish a messaging-only receiver marker.
    async fn sign_up(testnet: &EphemeralTestnet) -> Self {
        let client = Arc::new(FfiChatClient::from_pubky(
            testnet.sdk().expect("testnet Pubky client"),
        ));
        let identity_secret_hex = hex::encode(pubky::Keypair::random().secret());
        let session = client
            .signup_with_secret(
                identity_secret_hex.clone(),
                testnet.homeserver_app().public_key().z32(),
                None,
            )
            .await
            .expect("testnet signup should succeed");
        let noise_secret_hex = generate_receiver_noise_secret_key_hex();
        let noise_public_key = receiver_noise_public_key_from_secret_hex(noise_secret_hex.clone())
            .expect("generated noise secret should derive a public key");
        session
            .publish_receiver_marker(
                RECEIVER_PATH.into(),
                noise_public_key.clone(),
                messaging_capabilities(),
            )
            .await
            .expect("receiver marker publication should succeed");
        Self {
            client,
            session,
            identity_secret_hex,
            noise_secret_hex,
            noise_public_key,
        }
    }
}

fn messaging_capabilities() -> FfiChatReceiverCapabilities {
    FfiChatReceiverCapabilities {
        private_payments: true,
        payment_requests: false,
        receipts: false,
        outgoing_payments: false,
    }
}

fn chat_message_json(text: &str) -> String {
    format!(r#"{{"version":1,"kind":"{CHAT_KIND}","payload":{{"text":"{text}"}}}}"#)
}

/// Drive a handshake handle to completion by polling `advance` with a short
/// sleep between retries. Panics on timeout (10 s).
async fn drive_handshake(handshake: Arc<FfiChatLinkHandshake>) -> Arc<FfiChatLink> {
    let start = Instant::now();
    let timeout = Duration::from_secs(10);
    loop {
        assert!(
            start.elapsed() < timeout,
            "handshake timed out after {timeout:?}"
        );
        let step = handshake
            .advance()
            .await
            .expect("handshake advance should succeed");
        if step.complete {
            return step.link.expect("complete step should carry a link");
        }
        assert!(step.link.is_none(), "pending step should not carry a link");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Two signed-up peers with links established in both directions via the
/// marker-discovery + initiate/accept + advance FFI flow.
async fn linked_peers(
    testnet: &EphemeralTestnet,
) -> (ChatPeer, ChatPeer, Arc<FfiChatLink>, Arc<FfiChatLink>) {
    let initiator = ChatPeer::sign_up(testnet).await;
    let responder = ChatPeer::sign_up(testnet).await;

    // Discover the responder's marker like a real chat app would.
    let marker = initiator
        .client
        .get_receiver_marker(responder.session.pubky(), RECEIVER_PATH.into())
        .await
        .expect("marker fetch should succeed")
        .expect("responder marker should be published");
    assert_eq!(marker.receiver_path, RECEIVER_PATH);
    assert_eq!(marker.noise_public_key, responder.noise_public_key);
    assert!(marker.capabilities.private_payments);
    assert!(!marker.capabilities.payment_requests);

    let initiator_handshake = initiator
        .session
        .initiate_encrypted_link(
            initiator.noise_secret_hex.clone(),
            responder.session.pubky(),
            marker.noise_public_key.clone(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
        )
        .expect("initiating the Encrypted Link Handshake should succeed");
    let responder_handshake = responder
        .session
        .accept_encrypted_link(
            responder.noise_secret_hex.clone(),
            initiator.session.pubky(),
            initiator.noise_public_key.clone(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
        )
        .expect("accepting the Encrypted Link Handshake should succeed");

    let (initiator_link, responder_link) = tokio::join!(
        drive_handshake(initiator_handshake),
        drive_handshake(responder_handshake),
    );
    (initiator, responder, initiator_link, responder_link)
}

#[test]
fn test_generate_receiver_noise_secret_key_hex_is_32_random_bytes() {
    let first = generate_receiver_noise_secret_key_hex();
    let second = generate_receiver_noise_secret_key_hex();

    assert_eq!(hex::decode(&first).unwrap().len(), 32);
    assert_eq!(hex::decode(&second).unwrap().len(), 32);
    assert_ne!(first, second, "generated secrets should be random");
}

#[test]
fn test_receiver_noise_public_key_matches_keypair_derivation() {
    let secret = [7u8; 32];

    let derived = receiver_noise_public_key_from_secret_hex(hex::encode(secret)).unwrap();

    assert_eq!(
        derived,
        pubky::Keypair::from_secret(&secret).public_key().z32()
    );
}

#[test]
fn test_receiver_noise_public_key_rejects_invalid_secrets() {
    let invalid_hex = receiver_noise_public_key_from_secret_hex("not-hex".into()).unwrap_err();
    assert!(
        invalid_hex.to_string().contains("hex is invalid"),
        "expected hex validation error, got: {invalid_hex}"
    );

    let wrong_length =
        receiver_noise_public_key_from_secret_hex(hex::encode([7u8; 16])).unwrap_err();
    assert!(
        wrong_length.to_string().contains("must be 32 bytes"),
        "expected length validation error, got: {wrong_length}"
    );
}

#[tokio::test]
async fn test_chat_link_two_peers_exchange_custom_kind_messages() {
    let testnet = build_testnet().await;
    let (initiator, responder, initiator_link, responder_link) = linked_peers(&testnet).await;

    // Link metadata mirrors the wasm handle surface.
    assert_eq!(initiator_link.recipient(), responder.session.pubky());
    assert_eq!(
        initiator_link.remote_noise_public_key(),
        responder.noise_public_key
    );
    assert_eq!(initiator_link.local_receiver_path(), RECEIVER_PATH);
    assert_eq!(initiator_link.remote_receiver_path(), RECEIVER_PATH);
    assert_eq!(responder_link.recipient(), initiator.session.pubky());

    // Retry/recovery knobs apply to live handles.
    initiator_link.set_max_send_retries(5).await.unwrap();
    responder_link.set_max_send_retries(5).await.unwrap();

    // Custom-kind chat messages flow in both directions.
    let hello = chat_message_json("hello from initiator");
    initiator_link
        .send_private_application_message_json(hello.clone())
        .await
        .unwrap();

    let received = responder_link
        .receive_private_application_messages()
        .await
        .unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].version, Some(1));
    assert_eq!(received[0].kind.as_deref(), Some(CHAT_KIND));
    assert_eq!(received[0].raw_json, hello);

    let reply = chat_message_json("hello back");
    responder_link
        .send_private_application_message_json(reply.clone())
        .await
        .unwrap();

    let received_back = initiator_link
        .receive_private_application_messages()
        .await
        .unwrap();
    assert_eq!(received_back.len(), 1);
    assert_eq!(received_back[0].kind.as_deref(), Some(CHAT_KIND));
    assert_eq!(received_back[0].raw_json, reply);

    // The stream is drained after intake.
    assert!(responder_link
        .receive_private_application_messages()
        .await
        .unwrap()
        .is_empty());

    // Messages without the version/kind envelope are rejected before sending.
    let invalid = initiator_link
        .send_private_application_message_json(format!(r#"{{"kind":"{CHAT_KIND}"}}"#))
        .await
        .unwrap_err();
    assert!(
        invalid.to_string().contains("version"),
        "expected envelope validation error, got: {invalid}"
    );

    // Marker removal makes the receiver undiscoverable again.
    responder
        .session
        .remove_receiver_marker(RECEIVER_PATH.into())
        .await
        .unwrap();
    assert!(initiator
        .client
        .get_receiver_marker(responder.session.pubky(), RECEIVER_PATH.into())
        .await
        .unwrap()
        .is_none());

    // Closed links reject further use.
    initiator_link.close().await.unwrap();
    responder_link.close().await.unwrap();
    let closed = initiator_link
        .send_private_application_message_json(chat_message_json("too late"))
        .await
        .unwrap_err();
    assert!(
        closed.to_string().contains("link is closed"),
        "expected closed-link error, got: {closed}"
    );
    let already_closed = initiator_link.close().await.unwrap_err();
    assert!(
        already_closed.to_string().contains("link already closed"),
        "expected already-closed error, got: {already_closed}"
    );

    // Outbox recovery removes the initiator's written stream slots.
    let deleted = initiator
        .session
        .clear_encrypted_link_outbox(
            initiator.noise_secret_hex.clone(),
            responder.session.pubky(),
            responder.noise_public_key.clone(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
        )
        .await
        .unwrap();
    assert!(
        deleted >= 1,
        "handshake plus one send should leave at least one outbox slot, got {deleted}"
    );
}

#[tokio::test]
async fn test_chat_handshake_snapshot_restore_completes_and_exchanges() {
    let testnet = build_testnet().await;
    let initiator = ChatPeer::sign_up(&testnet).await;
    let responder = ChatPeer::sign_up(&testnet).await;

    let initiator_handshake = initiator
        .session
        .initiate_encrypted_link(
            initiator.noise_secret_hex.clone(),
            responder.session.pubky(),
            responder.noise_public_key.clone(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
        )
        .unwrap();
    let responder_handshake = responder
        .session
        .accept_encrypted_link(
            responder.noise_secret_hex.clone(),
            initiator.session.pubky(),
            initiator.noise_public_key.clone(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
        )
        .unwrap();

    // Tuning the recovery knob works on live handshakes.
    initiator_handshake
        .set_max_recovery_attempts(5)
        .await
        .unwrap();

    // Advance both sides once so snapshots capture an in-flight handshake.
    let step = initiator_handshake.advance().await.unwrap();
    assert!(!step.complete, "one step should not complete the handshake");
    let step = responder_handshake.advance().await.unwrap();
    assert!(!step.complete, "one step should not complete the handshake");

    let initiator_snapshot = initiator_handshake.snapshot().await.unwrap();
    let responder_snapshot = responder_handshake.snapshot().await.unwrap();
    let wire: serde_json::Value = serde_json::from_str(&initiator_snapshot)
        .expect("handshake snapshot should be opaque JSON");
    assert!(wire.get("version").is_some());

    // Drop the live handles and restore from the persisted snapshots, as an
    // app would after a restart.
    drop(initiator_handshake);
    drop(responder_handshake);
    let restored_initiator = initiator
        .session
        .restore_encrypted_link_handshake(
            initiator.noise_secret_hex.clone(),
            responder.session.pubky(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
            initiator_snapshot,
        )
        .await
        .unwrap();
    let restored_responder = responder
        .session
        .restore_encrypted_link_handshake(
            responder.noise_secret_hex.clone(),
            initiator.session.pubky(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
            responder_snapshot,
        )
        .await
        .unwrap();

    let (initiator_link, responder_link) = tokio::join!(
        drive_handshake(restored_initiator),
        drive_handshake(restored_responder),
    );

    let message = chat_message_json("restored handshake still works");
    initiator_link
        .send_private_application_message_json(message.clone())
        .await
        .unwrap();
    let received = responder_link
        .receive_private_application_messages()
        .await
        .unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].kind.as_deref(), Some(CHAT_KIND));
    assert_eq!(received[0].raw_json, message);

    initiator_link.close().await.unwrap();
    responder_link.close().await.unwrap();
}

#[tokio::test]
async fn test_chat_link_snapshot_restore_established_and_continue() {
    let testnet = build_testnet().await;
    let (initiator, responder, initiator_link, responder_link) = linked_peers(&testnet).await;

    // Exchange one message so snapshots capture advanced counters.
    let first = chat_message_json("before snapshot");
    initiator_link
        .send_private_application_message_json(first.clone())
        .await
        .unwrap();
    let received = responder_link
        .receive_private_application_messages()
        .await
        .unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].raw_json, first);

    let initiator_snapshot = initiator_link.snapshot().await.unwrap();
    let responder_snapshot = responder_link.snapshot().await.unwrap();

    // Simulate an app restart: close the live links, then restore.
    initiator_link.close().await.unwrap();
    responder_link.close().await.unwrap();
    let snapshot_after_close = initiator_link.snapshot().await.unwrap_err();
    assert!(
        snapshot_after_close.to_string().contains("link is closed"),
        "expected closed-link error, got: {snapshot_after_close}"
    );

    let restored_initiator = initiator
        .session
        .restore_encrypted_link(
            initiator.noise_secret_hex.clone(),
            responder.session.pubky(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
            initiator_snapshot,
        )
        .await
        .unwrap();
    let restored_responder = responder
        .session
        .restore_encrypted_link(
            responder.noise_secret_hex.clone(),
            initiator.session.pubky(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
            responder_snapshot,
        )
        .await
        .unwrap();
    assert_eq!(
        restored_initiator.recipient(),
        responder.session.pubky(),
        "restored link should keep the counterparty identity"
    );

    let second = chat_message_json("after restore");
    restored_initiator
        .send_private_application_message_json(second.clone())
        .await
        .unwrap();
    let received = restored_responder
        .receive_private_application_messages()
        .await
        .unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].kind.as_deref(), Some(CHAT_KIND));
    assert_eq!(received[0].raw_json, second);

    restored_initiator.close().await.unwrap();
    restored_responder.close().await.unwrap();
}

#[tokio::test]
async fn test_chat_session_export_restore_and_signin_roundtrip() {
    let testnet = build_testnet().await;
    let peer = ChatPeer::sign_up(&testnet).await;

    // Restore from the exported bearer token on a fresh handle.
    let exported = peer.session.export_session();
    let restored = peer.client.restore_session(exported).await.unwrap();
    assert_eq!(restored.pubky(), peer.session.pubky());

    // The restored session is live: it can publish and remove a marker.
    restored
        .publish_receiver_marker(
            "chat/server".into(),
            peer.noise_public_key.clone(),
            messaging_capabilities(),
        )
        .await
        .unwrap();
    restored
        .remove_receiver_marker("chat/server".into())
        .await
        .unwrap();

    // Signing in again with the raw identity secret yields the same identity.
    let signed_in = peer
        .client
        .signin_with_secret(peer.identity_secret_hex.clone())
        .await
        .unwrap();
    assert_eq!(signed_in.pubky(), peer.session.pubky());

    // Garbage tokens are rejected.
    let invalid = peer
        .client
        .restore_session("not-a-session-token".into())
        .await
        .unwrap_err();
    assert!(
        invalid.to_string().contains("session restore failed"),
        "expected restore failure, got: {invalid}"
    );
}

#[tokio::test]
async fn test_chat_auth_flow_signin_via_local_relay() {
    let testnet = build_testnet_with(true).await;
    // The signer identity must already own an account on the homeserver.
    let peer = ChatPeer::sign_up(&testnet).await;

    let relay_inbox = testnet
        .http_relay()
        .local_url()
        .join("inbox")
        .expect("relay inbox URL should be valid")
        .to_string();
    let flow = peer
        .client
        .start_auth_flow("/pub/paykit/:rw".into(), Some(relay_inbox))
        .await
        .unwrap();
    let auth_url = flow.authorization_url();
    assert!(
        auth_url.starts_with("pubkyauth:"),
        "expected a pubkyauth deep link, got: {auth_url}"
    );

    // Approve from the signer side (the Pubky Ring role) with the raw pubky
    // API while the flow awaits approval.
    let signer_identity = {
        let mut secret = [0u8; 32];
        hex::decode_to_slice(&peer.identity_secret_hex, &mut secret)
            .expect("stored identity secret should be valid hex");
        pubky::Keypair::from_secret(&secret)
    };
    let signer = testnet
        .sdk()
        .expect("testnet Pubky client")
        .signer(signer_identity);
    let (approval, session) = tokio::join!(signer.approve_auth(&auth_url), flow.await_approval());
    approval.expect("signer approval should succeed");
    let session = session.expect("auth flow should resolve to a session");
    assert_eq!(session.pubky(), peer.session.pubky());

    // The flow is consumed after approval.
    let consumed = flow.await_approval().await.unwrap_err();
    assert!(
        consumed.to_string().contains("auth flow already consumed"),
        "expected consumed-flow error, got: {consumed}"
    );
}
