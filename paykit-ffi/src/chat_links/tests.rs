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
    initiator_link.close_link().await.unwrap();
    responder_link.close_link().await.unwrap();
    let closed = initiator_link
        .send_private_application_message_json(chat_message_json("too late"))
        .await
        .unwrap_err();
    assert!(
        closed.to_string().contains("link is closed"),
        "expected closed-link error, got: {closed}"
    );
    let already_closed = initiator_link.close_link().await.unwrap_err();
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

    initiator_link.close_link().await.unwrap();
    responder_link.close_link().await.unwrap();
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
    initiator_link.close_link().await.unwrap();
    responder_link.close_link().await.unwrap();
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

    restored_initiator.close_link().await.unwrap();
    restored_responder.close_link().await.unwrap();
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

    // The approved session can exercise its /pub/paykit/:rw capability.
    session
        .publish_receiver_marker(
            "chat/server".into(),
            peer.noise_public_key.clone(),
            messaging_capabilities(),
        )
        .await
        .expect("approved session should be able to publish a Paykit marker");
    session
        .remove_receiver_marker("chat/server".into())
        .await
        .expect("approved session should be able to remove a Paykit marker");

    // The flow is consumed after approval.
    let consumed = flow.await_approval().await.unwrap_err();
    assert!(
        matches!(
            &consumed,
            PaykitFfiError::Protocol { code, context }
                if code == "consumed" && context.contains("auth flow already consumed")
        ),
        "expected consumed-flow error, got: {consumed}"
    );
}

fn error_parts(err: &PaykitFfiError) -> (&str, &str, String) {
    match err {
        PaykitFfiError::Storage { code, context } => ("storage", code.as_str(), context.clone()),
        PaykitFfiError::Identity { code, context } => ("identity", code.as_str(), context.clone()),
        PaykitFfiError::Transport { code, context } => {
            ("transport", code.as_str(), context.clone())
        }
        PaykitFfiError::NotFound { code, context } => ("not_found", code.as_str(), context.clone()),
        PaykitFfiError::Protocol { code, context } => ("protocol", code.as_str(), context.clone()),
        PaykitFfiError::Policy { code, context } => ("policy", code.as_str(), context.clone()),
        PaykitFfiError::PaymentAdapter { code, context } => {
            ("payment_adapter", code.as_str(), context.clone())
        }
        PaykitFfiError::RecoveryRequired { code, context } => {
            ("recovery_required", code.as_str(), context.clone())
        }
    }
}

fn assert_safe_chat_error(err: &PaykitFfiError) {
    let rendered = err.to_string();
    assert!(
        !rendered.contains("://"),
        "URL leaked into chat error: {rendered}"
    );
    assert!(
        !rendered.contains('{') && !rendered.contains('}'),
        "raw payload leaked into chat error: {rendered}"
    );
    assert!(
        !rendered.contains('\n'),
        "multiline payload leaked into chat error: {rendered}"
    );
    let (_, _, context) = error_parts(err);
    assert!(
        !context.contains('/'),
        "storage path leaked into chat error context: {context}"
    );
}

fn decode_secret_hex(hex_secret: &str) -> [u8; 32] {
    let mut secret = [0u8; 32];
    hex::decode_to_slice(hex_secret, &mut secret).expect("stored secret should be valid hex");
    secret
}

async fn raw_session(testnet: &EphemeralTestnet, identity_secret_hex: &str) -> pubky::PubkySession {
    let signer = testnet
        .sdk()
        .expect("testnet Pubky client")
        .signer(pubky::Keypair::from_secret(&decode_secret_hex(
            identity_secret_hex,
        )));
    signer.signin().await.expect("raw signin should succeed")
}

#[tokio::test]
async fn test_start_auth_flow_requires_paykit_rw() {
    let client = FfiChatClient::new().expect("default client should construct");

    let missing = client
        .start_auth_flow("/pub/pubky.app/:rw".into(), None)
        .await
        .unwrap_err();
    let (variant, code, context) = error_parts(&missing);
    assert_eq!(variant, "identity");
    assert_eq!(code, "capabilities_missing");
    assert!(
        context.contains("/pub/paykit/"),
        "expected paykit scope in validation error, got: {context}"
    );

    let ok = client.start_auth_flow("/pub/paykit/:rw".into(), None).await;
    assert!(ok.is_ok(), "exact paykit rw grant should be accepted");
}

#[test]
fn chat_auth_flow_uses_shared_pubky_http_client_without_insecure_tls() {
    let src = include_str!("../chat_links.rs");
    assert!(
        src.contains("self.inner.start_auth_flow(&caps, AuthFlowKind::signin())"),
        "default relay path must use the shared Pubky client"
    );
    assert!(
        src.contains(".client(self.inner.client().clone())"),
        "override relay path must reuse the shared PubkyHttpClient"
    );

    pubky::PubkyHttpClient::new().expect("shared PubkyHttpClient (icann + pkarr) must construct");
    pubky::pkarr::Client::builder()
        .build()
        .expect("pkarr RelaysClient path used by start_auth_flow must construct");
}

#[tokio::test]
async fn test_chat_message_and_auth_flow_debug_never_emit_secrets() {
    let message = FfiChatMessage {
        version: Some(1),
        kind: Some(CHAT_KIND.into()),
        raw_json: r#"{"version":1,"kind":"chat.message.v0","payload":{"text":"secret"}}"#.into(),
    };
    let message_debug = format!("{message:?}");
    assert!(
        message_debug.contains("redacted"),
        "Debug should mark raw_json as redacted: {message_debug}"
    );
    assert!(
        !message_debug.contains("payload") && !message_debug.contains("secret"),
        "raw JSON payload leaked into Debug: {message_debug}"
    );

    let client = FfiChatClient::new().expect("default client should construct");
    let flow = client
        .start_auth_flow("/pub/paykit/:rw".into(), None)
        .await
        .expect("valid capabilities should start a flow");
    let url = flow.authorization_url();
    let flow_debug = format!("{flow:?}");
    assert!(
        url.starts_with("pubkyauth:"),
        "authorization URL should be a pubkyauth deep link"
    );
    assert!(
        !flow_debug.contains("pubkyauth:"),
        "Debug must not emit the auth URL: {flow_debug}"
    );
    assert!(
        !flow_debug.contains(&url),
        "Debug must not emit the auth URL: {flow_debug}"
    );
}

#[test]
fn test_map_chat_lib_error_redacts_handshake_send_receive_payloads() {
    let handshake = map_chat_lib_error(paykit_lib::PaykitError::Transport {
        context: "handshake step failed: https://homeserver.example/pub/paykit/v0/private/SECRET {payload: leak}".into(),
        source: anyhow::anyhow!("GET https://homeserver.example/x failed: body"),
    });
    let send = map_chat_lib_error(paykit_lib::PaykitError::Transport {
        context: "failed to send Private Application Message: {err: Some(\"https://evil\") }"
            .into(),
        source: anyhow::anyhow!("raw send payload"),
    });
    let receive = map_chat_lib_error(paykit_lib::PaykitError::Transport {
        context:
            "failed to receive Private Application Messages: DecryptionError { inner: \"leak\" }"
                .into(),
        source: anyhow::anyhow!("raw receive payload"),
    });

    for err in [&handshake, &send, &receive] {
        assert_safe_chat_error(err);
    }

    let (_, handshake_code, handshake_ctx) = error_parts(&handshake);
    assert_eq!(handshake_code, "handshake_failed");
    assert_eq!(handshake_ctx, "handshake step failed");

    let (_, send_code, send_ctx) = error_parts(&send);
    assert_eq!(send_code, "send_failed");
    assert_eq!(send_ctx, "failed to send Private Application Message");

    let (_, receive_code, receive_ctx) = error_parts(&receive);
    assert_eq!(receive_code, "receive_failed");
    assert_eq!(
        receive_ctx,
        "failed to receive Private Application Messages"
    );

    let not_found = map_chat_lib_error(paykit_lib::PaykitError::NotFound(
        "/pub/paykit/v0/private/SECRET/inbox".into(),
    ));
    let invalid = map_chat_lib_error(paykit_lib::PaykitError::InvalidData {
        context: "/pub/paykit/v0/private/SECRET {payload}".into(),
        source: None,
    });
    let validation_path = map_chat_lib_error(paykit_lib::PaykitError::Validation(
        "/pub/paykit/v0/private/SECRET is not a valid receiver".into(),
    ));
    let validation_long = map_chat_lib_error(paykit_lib::PaykitError::Validation("x".repeat(200)));

    for err in [&not_found, &invalid, &validation_path, &validation_long] {
        assert_safe_chat_error(err);
    }

    let (not_found_variant, not_found_code, not_found_ctx) = error_parts(&not_found);
    assert_eq!(not_found_variant, "not_found");
    assert_eq!(not_found_code, "not_found");
    assert_eq!(not_found_ctx, "resource not found");

    let (_, invalid_code, invalid_ctx) = error_parts(&invalid);
    assert_eq!(invalid_code, "protocol_error");
    assert_eq!(invalid_ctx, "invalid encrypted link data");

    let (_, path_code, path_ctx) = error_parts(&validation_path);
    assert_eq!(path_code, "validation");
    assert_eq!(path_ctx, "encrypted link validation failed");

    let (_, long_code, long_ctx) = error_parts(&validation_long);
    assert_eq!(long_code, "validation");
    assert_eq!(long_ctx, "encrypted link validation failed");
}

#[tokio::test]
async fn test_advance_survives_ffi_future_cancellation() {
    let testnet = build_testnet().await;
    let initiator = ChatPeer::sign_up(&testnet).await;
    let responder = ChatPeer::sign_up(&testnet).await;

    let handshake = initiator
        .session
        .initiate_encrypted_link(
            initiator.noise_secret_hex.clone(),
            responder.session.pubky(),
            responder.noise_public_key.clone(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
        )
        .unwrap();

    tokio::select! {
        _ = handshake.advance() => {}
        _ = tokio::time::sleep(Duration::from_millis(1)) => {}
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let step = handshake
        .advance()
        .await
        .expect("cancelled advance must leave the handle usable");
    assert!(
        !step.complete,
        "a single initiator step should still be pending"
    );
    handshake
        .snapshot()
        .await
        .expect("handle must remain snapshot-able after a cancelled advance");
}

#[tokio::test]
async fn test_failing_advance_consumes_handle_and_snapshot_restore_recovers() {
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

    let step = initiator_handshake.advance().await.unwrap();
    assert!(!step.complete);

    let snapshot = responder_handshake
        .snapshot()
        .await
        .expect("fresh responder should snapshot");

    let slot = first_local_handshake_slot(
        &decode_secret_hex(&initiator.noise_secret_hex),
        &pubky::PublicKey::try_from(initiator.session.pubky().as_str()).unwrap(),
        &pubky::PublicKey::try_from(responder.session.pubky().as_str()).unwrap(),
        &pubky::PublicKey::try_from(responder.noise_public_key.as_str()).unwrap(),
        &paykit_lib::PaykitReceiverPath::new(RECEIVER_PATH).unwrap(),
        &paykit_lib::PaykitReceiverPath::new(RECEIVER_PATH).unwrap(),
    );
    let raw_session = raw_session(&testnet, &initiator.identity_secret_hex).await;
    let original = raw_session
        .storage()
        .get(&slot)
        .await
        .expect("initiator handshake slot should exist")
        .bytes()
        .await
        .expect("handshake slot bytes")
        .to_vec();
    raw_session
        .storage()
        .put(&slot, vec![0u8; 1020])
        .await
        .expect("overwriting the handshake slot should succeed");

    let failed = responder_handshake.advance().await.unwrap_err();
    let (variant, code, _) = error_parts(&failed);
    assert_eq!(variant, "protocol");
    assert_eq!(code, "handshake_failed");
    assert_safe_chat_error(&failed);

    let consumed = responder_handshake.advance().await.unwrap_err();
    let (variant, code, _) = error_parts(&consumed);
    assert_eq!(variant, "protocol");
    assert_eq!(code, "consumed");

    raw_session
        .storage()
        .put(&slot, original)
        .await
        .expect("restoring the original handshake slot should succeed");

    let restored = responder
        .session
        .restore_encrypted_link_handshake(
            responder.noise_secret_hex.clone(),
            initiator.session.pubky(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
            snapshot,
        )
        .await
        .expect("restore from the last persisted snapshot should succeed");

    let (initiator_link, responder_link) = tokio::join!(
        drive_handshake(initiator_handshake),
        drive_handshake(restored),
    );
    let message = chat_message_json("recovered after failed advance");
    initiator_link
        .send_private_application_message_json(message.clone())
        .await
        .unwrap();
    let received = responder_link
        .receive_private_application_messages()
        .await
        .unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].raw_json, message);
}

#[tokio::test]
async fn test_restore_handshake_rejects_wrong_noise_key_and_recipient() {
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
    assert!(!initiator_handshake.advance().await.unwrap().complete);
    assert!(!responder_handshake.advance().await.unwrap().complete);
    let snapshot = responder_handshake.snapshot().await.unwrap();

    let wrong_key = responder
        .session
        .restore_encrypted_link_handshake(
            generate_receiver_noise_secret_key_hex(),
            initiator.session.pubky(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
            snapshot.clone(),
        )
        .await
        .unwrap_err();
    let (variant, code, _) = error_parts(&wrong_key);
    assert!(
        matches!(
            (variant, code),
            ("transport", "transport_error")
                | ("protocol", "validation")
                | ("protocol", "protocol_error")
        ),
        "wrong noise key should be a typed restore error, got {variant}/{code}: {wrong_key}"
    );
    assert_safe_chat_error(&wrong_key);

    let wrong_recipient = responder
        .session
        .restore_encrypted_link_handshake(
            responder.noise_secret_hex.clone(),
            responder.session.pubky(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
            snapshot,
        )
        .await
        .unwrap_err();
    let (variant, code, context) = error_parts(&wrong_recipient);
    assert_eq!(variant, "protocol");
    assert_eq!(code, "validation");
    assert!(
        context.contains("recipient") || context.contains("remote"),
        "wrong recipient should mention the mismatch, got: {context}"
    );
    assert_safe_chat_error(&wrong_recipient);
}

#[tokio::test]
async fn test_send_rejects_missing_kind_and_oversize_payload() {
    let testnet = build_testnet().await;
    let (_initiator, _responder, initiator_link, responder_link) = linked_peers(&testnet).await;

    let missing_kind = initiator_link
        .send_private_application_message_json(r#"{"version":1,"payload":{"text":"x"}}"#.into())
        .await
        .unwrap_err();
    let (variant, code, context) = error_parts(&missing_kind);
    assert_eq!(variant, "protocol");
    assert_eq!(code, "validation");
    assert!(
        context.contains("kind"),
        "missing kind must be surfaced, got: {context}"
    );
    assert_safe_chat_error(&missing_kind);

    let oversized = format!(
        r#"{{"version":1,"kind":"{CHAT_KIND}","payload":"{}"}}"#,
        "x".repeat(1000)
    );
    assert!(oversized.len() > 1000);
    let oversize_err = initiator_link
        .send_private_application_message_json(oversized)
        .await
        .unwrap_err();
    let (variant, code, context) = error_parts(&oversize_err);
    assert_eq!(variant, "protocol");
    assert_eq!(code, "validation");
    assert!(
        context.contains("exceeds") || context.contains("1000"),
        "oversize payload must fail with a typed size error, got: {context}"
    );
    assert_safe_chat_error(&oversize_err);

    initiator_link.close_link().await.unwrap();
    responder_link.close_link().await.unwrap();
}

#[tokio::test]
async fn test_probe_none_crossed_and_established() {
    let testnet = build_testnet().await;
    let initiator = ChatPeer::sign_up(&testnet).await;
    let responder = ChatPeer::sign_up(&testnet).await;

    let none = responder
        .session
        .probe_inbound_encrypted_link(
            responder.noise_secret_hex.clone(),
            initiator.session.pubky(),
            initiator.noise_public_key.clone(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
        )
        .await
        .expect("probe with no inbound must succeed");
    assert!(
        matches!(none, FfiChatProbeResult::NoInbound),
        "expected NoInbound before anyone initiates"
    );

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
        .initiate_encrypted_link(
            responder.noise_secret_hex.clone(),
            initiator.session.pubky(),
            initiator.noise_public_key.clone(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
        )
        .unwrap();
    let (left, right) = tokio::join!(initiator_handshake.advance(), responder_handshake.advance());
    assert!(!left.unwrap().complete);
    assert!(!right.unwrap().complete);

    let initiator_probe = initiator
        .session
        .probe_inbound_encrypted_link(
            initiator.noise_secret_hex.clone(),
            responder.session.pubky(),
            responder.noise_public_key.clone(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
        )
        .await
        .expect("crossed probe must observe inbound");
    let responder_probe = responder
        .session
        .probe_inbound_encrypted_link(
            responder.noise_secret_hex.clone(),
            initiator.session.pubky(),
            initiator.noise_public_key.clone(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
        )
        .await
        .expect("crossed probe must observe inbound");
    assert!(
        !matches!(initiator_probe, FfiChatProbeResult::NoInbound),
        "simultaneous initiate must not look like no inbound"
    );
    assert!(
        !matches!(responder_probe, FfiChatProbeResult::NoInbound),
        "simultaneous initiate must not look like no inbound"
    );

    let keep_initiator = initiator.session.pubky() < responder.session.pubky();
    let (drive_left, drive_right) = if keep_initiator {
        match responder_probe {
            FfiChatProbeResult::Pending { handshake } => (initiator_handshake, handshake),
            FfiChatProbeResult::Established { link } => {
                let message = chat_message_json("probe established immediately");
                initiator_handshake.advance().await.ok();
                let _ = link;
                drop(message);
                panic!("XX handshake should not complete in one responder probe after one write");
            }
            FfiChatProbeResult::NoInbound => unreachable!("checked above"),
        }
    } else {
        match initiator_probe {
            FfiChatProbeResult::Pending { handshake } => (responder_handshake, handshake),
            FfiChatProbeResult::Established { link } => {
                let _ = link;
                panic!("XX handshake should not complete in one responder probe after one write");
            }
            FfiChatProbeResult::NoInbound => unreachable!("checked above"),
        }
    };

    let (left_link, right_link) =
        tokio::join!(drive_handshake(drive_left), drive_handshake(drive_right));
    let message = chat_message_json("crossed probe resolved");
    left_link
        .send_private_application_message_json(message.clone())
        .await
        .unwrap();
    let received = right_link
        .receive_private_application_messages()
        .await
        .unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].raw_json, message);

    let solo_initiator = ChatPeer::sign_up(&testnet).await;
    let solo_responder = ChatPeer::sign_up(&testnet).await;
    let solo_handshake = solo_initiator
        .session
        .initiate_encrypted_link(
            solo_initiator.noise_secret_hex.clone(),
            solo_responder.session.pubky(),
            solo_responder.noise_public_key.clone(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
        )
        .unwrap();
    assert!(!solo_handshake.advance().await.unwrap().complete);

    let probed = solo_responder
        .session
        .probe_inbound_encrypted_link(
            solo_responder.noise_secret_hex.clone(),
            solo_initiator.session.pubky(),
            solo_initiator.noise_public_key.clone(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
        )
        .await
        .expect("probe after a real initiate should find inbound");
    let responder_handle = match probed {
        FfiChatProbeResult::Pending { handshake } => handshake,
        FfiChatProbeResult::Established { link } => {
            let initiator_link = drive_handshake(solo_handshake).await;
            let message = chat_message_json("probe established");
            initiator_link
                .send_private_application_message_json(message.clone())
                .await
                .unwrap();
            let received = link.receive_private_application_messages().await.unwrap();
            assert_eq!(received[0].raw_json, message);
            return;
        }
        FfiChatProbeResult::NoInbound => panic!("inbound from initiate must be visible to probe"),
    };

    let (initiator_link, responder_link) = tokio::join!(
        drive_handshake(solo_handshake),
        drive_handshake(responder_handle),
    );
    let message = chat_message_json("probe established via drive");
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
}

#[tokio::test]
async fn test_advance_retry_while_in_flight_returns_settled_result() {
    let testnet = build_testnet().await;
    let initiator = ChatPeer::sign_up(&testnet).await;
    let responder = ChatPeer::sign_up(&testnet).await;

    let handshake = initiator
        .session
        .initiate_encrypted_link(
            initiator.noise_secret_hex.clone(),
            responder.session.pubky(),
            responder.noise_public_key.clone(),
            RECEIVER_PATH.into(),
            RECEIVER_PATH.into(),
        )
        .unwrap();

    handshake.arm_test_hold();
    tokio::select! {
        _ = handshake.advance() => panic!("advance completed before the spawned step entered the hold"),
        _ = handshake.wait_until_test_hold_entered() => {}
    }

    let in_flight = handshake.snapshot().await.unwrap_err();
    let (variant, code, _) = error_parts(&in_flight);
    assert_eq!(
        (variant, code),
        ("protocol", "in_flight"),
        "retry window must still be InFlight, not consumed: {in_flight}"
    );

    let mut retry = {
        let handshake = Arc::clone(&handshake);
        tokio::spawn(async move { handshake.advance().await })
    };
    tokio::select! {
        r = &mut retry => panic!("retry completed while the spawned step was still held: {r:?}"),
        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
    }
    let still_in_flight = handshake.snapshot().await.unwrap_err();
    let (variant, code, _) = error_parts(&still_in_flight);
    assert_eq!(
        (variant, code),
        ("protocol", "in_flight"),
        "retry-while-held must keep InFlight: {still_in_flight}"
    );

    handshake.release_test_hold();
    let step = retry
        .await
        .expect("retry task should join")
        .expect("retry while in-flight must return the settled result, not consumed");
    assert!(
        !step.complete,
        "a single initiator step should still be pending"
    );
    handshake
        .snapshot()
        .await
        .expect("handle must remain snapshot-able after an in-flight retry");
}

#[tokio::test]
async fn test_await_approval_second_call_while_pending_returns_settled_result() {
    let testnet = build_testnet_with(true).await;
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

    flow.arm_test_hold();
    tokio::select! {
        _ = flow.await_approval() => panic!("await_approval completed before the spawned wait entered the hold"),
        _ = flow.wait_until_test_hold_entered() => {}
    }

    let mut retry = {
        let flow = Arc::clone(&flow);
        tokio::spawn(async move { flow.await_approval().await })
    };
    tokio::select! {
        r = &mut retry => panic!("second await_approval completed while still held: {r:?}"),
        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
    }

    flow.release_test_hold();

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
    let (approval, session) = tokio::join!(signer.approve_auth(&auth_url), async {
        retry.await.expect("retry task should join")
    });
    approval.expect("signer approval should succeed");
    let session = session.expect(
        "second await_approval while pending must return the settled session, not consumed",
    );
    assert_eq!(session.pubky(), peer.session.pubky());
}

#[tokio::test]
async fn test_send_different_payload_after_parked_send_is_not_silently_dropped() {
    let testnet = build_testnet().await;
    let (_initiator, _responder, initiator_link, responder_link) = linked_peers(&testnet).await;

    let first = chat_message_json("parked-m1");
    let second = chat_message_json("follow-up-m2");

    initiator_link.arm_test_hold();
    tokio::select! {
        _ = initiator_link.send_private_application_message_json(first.clone()) => {
            panic!("send completed before the spawned step entered the hold");
        }
        _ = initiator_link.wait_until_test_hold_entered() => {}
    }

    let conflict = initiator_link
        .send_private_application_message_json(second.clone())
        .await
        .expect_err("a different payload must not wait on or inherit the in-flight send");
    let (variant, code, context) = error_parts(&conflict);
    assert_eq!(variant, "protocol");
    assert_eq!(code, "parked_result_conflict");
    assert!(
        context.contains("different payload"),
        "conflict context should distinguish payload mismatch, got: {context}"
    );
    assert_safe_chat_error(&conflict);

    initiator_link.release_test_hold();
    loop {
        match initiator_link.snapshot().await {
            Ok(_) => break,
            Err(err) => {
                let (variant, code, _) = error_parts(&err);
                assert_eq!(
                    (variant, code),
                    ("protocol", "in_flight"),
                    "waiting for parked send to settle, got: {err}"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    initiator_link
        .send_private_application_message_json(second.clone())
        .await
        .expect("settled parked send of a different payload must start a fresh send");

    let mut received = Vec::new();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        received.extend(
            responder_link
                .receive_private_application_messages()
                .await
                .unwrap(),
        );
        if received.iter().any(|message| message.raw_json == second) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        received.iter().any(|message| message.raw_json == second),
        "M2 must be sent after a parked M1; got: {received:?}"
    );

    initiator_link.close_link().await.unwrap();
    responder_link.close_link().await.unwrap();
}
