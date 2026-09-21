use super::*;

#[tokio::test]
async fn test_initiate_link_with_peer_requires_pubky_session() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    let sdk = PaykitSdk::with_clock(
        storage,
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );

    let result = sdk
        .initiate_link_with_peer(counterparty, receiver_path())
        .await;

    assert!(matches!(result, Err(PaykitSdkError::Identity { .. })));
}

#[tokio::test]
async fn test_initiate_link_with_peer_requires_session_before_using_stored_link() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    seed_initialized_identity_and_link(&storage, counterparty.clone()).await;
    let sdk = PaykitSdk::with_clock(
        storage.clone(),
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );

    let result = sdk
        .initiate_link_with_peer(counterparty, receiver_path())
        .await;

    assert!(matches!(result, Err(PaykitSdkError::Identity { .. })));
    let snapshot = storage.snapshot().unwrap();
    assert_eq!(snapshot.encrypted_link_states.len(), 1);
}

#[tokio::test]
async fn test_initiate_link_with_peer_preserves_untrusted_linking_state_without_session() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    crate::domain::linked_peers::save_link_handshake_state(
        &storage,
        counterparty.clone(),
        receiver_path(),
        EncryptedLinkHandshakeRole::Initiator,
        vec![1, 2, 3],
        FixedClock.now(),
    )
    .await
    .unwrap();
    let sdk = PaykitSdk::with_clock(
        storage.clone(),
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );

    let result = sdk
        .initiate_link_with_peer(counterparty.clone(), receiver_path())
        .await;

    assert!(matches!(result, Err(PaykitSdkError::Identity { .. })));
    assert!(
        crate::load_encrypted_link_state(&storage, &counterparty, &receiver_path())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn test_private_queue_readiness_allows_linking_peer_with_handshake() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    seed_initialized_identity_and_handshake(&storage, counterparty.clone()).await;
    let sdk = PaykitSdk::with_clock(
        storage,
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );

    let readiness = sdk
        .private_queue_readiness(&counterparty, &receiver_path())
        .await
        .unwrap();

    assert_eq!(readiness, PrivateQueueReadiness::PendingHandshake);
}

#[tokio::test]
async fn test_private_queue_readiness_rejects_linking_peer_without_handshake_role() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    storage
        .transaction({
            let counterparty = counterparty.clone();
            move |tx| {
                tx.save_linked_peer(LinkedPeerRecord {
                    counterparty: counterparty.clone(),
                    counterparty_receiver_path: receiver_path(),
                    state: LinkedPeerState::Linking,
                    last_sync_at: Some(FixedClock.now()),
                    last_private_receive_at: None,
                    failure_count: 0,
                    local_recovery_attempt_id: None,
                    local_recovery_marker_created_at: None,
                    local_recovery_marker_last_error: None,
                    remote_recovery_attempt_id: None,
                    remote_recovery_marker_observed_at: None,
                });
                tx.save_encrypted_link_state(EncryptedLinkStateRecord {
                    counterparty,
                    counterparty_receiver_path: receiver_path(),
                    link_snapshot: None,
                    handshake_snapshot: Some(vec![1, 2, 3]),
                    handshake_role: None,
                    generation: 0,
                    checkpointed_at: FixedClock.now(),
                    peer_receiver_noise_public_key: None,
                    replacement: Default::default(),
                });
                Ok(())
            }
        })
        .await
        .unwrap();
    let sdk = PaykitSdk::with_clock(
        storage,
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );

    let result = sdk
        .private_queue_readiness(&counterparty, &receiver_path())
        .await;

    assert!(matches!(
        result,
        Err(PaykitSdkError::RecoveryRequired { .. })
    ));
}

#[tokio::test]
async fn test_recovery_required_peer_allows_relink_attempt() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    crate::domain::linked_peers::save_linked_peer_state(
        &storage,
        counterparty.clone(),
        receiver_path(),
        LinkedPeerState::RecoveryRequired,
        FixedClock.now(),
    )
    .await
    .unwrap();
    let lease = storage
        .transaction({
            let counterparty = counterparty.clone();
            move |tx| {
                Ok(tx
                    .claim_peer_link_operation(
                        &counterparty,
                        &receiver_path(),
                        FixedClock.now(),
                        FixedClock.now() + chrono::Duration::seconds(60),
                    )
                    .unwrap())
            }
        })
        .await
        .unwrap();
    let sdk = PaykitSdk::with_clock(
        storage,
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );

    let result = sdk
        .start_link_handshake_with_claim(counterparty, EncryptedLinkHandshakeRole::Initiator, lease)
        .await;

    assert!(matches!(result, Err(PaykitSdkError::Identity { .. })));
}

#[tokio::test]
async fn test_ensure_link_recovery_required_ignores_stale_link_snapshot() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    storage
        .transaction({
            let counterparty = counterparty.clone();
            move |tx| {
                tx.save_linked_peer(LinkedPeerRecord {
                    counterparty: counterparty.clone(),
                    counterparty_receiver_path: receiver_path(),
                    state: LinkedPeerState::RecoveryRequired,
                    last_sync_at: Some(FixedClock.now()),
                    last_private_receive_at: None,
                    failure_count: 1,
                    local_recovery_attempt_id: None,
                    local_recovery_marker_created_at: None,
                    local_recovery_marker_last_error: None,
                    remote_recovery_attempt_id: None,
                    remote_recovery_marker_observed_at: None,
                });
                tx.save_encrypted_link_state(EncryptedLinkStateRecord {
                    counterparty,
                    counterparty_receiver_path: receiver_path(),
                    link_snapshot: Some(vec![1, 2, 3]),
                    handshake_snapshot: None,
                    handshake_role: None,
                    generation: 4,
                    checkpointed_at: FixedClock.now(),
                    peer_receiver_noise_public_key: None,
                    replacement: Default::default(),
                });
                Ok(())
            }
        })
        .await
        .unwrap();
    let lease = storage
        .transaction({
            let counterparty = counterparty.clone();
            move |tx| {
                Ok(tx
                    .claim_peer_link_operation(
                        &counterparty,
                        &receiver_path(),
                        FixedClock.now(),
                        FixedClock.now() + chrono::Duration::seconds(60),
                    )
                    .unwrap())
            }
        })
        .await
        .unwrap();
    let sdk = PaykitSdk::with_clock(
        storage.clone(),
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );

    let result = sdk
        .ensure_link_with_peer_with_claim(
            counterparty.clone(),
            EncryptedLinkHandshakeRole::Initiator,
            0,
            lease,
        )
        .await;

    assert!(matches!(result, Err(PaykitSdkError::Identity { .. })));
    let snapshot = storage.snapshot().unwrap();
    assert_eq!(
        snapshot.linked_peers[&(counterparty.clone(), receiver_path())].state,
        LinkedPeerState::RecoveryRequired
    );
    assert_eq!(
        snapshot.encrypted_link_states[&(counterparty.clone(), receiver_path())].link_snapshot,
        Some(vec![1, 2, 3])
    );
}

#[tokio::test]
async fn test_ensure_link_recovery_required_ignores_stale_handshake_snapshot() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    storage
        .transaction({
            let counterparty = counterparty.clone();
            move |tx| {
                tx.save_linked_peer(LinkedPeerRecord {
                    counterparty: counterparty.clone(),
                    counterparty_receiver_path: receiver_path(),
                    state: LinkedPeerState::RecoveryRequired,
                    last_sync_at: Some(FixedClock.now()),
                    last_private_receive_at: None,
                    failure_count: 1,
                    local_recovery_attempt_id: None,
                    local_recovery_marker_created_at: None,
                    local_recovery_marker_last_error: None,
                    remote_recovery_attempt_id: None,
                    remote_recovery_marker_observed_at: None,
                });
                tx.save_encrypted_link_state(EncryptedLinkStateRecord {
                    counterparty,
                    counterparty_receiver_path: receiver_path(),
                    link_snapshot: None,
                    handshake_snapshot: Some(vec![1, 2, 3]),
                    handshake_role: Some(EncryptedLinkHandshakeRole::Responder),
                    generation: 4,
                    checkpointed_at: FixedClock.now(),
                    peer_receiver_noise_public_key: None,
                    replacement: Default::default(),
                });
                Ok(())
            }
        })
        .await
        .unwrap();
    let lease = storage
        .transaction({
            let counterparty = counterparty.clone();
            move |tx| {
                Ok(tx
                    .claim_peer_link_operation(
                        &counterparty,
                        &receiver_path(),
                        FixedClock.now(),
                        FixedClock.now() + chrono::Duration::seconds(60),
                    )
                    .unwrap())
            }
        })
        .await
        .unwrap();
    let sdk = PaykitSdk::with_clock(
        storage.clone(),
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );

    let result = sdk
        .ensure_link_with_peer_with_claim(
            counterparty.clone(),
            EncryptedLinkHandshakeRole::Responder,
            0,
            lease,
        )
        .await;

    assert!(matches!(result, Err(PaykitSdkError::Identity { .. })));
    let snapshot = storage.snapshot().unwrap();
    assert_eq!(
        snapshot.linked_peers[&(counterparty.clone(), receiver_path())].state,
        LinkedPeerState::RecoveryRequired
    );
    assert_eq!(
        snapshot.encrypted_link_states[&(counterparty.clone(), receiver_path())].handshake_snapshot,
        Some(vec![1, 2, 3])
    );
}

#[tokio::test]
async fn test_advance_link_handshake_rejects_recovery_required_peer() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    storage
        .transaction({
            let counterparty = counterparty.clone();
            move |tx| {
                tx.save_linked_peer(LinkedPeerRecord {
                    counterparty: counterparty.clone(),
                    counterparty_receiver_path: receiver_path(),
                    state: LinkedPeerState::RecoveryRequired,
                    last_sync_at: Some(FixedClock.now()),
                    last_private_receive_at: None,
                    failure_count: 1,
                    local_recovery_attempt_id: None,
                    local_recovery_marker_created_at: None,
                    local_recovery_marker_last_error: None,
                    remote_recovery_attempt_id: None,
                    remote_recovery_marker_observed_at: None,
                });
                tx.save_encrypted_link_state(EncryptedLinkStateRecord {
                    counterparty,
                    counterparty_receiver_path: receiver_path(),
                    link_snapshot: Some(vec![1, 2, 3]),
                    handshake_snapshot: None,
                    handshake_role: None,
                    generation: 4,
                    checkpointed_at: FixedClock.now(),
                    peer_receiver_noise_public_key: None,
                    replacement: Default::default(),
                });
                Ok(())
            }
        })
        .await
        .unwrap();
    let sdk = PaykitSdk::with_clock(
        storage.clone(),
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );

    let result = sdk
        .advance_link_handshake(counterparty.clone(), receiver_path())
        .await;

    assert!(matches!(
        result,
        Err(PaykitSdkError::RecoveryRequired { .. })
    ));
    assert_eq!(
        crate::load_encrypted_link_state(&storage, &counterparty, &receiver_path())
            .await
            .unwrap()
            .unwrap()
            .generation,
        4
    );
}

#[tokio::test]
async fn test_advance_link_handshake_preserves_unusable_link_state_without_session() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    storage
        .transaction({
            let counterparty = counterparty.clone();
            move |tx| {
                tx.save_encrypted_link_state(EncryptedLinkStateRecord {
                    counterparty,
                    counterparty_receiver_path: receiver_path(),
                    link_snapshot: None,
                    handshake_snapshot: None,
                    handshake_role: None,
                    generation: 0,
                    checkpointed_at: FixedClock.now(),
                    peer_receiver_noise_public_key: None,
                    replacement: Default::default(),
                });
                Ok(())
            }
        })
        .await
        .unwrap();
    let sdk = PaykitSdk::with_clock(
        storage.clone(),
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );

    let result = sdk
        .advance_link_handshake(counterparty.clone(), receiver_path())
        .await;

    assert!(matches!(result, Err(PaykitSdkError::Identity { .. })));
    assert!(
        crate::load_encrypted_link_state(&storage, &counterparty, &receiver_path())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn test_advance_link_handshake_preserves_unusable_handshake_snapshot_without_session() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    storage
        .transaction({
            let counterparty = counterparty.clone();
            move |tx| {
                tx.save_encrypted_link_state(EncryptedLinkStateRecord {
                    counterparty,
                    counterparty_receiver_path: receiver_path(),
                    link_snapshot: None,
                    handshake_snapshot: Some(vec![1, 2, 3]),
                    handshake_role: Some(EncryptedLinkHandshakeRole::Initiator),
                    generation: 0,
                    checkpointed_at: FixedClock.now(),
                    peer_receiver_noise_public_key: None,
                    replacement: Default::default(),
                });
                Ok(())
            }
        })
        .await
        .unwrap();
    let sdk = PaykitSdk::with_clock(
        storage.clone(),
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );

    let result = sdk
        .advance_link_handshake(counterparty.clone(), receiver_path())
        .await;

    assert!(matches!(result, Err(PaykitSdkError::Identity { .. })));
    assert!(
        crate::load_encrypted_link_state(&storage, &counterparty, &receiver_path())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn test_advance_link_handshake_preserves_unusable_handshake_metadata_without_session() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    storage
        .transaction({
            let counterparty = counterparty.clone();
            move |tx| {
                tx.save_encrypted_link_state(EncryptedLinkStateRecord {
                    counterparty,
                    counterparty_receiver_path: receiver_path(),
                    link_snapshot: None,
                    handshake_snapshot: Some(vec![1, 2, 3]),
                    handshake_role: None,
                    generation: 0,
                    checkpointed_at: FixedClock.now(),
                    peer_receiver_noise_public_key: None,
                    replacement: Default::default(),
                });
                Ok(())
            }
        })
        .await
        .unwrap();
    let sdk = PaykitSdk::with_clock(
        storage.clone(),
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );

    let result = sdk
        .advance_link_handshake(counterparty.clone(), receiver_path())
        .await;

    assert!(matches!(result, Err(PaykitSdkError::Identity { .. })));
    assert!(
        crate::load_encrypted_link_state(&storage, &counterparty, &receiver_path())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn test_ensure_confirms_peer_capability_from_stored_marker_without_clearing() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    seed_recovery_required_snapshot(&storage, counterparty.clone(), Some("attempt-1")).await;
    let sdk = PaykitSdk::with_clock(
        storage.clone(),
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );
    let lease = sdk
        .claim_peer_link_operation(&counterparty, &receiver_path())
        .await
        .unwrap();
    let report = sdk
        .ensure_link_with_peer_with_claim(
            counterparty.clone(),
            EncryptedLinkHandshakeRole::Initiator,
            2,
            lease.clone(),
        )
        .await
        .unwrap();
    sdk.release_peer_link_operation(&lease).await.unwrap();

    assert_eq!(report.state, LinkedPeerState::RecoveryRequired);
    let link_state = crate::load_encrypted_link_state(&storage, &counterparty, &receiver_path())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(link_state.link_snapshot, Some(vec![1, 2, 3]));
    assert!(link_state.replacement.peer_capability_confirmed);
    assert!(!link_state.replacement.drain_acknowledged);
    assert!(!link_state.replacement.write_path_cleared);

    let lease = sdk
        .claim_peer_link_operation(&counterparty, &receiver_path())
        .await
        .unwrap();
    let drain = sdk
        .ensure_link_with_peer_with_claim(
            counterparty.clone(),
            EncryptedLinkHandshakeRole::Initiator,
            2,
            lease.clone(),
        )
        .await;
    let _ = sdk.release_peer_link_operation(&lease).await;
    assert!(matches!(drain, Err(PaykitSdkError::Identity { .. })));
    let after_drain =
        crate::load_encrypted_link_state(&storage, &counterparty, &receiver_path())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(after_drain.link_snapshot, Some(vec![1, 2, 3]));
    assert!(after_drain.replacement.peer_capability_confirmed);
    assert!(!after_drain.replacement.drain_acknowledged);
    assert!(!after_drain.replacement.write_path_cleared);
}

#[tokio::test]
async fn test_ensure_fail_closed_without_capability_does_not_delete_snapshot() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    seed_recovery_required_snapshot(&storage, counterparty.clone(), None).await;
    let sdk = PaykitSdk::with_clock(
        storage.clone(),
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );
    let lease = sdk
        .claim_peer_link_operation(&counterparty, &receiver_path())
        .await
        .unwrap();
    let result = sdk
        .ensure_link_with_peer_with_claim(
            counterparty.clone(),
            EncryptedLinkHandshakeRole::Initiator,
            2,
            lease.clone(),
        )
        .await;
    let _ = sdk.release_peer_link_operation(&lease).await;

    assert!(matches!(result, Err(PaykitSdkError::Identity { .. })));
    let link_state = crate::load_encrypted_link_state(&storage, &counterparty, &receiver_path())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(link_state.link_snapshot, Some(vec![1, 2, 3]));
    assert!(!link_state.replacement.peer_capability_confirmed);
    assert!(!link_state.replacement.write_path_cleared);
}

#[tokio::test]
async fn test_ensure_crash_after_save_before_clear_does_not_clear_without_session() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    storage
        .save_identity_state(IdentityState {
            local_pubky_public_key: Some(PubkyPublicKey::from_public_key(
                &pubky::Keypair::random().public_key(),
            )),
            local_receiver_noise_public_key: Some(receiver_noise_public_key()),
            initialized_at: FixedClock.now(),
            sign_out_generation: 0,
        })
        .await
        .unwrap();
    storage
        .transaction({
            let counterparty = counterparty.clone();
            move |tx| {
                tx.save_linked_peer(LinkedPeerRecord {
                    counterparty: counterparty.clone(),
                    counterparty_receiver_path: receiver_path(),
                    state: LinkedPeerState::Linking,
                    last_sync_at: Some(FixedClock.now()),
                    last_private_receive_at: None,
                    failure_count: 1,
                    local_recovery_attempt_id: None,
                    local_recovery_marker_created_at: None,
                    local_recovery_marker_last_error: None,
                    remote_recovery_attempt_id: Some("attempt-1".into()),
                    remote_recovery_marker_observed_at: Some(FixedClock.now()),
                });
                tx.save_encrypted_link_state(EncryptedLinkStateRecord {
                    counterparty,
                    counterparty_receiver_path: receiver_path(),
                    link_snapshot: Some(vec![9, 9, 9]),
                    handshake_snapshot: Some(vec![1, 2, 3]),
                    handshake_role: Some(EncryptedLinkHandshakeRole::Responder),
                    generation: 4,
                    checkpointed_at: FixedClock.now(),
                    peer_receiver_noise_public_key: None,
                    replacement: crate::storage::ReplacementHandshakeProgress {
                        drain_acknowledged: true,
                        write_path_cleared: false,
                        peer_capability_confirmed: true,
                    },
                });
                Ok(())
            }
        })
        .await
        .unwrap();
    let sdk = PaykitSdk::with_clock(
        storage.clone(),
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );
    let lease = sdk
        .claim_peer_link_operation(&counterparty, &receiver_path())
        .await
        .unwrap();
    let result = sdk
        .ensure_link_with_peer_with_claim(
            counterparty.clone(),
            EncryptedLinkHandshakeRole::Responder,
            2,
            lease.clone(),
        )
        .await;
    let _ = sdk.release_peer_link_operation(&lease).await;

    assert!(matches!(result, Err(PaykitSdkError::Identity { .. })));
    let link_state = crate::load_encrypted_link_state(&storage, &counterparty, &receiver_path())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(link_state.link_snapshot, Some(vec![9, 9, 9]));
    assert_eq!(link_state.handshake_snapshot, Some(vec![1, 2, 3]));
    assert_eq!(
        link_state.handshake_role,
        Some(EncryptedLinkHandshakeRole::Responder)
    );
    assert!(!link_state.replacement.write_path_cleared);
}

async fn seed_recovery_required_snapshot(
    storage: &InMemoryStorage,
    counterparty: PubkyPublicKey,
    remote_attempt: Option<&str>,
) {
    storage
        .save_identity_state(IdentityState {
            local_pubky_public_key: Some(PubkyPublicKey::from_public_key(
                &pubky::Keypair::random().public_key(),
            )),
            local_receiver_noise_public_key: Some(receiver_noise_public_key()),
            initialized_at: FixedClock.now(),
            sign_out_generation: 0,
        })
        .await
        .unwrap();
    let remote_attempt = remote_attempt.map(str::to_owned);
    storage
        .transaction(move |tx| {
            tx.save_linked_peer(LinkedPeerRecord {
                counterparty: counterparty.clone(),
                counterparty_receiver_path: receiver_path(),
                state: LinkedPeerState::RecoveryRequired,
                last_sync_at: Some(FixedClock.now()),
                last_private_receive_at: None,
                failure_count: 1,
                local_recovery_attempt_id: None,
                local_recovery_marker_created_at: None,
                local_recovery_marker_last_error: None,
                remote_recovery_attempt_id: remote_attempt,
                remote_recovery_marker_observed_at: None,
            });
            tx.save_encrypted_link_state(EncryptedLinkStateRecord {
                counterparty,
                counterparty_receiver_path: receiver_path(),
                link_snapshot: Some(vec![1, 2, 3]),
                handshake_snapshot: None,
                handshake_role: None,
                generation: 3,
                checkpointed_at: FixedClock.now(),
                peer_receiver_noise_public_key: None,
                replacement: Default::default(),
            });
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_ensure_linked_snapshot_does_not_short_circuit_without_receiver_lookup() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    seed_initialized_identity_and_link(&storage, counterparty.clone()).await;
    let sdk = PaykitSdk::with_clock(
        storage.clone(),
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );

    let result = sdk
        .ensure_link_with_peer(counterparty.clone(), receiver_path(), 0)
        .await;

    assert!(matches!(result, Err(PaykitSdkError::Identity { .. })));
    let link_state = crate::load_encrypted_link_state(&storage, &counterparty, &receiver_path())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(link_state.link_snapshot, Some(vec![1, 2, 3]));
    assert_eq!(link_state.peer_receiver_noise_public_key, None);
}

#[tokio::test]
async fn test_ensure_recovery_required_fingerprint_does_not_short_circuit_to_linked() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    seed_recovery_required_snapshot(&storage, counterparty.clone(), None).await;
    storage
        .transaction({
            let counterparty = counterparty.clone();
            move |tx| {
                let mut state = tx
                    .encrypted_link_state(&counterparty, &receiver_path())
                    .expect("seeded link state");
                state.peer_receiver_noise_public_key = Some(receiver_noise_public_key());
                tx.save_encrypted_link_state(state);
                Ok(())
            }
        })
        .await
        .unwrap();
    let sdk = PaykitSdk::with_clock(
        storage.clone(),
        TestPubkySessionProvider { session: None },
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );

    let result = sdk
        .ensure_link_with_peer(counterparty.clone(), receiver_path(), 2)
        .await;

    assert!(matches!(result, Err(PaykitSdkError::Identity { .. })));
    let snapshot = storage.snapshot().unwrap();
    let peer = &snapshot.linked_peers[&(counterparty.clone(), receiver_path())];
    assert_eq!(peer.state, LinkedPeerState::RecoveryRequired);
    let link_state = &snapshot.encrypted_link_states[&(counterparty.clone(), receiver_path())];
    assert_eq!(link_state.link_snapshot, Some(vec![1, 2, 3]));
    assert_eq!(
        link_state.peer_receiver_noise_public_key,
        Some(receiver_noise_public_key())
    );
}
