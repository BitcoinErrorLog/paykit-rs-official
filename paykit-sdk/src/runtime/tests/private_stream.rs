use super::*;

#[tokio::test]
async fn test_receive_private_messages_requires_pubky_session() {
    let storage = InMemoryStorage::new();
    let pubky = TestPubkySessionProvider { session: None };
    let sdk = PaykitSdk::with_clock(
        storage.clone(),
        pubky,
        TestPaymentAdapter,
        PaykitSdkConfig::default(),
        FixedClock,
    );
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    storage
        .transaction({
            let counterparty = counterparty.clone();
            move |tx| {
                tx.save_encrypted_link_state(EncryptedLinkStateRecord {
                    counterparty,
                    counterparty_receiver_path: receiver_path(),
                    link_snapshot: Some(vec![1, 2, 3]),
                    handshake_snapshot: None,
                    handshake_role: None,
                    generation: 1,
                    checkpointed_at: FixedClock.now(),
                    peer_receiver_noise_public_key: None,
                    replacement: Default::default(),
                });
                Ok(())
            }
        })
        .await
        .unwrap();

    let result = sdk
        .receive_private_messages(counterparty.clone(), receiver_path())
        .await;

    assert!(matches!(result, Err(PaykitSdkError::Identity { .. })));
    assert!(storage
        .transaction({
            let counterparty = counterparty.clone();
            move |tx| Ok(tx.peer_link_operation_lease(&counterparty, &receiver_path()))
        })
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_private_stream_items_fetches_by_id_and_omits_missing() {
    let storage = InMemoryStorage::new();
    let counterparty = PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key());
    let event_id = "650e8400-e29b-41d4-a716-446655440000";
    let raw_json = format!(
        r#"{{"version":1,"kind":"chat.message.v0","event_id":"{event_id}","body":"hi"}}"#
    );
    let first_id = storage
        .transaction({
            let counterparty = counterparty.clone();
            let raw_json = raw_json.clone();
            move |tx| {
                Ok(tx.insert_private_stream_item(NewPrivateStreamItem::new(
                    NewPrivateStreamItemDetails {
                        counterparty: counterparty.clone(),
                        counterparty_receiver_path: receiver_path(),
                        receive_batch_id: 0,
                        raw_json,
                        parsed_version: Some(1),
                        parsed_kind: Some("chat.message.v0".into()),
                        known_paykit_kind: None,
                        parse_status: PrivateStreamParseStatus::UnknownKind,
                        parse_error: None,
                        received_at: FixedClock.now(),
                    },
                )))
            }
        })
        .await
        .unwrap();
    let second_id = storage
        .transaction({
            let counterparty = counterparty.clone();
            move |tx| {
                Ok(tx.insert_private_stream_item(NewPrivateStreamItem::new(
                    NewPrivateStreamItemDetails {
                        counterparty,
                        counterparty_receiver_path: receiver_path(),
                        receive_batch_id: 0,
                        raw_json: r#"{"version":1,"kind":"chat.message.v0","event_id":"750e8400-e29b-41d4-a716-446655440001","body":"later"}"#.into(),
                        parsed_version: Some(1),
                        parsed_kind: Some("chat.message.v0".into()),
                        known_paykit_kind: None,
                        parse_status: PrivateStreamParseStatus::UnknownKind,
                        parse_error: None,
                        received_at: FixedClock.now(),
                    },
                )))
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

    let items = sdk
        .private_stream_items(vec![second_id, 99, first_id])
        .await
        .unwrap();

    assert_eq!(items.len(), 2);
    assert_eq!(items[0].stream_item_id, second_id);
    assert_eq!(items[1].stream_item_id, first_id);
    assert_eq!(items[1].event_id.as_deref(), Some(event_id));
    assert_eq!(items[1].kind.as_deref(), Some("chat.message.v0"));
    assert_eq!(items[1].parse_status, PrivateStreamParseStatus::UnknownKind);
}
