use super::*;

#[test]
fn test_paykit_not_found_maps_to_sdk_not_found() {
    let err = PaykitSdkError::from(paykit_lib::PaykitError::NotFound("missing receipt".into()));

    assert!(
        matches!(err, PaykitSdkError::NotFound { context, .. } if context == "missing receipt")
    );
}

#[test]
fn test_invalid_data_source_is_not_folded_into_protocol_string() {
    // Regression guard: `Protocol.context` crosses the FFI boundary verbatim
    // (generated Kotlin/Swift exception messages), while lib-level
    // `InvalidData` sources carry raw parse/decode causes that can embed
    // network data or decrypted plaintext. The conversion must keep only the
    // curated static context label and drop the cause entirely:
    // `PaykitSdkError` derives field-wise `Debug`, so a retained `source`
    // would surface in `format!("{err:?}")` and structured Rust logs even
    // though the FFI conversion never forwards it.
    let sentinel = "SENTINEL_RAW_PARSE_CAUSE";
    let err = PaykitSdkError::from(paykit_lib::PaykitError::InvalidData {
        context: "failed to parse receipt plaintext JSON".into(),
        source: Some(anyhow::anyhow!(
            "invalid type: string \"{sentinel}\", expected u8"
        )),
    });

    let (message, source) = match &err {
        PaykitSdkError::Protocol { context, source } => (context.clone(), source.as_ref()),
        other => panic!("expected Protocol error, got {other:?}"),
    };
    assert_eq!(message, "failed to parse receipt plaintext JSON");
    assert!(
        !message.contains(sentinel),
        "InvalidData source leaked into Protocol string: {message}"
    );
    assert!(
        source.is_none(),
        "InvalidData source must be dropped; derived Debug would render it"
    );
    let rendered = format!("{err} / {err:?}");
    assert!(
        !rendered.contains(sentinel),
        "InvalidData source leaked into Display/Debug: {rendered}"
    );
}

#[test]
fn transport_and_not_found_never_require_link_recovery() {
    assert!(!paykit_lib_error_requires_link_recovery(
        &paykit_lib::PaykitError::Transport {
            context: "homeserver timeout".into(),
            source: anyhow::anyhow!("dial"),
        }
    ));
    assert!(!paykit_lib_error_requires_link_recovery(
        &paykit_lib::PaykitError::NotFound("missing slot".into())
    ));
    assert!(paykit_lib_error_requires_link_recovery(
        &paykit_lib::PaykitError::InvalidData {
            context: "aead".into(),
            source: None,
        }
    ));
    assert!(paykit_lib_error_requires_link_recovery(
        &paykit_lib::PaykitError::Validation("bad snapshot".into())
    ));
    assert!(PaykitSdkError::Transport {
        context: "retry".into(),
        source: None,
    }
    .is_retryable_homeserver_failure());
    assert!(PaykitSdkError::NotFound {
        context: "gone".into(),
        source: None,
    }
    .is_retryable_homeserver_failure());
}

#[test]
fn restore_replay_transport_requires_link_recovery() {
    let restore_replay = paykit_lib::PaykitError::Transport {
        context: "failed to restore Encrypted Link: RestoreReplayError".into(),
        source: anyhow::anyhow!("pubky-noise restore failed: RestoreReplayError"),
    };
    assert!(paykit_lib_error_requires_link_recovery(&restore_replay));
    assert!(!PaykitSdkError::from(restore_replay).is_retryable_homeserver_failure());

    let source_only = paykit_lib::PaykitError::Transport {
        context: "failed to restore Encrypted Link".into(),
        source: anyhow::anyhow!("RestoreReplayError"),
    };
    assert!(paykit_lib_error_requires_link_recovery(&source_only));

    let timeout = paykit_lib::PaykitError::Transport {
        context: "failed to restore Encrypted Link: timeout".into(),
        source: anyhow::anyhow!("dial timed out"),
    };
    assert!(!paykit_lib_error_requires_link_recovery(&timeout));
    assert!(PaykitSdkError::from(timeout).is_retryable_homeserver_failure());
}
