use super::*;

impl<S, K, P, C> PaykitSdk<S, K, P, C>
where
    S: StorageAdapter,
    K: PubkySessionProvider,
    P: PaymentAdapter,
    C: Clock,
{
    pub(super) async fn ensure_peer_allows_private_automation(
        &self,
        counterparty: &PubkyPublicKey,
        counterparty_receiver_path: &PaykitReceiverPath,
    ) -> Result<()> {
        let (peer_state, has_active_link) = self
            .storage
            .transaction(|tx| {
                let peer_state = tx
                    .linked_peer(counterparty, counterparty_receiver_path)
                    .map(|peer| peer.state);
                let has_active_link = tx
                    .encrypted_link_state(counterparty, counterparty_receiver_path)
                    .and_then(|state| state.link_snapshot)
                    .is_some();
                Ok((peer_state, has_active_link))
            })
            .await?;
        match peer_state {
            Some(LinkedPeerState::Linked) if has_active_link => Ok(()),
            Some(LinkedPeerState::Linking) => Err(PaykitSdkError::RecoveryRequired {
                context: format!(
                    "Encrypted Link Handshake is still in progress for counterparty {counterparty}"
                ),
                source: None,
            }),
            Some(LinkedPeerState::RecoveryRequired) => Err(PaykitSdkError::RecoveryRequired {
                context: format!(
                    "Encrypted Link recovery is required for counterparty {counterparty}"
                ),
                source: None,
            }),
            Some(LinkedPeerState::Blocked) => Err(PaykitSdkError::Policy {
                context: format!("counterparty {counterparty} is blocked"),
                source: None,
            }),
            _ => Err(PaykitSdkError::RecoveryRequired {
                context: format!(
                    "no active Encrypted Link snapshot for counterparty {counterparty}"
                ),
                source: None,
            }),
        }
    }

    pub(super) async fn private_queue_readiness(
        &self,
        counterparty: &PubkyPublicKey,
        counterparty_receiver_path: &PaykitReceiverPath,
    ) -> Result<PrivateQueueReadiness> {
        let (peer_state, has_active_link, has_restorable_handshake) = self
            .storage
            .transaction(|tx| {
                let peer_state = tx
                    .linked_peer(counterparty, counterparty_receiver_path)
                    .map(|peer| peer.state);
                let state = tx.encrypted_link_state(counterparty, counterparty_receiver_path);
                let has_active_link = state
                    .as_ref()
                    .and_then(|state| state.link_snapshot.as_ref())
                    .is_some();
                let has_restorable_handshake = state.as_ref().is_some_and(|state| {
                    state.handshake_snapshot.is_some() && state.handshake_role.is_some()
                });
                Ok((peer_state, has_active_link, has_restorable_handshake))
            })
            .await?;
        let Some(peer_state) = peer_state else {
            return Err(PaykitSdkError::RecoveryRequired {
                context: format!(
                    "no active or in-progress Encrypted Link state for counterparty {counterparty}"
                ),
                source: None,
            });
        };
        match peer_state {
            LinkedPeerState::Linked if has_active_link => Ok(PrivateQueueReadiness::Ready),
            LinkedPeerState::Linking if has_restorable_handshake => {
                Ok(PrivateQueueReadiness::PendingHandshake)
            }
            LinkedPeerState::Linking => Err(PaykitSdkError::RecoveryRequired {
                context: format!(
                    "Encrypted Link Handshake state is incomplete for counterparty {counterparty}"
                ),
                source: None,
            }),
            LinkedPeerState::RecoveryRequired => Err(PaykitSdkError::RecoveryRequired {
                context: format!(
                    "Encrypted Link recovery is required for counterparty {counterparty}"
                ),
                source: None,
            }),
            LinkedPeerState::Blocked => Err(PaykitSdkError::Policy {
                context: format!("counterparty {counterparty} is blocked"),
                source: None,
            }),
            _ => Err(PaykitSdkError::RecoveryRequired {
                context: format!(
                    "no active or in-progress Encrypted Link state for counterparty {counterparty}"
                ),
                source: None,
            }),
        }
    }

    pub(super) async fn ensure_peer_not_blocked(
        &self,
        counterparty: &PubkyPublicKey,
        counterparty_receiver_path: &PaykitReceiverPath,
    ) -> Result<()> {
        let peer_state = self
            .storage
            .transaction(|tx| {
                Ok(tx
                    .linked_peer(counterparty, counterparty_receiver_path)
                    .map(|peer| peer.state))
            })
            .await?;
        if matches!(peer_state, Some(LinkedPeerState::Blocked)) {
            Err(PaykitSdkError::Policy {
                context: format!("counterparty {counterparty} is blocked"),
                source: None,
            })
        } else {
            Ok(())
        }
    }

    pub(super) async fn ensure_peer_not_recovery_required_or_blocked(
        &self,
        counterparty: &PubkyPublicKey,
        counterparty_receiver_path: &PaykitReceiverPath,
    ) -> Result<()> {
        let peer_state = self
            .storage
            .transaction(|tx| {
                Ok(tx
                    .linked_peer(counterparty, counterparty_receiver_path)
                    .map(|peer| peer.state))
            })
            .await?;
        match peer_state {
            Some(LinkedPeerState::RecoveryRequired) => Err(PaykitSdkError::RecoveryRequired {
                context: format!(
                    "Encrypted Link recovery is required for counterparty {counterparty}"
                ),
                source: None,
            }),
            Some(LinkedPeerState::Blocked) => Err(PaykitSdkError::Policy {
                context: format!("counterparty {counterparty} is blocked"),
                source: None,
            }),
            _ => Ok(()),
        }
    }

    /// Block a counterparty for local Paykit private workflows.
    ///
    /// Blocking is local policy. It clears stored Encrypted Link state so the
    /// peer cannot resume private workflows until explicitly unblocked and
    /// linked again.
    pub async fn block_peer(
        &self,
        counterparty: PubkyPublicKey,
        counterparty_receiver_path: PaykitReceiverPath,
    ) -> Result<LinkedPeerRecord> {
        let local_public_key = self.require_initialized_identity("block peer").await?;
        if counterparty == local_public_key {
            return Err(PaykitSdkError::Policy {
                context: "cannot block the local Paykit identity".into(),
                source: None,
            });
        }
        let lease = self
            .claim_peer_link_operation(&counterparty, &counterparty_receiver_path)
            .await?;
        let result = self
            .block_peer_with_claim(counterparty, lease.clone())
            .await;
        self.finish_peer_link_operation(lease, result).await
    }

    async fn block_peer_with_claim(
        &self,
        counterparty: PubkyPublicKey,
        lease: PeerLinkOperationLease,
    ) -> Result<LinkedPeerRecord> {
        let now = self.clock.now();
        self.storage
            .transaction(move |tx| {
                crate::storage::require_peer_link_operation_lease(tx, &lease)?;
                let mut record = tx
                    .linked_peer(&counterparty, &lease.counterparty_receiver_path)
                    .unwrap_or_else(|| {
                        default_linked_peer(
                            counterparty.clone(),
                            lease.counterparty_receiver_path.clone(),
                        )
                    });
                record.state = LinkedPeerState::Blocked;
                record.last_sync_at = Some(now);
                record.failure_count = 0;
                tx.save_linked_peer(record.clone());
                clear_encrypted_link_state(
                    tx,
                    &counterparty,
                    &lease.counterparty_receiver_path,
                    now,
                );
                Ok(record)
            })
            .await
    }

    /// Remove a local peer block and return the peer to `NotLinked`.
    ///
    /// Existing Encrypted Link snapshots are not restored. Callers should start
    /// a fresh Encrypted Link Handshake before private workflows resume.
    pub async fn unblock_peer(
        &self,
        counterparty: PubkyPublicKey,
        counterparty_receiver_path: PaykitReceiverPath,
    ) -> Result<LinkedPeerRecord> {
        let local_public_key = self.require_initialized_identity("unblock peer").await?;
        if counterparty == local_public_key {
            return Err(PaykitSdkError::Policy {
                context: "cannot unblock the local Paykit identity".into(),
                source: None,
            });
        }
        let lease = self
            .claim_peer_link_operation(&counterparty, &counterparty_receiver_path)
            .await?;
        let result = self
            .unblock_peer_with_claim(counterparty, lease.clone())
            .await;
        self.finish_peer_link_operation(lease, result).await
    }

    async fn unblock_peer_with_claim(
        &self,
        counterparty: PubkyPublicKey,
        lease: PeerLinkOperationLease,
    ) -> Result<LinkedPeerRecord> {
        let now = self.clock.now();
        self.storage
            .transaction(move |tx| {
                crate::storage::require_peer_link_operation_lease(tx, &lease)?;
                let mut record = tx
                    .linked_peer(&counterparty, &lease.counterparty_receiver_path)
                    .unwrap_or_else(|| {
                        default_linked_peer(
                            counterparty.clone(),
                            lease.counterparty_receiver_path.clone(),
                        )
                    });
                if record.state != LinkedPeerState::Blocked {
                    return Ok(record);
                }
                record.state = LinkedPeerState::NotLinked;
                record.last_sync_at = Some(now);
                record.failure_count = 0;
                tx.save_linked_peer(record.clone());
                clear_encrypted_link_state(
                    tx,
                    &counterparty,
                    &lease.counterparty_receiver_path,
                    now,
                );
                Ok(record)
            })
            .await
    }

    /// Start an Encrypted Link Handshake as the initiator.
    pub async fn initiate_link_with_peer(
        &self,
        counterparty: PubkyPublicKey,
        counterparty_receiver_path: PaykitReceiverPath,
    ) -> Result<LinkedPeerHandshakeReport> {
        self.start_link_handshake(
            counterparty,
            counterparty_receiver_path,
            EncryptedLinkHandshakeRole::Initiator,
        )
        .await
    }

    /// Start an Encrypted Link Handshake as the responder.
    pub async fn accept_link_with_peer(
        &self,
        counterparty: PubkyPublicKey,
        counterparty_receiver_path: PaykitReceiverPath,
    ) -> Result<LinkedPeerHandshakeReport> {
        self.start_link_handshake(
            counterparty,
            counterparty_receiver_path,
            EncryptedLinkHandshakeRole::Responder,
        )
        .await
    }

    /// Advance the stored Encrypted Link Handshake for one counterparty.
    pub async fn advance_link_handshake(
        &self,
        counterparty: PubkyPublicKey,
        counterparty_receiver_path: PaykitReceiverPath,
    ) -> Result<LinkedPeerHandshakeReport> {
        self.ensure_peer_not_recovery_required_or_blocked(
            &counterparty,
            &counterparty_receiver_path,
        )
        .await?;
        let _ = self.private_link_session_access().await?;
        let lease = self
            .claim_peer_link_operation(&counterparty, &counterparty_receiver_path)
            .await?;
        let result = self
            .advance_link_handshake_with_claim(counterparty, lease.clone())
            .await;
        self.finish_peer_link_operation(lease, result).await
    }

    /// Ensure an Encrypted Link is started or advanced for one counterparty.
    ///
    /// The SDK deterministically chooses the local handshake role from the two
    /// public keys. Existing active links are returned as linked. Existing
    /// pending handshakes are advanced. `max_advance_steps` bounds how many
    /// stored handshake advances this call attempts after starting or finding a
    /// pending handshake.
    pub async fn ensure_link_with_peer(
        &self,
        counterparty: PubkyPublicKey,
        counterparty_receiver_path: PaykitReceiverPath,
        max_advance_steps: u32,
    ) -> Result<LinkedPeerHandshakeReport> {
        let (session_access, _) = self.private_link_session_access().await?;
        let local_public_key = session_access.public_key()?;
        if local_public_key == counterparty {
            return Err(PaykitSdkError::Policy {
                context: "cannot establish an Encrypted Link with the local identity".into(),
                source: None,
            });
        }
        let role = deterministic_handshake_role(&local_public_key, &counterparty);
        let lease = self
            .claim_peer_link_operation(&counterparty, &counterparty_receiver_path)
            .await?;
        let result = self
            .ensure_link_with_peer_with_claim(counterparty, role, max_advance_steps, lease.clone())
            .await;
        self.finish_peer_link_operation(lease, result).await
    }

    /// Validate and seed an established Encrypted Link snapshot without any
    /// homeserver I/O. Hydration uses this after a non-mutating probe; it must
    /// never call `ensure_link_with_peer`, which treats stored bytes as live.
    pub async fn import_encrypted_link_snapshot(
        &self,
        counterparty: PubkyPublicKey,
        counterparty_receiver_path: PaykitReceiverPath,
        snapshot_bytes: Vec<u8>,
    ) -> Result<LinkedPeerHandshakeReport> {
        paykit_lib::EncryptedLinkSnapshot::deserialize(&snapshot_bytes)?;
        let now = self.clock.now();
        self.storage
            .transaction(move |tx| {
                let generation = tx
                    .encrypted_link_state(&counterparty, &counterparty_receiver_path)
                    .map(|state| state.generation.saturating_add(1))
                    .unwrap_or_default();
                let mut peer = tx
                    .linked_peer(&counterparty, &counterparty_receiver_path)
                    .unwrap_or_else(|| {
                        default_linked_peer(
                            counterparty.clone(),
                            counterparty_receiver_path.clone(),
                        )
                    });
                if peer.state == LinkedPeerState::Blocked {
                    return Err(PaykitSdkError::Policy {
                        context: format!("counterparty {counterparty} is blocked"),
                        source: None,
                    });
                }
                peer.state = LinkedPeerState::Linked;
                peer.last_sync_at = Some(now);
                peer.failure_count = 0;
                tx.save_linked_peer(peer);
                tx.save_encrypted_link_state(EncryptedLinkStateRecord {
                    counterparty: counterparty.clone(),
                    counterparty_receiver_path: counterparty_receiver_path.clone(),
                    link_snapshot: Some(snapshot_bytes),
                    handshake_snapshot: None,
                    handshake_role: None,
                    generation,
                    checkpointed_at: now,
                    peer_receiver_noise_public_key: None,
                    replacement: Default::default(),
                });
                Ok(LinkedPeerHandshakeReport {
                    counterparty,
                    counterparty_receiver_path,
                    state: LinkedPeerState::Linked,
                    generation,
                    handshake_role: None,
                })
            })
            .await
    }

    /// Export the durable snapshot used by a dual-read rollback release.
    ///
    /// Returns `None` when this peer does not currently have an established
    /// link. The bytes are opaque secret material; callers must not log them.
    pub async fn export_encrypted_link_snapshot(
        &self,
        counterparty: &PubkyPublicKey,
        counterparty_receiver_path: &PaykitReceiverPath,
    ) -> Result<Option<Vec<u8>>> {
        self.storage
            .transaction(|tx| {
                Ok(tx
                    .encrypted_link_state(counterparty, counterparty_receiver_path)
                    .and_then(|state| state.link_snapshot))
            })
            .await
    }

    /// Non-mutating hydration probe. This validates the snapshot envelope
    /// without reading or writing homeserver state and without persisting any
    /// SDK state.
    pub fn probe_encrypted_link_snapshot(snapshot_bytes: &[u8]) -> Result<()> {
        paykit_lib::EncryptedLinkSnapshot::deserialize(snapshot_bytes)?;
        Ok(())
    }

    pub(super) async fn ensure_link_with_peer_with_claim(
        &self,
        counterparty: PubkyPublicKey,
        role: EncryptedLinkHandshakeRole,
        max_advance_steps: u32,
        lease: PeerLinkOperationLease,
    ) -> Result<LinkedPeerHandshakeReport> {
        let (peer_state, link_state) = self
            .storage
            .transaction(|tx| {
                Ok((
                    tx.linked_peer(&counterparty, &lease.counterparty_receiver_path)
                        .map(|peer| peer.state),
                    tx.encrypted_link_state(&counterparty, &lease.counterparty_receiver_path),
                ))
            })
            .await?;

        if matches!(peer_state, Some(LinkedPeerState::Blocked)) {
            return Err(PaykitSdkError::Policy {
                context: format!("counterparty {counterparty} is blocked"),
                source: None,
            });
        }

        let mut report = if replacement_should_run(peer_state.as_ref(), link_state.as_ref()) {
            let report = self
                .advance_replacement_with_claim(counterparty.clone(), role, lease.clone())
                .await?;
            if report.state != LinkedPeerState::Linking {
                return Ok(report);
            }
            report
        } else {
            match (peer_state, link_state) {
                (_, Some(state))
                    if state.handshake_snapshot.is_some() && state.handshake_role.is_none() =>
                {
                    let mark = mark_recovery_required_with_lease(
                        &self.storage,
                        counterparty.clone(),
                        lease.clone(),
                        self.clock.now(),
                    )
                    .await?;
                    self.publish_local_recovery_marker_if_possible(
                        &counterparty,
                        &lease.counterparty_receiver_path,
                        mark.new_episode,
                    )
                    .await;
                    return Err(PaykitSdkError::RecoveryRequired {
                        context: format!(
                            "missing Encrypted Link Handshake role for counterparty {counterparty}"
                        ),
                        source: None,
                    });
                }
                (_, Some(state)) if state.handshake_snapshot.is_some() => {
                    save_linked_peer_state_with_lease(
                        &self.storage,
                        counterparty.clone(),
                        LinkedPeerState::Linking,
                        lease.clone(),
                        self.clock.now(),
                    )
                    .await?;
                    LinkedPeerHandshakeReport {
                        counterparty: counterparty.clone(),
                        counterparty_receiver_path: state.counterparty_receiver_path,
                        state: LinkedPeerState::Linking,
                        generation: state.generation,
                        handshake_role: state.handshake_role,
                    }
                }
                (_, Some(state)) if state.link_snapshot.is_some() => {
                    self.confirm_linked_peer_receiver_noise(
                        counterparty.clone(),
                        state,
                        lease.clone(),
                    )
                    .await?
                }
                _ => {
                    self.start_link_handshake_with_claim(counterparty.clone(), role, lease.clone())
                        .await?
                }
            }
        };

        for _ in 0..max_advance_steps {
            if report.state == LinkedPeerState::Linked {
                return Ok(report);
            }
            if report.state == LinkedPeerState::RecoveryRequired {
                return Ok(report);
            }
            report = match self
                .advance_link_handshake_with_claim(counterparty.clone(), lease.clone())
                .await
            {
                Ok(report) => report,
                Err(err) if link_handshake_error_requires_recovery(&err) => {
                    let recovery_required = self
                        .storage
                        .transaction(|tx| {
                            Ok(tx
                                .linked_peer(&counterparty, &lease.counterparty_receiver_path)
                                .is_some_and(|peer| {
                                    peer.state == LinkedPeerState::RecoveryRequired
                                }))
                        })
                        .await?;
                    if !recovery_required {
                        return Err(err);
                    }
                    let replacement = self
                        .advance_replacement_with_claim(
                            counterparty.clone(),
                            role,
                            lease.clone(),
                        )
                        .await?;
                    if replacement.state != LinkedPeerState::Linking {
                        return Ok(replacement);
                    }
                    replacement
                }
                Err(err) => return Err(err),
            };
        }

        Ok(report)
    }

    async fn advance_link_handshake_with_claim(
        &self,
        counterparty: PubkyPublicKey,
        lease: PeerLinkOperationLease,
    ) -> Result<LinkedPeerHandshakeReport> {
        self.advance_link_handshake_with_claim_inner(counterparty, lease, false)
            .await
    }

    async fn advance_link_handshake_with_claim_inner(
        &self,
        counterparty: PubkyPublicKey,
        lease: PeerLinkOperationLease,
        allow_recovery: bool,
    ) -> Result<LinkedPeerHandshakeReport> {
        if allow_recovery {
            self.ensure_peer_not_blocked(&counterparty, &lease.counterparty_receiver_path)
                .await?;
        } else {
            self.ensure_peer_not_recovery_required_or_blocked(
                &counterparty,
                &lease.counterparty_receiver_path,
            )
            .await?;
        }
        let Some(stored_link_state) = self
            .storage
            .transaction(|tx| {
                Ok(tx.encrypted_link_state(&counterparty, &lease.counterparty_receiver_path))
            })
            .await?
        else {
            return Err(PaykitSdkError::RecoveryRequired {
                context: format!("no Encrypted Link state for counterparty {counterparty}"),
                source: None,
            });
        };
        if stored_link_state.handshake_snapshot.is_none()
            && stored_link_state.link_snapshot.is_some()
        {
            if allow_recovery {
                return Ok(replacement_recovery_report(
                    counterparty,
                    stored_link_state.counterparty_receiver_path.clone(),
                    Some(&stored_link_state),
                ));
            }
            return self
                .confirm_linked_peer_receiver_noise(counterparty, stored_link_state, lease)
                .await;
        }

        let Some(handshake_role) = stored_link_state.handshake_role else {
            self.mark_link_recovery_required(&counterparty, lease)
                .await?;
            return Err(PaykitSdkError::RecoveryRequired {
                context: format!(
                    "missing Encrypted Link Handshake role for counterparty {counterparty}"
                ),
                source: None,
            });
        };
        let Some(snapshot_bytes) = stored_link_state.handshake_snapshot.as_ref() else {
            self.mark_link_recovery_required(&counterparty, lease)
                .await?;
            return Err(PaykitSdkError::RecoveryRequired {
                context: format!(
                    "no in-progress Encrypted Link Handshake snapshot for counterparty {counterparty}"
                ),
                source: None,
            });
        };

        let handshake = match self
            .restore_link_handshake_from_snapshot(
                counterparty.clone(),
                &stored_link_state.counterparty_receiver_path,
                snapshot_bytes,
            )
            .await
        {
            Ok(handshake) => handshake,
            Err(err) => {
                if link_handshake_error_requires_recovery(&err) {
                    self.mark_link_recovery_required(&counterparty, lease)
                        .await?;
                }
                return Err(err);
            }
        };

        self.advance_restored_link_handshake(
            counterparty,
            handshake,
            handshake_role,
            stored_link_state.generation,
            lease,
        )
        .await
    }

    async fn mark_link_recovery_required(
        &self,
        counterparty: &PubkyPublicKey,
        lease: PeerLinkOperationLease,
    ) -> Result<()> {
        let counterparty_receiver_path = lease.counterparty_receiver_path.clone();
        let mark = mark_recovery_required_with_lease(
            &self.storage,
            counterparty.clone(),
            lease,
            self.clock.now(),
        )
        .await?;
        self.publish_local_recovery_marker_if_possible(
            counterparty,
            &counterparty_receiver_path,
            mark.new_episode,
        )
        .await;
        Ok(())
    }

    async fn restore_link_handshake_from_snapshot(
        &self,
        counterparty: PubkyPublicKey,
        counterparty_receiver_path: &PaykitReceiverPath,
        snapshot_bytes: &[u8],
    ) -> Result<paykit_lib::EncryptedLinkHandshake> {
        let (session_access, secret_key) = self.private_link_session_access().await?;
        let remote_public_key = counterparty.to_public_key()?;
        let snapshot = match paykit_lib::EncryptedLinkHandshakeSnapshot::deserialize(snapshot_bytes)
        {
            Ok(snapshot) => snapshot,
            Err(err) => return Err(classified_lib_restore_error(err)),
        };
        match paykit_lib::restore_encrypted_link_handshake(
            session_access.session,
            secret_key,
            &remote_public_key,
            &self.config.receiver_path,
            counterparty_receiver_path,
            session_access.outbox_client,
            snapshot,
        )
        .await
        {
            Ok(handshake) => Ok(handshake),
            Err(err) => Err(classified_lib_restore_error(err)),
        }
    }

    async fn advance_restored_link_handshake(
        &self,
        counterparty: PubkyPublicKey,
        handshake: paykit_lib::EncryptedLinkHandshake,
        handshake_role: EncryptedLinkHandshakeRole,
        expected_generation: u64,
        lease: PeerLinkOperationLease,
    ) -> Result<LinkedPeerHandshakeReport> {
        let progress = match paykit_lib::advance_handshake(handshake).await {
            Ok(progress) => progress,
            Err(err) => {
                let err = classified_lib_restore_error(err);
                if link_handshake_error_requires_recovery(&err) {
                    self.mark_link_recovery_required(&counterparty, lease)
                        .await?;
                }
                return Err(err);
            }
        };

        match progress {
            paykit_lib::HandshakeProgress::Pending(handshake) => {
                save_link_handshake_state_if_generation_with_lease(
                    &self.storage,
                    counterparty,
                    handshake_role,
                    handshake.serialize(),
                    expected_generation,
                    lease,
                    self.clock.now(),
                )
                .await
            }
            paykit_lib::HandshakeProgress::Complete(link) => {
                let counterparty_receiver_path = lease.counterparty_receiver_path.clone();
                let report = save_linked_peer_link_state_if_generation_with_lease(
                    &self.storage,
                    counterparty.clone(),
                    link.serialize(),
                    expected_generation,
                    lease,
                    self.clock.now(),
                )
                .await?;
                self.remove_local_recovery_marker_if_recorded(
                    &counterparty,
                    &counterparty_receiver_path,
                )
                .await?;
                Ok(report)
            }
        }
    }

    async fn advance_replacement_with_claim(
        &self,
        counterparty: PubkyPublicKey,
        role: EncryptedLinkHandshakeRole,
        lease: PeerLinkOperationLease,
    ) -> Result<LinkedPeerHandshakeReport> {
        let (peer, link_state) = self
            .storage
            .transaction(|tx| {
                Ok((
                    tx.linked_peer(&counterparty, &lease.counterparty_receiver_path),
                    tx.encrypted_link_state(&counterparty, &lease.counterparty_receiver_path),
                ))
            })
            .await?;
        if matches!(
            peer.as_ref().map(|record| &record.state),
            Some(LinkedPeerState::Blocked)
        ) {
            return Err(PaykitSdkError::Policy {
                context: format!("counterparty {counterparty} is blocked"),
                source: None,
            });
        }

        let has_prior_snapshot = link_state
            .as_ref()
            .is_some_and(|state| state.link_snapshot.is_some());
        let progress = link_state
            .as_ref()
            .map(|state| state.replacement.clone())
            .unwrap_or_default();
        let capability = if !has_prior_snapshot {
            PeerCapabilityEvidence::FirstLink
        } else if progress.peer_capability_confirmed {
            PeerCapabilityEvidence::Advertised
        } else {
            self.probe_peer_recovery_capability(&counterparty, &lease, peer.as_ref())
                .await?
        };
        let view = ReplacementView {
            has_prior_snapshot,
            handshake_role: link_state.as_ref().and_then(|state| state.handshake_role),
            has_handshake_snapshot: link_state
                .as_ref()
                .is_some_and(|state| state.handshake_snapshot.is_some()),
            progress: progress.clone(),
            capability,
        };
        match next_replacement_step(&view) {
            ReplacementStep::ConfirmPeerCapability => {
                let mut progress = progress;
                progress.peer_capability_confirmed = true;
                let path = lease.counterparty_receiver_path.clone();
                save_replacement_progress_with_lease(
                    &self.storage,
                    counterparty.clone(),
                    lease,
                    self.clock.now(),
                    progress,
                )
                .await?;
                Ok(replacement_recovery_report(
                    counterparty,
                    path,
                    link_state.as_ref(),
                ))
            }
            ReplacementStep::WaitForPeerCapability => Ok(replacement_recovery_report(
                counterparty,
                lease.counterparty_receiver_path.clone(),
                link_state.as_ref(),
            )),
            ReplacementStep::FailClosed => Err(PaykitSdkError::RecoveryRequired {
                context: format!(
                    "peer recovery-marker capability for {counterparty} is unavailable; snapshots were not cleared"
                ),
                source: None,
            }),
            ReplacementStep::DrainOldInbox => {
                self.drain_old_inbox_with_claim(counterparty.clone(), lease.clone(), progress)
                    .await?;
                let drained = self
                    .storage
                    .transaction(|tx| {
                        Ok(tx.encrypted_link_state(
                            &counterparty,
                            &lease.counterparty_receiver_path,
                        ))
                    })
                    .await?;
                Ok(replacement_recovery_report(
                    counterparty,
                    lease.counterparty_receiver_path.clone(),
                    drained.as_ref(),
                ))
            }
            ReplacementStep::ClearLocalWritePath => {
                self.clear_local_write_path_with_claim(
                    counterparty.clone(),
                    lease.clone(),
                    progress,
                )
                .await?;
                let cleared = self
                    .storage
                    .transaction(|tx| {
                        Ok(tx.encrypted_link_state(
                            &counterparty,
                            &lease.counterparty_receiver_path,
                        ))
                    })
                    .await?;
                Ok(replacement_recovery_report(
                    counterparty,
                    lease.counterparty_receiver_path.clone(),
                    cleared.as_ref(),
                ))
            }
            ReplacementStep::StartReplacementHandshake => {
                self.start_replacement_link_handshake_with_claim(counterparty, role, lease)
                    .await
            }
            ReplacementStep::ResumeReplacementHandshake { .. } => {
                self.advance_link_handshake_with_claim_inner(counterparty, lease, true)
                    .await
            }
        }
    }

    async fn probe_peer_recovery_capability(
        &self,
        counterparty: &PubkyPublicKey,
        lease: &PeerLinkOperationLease,
        peer: Option<&LinkedPeerRecord>,
    ) -> Result<PeerCapabilityEvidence> {
        if peer.is_some_and(|record| record.remote_recovery_attempt_id.is_some()) {
            return Ok(PeerCapabilityEvidence::Advertised);
        }
        let public_storage =
            self.pubky
                .load_public_storage()
                .await?
                .ok_or_else(|| PaykitSdkError::Identity {
                    context: "no Pubky public storage available for recovery capability lookup"
                        .into(),
                    source: None,
                })?;
        let (session_access, secret_key) = self.private_link_session_access().await?;
        let remote_public_key = counterparty.to_public_key()?;
        let remote_noise_public_key = match self
            .receiver_noise_public_key(counterparty, &lease.counterparty_receiver_path)
            .await
        {
            Ok(key) => key,
            Err(err) if err.is_retryable_homeserver_failure() => {
                return Ok(match err {
                    PaykitSdkError::NotFound { .. } => PeerCapabilityEvidence::NotFound,
                    _ => PeerCapabilityEvidence::Transport,
                });
            }
            Err(PaykitSdkError::Protocol { .. }) => {
                return Ok(PeerCapabilityEvidence::Protocol);
            }
            Err(err) => return Err(err),
        };
        match paykit_lib::fetch_encrypted_link_recovery_marker(
            &public_storage,
            &secret_key,
            session_access.session.info().public_key(),
            &remote_public_key,
            &remote_noise_public_key,
            &self.config.receiver_path,
            &lease.counterparty_receiver_path,
        )
        .await
        {
            Ok(Some(_)) => Ok(PeerCapabilityEvidence::Advertised),
            Ok(None) => Ok(PeerCapabilityEvidence::Absent),
            Err(err) => Ok(match err {
                paykit_lib::PaykitError::Transport { .. } => PeerCapabilityEvidence::Transport,
                paykit_lib::PaykitError::NotFound(_) => PeerCapabilityEvidence::NotFound,
                paykit_lib::PaykitError::InvalidData { .. }
                | paykit_lib::PaykitError::Validation(_) => PeerCapabilityEvidence::Protocol,
            }),
        }
    }

    async fn drain_old_inbox_with_claim(
        &self,
        counterparty: PubkyPublicKey,
        lease: PeerLinkOperationLease,
        mut progress: ReplacementHandshakeProgress,
    ) -> Result<()> {
        let (session_access, _) = self.private_link_session_access().await?;
        match self
            .receive_private_messages_with_claim(counterparty.clone(), lease.clone(), session_access)
            .await
        {
            Ok(_) => {}
            Err(err) if err.completes_replacement_drain_attempt() => {}
            Err(err) => return Err(err),
        }
        progress.drain_acknowledged = true;
        save_replacement_progress_with_lease(
            &self.storage,
            counterparty,
            lease,
            self.clock.now(),
            progress,
        )
        .await
    }

    async fn clear_local_write_path_with_claim(
        &self,
        counterparty: PubkyPublicKey,
        lease: PeerLinkOperationLease,
        mut progress: ReplacementHandshakeProgress,
    ) -> Result<()> {
        let (session_access, secret_key) = self.private_link_session_access().await?;
        let remote_public_key = counterparty.to_public_key()?;
        let remote_noise_public_key = self
            .receiver_noise_public_key(&counterparty, &lease.counterparty_receiver_path)
            .await?;
        paykit_lib::clear_encrypted_link_outbox(
            &session_access.session,
            &secret_key,
            &remote_public_key,
            &remote_noise_public_key,
            &self.config.receiver_path,
            &lease.counterparty_receiver_path,
        )
        .await?;
        progress.write_path_cleared = true;
        save_replacement_progress_with_lease(
            &self.storage,
            counterparty,
            lease,
            self.clock.now(),
            progress,
        )
        .await
    }

    async fn start_replacement_link_handshake_with_claim(
        &self,
        counterparty: PubkyPublicKey,
        role: EncryptedLinkHandshakeRole,
        lease: PeerLinkOperationLease,
    ) -> Result<LinkedPeerHandshakeReport> {
        let (session_access, secret_key) = self.private_link_session_access().await?;
        let remote_public_key = counterparty.to_public_key()?;
        let remote_noise_public_key = self
            .receiver_noise_public_key(&counterparty, &lease.counterparty_receiver_path)
            .await?;
        let handshake = match role {
            EncryptedLinkHandshakeRole::Initiator => paykit_lib::initiate_encrypted_link(
                session_access.session,
                secret_key,
                &remote_public_key,
                &remote_noise_public_key,
                &self.config.receiver_path,
                &lease.counterparty_receiver_path,
                session_access.outbox_client,
            )?,
            EncryptedLinkHandshakeRole::Responder => paykit_lib::accept_encrypted_link(
                session_access.session,
                secret_key,
                &remote_public_key,
                &remote_noise_public_key,
                &self.config.receiver_path,
                &lease.counterparty_receiver_path,
                session_access.outbox_client,
            )?,
        };
        save_link_handshake_state_with_lease(
            &self.storage,
            counterparty,
            role,
            handshake.serialize(),
            lease,
            self.clock.now(),
            Some(PubkyPublicKey::from_public_key(&remote_noise_public_key)),
        )
        .await
    }

    async fn start_link_handshake(
        &self,
        counterparty: PubkyPublicKey,
        counterparty_receiver_path: PaykitReceiverPath,
        role: EncryptedLinkHandshakeRole,
    ) -> Result<LinkedPeerHandshakeReport> {
        let _ = self.private_link_session_access().await?;
        let lease = self
            .claim_peer_link_operation(&counterparty, &counterparty_receiver_path)
            .await?;
        let result = self
            .start_link_handshake_with_claim(counterparty, role, lease.clone())
            .await;
        self.finish_peer_link_operation(lease, result).await
    }

    pub(super) async fn start_link_handshake_with_claim(
        &self,
        counterparty: PubkyPublicKey,
        role: EncryptedLinkHandshakeRole,
        lease: PeerLinkOperationLease,
    ) -> Result<LinkedPeerHandshakeReport> {
        let peer_state = self
            .storage
            .transaction(|tx| {
                Ok(tx
                    .linked_peer(&counterparty, &lease.counterparty_receiver_path)
                    .map(|peer| peer.state))
            })
            .await?;
        if matches!(peer_state, Some(LinkedPeerState::Blocked)) {
            return Err(PaykitSdkError::Policy {
                context: format!("counterparty {counterparty} is blocked"),
                source: None,
            });
        }

        if !matches!(peer_state, Some(LinkedPeerState::RecoveryRequired)) {
            if let Some(existing) = self
                .storage
                .transaction(|tx| {
                    Ok(tx.encrypted_link_state(&counterparty, &lease.counterparty_receiver_path))
                })
                .await?
            {
                if existing.handshake_snapshot.is_some() {
                    if existing.handshake_role.is_none() {
                        let mark = mark_recovery_required_with_lease(
                            &self.storage,
                            counterparty.clone(),
                            lease.clone(),
                            self.clock.now(),
                        )
                        .await?;
                        self.publish_local_recovery_marker_if_possible(
                            &counterparty,
                            &lease.counterparty_receiver_path,
                            mark.new_episode,
                        )
                        .await;
                        return Err(PaykitSdkError::RecoveryRequired {
                            context: format!(
                                "missing Encrypted Link Handshake role for counterparty {counterparty}"
                            ),
                            source: None,
                        });
                    }
                    save_linked_peer_state_with_lease(
                        &self.storage,
                        counterparty.clone(),
                        LinkedPeerState::Linking,
                        lease.clone(),
                        self.clock.now(),
                    )
                    .await?;
                    return Ok(LinkedPeerHandshakeReport {
                        counterparty,
                        counterparty_receiver_path: existing.counterparty_receiver_path,
                        state: LinkedPeerState::Linking,
                        generation: existing.generation,
                        handshake_role: existing.handshake_role,
                    });
                }
                if existing.link_snapshot.is_some() {
                    return self
                        .confirm_linked_peer_receiver_noise(counterparty, existing, lease)
                        .await;
                }
            }
        }

        let (session_access, secret_key) = self.private_link_session_access().await?;
        let remote_public_key = counterparty.to_public_key()?;
        let remote_noise_public_key = self
            .receiver_noise_public_key(&counterparty, &lease.counterparty_receiver_path)
            .await?;
        if matches!(peer_state, Some(LinkedPeerState::RecoveryRequired)) {
            return Err(PaykitSdkError::RecoveryRequired {
                context: format!(
                    "counterparty {counterparty} requires an old-inbox drain before replacement handshake"
                ),
                source: None,
            });
        }
        let handshake = match role {
            EncryptedLinkHandshakeRole::Initiator => paykit_lib::initiate_encrypted_link(
                session_access.session,
                secret_key,
                &remote_public_key,
                &remote_noise_public_key,
                &self.config.receiver_path,
                &lease.counterparty_receiver_path,
                session_access.outbox_client,
            )?,
            EncryptedLinkHandshakeRole::Responder => paykit_lib::accept_encrypted_link(
                session_access.session,
                secret_key,
                &remote_public_key,
                &remote_noise_public_key,
                &self.config.receiver_path,
                &lease.counterparty_receiver_path,
                session_access.outbox_client,
            )?,
        };

        save_link_handshake_state_with_lease(
            &self.storage,
            counterparty,
            role,
            handshake.serialize(),
            lease,
            self.clock.now(),
            Some(PubkyPublicKey::from_public_key(&remote_noise_public_key)),
        )
        .await
    }

    pub(super) async fn claim_peer_link_operation(
        &self,
        counterparty: &PubkyPublicKey,
        counterparty_receiver_path: &PaykitReceiverPath,
    ) -> Result<PeerLinkOperationLease> {
        let now = self.clock.now();
        let lease_timeout = ChronoDuration::from_std(self.config.peer_link_operation_lease_timeout)
            .map_err(|err| PaykitSdkError::Policy {
                context: format!("invalid peer link lease timeout: {err}"),
                source: None,
            })?;
        let expires_at = now + lease_timeout;
        self.storage
            .transaction(|tx| {
                Ok(tx.claim_peer_link_operation(
                    counterparty,
                    counterparty_receiver_path,
                    now,
                    expires_at,
                ))
            })
            .await?
            .ok_or_else(|| PaykitSdkError::Policy {
                context: format!(
                    "peer link operation already in progress for counterparty {counterparty}"
                ),
                source: None,
            })
    }

    pub(super) async fn release_peer_link_operation(
        &self,
        lease: &PeerLinkOperationLease,
    ) -> Result<()> {
        self.storage
            .transaction(|tx| {
                tx.release_peer_link_operation(
                    &lease.counterparty,
                    &lease.counterparty_receiver_path,
                    lease.lease_id,
                );
                Ok(())
            })
            .await
    }

    pub(super) async fn finish_peer_link_operation<T>(
        &self,
        lease: PeerLinkOperationLease,
        result: Result<T>,
    ) -> Result<T> {
        let release_result = self.release_peer_link_operation(&lease).await;
        match (result, release_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(err), _) => Err(err),
            (Ok(_), Err(err)) => Err(err),
        }
    }

    pub(super) async fn private_link_session_access(
        &self,
    ) -> Result<(PubkySessionAccess, [u8; 32])> {
        let (session_access, _) = self.load_session_access_and_refresh_identity().await?;
        let session_access = session_access.ok_or_else(|| PaykitSdkError::Identity {
            context: "no Pubky session available".into(),
            source: None,
        })?;
        let secret_key = *session_access.receiver_noise_secret_key.as_bytes();
        Ok((session_access, secret_key))
    }

    async fn confirm_linked_peer_receiver_noise(
        &self,
        counterparty: PubkyPublicKey,
        state: EncryptedLinkStateRecord,
        lease: PeerLinkOperationLease,
    ) -> Result<LinkedPeerHandshakeReport> {
        let peer_state = self
            .storage
            .transaction(|tx| {
                Ok(tx
                    .linked_peer(&counterparty, &lease.counterparty_receiver_path)
                    .map(|peer| peer.state))
            })
            .await?;
        if matches!(peer_state, Some(LinkedPeerState::RecoveryRequired))
            || replacement_should_run(peer_state.as_ref(), Some(&state))
        {
            return Ok(replacement_recovery_report(
                counterparty,
                state.counterparty_receiver_path.clone(),
                Some(&state),
            ));
        }
        let live = PubkyPublicKey::from_public_key(
            &self
                .receiver_noise_public_key(&counterparty, &lease.counterparty_receiver_path)
                .await?,
        );
        match compare_peer_receiver_noise(state.peer_receiver_noise_public_key.as_ref(), &live) {
            PeerReceiverNoiseComparison::Mismatch => Err(PaykitSdkError::Policy {
                context: format!(
                    "peer receiver-noise fingerprint mismatch for {counterparty}; re-enrollment required"
                ),
                source: None,
            }),
            PeerReceiverNoiseComparison::CaptureLive => {
                save_peer_receiver_noise_fingerprint_with_lease(
                    &self.storage,
                    counterparty,
                    lease,
                    self.clock.now(),
                    live,
                )
                .await
            }
            PeerReceiverNoiseComparison::Match => {
                save_linked_peer_state_with_lease(
                    &self.storage,
                    counterparty.clone(),
                    LinkedPeerState::Linked,
                    lease,
                    self.clock.now(),
                )
                .await?;
                Ok(LinkedPeerHandshakeReport {
                    counterparty,
                    counterparty_receiver_path: state.counterparty_receiver_path,
                    state: LinkedPeerState::Linked,
                    generation: state.generation,
                    handshake_role: None,
                })
            }
        }
    }
}

fn classified_lib_restore_error(err: paykit_lib::PaykitError) -> PaykitSdkError {
    if paykit_lib_error_requires_link_recovery(&err) {
        PaykitSdkError::RecoveryRequired {
            context: "Encrypted Link Handshake restore failed integrity or validation checks"
                .into(),
            source: None,
        }
    } else {
        err.into()
    }
}

fn replacement_should_run(
    peer_state: Option<&LinkedPeerState>,
    link_state: Option<&EncryptedLinkStateRecord>,
) -> bool {
    matches!(peer_state, Some(LinkedPeerState::RecoveryRequired))
        || link_state.is_some_and(|state| {
            state.replacement.peer_capability_confirmed
                || state.replacement.drain_acknowledged
                || state.replacement.write_path_cleared
                || (state.link_snapshot.is_some() && state.handshake_snapshot.is_some())
        })
}

fn replacement_recovery_report(
    counterparty: PubkyPublicKey,
    counterparty_receiver_path: PaykitReceiverPath,
    link_state: Option<&EncryptedLinkStateRecord>,
) -> LinkedPeerHandshakeReport {
    LinkedPeerHandshakeReport {
        counterparty,
        counterparty_receiver_path,
        state: LinkedPeerState::RecoveryRequired,
        generation: link_state.map(|state| state.generation).unwrap_or_default(),
        handshake_role: None,
    }
}

fn clear_encrypted_link_state(
    tx: &mut dyn StorageTransaction,
    counterparty: &PubkyPublicKey,
    counterparty_receiver_path: &PaykitReceiverPath,
    now: DateTime<Utc>,
) {
    if let Some(link_state) = tx.encrypted_link_state(counterparty, counterparty_receiver_path) {
        tx.save_encrypted_link_state(EncryptedLinkStateRecord {
            counterparty: counterparty.clone(),
            counterparty_receiver_path: link_state.counterparty_receiver_path,
            link_snapshot: None,
            handshake_snapshot: None,
            handshake_role: None,
            generation: link_state.generation.saturating_add(1),
            checkpointed_at: now,
            peer_receiver_noise_public_key: None,
            replacement: Default::default(),
        });
    }
}

fn deterministic_handshake_role(
    local_public_key: &PubkyPublicKey,
    counterparty: &PubkyPublicKey,
) -> EncryptedLinkHandshakeRole {
    if local_public_key.as_str() < counterparty.as_str() {
        EncryptedLinkHandshakeRole::Initiator
    } else {
        EncryptedLinkHandshakeRole::Responder
    }
}
