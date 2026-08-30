use std::cell::RefCell;
use std::rc::Rc;

use paykit_lib::{
    accept_encrypted_link, advance_handshake, clear_encrypted_link_outbox, close_encrypted_link,
    initiate_encrypted_link, restore_encrypted_link, restore_encrypted_link_handshake,
    set_private_payment_list, EncryptedLink, EncryptedLinkHandshake,
    EncryptedLinkHandshakeSnapshot, EncryptedLinkSnapshot, HandshakeProgress, PaykitReceiverPath,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::{js_err, js_err_msg};
use crate::keys::{public_key_from_z32, secret_key_from_slice};
use crate::session::{PubkyClient, SessionHandle};

pub(crate) fn receiver_path(value: &str, what: &str) -> Result<PaykitReceiverPath, JsValue> {
    PaykitReceiverPath::new(value)
        .map_err(|err| js_err(&format!("invalid {what} receiver path"), err))
}

fn set(obj: &js_sys::Object, key: &str, value: &JsValue) {
    // Reflect::set on a plain object cannot fail.
    let _ = js_sys::Reflect::set(obj, &JsValue::from_str(key), value);
}

/// Initiate a Noise XX Encrypted Link Handshake toward a counterparty
/// (initiator role).
///
/// `receiverNoisePublicKey` comes from the counterparty's Receiver Marker
/// (see `getReceiverMarker`). Drive the returned handshake with `advance()`
/// until it completes.
#[wasm_bindgen(js_name = initiateEncryptedLink)]
pub fn initiate_encrypted_link_js(
    session: &SessionHandle,
    sender_noise_secret_key: &[u8],
    receiver_pubky: &str,
    receiver_noise_public_key: &str,
    local_receiver_path: &str,
    remote_receiver_path: &str,
    client: &PubkyClient,
) -> Result<LinkHandshakeHandle, JsValue> {
    let secret = secret_key_from_slice(sender_noise_secret_key)?;
    let receiver = public_key_from_z32(receiver_pubky, "receiver identity")?;
    let receiver_noise = public_key_from_z32(receiver_noise_public_key, "receiver noise")?;
    let local_path = receiver_path(local_receiver_path, "local")?;
    let remote_path = receiver_path(remote_receiver_path, "remote")?;
    let handshake = initiate_encrypted_link(
        session.inner.clone(),
        secret,
        &receiver,
        &receiver_noise,
        &local_path,
        &remote_path,
        client.inner.clone(),
    )
    .map_err(|err| js_err("failed to initiate Encrypted Link", err))?;
    Ok(LinkHandshakeHandle::new(handshake))
}

/// Accept a Noise XX Encrypted Link Handshake from a counterparty
/// (responder role).
#[wasm_bindgen(js_name = acceptEncryptedLink)]
pub fn accept_encrypted_link_js(
    session: &SessionHandle,
    receiver_noise_secret_key: &[u8],
    sender_pubky: &str,
    sender_noise_public_key: &str,
    local_receiver_path: &str,
    remote_receiver_path: &str,
    client: &PubkyClient,
) -> Result<LinkHandshakeHandle, JsValue> {
    let secret = secret_key_from_slice(receiver_noise_secret_key)?;
    let sender = public_key_from_z32(sender_pubky, "sender identity")?;
    let sender_noise = public_key_from_z32(sender_noise_public_key, "sender noise")?;
    let local_path = receiver_path(local_receiver_path, "local")?;
    let remote_path = receiver_path(remote_receiver_path, "remote")?;
    let handshake = accept_encrypted_link(
        session.inner.clone(),
        secret,
        &sender,
        &sender_noise,
        &local_path,
        &remote_path,
        client.inner.clone(),
    )
    .map_err(|err| js_err("failed to accept Encrypted Link", err))?;
    Ok(LinkHandshakeHandle::new(handshake))
}

/// Restore an in-progress handshake from snapshot bytes previously produced
/// by `LinkHandshakeHandle.snapshot()`.
#[wasm_bindgen(js_name = restoreEncryptedLinkHandshake)]
pub fn restore_encrypted_link_handshake_js(
    session: &SessionHandle,
    noise_secret_key: &[u8],
    remote_pubky: &str,
    local_receiver_path: &str,
    remote_receiver_path: &str,
    client: &PubkyClient,
    snapshot: &[u8],
) -> Result<js_sys::Promise, JsValue> {
    let secret = secret_key_from_slice(noise_secret_key)?;
    let remote = public_key_from_z32(remote_pubky, "remote identity")?;
    let local_path = receiver_path(local_receiver_path, "local")?;
    let remote_path = receiver_path(remote_receiver_path, "remote")?;
    let snapshot = EncryptedLinkHandshakeSnapshot::deserialize(snapshot)
        .map_err(|err| js_err("invalid handshake snapshot", err))?;
    let session = session.inner.clone();
    let client = client.inner.clone();
    Ok(future_to_promise(async move {
        let handshake = restore_encrypted_link_handshake(
            session,
            secret,
            &remote,
            &local_path,
            &remote_path,
            client,
            snapshot,
        )
        .await
        .map_err(|err| js_err("failed to restore Encrypted Link handshake", err))?;
        Ok(LinkHandshakeHandle::new(handshake).into())
    }))
}

/// Restore an established Encrypted Link from snapshot bytes previously
/// produced by `EncryptedLinkHandle.snapshot()`.
#[wasm_bindgen(js_name = restoreEncryptedLink)]
pub fn restore_encrypted_link_js(
    session: &SessionHandle,
    noise_secret_key: &[u8],
    remote_pubky: &str,
    local_receiver_path: &str,
    remote_receiver_path: &str,
    client: &PubkyClient,
    snapshot: &[u8],
) -> Result<js_sys::Promise, JsValue> {
    let secret = secret_key_from_slice(noise_secret_key)?;
    let remote = public_key_from_z32(remote_pubky, "remote identity")?;
    let local_path = receiver_path(local_receiver_path, "local")?;
    let remote_path = receiver_path(remote_receiver_path, "remote")?;
    let snapshot = EncryptedLinkSnapshot::deserialize(snapshot)
        .map_err(|err| js_err("invalid link snapshot", err))?;
    let session = session.inner.clone();
    let client = client.inner.clone();
    Ok(future_to_promise(async move {
        let link = restore_encrypted_link(
            session,
            secret,
            &remote,
            &local_path,
            &remote_path,
            client,
            snapshot,
        )
        .await
        .map_err(|err| js_err("failed to restore Encrypted Link", err))?;
        Ok(EncryptedLinkHandle::new(link).into())
    }))
}

/// Delete all encrypted stream slots written by the local identity for one
/// counterparty (recovery before a fresh handshake). Resolves to the number
/// of deleted slots.
#[wasm_bindgen(js_name = clearEncryptedLinkOutbox)]
pub fn clear_encrypted_link_outbox_js(
    session: &SessionHandle,
    local_noise_secret_key: &[u8],
    remote_pubky: &str,
    remote_noise_public_key: &str,
    local_receiver_path: &str,
    remote_receiver_path: &str,
) -> Result<js_sys::Promise, JsValue> {
    let secret = secret_key_from_slice(local_noise_secret_key)?;
    let remote = public_key_from_z32(remote_pubky, "remote identity")?;
    let remote_noise = public_key_from_z32(remote_noise_public_key, "remote noise")?;
    let local_path = receiver_path(local_receiver_path, "local")?;
    let remote_path = receiver_path(remote_receiver_path, "remote")?;
    let session = session.inner.clone();
    Ok(future_to_promise(async move {
        let deleted = clear_encrypted_link_outbox(
            &session,
            &secret,
            &remote,
            &remote_noise,
            &local_path,
            &remote_path,
        )
        .await
        .map_err(|err| js_err("failed to clear Encrypted Link outbox", err))?;
        Ok(JsValue::from_f64(deleted as f64))
    }))
}

/// Handle to an in-progress Encrypted Link handshake.
#[wasm_bindgen]
pub struct LinkHandshakeHandle {
    inner: Rc<RefCell<Option<EncryptedLinkHandshake>>>,
}

impl LinkHandshakeHandle {
    fn new(handshake: EncryptedLinkHandshake) -> Self {
        Self {
            inner: Rc::new(RefCell::new(Some(handshake))),
        }
    }
}

#[wasm_bindgen]
impl LinkHandshakeHandle {
    /// Advance the handshake by one step. Resolves to
    /// `{ status: "pending" }` (poll again after a delay) or
    /// `{ status: "complete", link: EncryptedLinkHandle }`.
    ///
    /// If the step errors, the in-memory handshake is consumed (matching the
    /// paykit-lib ownership model); recover via
    /// `restoreEncryptedLinkHandshake` with a persisted snapshot.
    pub fn advance(&self) -> js_sys::Promise {
        let cell = self.inner.clone();
        future_to_promise(async move {
            let handshake = cell.borrow_mut().take().ok_or_else(|| {
                js_err_msg("handshake consumed (completed, failed, or advance in flight)")
            })?;
            match advance_handshake(handshake).await {
                Ok(HandshakeProgress::Pending(handshake)) => {
                    cell.borrow_mut().replace(handshake);
                    let obj = js_sys::Object::new();
                    set(&obj, "status", &JsValue::from_str("pending"));
                    Ok(obj.into())
                }
                Ok(HandshakeProgress::Complete(link)) => {
                    let obj = js_sys::Object::new();
                    set(&obj, "status", &JsValue::from_str("complete"));
                    set(&obj, "link", &EncryptedLinkHandle::new(link).into());
                    Ok(obj.into())
                }
                Err(err) => Err(js_err("handshake step failed", err)),
            }
        })
    }

    /// Serialize the current handshake state. Snapshot bytes contain key
    /// material — store as secrets.
    pub fn snapshot(&self) -> Result<Vec<u8>, JsValue> {
        self.inner
            .borrow()
            .as_ref()
            .map(EncryptedLinkHandshake::serialize)
            .ok_or_else(|| js_err_msg("handshake consumed"))
    }

    /// Override the automatic write-failure recovery attempt limit.
    #[wasm_bindgen(js_name = setMaxRecoveryAttempts)]
    pub fn set_max_recovery_attempts(&self, max: u32) -> Result<(), JsValue> {
        self.inner
            .borrow_mut()
            .as_mut()
            .map(|handshake| {
                handshake.set_max_recovery_attempts(max);
            })
            .ok_or_else(|| js_err_msg("handshake consumed"))
    }
}

/// Handle to an established Encrypted Link.
#[wasm_bindgen]
pub struct EncryptedLinkHandle {
    inner: Rc<RefCell<Option<EncryptedLink>>>,
    recipient: String,
    remote_noise_public_key: String,
    local_receiver_path: String,
    remote_receiver_path: String,
}

impl EncryptedLinkHandle {
    fn new(link: EncryptedLink) -> Self {
        Self {
            recipient: link.recipient().z32(),
            remote_noise_public_key: link.remote_noise_public_key().z32(),
            local_receiver_path: link.local_receiver_path().to_string(),
            remote_receiver_path: link.snapshot().remote_receiver_path().to_string(),
            inner: Rc::new(RefCell::new(Some(link))),
        }
    }
}

#[wasm_bindgen]
impl EncryptedLinkHandle {
    /// Counterparty Pubky identity public key (z-base-32).
    pub fn recipient(&self) -> String {
        self.recipient.clone()
    }

    /// Counterparty receiver Noise public key (z-base-32).
    #[wasm_bindgen(js_name = remoteNoisePublicKey)]
    pub fn remote_noise_public_key(&self) -> String {
        self.remote_noise_public_key.clone()
    }

    /// Local Paykit receiver path.
    #[wasm_bindgen(js_name = localReceiverPath)]
    pub fn local_receiver_path(&self) -> String {
        self.local_receiver_path.clone()
    }

    /// Counterparty Paykit receiver path.
    #[wasm_bindgen(js_name = remoteReceiverPath)]
    pub fn remote_receiver_path(&self) -> String {
        self.remote_receiver_path.clone()
    }

    /// Send one raw JSON Private Application Message. The JSON must carry a
    /// `version` (u8) and `kind` (string) envelope; unknown kinds are allowed
    /// by contract (`send_private_application_message_json`).
    #[wasm_bindgen(js_name = sendPrivateApplicationMessageJson)]
    pub fn send_private_application_message_json(&self, raw_json: String) -> js_sys::Promise {
        let cell = self.inner.clone();
        future_to_promise(async move {
            let mut link = cell
                .borrow_mut()
                .take()
                .ok_or_else(|| js_err_msg("link is closed or an operation is in flight"))?;
            let result = link.send_private_application_message_json(&raw_json).await;
            cell.borrow_mut().replace(link);
            result.map_err(|err| js_err("failed to send Private Application Message", err))?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Encrypt and send a complete Private Payment List over this link.
    ///
    /// `endpoints` is a plain object `{ identifier: payload }` — the full
    /// desired list, not a patch. Binds paykit-lib
    /// `set_private_payment_list`. There is no homeserver GET for private
    /// endpoints; the counterparty reads them via
    /// `receivePrivateApplicationMessages` + `parsePrivatePaymentListJson`.
    /// Do not log payloads. Session and link lifetime remain the caller's
    /// responsibility.
    #[wasm_bindgen(js_name = sendPrivatePaymentList)]
    pub fn send_private_payment_list(
        &self,
        endpoints: js_sys::Object,
    ) -> Result<js_sys::Promise, JsValue> {
        let list = crate::payments::private_payment_list_from_js(&endpoints)?;
        let cell = self.inner.clone();
        Ok(future_to_promise(async move {
            let mut link = cell
                .borrow_mut()
                .take()
                .ok_or_else(|| js_err_msg("link is closed or an operation is in flight"))?;
            let result = set_private_payment_list(&mut link, &list).await;
            cell.borrow_mut().replace(link);
            result.map_err(|err| js_err("failed to send Private Payment List", err))?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Receive available Private Application Messages in stream order.
    /// Resolves to an array of `{ version, kind, rawJson }`. Persist returned
    /// messages before replacing a stored link snapshot (the read checkpoint
    /// advances past them).
    #[wasm_bindgen(js_name = receivePrivateApplicationMessages)]
    pub fn receive_private_application_messages(&self) -> js_sys::Promise {
        let cell = self.inner.clone();
        future_to_promise(async move {
            let mut link = cell
                .borrow_mut()
                .take()
                .ok_or_else(|| js_err_msg("link is closed or an operation is in flight"))?;
            let result = link.receive_private_application_messages().await;
            cell.borrow_mut().replace(link);
            let messages = result
                .map_err(|err| js_err("failed to receive Private Application Messages", err))?;
            let array = js_sys::Array::new();
            for message in messages {
                let obj = js_sys::Object::new();
                set(
                    &obj,
                    "version",
                    &message.version.map_or(JsValue::UNDEFINED, JsValue::from),
                );
                set(
                    &obj,
                    "kind",
                    &message
                        .kind
                        .as_deref()
                        .map_or(JsValue::UNDEFINED, JsValue::from_str),
                );
                set(&obj, "rawJson", &JsValue::from_str(&message.raw_json));
                array.push(&obj);
            }
            Ok(array.into())
        })
    }

    /// Serialize the current link state for persistence. Take a fresh
    /// snapshot after sending/receiving when persisted counters must catch
    /// up. Snapshot bytes contain key material — store as secrets.
    pub fn snapshot(&self) -> Result<Vec<u8>, JsValue> {
        self.inner
            .borrow()
            .as_ref()
            .map(EncryptedLink::serialize)
            .ok_or_else(|| js_err_msg("link is closed or an operation is in flight"))
    }

    /// Override the automatic send retry limit for transient homeserver
    /// write failures.
    #[wasm_bindgen(js_name = setMaxSendRetries)]
    pub fn set_max_send_retries(&self, max: u32) -> Result<(), JsValue> {
        self.inner
            .borrow_mut()
            .as_mut()
            .map(|link| {
                link.set_max_send_retries(max);
            })
            .ok_or_else(|| js_err_msg("link is closed or an operation is in flight"))
    }

    /// Close the link and clean up Noise session state. The handle becomes
    /// unusable afterwards.
    pub fn close(&self) -> js_sys::Promise {
        let cell = self.inner.clone();
        future_to_promise(async move {
            let link = cell
                .borrow_mut()
                .take()
                .ok_or_else(|| js_err_msg("link already closed"))?;
            close_encrypted_link(link)
                .await
                .map_err(|err| js_err("failed to close Encrypted Link", err))?;
            Ok(JsValue::UNDEFINED)
        })
    }
}
