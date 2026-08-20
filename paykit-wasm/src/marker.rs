use paykit_lib::{
    get_paykit_receiver_marker, publish_paykit_receiver_marker, remove_paykit_receiver_marker,
    PaykitReceiverCapabilities, PaykitReceiverMarker,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::js_err;
use crate::keys::public_key_from_z32;
use crate::link::receiver_path;
use crate::session::{PubkyClient, SessionHandle};

fn set(obj: &js_sys::Object, key: &str, value: &JsValue) {
    let _ = js_sys::Reflect::set(obj, &JsValue::from_str(key), value);
}

/// Publish a public Paykit Receiver Marker for the session owner, making the
/// receiver path discoverable and advertising the receiver Noise public key
/// used for Encrypted Link path derivation.
///
/// A messaging-only receiver typically sets `privatePayments = true` (the
/// Encrypted Link capability) and the payment capabilities to `false`.
#[wasm_bindgen(js_name = publishReceiverMarker)]
pub fn publish_receiver_marker_js(
    session: &SessionHandle,
    receiver_path_value: &str,
    noise_public_key: &str,
    private_payments: bool,
    payment_requests: bool,
    receipts: bool,
    outgoing_payments: bool,
) -> Result<js_sys::Promise, JsValue> {
    let path = receiver_path(receiver_path_value, "marker")?;
    let noise = public_key_from_z32(noise_public_key, "noise")?;
    let marker = PaykitReceiverMarker::new(
        path,
        PaykitReceiverCapabilities {
            private_payments,
            payment_requests,
            receipts,
            outgoing_payments,
        },
        noise,
    );
    let session = session.inner.clone();
    Ok(future_to_promise(async move {
        publish_paykit_receiver_marker(&session, &marker)
            .await
            .map_err(|err| js_err("failed to publish receiver marker", err))?;
        Ok(JsValue::UNDEFINED)
    }))
}

/// Fetch a counterparty's public Paykit Receiver Marker. Resolves to
/// `{ receiverPath, noisePublicKey, capabilities: { privatePayments,
/// paymentRequests, receipts, outgoingPayments } }`, or `undefined` if the
/// owner has not published one at that path.
#[wasm_bindgen(js_name = getReceiverMarker)]
pub fn get_receiver_marker_js(
    client: &PubkyClient,
    owner_pubky: &str,
    receiver_path_value: &str,
) -> Result<js_sys::Promise, JsValue> {
    let owner = public_key_from_z32(owner_pubky, "owner")?;
    let path = receiver_path(receiver_path_value, "marker")?;
    let storage = client.inner.public_storage();
    Ok(future_to_promise(async move {
        let marker = get_paykit_receiver_marker(&storage, &owner, &path)
            .await
            .map_err(|err| js_err("failed to fetch receiver marker", err))?;
        match marker {
            None => Ok(JsValue::UNDEFINED),
            Some(marker) => {
                let capabilities = js_sys::Object::new();
                set(
                    &capabilities,
                    "privatePayments",
                    &JsValue::from_bool(marker.capabilities.private_payments),
                );
                set(
                    &capabilities,
                    "paymentRequests",
                    &JsValue::from_bool(marker.capabilities.payment_requests),
                );
                set(
                    &capabilities,
                    "receipts",
                    &JsValue::from_bool(marker.capabilities.receipts),
                );
                set(
                    &capabilities,
                    "outgoingPayments",
                    &JsValue::from_bool(marker.capabilities.outgoing_payments),
                );
                let obj = js_sys::Object::new();
                set(
                    &obj,
                    "receiverPath",
                    &JsValue::from_str(marker.receiver_path.as_ref()),
                );
                set(
                    &obj,
                    "noisePublicKey",
                    &JsValue::from_str(&marker.noise_public_key.z32()),
                );
                set(&obj, "capabilities", &capabilities.into());
                Ok(obj.into())
            }
        }
    }))
}

/// Remove the session owner's public Paykit Receiver Marker at a path.
#[wasm_bindgen(js_name = removeReceiverMarker)]
pub fn remove_receiver_marker_js(
    session: &SessionHandle,
    receiver_path_value: &str,
) -> Result<js_sys::Promise, JsValue> {
    let path = receiver_path(receiver_path_value, "marker")?;
    let session = session.inner.clone();
    Ok(future_to_promise(async move {
        remove_paykit_receiver_marker(&session, &path)
            .await
            .map_err(|err| js_err("failed to remove receiver marker", err))?;
        Ok(JsValue::UNDEFINED)
    }))
}
