use std::collections::HashMap;

use paykit_lib::{
    get_payment_endpoint, get_payment_list, list_paykit_receiver_paths,
    parse_private_payment_list_json, remove_payment_endpoint, serialize_private_payment_list_json,
    set_payment_endpoint, PaymentEndpointIdentifier, PaymentEndpointPayload, PaymentList,
    PrivatePaymentList,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::{js_err, js_err_msg};
use crate::keys::public_key_from_z32;
use crate::link::receiver_path;
use crate::session::{PubkyClient, SessionHandle};

/// Define `key` as an own enumerable data property.
///
/// `Reflect::set` on a normal object treats `__proto__` as the prototype
/// setter (a valid [`PaymentEndpointIdentifier`]), which drops a string
/// payload as a silent no-op. `define_property` always creates an own
/// data property, so identifier→payload maps keep every key.
fn define_own_string(obj: &js_sys::Object, key: &str, value: &str) {
    let descriptor = js_sys::Object::new();
    let _ = js_sys::Reflect::set(
        &descriptor,
        &JsValue::from_str("value"),
        &JsValue::from_str(value),
    );
    let _ = js_sys::Reflect::set(&descriptor, &JsValue::from_str("writable"), &JsValue::TRUE);
    let _ = js_sys::Reflect::set(
        &descriptor,
        &JsValue::from_str("enumerable"),
        &JsValue::TRUE,
    );
    let _ = js_sys::Reflect::set(
        &descriptor,
        &JsValue::from_str("configurable"),
        &JsValue::TRUE,
    );
    let _ = js_sys::Reflect::define_property(obj, &JsValue::from_str(key), &descriptor);
}

fn payment_endpoint_identifier(value: &str) -> Result<PaymentEndpointIdentifier, JsValue> {
    identifier_from_str(value).map_err(|err| js_err_msg(&err))
}

pub(crate) fn identifier_from_str(value: &str) -> Result<PaymentEndpointIdentifier, String> {
    PaymentEndpointIdentifier::new(value)
        .map_err(|err| format!("invalid payment endpoint identifier: {err}"))
}

pub(crate) fn private_list_from_pairs(
    pairs: impl IntoIterator<Item = (String, String)>,
) -> Result<PrivatePaymentList, String> {
    let mut payment_endpoints = HashMap::new();
    for (key, value) in pairs {
        let identifier = identifier_from_str(&key)?;
        payment_endpoints.insert(identifier, PaymentEndpointPayload::new(value));
    }
    Ok(PrivatePaymentList::new(payment_endpoints))
}

pub(crate) fn serialize_private_list_pairs(
    pairs: impl IntoIterator<Item = (String, String)>,
) -> Result<String, String> {
    let list = private_list_from_pairs(pairs)?;
    serialize_private_payment_list_json(&list)
        .map_err(|err| format!("failed to serialize Private Payment List: {err}"))
}

pub(crate) fn parse_private_list_to_pairs(json: &str) -> Result<Vec<(String, String)>, String> {
    let list = parse_private_payment_list_json(json)
        .map_err(|err| format!("failed to parse Private Payment List: {err}"))?;
    let mut pairs: Vec<_> = list
        .payment_endpoints
        .iter()
        .map(|(identifier, payload)| {
            (
                identifier.as_str().to_string(),
                payload.as_str().to_string(),
            )
        })
        .collect();
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(pairs)
}

fn js_to_pairs(obj: &js_sys::Object) -> Result<Vec<(String, String)>, JsValue> {
    let keys = js_sys::Object::keys(obj);
    let mut pairs = Vec::with_capacity(keys.length() as usize);
    for index in 0..keys.length() {
        let key = keys.get(index);
        let identifier = key
            .as_string()
            .ok_or_else(|| js_err_msg("payment endpoint identifier must be a string"))?;
        let value = js_sys::Reflect::get(obj, &key)
            .map_err(|_| js_err_msg("failed to read payment endpoint"))?;
        let payload = value.as_string().ok_or_else(|| {
            js_err_msg(&format!(
                "payment endpoint payload for '{identifier}' must be a string"
            ))
        })?;
        pairs.push((identifier, payload));
    }
    Ok(pairs)
}

pub(crate) fn private_payment_list_from_js(
    obj: &js_sys::Object,
) -> Result<PrivatePaymentList, JsValue> {
    private_list_from_pairs(js_to_pairs(obj)?).map_err(|err| js_err_msg(&err))
}

fn payment_list_to_js(list: &PaymentList) -> js_sys::Object {
    let obj = js_sys::Object::new();
    for (identifier, payload) in &list.payment_endpoints {
        define_own_string(&obj, identifier.as_str(), payload.as_str());
    }
    obj
}

fn pairs_to_js(pairs: &[(String, String)]) -> js_sys::Object {
    let obj = js_sys::Object::new();
    for (identifier, payload) in pairs {
        define_own_string(&obj, identifier, payload);
    }
    obj
}

/// Publish or update a public Payment Endpoint for the session owner.
///
/// Authenticated PUT via the session. Path construction stays inside
/// paykit-lib (`PAYKIT_PATH_PREFIX`). Session creation, capability scope
/// (`/pub/paykit/:rw`), and key rotation remain the caller's
/// responsibility. Do not log `payload`.
#[wasm_bindgen(js_name = setPaymentEndpoint)]
pub fn set_payment_endpoint_js(
    session: &SessionHandle,
    receiver_path_value: &str,
    identifier: &str,
    payload: &str,
) -> Result<js_sys::Promise, JsValue> {
    let path = receiver_path(receiver_path_value, "payment")?;
    let identifier = payment_endpoint_identifier(identifier)?;
    let payload = PaymentEndpointPayload::new(payload);
    let session = session.inner.clone();
    Ok(future_to_promise(async move {
        set_payment_endpoint(&session, &path, identifier, payload)
            .await
            .map_err(|err| js_err("failed to set payment endpoint", err))?;
        Ok(JsValue::UNDEFINED)
    }))
}

/// Remove a public Payment Endpoint owned by the session.
///
/// A missing endpoint is success (paykit-lib treats homeserver 404 as
/// already absent). Session creation and capability scope remain the
/// caller's responsibility.
#[wasm_bindgen(js_name = removePaymentEndpoint)]
pub fn remove_payment_endpoint_js(
    session: &SessionHandle,
    receiver_path_value: &str,
    identifier: &str,
) -> Result<js_sys::Promise, JsValue> {
    let path = receiver_path(receiver_path_value, "payment")?;
    let identifier = payment_endpoint_identifier(identifier)?;
    let session = session.inner.clone();
    Ok(future_to_promise(async move {
        remove_payment_endpoint(&session, &path, identifier)
            .await
            .map_err(|err| js_err("failed to remove payment endpoint", err))?;
        Ok(JsValue::UNDEFINED)
    }))
}

/// Fetch one public Payment Endpoint for `payee` at `receiverPath`.
///
/// Resolves to the payload string, or `undefined` when the endpoint file is
/// missing or empty (homeserver 404/410). Other transport failures reject.
/// Session creation is not required; this is an unauthenticated public read.
#[wasm_bindgen(js_name = getPaymentEndpoint)]
pub fn get_payment_endpoint_js(
    client: &PubkyClient,
    payee_pubky: &str,
    receiver_path_value: &str,
    identifier: &str,
) -> Result<js_sys::Promise, JsValue> {
    let payee = public_key_from_z32(payee_pubky, "payee")?;
    let path = receiver_path(receiver_path_value, "payment")?;
    let identifier = payment_endpoint_identifier(identifier)?;
    let storage = client.inner.public_storage();
    Ok(future_to_promise(async move {
        let payload = get_payment_endpoint(&storage, &payee, &path, &identifier)
            .await
            .map_err(|err| js_err("failed to fetch payment endpoint", err))?;
        Ok(payload.map_or(JsValue::UNDEFINED, |payload| {
            JsValue::from_str(payload.as_str())
        }))
    }))
}

/// Fetch a peer's public Payment List (identifier → payload).
///
/// Resolves to a plain object. A missing directory or empty list is `{}`
/// (list ops treat 404 as empty). Invalid UTF-8 or unparseable paths reject.
#[wasm_bindgen(js_name = getPaymentList)]
pub fn get_payment_list_js(
    client: &PubkyClient,
    payee_pubky: &str,
    receiver_path_value: &str,
) -> Result<js_sys::Promise, JsValue> {
    let payee = public_key_from_z32(payee_pubky, "payee")?;
    let path = receiver_path(receiver_path_value, "payment")?;
    let storage = client.inner.public_storage();
    Ok(future_to_promise(async move {
        let list = get_payment_list(&storage, &payee, &path)
            .await
            .map_err(|err| js_err("failed to fetch payment list", err))?;
        Ok(payment_list_to_js(&list).into())
    }))
}

/// List the Payment Endpoint Identifiers a peer has published publicly.
///
/// Same fetch as `getPaymentList`; resolves to a sorted string array.
/// A missing directory is `[]`.
#[wasm_bindgen(js_name = listPaymentMethods)]
pub fn list_payment_methods_js(
    client: &PubkyClient,
    payee_pubky: &str,
    receiver_path_value: &str,
) -> Result<js_sys::Promise, JsValue> {
    let payee = public_key_from_z32(payee_pubky, "payee")?;
    let path = receiver_path(receiver_path_value, "payment")?;
    let storage = client.inner.public_storage();
    Ok(future_to_promise(async move {
        let list = get_payment_list(&storage, &payee, &path)
            .await
            .map_err(|err| js_err("failed to list payment methods", err))?;
        let mut identifiers: Vec<_> = list
            .payment_endpoints
            .keys()
            .map(|identifier| identifier.as_str().to_string())
            .collect();
        identifiers.sort();
        let array = js_sys::Array::new();
        for identifier in identifiers {
            array.push(&JsValue::from_str(&identifier));
        }
        Ok(array.into())
    }))
}

/// List publicly advertised Paykit receiver paths for a Pubky identity.
///
/// Discovery helper only — payment flows should still use the exact
/// receiver path selected by the app. Resolves to a sorted string array;
/// a missing tree is `[]`.
#[wasm_bindgen(js_name = listPaykitReceiverPaths)]
pub fn list_paykit_receiver_paths_js(
    client: &PubkyClient,
    owner_pubky: &str,
) -> Result<js_sys::Promise, JsValue> {
    let owner = public_key_from_z32(owner_pubky, "owner")?;
    let storage = client.inner.public_storage();
    Ok(future_to_promise(async move {
        let paths = list_paykit_receiver_paths(&storage, &owner)
            .await
            .map_err(|err| js_err("failed to list Paykit receiver paths", err))?;
        let array = js_sys::Array::new();
        for path in paths {
            array.push(&JsValue::from_str(path.as_str()));
        }
        Ok(array.into())
    }))
}

/// Parse a versioned `paykit.private_payment_list` JSON message.
///
/// Returns `{ identifier: payload, ... }`. There is no homeserver GET for
/// private endpoints — they arrive as Encrypted Link messages. Rejects
/// invalid identifiers, unknown versions/kinds, or malformed JSON.
#[wasm_bindgen(js_name = parsePrivatePaymentListJson)]
pub fn parse_private_payment_list_json_js(json: &str) -> Result<js_sys::Object, JsValue> {
    let pairs = parse_private_list_to_pairs(json).map_err(|err| js_err_msg(&err))?;
    Ok(pairs_to_js(&pairs))
}

/// Serialize a complete Private Payment List to its versioned JSON wire form.
///
/// `endpoints` is a plain object `{ identifier: payload }`. The result is
/// the full latest-state message (`version` 1, kind
/// `paykit.private_payment_list`), not a patch. Do not log payloads.
#[wasm_bindgen(js_name = serializePrivatePaymentListJson)]
pub fn serialize_private_payment_list_json_js(
    endpoints: js_sys::Object,
) -> Result<String, JsValue> {
    serialize_private_list_pairs(js_to_pairs(&endpoints)?).map_err(|err| js_err_msg(&err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_from_str_accepts_public_method_names() {
        assert_eq!(
            identifier_from_str("btc-lightning-bolt11")
                .unwrap()
                .as_str(),
            "btc-lightning-bolt11"
        );
    }

    #[test]
    fn identifier_from_str_accepts_proto_key() {
        assert_eq!(
            identifier_from_str("__proto__").unwrap().as_str(),
            "__proto__"
        );
    }

    #[test]
    fn private_list_round_trip_preserves_proto_identifier() {
        let json = serialize_private_list_pairs([
            ("__proto__".into(), "ln-proto".into()),
            ("lightning".into(), "ln...".into()),
        ])
        .unwrap();
        let pairs = parse_private_list_to_pairs(&json).unwrap();
        assert_eq!(
            pairs,
            vec![
                ("__proto__".into(), "ln-proto".into()),
                ("lightning".into(), "ln...".into()),
            ]
        );
    }

    #[test]
    fn identifier_from_str_rejects_reserved_and_traversal() {
        for bad in ["", "private", "encrypted-link-recovery", "..", "foo/bar"] {
            let err = identifier_from_str(bad).unwrap_err();
            assert!(
                err.contains("invalid payment endpoint identifier"),
                "expected identifier error for '{bad}', got: {err}"
            );
            assert!(
                !err.contains("ln-"),
                "identifier error must not include a payload"
            );
        }
    }

    #[test]
    fn private_list_round_trip_preserves_endpoints() {
        let json = serialize_private_list_pairs([
            ("onchain".into(), "bc1qexample".into()),
            ("lightning".into(), "ln...".into()),
        ])
        .unwrap();
        let pairs = parse_private_list_to_pairs(&json).unwrap();
        assert_eq!(
            pairs,
            vec![
                ("lightning".into(), "ln...".into()),
                ("onchain".into(), "bc1qexample".into()),
            ]
        );
        assert!(json.contains("\"kind\":\"paykit.private_payment_list\""));
        assert!(json.contains("\"version\":1"));
    }

    #[test]
    fn private_list_empty_object_round_trips() {
        let json = serialize_private_list_pairs([]).unwrap();
        assert!(parse_private_list_to_pairs(&json).unwrap().is_empty());
    }

    #[test]
    fn parse_private_list_rejects_reserved_identifier() {
        let err = parse_private_list_to_pairs(
            r#"{"version":1,"kind":"paykit.private_payment_list","payment_endpoints":{"private":"secret"}}"#,
        )
        .unwrap_err();
        assert!(err.contains("failed to parse Private Payment List"));
        assert!(
            !err.contains("secret"),
            "parse error must not echo the payload"
        );
    }

    #[test]
    fn parse_private_list_rejects_unversioned_object() {
        let err = parse_private_list_to_pairs(r#"{"lightning":"ln..."}"#).unwrap_err();
        assert!(err.contains("failed to parse Private Payment List"));
    }
}
