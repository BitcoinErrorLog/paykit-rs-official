use wasm_bindgen::JsValue;

/// Convert any displayable error into a JS `Error` with a stable
/// `context: detail` message shape.
pub(crate) fn js_err(context: &str, err: impl std::fmt::Display) -> JsValue {
    js_sys::Error::new(&format!("{context}: {err}")).into()
}

/// A plain JS `Error` with a static message.
pub(crate) fn js_err_msg(message: &str) -> JsValue {
    js_sys::Error::new(message).into()
}
