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

/// A JS `Error` whose `name` is a stable machine-readable code the client can
/// branch on (`err.name === "..."`), with the same `context: detail` message
/// shape as `js_err`.
pub(crate) fn js_err_named(name: &str, context: &str, detail: impl std::fmt::Display) -> JsValue {
    let err = js_sys::Error::new(&format!("{context}: {detail}"));
    err.set_name(name);
    err.into()
}
