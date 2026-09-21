#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) mod browser;
#[cfg(not(target_arch = "wasm32"))]
pub mod native;
#[cfg(target_arch = "wasm32")]
pub mod wasm;
