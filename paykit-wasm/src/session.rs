use std::cell::RefCell;
use std::rc::Rc;

use pubky::{AuthFlowKind, Capabilities, Pubky, PubkySession};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::{js_err, js_err_msg};
use crate::keys::{public_key_from_z32, secret_key_from_slice};

/// Pubky client facade. Construct once and reuse.
#[wasm_bindgen]
pub struct PubkyClient {
    pub(crate) inner: Pubky,
}

#[wasm_bindgen]
impl PubkyClient {
    /// Construct with mainnet defaults.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<PubkyClient, JsValue> {
        Ok(Self {
            inner: Pubky::new().map_err(|err| js_err("failed to construct Pubky client", err))?,
        })
    }

    /// Construct preconfigured for a local Pubky testnet.
    pub fn testnet() -> Result<PubkyClient, JsValue> {
        Ok(Self {
            inner: Pubky::testnet()
                .map_err(|err| js_err("failed to construct testnet Pubky client", err))?,
        })
    }

    /// Start a pubkyauth sign-in flow for the given capabilities
    /// (e.g. `"/pub/paykit/:rw"`). Present `authorizationUrl()` to the
    /// signer (Pubky Ring), then `awaitApproval()`.
    ///
    /// This is the production path for obtaining a homeserver session in the
    /// browser: the identity secret key never enters this runtime.
    #[wasm_bindgen(js_name = startAuthFlow)]
    pub fn start_auth_flow(&self, capabilities: &str) -> Result<AuthFlowHandle, JsValue> {
        let caps: Capabilities = capabilities
            .try_into()
            .map_err(|err| js_err("invalid capabilities", err))?;
        let flow = self
            .inner
            .start_auth_flow(&caps, AuthFlowKind::signin())
            .map_err(|err| js_err("failed to start auth flow", err))?;
        Ok(AuthFlowHandle {
            url: flow.authorization_url().to_string(),
            inner: Rc::new(RefCell::new(Some(flow))),
        })
    }

    /// Sign in with a raw identity secret key. Dev/test helper only — in
    /// production browser deployments the identity key must stay in the
    /// signer (use `startAuthFlow` instead).
    #[wasm_bindgen(js_name = signinWithSecret)]
    pub fn signin_with_secret(
        &self,
        identity_secret_key: &[u8],
    ) -> Result<js_sys::Promise, JsValue> {
        let secret = secret_key_from_slice(identity_secret_key)?;
        let signer = self.inner.signer(pubky::Keypair::from_secret(&secret));
        Ok(future_to_promise(async move {
            let session = signer
                .signin()
                .await
                .map_err(|err| js_err("signin failed", err))?;
            Ok(SessionHandle { inner: session }.into())
        }))
    }

    /// Restore a homeserver session from metadata previously produced by
    /// `SessionHandle.exportSession()`, without a new signer approval.
    ///
    /// The export string carries no secrets; the actual credential is the
    /// HTTP-only session cookie in the browser's cookie jar (set by the
    /// homeserver, sent via `credentials: include`). Restoring performs a
    /// `/session` round-trip to revalidate; it rejects if the export is
    /// malformed or the cookie is missing, expired, or revoked. Resolves to
    /// a `SessionHandle`.
    #[wasm_bindgen(js_name = restoreSession)]
    pub fn restore_session(&self, exported_session: String) -> js_sys::Promise {
        let client = self.inner.client().clone();
        future_to_promise(async move {
            let session = PubkySession::import(&exported_session, Some(client))
                .await
                .map_err(|err| js_err("session restore failed", err))?;
            Ok(SessionHandle { inner: session }.into())
        })
    }

    /// Sign up a new account on a homeserver with a raw identity secret key.
    /// Dev/test helper only (used against ephemeral testnets).
    #[wasm_bindgen(js_name = signupWithSecret)]
    pub fn signup_with_secret(
        &self,
        identity_secret_key: &[u8],
        homeserver_z32: &str,
        signup_token: Option<String>,
    ) -> Result<js_sys::Promise, JsValue> {
        let secret = secret_key_from_slice(identity_secret_key)?;
        let homeserver = public_key_from_z32(homeserver_z32, "homeserver")?;
        let signer = self.inner.signer(pubky::Keypair::from_secret(&secret));
        Ok(future_to_promise(async move {
            let session = signer
                .signup(&homeserver, signup_token.as_deref())
                .await
                .map_err(|err| js_err("signup failed", err))?;
            Ok(SessionHandle { inner: session }.into())
        }))
    }
}

/// An in-progress pubkyauth flow.
#[wasm_bindgen]
pub struct AuthFlowHandle {
    url: String,
    inner: Rc<RefCell<Option<pubky::PubkyAuthFlow>>>,
}

#[wasm_bindgen]
impl AuthFlowHandle {
    /// The `pubkyauth:` URL to present to the signer (QR code / deep link).
    #[wasm_bindgen(js_name = authorizationUrl)]
    pub fn authorization_url(&self) -> String {
        self.url.clone()
    }

    /// Wait until the signer approves and resolve to a `SessionHandle`.
    /// Consumes the flow; subsequent calls reject.
    #[wasm_bindgen(js_name = awaitApproval)]
    pub fn await_approval(&self) -> js_sys::Promise {
        let cell = self.inner.clone();
        future_to_promise(async move {
            let flow = cell
                .borrow_mut()
                .take()
                .ok_or_else(|| js_err_msg("auth flow already consumed"))?;
            let session = flow
                .await_approval()
                .await
                .map_err(|err| js_err("auth flow failed", err))?;
            Ok(SessionHandle { inner: session }.into())
        })
    }
}

/// An authenticated homeserver session for one Pubky identity.
#[wasm_bindgen]
pub struct SessionHandle {
    pub(crate) inner: PubkySession,
}

#[wasm_bindgen]
impl SessionHandle {
    /// The session owner's public key (z-base-32).
    pub fn pubky(&self) -> String {
        self.inner.info().public_key().z32()
    }

    /// Export session metadata for rehydrating via
    /// `PubkyClient.restoreSession()` after a page reload.
    ///
    /// The returned string contains **no secrets** — it is a base64 encoding
    /// of the public `SessionInfo` (pubky, capabilities). The credential
    /// itself is the HTTP-only session cookie the browser holds; the export
    /// only lets a new runtime reconstruct the session handle and revalidate
    /// against the homeserver through that cookie.
    #[wasm_bindgen(js_name = exportSession)]
    pub fn export_session(&self) -> String {
        self.inner.export()
    }
}
