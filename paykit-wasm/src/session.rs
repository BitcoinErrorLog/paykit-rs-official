use std::cell::RefCell;
use std::rc::Rc;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use pubky::errors::{AuthError, RequestError};
use pubky::{AuthFlowKind, Capabilities, Pubky, PubkySession};
use pubky_common::capabilities::{Action, Capability};
use pubky_common::session::SessionInfo;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::{js_err, js_err_msg, js_err_named};
use crate::keys::{public_key_from_z32, public_key_from_z32_or_hex, secret_key_from_slice};

/// The Paykit storage tree cookie-resume requires in the session scope.
const PAYKIT_SCOPE: &str = "/pub/paykit/";

/// `Error.name` when the homeserver did not accept the browser's cookie for
/// the requested pubky (no cookie, expired, revoked, or 401/403). A cookie
/// belonging to a DIFFERENT account also lands here: the homeserver simply
/// finds no session for the requested pubky and cannot attribute the failure.
pub(crate) const RESUME_ERR_UNAUTHORIZED: &str = "SessionResumeUnauthorized";
/// `Error.name` when a session validated but belongs to a different pubky
/// than requested (defensive; the request is routed by pubky, so this should
/// not occur against a conforming homeserver).
pub(crate) const RESUME_ERR_PUBKY_MISMATCH: &str = "SessionResumePubkyMismatch";
/// `Error.name` when the session is valid but its capabilities do not cover
/// `/pub/paykit/` with read+write (a sign-in that predates the combined
/// grant).
pub(crate) const RESUME_ERR_SCOPE_MISSING: &str = "SessionResumeScopeMissing";

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

    /// Resume a homeserver session purely from the browser's EXISTING
    /// HTTP-only session cookie for `pubky` — no exported metadata and no new
    /// signer approval. This is the zero-approval path for apps whose sign-in
    /// grant already covers the Paykit tree (`/pub/paykit/:rw`): the cookie
    /// set at sign-in is the credential; this call only rebuilds the wasm-side
    /// handle around it.
    ///
    /// How it works: the same `/session` revalidation round-trip
    /// `restoreSession` performs (the browser attaches the cookie via
    /// `credentials: include`), seeded with a synthesized placeholder for the
    /// requested pubky instead of a previously exported string. The
    /// homeserver's response supplies the authoritative `SessionInfo`
    /// (pubky, capabilities), which is verified before a handle is returned.
    ///
    /// Resolves to a `SessionHandle` identical to what `restoreSession` would
    /// produce (including `exportSession()` support). Rejects with a typed
    /// error the caller can branch on via `Error.name`:
    ///
    /// - `"SessionResumeUnauthorized"` — the homeserver holds no valid session
    ///   for this pubky behind the browser's cookies (missing/expired/revoked
    ///   cookie, or a cookie for another account).
    /// - `"SessionResumePubkyMismatch"` — a session validated but belongs to a
    ///   different pubky than requested.
    /// - `"SessionResumeScopeMissing"` — the session is valid but its scope
    ///   does not grant `/pub/paykit/` read+write (a legacy sign-in that
    ///   predates the combined grant); an interactive approval is required.
    ///
    /// Transport failures reject with the plain `cookie resume failed: ...`
    /// shape (retryable; says nothing about the cookie).
    #[wasm_bindgen(js_name = resumeSessionFromCookie)]
    pub fn resume_session_from_cookie(&self, pubky: &str) -> Result<js_sys::Promise, JsValue> {
        let public_key = public_key_from_z32(pubky, "pubky")?;
        let client = self.inner.client().clone();
        Ok(future_to_promise(async move {
            let expected = public_key.z32();
            // The synthesized export carries no secrets and no claimed
            // capabilities — exactly the shape `exportSession()` encodes —
            // and `PubkySession::import` replaces it wholesale with the
            // homeserver's authoritative SessionInfo after revalidating
            // through the cookie.
            let placeholder = SessionInfo::new(&public_key, Capabilities::default(), None);
            let export = BASE64_STANDARD.encode(placeholder.serialize());
            let session = PubkySession::import(&export, Some(client))
                .await
                .map_err(map_cookie_resume_error)?;
            let actual = session.info().public_key().z32();
            if actual != expected {
                return Err(js_err_named(
                    RESUME_ERR_PUBKY_MISMATCH,
                    "cookie resume failed",
                    format!("session belongs to {actual}, expected {expected}"),
                ));
            }
            if !capabilities_cover_paykit(session.info().capabilities()) {
                return Err(js_err_named(
                    RESUME_ERR_SCOPE_MISSING,
                    "cookie resume failed",
                    format!("session scope does not grant {PAYKIT_SCOPE} read+write"),
                ));
            }
            Ok(SessionHandle { inner: session }.into())
        }))
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

    /// Move an existing identity to `homeserverZ32` and republish `_pubky`.
    ///
    /// Dev/test helper. Signs up on that host, or signs in there if the user
    /// already exists (HTTP 409). Host-local data is not copied.
    #[wasm_bindgen(js_name = migrateHomeserverWithSecret)]
    pub fn migrate_homeserver_with_secret(
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
                .migrate_homeserver(&homeserver, signup_token.as_deref())
                .await
                .map_err(|err| js_err("homeserver migration failed", err))?;
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

    /// Authenticated PUT of `body` at an absolute homeserver path (e.g.
    /// `/pub/hypercolor.app/v1/…`). The browser attaches the HTTP-only
    /// session cookie; this is not a Cookie-header constructor and must
    /// never be fed `exportSession()` as a bearer.
    #[wasm_bindgen(js_name = putPublic)]
    pub fn put_public(&self, path: &str, body: &[u8]) -> js_sys::Promise {
        let session = self.inner.clone();
        let path = path.to_string();
        let body = body.to_vec();
        future_to_promise(async move {
            session
                .storage()
                .put(path, body)
                .await
                .map_err(|err| js_err("put failed", err))?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Authenticated DELETE of an absolute homeserver path. Cookie-authorized
    /// the same way as `putPublic`.
    #[wasm_bindgen(js_name = deletePublic)]
    pub fn delete_public(&self, path: &str) -> js_sys::Promise {
        let session = self.inner.clone();
        let path = path.to_string();
        future_to_promise(async move {
            session
                .storage()
                .delete(path)
                .await
                .map_err(|err| js_err("delete failed", err))?;
            Ok(JsValue::UNDEFINED)
        })
    }
}

/// Unauthenticated public GET of `{ownerPubky}{path}`.
///
/// `ownerPubky` accepts z-base-32 or 64-hex. A homeserver 404 or 410
/// resolves to `undefined`; other failures reject. Used to fetch a
/// paykit-connect SB2 handoff from `/pub/`.
#[wasm_bindgen(js_name = publicGet)]
pub fn public_get(
    client: &PubkyClient,
    owner_pubky: &str,
    path: &str,
) -> Result<js_sys::Promise, JsValue> {
    let owner = public_key_from_z32_or_hex(owner_pubky, "owner")?;
    let path = path.to_string();
    let storage = client.inner.public_storage();
    Ok(future_to_promise(async move {
        match storage.get((owner, path)).await {
            Ok(resp) => {
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|err| js_err("public get failed", err))?;
                Ok(js_sys::Uint8Array::from(bytes.as_ref()).into())
            }
            Err(err) if is_absent(&err) => Ok(JsValue::UNDEFINED),
            Err(err) => Err(js_err("public get failed", err)),
        }
    }))
}

/// Sign out and invalidate the homeserver session (cookie) server-side.
/// Consumes the `SessionHandle`.
#[wasm_bindgen(js_name = signOutSession)]
pub fn sign_out_session(session: SessionHandle) -> js_sys::Promise {
    let inner = session.inner;
    future_to_promise(async move {
        inner
            .signout()
            .await
            .map_err(|(err, _restored)| js_err("signout failed", err))?;
        Ok(JsValue::UNDEFINED)
    })
}

/// Classify a failed cookie-resume revalidation. `AuthError::RequestExpired`
/// is `PubkySession::import`'s "the homeserver answered but holds no session
/// behind these cookies" signal (404 on `/session`); 401/403 statuses carry
/// the same meaning from stricter servers. Everything else (transport,
/// unexpected server errors) stays untyped so callers treat it as retryable.
fn is_absent(err: &pubky::Error) -> bool {
    matches!(
        err,
        pubky::Error::Request(RequestError::Server { status, .. })
            if status.as_u16() == 404 || status.as_u16() == 410
    )
}

fn map_cookie_resume_error(err: pubky::Error) -> JsValue {
    match &err {
        pubky::Error::Authentication(AuthError::RequestExpired) => {
            js_err_named(RESUME_ERR_UNAUTHORIZED, "cookie resume failed", err)
        }
        pubky::Error::Request(RequestError::Server { status, .. })
            if status.as_u16() == 401 || status.as_u16() == 403 =>
        {
            js_err_named(RESUME_ERR_UNAUTHORIZED, "cookie resume failed", err)
        }
        _ => js_err("cookie resume failed", err),
    }
}

/// True when one capability grants read+write over the `/pub/paykit/` tree.
/// Scope semantics mirror the homeserver's (`pubky_common`): a scope covers
/// the tree when it is the tree itself or a directory prefix of it
/// (`/pub/paykit/`, `/pub/`, `/`); a non-directory scope covers only itself.
fn capabilities_cover_paykit(capabilities: &[Capability]) -> bool {
    capabilities.iter().any(|capability| {
        scope_covers(&capability.scope, PAYKIT_SCOPE)
            && capability.actions.contains(&Action::Read)
            && capability.actions.contains(&Action::Write)
    })
}

fn scope_covers(scope: &str, target: &str) -> bool {
    scope == target || (scope.ends_with('/') && target.starts_with(scope))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky::PublicKey;

    fn caps(spec: &str) -> Vec<Capability> {
        let parsed: Capabilities = spec.try_into().expect("valid capability spec");
        parsed.as_slice().to_vec()
    }

    #[test]
    fn paykit_scope_satisfied_by_the_deployed_combined_grant() {
        assert!(capabilities_cover_paykit(&caps(
            "/pub/pubky.app/:rw,/pub/paykit/:rw,/priv/pubky.app/:rw"
        )));
    }

    #[test]
    fn paykit_scope_satisfied_by_exact_and_parent_directory_grants() {
        assert!(capabilities_cover_paykit(&caps("/pub/paykit/:rw")));
        assert!(capabilities_cover_paykit(&caps("/pub/:rw")));
        assert!(capabilities_cover_paykit(&caps("/:rw")));
        assert!(capabilities_cover_paykit(&caps(
            "/pub/paykit/subdir-irrelevant.txt:r,/pub/paykit/:rw"
        )));
    }

    #[test]
    fn paykit_scope_missing_for_legacy_grants_without_paykit() {
        assert!(!capabilities_cover_paykit(&caps("/pub/pubky.app/:rw")));
        assert!(!capabilities_cover_paykit(&caps(
            "/pub/pubky.app/:rw,/priv/pubky.app/:rw"
        )));
        assert!(!capabilities_cover_paykit(&[]));
    }

    #[test]
    fn paykit_scope_requires_both_read_and_write() {
        assert!(!capabilities_cover_paykit(&caps("/pub/paykit/:r")));
        assert!(!capabilities_cover_paykit(&caps("/pub/paykit/:w")));
        // Read and write granted by DIFFERENT scopes is not one rw grant on
        // the tree; the homeserver evaluates capabilities individually.
        assert!(!capabilities_cover_paykit(&caps("/pub/paykit/:r,/pub/:w")));
    }

    #[test]
    fn paykit_scope_not_covered_by_non_directory_or_sibling_scopes() {
        // "/pub/paykit" (no trailing slash) names a file, not the tree.
        assert!(!capabilities_cover_paykit(&caps("/pub/paykit:rw")));
        assert!(!capabilities_cover_paykit(&caps("/pub/paykit-other/:rw")));
        assert!(!capabilities_cover_paykit(&caps("/pub/paykit/inbox/:rw")));
    }

    #[test]
    fn synthesized_resume_export_round_trips_like_export_session() {
        // The cookie-resume placeholder must stay wire-compatible with what
        // `SessionHandle.exportSession()` encodes: base64(SessionInfo). A
        // round-trip through the same deserializer `restoreSession` uses
        // proves the synthesized bytes are a valid import payload.
        let public_key =
            PublicKey::try_from_z32("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo")
                .expect("valid z32 key");
        let placeholder = SessionInfo::new(&public_key, Capabilities::default(), None);
        let export = BASE64_STANDARD.encode(placeholder.serialize());
        let decoded =
            SessionInfo::deserialize(&BASE64_STANDARD.decode(&export).expect("valid base64"))
                .expect("valid SessionInfo bytes");
        assert_eq!(decoded.public_key(), &public_key);
        assert!(decoded.capabilities().is_empty());
    }

    #[test]
    fn is_absent_matches_not_found_and_gone() {
        use pubky::StatusCode;
        let not_found = pubky::Error::Request(RequestError::Server {
            status: StatusCode::NOT_FOUND,
            message: "gone".into(),
        });
        let gone = pubky::Error::Request(RequestError::Server {
            status: StatusCode::GONE,
            message: "gone".into(),
        });
        let forbidden = pubky::Error::Request(RequestError::Server {
            status: StatusCode::FORBIDDEN,
            message: "no".into(),
        });
        assert!(is_absent(&not_found));
        assert!(is_absent(&gone));
        assert!(!is_absent(&forbidden));
    }
}
