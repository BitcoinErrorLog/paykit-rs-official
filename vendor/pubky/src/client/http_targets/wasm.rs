//! HTTP methods that support `https://` with Pkarr domains, including `_pubky.<pk>` URLs

use std::ops::ControlFlow;

use super::browser::{consider_browser_endpoint, rank_browser_endpoint, rewrite_url_for_browser};
use crate::PublicKey;
use crate::errors::{PkarrError, RequestError, Result};
use crate::{PubkyHttpClient, cross_log};
use futures_lite::StreamExt;
use pkarr::dns::rdata::SVCParam;
use pkarr::extra::endpoints::Endpoint;
use reqwest::{IntoUrl, Method, RequestBuilder};
use url::Url;

impl PubkyHttpClient {
    /// A wrapper around [`PubkyHttpClient::request`], with the same signature between native and WASM.
    pub(crate) async fn cross_request<T: IntoUrl>(
        &self,
        method: Method,
        url: T,
    ) -> Result<RequestBuilder> {
        let original_url = url.as_str();
        let mut url = Url::parse(original_url)?;

        let pubky_host = self.prepare_request(&mut url).await?;

        let builder = self
            .http
            .request(method, url.clone())
            .fetch_credentials_include();

        let builder = if let Some(pubky_host) = pubky_host {
            builder.header("pubky-host", pubky_host)
        } else {
            builder
        };

        Ok(builder)
    }

    /// - Resolves a clearnet host to call with fetch
    /// - Returns the `pubky-host` value if available
    ///
    /// # Errors
    /// - Returns [`crate::errors::PkarrError`] when PKARR resolution fails or produces invalid endpoints.
    pub async fn prepare_request(&self, url: &mut Url) -> Result<Option<String>> {
        let host = url.host_str().unwrap_or("").to_string();

        let mut pubky_host = None;

        if let Some(stripped) = host.strip_prefix("_pubky.") {
            if PublicKey::is_pubky_prefixed(stripped) {
                return Err(RequestError::Validation {
                    message: "pubky prefix is not allowed in transport hosts; use raw z32"
                        .to_string(),
                }
                .into());
            }
            if PublicKey::try_from_z32(stripped).is_ok() {
                self.transform_url(url).await?;
                pubky_host = Some(stripped.to_string());
            }
        } else {
            if PublicKey::is_pubky_prefixed(&host) {
                return Err(RequestError::Validation {
                    message: "pubky prefix is not allowed in transport hosts; use raw z32"
                        .to_string(),
                }
                .into());
            }
            if PublicKey::try_from_z32(&host).is_ok() {
                self.transform_url(url).await?;
                pubky_host = Some(host);
            }
        }

        Ok(pubky_host)
    }

    async fn transform_url(&self, url: &mut Url) -> Result<()> {
        let original_url = url.clone();
        let qname = original_url.host_str().unwrap_or("").to_string();
        cross_log!(debug, "Prepare WASM request {}", url.as_str());

        let stream = self.pkarr.resolve_https_endpoints(&qname);

        self.transform_url_with_stream(url, &qname, &original_url, stream)
            .await
    }

    async fn transform_url_with_stream<S>(
        &self,
        url: &mut Url,
        qname: &str,
        original_url: &Url,
        mut stream: S,
    ) -> Result<()>
    where
        S: futures_lite::Stream<Item = Endpoint> + Unpin,
    {
        let Some(endpoint) = Self::select_first_usable_endpoint(&mut stream).await else {
            cross_log!(error, "Could not resolve host {qname}");
            let host_display = if qname.is_empty() {
                "<empty host>".to_string()
            } else {
                qname.to_string()
            };
            return Err(PkarrError::InvalidRecord(format!(
                "No HTTPS endpoints found in PKARR record for `{host}` (original URL: {url})",
                host = host_display,
                url = original_url.as_str()
            ))
            .into());
        };

        // Do not await leftover stream items. pkarr's endpoint generator
        // parks at `yield` after the first usable record; the next `poll`
        // can `resolve()` another pubkey (fresh relay GETs) and races
        // reqwest's wasm AbortGuard on canceled sibling pkarr fetches
        // (`RuntimeError: unreachable`). Unused Endpoint values drop
        // synchronously here. That Drop is not the homeserver write —
        // write AbortGuard is owned by the later PUT/DELETE Response
        // and is still drained by `commit_issued_http_write`.
        drop(stream);

        self.apply_endpoint_to_url(url, &endpoint)?;

        cross_log!(debug, "Transformed URL to {}", url.as_str());

        Ok(())
    }

    async fn select_first_usable_endpoint<S>(stream: &mut S) -> Option<Endpoint>
    where
        S: futures_lite::Stream<Item = Endpoint> + Unpin,
    {
        let mut best = None;
        while let Some(endpoint) = stream.next().await {
            let rank = rank_browser_endpoint(endpoint.domain(), endpoint_has_http_port(&endpoint));
            if let ControlFlow::Break(endpoint) =
                consider_browser_endpoint(rank, endpoint, &mut best)
            {
                return Some(endpoint);
            }
        }

        best.map(|(_, endpoint)| endpoint)
    }

    fn apply_endpoint_to_url(&self, url: &mut Url, endpoint: &Endpoint) -> Result<()> {
        let domain = endpoint.domain().ok_or_else(|| {
            PkarrError::InvalidRecord(
                "WASM client cannot use a Pubky TLS endpoint (no ICANN/HTTP domain)".to_string(),
            )
        })?;
        rewrite_url_for_browser(url, domain, endpoint_http_port(endpoint), endpoint.port())
    }
}

fn endpoint_has_http_port(endpoint: &Endpoint) -> bool {
    endpoint
        .get_param(pubky_common::constants::reserved_param_keys::HTTP_PORT)
        .is_some()
}

fn endpoint_http_port(endpoint: &Endpoint) -> Option<u16> {
    endpoint
        .get_param(pubky_common::constants::reserved_param_keys::HTTP_PORT)
        .and_then(|param| match param {
            SVCParam::Unknown(_, bytes) => <[u8; 2]>::try_from(bytes.as_ref())
                .ok()
                .map(u16::from_be_bytes),
            SVCParam::Port(port) => Some(*port),
            _ => None,
        })
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::Keypair;
    use futures_lite::stream;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test(async)]
    async fn transform_url_errors_when_no_domain_is_found() {
        let client = PubkyHttpClient::new().unwrap();
        let pk = Keypair::random().public_key().z32();
        let mut url = Url::parse(&format!("https://_pubky.{pk}/pub/app/file.txt")).unwrap();
        let original = url.clone();

        let result = client
            .transform_url_with_stream(
                &mut url,
                url.host_str().unwrap(),
                &original,
                stream::empty(),
            )
            .await;

        let err = result.expect_err("transform_url should fail when no endpoint is resolved");

        let crate::errors::Error::Pkarr(PkarrError::InvalidRecord(message)) = err else {
            panic!("expected pkarr invalid record error, got {err:?}");
        };

        assert!(message.contains("No HTTPS endpoints found"));
    }

    #[wasm_bindgen_test(async)]
    async fn select_first_usable_endpoint_is_none_for_empty_stream() {
        let mut empty = stream::empty();

        let result = PubkyHttpClient::select_first_usable_endpoint(&mut empty).await;

        assert!(result.is_none());
    }
}
