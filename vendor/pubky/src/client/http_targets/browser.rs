//! Browser-reachable homeserver endpoint selection.
//!
//! A WASM / browser client cannot speak Pubky TLS. Homeservers advertise two
//! HTTPS SVCB records: a high-priority Pubky-TLS endpoint (target `.`, custom
//! port) and a lower-priority ICANN/HTTP endpoint (domain + optional
//! `HTTP_PORT`). Selection must prefer the record a browser can actually fetch.

use url::Url;

use crate::errors::Result;

/// Preference for a resolved homeserver endpoint in a browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BrowserEndpointRank {
    /// Target `.` or a z32 pubkey — Pubky TLS. Unusable in a browser.
    Unreachable = 0,
    /// ICANN (or localhost) HTTPS the browser can do with ordinary TLS.
    IcannHttps = 1,
    /// Explicit `HTTP_PORT` SVCB param: the homeserver's browser/HTTP advertisement.
    BrowserHttp = 2,
}

/// Rank an endpoint from the values a browser can inspect.
#[must_use]
pub(crate) const fn rank_browser_endpoint(
    domain: Option<&str>,
    has_http_port: bool,
) -> BrowserEndpointRank {
    if domain.is_none() {
        return BrowserEndpointRank::Unreachable;
    }
    if has_http_port {
        return BrowserEndpointRank::BrowserHttp;
    }
    BrowserEndpointRank::IcannHttps
}

/// Rewrite `url` to the ICANN/HTTP target a browser can fetch.
pub(crate) fn rewrite_url_for_browser(
    url: &mut Url,
    domain: &str,
    http_port: Option<u16>,
    https_port: Option<u16>,
) -> Result<()> {
    if let Some(port) = http_port {
        url.set_scheme("http")
            .map_err(|_err| url::ParseError::RelativeUrlWithCannotBeABaseBase)?;
        url.set_port(Some(port))
            .map_err(|_err| url::ParseError::InvalidPort)?;
    } else if let Some(port) = https_port {
        url.set_port(Some(port))
            .map_err(|_err| url::ParseError::InvalidPort)?;
    }

    url.set_host(Some(domain))
        .map_err(|_err| url::ParseError::SetHostOnCannotBeABaseUrl)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubky_tls_target_is_unreachable() {
        assert_eq!(
            rank_browser_endpoint(None, false),
            BrowserEndpointRank::Unreachable
        );
        assert_eq!(
            rank_browser_endpoint(None, true),
            BrowserEndpointRank::Unreachable
        );
    }

    #[test]
    fn icann_https_ranks_above_pubky_tls() {
        assert!(
            rank_browser_endpoint(Some("homeserver.staging.pubky.app"), false)
                > rank_browser_endpoint(None, false)
        );
    }

    #[test]
    fn http_port_wins_over_icann_https_on_any_host() {
        assert!(
            rank_browser_endpoint(Some("localhost"), true)
                > rank_browser_endpoint(Some("localhost"), false)
        );
        assert!(
            rank_browser_endpoint(Some("127.0.0.1"), true)
                > rank_browser_endpoint(Some("homeserver.example"), false)
        );
        assert_eq!(
            rank_browser_endpoint(Some("mail.example"), true),
            BrowserEndpointRank::BrowserHttp
        );
    }

    #[test]
    fn rewrite_http_port_uses_http_for_any_host() {
        let mut url =
            Url::parse("https://8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo/signup")
                .unwrap();
        rewrite_url_for_browser(&mut url, "127.0.0.1", Some(6286), Some(6287)).unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:6286/signup");
    }

    #[test]
    fn rewrite_without_http_port_keeps_https() {
        let mut url =
            Url::parse("https://8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo/session")
                .unwrap();
        rewrite_url_for_browser(&mut url, "homeserver.staging.pubky.app", None, None).unwrap();
        assert_eq!(url.as_str(), "https://homeserver.staging.pubky.app/session");
    }
}
