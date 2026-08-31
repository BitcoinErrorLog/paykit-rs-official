//! Browser-reachable homeserver endpoint selection.
//!
//! A WASM / browser client cannot speak Pubky TLS. Homeservers advertise two
//! HTTPS SVCB records: a high-priority Pubky-TLS endpoint (target `.`, custom
//! port) and a lower-priority ICANN/HTTP endpoint (domain + optional
//! `HTTP_PORT`). Selection must prefer the record a browser can actually fetch.

use std::ops::ControlFlow;

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

/// Fold one ranked candidate into the running choice.
///
/// `BrowserHttp` wins immediately so later records are not required.
/// `Unreachable` is skipped. `IcannHttps` is kept as a fallback.
pub(crate) fn consider_browser_endpoint<T>(
    rank: BrowserEndpointRank,
    item: T,
    best: &mut Option<(BrowserEndpointRank, T)>,
) -> ControlFlow<T> {
    match rank {
        BrowserEndpointRank::Unreachable => ControlFlow::Continue(()),
        BrowserEndpointRank::BrowserHttp => ControlFlow::Break(item),
        BrowserEndpointRank::IcannHttps => {
            if best.as_ref().is_none_or(|(best_rank, _)| rank > *best_rank) {
                *best = Some((rank, item));
            }
            ControlFlow::Continue(())
        }
    }
}

/// Choose the best browser-reachable candidate from an iterator of ranks.
///
/// Used by the WASM endpoint stream and by native tests of that policy.
/// Remaining items after a `BrowserHttp` win are not visited.
#[must_use]
pub(crate) fn select_best_browser_endpoint<I, T>(items: I) -> Option<T>
where
    I: IntoIterator<Item = (BrowserEndpointRank, T)>,
{
    let mut best = None;
    for (rank, item) in items {
        if let ControlFlow::Break(item) = consider_browser_endpoint(rank, item, &mut best) {
            return Some(item);
        }
    }
    best.map(|(_, item)| item)
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

    #[test]
    fn select_skips_unreachable_and_keeps_icann_https() {
        let chosen = select_best_browser_endpoint([
            (BrowserEndpointRank::Unreachable, "tls"),
            (BrowserEndpointRank::IcannHttps, "https"),
        ]);
        assert_eq!(chosen, Some("https"));
    }

    #[test]
    fn select_browser_http_wins_immediately() {
        let chosen = select_best_browser_endpoint([
            (BrowserEndpointRank::IcannHttps, "https"),
            (BrowserEndpointRank::BrowserHttp, "http"),
            (BrowserEndpointRank::IcannHttps, "later"),
        ]);
        assert_eq!(chosen, Some("http"));
    }

    #[test]
    fn select_browser_http_does_not_visit_later_records() {
        let mut visited = 0;
        let chosen = select_best_browser_endpoint(
            [
                (BrowserEndpointRank::BrowserHttp, "http"),
                (BrowserEndpointRank::IcannHttps, "must-not-visit"),
            ]
            .into_iter()
            .inspect(|_| visited += 1),
        );
        assert_eq!(chosen, Some("http"));
        assert_eq!(visited, 1);
    }

    #[test]
    fn select_empty_is_none() {
        let chosen = select_best_browser_endpoint::<_, &str>([]);
        assert_eq!(chosen, None);
    }
}
