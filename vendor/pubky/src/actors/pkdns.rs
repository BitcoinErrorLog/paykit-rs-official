//! PKDNS (Pkarr) top-level actor: resolve & publish `_pubky` records.
//!
//! - **Read-only (no keys):** `Pkdns::new()`
//! - **Publish (with keys):** `Pkdns::new_with_keypair(..)` or `signer.pkdns()`
//!
//! Reads do not require a session or keys. Publishing requires a `Keypair`.

use std::time::Duration;

use pkarr::{
    SignedPacket, Timestamp,
    dns::rdata::{RData, SVCB},
};

use crate::{
    Keypair, PubkyHttpClient, PubkySigner, PublicKey, cross_log,
    errors::{AuthError, Error, PkarrError, Result},
};

/// Default staleness window for homeserver `_pubky` Pkarr records (1 hour).
///
/// Used by [`crate::Pkdns::publish_homeserver_if_stale`] to decide when a record
/// should be republished. Republish too often and you add DHT churn; too rarely
/// and lookups may not be able to find the user's homeserver.
///
/// You can override this per instance via [`crate::Pkdns::set_stale_after`] (mutable setter).
pub const DEFAULT_STALE_AFTER: Duration = Duration::from_secs(60 * 60);

/// PKDNS actor: resolve & publish `_pubky` PKARR records.
///
/// Construct it **without** a keypair for read-only queries:
/// ```no_run
/// # async fn example() -> pubky::Result<()> {
/// let pkdns = pubky::Pkdns::new()?;
/// if let Some(host) = pkdns.get_homeserver_of(&"o4dk…uyy".try_into().unwrap()).await {
///     println!("homeserver: {host}");
/// }
/// # Ok(()) }
/// ```
///
/// Or **with** a keypair for publishing and self lookups:
/// ```no_run
/// # async fn example(kp: pubky::Keypair) -> pubky::Result<()> {
/// let pkdns = pubky::Pkdns::new_with_keypair(kp)?;
/// // Self-lookup (requires keypair on this Pkdns)
/// let my_host = pkdns.get_homeserver().await?;
/// println!("my homeserver: {my_host:?}");
///
/// // Publish if stale
/// pkdns.publish_homeserver_if_stale(None).await?;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct Pkdns {
    client: PubkyHttpClient,
    keypair: Option<Keypair>,
    /// Maximum age before a user record should be republished.
    /// Defaults to 1 hour.
    stale_after: Duration,
}

impl PubkySigner {
    /// Get a PKDNS actor bound to this signer's client and keypair (publishing enabled).
    #[inline]
    #[must_use]
    pub fn pkdns(&self) -> Pkdns {
        crate::Pkdns::with_client_and_keypair(self.client.clone(), self.keypair.clone())
    }
}

impl Pkdns {
    /// Construct a read-only PKDNS actor.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error`] if the underlying [`PubkyHttpClient`] cannot be created.
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: PubkyHttpClient::new()?,
            keypair: None,
            stale_after: DEFAULT_STALE_AFTER,
        })
    }

    /// Construct a publishing-capable PKDNS actor.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error`] if the underlying [`PubkyHttpClient`] cannot be created.
    pub fn new_with_keypair(keypair: Keypair) -> Result<Self> {
        Ok(Self {
            client: PubkyHttpClient::new()?,
            keypair: Some(keypair),
            stale_after: DEFAULT_STALE_AFTER,
        })
    }

    /// Infallible constructor with client + keypair (publishing enabled).
    /// Used internally for `signer.pkdns()`
    const fn with_client_and_keypair(client: PubkyHttpClient, keypair: Keypair) -> Self {
        Self {
            client,
            keypair: Some(keypair),
            stale_after: DEFAULT_STALE_AFTER,
        }
    }

    /// Create a read-only PKDNS actor bound to a specific client.
    /// No keypair attached; publishing is disabled.
    pub(crate) const fn with_client(client: PubkyHttpClient) -> Self {
        Self {
            client,
            keypair: None,
            stale_after: DEFAULT_STALE_AFTER,
        }
    }

    /// Set how long an existing `_pubky` PKARR record is considered **fresh** (builder-style).
    ///
    /// If the current record’s age is **≤ this duration**, [`Self::publish_homeserver_if_stale`]
    /// is a no-op; otherwise the record is (re)published.
    ///
    /// Defaults to 1 hour [`DEFAULT_STALE_AFTER`].
    ///
    /// # Examples
    /// ```no_run
    /// # use std::time::Duration;
    /// # async fn ex(signer: pubky::PubkySigner) -> pubky::Result<()> {
    /// let pkdns = signer.pkdns()
    ///     .set_stale_after(Duration::from_secs(30 * 60)); // 30 minutes
    ///
    /// // Will re-publish same homeserver only if the existing record is older than 30 minutes.
    /// pkdns.publish_homeserver_if_stale(None).await?;
    /// # Ok(()) }
    /// ```
    #[must_use]
    pub const fn set_stale_after(mut self, d: Duration) -> Self {
        self.stale_after = d;
        self
    }

    // -------------------- Reads --------------------

    /// Resolve current homeserver host for a user public key via Pkarr (no keypair required).
    ///
    /// Returns the `_pubky` SVCB/HTTPS target (domain or pubkey-as-host),
    /// or `None` if the record is missing/unresolvable.
    pub async fn get_homeserver_of(&self, user_public_key: &PublicKey) -> Option<PublicKey> {
        cross_log!(
            info,
            "Resolving homeserver for public key {} via PKARR",
            user_public_key
        );
        let packet = self.client.pkarr().resolve(user_public_key).await?;
        let s = extract_host_from_packet(&packet)?;
        let result = PublicKey::try_from_z32(&s).ok();
        cross_log!(
            debug,
            "Homeserver resolution for {} yielded {:?}",
            user_public_key,
            result
        );
        result
    }

    /// Convenience: resolve the homeserver for **this** user (requires keypair on `Pkdns`).
    ///
    /// Returns:
    /// - `Ok(Some(host))` if resolvable,
    /// - `Ok(None)` if no record is found,
    /// - `Err(_)` only for transport errors.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Authentication`] if called without an attached keypair.
    /// - Propagates transport failures from PKARR resolution.
    pub async fn get_homeserver(&self) -> Result<Option<PublicKey>> {
        let kp = self.keypair.as_ref().ok_or_else(|| {
            Error::from(AuthError::Validation(
                "get_homeserver() requires a keypair; use Pkdns::new_with_keypair() or signer.pkdns()".into(),
            ))
        })?;
        Ok(self.get_homeserver_of(&kp.public_key()).await)
    }

    // -------------------- Publishing (requires keypair) --------------------

    /// Publish `_pubky` **forcing** a refresh.
    ///
    /// If `host_override` is `None`, reuses the host found in the existing record (if any).
    ///
    /// # Errors
    /// - [`crate::errors::Error::Authentication`] if called without a keypair or validation fails.
    /// - [`crate::errors::Error::Pkarr`] if PKARR/DHT resolution or publish fails.
    pub async fn publish_homeserver_force(&self, host_override: Option<&PublicKey>) -> Result<()> {
        self.publish_homeserver(host_override, PublishMode::Force)
            .await
    }

    /// Publish `_pubky` **only if stale/missing**.
    ///
    /// If `host_override` is `None`, reuses the host found in the existing record (if any).
    ///
    /// # Errors
    /// - [`crate::errors::Error::Authentication`] if called without a keypair or validation fails.
    /// - [`crate::errors::Error::Pkarr`] if PKARR/DHT resolution or publish fails.
    pub async fn publish_homeserver_if_stale(
        &self,
        host_override: Option<&PublicKey>,
    ) -> Result<()> {
        self.publish_homeserver(host_override, PublishMode::IfStale)
            .await
    }

    // ---- internals ----

    async fn publish_homeserver(
        &self,
        host_override: Option<&PublicKey>,
        mode: PublishMode,
    ) -> Result<()> {
        let kp = self.keypair_ref()?;
        let pubky = kp.public_key();

        // 1) Resolve the most recent record once.
        cross_log!(
            info,
            "Preparing to publish homeserver record for {} with mode {:?}",
            pubky,
            mode
        );
        let existing = self.client.pkarr().resolve_most_recent(&pubky).await;

        // 2) Decide host string to publish.
        let Some(host_str) = Self::select_host(&pubky, host_override, existing.as_ref()) else {
            return Ok(());
        };

        // 3) Age check (for IfStale).
        if self.should_skip_due_to_age(mode, existing.as_ref(), &pubky) {
            return Ok(());
        }

        // 4) Publish with a bounded retry. CAS/concurrency failures re-resolve
        // the latest packet so the next compare-and-swap is not stuck on a
        // stale timestamp (`publish_homeserver_force` and `IfStale` share this).
        self.publish_with_retries(kp, &pubky, &host_str, existing)
            .await
    }

    async fn publish_homeserver_inner(
        &self,
        keypair: &Keypair,
        host: &str,
        existing: Option<SignedPacket>,
    ) -> Result<()> {
        let signed_packet = Self::build_homeserver_packet(keypair, host, existing.as_ref())?;

        cross_log!(
            debug,
            "Publishing `_pubky` packet for {} targeting host {}",
            keypair.public_key(),
            host
        );

        self.client
            .pkarr()
            .publish(&signed_packet, existing.map(|s| s.timestamp()))
            .await
            .map_err(PkarrError::from)?;

        cross_log!(
            info,
            "Successfully published `_pubky` packet for {}",
            keypair.public_key()
        );
        Ok(())
    }

    fn keypair_ref(&self) -> Result<&Keypair> {
        self.keypair.as_ref().ok_or_else(|| {
            Error::from(AuthError::Validation(
                "publishing `_pubky` requires a keypair (use Pkdns::new_with_keypair or signer.pkdns())".into(),
            ))
        })
    }

    fn select_host(
        pubky: &PublicKey,
        host_override: Option<&PublicKey>,
        existing: Option<&SignedPacket>,
    ) -> Option<String> {
        determine_host(host_override, existing).map_or_else(
            || {
                cross_log!(
                    info,
                    "No existing host found for {}; skipping publish",
                    pubky
                );
                None
            },
            |h| {
                cross_log!(
                    info,
                    "Selected host {} for `_pubky` publish of {}",
                    h,
                    pubky
                );
                Some(h)
            },
        )
    }

    fn should_skip_due_to_age(
        &self,
        mode: PublishMode,
        existing: Option<&SignedPacket>,
        pubky: &PublicKey,
    ) -> bool {
        if !matches!(mode, PublishMode::IfStale) {
            return false;
        }
        let Some(record) = existing else {
            return false;
        };

        let elapsed = Timestamp::now() - record.timestamp();
        let age = Duration::from_micros(elapsed.as_u64());
        if age <= self.stale_after {
            cross_log!(
                info,
                "Skipping publish for {}: record age {:?} <= stale_after {:?}",
                pubky,
                age,
                self.stale_after
            );
            return true;
        }

        false
    }

    async fn publish_with_retries(
        &self,
        keypair: &Keypair,
        pubky: &PublicKey,
        host: &str,
        mut existing: Option<SignedPacket>,
    ) -> Result<()> {
        let mut last_err = None;

        for attempt in 1..=PUBLISH_MAX_ATTEMPTS {
            cross_log!(
                info,
                "Publishing homeserver for {} (attempt {attempt}) -> host {}",
                pubky,
                host
            );
            match self
                .publish_homeserver_inner(keypair, host, existing.clone())
                .await
            {
                Ok(()) => return Ok(()),
                Err(err) => match classify_publish_retry(&err, attempt, PUBLISH_MAX_ATTEMPTS) {
                    Some(PublishRetry::ReResolve) => {
                        cross_log!(
                            warn,
                            "Concurrency error while publishing {}: {}; re-resolving latest packet",
                            pubky,
                            err
                        );
                        bounded_publish_backoff(attempt).await;
                        existing = self.client.pkarr().resolve_most_recent(pubky).await;
                        last_err = Some(err);
                    }
                    Some(PublishRetry::SameCas) => {
                        cross_log!(
                            warn,
                            "Retryable PKARR error while publishing {}: {}; retrying",
                            pubky,
                            err
                        );
                        bounded_publish_backoff(attempt).await;
                        last_err = Some(err);
                    }
                    None => {
                        cross_log!(error, "Failed to publish homeserver for {}: {}", pubky, err);
                        return Err(err);
                    }
                },
            }
        }

        Err(last_err.expect("publish retry loop stores the last retryable error"))
    }

    fn build_homeserver_packet(
        keypair: &Keypair,
        host: &str,
        existing: Option<&SignedPacket>,
    ) -> Result<SignedPacket> {
        // Keep previous records that are *not* `_pubky.*`, then write `_pubky` HTTPS/SVCB.
        let mut builder = SignedPacket::builder();
        if let Some(packet) = existing {
            for record in packet.all_resource_records() {
                if !record.name.to_string().starts_with("_pubky") {
                    builder = builder.record(record.to_owned());
                }
            }
        }

        let svcb = SVCB::new(0, host.try_into().map_err(PkarrError::from)?);
        let pubky_name = "_pubky".try_into().map_err(PkarrError::from)?;

        Ok(builder
            .https(pubky_name, svcb, 60 * 60)
            .sign(keypair)
            .map_err(PkarrError::from)?)
    }
}

/// Internal publish strategy.
#[derive(Debug, Clone, Copy)]
enum PublishMode {
    Force,
    IfStale,
}

/// How to recover from a failed `_pubky` publish attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishRetry {
    /// CAS / concurrency: the timestamp we compared against is stale. Re-resolve.
    ReResolve,
    /// Transient publish/query: retry with the same CAS timestamp.
    SameCas,
}

const PUBLISH_MAX_ATTEMPTS: u32 = 3;

fn is_concurrency_failure(err: &Error) -> bool {
    matches!(
        err,
        Error::Pkarr(PkarrError::Publish(
            pkarr::errors::PublishError::Concurrency(_)
        ))
    )
}

fn classify_publish_retry(err: &Error, attempt: u32, max_attempts: u32) -> Option<PublishRetry> {
    if attempt >= max_attempts {
        return None;
    }
    if is_concurrency_failure(err) {
        return Some(PublishRetry::ReResolve);
    }
    if matches!(err, Error::Pkarr(pk) if pk.is_retryable()) {
        return Some(PublishRetry::SameCas);
    }
    None
}

async fn bounded_publish_backoff(attempt: u32) {
    let millis = match attempt {
        1 => 50,
        2 => 150,
        _ => 300,
    };
    #[cfg(not(target_arch = "wasm32"))]
    tokio::time::sleep(Duration::from_millis(millis)).await;
    #[cfg(target_arch = "wasm32")]
    {
        let _ = millis;
    }
}

#[cfg(test)]
async fn publish_with_retries_loop<P, R, PFut, RFut>(
    mut existing: Option<SignedPacket>,
    mut publish: P,
    mut resolve: R,
) -> Result<()>
where
    P: FnMut(Option<SignedPacket>) -> PFut,
    PFut: core::future::Future<Output = Result<()>>,
    R: FnMut() -> RFut,
    RFut: core::future::Future<Output = Option<SignedPacket>>,
{
    let mut last_err = None;

    for attempt in 1..=PUBLISH_MAX_ATTEMPTS {
        match publish(existing.clone()).await {
            Ok(()) => return Ok(()),
            Err(err) => match classify_publish_retry(&err, attempt, PUBLISH_MAX_ATTEMPTS) {
                Some(PublishRetry::ReResolve) => {
                    bounded_publish_backoff(attempt).await;
                    existing = resolve().await;
                    last_err = Some(err);
                }
                Some(PublishRetry::SameCas) => {
                    bounded_publish_backoff(attempt).await;
                    last_err = Some(err);
                }
                None => return Err(err),
            },
        }
    }

    Err(last_err.expect("publish retry loop stores the last retryable error"))
}

/// Pick a host to publish: explicit override or the one found in the DHT packet.
fn determine_host(
    override_host: Option<&PublicKey>,
    dht_packet: Option<&SignedPacket>,
) -> Option<String> {
    if let Some(host) = override_host {
        cross_log!(info, "Using override host {} for `_pubky` publish", host);
        return Some(host.z32());
    }
    cross_log!(debug, "Deriving publish host from existing `_pubky` record");
    dht_packet.and_then(extract_host_from_packet)
}

/// Extract `_pubky` SVCB/HTTPS target from a signed Pkarr packet.
pub fn extract_host_from_packet(packet: &SignedPacket) -> Option<String> {
    packet
        .resource_records("_pubky")
        .find_map(|rr| match &rr.rdata {
            RData::SVCB(svcb) => Some(svcb.target.to_string()),
            RData::HTTPS(https) => Some(https.0.target.to_string()),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkarr::dns::rdata::TXT;

    #[test]
    fn republish_preserves_non_pubky_records() {
        let keypair = Keypair::random();
        let original_host = Keypair::random().public_key().z32();

        let mut dnslink_txt = TXT::new();
        dnslink_txt
            .add_string("dnslink=/ipfs/example")
            .expect("valid dnslink string");

        let existing_packet = SignedPacket::builder()
            .https(
                "_pubky".try_into().expect("_pubky name"),
                SVCB::new(
                    0,
                    original_host
                        .as_str()
                        .try_into()
                        .expect("host name conversion"),
                ),
                3600,
            )
            .txt(
                "_dnslink".try_into().expect("_dnslink name"),
                dnslink_txt,
                3600,
            )
            .sign(&keypair)
            .expect("signed existing packet");

        let new_host = Keypair::random().public_key().z32();

        let republished =
            Pkdns::build_homeserver_packet(&keypair, &new_host, Some(&existing_packet))
                .expect("republished packet");

        assert_eq!(
            extract_host_from_packet(&republished),
            Some(new_host.clone())
        );

        let original_dnslink = existing_packet
            .all_resource_records()
            .find(|rr| rr.name.to_string().starts_with("_dnslink"))
            .map(ToOwned::to_owned)
            .expect("original _dnslink record");

        let republished_dnslink = republished
            .all_resource_records()
            .find(|rr| rr.name.to_string().starts_with("_dnslink"))
            .map(ToOwned::to_owned)
            .expect("republished _dnslink record");

        assert_eq!(republished_dnslink.ttl, original_dnslink.ttl);
        assert_eq!(republished_dnslink.rdata, original_dnslink.rdata);
    }

    fn cas_failed() -> Error {
        pkarr::errors::PublishError::Concurrency(pkarr::errors::ConcurrencyError::CasFailed).into()
    }

    fn homeserver_packet(keypair: &Keypair, host: &str) -> SignedPacket {
        Pkdns::build_homeserver_packet(keypair, host, None).expect("signed homeserver packet")
    }

    #[test]
    fn classify_cas_re_resolves_until_the_last_attempt() {
        let err = cas_failed();
        assert_eq!(
            classify_publish_retry(&err, 1, PUBLISH_MAX_ATTEMPTS),
            Some(PublishRetry::ReResolve)
        );
        assert_eq!(
            classify_publish_retry(&err, 2, PUBLISH_MAX_ATTEMPTS),
            Some(PublishRetry::ReResolve)
        );
        assert_eq!(classify_publish_retry(&err, 3, PUBLISH_MAX_ATTEMPTS), None);
    }

    #[tokio::test]
    async fn cas_retry_re_resolves_instead_of_reusing_stale_timestamp() {
        let keypair = Keypair::random();
        let stale_host = Keypair::random().public_key().z32();
        let fresh_host = Keypair::random().public_key().z32();
        let stale = homeserver_packet(&keypair, &stale_host);
        let fresh = homeserver_packet(&keypair, &fresh_host);

        let seen: std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let resolve_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let seen_publish = seen.clone();
        let seen_resolve = resolve_count.clone();
        let fresh_for_resolve = fresh.clone();
        let fresh_host_for_publish = fresh_host.clone();

        let result = publish_with_retries_loop(
            Some(stale),
            {
                let seen_publish = seen_publish.clone();
                move |existing| {
                    let host = existing.as_ref().and_then(extract_host_from_packet);
                    seen_publish.lock().expect("lock").push(host.clone());
                    let ok = host.as_deref() == Some(fresh_host_for_publish.as_str());
                    async move { if ok { Ok(()) } else { Err(cas_failed()) } }
                }
            },
            move || {
                seen_resolve.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let packet = fresh_for_resolve.clone();
                async move { Some(packet) }
            },
        )
        .await;

        assert!(
            result.is_ok(),
            "CAS retry must succeed after re-resolve: {result:?}"
        );
        assert_eq!(
            resolve_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "must re-resolve exactly once after the first CAS failure"
        );
        let hosts = seen.lock().expect("lock").clone();
        assert_eq!(hosts, vec![Some(stale_host), Some(fresh_host)]);
    }
}
