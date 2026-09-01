//! Standard public HTTPS for Android ICANN hosts using rustls + Mozilla roots.
//!
//! reqwest 0.13's default rustls backend uses `rustls-platform-verifier`. On
//! Android that runs PKIX with revocation checking and hard-fails Let's Encrypt
//! YE1 leaves that omit an OCSP responder (`Certificate does not specify OCSP
//! responder` → rustls `UnknownIssuer`).
//!
//! This module builds a rustls `ClientConfig` from [`webpki_roots::TLS_SERVER_ROOTS`]
//! so hostname, validity, signature, EKU/KU, and chain checks still run, without
//! consulting Android PKIX revocation.
//!
//! **Revocation:** this configuration performs no OCSP or CRL checking. A
//! revoked-but-unexpired certificate that still chains to a Mozilla root is
//! accepted. That matches browser/`WebPKI`-root posture and pubky-homeserver
//! PR 456.
//!
//! **ALPN:** only `http/1.1`. Paykit/pubky reqwest clients are built without
//! the `http2` feature; advertising `h2` would let a server select HTTP/2 that
//! this stack cannot speak.
//!
//! PubkyTLS raw-public-key verification ([`crate::extra::tls`]) is unchanged.

use std::sync::Arc;

use rustls::ClientConfig;

/// Mozilla/`webpki` TLS server roots (`ISRG Root X1`/`X2` and the rest of the
/// public program).
pub fn mozilla_webpki_root_store() -> rustls::RootCertStore {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    root_store
}

/// rustls client config that authenticates servers against `root_store`.
///
/// Does not disable certificate or hostname verification, accept invalid
/// certificates, pin a leaf, or permit cleartext.
///
/// # Panics
///
/// Panics if the rustls ring provider does not advertise safe default TLS
/// protocol versions. The ring provider always does.
pub fn webpki_https_client_config(root_store: rustls::RootCertStore) -> ClientConfig {
    let mut tls_config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring provides safe default protocol versions")
            .with_root_certificates(root_store)
            .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tls_config
}

/// rustls client config using Mozilla/`webpki` roots.
pub fn mozilla_webpki_https_client_config() -> ClientConfig {
    webpki_https_client_config(mozilla_webpki_root_store())
}

/// Install [`mozilla_webpki_https_client_config`] on a reqwest builder.
///
/// `Client::build` fails if this `rustls::ClientConfig` does not unify with
/// the rustls version reqwest compiled against (`UnknownPreconfigured`).
pub fn apply_mozilla_webpki_https(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder.tls_backend_preconfigured(mozilla_webpki_https_client_config())
}

/// HTTP client used by pkarr `RelaysClient` for ICANN HTTPS to pkarr relays.
///
/// On Android this installs Mozilla/`webpki` roots. Other native targets keep
/// reqwest's default rustls backend (`rustls-platform-verifier`).
pub fn relays_http_client() -> reqwest::Client {
    let builder = reqwest::Client::builder();
    #[cfg(target_os = "android")]
    let builder = apply_mozilla_webpki_https(builder);
    builder
        .build()
        .expect("Client building should be infallible")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    struct TestChain {
        roots: rustls::RootCertStore,
        cert_der: CertificateDer<'static>,
        key_der: PrivateKeyDer<'static>,
    }

    fn test_chain(dns_name: &str) -> TestChain {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("empty CA SAN list is valid");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA cert");
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);

        let mut leaf_params =
            rcgen::CertificateParams::new(vec![dns_name.to_string()]).expect("leaf SANs");
        leaf_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::DigitalSignature);
        leaf_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert");

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_cert.der().to_vec()))
            .expect("add test CA");

        TestChain {
            roots,
            cert_der: CertificateDer::from(leaf_cert.der().to_vec()),
            key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        }
    }

    fn spawn_https_ok_server(chain: &TestChain) -> (u16, thread::JoinHandle<()>) {
        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring server versions")
        .with_no_client_auth()
        .with_single_cert(vec![chain.cert_der.clone()], chain.key_der.clone_key())
        .expect("server cert");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server_config = Arc::new(server_config);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        listener
            .set_nonblocking(false)
            .expect("blocking accept for the single test connection");
        let port = listener.local_addr().expect("local addr").port();
        let (ready_tx, ready_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            ready_tx.send(()).expect("server ready");
            let (mut sock, _) = listener.accept().expect("accept test client");
            let mut conn = rustls::ServerConnection::new(server_config).expect("server connection");
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);
            let mut buf = [0u8; 2048];
            let _ = tls.read(&mut buf);
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write HTTP response");
            let _ = tls.flush();
        });
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("HTTPS fixture thread started");
        (port, handle)
    }

    fn tls_error_text(err: &reqwest::Error) -> String {
        format!("{err:?}")
    }

    fn is_certificate_error(err: &reqwest::Error) -> bool {
        let text = tls_error_text(err);
        err.is_connect()
            || text.contains("Certificate")
            || text.contains("UnknownIssuer")
            || text.contains("NotValidForName")
            || text.contains("invalid peer certificate")
            || text.contains("certificate")
    }

    #[test]
    fn mozilla_roots_are_the_public_webpki_program() {
        let roots = mozilla_webpki_root_store();
        assert!(!roots.is_empty());
        assert_eq!(roots.len(), webpki_roots::TLS_SERVER_ROOTS.len());
        let tls = mozilla_webpki_https_client_config();
        assert_eq!(tls.alpn_protocols, [b"http/1.1".to_vec()]);
    }

    #[test]
    fn tls_backend_preconfigured_accepts_mozilla_webpki_rustls_config() {
        apply_mozilla_webpki_https(reqwest::Client::builder())
            .build()
            .expect(
                "reqwest must accept mozilla_webpki_https_client_config; rustls version drift \
                 becomes TlsBackend::UnknownPreconfigured",
            );
    }

    #[tokio::test]
    async fn webpki_reqwest_rejects_untrusted_test_ca() {
        let chain = test_chain("localhost");
        let (port, server) = spawn_https_ok_server(&chain);
        let client = apply_mozilla_webpki_https(reqwest::Client::builder())
            .build()
            .expect("webpki reqwest client");
        let err = client
            .get(format!("https://localhost:{port}/"))
            .send()
            .await
            .expect_err("Mozilla roots must reject a private test CA");
        assert!(
            is_certificate_error(&err),
            "expected certificate failure, got {err:?}"
        );
        let _ = server.join();
    }

    #[tokio::test]
    async fn webpki_reqwest_accepts_controlled_valid_chain() {
        let chain = test_chain("localhost");
        let (port, server) = spawn_https_ok_server(&chain);
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(webpki_https_client_config(chain.roots.clone()))
            .build()
            .expect("test-CA reqwest client");
        let response = client
            .get(format!("https://localhost:{port}/"))
            .send()
            .await
            .expect("trusted test chain must succeed");
        assert!(response.status().is_success());
        assert_eq!(response.text().await.expect("body"), "OK");
        let _ = server.join();
    }

    #[tokio::test]
    async fn webpki_reqwest_rejects_wrong_hostname() {
        let chain = test_chain("wrong.example");
        let (port, server) = spawn_https_ok_server(&chain);
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(webpki_https_client_config(chain.roots.clone()))
            .build()
            .expect("test-CA reqwest client");
        let err = client
            .get(format!("https://localhost:{port}/"))
            .send()
            .await
            .expect_err("hostname mismatch must fail");
        assert!(
            is_certificate_error(&err),
            "expected hostname/certificate failure, got {err:?}"
        );
        let _ = server.join();
    }

    #[tokio::test]
    #[ignore = "optional live WebPKI handshake against production ICANN hosts; not e2e auth"]
    async fn live_production_icann_hosts_handshake() {
        let client = apply_mozilla_webpki_https(reqwest::Client::builder())
            .timeout(Duration::from_secs(15))
            .build()
            .expect("webpki reqwest client");
        for origin in ["https://pkarr.pubky.app/", "https://httprelay.pubky.app/"] {
            match client.get(origin).send().await {
                Ok(_) => {}
                Err(err) => {
                    assert!(
                        !is_certificate_error(&err),
                        "production host TLS failed certificate checks: {err:?}"
                    );
                }
            }
        }
    }
}
