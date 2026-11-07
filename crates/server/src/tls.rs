//! Serving HTTPS, for servers that aren't behind a proxy. A certificate either comes
//! from files someone keeps up to date, or from an ACME service such as Let's Encrypt,
//! which is asked for one and renews it. ACME proves who we are on this same port, so
//! nothing else has to listen. Neither needs a restart when a certificate changes.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use axum::Router;
use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use axum_server::tls_rustls::RustlsConfig;
use futures_util::StreamExt;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_acme::AcmeConfig;
use rustls_acme::caches::DirCache;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::config::{AcmeSettings, TlsConfig};

type Service = IntoMakeServiceWithConnectInfo<Router, SocketAddr>;

/// How often to look for a renewed certificate on disk.
const RELOAD_EVERY: Duration = Duration::from_secs(3600);

/// Agents use HTTP/1.1 for their WebSockets, and browsers prefer HTTP/2 for pages.
fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

fn crypto() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Errors name the files but never say what's in them.
fn load_certificate(certificate: &Path, key: &Path) -> Result<ServerConfig> {
    let chain = CertificateDer::pem_file_iter(certificate)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .with_context(|| format!("reading certificate file {}", certificate.display()))?;
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|_| anyhow::anyhow!("reading key file {}", key.display()))?;
    let mut config = ServerConfig::builder_with_provider(crypto())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("the certificate and key don't work together")?;
    config.alpn_protocols = alpn_protocols();
    Ok(config)
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

/// Picks up a certificate replaced on disk. One that can't be read is left for next
/// time, and the one in use carries on, as a renewal may only be half done.
fn keep_certificate_current(
    certificate: PathBuf,
    key: PathBuf,
    serving: RustlsConfig,
    every: Duration,
) {
    tokio::spawn(async move {
        let times = || (modified(&certificate), modified(&key));
        let mut seen = times();
        loop {
            tokio::time::sleep(every).await;
            if times() == seen {
                continue;
            }
            match load_certificate(&certificate, &key) {
                Ok(config) => {
                    serving.reload_from_config(Arc::new(config));
                    seen = times();
                    info!("loaded a new certificate");
                }
                Err(error) => {
                    let error = format!("{error:#}");
                    warn!(error, "a changed certificate couldn't be loaded");
                }
            }
        }
    });
}

async fn serve_certificate(
    listener: TcpListener,
    certificate: PathBuf,
    key: PathBuf,
    service: Service,
    reload_every: Duration,
) -> Result<()> {
    let config = load_certificate(&certificate, &key)?;
    let serving = RustlsConfig::from_config(Arc::new(config));
    keep_certificate_current(certificate, key, serving.clone(), reload_every);
    axum_server::from_tcp_rustls(listener.into_std()?, serving)?
        .serve(service)
        .await?;
    Ok(())
}

/// The client that talks to the ACME service, which only needs its own trust for a
/// private service.
fn acme_client(ca_file: &Path) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    let certificates = CertificateDer::pem_file_iter(ca_file)
        .with_context(|| format!("reading CA file {}", ca_file.display()))?;
    for certificate in certificates {
        roots.add(certificate.context("parsing CA file")?)?;
    }
    let config = ClientConfig::builder_with_provider(crypto())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

async fn serve_acme(listener: TcpListener, acme: &AcmeSettings, service: Service) -> Result<()> {
    let mut config = AcmeConfig::new_with_provider(&acme.domains, crypto())
        .cache(DirCache::new(acme.cache_dir.clone()))
        .directory(&acme.directory);
    if let Some(email) = &acme.email {
        config = config.contact_push(format!("mailto:{email}"));
    }
    if let Some(ca_file) = &acme.ca_file {
        config = config.client_tls_config(acme_client(ca_file)?);
    }

    let mut state = config.state();
    let mut serving = (*state.default_rustls_config_with_provider(crypto())).clone();
    serving.alpn_protocols = alpn_protocols();
    let acceptor = state.axum_acceptor(Arc::new(serving));
    // This has to keep running for certificates to be issued and renewed.
    tokio::spawn(async move {
        while let Some(event) = state.next().await {
            match event {
                Ok(event) => info!(?event, "certificate"),
                Err(failure) => error!(error = ?failure, "getting a certificate failed"),
            }
        }
    });

    axum_server::from_tcp(listener.into_std()?)?
        .acceptor(acceptor)
        .serve(service)
        .await?;
    Ok(())
}

/// Runs until the listener fails.
pub async fn serve(listener: TcpListener, tls: &TlsConfig, service: Service) -> Result<()> {
    match tls {
        TlsConfig {
            acme: Some(acme), ..
        } => serve_acme(listener, acme, service).await,
        TlsConfig {
            certificate_file: Some(certificate),
            key_file: Some(key),
            ..
        } => {
            let (certificate, key) = (certificate.clone(), key.clone());
            serve_certificate(listener, certificate, key, service, RELOAD_EVERY).await
        }
        _ => anyhow::bail!("the tls block needs a certificate or acme"),
    }
}

#[cfg(test)]
mod tests {
    use axum::routing::get;
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use tempfile::TempDir;

    use super::*;

    fn certificate() -> CertifiedKey<rcgen::KeyPair> {
        generate_simple_self_signed(vec!["localhost".to_string()]).unwrap()
    }

    /// A certificate and key in files.
    fn on_disk(folder: &TempDir, name: &str) -> (PathBuf, PathBuf, String) {
        let made = certificate();
        let (cert, key) = (
            folder.path().join(format!("{name}.crt")),
            folder.path().join(format!("{name}.key")),
        );
        std::fs::write(&cert, made.cert.pem()).unwrap();
        std::fs::write(&key, made.signing_key.serialize_pem()).unwrap();
        (cert, key, made.cert.pem())
    }

    fn app() -> Service {
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .into_make_service_with_connect_info::<SocketAddr>()
    }

    /// Asks over HTTPS, trusting only this certificate.
    fn fetch(address: SocketAddr, certificate_pem: &str) -> Result<String, String> {
        let root = CertificateDer::from_pem_slice(certificate_pem.as_bytes()).unwrap();
        let root = ureq::tls::Certificate::from_der(root.as_ref()).to_owned();
        let tls = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::Specific(Arc::new(vec![root])))
            .build();
        let agent = ureq::Agent::config_builder().tls_config(tls).build();
        let agent = ureq::Agent::new_with_config(agent);
        agent
            .get(format!("https://localhost:{}/health", address.port()))
            .call()
            .map_err(|error| error.to_string())
            .and_then(|mut response| {
                response
                    .body_mut()
                    .read_to_string()
                    .map_err(|e| e.to_string())
            })
    }

    async fn serving(cert: PathBuf, key: PathBuf, reload_every: Duration) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve_certificate(listener, cert, key, app(), reload_every));
        address
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_certificate_from_files_serves_https() {
        let folder = tempfile::tempdir().unwrap();
        let (cert, key, pem) = on_disk(&folder, "site");
        let address = serving(cert, key, RELOAD_EVERY).await;

        let answer = tokio::task::spawn_blocking(move || fetch(address, &pem));

        assert_eq!(answer.await.unwrap().unwrap(), "ok");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_replaced_certificate_is_picked_up_without_a_restart() {
        let folder = tempfile::tempdir().unwrap();
        let (cert, key, old) = on_disk(&folder, "site");
        let address = serving(cert.clone(), key.clone(), Duration::from_millis(50)).await;

        // File times can be coarse, so the new ones have to land clearly later.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let (new_cert, new_key, new) = on_disk(&folder, "renewed");
        std::fs::rename(new_cert, &cert).unwrap();
        std::fs::rename(new_key, &key).unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;

        let (with_new, with_old) =
            tokio::task::spawn_blocking(move || (fetch(address, &new), fetch(address, &old)))
                .await
                .unwrap();
        assert_eq!(with_new.unwrap(), "ok");
        assert!(with_old.is_err(), "the old certificate has gone");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_broken_replacement_leaves_the_working_certificate_in_place() {
        let folder = tempfile::tempdir().unwrap();
        let (cert, key, pem) = on_disk(&folder, "site");
        let address = serving(cert.clone(), key, Duration::from_millis(50)).await;

        tokio::time::sleep(Duration::from_millis(1100)).await;
        std::fs::write(&cert, "not a certificate").unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        let answer = tokio::task::spawn_blocking(move || fetch(address, &pem));
        assert_eq!(answer.await.unwrap().unwrap(), "ok");
    }

    #[test]
    fn a_key_for_another_certificate_is_refused() {
        let folder = tempfile::tempdir().unwrap();
        let (cert, _, _) = on_disk(&folder, "one");
        let (_, key, _) = on_disk(&folder, "two");

        let error = load_certificate(&cert, &key).unwrap_err();

        assert!(
            format!("{error:#}").contains("don't work together"),
            "{error:#}"
        );
    }

    #[test]
    fn errors_name_the_file_and_never_show_what_is_in_it() {
        let folder = tempfile::tempdir().unwrap();
        let (cert, _, _) = on_disk(&folder, "site");
        let key = folder.path().join("broken.key");
        std::fs::write(&key, "a-secret-that-is-not-a-key").unwrap();

        let error = format!("{:#}", load_certificate(&cert, &key).unwrap_err());

        assert!(error.contains("broken.key"), "{error}");
        assert!(!error.contains("a-secret"), "{error}");
    }

    #[test]
    fn a_missing_file_says_which() {
        let folder = tempfile::tempdir().unwrap();
        let (_, key, _) = on_disk(&folder, "site");
        let missing = folder.path().join("missing.crt");

        let error = format!("{:#}", load_certificate(&missing, &key).unwrap_err());

        assert!(error.contains("missing.crt"), "{error}");
    }
}
