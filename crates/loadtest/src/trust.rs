//! Which certificates the load test trusts: the public roots, or only a private CA's,
//! as an agent with `ca_file` set does, for a server set up with certificates of its
//! own.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore};
use tokio_tungstenite::Connector;

/// The certificates of a private CA, read from a PEM file.
#[derive(Clone)]
pub struct PrivateCa {
    certificates: Vec<CertificateDer<'static>>,
}

impl PrivateCa {
    pub fn read(path: &Path) -> Result<Self> {
        let read = || -> Result<Vec<CertificateDer<'static>>> {
            let certificates: Result<Vec<_>, _> = CertificateDer::pem_file_iter(path)?.collect();
            Ok(certificates?)
        };
        let certificates = read().with_context(|| format!("reading CA file {}", path.display()))?;
        ensure!(
            !certificates.is_empty(),
            "CA file {} has no certificates in it",
            path.display()
        );
        Ok(Self { certificates })
    }

    /// For agents' connections: only this CA.
    pub fn connector(&self) -> Result<Connector> {
        let mut roots = RootCertStore::empty();
        for certificate in &self.certificates {
            roots
                .add(certificate.clone())
                .context("the CA file's certificate can't be used")?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Connector::Rustls(Arc::new(config)))
    }

    /// For the API and pages: only this CA.
    pub fn roots(&self) -> ureq::tls::RootCerts {
        let certificates: Vec<ureq::tls::Certificate<'static>> = self
            .certificates
            .iter()
            .map(|certificate| ureq::tls::Certificate::from_der(certificate).to_owned())
            .collect();
        ureq::tls::RootCerts::new_with_certs(&certificates)
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
    use rustls::pki_types::PrivateKeyDer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::server::Server;

    /// A private CA, written where the load test can read it, and a server
    /// certificate for localhost that it signed.
    fn private_ca(folder: &Path) -> (std::path::PathBuf, TlsAcceptor) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .signed_by(&key, &ca)
            .unwrap();
        let path = folder.join("ca.pem");
        std::fs::write(&path, ca.pem()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone()],
                PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        (path, TlsAcceptor::from(Arc::new(config)))
    }

    /// Answers each connection over TLS: as a WebSocket, or a page that says ok.
    async fn serve(acceptor: TlsAcceptor, websocket: bool) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(socket).await else {
                        return;
                    };
                    if websocket {
                        let _ = tokio_tungstenite::accept_async(tls).await;
                        return;
                    }
                    // A GET ends with its headers.
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        if tls.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        request.push(byte[0]);
                    }
                    let answer =
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                    let _ = tls.write_all(answer.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        port
    }

    /// Agents and the API reach a server whose certificate a private CA signed with
    /// that CA's file, and not without it.
    #[tokio::test]
    async fn a_server_signed_by_a_private_ca_is_trusted_with_its_file() {
        let folder = tempfile::tempdir().unwrap();
        let (path, acceptor) = private_ca(folder.path());
        let ca = PrivateCa::read(&path).unwrap();

        let agents = serve(acceptor.clone(), true).await;
        let url = format!("wss://localhost:{agents}/ws");
        let connector = Some(ca.connector().unwrap());
        let trusted =
            tokio_tungstenite::connect_async_tls_with_config(&url, None, false, connector);
        assert!(trusted.await.is_ok());
        let public = tokio_tungstenite::connect_async_tls_with_config(&url, None, false, None);
        assert!(public.await.is_err());

        let pages = serve(acceptor, false).await;
        let base = format!("https://localhost:{pages}");
        let load = |ca: Option<PrivateCa>| {
            let base = base.clone();
            tokio::task::spawn_blocking(move || {
                Server::new(base, "key".to_string(), ca.as_ref()).load_page("/")
            })
        };
        assert!(load(Some(ca)).await.unwrap().ok);
        assert!(!load(None).await.unwrap().ok);
    }

    #[test]
    fn a_file_without_a_certificate_is_refused() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("ca.pem");
        std::fs::write(&path, "not a certificate\n").unwrap();
        let error = PrivateCa::read(&path).err().unwrap();
        assert!(
            format!("{error:#}").contains("no certificates"),
            "{error:#}"
        );
        assert!(PrivateCa::read(&folder.path().join("missing.pem")).is_err());
    }
}
