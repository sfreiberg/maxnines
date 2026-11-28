//! What tests of checks that use TLS need: a server's side, with a certificate of
//! its own making for `localhost`, which checks don't trust.

use std::sync::Arc;

use tokio_rustls::TlsAcceptor;

pub(crate) fn acceptor() -> TlsAcceptor {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key =
        rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)
        .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

/// A server that reads the first of what it's sent, then hangs up without a word,
/// as a port that only takes TLS often does with what isn't.
pub(crate) async fn hangs_up() -> std::net::SocketAddr {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = [0u8; 1024];
                let _ = socket.read(&mut request).await;
            });
        }
    });
    address
}
