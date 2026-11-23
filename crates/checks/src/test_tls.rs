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
