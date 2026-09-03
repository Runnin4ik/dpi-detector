use std::sync::Arc;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme};

/// Returns the shared pure-Rust RustCrypto provider.
pub fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER: std::sync::OnceLock<Arc<rustls::crypto::CryptoProvider>> = std::sync::OnceLock::new();
    PROVIDER
        .get_or_init(|| {
            let p = Arc::new(rustls_rustcrypto::provider());
            let _ = rustls_rustcrypto::provider().install_default();
            p
        })
        .clone()
}

/// Creates a standard verifying TLS ClientConfig backed by system/webpki roots.
pub fn create_verifying_tls_config() -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("safe default protocol versions")
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Arc::new(config)
}

/// Creates a verifying TLS ClientConfig for DoH (RFC 8484) with ALPN h2 / http/1.1.
pub fn create_verifying_doh_tls_config() -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("safe default protocol versions")
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Arc::new(config)
}

/// A verifier that accepts any server certificate (CERT_NONE equivalent for DPI testing).
#[derive(Debug)]
pub struct InsecureDpiCertVerifier;

impl ServerCertVerifier for InsecureDpiCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

/// Creates an insecure TLS ClientConfig that ignores certificate validation.
/// STRICTLY for DPI probe testing (SNI checks on arbitrary IPs), NEVER for general HTTPS traffic.
pub fn create_insecure_dpi_tls_config() -> Arc<ClientConfig> {
    let verifier = Arc::new(InsecureDpiCertVerifier);
    let config = ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("safe default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    Arc::new(config)
}

/// Insecure DPI config restricted to TLS 1.3 only (mirrors create_dpi_client("TLSv1.3")).
pub fn create_insecure_dpi_tls_config_tls13() -> Arc<ClientConfig> {
    let verifier = Arc::new(InsecureDpiCertVerifier);
    let config = ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Arc::new(config)
}

/// Insecure DPI config restricted to TLS 1.2 only (mirrors create_dpi_client("TLSv1.2")).
pub fn create_insecure_dpi_tls_config_tls12() -> Arc<ClientConfig> {
    let verifier = Arc::new(InsecureDpiCertVerifier);
    let config = ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("TLS 1.2 protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Arc::new(config)
}
