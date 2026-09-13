use std::sync::{Arc, LazyLock};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme};

use crate::net::fingerprint::TlsFingerprint;

/// Returns the shared pure-Rust RustCrypto provider.
pub fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER: LazyLock<Arc<rustls::crypto::CryptoProvider>> = LazyLock::new(|| {
        let p = Arc::new(rustls_rustcrypto::provider());
        let _ = rustls_rustcrypto::provider().install_default();
        p
    });
    PROVIDER.clone()
}

/// The provider plus our pure-Rust `X25519MLKEM768` group, offered first.
///
/// Kept separate from [`crypto_provider`] on purpose: adding the hybrid group to
/// the shared provider would change the ClientHello (and the cost) of *every*
/// connection, including the DNS truth probes that must stay comparable. Only
/// fingerprint profiles and PQ-requiring probes use this one.
pub fn crypto_provider_with_pq() -> Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER: LazyLock<Arc<rustls::crypto::CryptoProvider>> = LazyLock::new(|| {
        let base = crypto_provider();
        let mut groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup> =
            vec![&crate::net::pq_kx::X25519MlKem768];
        groups.extend(
            base.kx_groups
                .iter()
                .copied()
                .filter(|g| g.name() != rustls::NamedGroup::X25519MLKEM768),
        );
        Arc::new(rustls::crypto::CryptoProvider {
            kx_groups: groups,
            ..(*base).clone()
        })
    });
    PROVIDER.clone()
}

/// Creates a standard verifying TLS ClientConfig backed by system/webpki roots.
pub fn create_verifying_tls_config() -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("safe default protocol versions")
        .with_root_certificates(root_store)
        .with_no_client_auth();
    keep_baseline_wire_shape(&mut config);

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
    keep_baseline_wire_shape(&mut config);

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
    create_insecure_dpi_tls_config_with(TlsFingerprint::Rustls)
}

/// Insecure DPI config restricted to TLS 1.3 only (mirrors create_dpi_client("TLSv1.3")).
pub fn create_insecure_dpi_tls_config_tls13() -> Arc<ClientConfig> {
    create_insecure_dpi_tls_config_tls13_with(TlsFingerprint::Rustls)
}

/// Insecure DPI config restricted to TLS 1.2 only (mirrors create_dpi_client("TLSv1.2")).
pub fn create_insecure_dpi_tls_config_tls12() -> Arc<ClientConfig> {
    create_insecure_dpi_tls_config_tls12_with(TlsFingerprint::Rustls)
}

/// Providers for a fingerprint: the hybrid group is offered only where the
/// profile advertises it, so an ordinary probe keeps byte-identical behaviour.
fn provider_for(fingerprint: TlsFingerprint) -> Arc<rustls::crypto::CryptoProvider> {
    if crate::net::fingerprint::needs_pq(fingerprint) {
        crypto_provider_with_pq()
    } else {
        crypto_provider()
    }
}

fn insecure_builder(
    fingerprint: TlsFingerprint,
    versions: Option<&[&'static rustls::SupportedProtocolVersion]>,
) -> ClientConfig {
    let provider = provider_for(fingerprint);
    let builder = match versions {
        Some(v) => ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(v)
            .expect("protocol versions supported by the provider"),
        None => ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("safe default protocol versions"),
    };
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureDpiCertVerifier))
        .with_no_client_auth();
    apply_fingerprint(&mut config, fingerprint);
    config
}

/// Installs the profile and keeps the baseline wire shape intact.
fn apply_fingerprint(config: &mut ClientConfig, fingerprint: TlsFingerprint) {
    if !crate::net::fingerprint::advertises_cert_compression(fingerprint) {
        keep_baseline_wire_shape(config);
    }
    crate::net::fingerprint::apply(config, fingerprint);
    // rustls validates the server's ALPN selection against `config.alpn_protocols`,
    // not against what the profile wrote into the extension. A profile that
    // offered http/1.1 while the config offered nothing made every server answer
    // `SelectedUnofferedApplicationProtocol`, so the two must agree.
    if let Some(profile) = &config.hello_profile {
        if let Some(alpn) = &profile.alpn {
            config.alpn_protocols = alpn.clone();
        }
    }
}

/// Restores the ClientHello shape of a build without the `brotli`/`zlib`
/// features — i.e. exactly what this tool sent before fingerprint profiles
/// existed. See [`crate::net::fingerprint::advertises_cert_compression`].
fn keep_baseline_wire_shape(config: &mut ClientConfig) {
    config.cert_decompressors.clear();
}

/// [`create_insecure_dpi_tls_config`] with a ClientHello profile.
pub fn create_insecure_dpi_tls_config_with(fingerprint: TlsFingerprint) -> Arc<ClientConfig> {
    Arc::new(insecure_builder(fingerprint, None))
}

/// [`create_insecure_dpi_tls_config_tls13`] with a ClientHello profile.
pub fn create_insecure_dpi_tls_config_tls13_with(
    fingerprint: TlsFingerprint,
) -> Arc<ClientConfig> {
    Arc::new(insecure_builder(fingerprint, Some(&[&rustls::version::TLS13])))
}

/// [`create_insecure_dpi_tls_config_tls12`] with a ClientHello profile.
pub fn create_insecure_dpi_tls_config_tls12_with(
    fingerprint: TlsFingerprint,
) -> Arc<ClientConfig> {
    Arc::new(insecure_builder(fingerprint, Some(&[&rustls::version::TLS12])))
}
