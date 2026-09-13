use std::sync::{Arc, LazyLock, Mutex};

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

/// The protocol versions a profile offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsVersion {
    /// Every version the provider supports: TLS 1.3 and 1.2.
    #[default]
    Any,
    /// TLS 1.2 only.
    Tls12,
    /// TLS 1.3 only.
    Tls13,
}

/// One description of the TLS client shape a probe presents.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsProfile {
    /// The ClientHello shape: cipher suites, extension order, groups, ALPN.
    pub fingerprint: TlsFingerprint,
    /// The protocol versions the hello offers.
    pub version: TlsVersion,
    /// An ALPN list to offer instead of the profile's own.
    ///
    /// `None` offers the profile's list (browsers send `h2, http/1.1`), `Some`
    /// replaces it — test 7 uses that to ask one protocol per run, which changes
    /// the ClientHello only in the ALPN extension's body and in JA4's ALPN field.
    pub alpn: Option<Vec<Vec<u8>>>,
    /// Verify the server certificate against the system roots instead of
    /// accepting any certificate.
    pub verify: bool,
}

impl TlsProfile {
    /// An insecure shape presenting `fingerprint`: every version the provider
    /// supports, the profile's own ALPN, any certificate accepted.
    ///
    /// STRICTLY for DPI probe testing (SNI checks on arbitrary IPs), NEVER for
    /// general HTTPS traffic — the certificate is the DPI signal here, not a
    /// trust decision. Use [`TlsProfile::verifying`] for traffic that has to be
    /// trusted.
    pub fn insecure(fingerprint: TlsFingerprint) -> Self {
        Self { fingerprint, ..Self::default() }
    }

    /// Offer TLS 1.3 only.
    ///
    /// Pinning the version is visible in the hello and is deliberate: rustls
    /// writes `supported_versions` from the config, so a pinned browser profile
    /// advertises `[GREASE, 0x0304]` where the Chrome 107 it imitates sends
    /// `[GREASE, 0x0304, 0x0303]` (Firefox, which does not grease, sends
    /// `[0x0304]` against a browser's `[0x0304, 0x0303]`).
    ///
    /// One version per hello is the price of test 2's two columns: a hello
    /// offering both lets the server choose, and the "TLS 1.3" column would
    /// silently carry a TLS 1.2 result. It stays a fingerprintable deviation —
    /// JA3 and JA4 cannot see it (extension codes, and the maximum version, are
    /// all they hash), but a middlebox that reads the body can, which is why
    /// `net::fingerprint::tests::grease_version_leads_supported_versions` pins
    /// both lists for both phases.
    pub fn tls13(mut self) -> Self {
        self.version = TlsVersion::Tls13;
        self
    }

    /// Offer TLS 1.2 only. Pinned the same way, and the same deviation:
    /// `[GREASE, 0x0303]` instead of a browser's `[GREASE, 0x0304, 0x0303]` —
    /// see [`TlsProfile::tls13`].
    pub fn tls12(mut self) -> Self {
        self.version = TlsVersion::Tls12;
        self
    }

    /// Offer `alpn` instead of the profile's own list.
    pub fn alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn = Some(alpn);
        self
    }

    /// Check the server certificate against the system (webpki) roots.
    ///
    /// The certificate is not the signal here: DoT, DoH and the HTTPS fetches
    /// have to reach a real server, so their configs verify.
    pub fn verifying() -> Self {
        Self { verify: true, ..Self::default() }
    }

    /// The protocol versions this profile asks the provider for.
    fn versions(&self) -> &'static [&'static rustls::SupportedProtocolVersion] {
        const TLS12_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
        const TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
        match self.version {
            TlsVersion::Any => rustls::DEFAULT_VERSIONS,
            TlsVersion::Tls12 => TLS12_ONLY,
            TlsVersion::Tls13 => TLS13_ONLY,
        }
    }
}

/// A verifier that accepts any server certificate: the certificate is the DPI
/// signal here, not a trust decision.
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

/// The client config every TLS connection in this crate is built from.
///
/// The profile carries the whole shape: the ClientHello fingerprint, the
/// protocol versions, the ALPN offer, and whether the certificate is verified.
/// Verifying profiles are built once per shape and shared ([`verifying_config`]);
/// insecure ones are built per call, because they cost no root store and a
/// private resumption store per config is what keeps one probe's session ticket
/// out of the next probe's ClientHello.
pub fn create_tls_config(profile: &TlsProfile) -> Arc<ClientConfig> {
    if profile.verify {
        verifying_config(profile)
    } else {
        Arc::new(build_config(profile))
    }
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

/// The verifying cache: one entry per shape [`create_tls_config`] was asked for.
type VerifyingCache = Mutex<Vec<(TlsProfile, Arc<ClientConfig>)>>;

/// A verifying config for `profile`, built once and shared.
///
/// Assembling the WebPKI roots (hundreds of anchors plus the verifier's name
/// index) is per-config work that a DoT/DoH probe would otherwise repeat on
/// every dial, and a `ClientConfig` is immutable once built, which is why these
/// are handed out as an `Arc`. The cache is only ever reached by the profiles
/// this build actually asks for (the plain one and DoH's).
fn verifying_config(profile: &TlsProfile) -> Arc<ClientConfig> {
    static CACHE: LazyLock<VerifyingCache> = LazyLock::new(|| Mutex::new(Vec::new()));

    let mut cache = CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, config)) = cache.iter().find(|(shape, _)| shape == profile) {
        return config.clone();
    }
    let config = Arc::new(build_config(profile));
    cache.push((profile.clone(), config.clone()));
    config
}

/// Builds the config `profile` describes: provider, versions, verifier, shape.
fn build_config(profile: &TlsProfile) -> ClientConfig {
    // `with_protocol_versions` rejects only a version the provider has no cipher
    // suite (with a matching key-exchange group) for, and this provider always
    // ships TLS 1.3 and 1.2; rustls has no non-`Result` form of the call.
    let builder = ClientConfig::builder_with_provider(provider_for(profile.fingerprint))
        .with_protocol_versions(profile.versions())
        .expect("the built-in provider serves TLS 1.3 and 1.2");

    let mut config = if profile.verify {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(root_store).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureDpiCertVerifier))
            .with_no_client_auth()
    };
    apply_profile(&mut config, profile);
    config
}

/// Installs the profile and keeps the baseline wire shape intact.
///
/// `profile.alpn` replaces the profile's own list when the caller pins one (test
/// 7 asks for one protocol per run). It has to be set in both places at once:
/// the hello's `alpn` extension is written from the *profile*, while rustls
/// validates the server's selection against `ClientConfig::alpn_protocols` — a
/// profile that offered http/1.1 while the config offered nothing made every
/// server answer `SelectedUnofferedApplicationProtocol`.
fn apply_profile(config: &mut ClientConfig, profile: &TlsProfile) {
    // The decompressor list is what makes rustls set `offered_cert_compression`,
    // and that is what puts extension 27 into the hello; the *offered algorithm
    // list* is the profile's. A profile that must not send the extension keeps
    // rustls's empty default, the shape this tool has always had.
    if crate::net::fingerprint::advertises_cert_compression(profile.fingerprint) {
        config.cert_decompressors = crate::net::cert_compression::decompressors();
    }
    crate::net::fingerprint::apply(config, profile.fingerprint);
    match &profile.alpn {
        Some(alpn) => {
            config.alpn_protocols = alpn.clone();
            if let Some(profile) = config.hello_profile.as_mut() {
                // Copy-on-write: the shared profile is only cloned for a caller
                // that asked for a different offer.
                Arc::make_mut(profile).alpn = Some(alpn.clone());
            }
        }
        None => {
            if let Some(profile) = &config.hello_profile {
                if let Some(profile_alpn) = &profile.alpn {
                    config.alpn_protocols = profile_alpn.clone();
                }
            }
        }
    }
}
