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
    /// replaces it — test 6 uses that to ask one protocol per run, which changes
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

    // A pinned run isolates one version (test 2's two columns, test 6's TLS 1.2
    // axis), and a profile's fallback versions exist to make an *unpinned* hello
    // look like the browser's. Keeping them here would advertise 1.1 behind a
    // hello that offers exactly one version — a shape no client sends and a
    // question the run is not asking. The same goes for the other version's
    // extensions and cipher suites: a browser drops them when it offers one
    // version, and the far side answers a hello that keeps them with a fatal
    // alert (see `fingerprint::pinned_drop`).
    if profile.version != TlsVersion::Any {
        if let Some(hello) = config.hello_profile.as_mut() {
            let hello = Arc::make_mut(hello);
            hello.legacy_versions.clear();

            let drop = crate::net::fingerprint::pinned_drop(profile.fingerprint, profile.version);
            if !drop.is_empty() {
                // Suppression is what removes them: an extension missing from
                // the order is still sent, only later, and one the profile
                // supplies verbatim would be sent from `raw_extensions`.
                hello.suppress_extensions.extend_from_slice(drop);
                if let Some(order) = hello.extension_order.as_mut() {
                    order.retain(|ext| !drop.contains(ext));
                }
                hello.raw_extensions.retain(|(ext, _)| !drop.contains(ext));
            }
            if let Some(suites) = hello.cipher_suites.as_mut() {
                suites.retain(|suite| offers_version(profile.version, *suite));
            }
        }
    }
}

/// Whether cipher suite `suite` belongs to `version`.
///
/// The TLS 1.3 suites are the `0x13xx` block and everything a browser offers
/// below it is a 1.2 suite, so a pinned hello keeps exactly one family — as the
/// browsers do (Chrome 107 pinned to 1.3 offers 0x1301-0x1303 alone, pinned to
/// 1.2 the ECDHE/RSA suites alone).
fn offers_version(version: TlsVersion, suite: u16) -> bool {
    let is_tls13 = (0x1301..=0x1305).contains(&suite);
    match version {
        TlsVersion::Tls13 => is_tls13,
        TlsVersion::Tls12 => !is_tls13,
        TlsVersion::Any => true,
    }
}

/// Why the two tests below exist, and why nothing else covers this.
///
/// `vendor/rustls-rustcrypto` is upstream's provider with its `rustls-webpki
/// 0.102` dependency removed: the OID table it took from `webpki::alg_id` now
/// comes from `rustls-pki-types` (`vendor/rustls-rustcrypto/README-PATCH.md`).
/// That table is what the provider reports as the algorithms it can verify, so a
/// mistake there is invisible to every other test in this crate — JA3 and JA4
/// hash a ClientHello and never verify anything, and the probes'
/// `TlsProfile::insecure` accepts any certificate. It surfaces in the field as a
/// site that opens in a browser and not here, which is the one failure this tool
/// must never report as censorship.
#[cfg(test)]
mod tests {
    use super::*;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{
        ClientConnection, RootCertStore, ServerConfig, ServerConnection, SignatureScheme,
        StreamOwned,
    };
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    /// One test chain, generated once and checked in: a CA (EC P-256,
    /// `CN=dpi-detector test CA`, `CA:TRUE` + `keyCertSign`) and three leaves
    /// under it, one per key type the provider can verify — `CN=localhost`,
    /// `SAN DNS:localhost, IP:127.0.0.1`, `EKU serverAuth`, keys EC P-256,
    /// RSA-2048 and Ed25519 as PKCS#8.
    ///
    /// `testdata/generate.py` is the script that wrote these files; run it again
    /// only if the 20-year validity window ever runs out.
    const CA: &[u8] = include_bytes!("testdata/ca.der");
    const LEAVES: &[(&str, &[u8], &[u8])] = &[
        ("ecdsa", include_bytes!("testdata/ecdsa.der"), include_bytes!("testdata/ecdsa.key.der")),
        ("rsa", include_bytes!("testdata/rsa.der"), include_bytes!("testdata/rsa.key.der")),
        (
            "ed25519",
            include_bytes!("testdata/ed25519.der"),
            include_bytes!("testdata/ed25519.key.der"),
        ),
    ];

    /// The `AlgorithmIdentifier` DER a peer's certificate carries, exactly as
    /// `rustls-pki-types` ships it in `src/data/alg-*.der`, for the five cases
    /// that between them cover every shape the provider reports: an OID alone
    /// (Ed25519, `ecdsa-with-SHA256`), an OID with the named curve as a
    /// parameter (`id-ecPublicKey` + prime256v1), and an OID with explicit
    /// parameters (`rsaEncryption` with NULL, `id-RSASSA-PSS` with its hash and
    /// salt parameters). Hardcoded rather than read back from `pki_types`: the
    /// point is to pin the data a certificate carries independently of the crate
    /// the provider imports it from.
    ///
    /// 1.2.840.10045.4.3.2 — `ecdsa-with-SHA256`.
    const ECDSA_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    /// 1.2.840.10045.2.1 + 1.2.840.10045.3.1.7 — `id-ecPublicKey` with `prime256v1`.
    const ECDSA_P256: &[u8] = &[
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x03, 0x01, 0x07,
    ];
    /// 1.2.840.10045.4.3.3 — `ecdsa-with-SHA384`.
    const ECDSA_SHA384: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
    /// 1.2.840.10045.2.1 + 1.3.132.0.34 — `id-ecPublicKey` with `secp384r1`.
    const ECDSA_P384: &[u8] = &[
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00,
        0x22,
    ];
    /// 1.3.101.112 — `id-Ed25519`.
    const ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
    /// 1.2.840.113549.1.1.1 — `rsaEncryption` with an explicit NULL parameter.
    const RSA_ENCRYPTION: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    /// 1.2.840.113549.1.1.11 — `sha256WithRSAEncryption` with an explicit NULL.
    const RSA_PKCS1_SHA256: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    ];
    /// 1.2.840.113549.1.1.10 — `id-RSASSA-PSS` with SHA-256, MGF1-SHA-256 and a
    /// 32-byte salt, which is the parameter set the provider's verifier uses.
    const RSA_PSS_SHA256: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0, 0x0f,
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
        0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
        0xa2, 0x03, 0x02, 0x01, 0x20,
    ];

    /// The provider must report, for every scheme it claims, the identifier pair
    /// a certificate signed by such a key carries: rustls hands these to path
    /// validation, and a pair that does not match the certificate is a
    /// verification failure that no ClientHello-level test can see.
    #[test]
    fn provider_reports_the_algorithm_identifiers_a_certificate_carries() {
        let provider = crypto_provider();
        let expected: &[(SignatureScheme, &[u8], &[u8])] = &[
            (SignatureScheme::ECDSA_NISTP256_SHA256, ECDSA_SHA256, ECDSA_P256),
            (SignatureScheme::ECDSA_NISTP384_SHA384, ECDSA_SHA384, ECDSA_P384),
            (SignatureScheme::ED25519, ED25519, ED25519),
            (SignatureScheme::RSA_PKCS1_SHA256, RSA_PKCS1_SHA256, RSA_ENCRYPTION),
            (SignatureScheme::RSA_PSS_SHA256, RSA_PSS_SHA256, RSA_ENCRYPTION),
        ];

        for (scheme, signature_oid, public_key_oid) in expected {
            let algorithms = provider
                .signature_verification_algorithms
                .mapping
                .iter()
                .find(|(mapped, _)| mapped == scheme)
                .map(|(_, algorithms)| *algorithms)
                .unwrap_or_else(|| panic!("{scheme:?} has no verification algorithm"));
            // TLS 1.3 tries only the first algorithm of a mapping, and a mapping
            // that leads with the wrong identifier breaks exactly that path.
            let first = algorithms
                .first()
                .unwrap_or_else(|| panic!("{scheme:?} maps to an empty algorithm list"));
            assert_eq!(
                first.signature_alg_id().as_ref(),
                *signature_oid,
                "{scheme:?} signature AlgorithmIdentifier"
            );
            assert_eq!(
                first.public_key_alg_id().as_ref(),
                *public_key_oid,
                "{scheme:?} public key AlgorithmIdentifier"
            );
        }
    }

    /// A full verifying handshake against a local rustls server, with the
    /// fixture CA as the only trust anchor. The client config is built straight
    /// from the provider, not from `create_tls_config`, because the verifying
    /// profile trusts `webpki-roots` and a test cannot add a root to it.
    ///
    /// Returns the client's view: `Ok(())` once the certificate verified and the
    /// request round-tripped, `Err(message)` otherwise. With `trust_ca = false`
    /// the root store is empty, which is the control: it must fail, otherwise the
    /// client would be accepting anything and would prove nothing.
    fn handshake(leaf: &'static [u8], key: &'static [u8], trust_ca: bool) -> Result<(), String> {
        let provider = crypto_provider();
        let server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("the provider serves TLS 1.2 and 1.3")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
            )
            .expect("the fixture leaf and its key form a valid certified key");

        let mut roots = RootCertStore::empty();
        if trust_ca {
            roots.add(CertificateDer::from(CA)).expect("the fixture CA parses");
        }
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("the provider serves TLS 1.2 and 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();

        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let addr = listener.local_addr().expect("a bound listener has an address");
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().expect("the client connects");
            socket.set_read_timeout(Some(Duration::from_secs(10))).expect("a read timeout");
            let connection =
                ServerConnection::new(Arc::new(server_config)).expect("a server connection");
            let mut stream = StreamOwned::new(connection, socket);
            // A rejected certificate fails the handshake on the first read, so
            // the server's own error is not the signal here — the client decides.
            let mut request = [0u8; 4];
            if stream.read_exact(&mut request).is_ok() {
                let _ = stream.write_all(b"pong");
                let _ = stream.flush();
            }
        });

        let socket = TcpStream::connect(addr).expect("the local server is reachable");
        socket.set_read_timeout(Some(Duration::from_secs(10))).expect("a read timeout");
        let connection = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from("localhost").expect("a static server name"),
        )
        .expect("a client connection");
        let mut stream = StreamOwned::new(connection, socket);
        let reply = stream.write_all(b"ping").and_then(|()| {
            let mut reply = [0u8; 4];
            stream.read_exact(&mut reply).map(|()| reply)
        });
        let _ = server.join();

        match reply {
            Ok(reply) if reply == *b"pong" => Ok(()),
            Ok(_) => Err("the server answered something other than pong".to_string()),
            Err(err) => Err(err.to_string()),
        }
    }

    /// Every key type the provider can verify, end to end: the handshake covers
    /// `ecdsa-with-SHA256`, `rsa_pss_rsae_sha256` (TLS 1.3 with an RSA key) and
    /// Ed25519, i.e. one algorithm per verifier module the patch touched.
    #[test]
    fn verifying_handshake_accepts_the_fixture_chain() {
        for (name, leaf, key) in LEAVES {
            handshake(leaf, key, true).unwrap_or_else(|err| panic!("{name} leaf rejected: {err}"));
        }
    }

    /// The control for the test above: the same server, the same handshake, an
    /// empty root store. Without this, a client that accepted every certificate
    /// (the probes' `InsecureDpiCertVerifier`) would pass the positive test too.
    #[test]
    fn verifying_handshake_rejects_a_chain_whose_ca_is_not_trusted() {
        let (name, leaf, key) = LEAVES[0];
        let err = handshake(leaf, key, false)
            .expect_err("an untrusted chain must not verify");
        assert!(err.contains("UnknownIssuer"), "{name} leaf: {err}");
    }

    /// RFC 8446 §4.2.8.2 on the provider's own X25519 group, which is what every
    /// probe that negotiates X25519 uses. An all-zero share is a low-order point
    /// and its Diffie-Hellman output is the identity; x25519-dalek returns that
    /// as zeros and only *reports* `was_contributory`, so a provider that does
    /// not read the report completes a handshake on a secret the peer can
    /// predict. Upstream RustCrypto leaves it unread (0.0.2-alpha and `master`
    /// alike), which is why `vendor/rustls-rustcrypto` carries the check.
    ///
    /// `net::pq_kx`'s own two paths are covered by `rejects_a_low_order_x25519_share`.
    #[test]
    fn provider_x25519_group_rejects_a_low_order_peer_key() {
        let provider = crypto_provider();
        let group = provider
            .kx_groups
            .iter()
            .copied()
            .find(|group| group.name() == rustls::NamedGroup::X25519)
            .expect("the provider offers X25519");

        let active = group.start().expect("the group starts a key exchange");
        let err = match active.complete(&[0u8; 32]) {
            Ok(_) => panic!("a low-order peer key must be rejected"),
            Err(err) => err,
        };
        assert!(
            matches!(
                err,
                RustlsError::PeerMisbehaved(rustls::PeerMisbehaved::InvalidKeyShare)
            ),
            "unexpected error: {err:?}"
        );
    }
}
