use std::sync::{Arc, LazyLock, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{EchGreaseConfig, EchMode};
use rustls::crypto::hpke::Hpke;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme};

use crate::net::fingerprint::{HelloVariant, TlsFingerprint};
use crate::net::hpke;

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
    /// Verify the server certificate against the bundled Mozilla roots
    /// (`webpki-roots`) instead of accepting any certificate. The OS store is
    /// never read: the bundle is what ships, so the answer is the same on every
    /// platform and nothing a machine has installed changes it.
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
    #[must_use = "the profile is the shape the connection presents"]
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
    #[must_use = "the change is in the returned profile; the receiver is consumed"]
    pub fn tls13(mut self) -> Self {
        self.version = TlsVersion::Tls13;
        self
    }

    /// Offer TLS 1.2 only. Pinned the same way, and the same deviation:
    /// `[GREASE, 0x0303]` instead of a browser's `[GREASE, 0x0304, 0x0303]` —
    /// see [`TlsProfile::tls13`].
    #[must_use = "the change is in the returned profile; the receiver is consumed"]
    pub fn tls12(mut self) -> Self {
        self.version = TlsVersion::Tls12;
        self
    }

    /// Offer `alpn` instead of the profile's own list.
    #[must_use = "the change is in the returned profile; the receiver is consumed"]
    pub fn alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn = Some(alpn);
        self
    }

    /// Check the server certificate against the bundled Mozilla roots.
    ///
    /// The certificate is not the signal here: DoT, DoH and the HTTPS fetches
    /// have to reach a real server, so their configs verify. A chain that does
    /// not trace to the bundle fails with `UnknownIssuer`, which the classifier
    /// reports as `no_root_certificates` ("NO CA BUNDLE") — including when a
    /// root installed on the machine (an antivirus web-shield, a proxy) signed
    /// the certificate in the middle, because that root is in the OS store and
    /// not here.
    #[must_use = "the profile is the shape the connection presents"]
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
/// Verifying profiles are built once per shape and shared (`verifying_config`);
/// insecure ones are built per call, because they cost no root store and a
/// private resumption store per config is what keeps one probe's session ticket
/// out of the next probe's ClientHello.
#[must_use = "the returned config is the shape every connection built from it presents"]
pub fn create_tls_config(profile: &TlsProfile) -> Arc<ClientConfig> {
    if profile.verify {
        verifying_config(profile)
    } else {
        Arc::new(build_config(profile))
    }
}

/// The config [`create_tls_config`] builds, with `variant` applied to its
/// ClientHello.
///
/// A verifying profile's config is cached and shared, so an edit copies it into
/// an owned one: a variant is private to the run that asked for it and must not
/// reach the next connection that presents the same shape.
#[must_use = "the returned config is the shape every connection built from it presents"]
pub fn create_tls_config_variant(
    profile: &TlsProfile,
    variant: Option<&HelloVariant>,
) -> Arc<ClientConfig> {
    let config = create_tls_config(profile);
    let Some(variant) = variant else {
        return config;
    };
    let mut edited = (*config).clone();
    crate::net::fingerprint::install_variant(&mut edited, variant);
    Arc::new(edited)
}

/// The ClientHello `profile` puts on the wire, record header included.
///
/// The same factory the probes use, so a caller hashes what goes out rather than
/// a re-derivation of it: the profile's lists, the version trim, the GREASE ECH
/// body drawn for this hello, the padding the floor asks for. It is what
/// `examples/tls_fingerprint` prints and what [`hello_ja4_variants`] hashes.
///
/// The SNI is a fixed name (`example.com`), the same one the harness uses when
/// it captures bytes: it is the only field a profile takes from the domain, and
/// its length moves the padding.
#[must_use = "the returned bytes are the ClientHello a caller hashes or dials with"]
pub fn hello_record(profile: &TlsProfile) -> Vec<u8> {
    hello_record_with(profile, None)
}

/// The ClientHello `profile` puts on the wire with `variant` applied, record
/// header included.
///
/// What [`hello_record`] is for the shape as it stands, this is for the shape
/// with one field moved: the bytes a variant actually sends, so a caller can
/// assert the edit landed rather than trust that it did.
#[must_use = "the returned bytes are the ClientHello a caller hashes or dials with"]
pub fn hello_record_with(profile: &TlsProfile, variant: Option<&HelloVariant>) -> Vec<u8> {
    hello_record_for(profile, variant, "example.com")
}

/// The ClientHello `profile` puts on the wire for the name `sni`, record header
/// included.
///
/// The name is the only field a profile takes from the domain, and it is not
/// cosmetic: its length moves the padding a shape pads to, so a capture made
/// against one host is not the capture another host would see. A replay has to
/// carry the name of the host it is dialled at, or it is answering a different
/// question than the run it is compared with.
#[must_use = "the returned bytes are the ClientHello a caller hashes or dials with"]
pub fn hello_record_for(profile: &TlsProfile, variant: Option<&HelloVariant>, sni: &str) -> Vec<u8> {
    let config = create_tls_config_variant(profile, variant);
    // Every product caller reaches this through `hello_record`/`hello_record_with`,
    // whose SNI is the constant `example.com`; only the `examples` harness passes
    // a name from its own argv. A name that cannot be dialled is therefore a
    // caller bug the harness hits first, not an input this tool can receive.
    let name = ServerName::try_from(sni.to_string()).expect("a name to dial");
    let mut conn = rustls::ClientConnection::new(config, name).expect("a client connection");
    let mut buf = Vec::new();
    conn.write_tls(&mut buf).expect("a ClientHello is the first flight");
    buf
}

/// The JA4 strings `fingerprint` can send on its own offer.
///
/// JA4 sorts the cipher and extension sets before hashing, so it is the stable
/// key a matcher can carry: every shape answers with one string, and the two
/// whose hello can fall under the 512-byte floor BoringSSL pads to answer with
/// two. `chrome123` and `chrome131android` are those two — their GREASE ECH body
/// is drawn from four lengths per connection and only the shortest leaves the
/// hello below the floor, so the padding extension is there on some connections
/// and not on others (measured: `t13d1517h2_…b1ff8ab2d16f` padded,
/// `t13d1516h2_…02713d6af862` not). The draw is per connection, so the list is
/// collected by building the hello until both appear or `JA4_BUILDS` samples
/// have run; for every other shape the first build is the whole answer, which is
/// what `hello_can_vary` decides — the loop's own exit tests the strings, so
/// on its own it would build the same hello `JA4_BUILDS` times over.
///
/// JA3 is deliberately not reported: a shape that shuffles its extension order
/// has no single JA3 by construction (see `TlsShape::permute_extensions`).
pub fn hello_ja4_variants(fingerprint: TlsFingerprint) -> Vec<String> {
    let profile = TlsProfile::insecure(fingerprint);
    let builds = if hello_can_vary(fingerprint) { JA4_BUILDS } else { 1 };
    let mut seen: Vec<String> = Vec::new();
    for _ in 0..builds {
        let ja4 = crate::net::ja4::client_hello_ja4(&hello_record(&profile));
        if !seen.contains(&ja4) {
            seen.push(ja4);
        }
        if seen.len() > 1 {
            break;
        }
    }
    seen.sort();
    seen
}

/// Whether two connections presenting `fingerprint` can put different JA4s on
/// the wire, i.e. whether [`hello_ja4_variants`] has to sample at all.
///
/// Only the padding extension can enter or leave a hello: JA4 hashes the sorted
/// extension *set* (and its count) with the GREASE values filtered out, so the
/// extension order, the GREASE slots, the random and the ECH body's own bytes
/// move without reaching it, and the encoder emits padding only when the message
/// would otherwise land under the shape's declared floor (`padding_to`; `None`
/// for every shape that never pads, and the field is inert unless the order
/// names extension 21). A shape therefore needs both halves — a floor to fall
/// under, and a hello whose *length* is drawn per connection. The only such draw
/// in this build is the GREASE ECH body (four lengths, 128–224 bytes; see
/// `fingerprint::sends_ech`), which is exactly why `chrome123` and
/// `chrome131android`, the two shapes that declare a floor *and* carry ECH, are
/// the two the doc comment above names.
///
/// Both halves are necessary, so the gate cannot miss a variant; it can only
/// over-approximate, and then the samples are the price. Neither half alone is
/// enough: `sends_ech` is true for nine shapes, and seven of them declare no
/// floor, so their drawn body length never reaches JA4.
fn hello_can_vary(fingerprint: TlsFingerprint) -> bool {
    if !crate::net::fingerprint::sends_ech(fingerprint) {
        return false;
    }
    crate::net::fingerprint::hello_profile(fingerprint)
        .is_some_and(|hello| hello.padding_to.is_some())
}

/// How many hellos [`hello_ja4_variants`] may build before it settles for what it
/// has seen. A varied shape needs both of its strings, and the rarer one is the
/// padded hello — one connection in four — so 32 samples miss it with
/// probability below 2·10⁻⁴; no shape has more than two (only the padding
/// extension can appear and disappear, and JA4 ignores everything else that
/// moves). Only the shapes `hello_can_vary` names spend it; every other shape
/// builds one hello.
const JA4_BUILDS: usize = 32;

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
    // The nine shapes whose client sends `encrypted_client_hello` carry it as
    // GREASE (see `fingerprint::sends_ech`). `with_ech_mode`, not upstream's
    // `with_ech`: the latter would drop the profile's TLS 1.2 fallback out of the
    // offer, and Chrome 120's own hello keeps it.
    //
    // The placeholder key is never on the wire — each connection encapsulates to
    // it afresh, which is why two greased hellos never share a body — but it has
    // to be a real X25519 public key for that encapsulation to run.
    let builder = if crate::net::fingerprint::sends_ech(profile.fingerprint) {
        let (placeholder, _) = hpke::AES_128_GCM
            .generate_key_pair()
            .expect("the provider serves X25519");
        builder.with_ech_mode(EchMode::Grease(EchGreaseConfig::new(
            &hpke::AES_128_GCM,
            placeholder,
        )))
    } else {
        builder
    };

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

    // A shape that advertises a stateful application extension — ALPS (17513 or
    // 17613) or `channel_id` (30032) — is owed a follow-up message by any server
    // that acknowledges it, and the patched rustls sends what the hook returns
    // ahead of the Finished (see `vendor/rustls/README-PATCH.md`). A shape that
    // advertises neither gets no hook: it can never be acknowledged, and a hook
    // that answered an unsolicited acknowledgement would put a message on the
    // wire the server never asked for.
    config.client_follow_up = config
        .hello_profile
        .as_ref()
        .and_then(|hello| {
            let advertised: Vec<u16> = hello
                .raw_extensions
                .iter()
                .map(|(ext, _)| *ext)
                .collect();
            crate::net::follow_up::ProbeFollowUp::for_shape(&advertised)
        })
        .map(|follow_up| Arc::new(follow_up) as Arc<dyn rustls::client::ClientFollowUp>);
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

    /// A shape's JA4 is what a matcher that carries a list of keys reads, so the
    /// two shapes measured as blocked and as passed must answer with the strings
    /// the measurements named. `chrome107`, `chrome116`, `chrome99android` and
    /// `edge101` are four different hellos — one of them reshuffles its
    /// extensions every connection — and one key: that is what makes the four
    /// rows of the burst table one entry for a censor.
    #[test]
    fn the_chrome_generation_without_ech_is_one_ja4() {
        const PRE_ECH: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";
        for fingerprint in [
            TlsFingerprint::Chrome107,
            TlsFingerprint::Chrome116,
            TlsFingerprint::Chrome99Android,
            TlsFingerprint::Edge101,
        ] {
            assert_eq!(
                hello_ja4_variants(fingerprint),
                vec![PRE_ECH.to_string()],
                "{}",
                fingerprint.code()
            );
        }
    }

    /// Only the padding floor can add a second string, and only two shapes can
    /// reach it: the ones that carry a GREASE ECH body whose length decides
    /// whether the hello lands under 512 bytes. Every other profile answers with
    /// exactly one, and every string is a well-formed JA4 — the shape of the key
    /// the legend prints and a matcher would carry.
    #[test]
    fn only_the_padding_floor_adds_a_second_ja4() {
        const PADDED: &str = "t13d1517h2_8daaf6152771_b1ff8ab2d16f";
        const SIBLING: &str = "t13d1516h2_8daaf6152771_02713d6af862";

        for fingerprint in TlsFingerprint::ALL {
            let variants = hello_ja4_variants(fingerprint);
            assert!(!variants.is_empty(), "{}", fingerprint.code());
            for ja4 in &variants {
                assert!(ja4_shaped(ja4), "{}: {ja4}", fingerprint.code());
            }
            let expected_two = matches!(
                fingerprint,
                TlsFingerprint::Chrome123 | TlsFingerprint::Chrome131Android
            );
            assert_eq!(
                variants.len(),
                if expected_two { 2 } else { 1 },
                "{}: {variants:?}",
                fingerprint.code()
            );
            if expected_two {
                assert_eq!(variants, vec![SIBLING.to_string(), PADDED.to_string()]);
            }
        }
    }

    /// `t13d1516h2_8daaf6152771_e5627efa2ab1`: protocol and version, the SNI and
    /// the counts, ALPN, then the two 12-hex hashes. Asserted by shape rather than
    /// by regex so the check needs no dependency.
    fn ja4_shaped(value: &str) -> bool {
        let fields: Vec<&str> = value.split('_').collect();
        let [prefix, ciphers, extensions] = fields.as_slice() else {
            return false;
        };
        let bytes = prefix.as_bytes();
        bytes.len() == 10
            && bytes[0] == b't'
            && matches!(&prefix[1..3], "13" | "12")
            && matches!(bytes[3], b'd' | b'i')
            && prefix[4..8].bytes().all(|c| c.is_ascii_digit())
            && prefix[8..10].bytes().all(|c| c.is_ascii_alphanumeric())
            && ciphers.len() == 12
            && extensions.len() == 12
            && ciphers.bytes().chain(extensions.bytes()).all(|c| c.is_ascii_hexdigit())
    }
}
