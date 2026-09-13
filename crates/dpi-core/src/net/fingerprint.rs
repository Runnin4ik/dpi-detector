//! TLS fingerprint profiles: the ClientHello shape a probe presents.
//!
//! # Why this exists
//!
//! Russian censorship (see the "сибирское ограничение" scheme) classifies TLS
//! clients by their ClientHello: Chrome/Safari/iOS-shaped fingerprints are
//! treated as suspicious, Firefox-shaped ones usually are not. A detector that
//! only ever presents one shape — rustls' own — cannot tell whether a block it
//! observes is caused by the destination or by its own fingerprint.
//!
//! Four profiles:
//!
//! * [`TlsFingerprint::Rustls`] — the untouched default. Every measurement the
//!   tool has ever taken was taken with this, so it stays the baseline.
//! * [`TlsFingerprint::Custom`] — a Firefox-148-shaped ClientHello. The shape is
//!   taken from uTLS `HelloFirefox_148` (the profile Xray/REALITY clients
//!   present), including its post-quantum key share.
//! * [`TlsFingerprint::Chrome`] / [`TlsFingerprint::Safari`] — the shapes the
//!   Russian TSPU has been *reported* to block: the JA3s of the `curl-impersonate`
//!   profiles `curl_chrome99..116` / `curl_edge99,101` (one identical JA3) and
//!   `curl_safari15.5..18.4` (another). They exist to answer "is this site
//!   blocked for me, or only for clients that look like curl?" — see
//!   [`chrome_like`] for the exact provenance and the one deviation.
//!
//! The blocked/not-blocked framing from the forum report is why both directions
//! exist: `chrome`/`safari` are the reported *triggers*, `custom` is the
//! Firefox-shaped client that reportedly is not, and `rustls` is the control.
//!
//! # What "shape" means here
//!
//! Cipher-suite list and order, `supported_groups`, `signature_algorithms`,
//! ALPN (http/1.1 only — see [`firefox_like`]), exact extension order,
//! extensions rustls does not normally emit, and the hybrid `X25519MLKEM768`
//! group. That is what JA3 and JA4 hash.
//!
//! It is **not** a byte-for-byte browser. ECH is omitted entirely (see
//! [`firefox_like`] — synthesizing it makes Google and Cloudflare abort the
//! handshake), record-layer splitting is rustls', and there is no ALPS and no
//! HTTP/2 fingerprint. A censor matching on JA3/JA4 sees a Firefox-shaped
//! client; one matching on peetprint, HTTP/2 settings or record timing can still
//! tell the difference. The report says so.

use std::sync::{Arc, LazyLock};

use rustls::client::hello_profile::GREASE_EXTENSION_MARKER;
use rustls::client::ClientHelloProfile;
use rustls::ClientConfig;


/// Which ClientHello shape the probes present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsFingerprint {
    /// Untouched rustls: the historical baseline.
    #[default]
    Rustls,
    /// Firefox-148-shaped (uTLS `HelloFirefox_148`).
    Custom,
    /// `curl_chrome99..116` / `curl_edge99,101`-shaped (reported TSPU trigger).
    Chrome,
    /// `curl_safari15.5..18.4`-shaped (reported TSPU trigger).
    Safari,
}

/// One selectable profile: its display strings.
///
/// Adding a profile means adding a row here plus its data function — nothing
/// else enumerates the variants.
struct Spec {
    id: TlsFingerprint,
    token: &'static str,
    code: &'static str,
}

const SPECS: [Spec; 4] = [
    Spec {
        id: TlsFingerprint::Rustls,
        token: "RUSTLS",
        code: "rustls",
    },
    Spec {
        id: TlsFingerprint::Custom,
        token: "FIREFOX",
        code: "custom",
    },
    Spec {
        id: TlsFingerprint::Chrome,
        token: "CHROME",
        code: "chrome",
    },
    Spec {
        id: TlsFingerprint::Safari,
        token: "SAFARI",
        code: "safari",
    },
];

impl TlsFingerprint {
    fn spec(self) -> &'static Spec {
        SPECS
            .iter()
            .find(|spec| spec.id == self)
            .expect("every variant has a spec row")
    }

    /// Canonical uppercase token for tables and logs. Never translated (rule 4).
    pub fn token(self) -> &'static str {
        self.spec().token
    }

    /// Stable value for machine JSON and the config file.
    pub fn code(self) -> &'static str {
        self.spec().code
    }

    /// Parses a configured value. `None` for anything unknown, so callers can
    /// warn and fall back instead of silently changing what gets measured.
    ///
    /// The forum that reported the TSPU fingerprints names them after the
    /// `curl-impersonate` profile, so those names are accepted — but only the
    /// ones whose shape this build actually reproduces: `curl_chrome99..107` and
    /// `curl_edge99,101` are one JA3, `curl_safari155..184` another, and
    /// `curl_firefox133` is the Firefox one. `curl_chrome110+` (shuffled
    /// extension order), `curl_safari260` (post-quantum group) and
    /// `curl_firefox135+` (signed certificate timestamps) describe shapes no
    /// profile here sends, so they are rejected rather than mapped to a
    /// neighbouring one.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim().to_ascii_lowercase();
        if let Some(version) = curl_version(&value, "curl_chrome").or_else(|| curl_version(&value, "curl_edge"))
        {
            return (version <= 107).then_some(Self::Chrome);
        }
        if let Some(version) = curl_version(&value, "curl_safari") {
            return matches!(version, 155 | 170 | 172 | 180 | 184).then_some(Self::Safari);
        }
        if let Some(version) = curl_version(&value, "curl_firefox") {
            return (version == 133).then_some(Self::Custom);
        }
        match value.as_str() {
            "rustls" | "default" | "none" => Some(Self::Rustls),
            "custom" | "firefox" | "firefox-like" | "firefox133" => Some(Self::Custom),
            "chrome" | "chrome99" | "chrome107" => Some(Self::Chrome),
            "safari" | "safari155" | "safari184" => Some(Self::Safari),
            _ => None,
        }
    }

    /// Values accepted by the config validator and the CLI.
    pub const ALL: [TlsFingerprint; 4] = [
        Self::Rustls,
        Self::Custom,
        Self::Chrome,
        Self::Safari,
    ];

    /// Parses a profile list for test 7: `all`, or comma/space separated names
    /// (including the `curl_*` aliases). Unknown tokens come back separately so
    /// the caller can warn instead of silently running a different test than the
    /// one that was asked for; an empty or all-unknown list means `all`.
    pub fn parse_list(value: &str) -> (Vec<Self>, Vec<String>) {
        let mut out: Vec<Self> = Vec::new();
        let mut unknown: Vec<String> = Vec::new();
        let mut all = false;
        for token in value.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if token.eq_ignore_ascii_case("all") {
                all = true;
                continue;
            }
            match Self::parse(token) {
                Some(fingerprint) => {
                    if !out.contains(&fingerprint) {
                        out.push(fingerprint);
                    }
                }
                None => unknown.push(token.to_string()),
            }
        }
        if all || out.is_empty() {
            out = Self::ALL.to_vec();
            if !all {
                // Nothing recognised at all is a mistake, not a request for all.
                unknown.clear();
                unknown.push(value.trim().to_string());
            }
        }
        (out, unknown)
    }
}

impl std::fmt::Display for TlsFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

/// The custom ClientHello shape, built once.
///
/// Derived from uTLS `HelloFirefox_148` (`u_parrots.go`), the definition Xray
/// uses for its `firefox` profile. Where rustls already emits an extension the
/// profile only fixes its position; where rustls has no field for it (SCT,
/// secure renegotiation, delegated credentials, record size limit, GREASE ECH)
/// the body is supplied verbatim.
pub fn custom_profile() -> Arc<ClientHelloProfile> {
    static PROFILE: LazyLock<Arc<ClientHelloProfile>> = LazyLock::new(|| Arc::new(firefox_like()));
    PROFILE.clone()
}

/// The `curl_chrome99..116` / `curl_edge99,101` shape, built once.
pub fn chrome_profile() -> Arc<ClientHelloProfile> {
    static PROFILE: LazyLock<Arc<ClientHelloProfile>> = LazyLock::new(|| Arc::new(chrome_like()));
    PROFILE.clone()
}

/// The `curl_safari15.5..18.4` shape, built once.
pub fn safari_profile() -> Arc<ClientHelloProfile> {
    static PROFILE: LazyLock<Arc<ClientHelloProfile>> = LazyLock::new(|| Arc::new(safari_like()));
    PROFILE.clone()
}

/// The numeric version in a `curl_*` profile name, if it has one.
///
/// `curl_chrome107` → 107, `curl_safari184_ios` → 184, `curl_edge99` → 99,
/// `curl_chrome` → `None` (a name without a version is not a profile).
fn curl_version(value: &str, prefix: &str) -> Option<u16> {
    let rest = value.strip_prefix(prefix)?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    (!digits.is_empty()).then(|| digits.parse().ok()).flatten()
}

/// True when the profile needs the post-quantum provider, so the advertised
/// group list and the actual key share agree.
///
/// Only the Firefox profile: the curl shapes reproduce Chrome 99–116 / Safari
/// 15.5–18.4, both of which predate `X25519MLKEM768`, and adding a group the
/// original does not send would change the fingerprint we are reproducing.
pub fn needs_pq(fingerprint: TlsFingerprint) -> bool {
    matches!(fingerprint, TlsFingerprint::Custom)
}

/// True when this selection advertises `compress_certificate` (extension 27).
///
/// The `brotli`/`zlib` rustls features are enabled in this workspace only so that
/// a profile can both advertise the extension and decode what the server then
/// sends. With those features on, plain rustls would start advertising extension
/// 27 in *every* ClientHello — a silent change to the baseline fingerprint that
/// all previous measurements were taken with. Callers therefore clear
/// [`rustls::ClientConfig::cert_decompressors`] for the default profile,
/// restoring the exact wire shape the tool has always sent.
pub fn advertises_cert_compression(fingerprint: TlsFingerprint) -> bool {
    !matches!(fingerprint, TlsFingerprint::Rustls)
}

/// Installs the profile on a client config, if the selection has one.
pub fn apply(config: &mut ClientConfig, fingerprint: TlsFingerprint) {
    config.hello_profile = match fingerprint {
        TlsFingerprint::Rustls => None,
        TlsFingerprint::Custom => Some(custom_profile()),
        TlsFingerprint::Chrome => Some(chrome_profile()),
        TlsFingerprint::Safari => Some(safari_profile()),
    };
}

/// Firefox 133's extension list, as `curl_firefox133` of curl-impersonate
/// v2.2.2 sends it.
///
/// Where rustls already emits an extension the profile only fixes its position;
/// where rustls has no field for it (secure renegotiation, delegated
/// credentials, record size limit, session ticket, GREASE ECH) the body is
/// supplied verbatim.
///
/// This used to follow uTLS `HelloFirefox_148` (the Xray/REALITY parrot). The
/// pinned version is now the one this repository's reference bundle
/// (`curl-impersonate v2.2.2`) actually sends, which differs from the uTLS
/// parrot in three extensions: 133 carries `session_ticket` (35) and
/// `psk_key_exchange_modes` (45), which uTLS's Firefox does not, and it has no
/// `signed_certificate_timestamp` (18). See `bundle_versions_match_their_ja3`.
///
/// One deliberate deviation remains: `encrypted_client_hello` (65037) is left
/// out. uTLS's own GREASE ECH encrypts a fake inner hello with a fresh HPKE key,
/// and this build has no HPKE provider; every hand-built body tried so far — the
/// current one included, placed last exactly where Firefox puts it — makes
/// `cloudflare.com`, `www.google.com` and `dns.google` answer
/// `fatal alert: DecodeError` (`tls_fingerprint live custom`). Since Google and
/// Cloudflare front much of what this tool probes, sending a hello they abort
/// would report our own artifact as censorship. JA4 therefore shows 15
/// extensions where `curl_firefox133` sends 16.
fn firefox_like() -> ClientHelloProfile {
    ClientHelloProfile {
        // Firefox 133 order, GREASE-free (Firefox does not grease).
        cipher_suites: Some(vec![
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0xc02b, // ECDHE_ECDSA_AES128_GCM_SHA256
            0xc02f, // ECDHE_RSA_AES128_GCM_SHA256
            0xcca9, // ECDHE_ECDSA_CHACHA20_POLY1305
            0xcca8, // ECDHE_RSA_CHACHA20_POLY1305
            0xc02c, // ECDHE_ECDSA_AES256_GCM_SHA384
            0xc030, // ECDHE_RSA_AES256_GCM_SHA384
            0xc00a, // ECDHE_ECDSA_AES256_CBC_SHA
            0xc009, // ECDHE_ECDSA_AES128_CBC_SHA
            0xc013, // ECDHE_RSA_AES128_CBC_SHA
            0xc014, // ECDHE_RSA_AES256_CBC_SHA
            0x009c, // RSA_AES128_GCM_SHA256
            0x009d, // RSA_AES256_GCM_SHA384
            0x002f, // RSA_AES128_CBC_SHA
            0x0035, // RSA_AES256_CBC_SHA
        ]),
        groups: Some(vec![
            4588, // X25519MLKEM768
            29,   // X25519
            23,   // secp256r1
            24,   // secp384r1
            25,   // secp521r1
            256,  // ffdhe2048
            257,  // ffdhe3072
        ]),
        extension_order: Some(vec![
            EXT_SERVER_NAME,
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_SUPPORTED_GROUPS,
            EXT_EC_POINT_FORMATS,
            EXT_SESSION_TICKET,
            EXT_ALPN,
            EXT_STATUS_REQUEST,
            EXT_DELEGATED_CREDENTIALS,
            EXT_KEY_SHARE,
            EXT_SUPPORTED_VERSIONS,
            EXT_SIGNATURE_ALGORITHMS,
            EXT_PSK_KEY_EXCHANGE_MODES,
            EXT_RECORD_SIZE_LIMIT,
            EXT_COMPRESS_CERTIFICATE,
        ]),
        raw_extensions: vec![
            // Empty renegotiated_connection vector.
            (EXT_RENEGOTIATION_INFO, vec![0x00]),
            // delegated_credentials: signature-scheme list, ECDSA only.
            (EXT_DELEGATED_CREDENTIALS, vec![0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03]),
            // record_size_limit: RFC 8449, 0x4001 as Firefox sends it.
            (EXT_RECORD_SIZE_LIMIT, vec![0x40, 0x01]),
            // ec_point_formats fallback: rustls derives it from the provider's
            // groups, which need not include every advertised curve.
            (EXT_EC_POINT_FORMATS, vec![0x01, 0x00]),
            // session_ticket: empty in a fresh session, and rustls omits the
            // extension entirely from a TLS 1.3-only hello — Firefox sends it in
            // both, so the profile supplies it.
            (EXT_SESSION_TICKET, Vec::new()),
        ],
        // Nothing suppressed: 35 and 45 are part of Firefox 133's shape.
        suppress_extensions: Vec::new(),
        signature_schemes: Some(vec![
            0x0403, // ECDSA P-256 SHA-256
            0x0503, // ECDSA P-384 SHA-384
            0x0603, // ECDSA P-521 SHA-512
            0x0804, // RSA-PSS SHA-256
            0x0805, // RSA-PSS SHA-384
            0x0806, // RSA-PSS SHA-512
            0x0401, // RSA-PKCS1 SHA-256
            0x0501, // RSA-PKCS1 SHA-384
            0x0601, // RSA-PKCS1 SHA-512
            0x0203, // ECDSA SHA-1
            0x0201, // RSA-PKCS1 SHA-1
        ]),
        // `h2, http/1.1`, exactly what Firefox offers. The probes speak both:
        // they branch on the negotiated ALPN (see `probe::tls`).
        alpn: Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
        // zlib, brotli — the two this build can actually decompress (`zstd` is
        // not a rustls feature; advertising it would invite a CompressedCertificate
        // we cannot read). The algorithm *list* is not part of JA3/JA4, only the
        // presence of extension 27 is.
        cert_compression: Some(vec![1, 2]),
        grease: false,
        // Firefox sends no padding; the JA3 this profile is pinned to has none.
        padding_to: None,
    }
}

/// The `curl_chrome107` shape — Chrome 107 / Edge 99–101.
///
/// Taken from the `curl-impersonate v2.2.2` bundle this repository measures
/// against (`.bat` wrapper `curl_chrome107`), and identical to what
/// `curl_chrome99..104` and `curl_edge99,101` send: those emit the *same* JA3,
/// so one profile reproduces the whole deterministic half of the fingerprint
/// list the forum report attributes to TSPU. `chrome110` and later permute the
/// extension order (`--tls-permute-extensions`), and `chrome119+` add ECH, which
/// is why those are reported as blocking only ~8–30% of the time.
///
/// Deliberate deviations: no GREASE *version* entry (rustls builds
/// `supported_versions` from the config, and versions are not hashed) and no
/// `encrypted_client_hello` (Chrome 107 predates it). See
/// `bundle_versions_match_their_ja3`.
fn chrome_like() -> ClientHelloProfile {
    ClientHelloProfile {
        cipher_suites: Some(vec![
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0xc02b, // ECDHE_ECDSA_AES128_GCM_SHA256
            0xc02f, // ECDHE_RSA_AES128_GCM_SHA256
            0xc02c, // ECDHE_ECDSA_AES256_GCM_SHA384
            0xc030, // ECDHE_RSA_AES256_GCM_SHA384
            0xcca9, // ECDHE_ECDSA_CHACHA20_POLY1305
            0xcca8, // ECDHE_RSA_CHACHA20_POLY1305
            0xc013, // ECDHE_RSA_AES128_CBC_SHA
            0xc014, // ECDHE_RSA_AES256_CBC_SHA
            0x009c, // RSA_AES128_GCM_SHA256
            0x009d, // RSA_AES256_GCM_SHA384
            0x002f, // RSA_AES128_CBC_SHA
            0x0035, // RSA_AES256_CBC_SHA
        ]),
        groups: Some(vec![
            29, // X25519
            23, // secp256r1
            24, // secp384r1
        ]),
        signature_schemes: Some(vec![
            0x0403, // ECDSA P-256 SHA-256
            0x0804, // RSA-PSS SHA-256
            0x0401, // RSA-PKCS1 SHA-256
            0x0503, // ECDSA P-384 SHA-384
            0x0805, // RSA-PSS SHA-384
            0x0501, // RSA-PKCS1 SHA-384
            0x0806, // RSA-PSS SHA-512
            0x0601, // RSA-PKCS1 SHA-512
        ]),
        extension_order: Some(vec![
            GREASE_EXTENSION_MARKER,
            EXT_SERVER_NAME,
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_SUPPORTED_GROUPS,
            EXT_EC_POINT_FORMATS,
            EXT_SESSION_TICKET,
            EXT_ALPN,
            EXT_STATUS_REQUEST,
            EXT_SIGNATURE_ALGORITHMS,
            EXT_SCT,
            EXT_KEY_SHARE,
            EXT_PSK_KEY_EXCHANGE_MODES,
            EXT_SUPPORTED_VERSIONS,
            EXT_COMPRESS_CERTIFICATE,
            EXT_APPLICATION_SETTINGS,
            GREASE_EXTENSION_MARKER,
            EXT_PADDING,
        ]),
        raw_extensions: vec![
            // Empty renegotiated_connection vector.
            (EXT_RENEGOTIATION_INFO, vec![0x00]),
            // ec_point_formats: uncompressed only.
            (EXT_EC_POINT_FORMATS, vec![0x01, 0x00]),
            // signed_certificate_timestamp in the ClientHello is empty.
            (EXT_SCT, Vec::new()),
            // session_ticket: empty in a fresh session. rustls drops the
            // extension from a TLS 1.3-only hello, Chrome sends it in both, so
            // the profile supplies it — without this the TLS 1.3 column and test
            // 7 sent a Chrome hello with one extension less than Chrome's.
            (EXT_SESSION_TICKET, Vec::new()),
            // ALPS: one protocol, h2.
            (EXT_APPLICATION_SETTINGS, vec![0x00, 0x03, 0x02, b'h', b'2']),
            // Padding: rustls computes the body so the hello reaches 512 bytes,
            // the way BoringSSL does. Only its presence enters JA3.
            (EXT_PADDING, Vec::new()),
        ],
        // Chrome sends session_ticket and psk_key_exchange_modes, so nothing is
        // suppressed — the difference from rustls' defaults is additive.
        suppress_extensions: Vec::new(),
        // `h2, http/1.1`, exactly what Chrome offers; the probes branch on the
        // negotiated protocol (see `probe::tls`).
        alpn: Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
        // brotli, exactly what Chrome 116 advertises.
        cert_compression: Some(vec![2]),
        grease: true,
        padding_to: Some(512),
    }
}

/// The `curl_safari155` shape — Safari 15.5, and 15.5–18.4 alike.
///
/// Taken from the `curl-impersonate v2.2.2` bundle (`.bat` wrapper
/// `curl_safari155`); `curl_safari170`, `curl_safari172_ios`, `curl_safari180`,
/// `curl_safari180_ios`, `curl_safari184` and `curl_safari184_ios` all send the
/// identical JA3. Safari differs from Chrome in ways a profile has to
/// reproduce: 20 ciphers (CBC-heavy), four groups, a duplicated `RSA-PSS
/// SHA-384` signature scheme, no `session_ticket`, no ALPS, and zlib rather than
/// brotli for certificate compression. See `bundle_versions_match_their_ja3`.
fn safari_like() -> ClientHelloProfile {
    ClientHelloProfile {
        cipher_suites: Some(vec![
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0xc02c, // ECDHE_ECDSA_AES256_GCM_SHA384
            0xc02b, // ECDHE_ECDSA_AES128_GCM_SHA256
            0xcca9, // ECDHE_ECDSA_CHACHA20_POLY1305
            0xc030, // ECDHE_RSA_AES256_GCM_SHA384
            0xc02f, // ECDHE_RSA_AES128_GCM_SHA256
            0xcca8, // ECDHE_RSA_CHACHA20_POLY1305
            0xc00a, // ECDHE_ECDSA_AES256_CBC_SHA
            0xc009, // ECDHE_ECDSA_AES128_CBC_SHA
            0xc014, // ECDHE_RSA_AES256_CBC_SHA
            0xc013, // ECDHE_RSA_AES128_CBC_SHA
            0x009d, // RSA_AES256_GCM_SHA384
            0x009c, // RSA_AES128_GCM_SHA256
            0x0035, // RSA_AES256_CBC_SHA
            0x002f, // RSA_AES128_CBC_SHA
            0xc008, // ECDHE_ECDSA_3DES_EDE_CBC_SHA
            0xc012, // ECDHE_RSA_3DES_EDE_CBC_SHA
            0x000a, // RSA_3DES_EDE_CBC_SHA
        ]),
        groups: Some(vec![
            29, // X25519
            23, // secp256r1
            24, // secp384r1
            25, // secp521r1
        ]),
        signature_schemes: Some(vec![
            0x0403, // ECDSA P-256 SHA-256
            0x0804, // RSA-PSS SHA-256
            0x0401, // RSA-PKCS1 SHA-256
            0x0503, // ECDSA P-384 SHA-384
            0x0203, // ECDSA SHA-1 — Safari 15.5 sends it; JA3 ignores the list,
                    // JA4 hashes it, which is how its absence was caught
            0x0805, // RSA-PSS SHA-384
            0x0805, // duplicated by Safari itself
            0x0501, // RSA-PKCS1 SHA-384
            0x0806, // RSA-PSS SHA-512
            0x0601, // RSA-PKCS1 SHA-512
            0x0201, // RSA-PKCS1 SHA-1
        ]),
        extension_order: Some(vec![
            GREASE_EXTENSION_MARKER,
            EXT_SERVER_NAME,
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_SUPPORTED_GROUPS,
            EXT_EC_POINT_FORMATS,
            EXT_ALPN,
            EXT_STATUS_REQUEST,
            EXT_SIGNATURE_ALGORITHMS,
            EXT_SCT,
            EXT_KEY_SHARE,
            EXT_PSK_KEY_EXCHANGE_MODES,
            EXT_SUPPORTED_VERSIONS,
            EXT_COMPRESS_CERTIFICATE,
            GREASE_EXTENSION_MARKER,
            EXT_PADDING,
        ]),
        raw_extensions: vec![
            (EXT_RENEGOTIATION_INFO, vec![0x00]),
            (EXT_EC_POINT_FORMATS, vec![0x01, 0x00]),
            (EXT_SCT, Vec::new()),
            (EXT_PADDING, Vec::new()),
        ],
        // rustls sends session_ticket; Safari does not.
        suppress_extensions: vec![EXT_SESSION_TICKET],
        // `h2, http/1.1`, exactly what Safari offers; the probes branch on the
        // negotiated protocol (see `probe::tls`).
        alpn: Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
        // zlib, exactly what Safari advertises.
        cert_compression: Some(vec![1]),
        grease: true,
        padding_to: Some(512),
    }
}

/// Extension type ids referenced by the profiles above.
const EXT_SERVER_NAME: u16 = 0;
const EXT_STATUS_REQUEST: u16 = 5;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_SCT: u16 = 18;
const EXT_PADDING: u16 = 21;
const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
const EXT_COMPRESS_CERTIFICATE: u16 = 27;
const EXT_RECORD_SIZE_LIMIT: u16 = 28;
const EXT_DELEGATED_CREDENTIALS: u16 = 34;
const EXT_SESSION_TICKET: u16 = 35;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
const EXT_KEY_SHARE: u16 = 51;
const EXT_RENEGOTIATION_INFO: u16 = 65281;
/// Chrome's ALPS (draft-vvv-tls-alps); also 17513 in the fixtures.
const EXT_APPLICATION_SETTINGS: u16 = 17513;

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned from the `curl-impersonate v2.2.2` bundle (see
    /// [`tests::bundle_versions_match_their_ja4`]).
    const CHROME_107_JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";
    const SAFARI_155_JA4: &str = "t13d2014h2_a09f3c656075_14788d8d241b";
    const FIREFOX_133_JA4_LESS_ECH: &str = "t13d1715h2_5b57614c22b0_8fb63dbc839a";

    #[test]
    fn fingerprint_tokens_are_stable() {
        assert_eq!(TlsFingerprint::Rustls.token(), "RUSTLS");
        assert_eq!(TlsFingerprint::Custom.token(), "FIREFOX");
        assert_eq!(TlsFingerprint::Rustls.code(), "rustls");
        assert_eq!(TlsFingerprint::Custom.code(), "custom");
        assert_eq!(TlsFingerprint::default(), TlsFingerprint::Rustls);
    }

    #[test]
    fn fingerprint_parses_known_values_and_rejects_others() {
        assert_eq!(TlsFingerprint::parse("rustls"), Some(TlsFingerprint::Rustls));
        assert_eq!(TlsFingerprint::parse("CUSTOM"), Some(TlsFingerprint::Custom));
        assert_eq!(TlsFingerprint::parse(" firefox "), Some(TlsFingerprint::Custom));
        assert_eq!(TlsFingerprint::parse("chrome"), Some(TlsFingerprint::Chrome));
        assert_eq!(TlsFingerprint::parse("safari"), Some(TlsFingerprint::Safari));
        // The names the fingerprint-blocking report uses are accepted when the
        // shape is the one a profile here reproduces, and rejected otherwise.
        assert_eq!(
            TlsFingerprint::parse("curl_chrome107"),
            Some(TlsFingerprint::Chrome)
        );
        assert_eq!(
            TlsFingerprint::parse("curl_edge101"),
            Some(TlsFingerprint::Chrome)
        );
        assert_eq!(
            TlsFingerprint::parse("curl_safari155"),
            Some(TlsFingerprint::Safari)
        );
        assert_eq!(
            TlsFingerprint::parse("curl_safari184_ios"),
            Some(TlsFingerprint::Safari)
        );
        assert_eq!(
            TlsFingerprint::parse("curl_firefox133"),
            Some(TlsFingerprint::Custom)
        );
        // Shapes no profile sends: shuffled extension order, post-quantum
        // group, signed certificate timestamps.
        assert_eq!(TlsFingerprint::parse("curl_chrome116"), None);
        assert_eq!(TlsFingerprint::parse("curl_safari260"), None);
        assert_eq!(TlsFingerprint::parse("curl_firefox147"), None);
        assert_eq!(TlsFingerprint::parse("curl_firefox144"), None);
        assert_eq!(TlsFingerprint::parse(""), None);
    }

    /// Test 7 takes a *list* of profiles; `all` and the curl aliases must work,
    /// and an unrecognised token must be reported rather than silently swapped
    /// for a different set.
    #[test]
    fn fingerprint_list_parsing() {
        assert_eq!(TlsFingerprint::parse_list("all").0, TlsFingerprint::ALL.to_vec());
        assert_eq!(TlsFingerprint::parse_list("").0, TlsFingerprint::ALL.to_vec());
        assert_eq!(
            TlsFingerprint::parse_list("chrome, safari").0,
            vec![TlsFingerprint::Chrome, TlsFingerprint::Safari]
        );
        assert_eq!(TlsFingerprint::parse_list("curl_chrome107").0, vec![TlsFingerprint::Chrome]);
        // Duplicates collapse, order is kept.
        assert_eq!(
            TlsFingerprint::parse_list("safari safari rustls").0,
            vec![TlsFingerprint::Safari, TlsFingerprint::Rustls]
        );
        // Mixed: the known half runs, the rest is reported.
        let (known, unknown) = TlsFingerprint::parse_list("custom,bogus");
        assert_eq!(known, vec![TlsFingerprint::Custom]);
        assert_eq!(unknown, vec!["bogus".to_string()]);
        // Nothing recognised: fall back to all, still reporting what was wrong.
        let (known, unknown) = TlsFingerprint::parse_list("bogus");
        assert_eq!(known, TlsFingerprint::ALL.to_vec());
        assert_eq!(unknown, vec!["bogus".to_string()]);
        assert!(TlsFingerprint::parse_list("all").1.is_empty());
    }

    /// The profile must describe Firefox 133: 17 ciphers, the hybrid group
    /// first, its extension order (session_ticket and psk_key_exchange_modes in,
    /// signed_certificate_timestamp out), and nothing suppressed.
    #[test]
    fn custom_profile_matches_firefox_133_shape() {
        let profile = custom_profile();

        assert_eq!(profile.cipher_suites.as_ref().map(|c| c.len()), Some(17));
        assert_eq!(profile.groups.as_ref().and_then(|g| g.first()), Some(&4588));

        let order = profile.extension_order.as_ref().expect("extension order");
        assert_eq!(order.len(), 15);
        assert_eq!(order.first(), Some(&EXT_SERVER_NAME));
        assert_eq!(order.last(), Some(&EXT_COMPRESS_CERTIFICATE));
        assert!(order.contains(&EXT_RENEGOTIATION_INFO));
        assert!(order.contains(&EXT_DELEGATED_CREDENTIALS));
        assert!(order.contains(&EXT_RECORD_SIZE_LIMIT));
        assert!(order.contains(&EXT_SESSION_TICKET));
        assert!(order.contains(&EXT_PSK_KEY_EXCHANGE_MODES));
        assert!(!order.contains(&EXT_SCT), "Firefox 133 sends no SCT");
        // 65037 is the one extension curl_firefox133 has and this profile does
        // not: every hand-built GREASE ECH body was rejected by the ECH-aware
        // servers (see `firefox_like`).
        assert_eq!(order.iter().filter(|ext| **ext == 65037).count(), 0);

        assert!(profile.suppress_extensions.is_empty());
        assert!(!profile.grease);
        // Firefox offers both protocols, and so must the profile now that the
        // probes speak HTTP/2 as well.
        assert_eq!(
            profile.alpn.as_deref(),
            Some(&[b"h2".to_vec(), b"http/1.1".to_vec()][..])
        );
    }

    /// The JA3 (and size) of the hello a profile writes, on the builder the
    /// caller asks for: `tls13_only` is what the probes and test 7 use, the
    /// general one is what the tools and the earlier measurements used.
    fn client_hello_of(fingerprint: TlsFingerprint, tls13_only: bool) -> (String, usize) {
        let (ja3, length, _) = client_hello_full(fingerprint, tls13_only);
        (ja3, length)
    }

    /// The three fingerprints of the hello a profile writes on `tls13_only`:
    /// JA3, the hello size, and JA4.
    fn client_hello_full(fingerprint: TlsFingerprint, tls13_only: bool) -> (String, usize, String) {
        let config = if tls13_only {
            crate::net::tls::create_insecure_dpi_tls_config_tls13_with(fingerprint)
        } else {
            crate::net::tls::create_insecure_dpi_tls_config_with(fingerprint)
        };
        let name = rustls::pki_types::ServerName::try_from("example.com").expect("valid name");
        let mut conn = rustls::ClientConnection::new(config, name).expect("client conn");
        let mut buf = Vec::new();
        conn.write_tls(&mut buf).expect("write ClientHello");
        (
            crate::net::ja3::client_hello_ja3(&buf),
            buf.len() - 5,
            crate::net::ja4::client_hello_ja4(&buf),
        )
    }

    /// The three profiles must send exactly the JA3 their pinned
    /// `curl-impersonate` version sends, measured from the v2.2.2 bundle with a
    /// local ClientHello sniffer (`curl_chrome107`, `curl_safari155`,
    /// `curl_firefox133`).
    ///
    /// Anything that changes these — an extension added or dropped, a cipher
    /// reordered, the padding extension lost — makes the profile stop
    /// reproducing the fingerprint the censor is reported to match on. Both
    /// builders are checked because they used to disagree: rustls drops
    /// `session_ticket` from a TLS 1.3-only hello, which cost Chrome an
    /// extension in the very column the probes use.
    #[test]
    fn bundle_versions_match_their_ja3() {
        const CHROME_107: &str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-\
             49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0";
        const SAFARI_155: &str = "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-\
             49161-49172-49171-157-156-53-47-49160-49170-10,\
             0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0";
        // `curl_firefox133` sends `...,28-27-65037` — the profile stops at 27,
        // because a GREASE ECH body this build writes is rejected by every
        // ECH-aware server (see `firefox_like`).
        const FIREFOX_133: &str = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-\
             49161-49171-49172-156-157-47-53,\
             0-23-65281-10-11-35-16-5-34-51-43-13-45-28-27,4588-29-23-24-25-256-257,0";

        for tls13_only in [true, false] {
            assert_eq!(
                client_hello_of(TlsFingerprint::Chrome, tls13_only).0,
                CHROME_107,
                "chrome (tls13_only={tls13_only})"
            );
            assert_eq!(
                client_hello_of(TlsFingerprint::Safari, tls13_only).0,
                SAFARI_155,
                "safari (tls13_only={tls13_only})"
            );
            assert_eq!(
                client_hello_of(TlsFingerprint::Custom, tls13_only).0,
                FIREFOX_133,
                "firefox (tls13_only={tls13_only})"
            );
        }

        // BoringSSL pads a browser hello to exactly 512 bytes — the
        // `curl-impersonate v2.2.2` chrome107/safari155 hellos measure 512 — and
        // the padding extension is part of the JA3s above, so both the size and a
        // lost pad are checked here.
        for fingerprint in [TlsFingerprint::Chrome, TlsFingerprint::Safari] {
            for tls13_only in [true, false] {
                let (_, length) = client_hello_of(fingerprint, tls13_only);
                assert_eq!(length, 512, "{fingerprint} hello (tls13_only={tls13_only})");
            }
        }
    }

    /// JA4 hashes what JA3 cannot: the signature-algorithms list and the ALPN
    /// value. These are the values of the pinned bundle versions, computed from
    /// the ClientHellos the same sniffer captured (`curl_chrome107`,
    /// `curl_safari155`, `curl_firefox133`) and cross-checked against what
    /// `tls.peet.ws` reports for our own probes.
    ///
    /// Firefox's differs in the extension count and hash only, and only because
    /// of the omitted `encrypted_client_hello` (see [`firefox_like`]); the
    /// cipher hash is the bundle's.
    #[test]
    fn bundle_versions_match_their_ja4() {
        for tls13_only in [true, false] {
            let (_, _, chrome) = client_hello_full(TlsFingerprint::Chrome, tls13_only);
            assert_eq!(chrome, CHROME_107_JA4, "chrome (tls13_only={tls13_only})");
            let (_, _, safari) = client_hello_full(TlsFingerprint::Safari, tls13_only);
            assert_eq!(safari, SAFARI_155_JA4, "safari (tls13_only={tls13_only})");
            let (_, _, firefox) = client_hello_full(TlsFingerprint::Custom, tls13_only);
            assert_eq!(firefox, FIREFOX_133_JA4_LESS_ECH, "firefox (tls13_only={tls13_only})");
        }
    }

    /// The curl shapes predate post-quantum key exchange, so they must not be
    /// given the hybrid group — a group the original does not offer would change
    /// the fingerprint being reproduced.
    #[test]
    fn curl_family_profiles_do_not_use_the_pq_provider() {
        assert!(!needs_pq(TlsFingerprint::Chrome));
        assert!(!needs_pq(TlsFingerprint::Safari));
        assert!(needs_pq(TlsFingerprint::Custom));
        assert!(advertises_cert_compression(TlsFingerprint::Chrome));
        assert!(advertises_cert_compression(TlsFingerprint::Safari));
        assert!(!advertises_cert_compression(TlsFingerprint::Rustls));
    }
}
