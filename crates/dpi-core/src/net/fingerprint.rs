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
    /// `curl-impersonate` profile (`curl_chrome116`, `curl_safari184`, …), so a
    /// `curl_*` name is accepted and mapped to the family whose JA3 it sends —
    /// `chrome99..116` and `edge99,101` are one JA3, `safari15.5..18.4` another.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim().to_ascii_lowercase();
        if value.starts_with("curl_chrome") || value.starts_with("curl_edge") {
            return Some(Self::Chrome);
        }
        if value.starts_with("curl_safari") {
            return Some(Self::Safari);
        }
        match value.as_str() {
            "rustls" | "default" | "none" => Some(Self::Rustls),
            "custom" | "firefox" | "firefox-like" => Some(Self::Custom),
            "chrome" | "chrome99" | "chrome116" => Some(Self::Chrome),
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

/// Firefox 148's extension list minus `encrypted_client_hello` (65037).
///
/// Measured 2026-09-10: a synthesized GREASE ECH body — well formed per
/// draft-ietf-tls-esni with self-consistent lengths, `config_id` tried at 0, 1
/// and 255 — makes `cloudflare.com`, `www.google.com` and `dns.google` answer
/// `fatal alert: DecodeError`: those servers implement ECH and only tolerate a
/// payload they can decrypt. Since a probe that cannot complete a handshake with
/// Google would report its own artifact as censorship, the extension is left out.
/// The price is one extension of fidelity — JA4 shows 14 extensions where a real
/// Firefox 148 sends 15.
fn firefox_like() -> ClientHelloProfile {
    ClientHelloProfile {
        // Firefox 148 order, GREASE-free (Firefox does not grease).
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
            EXT_ALPN,
            EXT_STATUS_REQUEST,
            EXT_DELEGATED_CREDENTIALS,
            EXT_SCT,
            EXT_KEY_SHARE,
            EXT_SUPPORTED_VERSIONS,
            EXT_SIGNATURE_ALGORITHMS,
            EXT_RECORD_SIZE_LIMIT,
            EXT_COMPRESS_CERTIFICATE,
        ]),
        raw_extensions: vec![
            // Empty renegotiated_connection vector.
            (EXT_RENEGOTIATION_INFO, vec![0x00]),
            // delegated_credentials: signature-scheme list, ECDSA only.
            (EXT_DELEGATED_CREDENTIALS, vec![0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03]),
            // signed_certificate_timestamp in the ClientHello is empty.
            (EXT_SCT, Vec::new()),
            // record_size_limit: RFC 8449, 0x4001 as Firefox sends it.
            (EXT_RECORD_SIZE_LIMIT, vec![0x40, 0x01]),
            // ec_point_formats fallback: rustls derives it from the provider's
            // groups, which need not include every advertised curve.
            (EXT_EC_POINT_FORMATS, vec![0x01, 0x00]),
        ],
        // rustls sends these two; Firefox 148 does not. Without suppressing
        // them the extension set — and with it the JA4 count and hash — differs.
        suppress_extensions: vec![EXT_SESSION_TICKET, EXT_PSK_KEY_EXCHANGE_MODES],
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
        // Deliberately http/1.1 only, not Firefox's `[h2, http/1.1]`.
        // The probes speak HTTP/1.1 (hyper's http1 client): offering h2 makes
        // every h2-capable server select it and the request then dies, which the
        // report would show as censorship that is really our own protocol
        // mismatch. JA3 is unaffected — it hashes extension *types*, not ALPN
        // values, so the extension-16 entry still matches Firefox. JA4's ALPN
        // field reads "h1" instead of "h2"; restoring that needs an h2-capable
        // probe path, not a different profile.
        alpn: Some(vec![b"http/1.1".to_vec()]),
        // zlib, brotli — the two this build can actually decompress (`zstd` is
        // not a rustls feature; advertising it would invite a CompressedCertificate
        // we cannot read). The algorithm *list* is not part of JA3/JA4, only the
        // presence of extension 27 is.
        cert_compression: Some(vec![1, 2]),
        grease: false,
        // uTLS's Firefox hello carries no padding extension; the live JA3 this
        // profile was verified against (peet.ws, 14 extensions) has none either.
        padding_to: None,
    }
}

/// The `curl_chrome99..116` / `curl_edge99,101` shape.
///
/// Taken from `tests/signatures/chrome_116.0.5845.180_win10.yaml` of
/// `lexiforest/curl-impersonate` — the fixture that project verifies its own
/// builds against. All ten of those profiles emit the *same* JA3, so one profile
/// reproduces the whole deterministic half of the fingerprint list the forum
/// report attributes to TSPU; `chrome119..131` emit the same extension *set*
/// with the order shuffled, which is why those are reported as blocking only
/// ~8–30% of the time.
///
/// Deliberate deviations: ALPN is `http/1.1` instead of `h2, http/1.1` (the
/// probes speak HTTP/1.1, and JA3 hashes extension types, not ALPN values — see
/// [`firefox_like`]), there is no ECH (Chrome 116 predates it) and no GREASE
/// *version* entry (rustls builds `supported_versions` from the config, and
/// versions are not hashed).
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
            // ALPS: one protocol, h2.
            (EXT_APPLICATION_SETTINGS, vec![0x00, 0x03, 0x02, b'h', b'2']),
            // Padding: rustls computes the body so the hello reaches 512 bytes,
            // the way BoringSSL does. Only its presence enters JA3.
            (EXT_PADDING, Vec::new()),
        ],
        // Chrome sends session_ticket and psk_key_exchange_modes, so nothing is
        // suppressed — the difference from rustls' defaults is additive.
        suppress_extensions: Vec::new(),
        // Deliberately http/1.1 only, as in [`firefox_like`].
        alpn: Some(vec![b"http/1.1".to_vec()]),
        // brotli, exactly what Chrome 116 advertises.
        cert_compression: Some(vec![2]),
        grease: true,
        padding_to: Some(512),
    }
}

/// The `curl_safari15.5..18.4` shape.
///
/// Taken from `tests/signatures/safari_18.4_macOS.yaml` of
/// `lexiforest/curl-impersonate`. All seven Safari profiles in the reported
/// trigger list emit this same JA3. Safari differs from Chrome in ways a profile
/// has to reproduce: 20 ciphers (CBC-heavy), five groups, a duplicated
/// `RSA-PSS SHA-384` signature scheme, no `session_ticket`, no ALPS, and zlib
/// rather than brotli for certificate compression.
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
        // Deliberately http/1.1 only, as in [`firefox_like`].
        alpn: Some(vec![b"http/1.1".to_vec()]),
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
        // The names the fingerprint-blocking report uses are accepted directly.
        assert_eq!(
            TlsFingerprint::parse("curl_chrome116"),
            Some(TlsFingerprint::Chrome)
        );
        assert_eq!(
            TlsFingerprint::parse("curl_edge101"),
            Some(TlsFingerprint::Chrome)
        );
        assert_eq!(
            TlsFingerprint::parse("curl_safari184_ios"),
            Some(TlsFingerprint::Safari)
        );
        assert_eq!(TlsFingerprint::parse("curl_firefox147"), None);
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
        assert_eq!(TlsFingerprint::parse_list("curl_chrome116").0, vec![TlsFingerprint::Chrome]);
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

    /// The profile must describe Firefox 148: 17 ciphers, its extension order
    /// (minus the omitted ECH grease), the hybrid group first, and rustls'
    /// extras suppressed.
    #[test]
    fn custom_profile_matches_firefox_148_shape() {
        let profile = custom_profile();

        assert_eq!(profile.cipher_suites.as_ref().map(|c| c.len()), Some(17));
        assert_eq!(profile.groups.as_ref().and_then(|g| g.first()), Some(&4588));

        let order = profile.extension_order.as_ref().expect("extension order");
        assert_eq!(order.len(), 14);
        assert_eq!(order.first(), Some(&EXT_SERVER_NAME));
        assert_eq!(order.last(), Some(&EXT_COMPRESS_CERTIFICATE));
        assert!(order.contains(&EXT_RENEGOTIATION_INFO));
        assert!(order.contains(&EXT_DELEGATED_CREDENTIALS));
        assert!(order.contains(&EXT_SCT));

        assert!(profile.suppress_extensions.contains(&EXT_SESSION_TICKET));
        assert!(profile.suppress_extensions.contains(&EXT_PSK_KEY_EXCHANGE_MODES));
        assert!(!profile.grease);

        // Probes speak HTTP/1.1; offering h2 would make servers select a
        // protocol the probe client cannot speak. JA3 hashes extension types,
        // so this does not affect JA3 parity.
        assert_eq!(profile.alpn.as_deref(), Some(&[b"http/1.1".to_vec()][..]));
    }

    /// The JA3 (and size) of the hello a profile actually writes.
    fn client_hello_of(fingerprint: TlsFingerprint) -> (String, usize) {
        let config = (*crate::net::tls::create_insecure_dpi_tls_config_with(fingerprint)).clone();
        let name = rustls::pki_types::ServerName::try_from("example.com").expect("valid name");
        let mut conn = rustls::ClientConnection::new(Arc::new(config), name).expect("client conn");
        let mut buf = Vec::new();
        conn.write_tls(&mut buf).expect("write ClientHello");
        (crate::net::ja3::client_hello_ja3(&buf), buf.len() - 5)
    }

    /// The two curl families must send exactly the JA3 the report attributes to
    /// TSPU's trigger list, computed here from the `curl-impersonate` fixtures
    /// (`tests/signatures/*.yaml`): all ten blocked chrome/edge profiles carry
    /// the first string, all seven safari profiles the second.
    ///
    /// Anything that changes these — an extension added or dropped, a cipher
    /// reordered, the padding extension lost — makes the profile stop
    /// reproducing the fingerprint the censor is reported to match on.
    #[test]
    fn curl_family_profiles_match_their_reported_ja3() {
        let (chrome_ja3, chrome_len) = client_hello_of(TlsFingerprint::Chrome);
        assert_eq!(
            chrome_ja3,
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,\
             0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
        );
        // BoringSSL pads a browser hello to 512 bytes; the padding extension is
        // part of the JA3 above, so a lost pad shows up as a missing "-21".
        assert!((512..768).contains(&chrome_len), "chrome hello: {chrome_len} bytes");

        let (safari_ja3, safari_len) = client_hello_of(TlsFingerprint::Safari);
        assert_eq!(
            safari_ja3,
            "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-\
             157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0"
        );
        assert!((512..768).contains(&safari_len), "safari hello: {safari_len} bytes");
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
