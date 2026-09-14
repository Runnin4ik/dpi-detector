//! Fingerprint profiles: the TLS and HTTP shape a probe presents.
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
//! * [`TlsFingerprint::Firefox`] — a Firefox-148-shaped ClientHello. The shape is
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
//! exist: `chrome`/`safari` are the reported *triggers*, `firefox` is the
//! Firefox-shaped client that reportedly is not, and `rustls` is the control.
//!
//! # What "shape" means here
//!
//! Three layers, all taken from the same `curl-impersonate v2.2.2` wrapper, so a
//! probe that looks like `curl_chrome107` in one of them looks like it in all:
//!
//! * **TLS** — cipher-suite list and order, `supported_groups`,
//!   `signature_algorithms`, ALPN, exact extension order, extensions rustls does
//!   not normally emit, and the hybrid `X25519MLKEM768` group. That is what JA3
//!   and JA4 hash; the tests pin both against the bundle.
//! * **HTTP** — the `User-Agent` and header set of the impersonated client, in
//!   its order ([`http_identity`]), `accept-encoding` included; the byte-counting
//!   probes override that one header to `identity` (see there). A `user_agent`
//!   set in `config.yml` wins over the profile's.
//! * **HTTP/2** — the `SETTINGS` values, which of them are sent, and the
//!   connection window that becomes the `WINDOW_UPDATE` increment
//!   ([`h2_fingerprint`]).
//!
//! It is **not** a byte-for-byte browser. What is left, and why:
//!
//! * ECH is omitted entirely (see [`firefox_like`] — synthesizing it makes
//!   Google and Cloudflare abort the handshake), and record-layer splitting is
//!   rustls'.
//! * A hello whose version is pinned for isolation — test 2's two columns and
//!   test 6's TLS 1.2 axis — advertises one version where the client it imitates
//!   sends two or more (`[GREASE, 0x0304]` instead of
//!   `[GREASE, 0x0304, 0x0303, 0x0302, 0x0301]`): rustls writes
//!   `supported_versions` from the config, and a build that cannot speak 1.2
//!   must not claim it. JA3 and JA4 do not hash versions; a middlebox reading the
//!   body can. Everywhere else — tests 3 and 4, and test 6's TLS 1.3 axis, which
//!   is the one that asks whether a *browser shape* is blocked — the offer is the
//!   browser's own, fallbacks included: Safari 15.5 lists TLS 1.1 and 1.0 behind
//!   1.2 ([`legacy_versions`]), and a peer that actually selects one is refused
//!   by the config and reported `NO TLS1.3`, not as a block.
//! * HTTP/2 pseudo-headers are ordered `m,s,a,p` (hyper's order; the clients send
//!   `m,a,s,p` for Chrome, `m,p,a,s` for Firefox, `m,s,p,a` for Safari) and the
//!   request `HEADERS` frame carries no priority (h2 0.4 dropped priority
//!   support; Chrome weight 256 / exclusive, Firefox 42 / 0, Safari 255 / 0).
//!
//! Measured against `tls.peet.ws` the TLS hashes, the header list and order, the
//! UA and the whole HTTP/2 `SETTINGS`/`WINDOW_UPDATE` pair match the bundle
//! exactly; `peetprint` — which folds in the priority and the pseudo-header
//! order — does not.

use std::sync::{Arc, LazyLock};

use h2::client::PseudoOrder;
use rustls::client::hello_profile::GREASE_EXTENSION_MARKER;
use rustls::client::ClientHelloProfile;
use rustls::ClientConfig;

use crate::net::tls::TlsVersion;


/// Which ClientHello shape the probes present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsFingerprint {
    /// Untouched rustls: the historical baseline.
    #[default]
    Rustls,
    /// `curl_firefox133`-shaped: Firefox 133's own ClientHello.
    Firefox,
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
    /// Token plus the version the shape reproduces, for the places that have
    /// room for it (burst table headers, the settings screen, the live line).
    /// The bare `token` stays version-less because it is also the round-trip
    /// name the parsers accept back.
    label: &'static str,
    code: &'static str,
}

const SPECS: [Spec; 4] = [
    Spec {
        id: TlsFingerprint::Rustls,
        token: "RUSTLS",
        label: "RUSTLS",
        code: "rustls",
    },
    Spec {
        id: TlsFingerprint::Firefox,
        token: "FIREFOX",
        label: "FIREFOX 133",
        code: "firefox",
    },
    Spec {
        id: TlsFingerprint::Chrome,
        token: "CHROME",
        label: "CHROME 107",
        code: "chrome",
    },
    Spec {
        id: TlsFingerprint::Safari,
        token: "SAFARI",
        label: "SAFARI 155",
        code: "safari",
    },
];

impl TlsFingerprint {
    /// The spec table below lists every variant: a missing row would be a bug in
    /// this file, not something the caller can trigger.
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

    /// Token plus the version it reproduces ("CHROME 107"). Latin like `token`
    /// and never translated (rule 4): a table header or a progress line that
    /// says only "CHROME" hides which shape was actually sent.
    pub fn display_label(self) -> &'static str {
        self.spec().label
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
            return (version == 133).then_some(Self::Firefox);
        }
        match value.as_str() {
            "rustls" | "default" | "none" => Some(Self::Rustls),
            "firefox" | "firefox-like" | "firefox133" => Some(Self::Firefox),
            "chrome" | "chrome99" | "chrome107" => Some(Self::Chrome),
            "safari" | "safari155" | "safari184" => Some(Self::Safari),
            _ => None,
        }
    }

    /// Values accepted by the config validator and the CLI.
    pub const ALL: [TlsFingerprint; 4] = [
        Self::Rustls,
        Self::Firefox,
        Self::Chrome,
        Self::Safari,
    ];

    /// Parses a profile list for test 6: `all`, or comma/space separated names
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

/// The HTTP identity a profile presents: the `User-Agent` and the headers of the
/// client whose ClientHello it reproduces, in the order that client sends them.
///
/// Taken from the same `curl-impersonate v2.2.2` wrapper the ClientHello is
/// pinned to, so a probe that looks like `curl_chrome107` at the TLS layer also
/// looks like it at the HTTP layer. One deviation, deliberate and opt-in:
///
/// * the probes that count the bytes a connection carries before it is cut
///   (tests 2–4: `read_timeout_at_24kb`, `tcp_block_min_kb`/`max_kb`) override
///   `accept-encoding` to `identity`, because a negotiated `Content-Encoding`
///   would make those numbers depend on how well the response happens to
///   compress. [`request_headers`](crate::probe::http::request_headers) does the
///   override per call; everything else, the fingerprint tests included, sends
///   the `accept-encoding` the impersonated client sends.
pub struct HttpIdentity {
    /// The UA of the impersonated client, `None` for the baseline profile.
    pub user_agent: Option<&'static str>,
    /// Headers in wire order, `user-agent` included where the impersonated
    /// client sends one. The call sites append their own tool-specific headers
    /// (`Connection`, `X-Pad`) after these.
    pub headers: &'static [(&'static str, &'static str)],
}

/// Chrome 107 / Edge 99–101 headers, in `curl_chrome107.bat` order.
const CHROME_HEADERS: &[(&str, &str)] = &[
    ("sec-ch-ua", r#""Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24""#),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", r#""Windows""#),
    ("upgrade-insecure-requests", "1"),
    (
        "user-agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
    ),
    (
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    ),
    ("sec-fetch-site", "none"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-user", "?1"),
    ("sec-fetch-dest", "document"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-language", "en-US,en;q=0.9"),
];

/// Firefox 133 headers, in `curl_firefox133.bat` order.
const FIREFOX_HEADERS: &[(&str, &str)] = &[
    (
        "user-agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    ),
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("accept-language", "en-US,en;q=0.5"),
    ("accept-encoding", "gzip, deflate, br, zstd"),
    ("upgrade-insecure-requests", "1"),
    ("sec-fetch-dest", "document"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-site", "none"),
    ("sec-fetch-user", "?1"),
    ("priority", "u=0, i"),
    ("te", "trailers"),
];

/// Safari 15.5 headers, in `curl_safari155.bat` order.
const SAFARI_HEADERS: &[(&str, &str)] = &[
    (
        "user-agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
    ),
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("accept-language", "en-GB,en-US;q=0.9,en;q=0.8"),
    ("accept-encoding", "gzip, deflate, br"),
];

/// The baseline probes' own header set. The Rustls profile is the control every
/// earlier measurement was taken with, so it keeps exactly what those runs sent
/// — the call sites add `Connection` and, for test 3/4, `X-Pad`.
const RUSTLS_HEADERS: &[(&str, &str)] = &[("accept-encoding", "identity")];

/// The HTTP identity of `fingerprint`.
pub fn http_identity(fingerprint: TlsFingerprint) -> HttpIdentity {
    match fingerprint {
        TlsFingerprint::Rustls => HttpIdentity { user_agent: None, headers: RUSTLS_HEADERS },
        TlsFingerprint::Firefox => HttpIdentity {
            user_agent: Some(FIREFOX_HEADERS[0].1),
            headers: FIREFOX_HEADERS,
        },
        TlsFingerprint::Chrome => HttpIdentity { user_agent: Some(CHROME_HEADERS[4].1), headers: CHROME_HEADERS },
        TlsFingerprint::Safari => HttpIdentity { user_agent: Some(SAFARI_HEADERS[0].1), headers: SAFARI_HEADERS },
    }
}

/// The HTTP/2 preface a profile presents, from the same wrapper as its headers.
///
/// `SETTINGS` values, which of them are sent, and the connection window
/// that becomes the `WINDOW_UPDATE` increment. The request's own shape — the
/// pseudo-header order and the PRIORITY flag with the weight and exclusivity the
/// wrapper names (`--http2-stream-weight`, `--http2-stream-exclusive`) — travels
/// beside it, in [`H2Fingerprint::priority`] and `pseudo_order`, and reaches the
/// wire through the patched `h2` (`vendor/h2/README-PATCH.md`).
pub struct H2Fingerprint {
    /// `SETTINGS_HEADER_TABLE_SIZE`; `None` omits the setting.
    pub header_table_size: Option<u32>,
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`; `None` omits the setting.
    pub max_concurrent_streams: Option<u32>,
    /// `SETTINGS_INITIAL_WINDOW_SIZE`.
    pub initial_window_size: u32,
    /// `SETTINGS_MAX_FRAME_SIZE`; `None` omits the setting.
    pub max_frame_size: Option<u32>,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`; `None` omits the setting. Chrome sends
    /// 262144, Firefox and Safari send none.
    pub max_header_list_size: Option<u32>,
    /// `SETTINGS_ENABLE_PUSH`; `None` omits the setting. Chrome and Firefox send
    /// `0`, Safari sends none.
    pub enable_push: Option<bool>,
    /// The order the preface lists its entries in, by setting id. Empty — every
    /// profile but Safari — is ascending, which is what those bundles send;
    /// Safari names `4` before `3`.
    pub settings_order: &'static [u16],
    /// Total connection window; h2 sends `WINDOW_UPDATE` with this minus the
    /// protocol's 65 535 default, which is the increment the impersonated client
    /// sends.
    pub connection_window: u32,
    /// The order the request puts its pseudo-header fields in. RFC 9113 leaves
    /// it open and the browsers disagree; no ClientHello hash shows it.
    pub pseudo_order: PseudoOrder,
    /// The request's `HEADERS` frame carries the PRIORITY flag, as
    /// `(weight, exclusive)` — the weight the impersonated client names, one
    /// more than the byte on the wire (Chrome's `256` is the frame's `255`).
    pub priority: Option<(u16, bool)>,
}

/// The HTTP/2 preface of `fingerprint`, `None` for the baseline profile (hyper's
/// own defaults, the shape every earlier measurement used).
pub fn h2_fingerprint(fingerprint: TlsFingerprint) -> Option<H2Fingerprint> {
    match fingerprint {
        // `1:65536;2:0;3:1000;4:6291456;6:262144`, window 15663105,
        // `--http2-stream-weight 256 --http2-stream-exclusive 1`, pseudo-headers
        // `masp`.
        TlsFingerprint::Chrome => Some(H2Fingerprint {
            header_table_size: Some(65_536),
            max_concurrent_streams: Some(1000),
            initial_window_size: 6_291_456,
            max_frame_size: None,
            max_header_list_size: Some(262_144),
            enable_push: Some(false),
            settings_order: &[],
            connection_window: 15_663_105 + 65_535,
            pseudo_order: PseudoOrder::MethodAuthoritySchemePath,
            priority: Some((256, true)),
        }),
        // `1:65536;2:0;4:131072;5:16384`, window 12517377,
        // `--http2-stream-weight 42 --http2-stream-exclusive 0`,
        // `--http2-pseudo-headers-order "mpas"`.
        TlsFingerprint::Firefox => Some(H2Fingerprint {
            header_table_size: Some(65_536),
            max_concurrent_streams: None,
            initial_window_size: 131_072,
            max_frame_size: Some(16_384),
            max_header_list_size: None,
            enable_push: Some(false),
            settings_order: &[],
            connection_window: 12_517_377 + 65_535,
            pseudo_order: PseudoOrder::MethodPathAuthorityScheme,
            priority: Some((42, false)),
        }),
        // `3:100;4:4194304`, window 10485760,
        // `--http2-stream-weight 255 --http2-stream-exclusive 0`,
        // `--http2-pseudo-headers-order "mspa"`.
        TlsFingerprint::Safari => Some(H2Fingerprint {
            header_table_size: None,
            max_concurrent_streams: Some(100),
            initial_window_size: 4_194_304,
            max_frame_size: None,
            max_header_list_size: None,
            enable_push: None,
            settings_order: &[4, 3],
            connection_window: 10_485_760 + 65_535,
            pseudo_order: PseudoOrder::MethodSchemePathAuthority,
            priority: Some((255, false)),
        }),
        TlsFingerprint::Rustls => None,
    }
}

/// The Firefox ClientHello shape, built once.
///
/// Derived from uTLS `HelloFirefox_148` (`u_parrots.go`), the definition Xray
/// uses for its `firefox` profile. Where rustls already emits an extension the
/// profile only fixes its position; where rustls has no field for it (SCT,
/// secure renegotiation, delegated credentials, record size limit, GREASE ECH)
/// the body is supplied verbatim.
pub fn firefox_profile() -> Arc<ClientHelloProfile> {
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
    matches!(fingerprint, TlsFingerprint::Firefox)
}

/// True when this selection advertises `compress_certificate` (extension 27).
///
/// The decompressors behind it are ours, not rustls's features (see
/// [`crate::net::cert_compression`]), and the decompressor list is exactly what
/// makes rustls offer the extension. Installing it for every profile would
/// advertise extension 27 in *every* ClientHello — a silent change to the
/// baseline fingerprint that all previous measurements were taken with — so the
/// default profile keeps rustls's empty list and sends the wire shape this tool
/// has always sent.
pub fn advertises_cert_compression(fingerprint: TlsFingerprint) -> bool {
    !matches!(fingerprint, TlsFingerprint::Rustls)
}

/// The extensions a browser leaves out of a hello that offers one version alone.
///
/// A ClientHello is not one fixed set: a client offering a single version drops
/// what belongs to the other one, and the pinned hello this tool sends is what a
/// probe column measures. Read off the `curl-impersonate v2.2.2` bundles pinned
/// the same way (`--tlsv1.3 --tls-max 1.3`, `--tls-max 1.2`):
///
/// * no 1.3-only hello carries `ec_point_formats`, Chrome 107 and Safari 15.5
///   also drop `extended_master_secret` and `renegotiation_info`, and Chrome
///   drops `session_ticket`;
/// * no 1.2-only hello carries `supported_versions`, and none carries padding —
///   the extension exists to lift a hello over 256 bytes, and a 1.2 hello is
///   already under that floor, which is where BoringSSL stops padding — nor ALPS
///   (17513), a 1.3 extension.
///
/// Firefox 133 keeps `extended_master_secret` and `renegotiation_info` at 1.3,
/// so the list is per profile rather than one rule for all three.
///
/// Without it a pinned hello advertises one version while still carrying the
/// other's extensions and cipher suites — a shape no client sends. Measured on
/// `standby-rezka.tv`: Chrome 107 and Safari 15.5 pinned to 1.3 got
/// `alert_illegal_parameter`, while the same shapes from the pinned bundle —
/// which drops these — got `200`.
pub fn pinned_drop(fingerprint: TlsFingerprint, version: TlsVersion) -> &'static [u16] {
    match (fingerprint, version) {
        (TlsFingerprint::Chrome, TlsVersion::Tls13) => &[
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_EC_POINT_FORMATS,
            EXT_SESSION_TICKET,
        ],
        (TlsFingerprint::Safari, TlsVersion::Tls13) => &[
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_EC_POINT_FORMATS,
        ],
        (TlsFingerprint::Firefox, TlsVersion::Tls13) => &[EXT_EC_POINT_FORMATS, EXT_SESSION_TICKET],
        (TlsFingerprint::Chrome, TlsVersion::Tls12) => {
            &[EXT_SUPPORTED_VERSIONS, EXT_APPLICATION_SETTINGS, EXT_PADDING]
        }
        (TlsFingerprint::Safari, TlsVersion::Tls12) => &[EXT_SUPPORTED_VERSIONS, EXT_PADDING],
        (TlsFingerprint::Firefox, TlsVersion::Tls12) => &[EXT_SUPPORTED_VERSIONS],
        (TlsFingerprint::Rustls, _) | (_, TlsVersion::Any) => &[],
    }
}

/// Installs the profile on a client config, if the selection has one.
pub fn apply(config: &mut ClientConfig, fingerprint: TlsFingerprint) {
    config.hello_profile = match fingerprint {
        TlsFingerprint::Rustls => None,
        TlsFingerprint::Firefox => Some(firefox_profile()),
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
///
/// Two more deviations the byte comparison against the pinned bundle found, both
/// in bodies no fingerprint hash covers (JA4 reads extension *types* and the
/// signature-algorithms list, never a compression list or a key share):
///
/// * `compress_certificate` lists zlib and brotli, the bundle's three also list
///   zstd — advertising it would mean decoding it, and this build has no
///   decompressor for it;
/// * the hello carries two key shares (X25519MLKEM768, X25519) where the
///   bundle's `--tls-key-shares-limit 3` sends three, the third a P-256 share.
///
/// Both are invisible to `tls.peet.ws` (`ja3`, `ja4` and `peetprint` are equal
/// outside the ECH above), which is why only a captured-byte comparison sees
/// them.
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
        // Firefox 133 offers 1.3 and 1.2 only.
        legacy_versions: Vec::new(),
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
        // Chrome 107 offers 1.3 and 1.2 only (`curl_chrome107` sends neither
        // 1.1 nor 1.0).
        legacy_versions: Vec::new(),
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
            // `curl_safari155.bat` names `rsa_pss_rsae_sha384` twice and BoringSSL
            // sends it once: the script's list is an input, the wire is what it
            // de-duplicates to. Copying the script instead cost this profile an
            // eleventh scheme, which the byte comparison against the pinned
            // bundle caught in the signature-algorithms extension.
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
        // Safari 15.5 keeps offering TLS 1.1 and 1.0 behind 1.2, and
        // `curl_safari155` sends both. They go on the wire verbatim; rustls still
        // negotiates nothing below 1.2, so a peer that selects one of them ends
        // the handshake in `PeerIncompatible::ServerDoesNotSupportTls12Or13` —
        // which the classifier already reads as `NO TLS1.3`, not as a block.
        legacy_versions: vec![0x0302, 0x0301],
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

    use crate::net::tls::{create_tls_config, TlsProfile};

    /// Pinned from the `curl-impersonate v2.2.2` bundle (see
    /// [`tests::bundle_versions_match_their_ja4`]).
    const CHROME_107_JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";
    const CHROME_107_JA3: &str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-\
             49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0";
    const SAFARI_155_JA4: &str = "t13d2014h2_a09f3c656075_2a6581477f52";
    const FIREFOX_133_JA4_LESS_ECH: &str = "t13d1715h2_5b57614c22b0_8fb63dbc839a";

    /// The HTTP identity and the ClientHello of a profile have to describe the
    /// same client: a `chrome107` hello behind a `Chrome/133` UA is a mismatch a
    /// header-matching middlebox reads in a single packet.
    #[test]
    fn http_identity_names_the_version_the_hello_imitates() {
        for (fingerprint, marker) in [
            (TlsFingerprint::Chrome, "Chrome/107.0.0.0"),
            (TlsFingerprint::Firefox, "Firefox/133.0"),
            (TlsFingerprint::Safari, "Version/15.5"),
        ] {
            let identity = http_identity(fingerprint);
            let ua = identity.user_agent.expect("a browser profile carries a UA");
            assert!(ua.contains(marker), "{}: {ua}", fingerprint.code());
            let (_, in_list) = identity
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
                .expect("the UA is part of the list, in its wire position");
            assert_eq!(*in_list, ua, "{}: field and list disagree", fingerprint.code());
            if let Some((_, value)) = identity.headers.iter().find(|(name, _)| *name == "sec-ch-ua") {
                let version = ua.split("Chrome/").nth(1).and_then(|v| v.split('.').next()).expect("UA version");
                assert!(value.contains(&format!("v=\"{version}\"")), "{}: {value}", fingerprint.code());
            }
            // The HTTP identity is the impersonated client's, encoding included:
            // what the byte-counting probes do with it is their own business.
            let (_, encoding) = identity
                .headers
                .iter()
                .find(|(name, _)| *name == "accept-encoding")
                .expect("every identity states its encoding");
            let expected = match fingerprint {
                TlsFingerprint::Firefox => "gzip, deflate, br, zstd",
                TlsFingerprint::Chrome | TlsFingerprint::Safari => "gzip, deflate, br",
                TlsFingerprint::Rustls => "identity",
            };
            assert_eq!(*encoding, expected, "{}: {}", fingerprint.code(), *encoding);
        }
        let baseline = http_identity(TlsFingerprint::Rustls);
        assert!(baseline.user_agent.is_none(), "the baseline profile impersonates nobody");
        assert_eq!(baseline.headers, [("accept-encoding", "identity")]);
    }

    /// The h2 preface is what the pinned wrapper configures through
    /// `--http2-settings` / `--http2-window-update`; the increment h2 puts on the
    /// wire is the connection window minus the protocol's 65535 default.
    #[test]
    fn h2_preface_matches_the_wrapper_it_is_pinned_to() {
        let chrome = h2_fingerprint(TlsFingerprint::Chrome).expect("chrome tunes h2");
        assert_eq!(chrome.header_table_size, Some(65_536));
        assert_eq!(chrome.max_concurrent_streams, Some(1000));
        assert_eq!(chrome.initial_window_size, 6_291_456);
        assert_eq!(chrome.max_frame_size, None, "Chrome advertises no MAX_FRAME_SIZE");
        assert_eq!(chrome.connection_window - 65_535, 15_663_105);

        let firefox = h2_fingerprint(TlsFingerprint::Firefox).expect("firefox tunes h2");
        assert_eq!(firefox.header_table_size, Some(65_536));
        assert_eq!(firefox.initial_window_size, 131_072);
        assert_eq!(firefox.max_frame_size, Some(16_384));
        assert_eq!(firefox.connection_window - 65_535, 12_517_377);

        let safari = h2_fingerprint(TlsFingerprint::Safari).expect("safari tunes h2");
        assert_eq!(safari.header_table_size, None, "Safari sends no HEADER_TABLE_SIZE");
        assert_eq!(safari.max_concurrent_streams, Some(100));
        assert_eq!(safari.initial_window_size, 4_194_304);
        assert_eq!(safari.connection_window - 65_535, 10_485_760);

        assert!(h2_fingerprint(TlsFingerprint::Rustls).is_none(), "the baseline keeps hyper's defaults");
    }

    /// The request shape is measured, not guessed: each triple is what the
    /// bundle named in its `.bat` and what it put on the wire (decrypted with the
    /// bundle's `SSLKEYLOGFILE`). Chrome 107 sends no
    /// `--http2-pseudo-headers-order`, Firefox 133 `"mpas"` and Safari 155
    /// `"mspa"`; all three take the PRIORITY flag on the request's `HEADERS`.
    #[test]
    fn h2_request_shape_matches_the_wrapper_it_is_pinned_to() {
        use PseudoOrder::*;

        let chrome = h2_fingerprint(TlsFingerprint::Chrome).expect("chrome tunes h2");
        assert_eq!(chrome.pseudo_order, MethodAuthoritySchemePath);
        assert_eq!(chrome.priority, Some((256, true)));

        let firefox = h2_fingerprint(TlsFingerprint::Firefox).expect("firefox tunes h2");
        assert_eq!(firefox.pseudo_order, MethodPathAuthorityScheme);
        assert_eq!(firefox.priority, Some((42, false)));

        let safari = h2_fingerprint(TlsFingerprint::Safari).expect("safari tunes h2");
        assert_eq!(safari.pseudo_order, MethodSchemePathAuthority);
        assert_eq!(safari.priority, Some((255, false)));
    }

    /// Which settings a preface carries is part of the shape: Chrome sends
    /// `SETTINGS_MAX_HEADER_LIST_SIZE = 262144` and `SETTINGS_ENABLE_PUSH = 0`,
    /// Firefox the push setting but no header-list size, Safari neither.
    #[test]
    fn h2_preface_settings_match_the_wrapper_they_are_pinned_to() {
        let chrome = h2_fingerprint(TlsFingerprint::Chrome).expect("chrome tunes h2");
        assert_eq!(chrome.max_header_list_size, Some(262_144));
        assert_eq!(chrome.enable_push, Some(false));

        let firefox = h2_fingerprint(TlsFingerprint::Firefox).expect("firefox tunes h2");
        assert_eq!(firefox.max_header_list_size, None, "Firefox sends no header-list size");
        assert_eq!(firefox.enable_push, Some(false));

        let safari = h2_fingerprint(TlsFingerprint::Safari).expect("safari tunes h2");
        assert_eq!(safari.max_header_list_size, None, "Safari sends no header-list size");
        assert_eq!(safari.enable_push, None, "Safari sends no push setting");
        assert_eq!(safari.settings_order, [4, 3], "Safari lists the window before the stream cap");
    }

    /// h2 sorts the settings it sends by id; Safari's preface does not, so the
    /// order is part of the shape. An empty order means the sorted default the
    /// other profiles and the baseline keep.
    #[test]
    fn h2_settings_go_out_in_the_order_the_wrapper_sends_them() {
        for (fingerprint, expected) in [
            (TlsFingerprint::Chrome, &[][..]),
            (TlsFingerprint::Firefox, &[][..]),
            (TlsFingerprint::Safari, &[4, 3][..]),
        ] {
            let h2 = h2_fingerprint(fingerprint).expect("browser profiles tune h2");
            assert_eq!(h2.settings_order, expected, "{}", fingerprint.code());
        }
    }

    /// The version-bearing label is display only: it must not collide with a
    /// parser name, and every profile whose shape is a pinned curl version has
    /// to say which one.
    #[test]
    fn display_labels_name_the_pinned_version() {
        assert_eq!(TlsFingerprint::Firefox.display_label(), "FIREFOX 133");
        assert_eq!(TlsFingerprint::Chrome.display_label(), "CHROME 107");
        assert_eq!(TlsFingerprint::Safari.display_label(), "SAFARI 155");
        assert_eq!(TlsFingerprint::Rustls.display_label(), "RUSTLS");
        for fp in TlsFingerprint::ALL {
            assert!(fp.display_label().starts_with(fp.token()), "{fp:?}");
            assert!(fp.display_label().is_ascii(), "{fp:?}");
        }
    }

    #[test]
    fn fingerprint_tokens_are_stable() {
        assert_eq!(TlsFingerprint::Rustls.token(), "RUSTLS");
        assert_eq!(TlsFingerprint::Firefox.token(), "FIREFOX");
        assert_eq!(TlsFingerprint::Rustls.code(), "rustls");
        assert_eq!(TlsFingerprint::Firefox.code(), "firefox");
        assert_eq!(TlsFingerprint::default(), TlsFingerprint::Rustls);
    }

    #[test]
    fn fingerprint_parses_known_values_and_rejects_others() {
        assert_eq!(TlsFingerprint::parse("rustls"), Some(TlsFingerprint::Rustls));
        assert_eq!(TlsFingerprint::parse("FIREFOX"), Some(TlsFingerprint::Firefox));
        assert_eq!(TlsFingerprint::parse(" firefox "), Some(TlsFingerprint::Firefox));
        // The old name is gone rather than aliased: a config or a script that
        // still says `custom` is told it is unknown instead of silently measuring
        // the same profile under a name the tool no longer prints.
        assert_eq!(TlsFingerprint::parse("custom"), None);
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
            Some(TlsFingerprint::Firefox)
        );
        // Shapes no profile sends: shuffled extension order, post-quantum
        // group, signed certificate timestamps.
        assert_eq!(TlsFingerprint::parse("curl_chrome116"), None);
        assert_eq!(TlsFingerprint::parse("curl_safari260"), None);
        assert_eq!(TlsFingerprint::parse("curl_firefox147"), None);
        assert_eq!(TlsFingerprint::parse("curl_firefox144"), None);
        assert_eq!(TlsFingerprint::parse(""), None);
    }

    /// Test 6 takes a *list* of profiles; `all` and the curl aliases must work,
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
        let (known, unknown) = TlsFingerprint::parse_list("firefox,bogus");
        assert_eq!(known, vec![TlsFingerprint::Firefox]);
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
        let profile = firefox_profile();

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

    /// The JA3 (and size) of the hello a profile writes on `version`: the two
    /// pinned builders are what the probes and test 6 use, `Any` is what the
    /// tools and the earlier measurements used.
    fn client_hello_of(fingerprint: TlsFingerprint, version: TlsVersion) -> (String, usize) {
        let (ja3, length, _) = client_hello_full(fingerprint, version);
        (ja3, length)
    }

    /// The three fingerprints of the hello a profile writes on `version`: JA3,
    /// the hello size, and JA4.
    fn client_hello_full(
        fingerprint: TlsFingerprint,
        version: TlsVersion,
    ) -> (String, usize, String) {
        let profile = match version {
            TlsVersion::Tls12 => TlsProfile::insecure(fingerprint).tls12(),
            TlsVersion::Tls13 => TlsProfile::insecure(fingerprint).tls13(),
            TlsVersion::Any => TlsProfile::insecure(fingerprint),
        };
        let config = create_tls_config(&profile);
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
    /// reproducing the fingerprint the censor is reported to match on.
    ///
    /// Both pinned builders were checked because a hello that advertises one
    /// version while still carrying the other's extensions and cipher suites is a
    /// shape no client sends: `standby-rezka.tv` answered the hybrid with
    /// `alert_illegal_parameter`. Pinned, the bundles drop what belongs to the
    /// other version — the 1.2-era extensions and the 1.2 cipher suites from a
    /// 1.3-only hello, `supported_versions` and the padding (a 1.2 hello is
    /// already under the 256-byte floor where BoringSSL stops padding) from a
    /// 1.2-only one — and Chrome also drops ALPS from the 1.2 hello.
    ///
    /// The 1.3 hellos are byte-identical to the pinned bundles; the point-formats
    /// field is empty there, which is what a 1.3-only browser hello has. The 1.2
    /// hellos stop one extension short of the bundle's, which lists
    /// `compress_certificate` (27) in a 1.2 hello — rustls offers it only when
    /// the hello also offers 1.3, so the cipher suites match and `27` is the one
    /// extension we cannot send. Firefox's 1.3 hello stops at `27` for the ECH
    /// reason in [`firefox_like`].
    #[test]
    fn bundle_versions_match_their_ja3() {
        const CHROME_107: &str = CHROME_107_JA3;
        const SAFARI_155: &str = "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-\
             49161-49172-49171-157-156-53-47-49160-49170-10,\
             0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0";
        // `curl_firefox133` sends `...,28-27-65037` — the profile stops at 27,
        // because a GREASE ECH body this build writes is rejected by every
        // ECH-aware server (see `firefox_like`).
        const FIREFOX_133: &str = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-\
             49161-49171-49172-156-157-47-53,\
             0-23-65281-10-11-35-16-5-34-51-43-13-45-28-27,4588-29-23-24-25-256-257,0";

        const CHROME_107_TLS13: &str =
            "771,4865-4866-4867,0-10-16-5-13-18-51-45-43-27-17513-21,29-23-24,";
        const SAFARI_155_TLS13: &str =
            "771,4865-4866-4867,0-10-16-5-13-18-51-45-43-27-21,29-23-24-25,";
        const FIREFOX_133_TLS13: &str =
            "771,4865-4867-4866,0-23-65281-10-16-5-34-51-43-13-45-28-27,4588-29-23-24-25-256-257,";

        const CHROME_107_TLS12: &str = "771,49195-49199-49196-49200-52393-52392-49171-49172-\
             156-157-47-53,0-23-65281-10-11-35-16-5-13-18,29-23-24,0";
        const SAFARI_155_TLS12: &str = "771,49196-49195-52393-49200-49199-52392-49162-49161-\
             49172-49171-157-156-53-47-49160-49170-10,\
             0-23-65281-10-11-16-5-13-18,29-23-24-25,0";
        const FIREFOX_133_TLS12: &str = "771,49195-49199-52393-52392-49196-49200-49162-49161-\
             49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-13-28,\
             4588-29-23-24-25-256-257,0";

        for (version, profiles) in [
            (
                TlsVersion::Any,
                [
                    (TlsFingerprint::Chrome, CHROME_107),
                    (TlsFingerprint::Safari, SAFARI_155),
                    (TlsFingerprint::Firefox, FIREFOX_133),
                ],
            ),
            (
                TlsVersion::Tls13,
                [
                    (TlsFingerprint::Chrome, CHROME_107_TLS13),
                    (TlsFingerprint::Safari, SAFARI_155_TLS13),
                    (TlsFingerprint::Firefox, FIREFOX_133_TLS13),
                ],
            ),
            (
                TlsVersion::Tls12,
                [
                    (TlsFingerprint::Chrome, CHROME_107_TLS12),
                    (TlsFingerprint::Safari, SAFARI_155_TLS12),
                    (TlsFingerprint::Firefox, FIREFOX_133_TLS12),
                ],
            ),
        ] {
            for (fingerprint, expected) in profiles {
                assert_eq!(
                    client_hello_of(fingerprint, version).0,
                    expected,
                    "{fingerprint} ({version:?})"
                );
            }
        }

        // BoringSSL pads a 1.3 browser hello to exactly 512 bytes — the
        // `curl-impersonate v2.2.2` chrome107/safari155 hellos measure 512 — and
        // the padding extension is part of the JA3s above, so both the size and a
        // lost pad are checked here. A 1.2 hello is shorter than the 256-byte
        // floor, so it carries no padding at all: the bundle's 1.2 hellos measure
        // 198 and 210 bytes against our 185 and 199 (the `compress_certificate`
        // difference), all of them well under the floor.
        for fingerprint in [TlsFingerprint::Chrome, TlsFingerprint::Safari] {
            for version in [TlsVersion::Any, TlsVersion::Tls13] {
                let (_, length) = client_hello_of(fingerprint, version);
                assert_eq!(length, 512, "{fingerprint} hello ({version:?})");
            }
            let (_, length) = client_hello_of(fingerprint, TlsVersion::Tls12);
            assert!(length < 256, "{fingerprint} 1.2 hello is padded: {length}");
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
        // The pinned 1.3 hashes are the bundle's: those hellos are byte-identical
        // to `curl_chrome107`/`curl_safari155`/`curl_firefox133` pinned with
        // `--tlsv1.3 --tls-max 1.3`. The 1.2 hashes are ours alone — the pinned
        // configuration is the one where rustls cannot send the bundle's
        // `compress_certificate`, so the extension count and hash differ by that
        // one extension.
        const CHROME_107_TLS13: &str = "t13d0312h2_55b375c5d22e_89e42599e699";
        const SAFARI_155_TLS13: &str = "t13d0311h2_55b375c5d22e_3727ed65331a";
        const FIREFOX_133_TLS13: &str = "t13d0313h2_55b375c5d22e_1dac57d28bce";
        const CHROME_107_TLS12: &str = "t12d1210h2_d34a8e72043a_fae48490d0f6";
        const SAFARI_155_TLS12: &str = "t12d1709h2_ba5946811be1_8c31861e0dbb";
        const FIREFOX_133_TLS12: &str = "t12d1411h2_c866b44c5a26_242292a3764d";

        for (version, chrome, safari, firefox) in [
            (
                TlsVersion::Any,
                CHROME_107_JA4,
                SAFARI_155_JA4,
                FIREFOX_133_JA4_LESS_ECH,
            ),
            (
                TlsVersion::Tls13,
                CHROME_107_TLS13,
                SAFARI_155_TLS13,
                FIREFOX_133_TLS13,
            ),
            (
                TlsVersion::Tls12,
                CHROME_107_TLS12,
                SAFARI_155_TLS12,
                FIREFOX_133_TLS12,
            ),
        ] {
            let (_, _, got) = client_hello_full(TlsFingerprint::Chrome, version);
            assert_eq!(got, chrome, "chrome ({version:?})");
            let (_, _, got) = client_hello_full(TlsFingerprint::Safari, version);
            assert_eq!(got, safari, "safari ({version:?})");
            let (_, _, got) = client_hello_full(TlsFingerprint::Firefox, version);
            assert_eq!(got, firefox, "firefox ({version:?})");
        }
    }

    /// Test 6 pins the TLS version and the ALPN it offers, and both have to
    /// reach the wire: the pinned JA4 shows the version field (`t12`/`t13`) and
    /// the ALPN field (`h2`/`h1`), while JA3 turns on the version — a 1.3-only
    /// hello carries 3 ciphers and 12 extensions against the browser offer's 15
    /// and 16 — but never on ALPN, whose values JA3 does not read.
    #[test]
    fn pinned_tls_version_and_alpn_reach_the_hello() {
        let hello = |tls12_only: bool, alpn: Option<Vec<Vec<u8>>>| {
            let mut profile = if tls12_only {
                TlsProfile::insecure(TlsFingerprint::Chrome).tls12()
            } else {
                TlsProfile::insecure(TlsFingerprint::Chrome).tls13()
            };
            if let Some(alpn) = alpn {
                profile = profile.alpn(alpn);
            }
            let config = create_tls_config(&profile);
            let name = rustls::pki_types::ServerName::try_from("example.com").expect("valid name");
            let mut conn = rustls::ClientConnection::new(config, name).expect("client conn");
            let mut buf = Vec::new();
            conn.write_tls(&mut buf).expect("write ClientHello");
            (crate::net::ja3::client_hello_ja3(&buf), crate::net::ja4::client_hello_ja4(&buf))
        };

        let (ja3_default, ja4_default) = hello(false, None);
        assert!(ja4_default.starts_with("t13d0312h2_"), "{ja4_default}");

        // HTTP/1.1 alone: same hello except the ALPN extension's body, so JA4
        // keeps its counts and hashes and changes only the ALPN field.
        let (ja3_http11, ja4_http11) = hello(false, Some(vec![b"http/1.1".to_vec()]));
        assert!(ja4_http11.starts_with("t13d0312h1_"), "{ja4_http11}");
        assert_eq!(
            ja4_http11.split_once('_').map(|x| x.1),
            ja4_default.split_once('_').map(|x| x.1),
            "h2 and http/1.1 differ in the ALPN field only"
        );
        assert_eq!(ja3_http11, ja3_default, "JA3 hashes types, not ALPN values");

        // TLS 1.2: the version field follows the pinned version. A browser's
        // 1.2-only hello carries no `supported_versions` for JA4 to read, so the
        // field comes from the ClientHello's legacy version — not from its TLS
        // 1.0 record header, which no client's protocol is.
        let (_, ja4_tls12) = hello(true, None);
        assert!(ja4_tls12.starts_with("t12d"), "{ja4_tls12}");
    }

    /// Browser hellos open `supported_versions` with a GREASE code point, and
    /// JA3/JA4 both ignore it — but a middlebox may read the list, so the hello
    /// has to carry it and the two fingerprint hashes have to be unmoved by it.
    ///
    /// Firefox greases nothing, so its list must stay plain: adding the value
    /// there would deviate from `curl_firefox133` rather than approach it.
    ///
    /// What `supported_versions` carries per builder.
    ///
    /// The unpinned builder is the browser's own offer — 1.3 *and* 1.2, with the
    /// profile's GREASE — and it is what tests 3 and 4 send, plus test 6's TLS
    /// 1.3 axis: the burst asks whether a *browser shape* is blocked, so the
    /// offer has to be the browser's, and it can only be built unpinned.
    ///
    /// The pinned builders are test 2's two columns (and test 6's TLS 1.2 axis),
    /// where the whole point is a client that speaks exactly one version: a
    /// hello offering both is never answered with 1.2, so the isolation is bought
    /// with one version in the list instead of two — `0x0304` for the 1.3 phase,
    /// `0x0303` for the 1.2 one. See `net::tls::TlsProfile::tls13` for why the
    /// deviation is accepted rather than faked.
    #[test]
    fn grease_version_leads_supported_versions() {
        // The `supported_versions` body of a hello, `None` when the hello does
        // not carry the extension at all, and the record size.
        let versions = |profile: TlsProfile| {
            let config = create_tls_config(&profile);
            let name = rustls::pki_types::ServerName::try_from("example.com").expect("valid name");
            let mut conn = rustls::ClientConnection::new(config, name).expect("client conn");
            let mut buf = Vec::new();
            conn.write_tls(&mut buf).expect("write ClientHello");
            let body = crate::net::ja3::extensions(&buf[crate::net::ja3::RECORD_HEADER..])
                .into_iter()
                .find(|(ext_type, _)| *ext_type == 43)
                .map(|(_, body)| body.to_vec());
            let list = body.map(|body| {
                let entries = body[0] as usize / 2;
                (0..entries)
                    .map(|i| u16::from_be_bytes([body[1 + 2 * i], body[2 + 2 * i]]))
                    .collect::<Vec<u16>>()
            });
            (list, buf.len())
        };

        for (fp, legacy) in [
            (TlsFingerprint::Chrome, Vec::new()),
            // Safari 15.5 keeps advertising TLS 1.1 and 1.0 behind 1.2, and
            // `curl_safari155` sends both — a hello without them is a shape no
            // Safari sends.
            (TlsFingerprint::Safari, vec![0x0302, 0x0301]),
        ] {
            // The browser's own offer: both modern versions, GREASE first, the
            // profile's fallbacks behind them, 512 bytes.
            let (browser, record) = versions(TlsProfile::insecure(fp));
            let browser = browser.expect("the browser offer carries supported_versions");
            assert!(is_grease_version(browser[0]), "{fp:?} must open with GREASE: {browser:04x?}");
            let expected = [vec![0x0304, 0x0303], legacy.clone()].concat();
            assert_eq!(&browser[1..], &expected[..], "{fp:?}: {browser:04x?}");
            assert_eq!(record, 512 + 5, "{fp:?}: the padded hello must stay 512 bytes");

            // Pinned to 1.3: one version in the list (test 2's TLS 1.3 column),
            // and no fallbacks — a pinned run isolates one version on purpose.
            let (only13, _) = versions(TlsProfile::insecure(fp).tls13());
            let only13 = only13.expect("a 1.3-only hello still names its version");
            assert!(is_grease_version(only13[0]), "{fp:?}: {only13:04x?}");
            assert_eq!(&only13[1..], &[0x0304], "{fp:?}: {only13:04x?}");

            // TLS 1.2 alone: the pinned version replaces 1.3 — and the extension
            // goes with it, because a hello that cannot negotiate anything above
            // 1.2 has no version list to send. That is what the pinned bundles
            // send (`curl_chrome107 --tls-max 1.2` carries no extension 43), and
            // it is the shape test 2's second column measures.
            let (only12, _) = versions(TlsProfile::insecure(fp).tls12());
            assert!(only12.is_none(), "{fp:?}: a 1.2-only hello carries no supported_versions");
        }

        let (firefox, _) = versions(TlsProfile::insecure(TlsFingerprint::Firefox));
        assert_eq!(
            firefox.expect("firefox carries supported_versions"),
            vec![0x0304, 0x0303],
            "Firefox does not grease, and offers both"
        );
        let (firefox13, _) = versions(TlsProfile::insecure(TlsFingerprint::Firefox).tls13());
        assert_eq!(firefox13.expect("a 1.3-only Firefox hello names its version"), vec![0x0304]);
        let (firefox12, _) = versions(TlsProfile::insecure(TlsFingerprint::Firefox).tls12());
        assert!(firefox12.is_none());
        let (rustls_list, _) = versions(TlsProfile::insecure(TlsFingerprint::Rustls));
        assert_eq!(
            rustls_list.expect("the baseline carries supported_versions"),
            vec![0x0304, 0x0303],
            "the baseline offers both, untouched"
        );
    }

    /// RFC 8701: `0x?a?a` with both bytes equal.
    fn is_grease_version(value: u16) -> bool {
        let (hi, lo) = (value >> 8, value & 0xff);
        hi == lo && lo & 0x0f == 0x0a
    }

    /// The curl shapes predate post-quantum key exchange, so they must not be
    /// given the hybrid group — a group the original does not offer would change
    /// the fingerprint being reproduced.
    #[test]
    fn curl_family_profiles_do_not_use_the_pq_provider() {
        assert!(!needs_pq(TlsFingerprint::Chrome));
        assert!(!needs_pq(TlsFingerprint::Safari));
        assert!(needs_pq(TlsFingerprint::Firefox));
        assert!(advertises_cert_compression(TlsFingerprint::Chrome));
        assert!(advertises_cert_compression(TlsFingerprint::Safari));
        assert!(!advertises_cert_compression(TlsFingerprint::Rustls));
    }

    /// The decompressor list is what rustls reads to decide whether to offer
    /// extension 27 and to pick a decoder for the algorithm the server answered
    /// with; an empty list against an advertised extension is a fatal
    /// `SelectedUnofferedCertCompression`. The default profile must keep the
    /// empty list so its hello stays the baseline shape.
    #[test]
    fn the_decompressor_list_follows_the_profile() {
        for (name, fingerprint, decompressors) in [
            ("Rustls", TlsFingerprint::Rustls, 0),
            ("Firefox", TlsFingerprint::Firefox, 2),
            ("Chrome", TlsFingerprint::Chrome, 2),
            ("Safari", TlsFingerprint::Safari, 2),
        ] {
            let config = create_tls_config(&TlsProfile::insecure(fingerprint).tls13());
            assert_eq!(
                config.cert_decompressors.len(),
                decompressors,
                "{name} decompressor count"
            );
        }
    }

    /// RFC 8879: the server may compress its certificate with anything the hello
    /// offered, so every code point a profile advertises has to have a
    /// decompressor behind it — otherwise the handshake dies on a certificate
    /// this build cannot read.
    #[test]
    fn every_advertised_compression_algorithm_is_readable() {
        for (name, profile) in [
            ("Firefox", firefox_profile()),
            ("Chrome", chrome_profile()),
            ("Safari", safari_profile()),
        ] {
            let advertised = profile
                .cert_compression
                .clone()
                .unwrap_or_else(|| panic!("{name} advertises no algorithm list"));
            assert!(!advertised.is_empty(), "{name} advertises an empty list");
            for code in advertised {
                assert!(
                    crate::net::cert_compression::covers(code.into()),
                    "{name} advertises {code}, which this build cannot decompress"
                );
            }
        }
    }
}
