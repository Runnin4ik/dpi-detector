//! Every profile's shape, as data.
//!
//! One record per selectable shape: its names, where the shape came from, and
//! the TLS lists a ClientHello is built from. The builder in [`super`] turns a
//! record into the `ClientHelloProfile` rustls writes; the accessors read the
//! same record, so nothing here is duplicated in a `match` arm.
//!
//! A record whose TLS shape is another record's — Edge is Chromium, Safari 18.0
//! is Safari 15.5's hello — names the shared lists instead of copying them, so
//! the family's shape lives in one place and the record carries only what makes
//! it a different client (its identity and its HTTP/2 preface). What each field
//! means is in [`TlsShape`]; the provenance of a record's numbers goes in its
//! `source`, so updating an upstream release is a deliberate revision of a shape
//! rather than a silent change of one.

use rustls::client::hello_profile::GREASE_EXTENSION_MARKER;
use rustls::client::ClientHelloProfile;

use super::h2::{H2Fingerprint, CHROME_H2, FIREFOX_H2, SAFARI_H2};
use super::identity::{CHROME_HEADERS, FIREFOX_HEADERS, SAFARI_HEADERS};
use super::TlsFingerprint;

/// One selectable shape.
///
/// The lists are raw IANA identifiers in wire order, so a record can be written
/// straight from a captured ClientHello. `ciphers`, `groups` and `sig_algs` are
/// what the profile *advertises*; a code point this build's provider cannot
/// serve is allowed in the list (browsers list more than they use) but has to
/// be named in `tests::UNIMPLEMENTED`, which is what keeps the gap between the
/// shape and the provider an explicit decision.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TlsShape {
    /// The variant this record describes. Every variant has exactly one record.
    pub(crate) variant: TlsFingerprint,
    /// Stable value for machine JSON and the config file.
    pub(crate) code: &'static str,
    /// Canonical uppercase token for tables and logs. Never translated (rule 4).
    pub(crate) token: &'static str,
    /// Token plus the version the shape reproduces ("CHROME 133"), for the
    /// places that have room for it (burst table headers, the settings screen,
    /// the live line). Latin like `token` and never translated (rule 4): a table
    /// header that says only "CHROME" hides which shape was actually sent.
    pub(crate) label: &'static str,
    /// Where the numbers were taken from, versions included: the reference
    /// bundle a shape is pinned to, and the capture it was read out of. Reads in
    /// `--legend`, and is the reason a pin can be re-measured.
    pub(crate) source: &'static str,
    /// Names the parsers accept in addition to `code`, lowercase.
    pub(crate) aliases: &'static [&'static str],
    /// The `curl-impersonate` wrapper names that emit this shape, when the
    /// bundle's own names are accepted as well.
    pub(crate) curl: Option<CurlNames>,
    /// The untouched rustls hello: no profile is installed, nobody is
    /// impersonated, and every earlier measurement was taken with it.
    pub(crate) baseline: bool,
    /// Cipher suites, in wire order.
    pub(crate) ciphers: &'static [u16],
    /// `supported_groups`, in wire order. The first entry is the group the
    /// provider shares a key with — `tests::the_advertised_group_list_opens_with_the_group_we_share`
    /// pins that, because a list that opens with another group is a shape no
    /// client sends.
    pub(crate) groups: &'static [u16],
    /// `signature_algorithms`, in wire order.
    pub(crate) sig_algs: &'static [u16],
    /// The full extension list, in the order the client sends it.
    /// `GREASE_EXTENSION_MARKER` marks a GREASE slot (RFC 8701).
    pub(crate) ext_order: &'static [u16],
    /// Extensions emitted verbatim as `(type, body)`, for what rustls has no
    /// typed field for or for a body the client shapes itself (session ticket,
    /// padding, ALPS, secure renegotiation, SCT).
    pub(crate) raw_exts: &'static [(u16, &'static [u8])],
    /// Extensions the client never sends, which rustls otherwise would.
    pub(crate) suppress: &'static [u16],
    /// Extensions a hello pinned to TLS 1.3 alone drops — the 1.2-era ones. See
    /// [`super::pinned_drop`].
    pub(crate) drop13: &'static [u16],
    /// Extensions a hello pinned to TLS 1.2 alone drops: `supported_versions`,
    /// the 1.3-only ALPS, and padding (a 1.2 hello is under the 256-byte floor
    /// where BoringSSL stops padding).
    pub(crate) drop12: &'static [u16],
    /// ALPN protocols, in wire order.
    pub(crate) alpn: &'static [&'static [u8]],
    /// Pad the hello to at least this many bytes (RFC 7685).
    pub(crate) padding_to: Option<u16>,
    /// Emit GREASE values. Chrome and Safari grease, Firefox does not.
    pub(crate) grease: bool,
    /// RFC 8879 code points this shape advertises; empty means rustls's own
    /// empty list and no `compress_certificate` extension.
    pub(crate) cert_compression: &'static [u16],
    /// Needs the provider that carries `X25519MLKEM768`, because the shape
    /// offers the hybrid group and its key share has to be the first group's.
    pub(crate) pq: bool,
    /// Versions offered *behind* 1.2, in wire order. Empty for every shape whose
    /// client offers 1.3 and 1.2 only.
    pub(crate) legacy_versions: &'static [u16],
    /// The HTTP header set, `None` for the baseline.
    pub(crate) headers: Option<&'static [(&'static str, &'static str)]>,
    /// The HTTP/2 preface, `None` for the baseline (hyper's own defaults).
    pub(crate) h2: Option<&'static H2Fingerprint>,
}

/// The `curl-impersonate` names that emit a shape.
///
/// The forum that reported the TSPU fingerprints names the profiles after the
/// bundle, so those names are accepted — but only where this build reproduces
/// the shape they describe: a bundle profile whose JA3 differs (`chrome110+`
/// shuffles the extension order, `safari260` offers the post-quantum group,
/// `firefox135+` adds SCT) is rejected rather than mapped to a neighbour.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CurlNames {
    /// Every numbered profile of these prefixes up to and including the
    /// version: the bundle emits one identical JA3 for all of them.
    UpTo(&'static [&'static str], u16),
    /// Only the versions named, because the bundle changes shape between them.
    Only(&'static [&'static str], &'static [u16]),
}

/// Chrome 99–107's cipher list, which Chrome 133 keeps and Edge 99–101 sends
/// unchanged (`curl_edge99/101` and `curl_chrome99..107` emit one JA3, and uTLS
/// `HelloEdge_106` lists the same suites).
const CHROME_TLS_CIPHERS: &[u16] = &[
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
];

/// Chrome 99–133's signature schemes, in all three Chromium records.
const CHROME_TLS_SIG_ALGS: &[u16] = &[
    0x0403, // ECDSA P-256 SHA-256
    0x0804, // RSA-PSS SHA-256
    0x0401, // RSA-PKCS1 SHA-256
    0x0503, // ECDSA P-384 SHA-384
    0x0805, // RSA-PSS SHA-384
    0x0501, // RSA-PKCS1 SHA-384
    0x0806, // RSA-PSS SHA-512
    0x0601, // RSA-PKCS1 SHA-512
];

/// Chrome 99–107 / Edge 99–101's groups: X25519, P-256, P-384.
const CHROME_TLS_GROUPS: &[u16] = &[
    29, // X25519
    23, // secp256r1
    24, // secp384r1
];

/// Chrome 99–107 / Edge 99–101's extension order, in the order the bundle sends
/// it: one GREASE slot first and one before the padding.
const CHROME_TLS_EXT_ORDER: &[u16] = &[
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
];

/// The bodies Chrome 99–107 / Edge 99–101 emit verbatim.
const CHROME_TLS_RAW_EXTS: &[(u16, &[u8])] = &[
    // Empty renegotiated_connection vector.
    (EXT_RENEGOTIATION_INFO, &[0x00]),
    // ec_point_formats: uncompressed only.
    (EXT_EC_POINT_FORMATS, &[0x01, 0x00]),
    // signed_certificate_timestamp in the ClientHello is empty.
    (EXT_SCT, &[]),
    // session_ticket: empty in a fresh session. rustls drops the extension from
    // a TLS 1.3-only hello, Chrome sends it in both, so the profile supplies it
    // — without this the TLS 1.3 column and test 7 sent a Chrome hello with one
    // extension less than Chrome's.
    (EXT_SESSION_TICKET, &[]),
    // ALPS: one protocol, h2.
    (EXT_APPLICATION_SETTINGS, &[0x00, 0x03, 0x02, b'h', b'2']),
    // Padding: rustls computes the body so the hello reaches 512 bytes, the way
    // BoringSSL does. Only its presence enters JA3.
    (EXT_PADDING, &[]),
];

/// Both protocols, exactly what every Chromium profile offers; the probes
/// branch on the negotiated protocol (see `probe::tls`).
const H2_AND_HTTP11: &[&[u8]] = &[b"h2", b"http/1.1"];

/// brotli, exactly what Chrome 107, Chrome 133 and Edge 101 advertise.
const BROTLI: &[u16] = &[2];

/// The `curl_safari15.5..18.4` cipher list: 20 suites, CBC-heavy, 3DES at the
/// end. Safari 18.0's bundle wrapper lists the same 20 in the same order.
const SAFARI_TLS_CIPHERS: &[u16] = &[
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
];

/// Safari 15.5–18.4's four groups. The provider implements three of them, and
/// the fourth is listed without ever being a key share — see
/// `tests::UNIMPLEMENTED`.
const SAFARI_TLS_GROUPS: &[u16] = &[
    29, // X25519
    23, // secp256r1
    24, // secp384r1
    25, // secp521r1
];

/// Safari 15.5–18.4's signature schemes. `curl_safari180` and `curl_safari184`
/// list the same ten, `rsa_pss_rsae_sha384` twice, which is why the duplicate
/// comment below matters: the script's list is an input, the wire is what
/// BoringSSL de-duplicates it to.
const SAFARI_TLS_SIG_ALGS: &[u16] = &[
    0x0403, // ECDSA P-256 SHA-256
    0x0804, // RSA-PSS SHA-256
    0x0401, // RSA-PKCS1 SHA-256
    0x0503, // ECDSA P-384 SHA-384
    0x0203, // ECDSA SHA-1 — Safari 15.5 sends it; JA3 ignores the list,
            // JA4 hashes it, which is how its absence was caught
    0x0805, // RSA-PSS SHA-384
    // `curl_safari155.bat` names `rsa_pss_rsae_sha384` twice and BoringSSL
    // sends it once: copying the script instead cost this profile an eleventh
    // scheme, which the byte comparison against the pinned bundle caught in the
    // signature-algorithms extension.
    0x0501, // RSA-PKCS1 SHA-384
    0x0806, // RSA-PSS SHA-512
    0x0601, // RSA-PKCS1 SHA-512
    0x0201, // RSA-PKCS1 SHA-1
];

/// Safari 15.5–18.4's extension order, GREASE at both ends.
const SAFARI_TLS_EXT_ORDER: &[u16] = &[
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
];

/// The bodies Safari 15.5–18.4 emit verbatim.
const SAFARI_TLS_RAW_EXTS: &[(u16, &[u8])] = &[
    (EXT_RENEGOTIATION_INFO, &[0x00]),
    (EXT_EC_POINT_FORMATS, &[0x01, 0x00]),
    (EXT_SCT, &[]),
    (EXT_PADDING, &[]),
];

/// Every selectable shape, in report order: the baseline first, then one record
/// per profile. `tests::fingerprint_table_is_total` pins the table against
/// [`TlsFingerprint::ALL`] in both directions, so a variant without a record
/// fails the suite instead of silently falling back to the baseline.
pub(crate) static SHAPES: &[TlsShape] = &[
    TlsShape {
        variant: TlsFingerprint::Rustls,
        code: "rustls",
        token: "RUSTLS",
        label: "RUSTLS",
        source: "rustls (unmodified)",
        aliases: &["rustls", "default", "none"],
        curl: None,
        baseline: true,
        ciphers: &[],
        groups: &[],
        sig_algs: &[],
        ext_order: &[],
        raw_exts: &[],
        suppress: &[],
        drop13: &[],
        drop12: &[],
        alpn: &[],
        padding_to: None,
        grease: false,
        cert_compression: &[],
        pq: false,
        legacy_versions: &[],
        headers: None,
        h2: None,
    },
    // Firefox 133, as `curl_firefox133` of curl-impersonate v2.2.2 sends it.
    //
    // This used to follow uTLS `HelloFirefox_148` (the Xray/REALITY parrot). The
    // pinned version is now the one this repository's reference bundle
    // (`curl-impersonate v2.2.2`) actually sends, which differs from the uTLS
    // parrot in three extensions: 133 carries `session_ticket` (35) and
    // `psk_key_exchange_modes` (45), which uTLS's Firefox does not, and it has
    // no `signed_certificate_timestamp` (18). See
    // `tests::bundle_versions_match_their_ja3`.
    //
    // One deliberate deviation remains: `encrypted_client_hello` (65037) is left
    // out. uTLS's own GREASE ECH encrypts a fake inner hello with a fresh HPKE
    // key, and this build has no HPKE provider; every hand-built body tried so
    // far — the current one included, placed last exactly where Firefox puts it
    // — makes `cloudflare.com`, `www.google.com` and `dns.google` answer
    // `fatal alert: DecodeError` (`tls_fingerprint live custom`). Since Google
    // and Cloudflare front much of what this tool probes, sending a hello they
    // abort would report our own artifact as censorship. JA4 therefore shows 15
    // extensions where `curl_firefox133` sends 16.
    //
    // Two more deviations the byte comparison against the pinned bundle found,
    // both in bodies no fingerprint hash covers (JA4 reads extension *types* and
    // the signature-algorithms list, never a compression list or a key share):
    //
    // * `compress_certificate` lists zlib and brotli, the bundle's three also
    //   list zstd — advertising it would mean decoding it, and this build has no
    //   decompressor for it;
    // * the hello carries two key shares (X25519MLKEM768, X25519) where the
    //   bundle's `--tls-key-shares-limit 3` sends three, the third a P-256
    //   share.
    //
    // Both are invisible to `tls.peet.ws` (`ja3`, `ja4` and `peetprint` are
    // equal outside the ECH above), which is why only a captured-byte comparison
    // sees them.
    TlsShape {
        variant: TlsFingerprint::Firefox,
        code: "firefox",
        token: "FIREFOX",
        label: "FIREFOX 133",
        source: "curl_firefox133 (curl-impersonate v2.2.2)",
        aliases: &["firefox", "firefox-like", "firefox133"],
        curl: Some(CurlNames::Only(&["curl_firefox"], &[133])),
        baseline: false,
        ciphers: &[
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
        ],
        groups: &[
            4588, // X25519MLKEM768
            29,   // X25519
            23,   // secp256r1
            24,   // secp384r1
            25,   // secp521r1
            256,  // ffdhe2048
            257,  // ffdhe3072
        ],
        sig_algs: &[
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
        ],
        ext_order: &[
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
        ],
        raw_exts: &[
            // Empty renegotiated_connection vector.
            (EXT_RENEGOTIATION_INFO, &[0x00]),
            // delegated_credentials: signature-scheme list, ECDSA only.
            (EXT_DELEGATED_CREDENTIALS, &[0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03]),
            // record_size_limit: RFC 8449, 0x4001 as Firefox sends it.
            (EXT_RECORD_SIZE_LIMIT, &[0x40, 0x01]),
            // ec_point_formats fallback: rustls derives it from the provider's
            // groups, which need not include every advertised curve.
            (EXT_EC_POINT_FORMATS, &[0x01, 0x00]),
            // session_ticket: empty in a fresh session, and rustls omits the
            // extension entirely from a TLS 1.3-only hello — Firefox sends it in
            // both, so the profile supplies it.
            (EXT_SESSION_TICKET, &[]),
        ],
        // Nothing suppressed: 35 and 45 are part of Firefox 133's shape.
        suppress: &[],
        // Firefox 133 keeps `extended_master_secret` and `renegotiation_info` at
        // 1.3, and drops `session_ticket` there.
        drop13: &[EXT_EC_POINT_FORMATS, EXT_SESSION_TICKET],
        drop12: &[EXT_SUPPORTED_VERSIONS],
        alpn: H2_AND_HTTP11,
        // Firefox sends no padding; the JA3 this profile is pinned to has none.
        padding_to: None,
        grease: false,
        // zlib, brotli — the two this build can actually decompress (`zstd` is
        // not a rustls feature; advertising it would invite a
        // CompressedCertificate we cannot read). The algorithm *list* is not
        // part of JA3/JA4, only the presence of extension 27 is.
        cert_compression: &[1, 2],
        pq: true,
        // Firefox 133 offers 1.3 and 1.2 only.
        legacy_versions: &[],
        headers: Some(FIREFOX_HEADERS),
        h2: Some(&FIREFOX_H2),
    },
    // The `curl_chrome107` shape — Chrome 107, and the same TLS shape as Edge
    // 99–101.
    //
    // Taken from the `curl-impersonate v2.2.2` bundle this repository measures
    // against (`.bat` wrapper `curl_chrome107`), and identical to what
    // `curl_chrome99..104` send: those emit the *same* JA3, so one profile
    // reproduces the whole deterministic half of the fingerprint list the forum
    // report attributes to TSPU. `chrome110` and later permute the extension
    // order (`--tls-permute-extensions`), and `chrome119+` add ECH, which is why
    // those are reported as blocking only ~8–30% of the time.
    //
    // Deliberate deviations: no GREASE *version* entry (rustls builds
    // `supported_versions` from the config, and versions are not hashed) and no
    // `encrypted_client_hello` (Chrome 107 predates it). See
    // `tests::bundle_versions_match_their_ja3`.
    TlsShape {
        variant: TlsFingerprint::Chrome,
        code: "chrome",
        token: "CHROME",
        label: "CHROME 107",
        source: "curl_chrome107 (curl-impersonate v2.2.2)",
        aliases: &["chrome", "chrome99", "chrome107"],
        curl: Some(CurlNames::UpTo(&["curl_chrome", "curl_edge"], 107)),
        baseline: false,
        ciphers: CHROME_TLS_CIPHERS,
        groups: CHROME_TLS_GROUPS,
        sig_algs: CHROME_TLS_SIG_ALGS,
        ext_order: CHROME_TLS_EXT_ORDER,
        raw_exts: CHROME_TLS_RAW_EXTS,
        // Chrome sends session_ticket and psk_key_exchange_modes, so nothing is
        // suppressed — the difference from rustls' defaults is additive.
        suppress: &[],
        drop13: &[
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_EC_POINT_FORMATS,
            EXT_SESSION_TICKET,
        ],
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_APPLICATION_SETTINGS, EXT_PADDING],
        alpn: H2_AND_HTTP11,
        padding_to: Some(512),
        grease: true,
        cert_compression: BROTLI,
        pq: false,
        // Chrome 107 offers 1.3 and 1.2 only (`curl_chrome107` sends neither
        // 1.1 nor 1.0).
        legacy_versions: &[],
        headers: Some(CHROME_HEADERS),
        h2: Some(&CHROME_H2),
    },
    // The `curl_safari155` shape — Safari 15.5, and 15.5–18.4 alike.
    //
    // Taken from the `curl-impersonate v2.2.2` bundle (`.bat` wrapper
    // `curl_safari155`); `curl_safari170`, `curl_safari172_ios`,
    // `curl_safari180`, `curl_safari180_ios`, `curl_safari184` and
    // `curl_safari184_ios` all send the identical JA3. Safari differs from
    // Chrome in ways a profile has to reproduce: 20 ciphers (CBC-heavy), four
    // groups, a duplicated `RSA-PSS SHA-384` signature scheme, no
    // `session_ticket`, no ALPS, and zlib rather than brotli for certificate
    // compression. See `tests::bundle_versions_match_their_ja3`.
    TlsShape {
        variant: TlsFingerprint::Safari,
        code: "safari",
        token: "SAFARI",
        label: "SAFARI 155",
        source: "curl_safari155 (curl-impersonate v2.2.2)",
        aliases: &["safari", "safari155", "safari184"],
        curl: Some(CurlNames::Only(&["curl_safari"], &[155, 170, 172, 180, 184])),
        baseline: false,
        ciphers: SAFARI_TLS_CIPHERS,
        groups: SAFARI_TLS_GROUPS,
        sig_algs: SAFARI_TLS_SIG_ALGS,
        ext_order: SAFARI_TLS_EXT_ORDER,
        raw_exts: SAFARI_TLS_RAW_EXTS,
        // rustls sends session_ticket; Safari does not.
        suppress: &[EXT_SESSION_TICKET],
        drop13: &[EXT_EXTENDED_MASTER_SECRET, EXT_RENEGOTIATION_INFO, EXT_EC_POINT_FORMATS],
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_PADDING],
        alpn: H2_AND_HTTP11,
        padding_to: Some(512),
        grease: true,
        // zlib, exactly what Safari advertises.
        cert_compression: &[1],
        pq: false,
        // Safari 15.5 keeps offering TLS 1.1 and 1.0 behind 1.2, and
        // `curl_safari155` sends both. They go on the wire verbatim; rustls still
        // negotiates nothing below 1.2, so a peer that selects one of them ends
        // the handshake in `PeerIncompatible::ServerDoesNotSupportTls12Or13` —
        // which the classifier already reads as `NO TLS1.3`, not as a block.
        legacy_versions: &[0x0302, 0x0301],
        headers: Some(SAFARI_HEADERS),
        h2: Some(&SAFARI_H2),
    },
];

impl CurlNames {
    /// True when `value` names one of the bundle profiles that emit this shape.
    fn matches(&self, value: &str) -> bool {
        match self {
            CurlNames::UpTo(prefixes, max) => prefixes
                .iter()
                .any(|prefix| curl_version(value, prefix).is_some_and(|version| version <= *max)),
            CurlNames::Only(prefixes, versions) => prefixes
                .iter()
                .any(|prefix| curl_version(value, prefix).is_some_and(|v| versions.contains(&v))),
        }
    }
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

impl TlsShape {
    /// True when `value` (already lowercased and trimmed) names this shape —
    /// either by one of its own names or by a bundle profile it reproduces.
    pub(crate) fn matches_name(&self, value: &str) -> bool {
        self.aliases.contains(&value)
            || self.curl.as_ref().is_some_and(|curl| curl.matches(value))
    }

    /// The ClientHello shape rustls writes for this record, `None` for the
    /// baseline — the one row that installs no profile at all.
    pub(crate) fn build(&self) -> Option<ClientHelloProfile> {
        if self.baseline {
            return None;
        }
        Some(ClientHelloProfile {
            cipher_suites: Some(self.ciphers.to_vec()),
            groups: Some(self.groups.to_vec()),
            signature_schemes: Some(self.sig_algs.to_vec()),
            alpn: Some(self.alpn.iter().map(|protocol| protocol.to_vec()).collect()),
            extension_order: Some(self.ext_order.to_vec()),
            raw_extensions: self.raw_exts.iter().map(|(ext, body)| (*ext, body.to_vec())).collect(),
            suppress_extensions: self.suppress.to_vec(),
            grease: self.grease,
            cert_compression: Some(self.cert_compression.to_vec()),
            padding_to: self.padding_to,
            legacy_versions: self.legacy_versions.to_vec(),
        })
    }
}

/// Extension type ids referenced by the shapes above.
pub(crate) const EXT_SERVER_NAME: u16 = 0;
pub(crate) const EXT_STATUS_REQUEST: u16 = 5;
pub(crate) const EXT_SUPPORTED_GROUPS: u16 = 10;
pub(crate) const EXT_EC_POINT_FORMATS: u16 = 11;
pub(crate) const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub(crate) const EXT_ALPN: u16 = 16;
pub(crate) const EXT_SCT: u16 = 18;
pub(crate) const EXT_PADDING: u16 = 21;
pub(crate) const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
pub(crate) const EXT_COMPRESS_CERTIFICATE: u16 = 27;
pub(crate) const EXT_RECORD_SIZE_LIMIT: u16 = 28;
pub(crate) const EXT_DELEGATED_CREDENTIALS: u16 = 34;
pub(crate) const EXT_SESSION_TICKET: u16 = 35;
pub(crate) const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub(crate) const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
pub(crate) const EXT_KEY_SHARE: u16 = 51;
pub(crate) const EXT_RENEGOTIATION_INFO: u16 = 65281;
/// Chrome's ALPS (draft-vvv-tls-alps), as Chrome 107 and Safari send it.
pub(crate) const EXT_APPLICATION_SETTINGS: u16 = 17513;
