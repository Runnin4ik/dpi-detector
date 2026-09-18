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

use super::h2::{
    H2Fingerprint, CHROME120_H2, CHROME99_ANDROID_H2, CHROME_H2, EDGE101_H2, FIREFOX_H2,
    SAFARI18_H2, SAFARI260_H2, SAFARI_H2,
};
use super::identity::{
    CHROME120_HEADERS, CHROME131_ANDROID_HEADERS, CHROME131_HEADERS, CHROME133_HEADERS,
    CHROME136_HEADERS, CHROME99_ANDROID_HEADERS, CHROME_HEADERS, EDGE101_HEADERS,
    FIREFOX135_HEADERS, FIREFOX144_HEADERS, FIREFOX_HEADERS, SAFARI153_HEADERS, SAFARI184_IOS_HEADERS,
    SAFARI18_HEADERS, SAFARI260_HEADERS, SAFARI260_IOS_HEADERS, SAFARI_HEADERS, TOR_HEADERS,
};
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
///
/// The device wrappers are the same ClientHello behind a different identity
/// (`curl_chrome131_android` is Chrome 131's hello with an Android UA and
/// `sec-ch-ua-platform: "Android"`), so a record answers to them only when its
/// own identity is that device's — hence the suffix every arm carries.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CurlNames {
    /// Every numbered profile of these prefixes up to and including the
    /// version, whose name ends in one of `suffixes` right after the digits.
    UpTo(&'static [&'static str], u16, &'static [&'static str]),
    /// Only the versions named, because the bundle changes shape between them.
    Only(&'static [&'static str], &'static [u16], &'static [&'static str]),
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

/// Safari 26.0's groups: the four above with the hybrid group in front, which
/// is the whole TLS difference between 26.0 on macOS and 26.0 on iOS.
const SAFARI_TLS_PQ_GROUPS: &[u16] = &[
    4588, // X25519MLKEM768
    29,   // X25519
    23,   // secp256r1
    24,   // secp384r1
    25,   // secp521r1
];

/// Safari 15.3 and 15.5's signature schemes, as the wire carries them: the
/// wrapper's list with `rsa_pss_rsae_sha384` twice, eleven entries.
///
/// BoringSSL sends the duplicate rather than collapsing it — measured on
/// `curl_safari153` and `curl_safari155` against a local listener, and visible
/// in the bundle's own `safari_15.5_macos12.4` capture — and JA4 hashes this
/// list, so the duplicate is part of the fingerprint: with ten entries the
/// extension hash is ours, with eleven it is the bundle's `14788d8d241b`.
const SAFARI_TLS_SIG_ALGS: &[u16] = &[
    0x0403, // ECDSA P-256 SHA-256
    0x0804, // RSA-PSS SHA-256
    0x0401, // RSA-PKCS1 SHA-256
    0x0503, // ECDSA P-384 SHA-384
    0x0203, // ECDSA SHA-1 — Safari 15.5 sends it, Safari 18 does not
    0x0805, // RSA-PSS SHA-384
    0x0805, // RSA-PSS SHA-384 again, as `curl_safari155` lists it
    0x0501, // RSA-PKCS1 SHA-384
    0x0806, // RSA-PSS SHA-512
    0x0601, // RSA-PKCS1 SHA-512
    0x0201, // RSA-PKCS1 SHA-1
];

/// Safari 18.x and 26.x's signature schemes: the list above without
/// `ecdsa_sha1`, which Safari 18 dropped, duplicate included.
///
/// That one scheme is the whole difference between the two extensions hashes
/// (`e42f34c56612` for 18.0 against `14788d8d241b` for 15.5), which is why the
/// 18.0 record cannot reuse the 15.5 lists wholesale and why JA4 — the only
/// fingerprint that hashes this list — is what caught it.
const SAFARI18_TLS_SIG_ALGS: &[u16] = &[
    0x0403, // ECDSA P-256 SHA-256
    0x0804, // RSA-PSS SHA-256
    0x0401, // RSA-PKCS1 SHA-256
    0x0503, // ECDSA P-384 SHA-384
    0x0805, // RSA-PSS SHA-384
    0x0805, // RSA-PSS SHA-384 again
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

/// Chrome 110–131's extension order: Chrome 99–107's list without the padding
/// slot, which those releases no longer send.
///
/// `curl_chrome110…131` carry no extension 21 (nothing pads their 300-odd-byte
/// hello), and uTLS's `HelloChrome_120`/`HelloChrome_131` name the rest in
/// exactly this order. Chromium permutes per connection, so this is one order
/// out of the distribution the same way Chrome 133's is: the tests pin the
/// extension *set* and the order-insensitive JA4.
const CHROME_NO_PADDING_EXT_ORDER: &[u16] = &[
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
];

/// Chrome 133–146's extension order, uTLS `HelloChrome_133`'s pre-shuffle list:
/// the same entries as above with ALPS at its new code point.
const CHROME_ALPS_NEW_EXT_ORDER: &[u16] = &[
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
    EXT_APPLICATION_SETTINGS_NEW,
    GREASE_EXTENSION_MARKER,
];

/// The bodies Chrome 133–146 emit verbatim: the shared set with ALPS at its new
/// code point, same one-protocol body.
const CHROME_ALPS_NEW_RAW_EXTS: &[(u16, &[u8])] = &[
    (EXT_RENEGOTIATION_INFO, &[0x00]),
    (EXT_EC_POINT_FORMATS, &[0x01, 0x00]),
    (EXT_SCT, &[]),
    (EXT_SESSION_TICKET, &[]),
    (EXT_APPLICATION_SETTINGS_NEW, &[0x00, 0x03, 0x02, b'h', b'2']),
];

/// The groups Chrome 120 and 131's Android wrapper lead with: X25519, P-256,
/// P-384, no hybrid — the one thing `curl_chrome131_android` drops from its
/// desktop sibling (`--curves X25519:P-256:P-384`).
const CHROME_TLS_PQ_GROUPS: &[u16] = &[
    4588, // X25519MLKEM768
    29,   // X25519
    23,   // secp256r1
    24,   // secp384r1
];

/// Safari 15.3's cipher list: 15.5's twenty plus six CBC/SHA-256 suites that
/// 15.5 dropped — `curl_safari153` lists 26 and `curl_safari155` lists 20, and
/// the bundle's `safari_15.3_macos11.6.4` capture agrees. JA3 shows the
/// difference in its first field, which is why 15.3 is a record of its own
/// rather than another alias of `safari`.
const SAFARI153_TLS_CIPHERS: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0xc02c, // ECDHE_ECDSA_AES256_GCM_SHA384
    0xc02b, // ECDHE_ECDSA_AES128_GCM_SHA256
    0xcca9, // ECDHE_ECDSA_CHACHA20_POLY1305
    0xc030, // ECDHE_RSA_AES256_GCM_SHA384
    0xc02f, // ECDHE_RSA_AES128_GCM_SHA256
    0xcca8, // ECDHE_RSA_CHACHA20_POLY1305
    0xc024, // ECDHE_ECDSA_AES256_CBC_SHA384
    0xc023, // ECDHE_ECDSA_AES128_CBC_SHA256
    0xc00a, // ECDHE_ECDSA_AES256_CBC_SHA
    0xc009, // ECDHE_ECDSA_AES128_CBC_SHA
    0xc028, // ECDHE_RSA_AES256_CBC_SHA384
    0xc027, // ECDHE_RSA_AES128_CBC_SHA256
    0xc014, // ECDHE_RSA_AES256_CBC_SHA
    0xc013, // ECDHE_RSA_AES128_CBC_SHA
    0x009d, // RSA_AES256_GCM_SHA384
    0x009c, // RSA_AES128_GCM_SHA256
    0x003d, // RSA_AES256_CBC_SHA256
    0x003c, // RSA_AES128_CBC_SHA256
    0x0035, // RSA_AES256_CBC_SHA
    0x002f, // RSA_AES128_CBC_SHA
    0xc008, // ECDHE_ECDSA_3DES_EDE_CBC_SHA
    0xc012, // ECDHE_RSA_3DES_EDE_CBC_SHA
    0x000a, // RSA_3DES_EDE_CBC_SHA
];

/// Safari 15.3's extension order: 15.5's without `compress_certificate`, which
/// `curl_safari153` does not advertise (its wrapper passes no
/// `--cert-compression`), and with the same GREASE slots.
const SAFARI153_TLS_EXT_ORDER: &[u16] = &[
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
    GREASE_EXTENSION_MARKER,
    EXT_PADDING,
];

/// Safari 26.0's cipher list: the same twenty suites with the three TLS 1.3 ones
/// reordered (`4866-4867-4865`), the only JA3-visible change in them. JA4 sorts
/// what it hashes, so this list hashes to 15.5's cipher hash and the difference
/// lives in JA3 alone.
const SAFARI260_TLS_CIPHERS: &[u16] = &[
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0x1301, // TLS_AES_128_GCM_SHA256
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

/// Safari 26.0's extension order, read from `curl_safari260`: no padding, and
/// `session_ticket` back after the point formats.
const SAFARI260_TLS_EXT_ORDER: &[u16] = &[
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
    GREASE_EXTENSION_MARKER,
];

/// Safari 26.0 iOS's extension order: the same with padding, which iOS still
/// sends — its hello measures 512 bytes, macOS 26's does not.
const SAFARI260_IOS_TLS_EXT_ORDER: &[u16] = &[
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
    GREASE_EXTENSION_MARKER,
    EXT_PADDING,
];

/// Firefox 133–144's cipher list, and Tor 14.5's without the two CBC suites at
/// `49162`/`49161`.
const FIREFOX_TLS_CIPHERS: &[u16] = &[
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
];

/// Tor Browser 14.5's cipher list: Firefox 128 ESR's, fifteen suites.
const TOR_TLS_CIPHERS: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0xc02b, // ECDHE_ECDSA_AES128_GCM_SHA256
    0xc02f, // ECDHE_RSA_AES128_GCM_SHA256
    0xcca9, // ECDHE_ECDSA_CHACHA20_POLY1305
    0xcca8, // ECDHE_RSA_CHACHA20_POLY1305
    0xc02c, // ECDHE_ECDSA_AES256_GCM_SHA384
    0xc030, // ECDHE_RSA_AES256_GCM_SHA384
    0xc013, // ECDHE_RSA_AES128_CBC_SHA
    0xc014, // ECDHE_RSA_AES256_CBC_SHA
    0x009c, // RSA_AES128_GCM_SHA256
    0x009d, // RSA_AES256_GCM_SHA384
    0x002f, // RSA_AES128_CBC_SHA
    0x0035, // RSA_AES256_CBC_SHA
];

/// Firefox 133–144's groups: the hybrid group first, then X25519, the two NIST
/// curves and the two finite-field groups Firefox lists without ever sharing a
/// key with them.
const FIREFOX_TLS_GROUPS: &[u16] = &[
    4588, // X25519MLKEM768
    29,   // X25519
    23,   // secp256r1
    24,   // secp384r1
    25,   // secp521r1
    256,  // ffdhe2048
    257,  // ffdhe3072
];

/// Tor Browser 14.5's groups: Firefox's without the hybrid group, which Tor
/// 14.5 (Firefox 128 ESR) does not offer.
const TOR_TLS_GROUPS: &[u16] = &[
    29,  // X25519
    23,  // secp256r1
    24,  // secp384r1
    25,  // secp521r1
    256, // ffdhe2048
    257, // ffdhe3072
];

/// Firefox 133–144's signature schemes. `curl_tor145` sends the same eleven in
/// the same order.
const FIREFOX_TLS_SIG_ALGS: &[u16] = &[
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
];

/// Firefox 133's extension order, GREASE-free (Firefox does not grease).
const FIREFOX_TLS_EXT_ORDER: &[u16] = &[
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
];

/// Firefox 135–144's extension order: 133's with
/// `signed_certificate_timestamp` after `delegated_credentials`, which is the
/// single extension Firefox added in between.
const FIREFOX135_TLS_EXT_ORDER: &[u16] = &[
    EXT_SERVER_NAME,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_RENEGOTIATION_INFO,
    EXT_SUPPORTED_GROUPS,
    EXT_EC_POINT_FORMATS,
    EXT_SESSION_TICKET,
    EXT_ALPN,
    EXT_STATUS_REQUEST,
    EXT_DELEGATED_CREDENTIALS,
    EXT_SCT,
    EXT_KEY_SHARE,
    EXT_SUPPORTED_VERSIONS,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_PSK_KEY_EXCHANGE_MODES,
    EXT_RECORD_SIZE_LIMIT,
    EXT_COMPRESS_CERTIFICATE,
];

/// Tor Browser 14.5's extension order, exactly the wrapper's
/// `--tls-extension-order`: no GREASE (Tor does not grease), no
/// `compress_certificate`, no SCT, and ECH last — which this build omits, so
/// the order stops at `record_size_limit`.
const TOR_TLS_EXT_ORDER: &[u16] = &[
    EXT_SERVER_NAME,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_RENEGOTIATION_INFO,
    EXT_SUPPORTED_GROUPS,
    EXT_EC_POINT_FORMATS,
    EXT_ALPN,
    EXT_STATUS_REQUEST,
    EXT_DELEGATED_CREDENTIALS,
    EXT_KEY_SHARE,
    EXT_SUPPORTED_VERSIONS,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_RECORD_SIZE_LIMIT,
];

/// The bodies Firefox 133–144 emit verbatim. The SCT entry is inert in 133's
/// hello (the extension is not in its order) and live in 135's.
const FIREFOX_TLS_RAW_EXTS: &[(u16, &[u8])] = &[
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
    // signed_certificate_timestamp is empty in a ClientHello.
    (EXT_SCT, &[]),
];

/// The bodies Safari 26.x emit verbatim: the 18.x set with the session ticket
/// back, which 26.x sends and the older Safari rows suppress. The padding entry
/// is inert where the order does not name it, which is macOS 26.
const SAFARI260_TLS_RAW_EXTS: &[(u16, &[u8])] = &[
    (EXT_RENEGOTIATION_INFO, &[0x00]),
    (EXT_EC_POINT_FORMATS, &[0x01, 0x00]),
    (EXT_SCT, &[]),
    (EXT_SESSION_TICKET, &[]),
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
        curl: Some(CurlNames::Only(&["curl_firefox"], &[133], &[""])),
        baseline: false,
        ciphers: FIREFOX_TLS_CIPHERS,
        groups: FIREFOX_TLS_GROUPS,
        sig_algs: FIREFOX_TLS_SIG_ALGS,
        ext_order: FIREFOX_TLS_EXT_ORDER,
        raw_exts: FIREFOX_TLS_RAW_EXTS,
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
        curl: Some(CurlNames::UpTo(&["curl_chrome"], 107, &[""])),
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
    // The `curl_safari155` shape — Safari 15.5 and 17.0, which send one hello.
    //
    // Taken from the `curl-impersonate v2.2.2` bundle (`.bat` wrapper
    // `curl_safari155`); `curl_safari170` sends the identical JA3, and so do
    // `curl_safari180`/`curl_safari184`, whose *JA4* differs by one signature
    // scheme (`ecdsa_sha1`, see [`SAFARI18_TLS_SIG_ALGS`]) — which is why 18.x
    // has a record of its own. Safari differs from Chrome in ways a profile has
    // to reproduce: 20 ciphers (CBC-heavy), four groups, a duplicated
    // `RSA-PSS SHA-384` signature scheme, no `session_ticket`, no ALPS, and zlib
    // rather than brotli for certificate compression. See
    // `tests::bundle_versions_match_their_ja3`.
    //
    // This row is the shape and the identity Safari 15.5 and 17.0 send: the
    // report's older bundle versions, and the flagship "Safari" the TSPU rule
    // names.
    TlsShape {
        variant: TlsFingerprint::Safari,
        code: "safari",
        token: "SAFARI",
        label: "SAFARI 155",
        source: "curl_safari155 (curl-impersonate v2.2.2)",
        aliases: &["safari", "safari155", "safari170"],
        curl: Some(CurlNames::Only(&["curl_safari"], &[155, 170], &[""])),
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
    // Chrome 133, as `curl_chrome133a` of curl-impersonate v2.2.3 sends it and
    // as uTLS `HelloChrome_133` (v1.8.2, unchanged on master) defines it. Both
    // sources agree on every list; uTLS supplies the extension *order* the
    // bundle cannot, because Chromium permutes it per connection.
    //
    // What differs from Chrome 107: the hybrid `X25519MLKEM768` group leads the
    // list (and is shared, so the hello carries an ML-KEM and an X25519 share),
    // ALPS moves to its new code point 17613 (`HelloChrome_131` is the same
    // shape with the old 17513 — that is why 131 is not an alias), padding is
    // gone, and `accept-encoding` gained `zstd`.
    //
    // Two things a permuted, ECH-carrying client cannot give this build:
    //
    // * `encrypted_client_hello` (65037) is omitted for the reason in the
    //   Firefox record — a body we synthesize is rejected by every ECH-aware
    //   server. JA3 and JA4 therefore carry one extension fewer than the
    //   source's, which is why the tests pin the extension *set* and the
    //   JA4 cipher hash rather than a whole JA4 string: no source publishes a
    //   hash for an ECH-less Chrome 133, and pinning our own dump would lock in
    //   whatever this build happens to send.
    // * the order below is uTLS's pre-shuffle list. Chromium randomizes the
    //   order of every hello (`ShuffleChromeTLSExtensions`), so a real Chrome
    //   133 sends one of many orders and its JA3 differs per connection; JA4,
    //   which sorts what it hashes, is the stable key. This profile sends one
    //   order from that distribution, deterministically, which is what makes a
    //   column of the burst reproducible at all.
    TlsShape {
        variant: TlsFingerprint::Chrome133,
        code: "chrome133",
        token: "CHROME",
        label: "CHROME 133",
        source: "curl_chrome133a (curl-impersonate v2.2.3) / uTLS HelloChrome_133 (v1.8.2)",
        aliases: &["chrome133", "chrome133a"],
        curl: Some(CurlNames::Only(&["curl_chrome"], &[133], &["", "a"])),
        baseline: false,
        ciphers: CHROME_TLS_CIPHERS,
        groups: CHROME_TLS_PQ_GROUPS,
        sig_algs: CHROME_TLS_SIG_ALGS,
        ext_order: CHROME_ALPS_NEW_EXT_ORDER,
        raw_exts: CHROME_ALPS_NEW_RAW_EXTS,
        suppress: &[],
        drop13: &[
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_EC_POINT_FORMATS,
            EXT_SESSION_TICKET,
        ],
        // No padding in this shape, so only the version list and ALPS go.
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_APPLICATION_SETTINGS_NEW],
        alpn: H2_AND_HTTP11,
        // Chrome 110+ stopped padding: the captured 133 hello is far past the
        // 256-byte floor anyway, with an ML-KEM share in it.
        padding_to: None,
        grease: true,
        cert_compression: BROTLI,
        pq: true,
        legacy_versions: &[],
        headers: Some(CHROME133_HEADERS),
        h2: Some(&CHROME120_H2),
    },
    // Safari 18.0, as `curl_safari180` of curl-impersonate v2.2.3 sends it (and
    // 18.4, `curl_safari184`, which sends the same hello).
    //
    // The cipher, group and extension lists are Safari 15.5's, but the
    // *signature schemes* are not: Safari 18 dropped `ecdsa_sha1`, and JA4 —
    // the only fingerprint that hashes this list — reads the two hellos as
    // `e42f34c56612` and `14788d8d241b`. An earlier version of this record
    // reused the 15.5 list, which made its extension hash ours instead of the
    // bundle's; the duplicate `rsa_pss_rsae_sha384` was missing for the same
    // reason. Both are in [`SAFARI18_TLS_SIG_ALGS`] now.
    //
    // It answers the question the older Safari row cannot: whether a *current*
    // Safari is treated like the version the forum report named. The HTTP
    // identity is the 18.x one (`Version/18.0`, a `priority` header,
    // `en-US,en;q=0.9`), and the preface is Safari's own.
    TlsShape {
        variant: TlsFingerprint::Safari18,
        code: "safari18",
        token: "SAFARI",
        label: "SAFARI 18",
        source: "curl_safari180 / curl_safari184 (curl-impersonate v2.2.2)",
        aliases: &["safari18", "safari180", "safari184"],
        curl: Some(CurlNames::Only(&["curl_safari"], &[180, 184], &[""])),
        baseline: false,
        ciphers: SAFARI_TLS_CIPHERS,
        groups: SAFARI_TLS_GROUPS,
        sig_algs: SAFARI18_TLS_SIG_ALGS,
        ext_order: SAFARI_TLS_EXT_ORDER,
        raw_exts: SAFARI_TLS_RAW_EXTS,
        suppress: &[EXT_SESSION_TICKET],
        drop13: &[EXT_EXTENDED_MASTER_SECRET, EXT_RENEGOTIATION_INFO, EXT_EC_POINT_FORMATS],
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_PADDING],
        alpn: H2_AND_HTTP11,
        padding_to: Some(512),
        grease: true,
        cert_compression: &[1],
        pq: false,
        legacy_versions: &[0x0302, 0x0301],
        headers: Some(SAFARI18_HEADERS),
        h2: Some(&SAFARI18_H2),
    },
    // Edge 101, as `curl_edge101` of curl-impersonate v2.2.3 sends it, with
    // uTLS `HelloEdge_106` as the second reading of the same shape.
    //
    // Edge is Chromium: the TLS lists above are Chrome 99–107's, and the bundle
    // documents that Chromium browsers differ only in `User-Agent` and
    // `sec-ch-ua-platform`. The identity is therefore the whole point of this
    // record, and so is the one h2 difference — Edge sends no
    // `SETTINGS_ENABLE_PUSH`.
    TlsShape {
        variant: TlsFingerprint::Edge,
        code: "edge101",
        token: "EDGE",
        label: "EDGE 101",
        source: "curl_edge101 (curl-impersonate v2.2.3) / uTLS HelloEdge_106 (v1.8.2)",
        aliases: &["edge", "edge99", "edge101"],
        curl: Some(CurlNames::Only(&["curl_edge"], &[99, 101], &[""])),
        baseline: false,
        ciphers: CHROME_TLS_CIPHERS,
        groups: CHROME_TLS_GROUPS,
        sig_algs: CHROME_TLS_SIG_ALGS,
        ext_order: CHROME_TLS_EXT_ORDER,
        raw_exts: CHROME_TLS_RAW_EXTS,
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
        legacy_versions: &[],
        headers: Some(EDGE101_HEADERS),
        h2: Some(&EDGE101_H2),
    },
    // Chrome 99 on Android, as `curl_chrome99_android` sends it: Chrome 107's
    // hello behind a phone's identity.
    //
    // The TLS lists are [`CHROME_TLS_*`] — the bundle's own
    // `chrome_99.0.4844.73_android12-pixel6` capture carries the same JA3 as its
    // Windows sibling — so what makes this a row of its own is everything above
    // the hello: `sec-ch-ua-mobile: ?1`, `sec-ch-ua-platform: "Android"`, a
    // Pixel 6 UA, and an HTTP/2 preface with no `SETTINGS_ENABLE_PUSH` and a
    // concurrent-stream cap of 1000. A censor that reads the UA and the header
    // set treats a phone differently from a desktop, and this is the shape to
    // measure that with.
    //
    // It is also the first record whose bundle name carries a device suffix:
    // `parse("curl_chrome99_android")` used to answer `chrome` (Chrome 99 ≤ 107),
    // which sent a Windows UA for an Android profile.
    TlsShape {
        variant: TlsFingerprint::Chrome99Android,
        code: "chrome99android",
        token: "CHROME",
        label: "CHROME 99 ANDROID",
        source: "curl_chrome99_android (curl-impersonate v2.2.2)",
        aliases: &["chrome99android", "chrome99_android", "chrome-android"],
        curl: Some(CurlNames::Only(&["curl_chrome"], &[99], &["_android"])),
        baseline: false,
        ciphers: CHROME_TLS_CIPHERS,
        groups: CHROME_TLS_GROUPS,
        sig_algs: CHROME_TLS_SIG_ALGS,
        ext_order: CHROME_TLS_EXT_ORDER,
        raw_exts: CHROME_TLS_RAW_EXTS,
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
        legacy_versions: &[],
        headers: Some(CHROME99_ANDROID_HEADERS),
        h2: Some(&CHROME99_ANDROID_H2),
    },
    // Chrome 120, as `curl_chrome120` sends it: the first Chromium release in
    // this bundle that pads nothing and adds ECH.
    //
    // What differs from Chrome 107: no padding extension, ALPS still at 17513,
    // `encrypted_client_hello` (65037) — omitted here for the reason in the
    // Firefox record, so this hello carries one extension fewer than
    // `curl_chrome120` — and an HTTP layer that keeps `accept-encoding: gzip,
    // deflate, br` and sends no `priority` header, which is why one header table
    // per version is the honest description rather than one per family.
    //
    // `curl_chrome119` and `curl_chrome123` send the same shape with another UA;
    // they are not accepted, because the UA is part of what a probe presents.
    TlsShape {
        variant: TlsFingerprint::Chrome120,
        code: "chrome120",
        token: "CHROME",
        label: "CHROME 120",
        source: "curl_chrome120 (curl-impersonate v2.2.2)",
        aliases: &["chrome120"],
        curl: Some(CurlNames::Only(&["curl_chrome"], &[120], &[""])),
        baseline: false,
        ciphers: CHROME_TLS_CIPHERS,
        groups: CHROME_TLS_GROUPS,
        sig_algs: CHROME_TLS_SIG_ALGS,
        ext_order: CHROME_NO_PADDING_EXT_ORDER,
        raw_exts: CHROME_TLS_RAW_EXTS,
        suppress: &[],
        drop13: &[
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_EC_POINT_FORMATS,
            EXT_SESSION_TICKET,
        ],
        // No padding in the order, so only the version list and ALPS go.
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_APPLICATION_SETTINGS],
        alpn: H2_AND_HTTP11,
        padding_to: None,
        grease: true,
        cert_compression: BROTLI,
        pq: false,
        legacy_versions: &[],
        headers: Some(CHROME120_HEADERS),
        h2: Some(&CHROME120_H2),
    },
    // Chrome 131, as `curl_chrome131` sends it: Chrome 133's shape one
    // code point earlier — the hybrid group leads the list and is shared, ALPS
    // is still at 17513, and there is no padding.
    //
    // It is the profile that separates the two halves of the "post-quantum
    // group" question a censor can read: 131 and 133 differ in the ALPS code
    // point and in nothing a JA3 carries, so a site that blocks 133 and passes
    // 131 is reacting to something other than the group.
    TlsShape {
        variant: TlsFingerprint::Chrome131,
        code: "chrome131",
        token: "CHROME",
        label: "CHROME 131",
        source: "curl_chrome131 (curl-impersonate v2.2.2)",
        aliases: &["chrome131"],
        curl: Some(CurlNames::Only(&["curl_chrome"], &[131], &[""])),
        baseline: false,
        ciphers: CHROME_TLS_CIPHERS,
        groups: CHROME_TLS_PQ_GROUPS,
        sig_algs: CHROME_TLS_SIG_ALGS,
        ext_order: CHROME_NO_PADDING_EXT_ORDER,
        raw_exts: CHROME_TLS_RAW_EXTS,
        suppress: &[],
        drop13: &[
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_EC_POINT_FORMATS,
            EXT_SESSION_TICKET,
        ],
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_APPLICATION_SETTINGS],
        alpn: H2_AND_HTTP11,
        padding_to: None,
        grease: true,
        cert_compression: BROTLI,
        pq: true,
        legacy_versions: &[],
        headers: Some(CHROME131_HEADERS),
        h2: Some(&CHROME120_H2),
    },
    // Chrome 131 on Android, as `curl_chrome131_android` sends it.
    //
    // Its wrapper's first comment line is the whole difference from the desktop
    // row: "The only difference from desktop is the absense of MLKEM", so the
    // group list is X25519/P-256/P-384 and nothing is post-quantum. Everything
    // else — the ECH extension we omit, the ALPS code point, the header set —
    // tracks the desktop 131 with the phone's UA and platform.
    TlsShape {
        variant: TlsFingerprint::Chrome131Android,
        code: "chrome131android",
        token: "CHROME",
        label: "CHROME 131 ANDROID",
        source: "curl_chrome131_android (curl-impersonate v2.2.2)",
        aliases: &["chrome131android", "chrome131_android"],
        curl: Some(CurlNames::Only(&["curl_chrome"], &[131], &["_android"])),
        baseline: false,
        ciphers: CHROME_TLS_CIPHERS,
        groups: CHROME_TLS_GROUPS,
        sig_algs: CHROME_TLS_SIG_ALGS,
        ext_order: CHROME_NO_PADDING_EXT_ORDER,
        raw_exts: CHROME_TLS_RAW_EXTS,
        suppress: &[],
        drop13: &[
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_EC_POINT_FORMATS,
            EXT_SESSION_TICKET,
        ],
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_APPLICATION_SETTINGS],
        alpn: H2_AND_HTTP11,
        padding_to: None,
        grease: true,
        cert_compression: BROTLI,
        pq: false,
        legacy_versions: &[],
        headers: Some(CHROME131_ANDROID_HEADERS),
        h2: Some(&CHROME120_H2),
    },
    // Chrome 136, as `curl_chrome136` sends it: the newest desktop Chromium in
    // this bundle, and the same hello as Chrome 133 (the bundle's own capture
    // says so in one line — "The only difference from Chrome 131 is:
    // X25519Kyber768 was replaced by MLKEM" — and `curl_chrome142`,
    // `curl_chrome145` and `curl_chrome146` send it too, 133 through 146 sharing
    // one extension set with ALPS at 17613).
    //
    // The same Hello, a newer identity: this is the profile that answers
    // "is the browser I actually run blocked" for a Chrome past 133, at the cost
    // of one more list of headers.
    TlsShape {
        variant: TlsFingerprint::Chrome136,
        code: "chrome136",
        token: "CHROME",
        label: "CHROME 136",
        source: "curl_chrome136 (curl-impersonate v2.2.2)",
        aliases: &["chrome136"],
        curl: Some(CurlNames::Only(&["curl_chrome"], &[136], &[""])),
        baseline: false,
        ciphers: CHROME_TLS_CIPHERS,
        groups: CHROME_TLS_PQ_GROUPS,
        sig_algs: CHROME_TLS_SIG_ALGS,
        ext_order: CHROME_ALPS_NEW_EXT_ORDER,
        raw_exts: CHROME_ALPS_NEW_RAW_EXTS,
        suppress: &[],
        drop13: &[
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_EC_POINT_FORMATS,
            EXT_SESSION_TICKET,
        ],
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_APPLICATION_SETTINGS_NEW],
        alpn: H2_AND_HTTP11,
        padding_to: None,
        grease: true,
        cert_compression: BROTLI,
        pq: true,
        legacy_versions: &[],
        headers: Some(CHROME136_HEADERS),
        h2: Some(&CHROME120_H2),
    },
    // Firefox 135, as `curl_firefox135` sends it: Firefox 133's hello plus
    // `signed_certificate_timestamp` (18) between `delegated_credentials` and
    // `key_share`.
    //
    // One extension is the whole difference, and it is the one the plan called
    // out as a shape this build could not reproduce: 18 is a body this profile
    // already writes for Chrome, so it costs a record rather than a patch. The
    // deviations are Firefox 133's (no ECH, `zlib, brotli` where the bundle
    // advertises zstd too, two key shares where the wrapper's
    // `--tls-key-shares-limit 3` sends three).
    TlsShape {
        variant: TlsFingerprint::Firefox135,
        code: "firefox135",
        token: "FIREFOX",
        label: "FIREFOX 135",
        source: "curl_firefox135 (curl-impersonate v2.2.2)",
        aliases: &["firefox135"],
        curl: Some(CurlNames::Only(&["curl_firefox"], &[135], &[""])),
        baseline: false,
        ciphers: FIREFOX_TLS_CIPHERS,
        groups: FIREFOX_TLS_GROUPS,
        sig_algs: FIREFOX_TLS_SIG_ALGS,
        ext_order: FIREFOX135_TLS_EXT_ORDER,
        raw_exts: FIREFOX_TLS_RAW_EXTS,
        suppress: &[],
        drop13: &[EXT_EC_POINT_FORMATS, EXT_SESSION_TICKET],
        drop12: &[EXT_SUPPORTED_VERSIONS],
        alpn: H2_AND_HTTP11,
        padding_to: None,
        grease: false,
        cert_compression: &[1, 2],
        pq: true,
        legacy_versions: &[],
        headers: Some(FIREFOX135_HEADERS),
        h2: Some(&FIREFOX_H2),
    },
    // Firefox 144, as `curl_firefox144` sends it (the wrapper is a one-liner —
    // `--impersonate firefox144` — and the bundle's `firefox_144.0.0_linux`
    // capture is the reading of it this record is pinned to).
    //
    // The hello is Firefox 135's byte for byte; what a DPI middlebox can read
    // differently is the identity, which is the reason to carry both.
    // `curl_firefox147` sends the same hello again and is not accepted, for the
    // same reason 119/123 are not: the UA is part of what a probe presents.
    TlsShape {
        variant: TlsFingerprint::Firefox144,
        code: "firefox144",
        token: "FIREFOX",
        label: "FIREFOX 144",
        source: "curl_firefox144 (curl-impersonate v2.2.2)",
        aliases: &["firefox144"],
        curl: Some(CurlNames::Only(&["curl_firefox"], &[144], &[""])),
        baseline: false,
        ciphers: FIREFOX_TLS_CIPHERS,
        groups: FIREFOX_TLS_GROUPS,
        sig_algs: FIREFOX_TLS_SIG_ALGS,
        ext_order: FIREFOX135_TLS_EXT_ORDER,
        raw_exts: FIREFOX_TLS_RAW_EXTS,
        suppress: &[],
        drop13: &[EXT_EC_POINT_FORMATS, EXT_SESSION_TICKET],
        drop12: &[EXT_SUPPORTED_VERSIONS],
        alpn: H2_AND_HTTP11,
        padding_to: None,
        grease: false,
        cert_compression: &[1, 2],
        pq: true,
        legacy_versions: &[],
        headers: Some(FIREFOX144_HEADERS),
        h2: Some(&FIREFOX_H2),
    },
    // Safari 15.3, as `curl_safari153` sends it — the one Safari in the bundle
    // whose *cipher list* differs from 15.5's: 26 suites against 20, the six
    // extra ones CBC/SHA-256, and no `compress_certificate`.
    //
    // JA3 carries both differences in its first two fields, so this profile is
    // reproducible exactly: the source publishes its JA3 and JA4
    // (`a94da16745ee3dbe77c10610f3f33a23` / `t13d2613h2_…_845d286b0d67`) and the
    // tests pin both.
    TlsShape {
        variant: TlsFingerprint::Safari153,
        code: "safari153",
        token: "SAFARI",
        label: "SAFARI 153",
        source: "curl_safari153 (curl-impersonate v2.2.2)",
        aliases: &["safari153"],
        curl: Some(CurlNames::Only(&["curl_safari"], &[153], &[""])),
        baseline: false,
        ciphers: SAFARI153_TLS_CIPHERS,
        groups: SAFARI_TLS_GROUPS,
        sig_algs: SAFARI_TLS_SIG_ALGS,
        ext_order: SAFARI153_TLS_EXT_ORDER,
        raw_exts: SAFARI_TLS_RAW_EXTS,
        suppress: &[EXT_SESSION_TICKET],
        drop13: &[EXT_EXTENDED_MASTER_SECRET, EXT_RENEGOTIATION_INFO, EXT_EC_POINT_FORMATS],
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_PADDING],
        alpn: H2_AND_HTTP11,
        padding_to: Some(512),
        grease: true,
        // No `compress_certificate`: the wrapper advertises none.
        cert_compression: &[],
        pq: false,
        legacy_versions: &[0x0302, 0x0301],
        headers: Some(SAFARI153_HEADERS),
        h2: Some(&SAFARI_H2),
    },
    // Safari 18.4 on iOS, as `curl_safari184_ios` sends it: the 18.x hello
    // behind an iPhone's identity.
    //
    // The TLS shape is [`TlsFingerprint::Safari18`]'s — same lists, same
    // preface — and the identity is what the row is for: the iOS UA, its own
    // `priority`, and the Safari 18 h2 preface. `curl_safari180_ios` and
    // `curl_safari172_ios` are not accepted: their UAs name versions this build
    // does not present.
    TlsShape {
        variant: TlsFingerprint::Safari184Ios,
        code: "safari184ios",
        token: "SAFARI",
        label: "SAFARI 184 IOS",
        source: "curl_safari184_ios (curl-impersonate v2.2.2)",
        aliases: &["safari184ios", "safari184_ios", "ios"],
        curl: Some(CurlNames::Only(&["curl_safari"], &[184], &["_ios"])),
        baseline: false,
        ciphers: SAFARI_TLS_CIPHERS,
        groups: SAFARI_TLS_GROUPS,
        sig_algs: SAFARI18_TLS_SIG_ALGS,
        ext_order: SAFARI_TLS_EXT_ORDER,
        raw_exts: SAFARI_TLS_RAW_EXTS,
        suppress: &[EXT_SESSION_TICKET],
        drop13: &[EXT_EXTENDED_MASTER_SECRET, EXT_RENEGOTIATION_INFO, EXT_EC_POINT_FORMATS],
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_PADDING],
        alpn: H2_AND_HTTP11,
        padding_to: Some(512),
        grease: true,
        cert_compression: &[1],
        pq: false,
        legacy_versions: &[0x0302, 0x0301],
        headers: Some(SAFARI184_IOS_HEADERS),
        h2: Some(&SAFARI18_H2),
    },
    // Safari 26.0 on macOS, as `curl_safari260` sends it: the first Safari in
    // the bundle that offers the hybrid group, and the first client of any
    // family whose hello carries no padding *and* a session ticket.
    //
    // Two more firsts worth knowing when a verdict surprises: the three TLS 1.3
    // suites are reordered (`4866-4867-4865`), which only JA3 shows, and the
    // wrapper passes `--http2-no-priority`, so its request `HEADERS` frame
    // carries no PRIORITY — the first profile here whose preface is `None` in
    // that field.
    TlsShape {
        variant: TlsFingerprint::Safari260,
        code: "safari260",
        token: "SAFARI",
        label: "SAFARI 26",
        source: "curl_safari260 (curl-impersonate v2.2.2)",
        aliases: &["safari26", "safari260"],
        curl: Some(CurlNames::Only(&["curl_safari"], &[260], &[""])),
        baseline: false,
        ciphers: SAFARI260_TLS_CIPHERS,
        groups: SAFARI_TLS_PQ_GROUPS,
        sig_algs: SAFARI18_TLS_SIG_ALGS,
        ext_order: SAFARI260_TLS_EXT_ORDER,
        raw_exts: SAFARI260_TLS_RAW_EXTS,
        // The session ticket is part of this shape, so nothing is suppressed.
        suppress: &[],
        drop13: &[EXT_EXTENDED_MASTER_SECRET, EXT_RENEGOTIATION_INFO, EXT_EC_POINT_FORMATS],
        drop12: &[EXT_SUPPORTED_VERSIONS],
        alpn: H2_AND_HTTP11,
        // No padding either, and the hello says so.
        padding_to: None,
        grease: true,
        cert_compression: &[1],
        pq: true,
        // Safari 26 offers 1.3 and 1.2 only, where 15.5–18.4 still listed 1.1
        // and 1.0 behind them.
        legacy_versions: &[],
        headers: Some(SAFARI260_HEADERS),
        h2: Some(&SAFARI260_H2),
    },
    // Safari 26.0 on iOS, as `curl_safari260_ios` sends it.
    //
    // The same release as the macOS row with three differences a middlebox can
    // read: no hybrid group (iOS keeps X25519 first), the padding extension back
    // (its hello measures 512 bytes where macOS 26's does not), and the iOS UA.
    // Everything else, the cipher order and the preface included, matches 26.0
    // on macOS.
    TlsShape {
        variant: TlsFingerprint::Safari260Ios,
        code: "safari260ios",
        token: "SAFARI",
        label: "SAFARI 26 IOS",
        source: "curl_safari260_ios (curl-impersonate v2.2.2)",
        aliases: &["safari260ios", "safari260_ios"],
        curl: Some(CurlNames::Only(&["curl_safari"], &[260], &["_ios"])),
        baseline: false,
        ciphers: SAFARI_TLS_CIPHERS,
        groups: SAFARI_TLS_GROUPS,
        sig_algs: SAFARI18_TLS_SIG_ALGS,
        ext_order: SAFARI260_IOS_TLS_EXT_ORDER,
        raw_exts: SAFARI260_TLS_RAW_EXTS,
        suppress: &[],
        drop13: &[EXT_EXTENDED_MASTER_SECRET, EXT_RENEGOTIATION_INFO, EXT_EC_POINT_FORMATS],
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_PADDING],
        alpn: H2_AND_HTTP11,
        padding_to: Some(512),
        grease: true,
        cert_compression: &[1],
        pq: false,
        legacy_versions: &[],
        headers: Some(SAFARI260_IOS_HEADERS),
        h2: Some(&SAFARI260_H2),
    },
    // Tor Browser 14.5, as `curl_tor145` sends it: Firefox 128 ESR's hello
    // wearing the browser's own identity.
    //
    // Nothing in this profile greases, and that is the shape, not an omission:
    // the wrapper passes no `--tls-grease`, the capture carries no GREASE
    // extension, and the extension order is written out in the wrapper. Tor also
    // lists the two finite-field groups Firefox lists and never shares a key
    // with, and it drops `compress_certificate` — so a hello-shaped block that
    // reacts to extension 27 alone cannot be what passes Tor.
    //
    // One deviation: `encrypted_client_hello` (last in the wrapper's order) is
    // omitted for the reason in the Firefox record.
    TlsShape {
        variant: TlsFingerprint::Tor145,
        code: "tor145",
        token: "TOR",
        label: "TOR 145",
        source: "curl_tor145 (curl-impersonate v2.2.2)",
        aliases: &["tor", "tor145", "tor-browser"],
        curl: Some(CurlNames::Only(&["curl_tor"], &[145], &[""])),
        baseline: false,
        ciphers: TOR_TLS_CIPHERS,
        groups: TOR_TLS_GROUPS,
        sig_algs: FIREFOX_TLS_SIG_ALGS,
        ext_order: TOR_TLS_EXT_ORDER,
        raw_exts: FIREFOX_TLS_RAW_EXTS,
        // rustls sends session_ticket and psk_key_exchange_modes by default; Tor
        // sends neither, and its order names no `compress_certificate` either.
        suppress: &[
            EXT_SESSION_TICKET,
            EXT_PSK_KEY_EXCHANGE_MODES,
            EXT_COMPRESS_CERTIFICATE,
        ],
        drop13: &[EXT_EC_POINT_FORMATS],
        drop12: &[EXT_SUPPORTED_VERSIONS],
        alpn: H2_AND_HTTP11,
        padding_to: None,
        grease: false,
        cert_compression: &[],
        pq: false,
        legacy_versions: &[],
        headers: Some(TOR_HEADERS),
        h2: Some(&FIREFOX_H2),
    },
];

impl CurlNames {
    /// True when `value` names one of the bundle profiles that emit this shape.
    fn matches(&self, value: &str) -> bool {
        match self {
            CurlNames::UpTo(prefixes, max, suffixes) => prefixes.iter().any(|prefix| {
                curl_version(value, prefix, suffixes).is_some_and(|version| version <= *max)
            }),
            CurlNames::Only(prefixes, versions, suffixes) => prefixes.iter().any(|prefix| {
                curl_version(value, prefix, suffixes).is_some_and(|v| versions.contains(&v))
            }),
        }
    }
}

/// The numeric version in a `curl_*` profile name, if it has one and the name
/// carries one of `suffixes` right after the digits.
///
/// `curl_chrome107` → 107 with the empty suffix, `curl_chrome99_android` → 99
/// with `_android`, `curl_chrome133a` → 133 with `a`, `curl_chrome99` → `None`
/// for the Android suffixes. The suffix is checked because the wrappers that
/// carry one differ in their identity, not in their hello: a record that
/// reproduces one must not answer to the other.
fn curl_version(value: &str, prefix: &str, suffixes: &[&str]) -> Option<u16> {
    let rest = value.strip_prefix(prefix)?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() || !suffixes.iter().any(|suffix| *suffix == &rest[digits.len()..]) {
        return None;
    }
    digits.parse().ok()
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
/// The same extension at the code point Chrome 133 moved it to
/// (`--tls-use-new-alps-codepoint`, and `utlsExtensionApplicationSettingsNew`).
pub(crate) const EXT_APPLICATION_SETTINGS_NEW: u16 = 17613;
