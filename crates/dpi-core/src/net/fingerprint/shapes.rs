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
    SAFARI18_H2, SAFARI184_IOS_H2, SAFARI260_H2, SAFARI_H2,
};
use super::identity::{
    CHROME120_HEADERS, CHROME131_ANDROID_HEADERS, CHROME131_HEADERS, CHROME146_HEADERS,
    CHROME99_ANDROID_HEADERS, CHROME_HEADERS, EDGE101_HEADERS, FIREFOX144_HEADERS, FIREFOX_HEADERS,
    SAFARI153_HEADERS, SAFARI184_IOS_HEADERS, SAFARI18_HEADERS, SAFARI260_HEADERS,
    SAFARI260_IOS_HEADERS, SAFARI_HEADERS, TOR_HEADERS,
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
    /// Whether the impersonated client carries `encrypted_client_hello` (65037).
    ///
    /// Nine of the nineteen shapes do, and every one of them does it as GREASE:
    /// their wrappers say `--ech true`, and curl can only fetch an ECHConfigList
    /// through DoH or `--ecl:`, neither of which the wrappers pass — so what
    /// reaches the wire is a grease extension. Measured on the bundle's own
    /// hello: `curl_chrome136`, `curl_firefox133` and `curl_tor145` all send the
    /// same kind of body — `outer`, suite `0001 0001`, a random `config_id`, a
    /// 32-byte `enc` and a random payload of 144, 176, 208 or 240 bytes, which is
    /// an extension of 186, 218, 250 or 282 bytes — the same shape on three
    /// different browsers, which a real config never is.
    ///
    /// This is what `net::tls` turns into `EchMode::Grease`; a real
    /// `EchMode::Enable` would need the host's own HTTPS record, which is a
    /// different kind of fidelity than these records promise (see the plan).
    pub(crate) ech: bool,
    /// Shuffle the extension order once per connection.
    ///
    /// Measured twice, because it decides whether a shape can be pinned at all:
    /// the bundle's own wrappers name `--tls-permute-extensions` for
    /// `curl_chrome120` through `curl_chrome146` and for nothing older, and the
    /// fork's captures carry `tls_permute_extensions: true` for every Chromium
    /// from 110 up (Edge from 118). Chromium enables it unconditionally
    /// (`SSL_set_permute_extensions` in `ssl_client_socket_impl.cc`), and
    /// BoringSSL's `ssl_setup_extension_permutation` draws a fresh Fisher–Yates
    /// pass per connection — so two hellos from one Chrome are never ordered
    /// alike, and a profile that pins one order is the one thing Chrome 110+
    /// never sends.
    pub(crate) permute_extensions: bool,
    /// Whether the impersonated client sends its `priority` header over
    /// HTTP/1.1 as well as HTTP/2.
    ///
    /// Measured on the bundle's own h1 request (`tools/fingerprint`, stage
    /// `headers`): `curl_firefox133`, `curl_firefox135`, `curl_firefox144` and
    /// `curl_tor145` carry `Priority` on both protocols, every Chrome, Edge and
    /// Safari wrapper carries it on HTTP/2 only. curl decides that per
    /// impersonation profile, not per `-H` line — the four wrappers name it
    /// exactly as the others do.
    pub(crate) priority_on_h1: bool,
    /// RFC 8879 code points this shape advertises; empty means rustls's own
    /// empty list and no `compress_certificate` extension.
    pub(crate) cert_compression: &'static [u16],
    /// The groups a key share is sent for, in wire order, `None` for rustls's
    /// own choice of one share plus a hybrid component.
    ///
    /// `curl_firefox133`, `curl_firefox135`, `curl_firefox144` and `curl_tor145`
    /// pass `--tls-key-shares-limit 3`, which puts three shares on the wire
    /// (measured: `tools/fingerprint`, stage `hello`); every other wrapper
    /// leaves the count where rustls puts it. A hybrid group named here brings
    /// its component's share with it, so Firefox's list is
    /// `[X25519MLKEM768, secp256r1]` — three entries on the wire, not two.
    pub(crate) key_share_groups: Option<&'static [u16]>,
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

/// `zlib, brotli, zstd`, the list the whole Firefox family advertises.
///
/// Measured on the bundle's own hello: `curl_firefox133`, `curl_firefox135` and
/// `curl_firefox144` carry `compress_certificate` with the body
/// `06000100020003` — three algorithms in that order. `curl_tor145` names the
/// same `--cert-compression` and sends no such extension at all, so its record
/// keeps an empty list.
///
/// The code points are RFC 8879's: 1 zlib, 2 brotli, 3 zstd.
const FIREFOX_COMPRESSION: &[u16] = &[1, 2, 3];

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
/// slot, which those releases no longer send on their own — nothing pads a
/// 300-byte hello.
///
/// `curl_chrome110…131` carry no extension 21 on their longer hellos, and uTLS's
/// `HelloChrome_120`/`HelloChrome_131` name the rest in exactly this order.
/// Chromium permutes per connection, so this is one order out of the
/// distribution the same way Chrome 133's is: the tests pin the extension *set*
/// and the order-insensitive JA4. Chrome 120 and 131 Android would carry one
/// under the 512-byte floor — the client pads there with the shortest GREASE ECH
/// body — and they do not here, for the reason in the Chrome 120 record.
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
    EXT_ENCRYPTED_CLIENT_HELLO,
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
    EXT_ENCRYPTED_CLIENT_HELLO,
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

/// The groups `curl_firefox133` and `curl_firefox144` send a key share for:
/// `--tls-key-shares-limit 3` with Firefox's curve list. The hybrid group's own
/// entry carries its X25519 component, so these two groups are three shares on
/// the wire — X25519MLKEM768, X25519 and P-256 — which is what both the bundle
/// and the fork's capture of the browser put there.
const FIREFOX_KEY_SHARE_GROUPS: &[u16] = &[
    4588, // X25519MLKEM768, with its X25519 component
    23,   // secp256r1
];

/// The groups `curl_tor145` sends a share for: its curve list's first three,
/// which is what `--tls-key-shares-limit 3` produces without a hybrid group.
/// The fork's capture of Tor 14.5 itself stops after P-256, so this record is
/// one share longer than the browser it copies — the wrapper asks for three.
const TOR_KEY_SHARE_GROUPS: &[u16] = &[
    29, // X25519
    23, // secp256r1
    24, // secp384r1
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
    EXT_ENCRYPTED_CLIENT_HELLO,
];

/// Firefox 135–144's extension order: 133's with
/// `signed_certificate_timestamp` after `delegated_credentials`, which is the
/// single extension Firefox added in between.
const FIREFOX144_TLS_EXT_ORDER: &[u16] = &[
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
    EXT_ENCRYPTED_CLIENT_HELLO,
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
    EXT_ENCRYPTED_CLIENT_HELLO,
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
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        cert_compression: &[],
        key_share_groups: None,
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
    // `encrypted_client_hello` (65037) closes the list, as GREASE: the wrapper
    // names `--ech true` and curl can only fetch a real ECHConfigList through
    // DoH or `--ecl:`, neither of which it passes. `net::tls` installs
    // `EchMode::Grease`, `net::hpke` is the HPKE suite it encapsulates with, and
    // the extension is rebuilt per connection — `enc` is a fresh X25519 public
    // key and the payload is random — so its *bytes* are never comparable, the
    // same as a real browser's. JA4 counts it: 16 extensions, which is what
    // `curl_firefox133` sends.
    //
    // An earlier attempt at this record *hand-built* the body and had
    // `cloudflare.com`, `www.google.com` and `dns.google` answer `fatal alert:
    // DecodeError`; rustls's GREASE path is accepted by all four of those hosts
    // (measured again with `tls_fingerprint liveany firefox cloudflare.com
    // www.google.com dns.google tls.peet.ws`), which is the difference between a
    // body that parses on a server's ECH path and one that does not.
    //
    // The GREASE ECH body used to be listed here as a deviation — ours was 441
    // bytes where the bundle's is 186, 218, 250 or 282 — because rustls sized
    // the payload from the inner hello this client would really send. It now
    // draws the length from the same four values BoringSSL draws from, so only
    // the random content of the body differs.
    //
    // The key shares, `compress_certificate` list and h2 preface that used to be
    // listed here as deviations are the bundle's own since the pass that closed
    // them (`--tls-key-shares-limit 3`, `zlib, brotli, zstd`, `8:1`/`9:1`).
    TlsShape {
        variant: TlsFingerprint::Firefox133,
        code: "firefox133",
        token: "FIREFOX",
        label: "FIREFOX 133",
        source: "curl-impersonate v2.2.2",
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
        permute_extensions: false,
        ech: true,
        priority_on_h1: true,
        // zlib, brotli — the two this build can actually decompress (`zstd` is
        // not a rustls feature; advertising it would invite a
        // CompressedCertificate we cannot read). The algorithm *list* is not
        // part of JA3/JA4, only the presence of extension 27 is.
        cert_compression: FIREFOX_COMPRESSION,
        key_share_groups: Some(FIREFOX_KEY_SHARE_GROUPS),
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
        variant: TlsFingerprint::Chrome107,
        code: "chrome107",
        token: "CHROME",
        label: "CHROME 107",
        source: "curl-impersonate v2.2.2",
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
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        cert_compression: BROTLI,
        key_share_groups: None,
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
        variant: TlsFingerprint::Safari155,
        code: "safari155",
        token: "SAFARI",
        label: "SAFARI 155",
        source: "curl-impersonate v2.2.2",
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
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        // zlib, exactly what Safari advertises.
        cert_compression: &[1],
        key_share_groups: None,
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
    // Safari 18.0, as `curl_safari180` sends it.
    //
    // The cipher, group and extension lists are Safari 15.5's, but the
    // *signature schemes* are not: Safari 18 dropped `ecdsa_sha1`, and JA4 —
    // the only fingerprint that hashes this list — reads the two hellos as
    // `e42f34c56612` and `14788d8d241b`. An earlier version of this record
    // reused the 15.5 list, which made its extension hash ours instead of the
    // bundle's; the duplicate `rsa_pss_rsae_sha384` was missing for the same
    // reason. Both are in [`SAFARI18_TLS_SIG_ALGS`] now.
    //
    // Safari 18.4's *desktop* wrapper, `curl_safari184`, sends this TLS hello
    // with a different h2 preface (`2:0;3:100;4:2097152;9:1` — no
    // `SETTINGS_ENABLE_CONNECT_PROTOCOL`, where 18.0 sends `8:1;9:1`), so the
    // two are separate clients below the hello and this record is 18.0's. The
    // iOS 18.4 wrapper is [`TlsFingerprint::Safari184Ios`].
    //
    // It answers the question the older Safari row cannot: whether a *current*
    // Safari is treated like the version the forum report named. The HTTP
    // identity is 18.0's (`Version/18.0`, a `priority` header,
    // `en-US,en;q=0.9`), and the preface is Safari's own.
    TlsShape {
        variant: TlsFingerprint::Safari180,
        code: "safari180",
        token: "SAFARI",
        label: "SAFARI 180",
        source: "curl-impersonate v2.2.2",
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
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        cert_compression: &[1],
        key_share_groups: None,
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
        variant: TlsFingerprint::Edge101,
        code: "edge101",
        token: "EDGE",
        label: "EDGE 101",
        source: "curl-impersonate v2.2.3 / uTLS HelloEdge_106 (v1.8.2)",
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
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        cert_compression: BROTLI,
        key_share_groups: None,
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
        source: "curl-impersonate v2.2.2",
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
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        cert_compression: BROTLI,
        key_share_groups: None,
        pq: false,
        legacy_versions: &[],
        headers: Some(CHROME99_ANDROID_HEADERS),
        h2: Some(&CHROME99_ANDROID_H2),
    },
    // Chrome 120, as `curl_chrome120` sends it: the first Chromium release in
    // this bundle that carries ECH.
    //
    // What differs from Chrome 107: ALPS still at 17513, `encrypted_client_hello`
    // (65037) as GREASE — the extension the wrapper sends, not one this build
    // invents — and an HTTP layer that keeps `accept-encoding: gzip, deflate,
    // br` and sends no `priority` header, which is why one header table per
    // version is the honest description rather than one per family.
    //
    // This and Chrome 131 Android are the two shapes whose hello can fall under
    // the 512-byte floor: with the shortest GREASE ECH body it is 497 bytes, and
    // the client pads there — 16 bytes of padding bring it to 517, measured on
    // the wrapper. We do not: the profile's `padding_to` measures the hello
    // before rustls appends the typed ECH body, so a slot here overshoots by the
    // whole body (803 bytes against 517). The hello is then the *unpadded* value
    // the client itself sends on three connections out of four, never a shape it
    // never sends — the gap is a frequency, not a shape.
    //
    // `curl_chrome119` and `curl_chrome123` send this hello under their own
    // UAs, and they are not separate profiles here: a profile is one hello plus
    // one identity, and the identity this record carries is 120's. Measured —
    // each wrapper captured through a local listener — all three send one cipher
    // list, group list, signature-scheme list and extension set.
    TlsShape {
        variant: TlsFingerprint::Chrome120,
        code: "chrome120",
        token: "CHROME",
        label: "CHROME 120",
        source: "curl-impersonate v2.2.2",
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
        permute_extensions: true,
        ech: true,
        priority_on_h1: false,
        cert_compression: BROTLI,
        key_share_groups: None,
        pq: false,
        legacy_versions: &[],
        headers: Some(CHROME120_HEADERS),
        h2: Some(&CHROME120_H2),
    },
    // Chrome 131, as `curl_chrome131` sends it: Chrome 146's shape with ALPS
    // one code point earlier — the hybrid group leads the list and is shared,
    // ALPS is still at 17513, and there is no padding.
    //
    // It is the profile that separates the two halves of the "post-quantum
    // group" question a censor can read: 131 and 146 differ in the ALPS code
    // point and in nothing a JA3 carries, so a site that blocks 146 and passes
    // 131 is reacting to something other than the group.
    TlsShape {
        variant: TlsFingerprint::Chrome131,
        code: "chrome131",
        token: "CHROME",
        label: "CHROME 131",
        source: "curl-impersonate v2.2.2",
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
        permute_extensions: true,
        ech: true,
        priority_on_h1: false,
        cert_compression: BROTLI,
        key_share_groups: None,
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
    // else — the ECH extension, the ALPS code point, the 512-byte floor the
    // shortest ECH body drops it under (see the desktop record), the header set —
    // tracks the desktop 131 with the phone's UA and platform.
    TlsShape {
        variant: TlsFingerprint::Chrome131Android,
        code: "chrome131android",
        token: "CHROME",
        label: "CHROME 131 ANDROID",
        source: "curl-impersonate v2.2.2",
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
        permute_extensions: true,
        ech: true,
        priority_on_h1: false,
        cert_compression: BROTLI,
        key_share_groups: None,
        pq: false,
        legacy_versions: &[],
        headers: Some(CHROME131_ANDROID_HEADERS),
        h2: Some(&CHROME120_H2),
    },
    // Chrome 146, as `curl_chrome146` sends it: the newest desktop Chromium in
    // this bundle, and the only desktop Chrome profile past 131.
    //
    // Chrome 133, 136, 142, 145 and 146 send one hello — the same cipher, group,
    // signature-scheme and extension lists, the same JA4
    // (`t13d1516h2_8daaf6152771_d8a2da3f94cd`), the same h2 preface and the same
    // header names; only the version in the UA and the `sec-ch-ua` brand list
    // differ, which is the identity. Nothing a middlebox could match on
    // distinguishes them, so one record covers the five, with the newest
    // identity: four names for one shape would multiply the burst report by four
    // and tell the same story four times.
    //
    // Where the chain breaks it is kept: Chrome 107 shuffles nothing, Chrome 120
    // adds ECH, Chrome 131 adds the hybrid group, and this one moves ALPS to
    // 17613.
    TlsShape {
        variant: TlsFingerprint::Chrome146,
        code: "chrome146",
        token: "CHROME",
        label: "CHROME 146",
        source: "curl-impersonate v2.2.2",
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
        permute_extensions: true,
        ech: true,
        priority_on_h1: false,
        cert_compression: BROTLI,
        key_share_groups: None,
        pq: true,
        legacy_versions: &[],
        headers: Some(CHROME146_HEADERS),
        h2: Some(&CHROME120_H2),
    },
    // Firefox 144, as `curl_firefox144` sends it (the wrapper is a one-liner —
    // `--impersonate firefox144` — and the bundle's `firefox_144.0.0_linux`
    // capture is the reading of it this record is pinned to).
    //
    // The hello is Firefox 133's plus `signed_certificate_timestamp` (18),
    // between `delegated_credentials` and `key_share` — the one extension the
    // plan called out as a shape this build could not reproduce before, and the
    // reason the 133 record stays separate: a middlebox that reacts to 18 alone
    // reads the two as different clients. Firefox 135 and 147 send this same
    // hello, so they are one profile here, under the newest identity.
    TlsShape {
        variant: TlsFingerprint::Firefox144,
        code: "firefox144",
        token: "FIREFOX",
        label: "FIREFOX 144",
        source: "curl-impersonate v2.2.2",
        baseline: false,
        ciphers: FIREFOX_TLS_CIPHERS,
        groups: FIREFOX_TLS_GROUPS,
        sig_algs: FIREFOX_TLS_SIG_ALGS,
        ext_order: FIREFOX144_TLS_EXT_ORDER,
        raw_exts: FIREFOX_TLS_RAW_EXTS,
        suppress: &[],
        drop13: &[EXT_EC_POINT_FORMATS, EXT_SESSION_TICKET],
        drop12: &[EXT_SUPPORTED_VERSIONS],
        alpn: H2_AND_HTTP11,
        padding_to: None,
        grease: false,
        permute_extensions: false,
        ech: true,
        priority_on_h1: true,
        cert_compression: FIREFOX_COMPRESSION,
        key_share_groups: Some(FIREFOX_KEY_SHARE_GROUPS),
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
        source: "curl-impersonate v2.2.2",
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
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        // No `compress_certificate`: the wrapper advertises none.
        cert_compression: &[],
        key_share_groups: None,
        pq: false,
        legacy_versions: &[0x0302, 0x0301],
        headers: Some(SAFARI153_HEADERS),
        h2: Some(&SAFARI_H2),
    },
    // Safari 18.4 on iOS, as `curl_safari184_ios` sends it: the 18.x hello
    // behind an iPhone's identity.
    //
    // The TLS shape is [`TlsFingerprint::Safari180`]'s — same lists — and the
    // identity and the h2 preface are what the row is for: the iOS UA, its own
    // `priority`, and a preface with `9:1` and no `8:1`, which is what the iOS
    // 18.4 build sends.
    TlsShape {
        variant: TlsFingerprint::Safari184Ios,
        code: "safari184ios",
        token: "SAFARI",
        label: "SAFARI 184 IOS",
        source: "curl-impersonate v2.2.2",
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
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        cert_compression: &[1],
        key_share_groups: None,
        pq: false,
        legacy_versions: &[0x0302, 0x0301],
        headers: Some(SAFARI184_IOS_HEADERS),
        h2: Some(&SAFARI184_IOS_H2),
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
        label: "SAFARI 260",
        source: "curl-impersonate v2.2.2",
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
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        cert_compression: &[1],
        key_share_groups: None,
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
        label: "SAFARI 260 IOS",
        source: "curl-impersonate v2.2.2",
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
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        cert_compression: &[1],
        key_share_groups: None,
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
        source: "curl-impersonate v2.2.2",
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
        permute_extensions: false,
        ech: true,
        priority_on_h1: true,
        cert_compression: &[],
        key_share_groups: Some(TOR_KEY_SHARE_GROUPS),
        pq: false,
        legacy_versions: &[],
        headers: Some(TOR_HEADERS),
        h2: Some(&FIREFOX_H2),
    },
];

impl TlsShape {
    /// True when `value` (already lowercased and trimmed) names this record.
    ///
    /// One name per record: the `code`, which is also what the config file, the
    /// JSON and `--legend` carry, so there is nothing here that can resolve to a
    /// different version than it says.
    pub(crate) fn matches_name(&self, value: &str) -> bool {
        self.code == value
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
            key_share_groups: self.key_share_groups.map(|groups| groups.to_vec()),
            signature_schemes: Some(self.sig_algs.to_vec()),
            alpn: Some(self.alpn.iter().map(|protocol| protocol.to_vec()).collect()),
            extension_order: Some(self.ext_order.to_vec()),
            raw_extensions: self.raw_exts.iter().map(|(ext, body)| (*ext, body.to_vec())).collect(),
            suppress_extensions: self.suppress.to_vec(),
            grease: self.grease,
            permute_extensions: self.permute_extensions,
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
/// `encrypted_client_hello` (draft-ietf-tls-esni), the extension seven shapes
/// carry as GREASE.
pub(crate) const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 65037;
/// Chrome's ALPS (draft-vvv-tls-alps), as Chrome 107 and Safari send it.
pub(crate) const EXT_APPLICATION_SETTINGS: u16 = 17513;
/// The same extension at the code point Chrome 133 moved it to
/// (`--tls-use-new-alps-codepoint`, and `utlsExtensionApplicationSettingsNew`).
pub(crate) const EXT_APPLICATION_SETTINGS_NEW: u16 = 17613;
