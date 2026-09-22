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
    H2Fingerprint, CHROME123_H2, CHROME99_ANDROID_H2, CHROME_H2, EDGE101_H2, FIREFOX_H2,
    SAFARI170_H2, SAFARI172_IOS_H2, SAFARI18_H2, SAFARI184_IOS_H2, SAFARI260_H2, SAFARI_H2,
};
use super::identity::{
    CHROME115_PQ_HEADERS, CHROME116_HEADERS, CHROME123_HEADERS, CHROME131_ANDROID_HEADERS,
    CHROME131_HEADERS, CHROME146_HEADERS, CHROME70_HEADERS, CHROME72_HEADERS, CHROME87_HEADERS,
    CHROME99_ANDROID_HEADERS, CHROME_HEADERS, EDGE101_HEADERS, FIREFOX105_HEADERS,
    FIREFOX120_HEADERS, FIREFOX147_HEADERS, FIREFOX65_HEADERS, FIREFOX99_HEADERS,
    FIREFOX_HEADERS, GO127_HEADERS, SAFARI153_HEADERS, SAFARI170_HEADERS, SAFARI172_IOS_HEADERS,
    SAFARI184_IOS_HEADERS, SAFARI18_HEADERS, SAFARI260_HEADERS, SAFARI260_IOS_HEADERS,
    SAFARI_HEADERS, TOR_HEADERS,
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
    /// different kind of fidelity than these records promise (see
    /// `docs/ADDING_A_PROFILE.md`).
    pub(crate) ech: bool,
    /// Shuffle the extension order once per connection.
    ///
    /// Measured twice, because it decides whether a shape can be pinned at all:
    /// the bundle's own wrappers name `--tls-permute-extensions` for
    /// `curl_chrome123` through `curl_chrome146` and for nothing older, and the
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
    /// `headers`): `curl_firefox133`, `curl_firefox147` and
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
    /// `curl_firefox133`, `curl_firefox147` and `curl_tor145`
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
/// Measured on the bundle's own hello: `curl_firefox133` and
/// `curl_firefox147` carry `compress_certificate` with the body
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
/// and the order-insensitive JA4. The two records whose hello can fall under the
/// 512-byte floor name the padding slot too
/// ([`CHROME_PADDING_AND_ECH_EXT_ORDER`]).
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

/// Chrome 119–131's extension order where the hello can fall under the floor:
/// Chrome 99–107's list — padding slot included — plus the ECH the wrapper sends.
///
/// BoringSSL's table has the padding slot and adds ECH outside it, so the order
/// names padding before the ECH the encoder appends; `curl_chrome123` and
/// `curl_chrome131_android` both pad when the shortest GREASE ECH body leaves
/// them at 497 bytes, and both carry extension 21 on those connections.
const CHROME_PADDING_AND_ECH_EXT_ORDER: &[u16] = &[
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

/// Chrome 115 PQ's extension order: Chrome 99–107's list with ALPS at 17513 and
/// **no padding slot**, which is the one difference from [`CHROME_TLS_EXT_ORDER`]
/// and the capture's own set — the measured hello is 1524 bytes, so BoringSSL's
/// 512-byte floor never fires on it and the release never sends extension 21.
///
/// This build cannot share the hybrid group that makes the spec hello that large
/// ([`CHROME115_PQ_KEY_SHARE_GROUPS`]), so its own hello falls under the floor,
/// where the padding *rule* would add a slot a real Chrome 115 never has. The
/// slot is therefore left out of the order: what the record reproduces is the
/// measured extension set, 15 types including ALPS and without padding, which is
/// what `t13d1515h2_8daaf6152771_f37e75b10bcc` hashes.
const CHROME115_PQ_TLS_EXT_ORDER: &[u16] = &[
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

/// The groups Chrome 120 and 131's Android wrapper lead with: X25519, P-256,
/// P-384, no hybrid — the one thing `curl_chrome131_android` drops from its
/// desktop sibling (`--curves X25519:P-256:P-384`).
const CHROME_TLS_PQ_GROUPS: &[u16] = &[
    4588, // X25519MLKEM768
    29,   // X25519
    23,   // secp256r1
    24,   // secp384r1
];

/// Chrome 70 and 72's cipher list: Chrome 87's fifteen suites with
/// `RSA_3DES_EDE_CBC_SHA` appended — the one suite 87 dropped. uTLS
/// `HelloChrome_70`/`HelloChrome_72` write the same seventeen entries, and the
/// captures read `…-156-157-47-53-10` where Chrome 87's JA3 stops at `-53`.
const CHROME70_TLS_CIPHERS: &[u16] = &[
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
    0x000a, // RSA_3DES_EDE_CBC_SHA
];

/// Chrome 70 and 72's signature schemes: Chrome 87's eight with
/// `rsa_pkcs1_sha1` appended, the ninth entry both uTLS literals list and the
/// reason their JA4 extension hash (`4551aecd7b38` for 70, `45f260be83e2` for
/// 72) differs from Chrome 87's `de4a06bb82e3` — the two hellos carry the same
/// extension types, so this list is the only thing that moves the hash.
const CHROME70_TLS_SIG_ALGS: &[u16] = &[
    0x0403, // ECDSA P-256 SHA-256
    0x0804, // RSA-PSS SHA-256
    0x0401, // RSA-PKCS1 SHA-256
    0x0503, // ECDSA P-384 SHA-384
    0x0805, // RSA-PSS SHA-384
    0x0501, // RSA-PKCS1 SHA-384
    0x0806, // RSA-PSS SHA-512
    0x0601, // RSA-PKCS1 SHA-512
    0x0201, // RSA-PKCS1 SHA-1
];

/// Chrome 72 and 87's extension order: Chrome 99–107's list — GREASE at both
/// ends, padding last — without `application_settings` (17513), which neither
/// release sent.
///
/// That one missing extension is the whole difference from Chrome 107's
/// extension hash (`e5627efa2ab1` against `45f260be83e2`/`de4a06bb82e3`); the
/// signature-scheme list is not part of it, since Chrome 87 sends
/// [`CHROME_TLS_SIG_ALGS`] unchanged.
const CHROME72_TLS_EXT_ORDER: &[u16] = &[
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

/// Chrome 70's extension order: the same fifteen entries as Chrome 72's, in the
/// order that release sent them — `renegotiation_info` first, and the
/// `channel_id` placeholder in the middle, where Chrome 72 has none.
///
/// 360Browser 11.0 sends the same bodies in a third order (`Hello360_11_0`), so
/// it shares this record's JA4 (`46e7e9700bed_…`) and not its JA3; the uTLS
/// `HelloChrome_70` literal is the transcription source because its order is the
/// one the capture carries.
const CHROME70_TLS_EXT_ORDER: &[u16] = &[
    GREASE_EXTENSION_MARKER,
    EXT_RENEGOTIATION_INFO,
    EXT_SERVER_NAME,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_SESSION_TICKET,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_STATUS_REQUEST,
    EXT_SCT,
    EXT_ALPN,
    EXT_FAKE_CHANNEL_ID,
    EXT_EC_POINT_FORMATS,
    EXT_KEY_SHARE,
    EXT_PSK_KEY_EXCHANGE_MODES,
    EXT_SUPPORTED_VERSIONS,
    EXT_SUPPORTED_GROUPS,
    EXT_COMPRESS_CERTIFICATE,
    GREASE_EXTENSION_MARKER,
    EXT_PADDING,
];

/// The bodies Chrome 70 emits verbatim: Chrome 99–107's set plus the empty
/// `channel_id` body, and without the ALPS entry this order names no slot for.
const CHROME70_TLS_RAW_EXTS: &[(u16, &[u8])] = &[
    // Empty renegotiated_connection vector.
    (EXT_RENEGOTIATION_INFO, &[0x00]),
    // ec_point_formats: uncompressed only.
    (EXT_EC_POINT_FORMATS, &[0x01, 0x00]),
    // signed_certificate_timestamp in the ClientHello is empty.
    (EXT_SCT, &[]),
    // session_ticket: empty in a fresh session, supplied for the reason in
    // [`CHROME_TLS_RAW_EXTS`].
    (EXT_SESSION_TICKET, &[]),
    // channel_id, as the placeholder Chrome 70 sent instead of the real
    // extension: present, zero-length.
    (EXT_FAKE_CHANNEL_ID, &[]),
    // Padding: rustls computes the body so the hello reaches 512 bytes.
    (EXT_PADDING, &[]),
];

/// Chrome 115 PQ's groups: the draft hybrid group that release offered, then the
/// three Chrome 87–107 lists. `X25519Kyber768Draft00` (25497) is what Chrome 115
/// put in front of X25519; Chrome 120 replaced it with the final
/// `X25519MLKEM768` (4588), which is [`CHROME_TLS_PQ_GROUPS`].
///
/// The draft group is advertised without ever being shared: this build serves no
/// `0x6399` (named in `tests::UNIMPLEMENTED`), and the record's key share is the
/// X25519 entry below it.
const CHROME115_PQ_TLS_GROUPS: &[u16] = &[
    25497, // X25519Kyber768Draft00
    29,    // X25519
    23,    // secp256r1
    24,    // secp384r1
];

/// The one key share `chrome115pq` sends: X25519, the second of the two the uTLS
/// spec puts on the wire.
///
/// The spec shares `X25519Kyber768Draft00` first and X25519 after it; this build
/// has no draft-00 group to share it with — the PQ provider carries
/// `X25519MLKEM768`, a different group at a different code point — and a share
/// for a group the handshake cannot complete fails rather than degrades. So the
/// record names the one exchange it can run, which is also a group the advertised
/// list carries, where the spec's hybrid share is not one this build has.
const CHROME115_PQ_KEY_SHARE_GROUPS: &[u16] = &[29]; // X25519

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

/// Firefox 99 and 102's cipher list: Firefox 133's seventeen with
/// `RSA_3DES_EDE_CBC_SHA` appended — the one suite Firefox dropped between 102
/// and 105, and the reason 99's JA4 cipher hash (`e8a523a41297`) differs from
/// 105's (`5b57614c22b0`) although their hellos are otherwise the same size.
const FIREFOX99_TLS_CIPHERS: &[u16] = &[
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
    0x000a, // RSA_3DES_EDE_CBC_SHA
];

/// Firefox 63/65's cipher list: Firefox 99's with the two static-RSA AES-GCM
/// suites replaced by the DHE_RSA CBC suites uTLS writes as
/// `FAKE_TLS_DHE_RSA_WITH_AES_128/256_CBC_SHA` — the real code points (0x0033,
/// 0x0039), listed by a client that offers no DHE key exchange and no SHA-1 CBC
/// shape, which is why they are in `tests::UNIMPLEMENTED` twice over.
const FIREFOX65_TLS_CIPHERS: &[u16] = &[
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
    0x0033, // DHE_RSA_AES128_CBC_SHA, as uTLS lists it
    0x0039, // DHE_RSA_AES256_CBC_SHA, as uTLS lists it
    0x002f, // RSA_AES128_CBC_SHA
    0x0035, // RSA_AES256_CBC_SHA
    0x000a, // RSA_3DES_EDE_CBC_SHA
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

/// The groups `curl_firefox133` and `curl_firefox147` send a key share for:
/// `--tls-key-shares-limit 3` with Firefox's curve list. The hybrid group's own
/// entry carries its X25519 component, so these two groups are three shares on
/// the wire — X25519MLKEM768, X25519 and P-256 — which is what both the bundle
/// and the fork's capture of the browser put there.
const FIREFOX_KEY_SHARE_GROUPS: &[u16] = &[
    4588, // X25519MLKEM768, with its X25519 component
    23,   // secp256r1
];

/// The groups Firefox 65–120 send a key share for: the two the uTLS specs name
/// in their `KeyShareExtension`, in that order — measured as `key_share = 29,23`
/// on all four captures. Firefox 133 puts the hybrid group in front
/// ([`FIREFOX_KEY_SHARE_GROUPS`]); these four releases predate it.
const FIREFOX_PRE_HYBRID_KEY_SHARE_GROUPS: &[u16] = &[
    29, // X25519
    23, // secp256r1
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

/// Firefox 135–147's extension order: 133's with
/// `signed_certificate_timestamp` after `delegated_credentials`, which is the
/// single extension Firefox added in between.
const FIREFOX147_TLS_EXT_ORDER: &[u16] = &[
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

/// Firefox 120's extension order: Firefox 133's without `compress_certificate`
/// (27), which Firefox added after 120 — the spec lists no such extension and
/// the capture carries none, which is why this record's JA4 extension hash
/// (`5c2c66f702b0`) differs from 133's (`eeeea6562960`) in that one type.
/// GREASE-free, and ECH last, as in 133.
const FIREFOX120_TLS_EXT_ORDER: &[u16] = &[
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
    EXT_ENCRYPTED_CLIENT_HELLO,
];

/// Firefox 99 and 105's extension order: [`FIREFOX120_TLS_EXT_ORDER`] with the
/// padding slot where 120 has ECH — the two releases pad their hello to the
/// 512-byte floor BoringSSL uses and predate `encrypted_client_hello`.
///
/// The two send one extension *set*, which is why their JA4 extension hash is
/// the same string (`3d5424432f57`) while their cipher hashes differ: 99's list
/// carries one suite more ([`FIREFOX99_TLS_CIPHERS`]), and the padding body
/// compensates for it so both hellos measure 512 bytes.
const FIREFOX99_TLS_EXT_ORDER: &[u16] = &[
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
    EXT_PADDING,
];

/// Firefox 63/65's extension order: [`FIREFOX99_TLS_EXT_ORDER`] without
/// `delegated_credentials` (34), which Firefox 65 does not send yet — the single
/// difference, and the reason its extension count is 14 where 99's is 15.
const FIREFOX65_TLS_EXT_ORDER: &[u16] = &[
    EXT_SERVER_NAME,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_RENEGOTIATION_INFO,
    EXT_SUPPORTED_GROUPS,
    EXT_EC_POINT_FORMATS,
    EXT_SESSION_TICKET,
    EXT_ALPN,
    EXT_STATUS_REQUEST,
    EXT_KEY_SHARE,
    EXT_SUPPORTED_VERSIONS,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_PSK_KEY_EXCHANGE_MODES,
    EXT_RECORD_SIZE_LIMIT,
    EXT_PADDING,
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
/// hello (the extension is not in its order) and live in 135's. The padding entry
/// is inert where the order does not name it — 120 and 133–147 — and is what puts
/// Firefox 65, 99 and 105 on the 512-byte floor.
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
    // The 512-byte floor's slot, sized by the builder from `padding_to`.
    (EXT_PADDING, &[]),
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

/// The Go client's hello, as uTLS `HelloGolang` writes it — the one uTLS shape
/// with no spec literal: `buildHandshakeState` hands the handshake to the
/// `crypto/tls` fork uTLS vendors, so `makeClientHello`/`marshalMsg` are the
/// authority and the capture is the whole measurement.
///
/// Every list below is read from `HelloGolang-0.hex` (1466 bytes): Go's
/// `cipherSuitesPreferenceOrder` selection, its `defaultCurvePreferences`, its
/// `defaultSupportedSignatureAlgorithms`, and the fixed extension order
/// `marshalMsg` writes. Nothing greases, nothing pads, and there is no ALPN,
/// ALPS, ECH, `compress_certificate`, `record_size_limit` or
/// `delegated_credentials` — a Go client sends none of them.
///
/// The capture is the fork's hello, not the installed Go toolchain's: a newer
/// Go adds ML-DSA signature schemes and a `signature_algorithms_cert`
/// extension, and none of them is on this wire.
const GO_TLS_CIPHERS: &[u16] = &[
    0xc02b, // ECDHE_ECDSA_AES128_GCM_SHA256
    0xc02f, // ECDHE_RSA_AES128_GCM_SHA256
    0xc02c, // ECDHE_ECDSA_AES256_GCM_SHA384
    0xc030, // ECDHE_RSA_AES256_GCM_SHA384
    0xcca9, // ECDHE_ECDSA_CHACHA20_POLY1305
    0xcca8, // ECDHE_RSA_CHACHA20_POLY1305
    0xc009, // ECDHE_ECDSA_AES128_CBC_SHA
    0xc013, // ECDHE_RSA_AES128_CBC_SHA
    0xc00a, // ECDHE_ECDSA_AES256_CBC_SHA
    0xc014, // ECDHE_RSA_AES256_CBC_SHA
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
];

/// Go's curves: the hybrid group Go 1.24 added in front of Go's classical four,
/// all of them shared-classical in this build's provider. The key share follows
/// from them (see the record).
const GO_TLS_GROUPS: &[u16] = &[
    4588, // X25519MLKEM768
    29,   // X25519
    23,   // secp256r1
    24,   // secp384r1
    25,   // secp521r1
];

/// Go's signature schemes, in the order `defaultSupportedSignatureAlgorithms`
/// lists them: RSA-PSS first, Ed25519 between the P-256 and the P-384 ECDSA
/// scheme, and the two SHA-1 schemes last.
const GO_TLS_SIG_ALGS: &[u16] = &[
    0x0804, // RSA-PSS SHA-256
    0x0403, // ECDSA P-256 SHA-256
    0x0807, // Ed25519
    0x0805, // RSA-PSS SHA-384
    0x0806, // RSA-PSS SHA-512
    0x0401, // RSA-PKCS1 SHA-256
    0x0501, // RSA-PKCS1 SHA-384
    0x0601, // RSA-PKCS1 SHA-512
    0x0503, // ECDSA P-384 SHA-384
    0x0603, // ECDSA P-521 SHA-512
    0x0201, // RSA-PKCS1 SHA-1
    0x0203, // ECDSA SHA-1
];

/// Go's extension order: the ten `marshalMsg` writes, in the order the capture
/// carries. `server_name` is first and there is no ALPN slot — a Go client with
/// no `NextProtos` sends none, and this record offers none.
const GO_TLS_EXT_ORDER: &[u16] = &[
    EXT_SERVER_NAME,
    EXT_EC_POINT_FORMATS,
    EXT_RENEGOTIATION_INFO,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_SCT,
    EXT_STATUS_REQUEST,
    EXT_SUPPORTED_GROUPS,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_SUPPORTED_VERSIONS,
    EXT_KEY_SHARE,
];

/// The bodies Go emits verbatim: secure renegotiation, the point formats, and
/// the empty `signed_certificate_timestamp`. `extended_master_secret` and
/// `status_request` are rustls's own and need no body.
const GO_TLS_RAW_EXTS: &[(u16, &[u8])] = &[
    // Empty renegotiated_connection vector.
    (EXT_RENEGOTIATION_INFO, &[0x00]),
    // ec_point_formats: uncompressed only.
    (EXT_EC_POINT_FORMATS, &[0x01, 0x00]),
    // signed_certificate_timestamp in the ClientHello is empty.
    (EXT_SCT, &[]),
];

/// Every selectable shape, in report order: the baseline first, then one browser
/// at a time alphabetically with the newest version of each first, and the phone
/// shape of a version right after its desktop sibling (`chrome146` … `chrome70`,
/// `edge101`, `firefox147` … `firefox65`, `go127`, `safari260` … `safari153`,
/// `tor145`).
/// `tests::fingerprint_table_is_total` pins the table against
/// [`TlsFingerprint::ALL`] in both directions, so a variant without a record
/// fails the suite instead of silently falling back to the baseline, and a
/// record added out of order is a one-line move here and in `ALL`.
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
        h2: Some(&CHROME123_H2),
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
        h2: Some(&CHROME123_H2),
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
        ext_order: CHROME_PADDING_AND_ECH_EXT_ORDER,
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
        permute_extensions: true,
        ech: true,
        priority_on_h1: false,
        cert_compression: BROTLI,
        key_share_groups: None,
        pq: false,
        legacy_versions: &[],
        headers: Some(CHROME131_ANDROID_HEADERS),
        h2: Some(&CHROME123_H2),
    },
    // Chrome 123, as `curl_chrome123` sends it: the newest Chromium in this
    // bundle whose hello carries ECH.
    //
    // What differs from Chrome 107: ALPS still at 17513, `encrypted_client_hello`
    // (65037) as GREASE — the extension the wrapper sends, not one this build
    // invents — and an HTTP layer of its own: `accept-encoding` gained `zstd`
    // with this release and the request still carries no `priority` header, which
    // is why one header table per version is the honest description rather than
    // one per family.
    //
    // This and Chrome 131 Android are the two shapes whose hello can fall under
    // the 512-byte floor: with the shortest GREASE ECH body it comes to 497
    // bytes, and BoringSSL pads there — 16 bytes of padding bring it to the 512
    // the bundle's hellos measure, and the extension is part of the JA3/JA4 the
    // client sends. The padding slot counts the extensions that follow it
    // (`vendor/rustls`, `ClientExtensions::encode`), so what goes out is that
    // padded hello, and the other three body lengths leave the hello above the
    // floor exactly as they do for the client.
    //
    // `curl_chrome119` and `curl_chrome120` send this hello under their own
    // UAs, and they are not separate profiles here: a profile is one hello plus
    // one identity, and the identity this record carries is 123's, the newest of
    // the three. Measured — each wrapper captured through a local listener and
    // through `tls.peet.ws` — all three send one cipher list, group list,
    // signature-scheme list, extension set and h2 preface; 123 differs above the
    // hello by the `zstd` codec and the version its identity names.
    TlsShape {
        variant: TlsFingerprint::Chrome123,
        code: "chrome123",
        token: "CHROME",
        label: "CHROME 123",
        source: "curl-impersonate v2.2.2",
        baseline: false,
        ciphers: CHROME_TLS_CIPHERS,
        groups: CHROME_TLS_GROUPS,
        sig_algs: CHROME_TLS_SIG_ALGS,
        ext_order: CHROME_PADDING_AND_ECH_EXT_ORDER,
        raw_exts: CHROME_TLS_RAW_EXTS,
        suppress: &[],
        drop13: &[
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_EC_POINT_FORMATS,
            EXT_SESSION_TICKET,
        ],
        // The padding extension goes with the pinned 1.2 hello, ALPS and the
        // version list with it.
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_APPLICATION_SETTINGS, EXT_PADDING],
        alpn: H2_AND_HTTP11,
        padding_to: Some(512),
        grease: true,
        permute_extensions: true,
        ech: true,
        priority_on_h1: false,
        cert_compression: BROTLI,
        key_share_groups: None,
        pq: false,
        legacy_versions: &[],
        headers: Some(CHROME123_HEADERS),
        h2: Some(&CHROME123_H2),
    },
    // Chrome 116, as `curl_chrome116` sends it: Chrome 107's hello, shuffled.
    //
    // Chromium 110 turned on `ssl_setup_extension_permutation`, so from 110 on
    // the extension order is drawn per connection (see
    // `TlsShape::permute_extensions`) and JA3 stops identifying the client. The
    // set, the ciphers, the groups, the signature schemes and the h2 preface are
    // Chrome 107's, so the two records differ in exactly that one behaviour —
    // which is what makes this row the control for the question the whole table
    // exists to answer. Measured, 116 is refused exactly like 107, and its JA4 is
    // the same string (`t13d1516h2_8daaf6152771_e5627efa2ab1`) while its JA3 is a
    // fresh sample every connection: a censor that matched an extension *order*
    // could not catch it, and the one that was measured carries the key
    // `--legend` prints for both rows.
    //
    // What it does *not* carry that Chrome 123 does: `encrypted_client_hello`,
    // `zstd` in `accept-encoding` and the rebuilt ALPS position — which is why
    // 123 is a separate record rather than this one with a newer identity.
    TlsShape {
        variant: TlsFingerprint::Chrome116,
        code: "chrome116",
        token: "CHROME",
        label: "CHROME 116",
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
        permute_extensions: true,
        ech: false,
        priority_on_h1: false,
        cert_compression: BROTLI,
        key_share_groups: None,
        pq: false,
        legacy_versions: &[],
        headers: Some(CHROME116_HEADERS),
        h2: Some(&CHROME_H2),
    },
    // Chrome 115 with the draft hybrid group, as uTLS `HelloChrome_115_PQ`
    // sends it (`target/fingerprint/utls-ladder/HelloChrome_115_PQ-0.hex`).
    //
    // What it reproduces: Chrome 115's own hello — Chrome 107's fifteen ciphers,
    // its eight signature schemes and its extension order with ALPS still at
    // 17513 — plus the one thing 107 does not offer, the draft hybrid group
    // `X25519Kyber768Draft00` (25497) in front of X25519, and Chromium's
    // per-connection shuffle, which the spec applies in uTLS
    // (`ShuffleChromeTLSExtensions`) and the browser in BoringSSL. JA3 is
    // therefore one draw out of the distribution and JA4 is the stable reading,
    // exactly as for Chrome 116.
    //
    // What separates it from the neighbours: 116 shuffles Chrome 107's order too
    // but offers no hybrid group, and 120 replaces this draft group with the
    // final `X25519MLKEM768` (4588, see [`CHROME_TLS_PQ_GROUPS`]) — so the group
    // list is the whole of what this row adds, and the extension set the whole of
    // what it takes away from 116 (no `encrypted_client_hello`, no `zstd`).
    //
    // One deviation, and it is the provider's: this build serves no `0x6399`
    // (named in `tests::UNIMPLEMENTED` and in `docs/ADDING_A_PROFILE.md`), so
    // the record advertises 25497 and shares X25519 alone where the spec shares
    // both ([`CHROME115_PQ_KEY_SHARE_GROUPS`]). JA3 and JA4 read the group
    // *list*, not the shares, so both stay the capture's; what the missing share
    // does change is the hello's length, which is why the record leaves out the
    // padding slot as well — a real Chrome 115 is always above BoringSSL's
    // 512-byte floor and never sends one. See [`CHROME115_PQ_TLS_EXT_ORDER`].
    //
    // The identity is the source's minimum and no more: uTLS has no HTTP layer,
    // so the record carries the version's own `user-agent` and its encoding, and
    // `h2: None` leaves the preface at hyper's default — nothing here claims an
    // h2 shape that was never measured.
    TlsShape {
        variant: TlsFingerprint::Chrome115Pq,
        code: "chrome115pq",
        token: "CHROME",
        label: "CHROME 115 PQ",
        source: "uTLS v1.8.2 HelloChrome_115_PQ",
        baseline: false,
        ciphers: CHROME_TLS_CIPHERS,
        groups: CHROME115_PQ_TLS_GROUPS,
        sig_algs: CHROME_TLS_SIG_ALGS,
        ext_order: CHROME115_PQ_TLS_EXT_ORDER,
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
        // No padding: the spec's 1524-byte hello never takes extension 21, and
        // this build's shorter one must not either (see
        // [`CHROME115_PQ_TLS_EXT_ORDER`]).
        padding_to: None,
        grease: true,
        permute_extensions: true,
        ech: false,
        priority_on_h1: false,
        cert_compression: BROTLI,
        key_share_groups: Some(CHROME115_PQ_KEY_SHARE_GROUPS),
        pq: false,
        // The spec's `supported_versions` is GREASE, 1.3, 1.2 — Chrome 115 no
        // longer lists 1.1 and 1.0 behind them.
        legacy_versions: &[],
        headers: Some(CHROME115_PQ_HEADERS),
        h2: None,
    },
    // The `curl_chrome107` shape — Chrome 107, and the same TLS shape as Edge
    // 99–101.
    //
    // Taken from the `curl-impersonate v2.2.2` bundle this repository measures
    // against (`.bat` wrapper `curl_chrome107`), and identical to what
    // `curl_chrome99..104` send: one key,
    // `t13d1516h2_8daaf6152771_e5627efa2ab1` (`--legend` prints it), covers this
    // whole generation — the phone-shaped hello of `chrome99android`, the
    // identity-swapped one of `edge101` and the shuffled one of `chrome116` all
    // answer with that string, which is why those four rows of the burst table
    // move together. Chrome 115 PQ is the one shape in this version range that
    // does not: it sends fifteen extensions where these four send sixteen and
    // answers with a key of its own (see that record).
    //
    // The forum report's "chrome 99-116 / edge 99-101" is that
    // generation; it also reported `chrome110+` as blocked only part of the time,
    // and on the path where this was measured the whole generation was refused on
    // every attempt while the ECH one (119+, a different key) answered every one.
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
    // Chrome 87, as uTLS `HelloChrome_87` sends it — and Chrome 83, whose spec
    // literal is byte-for-byte the same text under another label
    // (`u_parrots.go` 231-301 against 303-373), so one record covers both
    // releases, as the Firefox 135–147 rows cover theirs.
    //
    // What it reproduces: the 512-byte padded hello of Chrome 83–99, which is
    // Chrome 107's cipher, group and signature-scheme lists with one extension
    // fewer — no ALPS. 17513 is what separates the two JA4 extension hashes
    // (`de4a06bb82e3` here, `e5627efa2ab1` for 107) even though both hellos carry
    // [`CHROME_TLS_SIG_ALGS`] unchanged; a middlebox matching the 107 generation
    // is matching the ALPS slot and the `zstd` codec of its HTTP layer, not this
    // record.
    //
    // Chrome 87 differs from Chrome 72 in the other direction and by less than a
    // release: 72's cipher list carries RSA 3DES and its signature schemes
    // `rsa_pkcs1_sha1` ([`CHROME70_TLS_CIPHERS`], [`CHROME70_TLS_SIG_ALGS`]),
    // which 87 dropped. Both still offer TLS 1.1 and 1.0 behind 1.2 and pad their
    // hello to the same floor.
    //
    // The identity is the source's minimum and no more: uTLS has no HTTP layer,
    // so the record carries the version's own `user-agent` and its encoding, and
    // `h2: None` leaves the preface at hyper's default.
    TlsShape {
        variant: TlsFingerprint::Chrome87,
        code: "chrome87",
        token: "CHROME",
        label: "CHROME 87",
        source: "uTLS v1.8.2 HelloChrome_87",
        baseline: false,
        ciphers: CHROME_TLS_CIPHERS,
        groups: CHROME_TLS_GROUPS,
        sig_algs: CHROME_TLS_SIG_ALGS,
        ext_order: CHROME72_TLS_EXT_ORDER,
        raw_exts: CHROME_TLS_RAW_EXTS,
        suppress: &[],
        drop13: &[
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_EC_POINT_FORMATS,
            EXT_SESSION_TICKET,
        ],
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_PADDING],
        alpn: H2_AND_HTTP11,
        padding_to: Some(512),
        grease: true,
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        cert_compression: BROTLI,
        key_share_groups: None,
        pq: false,
        // The spec's `supported_versions` is GREASE, 1.3, 1.2, 1.1, 1.0 — the
        // shape of a client that still had the old versions on offer.
        legacy_versions: &[0x0302, 0x0301],
        headers: Some(CHROME87_HEADERS),
        h2: None,
    },
    // Chrome 72, as uTLS `HelloChrome_72` sends it — Chrome 70's bodies behind a
    // reordered extension list, and Chrome 87's shape with the two suites and the
    // one signature scheme that 87 dropped.
    //
    // What it reproduces, and what separates it from 70: `server_name`,
    // `extended_master_secret` and the curve list have moved to the front, the
    // cipher list still ends at RSA 3DES, and the `channel_id` placeholder is
    // gone — 72 sends fifteen extensions where 70 sends sixteen, which is the
    // whole of the JA3 difference (`…-16-…-21` against `…-30032-11-…`). The two
    // share one JA4 cipher hash (`46e7e9700bed`) and one 512-byte padded hello.
    //
    // The identity is the source's minimum and no more: uTLS has no HTTP layer,
    // so the record carries the version's own `user-agent` and its encoding, and
    // `h2: None` leaves the preface at hyper's default.
    TlsShape {
        variant: TlsFingerprint::Chrome72,
        code: "chrome72",
        token: "CHROME",
        label: "CHROME 72",
        source: "uTLS v1.8.2 HelloChrome_72",
        baseline: false,
        ciphers: CHROME70_TLS_CIPHERS,
        groups: CHROME_TLS_GROUPS,
        sig_algs: CHROME70_TLS_SIG_ALGS,
        ext_order: CHROME72_TLS_EXT_ORDER,
        raw_exts: CHROME_TLS_RAW_EXTS,
        suppress: &[],
        drop13: &[
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_EC_POINT_FORMATS,
            EXT_SESSION_TICKET,
        ],
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_PADDING],
        alpn: H2_AND_HTTP11,
        padding_to: Some(512),
        grease: true,
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        cert_compression: BROTLI,
        key_share_groups: None,
        pq: false,
        legacy_versions: &[0x0302, 0x0301],
        headers: Some(CHROME72_HEADERS),
        h2: None,
    },
    // Chrome 70, as uTLS `HelloChrome_70` sends it, and the same TLS bodies 72
    // sends.
    //
    // What it reproduces, and what separates it from 72: `renegotiation_info`
    // first, the older curve/point/version placement, and `channel_id` (30032) —
    // the zero-length placeholder the last Chrome of this generation still sent
    // in the middle of its list ([`CHROME70_TLS_EXT_ORDER`]). It is also the
    // record that covers 360Browser 11.0: `Hello360_11_0` carries the same
    // ciphers, groups, signature schemes and bodies in a third order, so the two
    // are one JA4 (`46e7e9700bed_…`) and two JA3s, and this row is the uTLS
    // literal whose order the capture carries.
    //
    // The identity is the source's minimum and no more: uTLS has no HTTP layer,
    // so the record carries the version's own `user-agent` and its encoding, and
    // `h2: None` leaves the preface at hyper's default.
    TlsShape {
        variant: TlsFingerprint::Chrome70,
        code: "chrome70",
        token: "CHROME",
        label: "CHROME 70",
        source: "uTLS v1.8.2 HelloChrome_70",
        baseline: false,
        ciphers: CHROME70_TLS_CIPHERS,
        groups: CHROME_TLS_GROUPS,
        sig_algs: CHROME70_TLS_SIG_ALGS,
        ext_order: CHROME70_TLS_EXT_ORDER,
        raw_exts: CHROME70_TLS_RAW_EXTS,
        suppress: &[],
        drop13: &[
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_EC_POINT_FORMATS,
            EXT_SESSION_TICKET,
        ],
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_PADDING],
        alpn: H2_AND_HTTP11,
        padding_to: Some(512),
        grease: true,
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        cert_compression: BROTLI,
        key_share_groups: None,
        pq: false,
        // Chrome 70's own literal sets `TLSVersMin = 1.0`, and its
        // `supported_versions` lists 1.3, 1.2, 1.1 and 1.0.
        legacy_versions: &[0x0302, 0x0301],
        headers: Some(CHROME70_HEADERS),
        h2: None,
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
    // Firefox 147, as `curl_firefox147` sends it (the wrapper is a one-liner —
    // `--impersonate firefox147` — and the bundle's `firefox_144.0.0_linux`
    // capture is the reading of it this record is pinned to).
    //
    // The hello is Firefox 133's plus `signed_certificate_timestamp` (18),
    // between `delegated_credentials` and `key_share` — the one extension the
    // plan called out as a shape this build could not reproduce before, and the
    // reason the 133 record stays separate: a middlebox that reacts to 18 alone
    // reads the two as different clients. Firefox 135 and 147 send this same
    // hello, so they are one profile here, under the newest identity.
    TlsShape {
        variant: TlsFingerprint::Firefox147,
        code: "firefox147",
        token: "FIREFOX",
        label: "FIREFOX 147",
        source: "curl-impersonate v2.2.2",
        baseline: false,
        ciphers: FIREFOX_TLS_CIPHERS,
        groups: FIREFOX_TLS_GROUPS,
        sig_algs: FIREFOX_TLS_SIG_ALGS,
        ext_order: FIREFOX147_TLS_EXT_ORDER,
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
        headers: Some(FIREFOX147_HEADERS),
        h2: Some(&FIREFOX_H2),
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
    // Firefox 120, as uTLS `HelloFirefox_120` sends it — the shape
    // `HelloFirefox_Auto` resolves to, and Firefox 133's minus two things.
    //
    // What it reproduces: Firefox 120's hello is Firefox 133's without
    // `compress_certificate` (27) and without the hybrid group — fifteen
    // extensions instead of sixteen, six curves instead of seven, and
    // `encrypted_client_hello` still closing the list as GREASE. Everything else
    // is 133's: the seventeen ciphers, the eleven signature schemes, the two key
    // shares and an unpadded hello (120 sends no padding).
    //
    // One deviation, and it is ours: the spec pins the GREASE-ECH payload to a
    // single length (223 encoded bytes, 239 on the wire), where this build draws
    // it from BoringSSL's four values as every other ECH record does. The hash
    // is unaffected — ECH length is in no fingerprint — but the record size
    // differs on three draws in four. Named in `docs/ADDING_A_PROFILE.md`.
    //
    // The identity is the source's minimum and no more: uTLS has no HTTP layer,
    // so the record carries the version's own `user-agent` and its encoding, and
    // `h2: None` leaves the preface at hyper's default.
    TlsShape {
        variant: TlsFingerprint::Firefox120,
        code: "firefox120",
        token: "FIREFOX",
        label: "FIREFOX 120",
        source: "uTLS v1.8.2 HelloFirefox_120",
        baseline: false,
        ciphers: FIREFOX_TLS_CIPHERS,
        // Firefox's pre-hybrid curve list, which Tor 14.5 also sends — the six
        // groups [`TOR_TLS_GROUPS`] already spells out.
        groups: TOR_TLS_GROUPS,
        sig_algs: FIREFOX_TLS_SIG_ALGS,
        ext_order: FIREFOX120_TLS_EXT_ORDER,
        raw_exts: FIREFOX_TLS_RAW_EXTS,
        suppress: &[],
        drop13: &[EXT_EC_POINT_FORMATS, EXT_SESSION_TICKET],
        drop12: &[EXT_SUPPORTED_VERSIONS],
        alpn: H2_AND_HTTP11,
        padding_to: None,
        grease: false,
        permute_extensions: false,
        ech: true,
        priority_on_h1: false,
        // No `compress_certificate`: 120 predates it, and advertising the
        // algorithms without the extension would be a shape neither client
        // sends.
        cert_compression: &[],
        key_share_groups: Some(FIREFOX_PRE_HYBRID_KEY_SHARE_GROUPS),
        pq: false,
        // The spec offers 1.3 and 1.2 only.
        legacy_versions: &[],
        headers: Some(FIREFOX120_HEADERS),
        h2: None,
    },
    // Firefox 105, as uTLS `HelloFirefox_105` sends it.
    //
    // What it reproduces: Firefox 105's hello is 133's without
    // `compress_certificate` (27), without the SCT slot (18) and without ECH,
    // with the padding slot Firefox still used and the same seventeen ciphers,
    // six curves, eleven signature schemes and two key shares. Firefox 102 sends
    // the same JA3 and the same JA4 under this shape — its `TLSVersMin`, its ALPN
    // *list* (one protocol against two, which JA4 reads through the first alone)
    // and the compensating padding body are the differences, and none of them
    // reaches either hash — so the record covers both releases.
    //
    // What separates it from Firefox 99: 105 dropped `RSA_3DES_EDE_CBC_SHA`, and
    // its `supported_versions` no longer offers 1.1 and 1.0. The two share one
    // extension hash (`3d5424432f57`) and differ in the cipher hash, which is
    // exactly the extra suite.
    //
    // The identity is the source's minimum and no more: uTLS has no HTTP layer,
    // so the record carries the version's own `user-agent` and its encoding, and
    // `h2: None` leaves the preface at hyper's default.
    TlsShape {
        variant: TlsFingerprint::Firefox105,
        code: "firefox105",
        token: "FIREFOX",
        label: "FIREFOX 105",
        source: "uTLS v1.8.2 HelloFirefox_105",
        baseline: false,
        ciphers: FIREFOX_TLS_CIPHERS,
        // The same six groups as [`TOR_TLS_GROUPS`], Firefox's pre-hybrid list.
        groups: TOR_TLS_GROUPS,
        sig_algs: FIREFOX_TLS_SIG_ALGS,
        ext_order: FIREFOX99_TLS_EXT_ORDER,
        raw_exts: FIREFOX_TLS_RAW_EXTS,
        suppress: &[],
        drop13: &[EXT_EC_POINT_FORMATS, EXT_SESSION_TICKET],
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_PADDING],
        alpn: H2_AND_HTTP11,
        padding_to: Some(512),
        grease: false,
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        cert_compression: &[],
        key_share_groups: Some(FIREFOX_PRE_HYBRID_KEY_SHARE_GROUPS),
        pq: false,
        legacy_versions: &[],
        headers: Some(FIREFOX105_HEADERS),
        h2: None,
    },
    // Firefox 99, as uTLS `HelloFirefox_99` sends it.
    //
    // What it reproduces: Firefox 105's shape with one cipher more —
    // `RSA_3DES_EDE_CBC_SHA` (0x000a), the last entry of its eighteen — and the
    // old versions still on offer behind 1.2. The two hellos carry the same
    // fifteen extensions in the same order and hash to the same extension hash;
    // only the cipher hash moves (`e8a523a41297` against `5b57614c22b0`), which
    // is why this is a record of its own rather than a 105 alias with a comment:
    // a censor reading JA4's cipher hash reads the two as different clients.
    //
    // The identity is the source's minimum and no more: uTLS has no HTTP layer,
    // so the record carries the version's own `user-agent` and its encoding, and
    // `h2: None` leaves the preface at hyper's default.
    TlsShape {
        variant: TlsFingerprint::Firefox99,
        code: "firefox99",
        token: "FIREFOX",
        label: "FIREFOX 99",
        source: "uTLS v1.8.2 HelloFirefox_99",
        baseline: false,
        ciphers: FIREFOX99_TLS_CIPHERS,
        groups: TOR_TLS_GROUPS,
        sig_algs: FIREFOX_TLS_SIG_ALGS,
        ext_order: FIREFOX99_TLS_EXT_ORDER,
        raw_exts: FIREFOX_TLS_RAW_EXTS,
        suppress: &[],
        drop13: &[EXT_EC_POINT_FORMATS, EXT_SESSION_TICKET],
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_PADDING],
        alpn: H2_AND_HTTP11,
        padding_to: Some(512),
        grease: false,
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        cert_compression: &[],
        key_share_groups: Some(FIREFOX_PRE_HYBRID_KEY_SHARE_GROUPS),
        pq: false,
        legacy_versions: &[0x0302, 0x0301],
        headers: Some(FIREFOX99_HEADERS),
        h2: None,
    },
    // Firefox 65, as uTLS `HelloFirefox_65` sends it — and Firefox 63, which one
    // spec literal serves (`case HelloFirefox_63, HelloFirefox_65`), so one
    // record covers both.
    //
    // What it reproduces: the oldest Firefox here, and the only one without
    // `delegated_credentials` (34) — fourteen extensions where every later
    // Firefox sends fifteen — and the only one whose cipher list carries the
    // DHE_RSA CBC pair uTLS writes as `FAKE_TLS_DHE_RSA_WITH_AES_128/256_CBC_SHA`
    // (0x0033/0x0039) in place of the static-RSA AES-GCM two. The curve list, the
    // signature schemes, the two key shares, the `record_size_limit` body and the
    // 512-byte padding are Firefox 99's.
    //
    // The identity is the source's minimum and no more: uTLS has no HTTP layer,
    // so the record carries the version's own `user-agent` and its encoding, and
    // `h2: None` leaves the preface at hyper's default.
    TlsShape {
        variant: TlsFingerprint::Firefox65,
        code: "firefox65",
        token: "FIREFOX",
        label: "FIREFOX 65",
        source: "uTLS v1.8.2 HelloFirefox_65",
        baseline: false,
        ciphers: FIREFOX65_TLS_CIPHERS,
        groups: TOR_TLS_GROUPS,
        sig_algs: FIREFOX_TLS_SIG_ALGS,
        ext_order: FIREFOX65_TLS_EXT_ORDER,
        raw_exts: FIREFOX_TLS_RAW_EXTS,
        suppress: &[],
        drop13: &[EXT_EC_POINT_FORMATS, EXT_SESSION_TICKET],
        drop12: &[EXT_SUPPORTED_VERSIONS, EXT_PADDING],
        alpn: H2_AND_HTTP11,
        padding_to: Some(512),
        grease: false,
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        cert_compression: &[],
        key_share_groups: Some(FIREFOX_PRE_HYBRID_KEY_SHARE_GROUPS),
        pq: false,
        legacy_versions: &[0x0302, 0x0301],
        headers: Some(FIREFOX65_HEADERS),
        h2: None,
    },
    // Go 1.27's `crypto/tls`, through uTLS `HelloGolang`: the client the
    // `Go-http-client/1.1` identity belongs to, and the one record here that is
    // not a browser.
    //
    // What it reproduces: thirteen ciphers (Go's own preference order, which puts
    // the CBC suites above the TLS 1.3 ones), five curves with the hybrid group
    // Go added in front, twelve signature schemes with Ed25519 among them, and
    // ten extensions in the fixed order `crypto/tls` writes. Nothing greases and
    // nothing pads, and the hybrid key share is most of the 1466-byte hello the
    // capture measures.
    //
    // Three things distinguish it from every other record: it sends no ALPN at
    // all (a Go client with no `NextProtos` offers none, so the probes speak
    // HTTP/1.1 to it), it advertises no `compress_certificate`, and it names no
    // key share of its own — its two shares are rustls's default choice for the
    // group list, the hybrid group and its X25519 component.
    //
    // The identity is the source's minimum and no more: `crypto/tls` has no HTTP
    // layer beyond its own default `User-Agent`, so the record carries that and
    // the one encoding Go advertises, and `h2: None` leaves the preface at
    // hyper's default.
    //
    // The capture behind these numbers is uTLS v1.8.2's vendored `crypto/tls`
    // fork, which is the hello a peer of this profile reads; a local Go 1.27
    // adds ML-DSA schemes and a `signature_algorithms_cert` extension on top of
    // it, and none of them is in this shape.
    TlsShape {
        variant: TlsFingerprint::Go127,
        code: "go127",
        token: "GO",
        label: "GO 1.27",
        source: "Go 1.27 crypto/tls, through uTLS HelloGolang",
        baseline: false,
        ciphers: GO_TLS_CIPHERS,
        groups: GO_TLS_GROUPS,
        sig_algs: GO_TLS_SIG_ALGS,
        ext_order: GO_TLS_EXT_ORDER,
        raw_exts: GO_TLS_RAW_EXTS,
        // None of these three is in the order above: Go sends no ALPN, no
        // session ticket and no PSK modes, and rustls would send all three.
        suppress: &[
            EXT_ALPN,
            EXT_SESSION_TICKET,
            EXT_PSK_KEY_EXCHANGE_MODES,
        ],
        drop13: &[EXT_EXTENDED_MASTER_SECRET, EXT_RENEGOTIATION_INFO, EXT_EC_POINT_FORMATS],
        drop12: &[EXT_SUPPORTED_VERSIONS],
        // No ALPN: the record offers none, and `suppress` keeps rustls from
        // writing an extension Go does not send.
        alpn: &[],
        padding_to: None,
        grease: false,
        permute_extensions: false,
        ech: false,
        priority_on_h1: false,
        cert_compression: &[],
        // rustls's own choice: the hybrid group first and its X25519 component
        // after it, which is the capture's `key_share = 4588,29`.
        key_share_groups: None,
        pq: true,
        legacy_versions: &[],
        headers: Some(GO127_HEADERS),
        h2: None,
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
    // Safari 17.2 on iOS, as `curl_safari172_ios` sends it: 17.0's hello and
    // identity behind the phone's `User-Agent`, with a 2 MiB stream window in the
    // preface instead of 4 MiB.
    TlsShape {
        variant: TlsFingerprint::Safari172Ios,
        code: "safari172ios",
        token: "SAFARI",
        label: "SAFARI 172 IOS",
        source: "curl-impersonate v2.2.2",
        baseline: false,
        ciphers: SAFARI_TLS_CIPHERS,
        groups: SAFARI_TLS_GROUPS,
        sig_algs: SAFARI_TLS_SIG_ALGS,
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
        headers: Some(SAFARI172_IOS_HEADERS),
        h2: Some(&SAFARI172_IOS_H2),
    },
    // Safari 17.0, as `curl_safari170` sends it: 15.5's hello, a newer preface
    // and a fuller identity.
    //
    // The reason this is a record rather than the alias it used to be: its
    // `SETTINGS` are `2:0;4:4194304;3:100` — 15.5's list with
    // `SETTINGS_ENABLE_PUSH` in front — and its request carries the three
    // `Sec-Fetch-*` fields 15.5 does not. Resolving `safari170` to the 15.5
    // record therefore announced a preface the real 17.0 never sends.
    TlsShape {
        variant: TlsFingerprint::Safari170,
        code: "safari170",
        token: "SAFARI",
        label: "SAFARI 170",
        source: "curl-impersonate v2.2.2",
        baseline: false,
        ciphers: SAFARI_TLS_CIPHERS,
        groups: SAFARI_TLS_GROUPS,
        sig_algs: SAFARI_TLS_SIG_ALGS,
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
        headers: Some(SAFARI170_HEADERS),
        h2: Some(&SAFARI170_H2),
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
    // Tor Browser 14.5, as `curl_tor145` sends it: Firefox 128 ESR's hello
    // wearing the browser's own identity.
    //
    // What this row measures is the *wrapper's* hello, not a live Tor Browser's.
    // The shape carries neither `psk_key_exchange_modes` (45) nor
    // `session_ticket` (35) nor `compress_certificate` (27), and every live
    // Firefox sends all three — both Firefox rows here do. So a block this row
    // meets is a block of *this string*: whether Tor Browser itself answers with
    // it is an open question, and the way to settle it is a capture of a live
    // client measured with `hello <capture.hex>`.
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
/// `channel_id`, as the placeholder Chrome 70 sent it: uTLS's
/// `FakeChannelIDExtension{}` writes a zero-length body at the new code point
/// (30032; 30031 was the old one, which no shape here sends).
pub(crate) const EXT_FAKE_CHANNEL_ID: u16 = 30032;
