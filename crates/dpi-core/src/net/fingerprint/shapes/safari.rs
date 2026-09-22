//! Safari's constants and records: macOS and iOS, 15.3 through 26.0.

use rustls::client::hello_profile::GREASE_EXTENSION_MARKER;

use super::super::TlsFingerprint;
use super::super::h2::{
    SAFARI170_H2, SAFARI172_IOS_H2, SAFARI184_IOS_H2, SAFARI18_H2, SAFARI260_H2, SAFARI_H2,
};
use super::super::identity::{
    SAFARI153_HEADERS, SAFARI170_HEADERS, SAFARI172_IOS_HEADERS, SAFARI184_IOS_HEADERS,
    SAFARI18_HEADERS, SAFARI260_HEADERS, SAFARI260_IOS_HEADERS, SAFARI_HEADERS,
};
use super::{
    EXT_ALPN, EXT_COMPRESS_CERTIFICATE, EXT_EC_POINT_FORMATS, EXT_EXTENDED_MASTER_SECRET,
    EXT_KEY_SHARE, EXT_PADDING, EXT_PSK_KEY_EXCHANGE_MODES, EXT_RENEGOTIATION_INFO, EXT_SCT,
    EXT_SERVER_NAME, EXT_SESSION_TICKET, EXT_SIGNATURE_ALGORITHMS, EXT_STATUS_REQUEST,
    EXT_SUPPORTED_GROUPS, EXT_SUPPORTED_VERSIONS, H2_AND_HTTP11,
};
use super::TlsShape;

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

// Safari 26.0 on macOS, as `curl_safari260` sends it: the first Safari in
// the bundle that offers the hybrid group, and the first client of any
// family whose hello carries no padding *and* a session ticket.
//
// Two more firsts worth knowing when a verdict surprises: the three TLS 1.3
// suites are reordered (`4866-4867-4865`), which only JA3 shows, and the
// wrapper passes `--http2-no-priority`, so its request `HEADERS` frame
// carries no PRIORITY — the first profile here whose preface is `None` in
// that field.
pub(crate) const SAFARI260: TlsShape = TlsShape {
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
};
// Safari 26.0 on iOS, as `curl_safari260_ios` sends it.
//
// The same release as the macOS row with three differences a middlebox can
// read: no hybrid group (iOS keeps X25519 first), the padding extension back
// (its hello measures 512 bytes where macOS 26's does not), and the iOS UA.
// Everything else, the cipher order and the preface included, matches 26.0
// on macOS.
pub(crate) const SAFARI260_IOS: TlsShape = TlsShape {
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
};
// Safari 18.4 on iOS, as `curl_safari184_ios` sends it: the 18.x hello
// behind an iPhone's identity.
//
// The TLS shape is [`TlsFingerprint::Safari180`]'s — same lists — and the
// identity and the h2 preface are what the row is for: the iOS UA, its own
// `priority`, and a preface with `9:1` and no `8:1`, which is what the iOS
// 18.4 build sends.
pub(crate) const SAFARI184_IOS: TlsShape = TlsShape {
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
};
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
pub(crate) const SAFARI180: TlsShape = TlsShape {
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
};
// Safari 17.2 on iOS, as `curl_safari172_ios` sends it: 17.0's hello and
// identity behind the phone's `User-Agent`, with a 2 MiB stream window in the
// preface instead of 4 MiB.
pub(crate) const SAFARI172_IOS: TlsShape = TlsShape {
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
};
// Safari 17.0, as `curl_safari170` sends it: 15.5's hello, a newer preface
// and a fuller identity.
//
// The reason this is a record rather than the alias it used to be: its
// `SETTINGS` are `2:0;4:4194304;3:100` — 15.5's list with
// `SETTINGS_ENABLE_PUSH` in front — and its request carries the three
// `Sec-Fetch-*` fields 15.5 does not. Resolving `safari170` to the 15.5
// record therefore announced a preface the real 17.0 never sends.
pub(crate) const SAFARI170: TlsShape = TlsShape {
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
};

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
pub(crate) const SAFARI155: TlsShape = TlsShape {
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
};
// Safari 15.3, as `curl_safari153` sends it — the one Safari in the bundle
// whose *cipher list* differs from 15.5's: 26 suites against 20, the six
// extra ones CBC/SHA-256, and no `compress_certificate`.
//
// JA3 carries both differences in its first two fields, so this profile is
// reproducible exactly: the source publishes its JA3 and JA4
// (`a94da16745ee3dbe77c10610f3f33a23` / `t13d2613h2_…_845d286b0d67`) and the
// tests pin both.
pub(crate) const SAFARI153: TlsShape = TlsShape {
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
};
