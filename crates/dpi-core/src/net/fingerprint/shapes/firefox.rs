//! Firefox's constants and records, and the lists Tor Browser's wrapper shares
//! with them.

use super::super::TlsFingerprint;
use super::super::h2::FIREFOX_H2;
use super::super::identity::{
    FIREFOX105_HEADERS, FIREFOX120_HEADERS, FIREFOX147_HEADERS, FIREFOX65_HEADERS,
    FIREFOX99_HEADERS, FIREFOX_HEADERS,
};
use super::tor::TOR_TLS_GROUPS;
use super::{
    EXT_ALPN, EXT_COMPRESS_CERTIFICATE, EXT_DELEGATED_CREDENTIALS, EXT_EC_POINT_FORMATS,
    EXT_ENCRYPTED_CLIENT_HELLO, EXT_EXTENDED_MASTER_SECRET, EXT_KEY_SHARE, EXT_PADDING,
    EXT_PSK_KEY_EXCHANGE_MODES, EXT_RECORD_SIZE_LIMIT, EXT_RENEGOTIATION_INFO, EXT_SCT,
    EXT_SERVER_NAME, EXT_SESSION_TICKET, EXT_SIGNATURE_ALGORITHMS, EXT_STATUS_REQUEST,
    EXT_SUPPORTED_GROUPS, EXT_SUPPORTED_VERSIONS, H2_AND_HTTP11,
};
use super::TlsShape;

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

/// Firefox 133–144's signature schemes. `curl_tor145` sends the same eleven in
/// the same order.
pub(crate) const FIREFOX_TLS_SIG_ALGS: &[u16] = &[
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

/// The bodies Firefox 133–144 emit verbatim. The SCT entry is inert in 133's
/// hello (the extension is not in its order) and live in 135's. The padding entry
/// is inert where the order does not name it — 120 and 133–147 — and is what puts
/// Firefox 65, 99 and 105 on the 512-byte floor.
pub(crate) const FIREFOX_TLS_RAW_EXTS: &[(u16, &[u8])] = &[
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
pub(crate) const FIREFOX147: TlsShape = TlsShape {
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
};
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
pub(crate) const FIREFOX133: TlsShape = TlsShape {
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
};
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
pub(crate) const FIREFOX120: TlsShape = TlsShape {
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
};
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
pub(crate) const FIREFOX105: TlsShape = TlsShape {
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
};
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
pub(crate) const FIREFOX99: TlsShape = TlsShape {
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
};
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
pub(crate) const FIREFOX65: TlsShape = TlsShape {
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
};
