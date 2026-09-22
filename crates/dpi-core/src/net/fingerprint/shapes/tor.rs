//! Tor Browser 14.5's constants and record: Firefox 128 ESR's hello as the
//! wrapper sends it.

use super::super::TlsFingerprint;
use super::firefox::{FIREFOX_TLS_RAW_EXTS, FIREFOX_TLS_SIG_ALGS};
use super::super::h2::FIREFOX_H2;
use super::super::identity::TOR_HEADERS;
use super::{
    EXT_ALPN, EXT_COMPRESS_CERTIFICATE, EXT_DELEGATED_CREDENTIALS, EXT_EC_POINT_FORMATS,
    EXT_ENCRYPTED_CLIENT_HELLO, EXT_EXTENDED_MASTER_SECRET, EXT_KEY_SHARE,
    EXT_PSK_KEY_EXCHANGE_MODES, EXT_RECORD_SIZE_LIMIT, EXT_RENEGOTIATION_INFO, EXT_SERVER_NAME,
    EXT_SESSION_TICKET, EXT_SIGNATURE_ALGORITHMS, EXT_STATUS_REQUEST, EXT_SUPPORTED_GROUPS,
    EXT_SUPPORTED_VERSIONS, H2_AND_HTTP11,
};
use super::TlsShape;

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

/// Tor Browser 14.5's groups: Firefox's without the hybrid group, which Tor
/// 14.5 (Firefox 128 ESR) does not offer.
pub(crate) const TOR_TLS_GROUPS: &[u16] = &[
    29,  // X25519
    23,  // secp256r1
    24,  // secp384r1
    25,  // secp521r1
    256, // ffdhe2048
    257, // ffdhe3072
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
pub(crate) const TOR145: TlsShape = TlsShape {
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
};
