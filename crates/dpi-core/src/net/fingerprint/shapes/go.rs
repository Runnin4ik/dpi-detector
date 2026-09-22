//! Go's constants and record: the `crypto/tls` hello uTLS `HelloGolang` writes.

use super::super::TlsFingerprint;
use super::super::identity::GO127_HEADERS;
use super::{
    EXT_ALPN, EXT_EC_POINT_FORMATS, EXT_EXTENDED_MASTER_SECRET, EXT_KEY_SHARE,
    EXT_PSK_KEY_EXCHANGE_MODES, EXT_RENEGOTIATION_INFO, EXT_SCT, EXT_SERVER_NAME,
    EXT_SESSION_TICKET, EXT_SIGNATURE_ALGORITHMS, EXT_STATUS_REQUEST, EXT_SUPPORTED_GROUPS,
    EXT_SUPPORTED_VERSIONS,
};
use super::TlsShape;

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
pub(crate) const GO127: TlsShape = TlsShape {
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
};
