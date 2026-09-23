//! Chrome's constants and records: the Chromium lists Edge also sends, and the
//! eleven Chrome profiles that advertise them.

use rustls::client::hello_profile::GREASE_EXTENSION_MARKER;

use super::super::TlsFingerprint;
use super::super::h2::{CHROME123_H2, CHROME99_ANDROID_H2, CHROME_H2};
use super::super::identity::{
    CHROME115_PQ_HEADERS, CHROME116_HEADERS, CHROME123_HEADERS, CHROME131_ANDROID_HEADERS,
    CHROME131_HEADERS, CHROME133_HEADERS, CHROME146_HEADERS, CHROME70_HEADERS, CHROME72_HEADERS, CHROME87_HEADERS,
    CHROME99_ANDROID_HEADERS, CHROME_HEADERS,
};
use super::{
    BROTLI, EXT_ALPN, EXT_APPLICATION_SETTINGS, EXT_APPLICATION_SETTINGS_NEW,
    EXT_COMPRESS_CERTIFICATE, EXT_EC_POINT_FORMATS, EXT_ENCRYPTED_CLIENT_HELLO,
    EXT_EXTENDED_MASTER_SECRET, EXT_FAKE_CHANNEL_ID, EXT_KEY_SHARE, EXT_PADDING,
    EXT_PSK_KEY_EXCHANGE_MODES, EXT_RENEGOTIATION_INFO, EXT_SCT, EXT_SERVER_NAME,
    EXT_SESSION_TICKET, EXT_SIGNATURE_ALGORITHMS, EXT_STATUS_REQUEST, EXT_SUPPORTED_GROUPS,
    EXT_SUPPORTED_VERSIONS, H2_AND_HTTP11,
};
use super::TlsShape;

/// Chrome 99–107's cipher list, which Chrome 133 keeps and Edge 99–101 sends
/// unchanged (`curl_edge99/101` and `curl_chrome99..107` emit one JA3, and uTLS
/// `HelloEdge_106` lists the same suites).
pub(crate) const CHROME_TLS_CIPHERS: &[u16] = &[
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
pub(crate) const CHROME_TLS_SIG_ALGS: &[u16] = &[
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
pub(crate) const CHROME_TLS_GROUPS: &[u16] = &[
    29, // X25519
    23, // secp256r1
    24, // secp384r1
];

/// Chrome 99–107 / Edge 99–101's extension order, in the order the bundle sends
/// it: one GREASE slot first and one before the padding.
pub(crate) const CHROME_TLS_EXT_ORDER: &[u16] = &[
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
pub(crate) const CHROME_TLS_RAW_EXTS: &[(u16, &[u8])] = &[
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
pub(crate) const CHROME146: TlsShape = TlsShape {
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
};

// Chrome 133, as `curl_chrome133a` sends it: Chrome 146's hello exactly — the
// same ciphers, extension set, order, bodies, hybrid group, ECH and shuffling —
// under the 133 identity. The bundle's own capture agrees: the two report one
// JA4 (`t13d1516h2_8daaf6152771_d8a2da3f94cd`), one peetprint and one h2
// preface, and differ only in the brand list and the `User-Agent`.
//
// The repository's rule is one record per hello, and this is a deliberate
// exception to it: with the censor reading the ClientHello, a 133 record can
// only behave like the 146 one, and a run that presents both asks whether that
// is true. A difference between them would be the identity being read, which is
// what the record is for.
pub(crate) const CHROME133: TlsShape = TlsShape {
    variant: TlsFingerprint::Chrome133,
    code: "chrome133",
    token: "CHROME",
    label: "CHROME 133",
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
    headers: Some(CHROME133_HEADERS),
    h2: Some(&CHROME123_H2),
};

// Chrome 131, as `curl_chrome131` sends it: Chrome 146's shape with ALPS
// one code point earlier — the hybrid group leads the list and is shared,
// ALPS is still at 17513, and there is no padding.
//
// It is the profile that separates the two halves of the "post-quantum
// group" question a censor can read: 131 and 146 differ in the ALPS code
// point and in nothing a JA3 carries, so a site that blocks 146 and passes
// 131 is reacting to something other than the group.
pub(crate) const CHROME131: TlsShape = TlsShape {
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
};
// Chrome 131 on Android, as `curl_chrome131_android` sends it.
//
// Its wrapper's first comment line is the whole difference from the desktop
// row: "The only difference from desktop is the absense of MLKEM", so the
// group list is X25519/P-256/P-384 and nothing is post-quantum. Everything
// else — the ECH extension, the ALPS code point, the 512-byte floor the
// shortest ECH body drops it under (see the desktop record), the header set —
// tracks the desktop 131 with the phone's UA and platform.
pub(crate) const CHROME131_ANDROID: TlsShape = TlsShape {
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
};
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
pub(crate) const CHROME123: TlsShape = TlsShape {
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
};
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
pub(crate) const CHROME116: TlsShape = TlsShape {
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
};
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
pub(crate) const CHROME115_PQ: TlsShape = TlsShape {
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
};
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
pub(crate) const CHROME107: TlsShape = TlsShape {
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
};
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
pub(crate) const CHROME99_ANDROID: TlsShape = TlsShape {
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
};
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
pub(crate) const CHROME87: TlsShape = TlsShape {
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
};
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
pub(crate) const CHROME72: TlsShape = TlsShape {
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
};
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
pub(crate) const CHROME70: TlsShape = TlsShape {
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
};
