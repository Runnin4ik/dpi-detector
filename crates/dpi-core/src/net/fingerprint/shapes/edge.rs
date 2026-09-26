//! Edge's record: Chromium's TLS lists under Edge's own identity and h2
//! preface.

use super::super::TlsFingerprint;
use super::chrome::{
    CHROME_TLS_CIPHERS, CHROME_TLS_DROP12_ALPS_PADDING, CHROME_TLS_DROP13, CHROME_TLS_EXT_ORDER,
    CHROME_TLS_GROUPS, CHROME_TLS_RAW_EXTS, CHROME_TLS_SIG_ALGS,
};
use super::super::h2::EDGE101_H2;
use super::super::identity::EDGE101_HEADERS;
use super::{BROTLI, H2_AND_HTTP11};
use super::TlsShape;

// Edge 101, as `curl_edge101` of curl-impersonate v2.2.3 sends it, with
// uTLS `HelloEdge_106` as the second reading of the same shape.
//
// Edge is Chromium: the TLS lists above are Chrome 99–107's, and the bundle
// documents that Chromium browsers differ only in `User-Agent` and
// `sec-ch-ua-platform`. The identity is therefore the whole point of this
// record, and so is the one h2 difference — Edge sends no
// `SETTINGS_ENABLE_PUSH`.
pub(crate) const EDGE101: TlsShape = TlsShape {
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
    // Chromium's drop lists, the same ones the Chrome 99–107 records use.
    drop13: CHROME_TLS_DROP13,
    drop12: CHROME_TLS_DROP12_ALPS_PADDING,
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
};
