//! The baseline record: no profile is installed for it, so rustls's own hello
//! goes out.

use super::super::TlsFingerprint;
use super::TlsShape;

pub(crate) const RUSTLS: TlsShape = TlsShape {
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
};
