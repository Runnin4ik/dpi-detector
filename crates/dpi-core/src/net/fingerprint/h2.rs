//! The HTTP/2 preface a profile presents, from the same wrapper as its headers.
//!
//! `SETTINGS` values, which of them are sent, and the connection window that
//! becomes the `WINDOW_UPDATE` increment. The request's own shape — the
//! pseudo-header order and the PRIORITY flag with the weight and exclusivity the
//! wrapper names (`--http2-stream-weight`, `--http2-stream-exclusive`) —
//! travels beside it, in [`H2Fingerprint::priority`] and `pseudo_order`, and
//! reaches the wire through the patched `h2` (`vendor/h2/README-PATCH.md`).

use h2::client::PseudoOrder;

use super::shapes::TlsShape;

/// The HTTP/2 preface a profile presents.
///
/// Every field is data, so the table below is the whole of a profile's h2
/// shape: no `match` on a variant decides a setting. `h2_fingerprint` hands the
/// baseline `None`, which is hyper's own defaults — the shape every earlier
/// measurement used.
#[derive(Debug, Clone, Copy)]
pub struct H2Fingerprint {
    /// `SETTINGS_HEADER_TABLE_SIZE`; `None` omits the setting.
    pub header_table_size: Option<u32>,
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`; `None` omits the setting.
    pub max_concurrent_streams: Option<u32>,
    /// `SETTINGS_INITIAL_WINDOW_SIZE`.
    pub initial_window_size: u32,
    /// `SETTINGS_MAX_FRAME_SIZE`; `None` omits the setting.
    pub max_frame_size: Option<u32>,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`; `None` omits the setting. Chrome sends
    /// 262144, Firefox and Safari send none.
    pub max_header_list_size: Option<u32>,
    /// `SETTINGS_ENABLE_PUSH`; `None` omits the setting. Chrome and Firefox send
    /// `0`, Safari sends none.
    pub enable_push: Option<bool>,
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL`; `None` omits the setting. Safari 18
    /// sends `true` — Chrome and Firefox never do, and this build issues no
    /// extended CONNECT request, so the setting is shape only.
    pub enable_connect_protocol: Option<bool>,
    /// `SETTINGS_NO_RFC7540_PRIORITIES`; `None` omits the setting. Safari 18 and
    /// 26 send `true`, which tells the peer the RFC 7540 priority scheme is not
    /// used — independently of the PRIORITY flag a `HEADERS` frame may carry.
    pub no_rfc7540_priorities: Option<bool>,
    /// The order the preface lists its entries in, by setting id. Empty — every
    /// profile but Safari — is ascending, which is what those bundles send;
    /// Safari names `4` before `3`.
    pub settings_order: &'static [u16],
    /// Total connection window; h2 sends `WINDOW_UPDATE` with this minus the
    /// protocol's 65 535 default, which is the increment the impersonated client
    /// sends.
    pub connection_window: u32,
    /// The order the request puts its pseudo-header fields in. RFC 9113 leaves
    /// it open and the browsers disagree; no ClientHello hash shows it.
    pub pseudo_order: PseudoOrder,
    /// The request's `HEADERS` frame carries the PRIORITY flag, as
    /// `(weight, exclusive)` — the weight the impersonated client names, one
    /// more than the byte on the wire (Chrome's `256` is the frame's `255`).
    pub priority: Option<(u16, bool)>,
}

impl TlsShape {
    /// This shape's preface, `None` for the baseline profile.
    pub(crate) fn preface(self) -> Option<H2Fingerprint> {
        self.h2.copied()
    }
}

/// The HTTP/2 preface of `fingerprint`, `None` for the baseline profile
/// (hyper's own defaults, the shape every earlier measurement used).
pub fn h2_fingerprint(fingerprint: super::TlsFingerprint) -> Option<H2Fingerprint> {
    fingerprint.spec().preface()
}

/// `1:65536;2:0;4:6291456;6:262144`, window 15663105,
/// `--http2-stream-weight 256 --http2-stream-exclusive 1`, pseudo-headers `masp`
/// (the curl default, no flag).
///
/// Chrome's preface from 119 on, and the one every desktop record with this shape sends:
/// 99–107 still carried `3:1000` (`SETTINGS_MAX_CONCURRENT_STREAMS`), 120 and
/// later dropped it, and the 123, 131 and 146 records send this same list.
pub(crate) const CHROME123_H2: H2Fingerprint = H2Fingerprint {
    header_table_size: Some(65_536),
    max_concurrent_streams: None,
    initial_window_size: 6_291_456,
    max_frame_size: None,
    max_header_list_size: Some(262_144),
    enable_push: Some(false),
    enable_connect_protocol: None,
    no_rfc7540_priorities: None,
    settings_order: &[],
    connection_window: 15_663_105 + 65_535,
    pseudo_order: PseudoOrder::MethodAuthoritySchemePath,
    priority: Some((256, true)),
};

/// `1:65536;3:1000;4:6291456;6:262144`, window 15663105,
/// `--http2-stream-weight 256 --http2-stream-exclusive 1`, pseudo-headers `masp`.
///
/// Chrome on Android, which is `curl_chrome99_android`'s preface: it keeps the
/// stream cap Chrome 99–107 sent and, unlike those, sends no
/// `SETTINGS_ENABLE_PUSH` — the same shape Chromium's Android build had while
/// the desktop build did not.
pub(crate) const CHROME99_ANDROID_H2: H2Fingerprint = H2Fingerprint {
    header_table_size: Some(65_536),
    max_concurrent_streams: Some(1000),
    initial_window_size: 6_291_456,
    max_frame_size: None,
    max_header_list_size: Some(262_144),
    enable_push: None,
    enable_connect_protocol: None,
    no_rfc7540_priorities: None,
    settings_order: &[],
    connection_window: 15_663_105 + 65_535,
    pseudo_order: PseudoOrder::MethodAuthoritySchemePath,
    priority: Some((256, true)),
};

/// `1:65536;3:1000;4:6291456;6:262144`, window 15663105,
/// `--http2-stream-weight 256 --http2-stream-exclusive 1`, pseudo-headers `masp`.
/// Edge leaves out `SETTINGS_ENABLE_PUSH`, which Chrome sends.
pub(crate) const EDGE101_H2: H2Fingerprint = H2Fingerprint {
    header_table_size: Some(65_536),
    max_concurrent_streams: Some(1000),
    initial_window_size: 6_291_456,
    max_frame_size: None,
    max_header_list_size: Some(262_144),
    enable_push: None,
    enable_connect_protocol: None,
    no_rfc7540_priorities: None,
    settings_order: &[],
    connection_window: 15_663_105 + 65_535,
    pseudo_order: PseudoOrder::MethodAuthoritySchemePath,
    priority: Some((256, true)),
};

/// `2:0;3:100;4:2097152;8:1;9:1`, window 10420225,
/// `--http2-pseudo-headers-order "msap" --http2-stream-weight 256
/// --http2-stream-exclusive 0`.
///
/// Safari 18.0, whose preface announces the extended CONNECT protocol (`8:1`)
/// and `SETTINGS_NO_RFC7540_PRIORITIES` (`9:1`) — the two settings the wrapper
/// names and the fork's own capture of Safari 18.0 records. Its iOS sibling
/// sends `9:1` alone ([`SAFARI184_IOS_H2`]), and Safari 26.0 sends the same
/// nine-only list with no request priority ([`SAFARI260_H2`]).
pub(crate) const SAFARI18_H2: H2Fingerprint = H2Fingerprint {
    header_table_size: None,
    max_concurrent_streams: Some(100),
    initial_window_size: 2_097_152,
    max_frame_size: None,
    max_header_list_size: None,
    enable_push: Some(false),
    enable_connect_protocol: Some(true),
    no_rfc7540_priorities: Some(true),
    settings_order: &[],
    connection_window: 10_420_225 + 65_535,
    pseudo_order: PseudoOrder::MethodSchemeAuthorityPath,
    priority: Some((256, false)),
};

/// `2:0;3:100;4:2097152;9:1`, window 10420225,
/// `--http2-pseudo-headers-order "msap" --http2-stream-weight 256
/// --http2-stream-exclusive 0`.
///
/// Safari 18.4 on iOS: the same preface as 18.0 macOS minus
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL`. `curl_safari184_ios` names the same list
/// (its `--http2-settings` carries an empty entry where `8:1` would be, which
/// nghttp2 drops), and the fork's capture of Safari 18.4 on iOS records
/// `2:0;3:100;4:2097152;9:1` for the browser itself — so the iOS build sends no
/// extended-CONNECT setting, and the wrapper's stray separator is not a typo
/// that changes the shape.
pub(crate) const SAFARI184_IOS_H2: H2Fingerprint = H2Fingerprint {
    header_table_size: None,
    max_concurrent_streams: Some(100),
    initial_window_size: 2_097_152,
    max_frame_size: None,
    max_header_list_size: None,
    enable_push: Some(false),
    enable_connect_protocol: None,
    no_rfc7540_priorities: Some(true),
    settings_order: &[],
    connection_window: 10_420_225 + 65_535,
    pseudo_order: PseudoOrder::MethodSchemeAuthorityPath,
    priority: Some((256, false)),
};

/// `2:0;3:100;4:2097152;9:1`, window 10420225,
/// `--http2-pseudo-headers-order "msap" --http2-no-priority`.
///
/// Safari 26.0, on macOS and iOS alike, and the first preface here with no
/// PRIORITY flag on the request at all: the wrapper passes
/// `--http2-no-priority`, so there is no weight and no exclusivity to send —
/// which is a difference `peetprint` reads and the akamai fingerprint does not.
pub(crate) const SAFARI260_H2: H2Fingerprint = H2Fingerprint {
    header_table_size: None,
    max_concurrent_streams: Some(100),
    initial_window_size: 2_097_152,
    max_frame_size: None,
    max_header_list_size: None,
    enable_push: Some(false),
    enable_connect_protocol: None,
    no_rfc7540_priorities: Some(true),
    settings_order: &[],
    connection_window: 10_420_225 + 65_535,
    pseudo_order: PseudoOrder::MethodSchemeAuthorityPath,
    priority: None,
};

/// `2:0;4:4194304;3:100`, window 10485760,
/// `--http2-stream-weight 255 --http2-stream-exclusive 0`,
/// `--http2-pseudo-headers-order "mspa"`.
///
/// Safari 17.0 and 17.2 on iOS: [`SAFARI_H2`]'s list with
/// `SETTINGS_ENABLE_PUSH = 0` ahead of it, which is the first Safari preface
/// here that names `2` first — `settings_order` carries that (`[2, 4, 3]`, and
/// the frozen ids are `ENABLE_PUSH`, `INITIAL_WINDOW_SIZE`,
/// `MAX_CONCURRENT_STREAMS`). Its iOS sibling sends a 2 MiB stream window
/// ([`SAFARI172_IOS_H2`]); everything else is 15.5's.
pub(crate) const SAFARI170_H2: H2Fingerprint = H2Fingerprint {
    header_table_size: None,
    max_concurrent_streams: Some(100),
    initial_window_size: 4_194_304,
    max_frame_size: None,
    max_header_list_size: None,
    enable_push: Some(false),
    enable_connect_protocol: None,
    no_rfc7540_priorities: None,
    settings_order: &[2, 4, 3],
    connection_window: 10_485_760 + 65_535,
    pseudo_order: PseudoOrder::MethodSchemePathAuthority,
    priority: Some((255, false)),
};

/// `2:0;4:2097152;3:100`, window 10485760,
/// `--http2-stream-weight 255 --http2-stream-exclusive 0`,
/// `--http2-pseudo-headers-order "mspa"`.
///
/// Safari 17.2 on iOS: the same preface as 17.0 with a 2 MiB initial stream
/// window, which is what the phone's build of Safari names.
pub(crate) const SAFARI172_IOS_H2: H2Fingerprint = H2Fingerprint {
    header_table_size: None,
    max_concurrent_streams: Some(100),
    initial_window_size: 2_097_152,
    max_frame_size: None,
    max_header_list_size: None,
    enable_push: Some(false),
    enable_connect_protocol: None,
    no_rfc7540_priorities: None,
    settings_order: &[2, 4, 3],
    connection_window: 10_485_760 + 65_535,
    pseudo_order: PseudoOrder::MethodSchemePathAuthority,
    priority: Some((255, false)),
};

/// `1:65536;2:0;3:1000;4:6291456;6:262144`, window 15663105,
/// `--http2-stream-weight 256 --http2-stream-exclusive 1`, pseudo-headers `masp`.
pub(crate) const CHROME_H2: H2Fingerprint = H2Fingerprint {
    header_table_size: Some(65_536),
    max_concurrent_streams: Some(1000),
    initial_window_size: 6_291_456,
    max_frame_size: None,
    max_header_list_size: Some(262_144),
    enable_push: Some(false),
    enable_connect_protocol: None,
    no_rfc7540_priorities: None,
    settings_order: &[],
    connection_window: 15_663_105 + 65_535,
    pseudo_order: PseudoOrder::MethodAuthoritySchemePath,
    priority: Some((256, true)),
};

/// `1:65536;2:0;4:131072;5:16384`, window 12517377,
/// `--http2-stream-weight 42 --http2-stream-exclusive 0`,
/// `--http2-pseudo-headers-order "mpas"`.
pub(crate) const FIREFOX_H2: H2Fingerprint = H2Fingerprint {
    header_table_size: Some(65_536),
    max_concurrent_streams: None,
    initial_window_size: 131_072,
    max_frame_size: Some(16_384),
    max_header_list_size: None,
    enable_push: Some(false),
    enable_connect_protocol: None,
    no_rfc7540_priorities: None,
    settings_order: &[],
    connection_window: 12_517_377 + 65_535,
    pseudo_order: PseudoOrder::MethodPathAuthorityScheme,
    priority: Some((42, false)),
};

/// `3:100;4:4194304`, window 10485760,
/// `--http2-stream-weight 255 --http2-stream-exclusive 0`,
/// `--http2-pseudo-headers-order "mspa"`.
pub(crate) const SAFARI_H2: H2Fingerprint = H2Fingerprint {
    header_table_size: None,
    max_concurrent_streams: Some(100),
    initial_window_size: 4_194_304,
    max_frame_size: None,
    max_header_list_size: None,
    enable_push: None,
    enable_connect_protocol: None,
    no_rfc7540_priorities: None,
    settings_order: &[4, 3],
    connection_window: 10_485_760 + 65_535,
    pseudo_order: PseudoOrder::MethodSchemePathAuthority,
    priority: Some((255, false)),
};
