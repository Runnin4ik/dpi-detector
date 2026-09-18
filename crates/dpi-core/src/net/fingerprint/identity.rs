//! The HTTP identity of each profile: the `User-Agent` and the headers of the
//! client whose ClientHello the profile reproduces, in the order that client
//! sends them.
//!
//! One table per impersonated client, taken from the same
//! `curl-impersonate v2.2.2` wrapper the ClientHello is pinned to, so a probe
//! that looks like `curl_chrome107` at the TLS layer also looks like it at the
//! HTTP layer. The **spelling** of each name is part of that: HTTP/2 lowercases
//! field names by rule (RFC 9113 §8.2.1), but over HTTP/1.1 the client writes
//! `Sec-Fetch-Site`, `TE` and `Accept-Encoding` in the case its `-H` list was
//! written in — which the bundles of Safari 18 and later write lowercase
//! throughout. [`header_case_map`](crate::probe::http) hands those spellings to
//! hyper's h1 encoder; the h2 encoder ignores them.
//!
//! One deviation, deliberate and opt-in:
//!
//! * the probes that count the bytes a connection carries before it is cut
//!   (tests 2–4: `read_timeout_at_24kb`, `tcp_block_min_kb`/`max_kb`) override
//!   `accept-encoding` to `identity`, because a negotiated `Content-Encoding`
//!   would make those numbers depend on how well the response happens to
//!   compress. [`request_headers`](crate::probe::http::request_headers) does the
//!   override per call; everything else, the fingerprint tests included, sends
//!   the `accept-encoding` the impersonated client sends.

use super::shapes::TlsShape;

/// The HTTP identity a profile presents.
#[derive(Debug, Clone, Copy)]
pub struct HttpIdentity {
    /// The UA of the impersonated client, `None` for the baseline profile.
    pub user_agent: Option<&'static str>,
    /// Headers in wire order, `user-agent` included where the impersonated
    /// client sends one. The call sites append their own tool-specific headers
    /// (`Connection`, `X-Pad`) after these.
    pub headers: &'static [(&'static str, &'static str)],
    /// Whether this client's `priority` header goes out over HTTP/1.1 too; see
    /// [`TlsShape::priority_on_h1`]. The h2 request always carries it.
    pub priority_on_h1: bool,
}

impl TlsShape {
    /// The identity this shape presents. The baseline hands back its own header
    /// set and no `User-Agent`: it is the control every earlier measurement was
    /// taken with, so it keeps exactly what those runs sent — the call sites add
    /// `Connection` and, for test 3/4, `X-Pad`.
    pub(crate) fn identity(&self) -> HttpIdentity {
        let headers = self.headers.unwrap_or(RUSTLS_HEADERS);
        // Read out of the list rather than named by index: the UA is part of the
        // header set, in its wire position, and an index would silently point at
        // a different header the day one is inserted above it.
        let user_agent = self
            .headers
            .and_then(|headers| headers.iter().find(|(name, _)| name.eq_ignore_ascii_case("user-agent")))
            .map(|(_, value)| *value);
        HttpIdentity { user_agent, headers, priority_on_h1: self.priority_on_h1 }
    }
}

/// The HTTP identity of `fingerprint`.
pub fn http_identity(fingerprint: super::TlsFingerprint) -> HttpIdentity {
    fingerprint.spec().identity()
}

/// Safari 18.0 headers, in `curl_safari180.bat` order.
pub(crate) const SAFARI18_HEADERS: &[(&str, &str)] = &[
    ("sec-fetch-dest", "document"),
    (
        "user-agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    ),
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("sec-fetch-site", "none"),
    ("sec-fetch-mode", "navigate"),
    ("accept-language", "en-US,en;q=0.9"),
    ("priority", "u=0, i"),
    ("accept-encoding", "gzip, deflate, br"),
];

/// Chrome 133 headers, in `curl_chrome133a.bat` order. Two headers Chrome 107
/// does not send: `accept-encoding` gained `zstd`, and `priority` is new. The
/// `accept` list ends in `q=0.7` where 107's ends in `q=0.9`.
pub(crate) const CHROME133_HEADERS: &[(&str, &str)] = &[
    ("sec-ch-ua", r#""Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133""#),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", r#""macOS""#),
    ("Upgrade-Insecure-Requests", "1"),
    (
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    ),
    (
        "Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    ),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-User", "?1"),
    ("Sec-Fetch-Dest", "document"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("priority", "u=0, i"),
];

/// Edge 101 headers, in `curl_edge101.bat` order. Edge is Chromium with its own
/// `User-Agent`, `sec-ch-ua` and `sec-ch-ua-platform`; the TLS shape is Chrome's
/// (see `shapes::CHROME_TLS_*`), so the identity is what tells the two apart.
pub(crate) const EDGE101_HEADERS: &[(&str, &str)] = &[
    ("sec-ch-ua", r#"" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101""#),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", r#""Windows""#),
    ("Upgrade-Insecure-Requests", "1"),
    (
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47",
    ),
    (
        "Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    ),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-User", "?1"),
    ("Sec-Fetch-Dest", "document"),
    ("Accept-Encoding", "gzip, deflate, br"),
    ("Accept-Language", "en-US,en;q=0.9"),
];

/// The baseline probes' own header set.
pub(crate) const RUSTLS_HEADERS: &[(&str, &str)] = &[("accept-encoding", "identity")];

/// Chrome 107 / Edge 99–101 headers, in `curl_chrome107.bat` order.
pub(crate) const CHROME_HEADERS: &[(&str, &str)] = &[
    ("sec-ch-ua", r#""Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24""#),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", r#""Windows""#),
    ("Upgrade-Insecure-Requests", "1"),
    (
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
    ),
    (
        "Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    ),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-User", "?1"),
    ("Sec-Fetch-Dest", "document"),
    ("Accept-Encoding", "gzip, deflate, br"),
    ("Accept-Language", "en-US,en;q=0.9"),
];

/// Firefox 133 headers, in `curl_firefox133.bat` order.
pub(crate) const FIREFOX_HEADERS: &[(&str, &str)] = &[
    (
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    ),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.5"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    ("Upgrade-Insecure-Requests", "1"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-User", "?1"),
    ("Priority", "u=0, i"),
    ("TE", "Trailers"),
];

/// Safari 15.5 headers, in `curl_safari155.bat` order.
pub(crate) const SAFARI_HEADERS: &[(&str, &str)] = &[
    (
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
    ),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("Accept-Language", "en-GB,en-US;q=0.9,en;q=0.8"),
    ("Accept-Encoding", "gzip, deflate, br"),
];

/// Safari 15.3 headers, in `curl_safari153.bat` order. The same set as 15.5's
/// with the version it names and `en-us` where 15.5 sends `en-GB,en-US;q=0.9,
/// en;q=0.8` — the wrapper's own list, not a normalised one.
pub(crate) const SAFARI153_HEADERS: &[(&str, &str)] = &[
    (
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15",
    ),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("Accept-Language", "en-us"),
    ("Accept-Encoding", "gzip, deflate, br"),
];

/// Chrome 99 on Android headers, in `curl_chrome99_android.bat` order: the
/// desktop 99 brand line (including its leading space), a Pixel 6 UA and
/// `sec-ch-ua-mobile: ?1`.
pub(crate) const CHROME99_ANDROID_HEADERS: &[(&str, &str)] = &[
    ("sec-ch-ua", r#"" Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99""#),
    ("sec-ch-ua-mobile", "?1"),
    ("sec-ch-ua-platform", r#""Android""#),
    ("Upgrade-Insecure-Requests", "1"),
    (
        "User-Agent",
        "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.58 Mobile Safari/537.36",
    ),
    (
        "Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    ),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-User", "?1"),
    ("Sec-Fetch-Dest", "document"),
    ("Accept-Encoding", "gzip, deflate, br"),
    ("Accept-Language", "en-US,en;q=0.9"),
];

/// Chrome 120 headers, in `curl_chrome120.bat` order. Two differences from
/// Chrome 133's below: `accept-encoding` has no `zstd` yet, and there is no
/// `priority` header — Chrome added both at 133, so a record that sent 133's
/// list under a 120 UA would be inconsistent in the packet a censor reads.
pub(crate) const CHROME120_HEADERS: &[(&str, &str)] = &[
    ("sec-ch-ua", r#""Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120""#),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", r#""macOS""#),
    ("Upgrade-Insecure-Requests", "1"),
    (
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ),
    (
        "Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    ),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-User", "?1"),
    ("Sec-Fetch-Dest", "document"),
    ("Accept-Encoding", "gzip, deflate, br"),
    ("Accept-Language", "en-US,en;q=0.9"),
];

/// Chrome 131 headers, in `curl_chrome131.bat` order: Chrome 133's set with the
/// version it names.
pub(crate) const CHROME131_HEADERS: &[(&str, &str)] = &[
    ("sec-ch-ua", r#""Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24""#),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", r#""macOS""#),
    ("Upgrade-Insecure-Requests", "1"),
    (
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    ),
    (
        "Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    ),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-User", "?1"),
    ("Sec-Fetch-Dest", "document"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("priority", "u=0, i"),
];

/// Chrome 131 on Android headers, in `curl_chrome131_android.bat` order. The
/// bundle's own capture reads `sec-ch-ua-mobile: ?0` with
/// `sec-ch-ua-platform: "Android"`, which is what the wrapper sends; the
/// fingerprint is what the bundle does, not what the browser would do.
pub(crate) const CHROME131_ANDROID_HEADERS: &[(&str, &str)] = &[
    ("sec-ch-ua", r#""Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24""#),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", r#""Android""#),
    ("Upgrade-Insecure-Requests", "1"),
    (
        "User-Agent",
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    ),
    (
        "Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    ),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-User", "?1"),
    ("Sec-Fetch-Dest", "document"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("priority", "u=0, i"),
];

/// Chrome 136 headers, in `curl_chrome136.bat` order: Chrome 133's set with the
/// 136 brand list (`"Chromium"` first, `"Not(A:Brand";v="99"` last) and UA.
pub(crate) const CHROME136_HEADERS: &[(&str, &str)] = &[
    ("sec-ch-ua", r#""Chromium";v="136", "Google Chrome";v="136", "Not(A:Brand";v="99""#),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", r#""macOS""#),
    ("Upgrade-Insecure-Requests", "1"),
    (
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    ),
    (
        "Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    ),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-User", "?1"),
    ("Sec-Fetch-Dest", "document"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("priority", "u=0, i"),
];

/// Firefox 135 headers, in `curl_firefox135.bat` order: Firefox 133's set with
/// the version it names.
pub(crate) const FIREFOX135_HEADERS: &[(&str, &str)] = &[
    (
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
    ),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.5"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    ("Upgrade-Insecure-Requests", "1"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-User", "?1"),
    ("Priority", "u=0, i"),
    ("TE", "Trailers"),
];

/// Firefox 144 headers. `curl_firefox144.bat` is `--impersonate firefox144`, so
/// the list comes from the bundle's own `firefox_144.0.0_linux` capture, which
/// is the same set with 144 in the UA. The `TE` spelling comes from that
/// request too: the bundle's built-in profile writes `Te`, where
/// `curl_firefox135` — and Firefox itself — writes `TE`.
pub(crate) const FIREFOX144_HEADERS: &[(&str, &str)] = &[
    (
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0",
    ),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.5"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    ("Upgrade-Insecure-Requests", "1"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-User", "?1"),
    ("Priority", "u=0, i"),
    ("Te", "trailers"),
];

/// Safari 18.4 on iOS headers, in `curl_safari184_ios.bat` order.
pub(crate) const SAFARI184_IOS_HEADERS: &[(&str, &str)] = &[
    ("sec-fetch-dest", "document"),
    (
        "user-agent",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
    ),
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("sec-fetch-site", "none"),
    ("sec-fetch-mode", "navigate"),
    ("accept-language", "en-US,en;q=0.9"),
    ("priority", "u=0, i"),
    ("accept-encoding", "gzip, deflate, br"),
];

/// Safari 26.0 headers, in `curl_safari260.bat` order: 18.x's set with the
/// version it names and `zstd` added to `accept-encoding`.
pub(crate) const SAFARI260_HEADERS: &[(&str, &str)] = &[
    ("sec-fetch-dest", "document"),
    (
        "user-agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
    ),
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("sec-fetch-site", "none"),
    ("sec-fetch-mode", "navigate"),
    ("accept-language", "en-US,en;q=0.9"),
    ("priority", "u=0, i"),
    ("accept-encoding", "gzip, deflate, br, zstd"),
];

/// Safari 26.0 on iOS headers, in `curl_safari260_ios.bat` order.
pub(crate) const SAFARI260_IOS_HEADERS: &[(&str, &str)] = &[
    ("sec-fetch-dest", "document"),
    (
        "user-agent",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
    ),
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("sec-fetch-site", "none"),
    ("sec-fetch-mode", "navigate"),
    ("accept-language", "en-US,en;q=0.9"),
    ("priority", "u=0, i"),
    ("accept-encoding", "gzip, deflate, br, zstd"),
];

/// Tor Browser 14.5 headers, in `curl_tor145.bat` order. The UA is Firefox 128
/// ESR's, which is the release Tor Browser 14.5 is built on; `Sec-GPC` is Tor's
/// own addition and `TE: trailers` the one Firefox sends too.
pub(crate) const TOR_HEADERS: &[(&str, &str)] = &[
    (
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
    ),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.5"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    ("Sec-GPC", "1"),
    ("Upgrade-Insecure-Requests", "1"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-User", "?1"),
    ("Priority", "u=0, i"),
    ("TE", "Trailers"),
];
