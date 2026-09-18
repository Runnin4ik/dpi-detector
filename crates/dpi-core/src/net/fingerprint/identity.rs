//! The HTTP identity of each profile: the `User-Agent` and the headers of the
//! client whose ClientHello the profile reproduces, in the order that client
//! sends them.
//!
//! One table per impersonated client, taken from the same
//! `curl-impersonate v2.2.2` wrapper the ClientHello is pinned to, so a probe
//! that looks like `curl_chrome107` at the TLS layer also looks like it at the
//! HTTP layer. One deviation, deliberate and opt-in:
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
        HttpIdentity { user_agent, headers }
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
    ("upgrade-insecure-requests", "1"),
    (
        "user-agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    ),
    (
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    ),
    ("sec-fetch-site", "none"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-user", "?1"),
    ("sec-fetch-dest", "document"),
    ("accept-encoding", "gzip, deflate, br, zstd"),
    ("accept-language", "en-US,en;q=0.9"),
    ("priority", "u=0, i"),
];

/// Edge 101 headers, in `curl_edge101.bat` order. Edge is Chromium with its own
/// `User-Agent`, `sec-ch-ua` and `sec-ch-ua-platform`; the TLS shape is Chrome's
/// (see `shapes::CHROME_TLS_*`), so the identity is what tells the two apart.
pub(crate) const EDGE101_HEADERS: &[(&str, &str)] = &[
    ("sec-ch-ua", r#"" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101""#),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", r#""Windows""#),
    ("upgrade-insecure-requests", "1"),
    (
        "user-agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47",
    ),
    (
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    ),
    ("sec-fetch-site", "none"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-user", "?1"),
    ("sec-fetch-dest", "document"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-language", "en-US,en;q=0.9"),
];

/// The baseline probes' own header set.
pub(crate) const RUSTLS_HEADERS: &[(&str, &str)] = &[("accept-encoding", "identity")];

/// Chrome 107 / Edge 99–101 headers, in `curl_chrome107.bat` order.
pub(crate) const CHROME_HEADERS: &[(&str, &str)] = &[
    ("sec-ch-ua", r#""Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24""#),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", r#""Windows""#),
    ("upgrade-insecure-requests", "1"),
    (
        "user-agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
    ),
    (
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    ),
    ("sec-fetch-site", "none"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-user", "?1"),
    ("sec-fetch-dest", "document"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-language", "en-US,en;q=0.9"),
];

/// Firefox 133 headers, in `curl_firefox133.bat` order.
pub(crate) const FIREFOX_HEADERS: &[(&str, &str)] = &[
    (
        "user-agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    ),
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("accept-language", "en-US,en;q=0.5"),
    ("accept-encoding", "gzip, deflate, br, zstd"),
    ("upgrade-insecure-requests", "1"),
    ("sec-fetch-dest", "document"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-site", "none"),
    ("sec-fetch-user", "?1"),
    ("priority", "u=0, i"),
    ("te", "trailers"),
];

/// Safari 15.5 headers, in `curl_safari155.bat` order.
pub(crate) const SAFARI_HEADERS: &[(&str, &str)] = &[
    (
        "user-agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
    ),
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("accept-language", "en-GB,en-US;q=0.9,en;q=0.8"),
    ("accept-encoding", "gzip, deflate, br"),
];
