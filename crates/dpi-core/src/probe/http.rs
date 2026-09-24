//! HTTP over an established connection, in whichever protocol ALPN negotiated.
//!
//! Fingerprint profiles advertise `h2, http/1.1` (that is what Chrome, Safari
//! and Firefox offer), so every server that speaks HTTP/2 selects it. A probe
//! that then started an HTTP/1.1 client would fail on every h2-capable site and
//! report the mismatch as censorship, so the probes speak both: one enum over
//! hyper's two client connections, and a request builder that drops the headers
//! HTTP/2 forbids so a call site describes one request instead of two.
//!
//! A probe also presents the profile's HTTP identity — its `User-Agent` and
//! header set ([`crate::net::fingerprint::http_identity`]) and its HTTP/2 preface
//! (`h2_fingerprint`),
//! both taken from the `curl-impersonate` wrapper the ClientHello is pinned to.
//! The request itself comes from the call site: which headers a test sends is a
//! property of the test, the profile only decides what the client looks like.
//!
//! `check_http` is the whole HTTP phase — the request, the status and redirect
//! judgement, the body read and the verdicts they produce — so tests 2 and 6 send
//! the same thing and mean the same status when they report one.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::ext::HeaderCaseMap;
use hyper::header::{HeaderName, HeaderValue, HOST};
use hyper::http::request::Builder;
use hyper::{Method, Request, Response, Uri, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use tokio::time::timeout;

use crate::classify::{
    classify_connect_error_full, classify_ssl_error, ConnectionStage, Detail, DpiProbeStream,
    DpiStatus, ProbeStage,
};
use crate::config::AppConfig;
use h2::client::RequestShape;

use crate::net::fingerprint::{h2_fingerprint, http_identity, HttpIdentity, TlsFingerprint};

/// Message plus the OS code and kind of the `io::Error` at the end of a hyper
/// error chain.
///
/// The trailing `io::Error` is the only element that carries the OS code, and
/// Windows localizes its message, so the code — not the text — is the signal the
/// classifier can rely on when it has to tell a reset from an abort.
pub(crate) fn hyper_err_info(e: &hyper::Error) -> (String, Option<i32>, Option<std::io::ErrorKind>) {
    let mut msg = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        if let Some(io_err) = s.downcast_ref::<std::io::Error>() {
            msg.push_str(&format!(" | {}", io_err));
            return (msg, io_err.raw_os_error(), Some(io_err.kind()));
        }
        source = std::error::Error::source(s);
    }
    (msg, None, None)
}

/// A request both protocols can carry.
///
/// `host` is the SNI name: the `Host` header in HTTP/1.1, the `:authority`
/// pseudo-header (taken from the URI) in HTTP/2. The helper is only ever handed
/// a connection that is already TLS, so the HTTP/2 form is `https://`.
///
/// `headers` is the complete, ordered list — `user-agent` included, in the
/// position the impersonated client puts it ([`HttpIdentity::headers`] plus
/// whatever the test needs).
pub struct HttpRequest<'a> {
    pub method: Method,
    pub host: &'a str,
    pub path: &'a str,
    /// Sent in this order, minus the connection-specific ones HTTP/2 rejects.
    ///
    /// Every value but a test's own extras is a constant the profile carries or
    /// a borrow of the configured `USER_AGENT`, so the list is a `Cow` per value
    /// and a request copies nothing it did not build.
    pub headers: Vec<(&'a str, Cow<'a, str>)>,
    /// Whether the client the profile copies sends `priority` over HTTP/1.1 as
    /// well ([`HttpIdentity::priority_on_h1`]); HTTP/2 always carries it.
    pub priority_on_h1: bool,
}

/// The headers a probe sends: the profile's identity followed by the extras the
/// test needs (`Connection`, `X-Pad`), so every call site builds one list.
///
/// `identity_encoding` replaces the profile's `accept-encoding` with `identity`
/// *in place* — same header, same position, same byte count — for the probes
/// that count the bytes a connection carries before it is cut. A negotiated
/// `Content-Encoding` would make those numbers depend on how well the response
/// compresses; the fingerprint tests send what the impersonated client sends.
///
/// The list borrows its constants: the profile's header set and the configured
/// `USER_AGENT` are the same bytes on every request, and only the extras arrive
/// owned (`Cow::Owned`), so a probe that sends ten identity headers allocates
/// nothing for them.
pub fn request_headers<'a>(
    identity: &HttpIdentity,
    user_agent: &'a str,
    extras: impl IntoIterator<Item = (&'a str, Cow<'a, str>)>,
    identity_encoding: bool,
) -> Vec<(&'a str, Cow<'a, str>)> {
    let mut headers: Vec<(&'a str, Cow<'a, str>)> = identity
        .headers
        .iter()
        .map(|(name, value)| {
            // The profile's own UA comes from the identity; everything else is a
            // constant. `name` is `&'static str`, which outlives `'a`.
            let value = if name.eq_ignore_ascii_case("user-agent") {
                Cow::Borrowed(user_agent)
            } else {
                Cow::Borrowed(*value)
            };
            (*name, value)
        })
        .collect();
    if identity_encoding {
        for (name, value) in &mut headers {
            if name.eq_ignore_ascii_case("accept-encoding") {
                *value = Cow::Borrowed("identity");
            }
        }
    }
    headers.extend(extras);
    headers
}

/// A hyper sender for whichever protocol the connection agreed on.
///
/// Opaque on purpose: the HTTP/2 arm carries the request shape its profile
/// pinned (pseudo-header order and whether a request's `HEADERS` frame takes the
/// PRIORITY flag), and that shape is [`RequestShape`] — a type the patched `h2`
/// adds (`vendor/h2/README-PATCH.md`) and no published `h2` has. A caller names
/// the sender and its methods, never the variant, so replacing the fork stays a
/// change inside this crate.
pub struct HttpSender(Sender);

/// The two client connections, one per protocol.
///
/// Private: both arms carry hyper's own `SendRequest`, and the h2 one carries
/// the fork-only request shape beside it.
enum Sender {
    H1(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    H2 {
        sender: hyper::client::conn::http2::SendRequest<Full<Bytes>>,
        shape: Option<RequestShape>,
    },
}

impl HttpSender {
    /// Runs the HTTP handshake over `io` and spawns the connection driver.
    ///
    /// `io` is a `TokioIo`-wrapped stream (hyper's own I/O traits), and
    /// `alpn_h2` must be what the TLS handshake negotiated — it is the only
    /// thing that decides which client to start. `fingerprint` tunes the HTTP/2
    /// preface and the shape of the requests on it: hyper's defaults are the
    /// baseline, a browser profile overrides them with the ones its ClientHello
    /// is pinned to.
    pub async fn handshake<T>(io: T, alpn_h2: bool, fingerprint: TlsFingerprint) -> hyper::Result<Self>
    where
        T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        if alpn_h2 {
            let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
            if let Some(h2) = h2_fingerprint(fingerprint) {
                builder
                    .header_table_size(h2.header_table_size)
                    .initial_stream_window_size(h2.initial_window_size)
                    .initial_connection_window_size(h2.connection_window)
                    .max_frame_size(h2.max_frame_size)
                    .max_header_list_size(h2.max_header_list_size)
                    .enable_push(h2.enable_push)
                    .enable_connect_protocol(h2.enable_connect_protocol)
                    .no_rfc7540_priorities(h2.no_rfc7540_priorities)
                    .settings_order(h2.settings_order.iter().copied())
                    .max_concurrent_streams(h2.max_concurrent_streams);
            }
            let (sender, connection) = builder.handshake(io).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let shape = h2_fingerprint(fingerprint).map(|h2| RequestShape {
                pseudo_order: h2.pseudo_order,
                priority: h2.priority,
            });
            Ok(Self(Sender::H2 { sender, shape }))
        } else {
            let (sender, connection) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(Self(Sender::H1(sender)))
        }
    }

    /// True when the connection speaks HTTP/2.
    pub fn is_h2(&self) -> bool {
        matches!(self.0, Sender::H2 { .. })
    }

    /// True once the peer closed the connection or the driver stopped.
    pub fn is_closed(&self) -> bool {
        match &self.0 {
            Sender::H1(sender) => sender.is_closed(),
            Sender::H2 { sender, .. } => sender.is_closed(),
        }
    }

    /// Sends one request, built for the protocol in use.
    ///
    /// A request the builder refuses falls back instead of aborting: an h1 one
    /// to `build_request_lenient`, an h2 one to a request the layer itself
    /// rejects (`rejected_h2_request`). `send` also serves callers that do not
    /// validate their identity first, and under `panic = "abort"` an `expect`
    /// here would kill the whole run.
    pub async fn send(&mut self, req: HttpRequest<'_>) -> hyper::Result<Response<Incoming>> {
        match &mut self.0 {
            Sender::H1(sender) => {
                let request =
                    build_request(&req, false).unwrap_or_else(|_| build_request_lenient(&req));
                sender.send_request(request).await
            }
            Sender::H2 { sender, shape } => {
                let mut request = build_request(&req, true).unwrap_or_else(|_| rejected_h2_request());
                if let Some(shape) = *shape {
                    request.extensions_mut().insert(shape);
                }
                sender.send_request(request).await
            }
        }
    }
}

/// Builds the wire request for one of the two protocols.
///
/// The shape an h2 profile pinned is attached by [`HttpSender::send`], which is
/// where the protocol is known; the h1 header casing is attached here, because
/// it is a property of the message.
///
/// Returns the error `http` reports for a value it will not put on the wire. Not
/// every value is a constant: the user-agent comes from `config.yml` verbatim
/// (`config.rs::user_agent_for`), and a `USER_AGENT: |` block scalar leaves a
/// trailing newline that `http` rejects. That used to reach an `expect` here,
/// which under `panic = "abort"` killed the process; `check_http` now reports it
/// as a run error before this point, and [`HttpSender::send`] falls back for the
/// callers that do not validate first ([`build_request_lenient`] for h1,
/// [`rejected_h2_request`] for h2).
fn build_request(req: &HttpRequest<'_>, h2: bool) -> Result<Request<Full<Bytes>>, hyper::http::Error> {
    let case_map = (!h2).then(|| header_case_map(req));
    let mut builder = Request::builder().method(req.method.clone());
    if h2 {
        builder = builder.uri(format!("https://{}{}", req.host, req.path));
    } else {
        builder = builder.uri(req.path).header(HOST, req.host);
    }
    builder = add_headers(builder, req, h2, false)?;
    let mut request = builder.body(Full::new(Bytes::new()))?;
    if let Some(case_map) = case_map {
        request.extensions_mut().insert(case_map);
    }
    Ok(request)
}

/// [`build_request`] with every value `http` refuses dropped.
///
/// This is the h1 request form the strict build already produces, so the two
/// describe the same message; [`HttpSender::send`] falls back to it so that a
/// value it did not validate itself cannot abort the process.
fn build_request_lenient(req: &HttpRequest<'_>) -> Request<Full<Bytes>> {
    let uri = Uri::try_from(req.path).unwrap_or_else(|_| Uri::from_static("/"));
    let mut builder = Request::builder().method(req.method.clone()).uri(uri);
    if let Ok(host) = HeaderValue::from_str(req.host) {
        builder = builder.header(HOST, host);
    }
    // Every header value is validated before it is added, so the builder has
    // nothing left to refuse; `body` reports a `Result` only because the API
    // does. The floor is unreachable, not a fallback in use.
    let mut request = add_headers(builder, req, false, true)
        .and_then(|builder| builder.body(Full::new(Bytes::new())))
        .unwrap_or_else(|_| Request::new(Full::new(Bytes::new())));
    request.extensions_mut().insert(header_case_map(req));
    request
}

/// A request the h2 layer refuses before anything reaches the wire.
///
/// An h2 request's `:authority` comes from its URI alone (the h2 client builds
/// the pseudo-header from the URI, `vendor/h2/src/frame/headers.rs`), so a host
/// `http` will not take as one has no equivalent request to fall back to.
/// Handing the layer a request with no scheme or authority makes it report
/// `MissingUriSchemeAndAuthority`, which [`HttpSender::send`] returns the way it
/// returns every other send failure — instead of aborting the process under
/// `panic = "abort"`.
fn rejected_h2_request() -> Request<Full<Bytes>> {
    let mut request = Request::new(Full::new(Bytes::new()));
    *request.version_mut() = Version::HTTP_2;
    request
}

/// The request's headers in the order the identity carries them, minus the ones
/// the protocol rejects and with `te` normalized for h2. A value `http` will not
/// take is an error, or — with `drop_invalid` — skipped.
fn add_headers(
    mut builder: Builder,
    req: &HttpRequest<'_>,
    h2: bool,
    drop_invalid: bool,
) -> Result<Builder, hyper::http::Error> {
    for (name, value) in &req.headers {
        if h2 && is_connection_specific(name) {
            continue;
        }
        // `Priority` is an h2-only header for the clients curl puts it there
        // for and an ordinary one for the Firefox family and Tor, which send it
        // over h1 as well — the profile carries the measurement
        // (`TlsShape::priority_on_h1`, taken from the bundle's own h1 request).
        if !h2 && !req.priority_on_h1 && name.eq_ignore_ascii_case("priority") {
            continue;
        }
        // RFC 9113 §8.2.2 allows `TE` on an h2 request with `trailers` as its
        // only value, and curl normalizes the wrapper's `TE: Trailers` for h2 as
        // well: the bundle's own request has `te: trailers` there and
        // `TE: Trailers` over h1. hyper drops the header rather than rewriting
        // it, so the h2 spelling is ours to make.
        if h2 && name.eq_ignore_ascii_case("te") {
            builder = builder.header(*name, "trailers");
            continue;
        }
        if drop_invalid {
            if let Ok(value) = HeaderValue::from_str(value.as_ref()) {
                builder = builder.header(*name, value);
            }
            continue;
        }
        builder = builder.header(*name, value.as_ref());
    }
    Ok(builder)
}

/// The spellings an identity writes its header names with, for hyper's h1
/// encoder.
///
/// `http::HeaderName` is lowercase, so a request built from a `HeaderMap` goes
/// out lowercased — and no browser writes `Sec-Fetch-Site`, `TE` or `Accept-
/// Encoding` that way over HTTP/1.1. hyper's encoder writes the spelling this
/// map holds for a name (and the lowercase name for one it does not mention), so
/// every spelling the identity carries is recorded, `Host` included: the builder
/// adds that one, not the profile, and curl capitalizes it.
///
/// HTTP/2 needs none of this: RFC 9113 §8.2.1 requires lowercase field names,
/// and the h2 encoder writes them lowercased whatever this map says.
fn header_case_map(req: &HttpRequest<'_>) -> HeaderCaseMap {
    let mut map = HeaderCaseMap::default();
    map.append(HOST, Bytes::from_static(b"Host"));
    for (name, _) in &req.headers {
        // `HeaderName::from_bytes` lowercases the key the encoder looks up; the
        // bytes recorded beside it are the spelling the client writes.
        if let Ok(key) = HeaderName::from_bytes(name.as_bytes()) {
            map.append(key, Bytes::copy_from_slice(name.as_bytes()));
        }
    }
    map
}

/// The headers RFC 7540 §8.1.2.2 forbids on an HTTP/2 request: sending one is a
/// protocol error, and `keep-alive` semantics are implied by the connection.
fn is_connection_specific(name: &str) -> bool {
    const FORBIDDEN: [&str; 5] = ["connection", "host", "keep-alive", "transfer-encoding", "upgrade"];
    FORBIDDEN.iter().any(|forbidden| name.eq_ignore_ascii_case(forbidden))
}

/// The protocol a TLS stream negotiated, as the flag [`HttpSender::handshake`]
/// wants.
pub(crate) fn negotiated_h2<S>(tls: &tokio_rustls::client::TlsStream<S>) -> bool {
    tls.get_ref().1.alpn_protocol() == Some(b"h2")
}

const BODY_CAP: usize = 64 * 1024;

fn strip_www(host: &str) -> &str {
    host.strip_prefix("www.").unwrap_or(host)
}

/// Redirects that are expected rather than suspicious: the host that was asked
/// for and the host the site sends the browser to, both lower-case and with a
/// leading `www.` dropped (`strip_www` runs before the lookup, so
/// `www.messenger.com` → `www.facebook.com` is the pair below).
///
/// The site-family rule in [`site_of`] reads each pair's two hosts as different
/// sites, so a redirect between them lands on `RedirSuspect` — the red `REDIR` —
/// and this is the list where such a redirect is declared the site's own
/// behaviour instead. It grows by one line per pair; the direction matters, and
/// a host that is not in the list keeps the default verdict.
///
/// Both entries are Meta's own sign-in hop, measured on the live sites: the two
/// names answer `301` to `https://www.facebook.com/` and nothing else, so the
/// row reads `OK` with the target named. A hop between the two of them
/// (`www.instagram.com` → `www.messenger.com`) is not a pair and stays `REDIR`.
const REDIRECT_EXCEPTIONS: &[(&str, &str)] = &[
    ("messenger.com", "facebook.com"),
    ("instagram.com", "facebook.com"),
];

/// True when `from` → `to` is a declared exception in [`REDIRECT_EXCEPTIONS`].
fn is_expected_redirect(from: &str, to: &str) -> bool {
    REDIRECT_EXCEPTIONS.iter().any(|(known_from, known_to)| *known_from == from && *known_to == to)
}

pub(crate) fn parse_host(url_or_host: &str) -> String {
    let mut s = url_or_host.trim().to_ascii_lowercase();
    if let Some(idx) = s.find("://") {
        s = s[idx + 3..].to_string();
    }
    if let Some(idx) = s.find(['/', '?', '#']) {
        s = s[..idx].to_string();
    }
    // Strip :port (but not bare IPv6)
    if s.matches(':').count() == 1 {
        if let Some(idx) = s.rfind(':') {
            let port = &s[idx + 1..];
            if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
                s = s[..idx].to_string();
            }
        }
    }
    s.trim_matches(|c| c == '.' || c == '[' || c == ']').to_string()
}

/// Resolves a `Location` against the probe's base URL the way RFC 3986 relative
/// reference resolution does for the shapes a redirect uses, so the redirect
/// is judged against the host it really goes to:
///   `https://host/x`  - absolute, used as is;
///   `//host/x`        - protocol-relative: scheme from the base, host from the
///                       Location (a foreign host here is NOT a local path);
///   `/x`, `x`, `?q`   - relative: stays on the base scheme and host.
fn resolve_location(base: &str, location: &str) -> String {
    let scheme = base.split("://").next().unwrap_or("https");
    if location.contains("://") {
        return location.to_string();
    }
    if let Some(rest) = location.strip_prefix("//") {
        return format!("{}://{}", scheme, rest);
    }
    let host = parse_host(base);
    if location.starts_with('/') {
        format!("{}://{}{}", scheme, host, location)
    } else {
        format!("{}://{}/{}", scheme, host, location)
    }
}

/// The site a host belongs to when it is a subdomain of one: `m.youtube.com` →
/// `youtube.com`. A two-label host returns `None` — its parent is a TLD, and
/// treating `com` as a site would make every `.com` host the same site.
///
/// The rule is label arithmetic, not a public-suffix lookup, so parents whose
/// labels belong to different owners (`user1.github.io` and `user2.github.io`)
/// are read as one site. That is the price of not carrying a suffix list, and it
/// errs towards "this redirect stays on the site it came from".
fn site_of(host: &str) -> Option<&str> {
    let (_, rest) = host.split_once('.')?;
    rest.contains('.').then_some(rest)
}

/// Classifies a redirect by host: the same site family → OK (in the HTTP phase a
/// same-host hop to https reads `301 → https`, elsewhere `→ https`), a foreign
/// host → REDIR with the host it named.
///
/// "Same family" is any of three things, with a leading `www.` ignored on both
/// sides:
/// * the same name (`holod.media` → `www.holod.media`);
/// * one a subdomain of the other (`m.holod.media` → `holod.media`);
/// * two subdomains of the same site (`m.youtube.com` → `www.youtube.com`) —
///   the site is the host minus its first label, see [`site_of`].
///
/// Everything else counts as foreign, so `youtube.com` → `example.com` stays a
/// red REDIR — and so does `a.example.com` → `b.other.com`, which are two sites
/// under different parents. A pair listed in [`REDIRECT_EXCEPTIONS`] is the one
/// way a foreign hop comes out `OK`.
pub(crate) fn classify_redirect(
    domain: &str,
    base_url: &str,
    status: u16,
    location: &str,
    http_phase: bool,
) -> (DpiStatus, Detail) {
    let resolved = resolve_location(base_url, location);

    let loc_host_raw = parse_host(&resolved);
    let loc_host = loc_host_raw.to_ascii_lowercase();
    let scheme_https = resolved.to_ascii_lowercase().starts_with("https");
    let norm_loc = strip_www(&loc_host).to_string();
    let norm_dom = strip_www(&domain.to_ascii_lowercase()).to_string();
    let site_loc = site_of(&norm_loc);
    let same_site = norm_loc == norm_dom
        || norm_loc.ends_with(&format!(".{}", norm_dom))
        || norm_dom.ends_with(&format!(".{}", norm_loc))
        || (site_loc.is_some() && site_loc == site_of(&norm_dom));
    let short_host: String = loc_host.chars().take(30).collect();

    // A declared exception ([`REDIRECT_EXCEPTIONS`]) is the site's own redirect:
    // OK, and the detail still names the host the browser is sent to — the pair
    // is `(asked for, sent to)`, so `www.messenger.com` → `www.facebook.com`
    // reads as that redirect rather than as an upgrade on the same host.
    if is_expected_redirect(&norm_dom, &norm_loc) {
        return (DpiStatus::Ok, Detail::Redirect { host: short_host });
    }

    if http_phase {
        if same_site && scheme_https {
            return (DpiStatus::Ok, Detail::UpgradeHttps { status: Some(status) });
        }
        if same_site {
            // Same domain (or a subdomain) is a normal redirect: OK, not a badge
            // of its own. Only a foreign domain is flagged, as a red REDIR.
            return (DpiStatus::Ok, Detail::HttpStatus(status));
        }
        return (DpiStatus::RedirSuspect, Detail::Redirect { host: short_host });
    }

    if same_site && scheme_https {
        return (DpiStatus::Ok, Detail::UpgradeHttps { status: None });
    }
    if same_site {
        return (DpiStatus::Ok, Detail::Redirect { host: short_host });
    }
    (DpiStatus::RedirSuspect, Detail::Redirect { host: short_host })
}

/// The verdict for a read that died after `bytes` had already arrived.
///
/// Inside the fat window the badge is `16KB DROP` — the same one in every test but
/// the 16 KB test, which sends rather than reads and calls it `DETECTED` — and the
/// detail names the offset (`READ TIMEOUT at N KB`). Before the window opens it is
/// a plain read timeout that still says the offset, because where it died is the
/// useful part either way. One function for the h1 and h2 paths, which asked the
/// same question and used to answer it with two copies of the same eight lines.
pub(crate) fn fat_read_verdict(bytes: usize, min_kb: u64, max_kb: u64) -> (DpiStatus, Detail) {
    let kb = bytes as f64 / 1024.0;
    if kb >= min_kb as f64 && kb <= max_kb as f64 {
        return (
            DpiStatus::Tcp16Range,
            Detail::at_kb(Detail::ReadTimeoutWordCaps, kb),
        );
    }
    if bytes > 0 {
        return (
            DpiStatus::ReadTimeout,
            Detail::at_kb(Detail::ReadTimeoutWord, kb),
        );
    }
    (DpiStatus::ReadTimeout, Detail::at_kb(Detail::ReadTimeoutWordCaps, 0.0))
}

pub(crate) fn inner_hyper(
    e: &hyper::Error,
    stage: ProbeStage,
    bytes: usize,
    min_kb: u64,
    max_kb: u64,
) -> (DpiStatus, Detail) {
    let (msg, os_code, os_kind) = hyper_err_info(e);
    let lower = msg.to_ascii_lowercase();

    // Read timeout inside the fat window → the 16KB DROP badge, and the detail
    // names the offset the way the fat probe does: `READ TIMEOUT at N KB`. The
    // badge is the same in every test but test 3; the window is the detail's job.
    if (e.is_timeout() || lower.contains("timed out")) && stage == ProbeStage::ReadingData {
        return fat_read_verdict(bytes, min_kb, max_kb);
    }

    let (s, d) = classify_ssl_error(&msg, bytes, ConnectionStage::TlsClientHelloSent);
    if s != DpiStatus::Unknown {
        return (s, d);
    }
    classify_connect_error_full(&msg, os_code, os_kind, bytes, stage)
}

/// The HTTP phase of a probe: HTTP/2 or HTTP/1.1 by the ALPN the handshake
/// negotiated, `GET /` with the profile's identity, and a verdict from the
/// status, the redirect target and the body as it arrives.
///
/// Test 2 runs it once per TLS column, test 6 once per handshake it fires, so
/// both report the same status for the same server behaviour.
pub(crate) async fn check_http(
    tls_stream: tokio_rustls::client::TlsStream<DpiProbeStream<tokio::net::TcpStream>>,
    domain: &str,
    cfg: &AppConfig,
    fingerprint: TlsFingerprint,
    stage: &Arc<Mutex<ProbeStage>>,
    identity_encoding: bool,
) -> (DpiStatus, Detail, usize) {
        *stage.lock() = ProbeStage::TlsConnected;
        let alpn_h2 = negotiated_h2(&tls_stream);
        let io = TokioIo::new(tls_stream);
        let mut sender = match HttpSender::handshake(io, alpn_h2, fingerprint).await {
            Ok(sender) => sender,
            Err(e) => {
                let (s, d) = inner_hyper(&e, ProbeStage::TlsConnected, 0, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                return (s, d, 0usize);
            }
        };

        // GET with Host = domain, fresh socket per probe (Connection: close).
        // The headers are the profile's identity, so a probe that looks like
        // `curl_chrome107` at the TLS layer looks like it here too.
        let user_agent = cfg.user_agent_for(fingerprint);
        let identity = http_identity(fingerprint);
        let headers = request_headers(
            &identity,
            user_agent,
            [("Connection", "close".into())],
            identity_encoding,
        );
        // Every value but the user-agent is the profile's own constant, and the
        // user-agent comes from `config.yml` verbatim
        // (`config.rs::user_agent_for`): a `USER_AGENT: |` block scalar ends in a
        // newline, and `http` refuses to put a control byte on the wire. That is
        // a configuration error, not something the network did, so the probe
        // reports it instead of a verdict — and it never reaches the request
        // builder, where under `panic = "abort"` it would kill the run.
        if let Some((name, _)) = headers.iter().find(|(_, value)| HeaderValue::from_str(value.as_ref()).is_err()) {
            let detail = if name.eq_ignore_ascii_case("user-agent") {
                Detail::Other("invalid USER_AGENT in config.yml".to_string())
            } else {
                Detail::Other(format!("invalid {} header value", name))
            };
            return (DpiStatus::Err, detail, 0usize);
        }
        let req = HttpRequest {
            method: Method::GET,
            host: domain,
            path: "/",
            headers,
            priority_on_h1: identity.priority_on_h1,
        };

        *stage.lock() = ProbeStage::SendingData;
        let resp = match timeout(Duration::from_secs_f64(cfg.read_timeout), sender.send(req)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                // The stage the request went out under, read out of the guard:
                // `ProbeStage` is `Copy`, so nothing is cloned out of it.
                let st = *stage.lock();
                let (s, d) = inner_hyper(&e, st, 0, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                return (s, d, 0usize);
            }
            Err(_) => {
                return (DpiStatus::ReadTimeout, Detail::at_kb(Detail::ReadTimeoutWordCaps, 0.0), 0usize);
            }
        };

        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if status == 451 {
            return (DpiStatus::Blocked, Detail::HttpStatus(451), 0usize);
        }
        if !location.is_empty() && (300..400).contains(&status) {
            let (s, d) = classify_redirect(domain, &format!("https://{}", domain), status, &location, false);
            return (s, d, 0usize);
        }
        if (300..400).contains(&status) {
            // A 3xx with no Location points nowhere foreign: normal, like a
            // same-host redirect.
            return (DpiStatus::Ok, Detail::None, 0usize);
        }

        // Read body capped at 64 KB
        *stage.lock() = ProbeStage::ReadingData;
        let mut body = resp.into_body();
        let mut bytes_read: usize = 0;
        loop {
            match timeout(Duration::from_secs_f64(cfg.read_timeout), body.frame()).await {
                Ok(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        bytes_read += data.len();
                        if bytes_read >= BODY_CAP {
                            break;
                        }
                    }
                }
                Ok(Some(Err(e))) => {
                    let (s, d) = inner_hyper(&e, ProbeStage::ReadingData, bytes_read, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                    return (s, d, bytes_read);
                }
                Ok(None) => break,
                Err(_) => {
                    let (s, d) = fat_read_verdict(bytes_read, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                    return (s, d, bytes_read);
                }
            }
        }

        if (200..500).contains(&status) {
            (DpiStatus::Ok, Detail::None, bytes_read)
        } else {
            (DpiStatus::Ok, Detail::HttpStatus(status), bytes_read)
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A read that died inside the fat window is the `16KB DROP` badge with the
    /// offset in the detail (`READ TIMEOUT at N KB`); before the window opens the
    /// verdict is a plain read timeout that still names the offset, and a read that
    /// got nothing has no offset to name.
    #[test]
    fn a_read_cut_says_where_it_happened() {
        let (s, d) = fat_read_verdict(20 * 1024, 14, 36);
        assert_eq!(s, DpiStatus::Tcp16Range);
        assert_eq!(d.code(), "read_timeout_word_at_20kb");
        assert_eq!(s.display_label(), "16KB DROP");

        let (s, d) = fat_read_verdict(8 * 1024, 14, 36);
        assert_eq!(s, DpiStatus::ReadTimeout);
        assert_eq!(d.code(), "read_timeout_word_at_8kb");

        let (s, d) = fat_read_verdict(0, 14, 36);
        assert_eq!(s, DpiStatus::ReadTimeout);
        assert_eq!(d.code(), "read_timeout_word_at_0kb");
    }

    fn request() -> HttpRequest<'static> {
        HttpRequest {
            method: Method::GET,
            host: "example.com",
            path: "/x",
            headers: vec![
                ("user-agent", "ua".into()),
                ("accept-encoding", "identity".into()),
                ("connection", "close".into()),
            ],
            priority_on_h1: false,
        }
    }

    /// HTTP/2 takes the authority from the URI and rejects the headers HTTP/1.1
    /// needs, so the same request description has to produce two different ones.
    #[test]
    fn http2_builds_an_absolute_uri_and_drops_connection_headers() {
        let request = build_request(&request(), true).expect("the test request builds");
        assert_eq!(request.uri().to_string(), "https://example.com/x");
        assert_eq!(request.headers().get("accept-encoding").expect("kept"), "identity");
        assert!(request.headers().get("connection").is_none(), "HTTP/2 forbids Connection");
        assert!(request.headers().get(HOST).is_none(), "authority comes from the URI");
        assert_eq!(request.headers().get("user-agent").expect("ua"), "ua");
    }

    #[test]
    fn http1_keeps_the_path_host_and_connection_headers() {
        let request = build_request(&request(), false).expect("the test request builds");
        assert_eq!(request.uri().to_string(), "/x");
        assert_eq!(request.headers().get(HOST).expect("host"), "example.com");
        assert_eq!(request.headers().get("connection").expect("close"), "close");
    }

    /// The h1 request carries the spellings its identity writes, and the h2 one
    /// carries none: RFC 9113 lowercases every field name, so a case map on an
    /// h2 request would be dead weight. hyper reads the map from the request's
    /// extensions (`vendor/hyper/src/proto/h1/role.rs`, `Client::encode`).
    #[test]
    fn only_the_h1_request_carries_the_name_spellings() {
        let mut chrome = request();
        chrome.headers.push(("Sec-Fetch-Site", "none".into()));
        assert!(build_request(&chrome, false).expect("builds").extensions().get::<HeaderCaseMap>().is_some());
        let mut chrome = request();
        chrome.headers.push(("Sec-Fetch-Site", "none".into()));
        assert!(build_request(&chrome, true).expect("builds").extensions().get::<HeaderCaseMap>().is_none());
    }

    /// `priority` goes out on h1 only for a client that sends it there: the
    /// bundle's own h1 request carries it for Firefox and Tor and not for
    /// Chrome, Safari or Edge.
    #[test]
    fn priority_is_h1_only_for_the_clients_that_send_it_there() {
        let with_priority = |on_h1: bool| {
            let mut req = request();
            req.priority_on_h1 = on_h1;
            req.headers.push(("Priority", "u=0, i".into()));
            req
        };
        let kept = build_request(&with_priority(true), false).expect("builds");
        assert_eq!(kept.headers().get("priority").expect("kept on h1"), "u=0, i");
        let dropped = build_request(&with_priority(false), false).expect("builds");
        assert!(dropped.headers().get("priority").is_none(), "h2-only for this client");
        let h2 = build_request(&with_priority(false), true).expect("builds");
        assert_eq!(h2.headers().get("priority").expect("always on h2"), "u=0, i");
    }

    /// `TE` travels as the client writes it over h1 and as RFC 9113 §8.2.2
    /// allows over h2 — `trailers`, which is what curl puts there too; hyper
    /// drops the header rather than rewriting a value it cannot send.
    #[test]
    fn te_keeps_its_spelling_on_h1_and_normalizes_on_h2() {
        let with_te = || {
            let mut req = request();
            req.headers.push(("TE", "Trailers".into()));
            req
        };
        let h1 = build_request(&with_te(), false).expect("builds");
        assert_eq!(h1.headers().get("te").expect("kept"), "Trailers");
        let h2 = build_request(&with_te(), true).expect("builds");
        assert_eq!(h2.headers().get("te").expect("kept"), "trailers");
    }
}
