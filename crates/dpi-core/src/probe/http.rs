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
//! ([`h2_fingerprint`]),
//! both taken from the `curl-impersonate` wrapper the ClientHello is pinned to.
//! The request itself comes from the call site: which headers a test sends is a
//! property of the test, the profile only decides what the client looks like.
//!
//! [`check_http`] is the whole HTTP phase — the request, the status and redirect
//! judgement, the body read and the verdicts they produce — so tests 2 and 6 send
//! the same thing and mean the same status when they report one.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::HOST;
use hyper::{Method, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use tokio::time::timeout;

use crate::classify::{
    classify_connect_error_full, classify_ssl_error, ConnectionStage, Detail, DpiProbeStream, DpiStatus,
};
use crate::config::AppConfig;
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
    pub headers: Vec<(&'a str, String)>,
}

/// The headers a probe sends: the profile's identity followed by the extras the
/// test needs (`Connection`, `X-Pad`), so every call site builds one list.
pub fn request_headers<'a>(
    identity: &HttpIdentity,
    user_agent: &'a str,
    extras: impl IntoIterator<Item = (&'a str, String)>,
) -> Vec<(&'a str, String)> {
    let mut headers: Vec<(&'a str, String)> = identity
        .headers
        .iter()
        .map(|(name, value)| {
            // The profile's own UA comes from the identity; everything else is a
            // constant. `name` is `&'static str`, which outlives `'a`.
            let value = if name.eq_ignore_ascii_case("user-agent") {
                user_agent.to_string()
            } else {
                (*value).to_string()
            };
            (*name, value)
        })
        .collect();
    headers.extend(extras);
    headers
}

/// A hyper sender for whichever protocol the connection agreed on.
pub enum HttpSender {
    H1(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    H2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}

impl HttpSender {
    /// Runs the HTTP handshake over `io` and spawns the connection driver.
    ///
    /// `io` is a `TokioIo`-wrapped stream (hyper's own I/O traits), and
    /// `alpn_h2` must be what the TLS handshake negotiated — it is the only
    /// thing that decides which client to start. `fingerprint` only tunes the
    /// HTTP/2 preface: hyper's defaults are the baseline, a browser profile
    /// overrides them with the ones its ClientHello is pinned to.
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
                    // `enable_push(false)` is not exposed here: hyper sets it on
                    // every client, so `SETTINGS_ENABLE_PUSH = 0` is always sent.
                    .max_concurrent_streams(h2.max_concurrent_streams);
            }
            let (sender, connection) = builder.handshake(io).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(Self::H2(sender))
        } else {
            let (sender, connection) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(Self::H1(sender))
        }
    }

    /// True when the connection speaks HTTP/2.
    pub fn is_h2(&self) -> bool {
        matches!(self, Self::H2(_))
    }

    /// True once the peer closed the connection or the driver stopped.
    pub fn is_closed(&self) -> bool {
        match self {
            Self::H1(sender) => sender.is_closed(),
            Self::H2(sender) => sender.is_closed(),
        }
    }

    /// Sends one request, built for the protocol in use.
    pub async fn send(&mut self, req: HttpRequest<'_>) -> hyper::Result<Response<Incoming>> {
        let request = build_request(req, self.is_h2());
        match self {
            Self::H1(sender) => sender.send_request(request).await,
            Self::H2(sender) => sender.send_request(request).await,
        }
    }
}

/// Builds the wire request for one of the two protocols.
fn build_request(req: HttpRequest<'_>, h2: bool) -> Request<Full<Bytes>> {
    let mut builder = Request::builder().method(req.method);
    if h2 {
        builder = builder.uri(format!("https://{}{}", req.host, req.path));
    } else {
        builder = builder.uri(req.path).header(HOST, req.host);
    }
    for (name, value) in req.headers {
        if h2 && is_connection_specific(name) {
            continue;
        }
        builder = builder.header(name, value);
    }
    // Method, URI and every header above are already-validated constants and
    // caller strings, so the request cannot fail to build.
    builder.body(Full::new(Bytes::new())).expect("valid request")
}

/// The headers RFC 7540 §8.1.2.2 forbids on an HTTP/2 request: sending one is a
/// protocol error, and `keep-alive` semantics are implied by the connection.
fn is_connection_specific(name: &str) -> bool {
    const FORBIDDEN: [&str; 5] = ["connection", "host", "keep-alive", "transfer-encoding", "upgrade"];
    FORBIDDEN.iter().any(|forbidden| name.eq_ignore_ascii_case(forbidden))
}

/// The protocol a TLS stream negotiated, as the flag [`HttpSender::handshake`]
/// wants.
pub fn negotiated_h2<S>(tls: &tokio_rustls::client::TlsStream<S>) -> bool {
    tls.get_ref().1.alpn_protocol() == Some(b"h2")
}

const BODY_CAP: usize = 64 * 1024;

fn strip_www(host: &str) -> &str {
    host.strip_prefix("www.").unwrap_or(host)
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

/// Classifies a redirect by host: same host or subdomain → OK (in the HTTP phase a
/// same-host hop to https reads `301 → https`), a foreign host → REDIR with its short name.
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
    let same_host = norm_loc == norm_dom || norm_loc.ends_with(&format!(".{}", norm_dom));
    let short_host: String = loc_host.chars().take(30).collect();

    if http_phase {
        if same_host && scheme_https {
            return (DpiStatus::Ok, Detail::Other(format!("{} → https", status)));
        }
        if same_host {
            // Same domain (or a subdomain) is a normal redirect: OK, not a badge
            // of its own. Only a foreign domain is flagged, as a red REDIR.
            return (DpiStatus::Ok, Detail::HttpStatus(status));
        }
        return (DpiStatus::RedirSuspect, Detail::Other(format!("→ {}", short_host)));
    }

    if same_host && scheme_https {
        return (DpiStatus::Ok, Detail::Other("→ https".to_string()));
    }
    if same_host {
        return (DpiStatus::Ok, Detail::Other(format!("→ {}", short_host)));
    }
    (DpiStatus::RedirSuspect, Detail::Other(format!("→ {}", short_host)))
}

pub(crate) fn inner_hyper(
    e: &hyper::Error,
    stage: &str,
    bytes: usize,
    min_kb: u64,
    max_kb: u64,
) -> (DpiStatus, Detail) {
    let (msg, os_code, os_kind) = hyper_err_info(e);
    let lower = msg.to_ascii_lowercase();

    // Read timeout inside the fat window → TCP16-20 signature
    if (e.is_timeout() || lower.contains("timed out")) && stage == "reading_data" {
        let kb = bytes as f64 / 1024.0;
        if kb >= min_kb as f64 && kb <= max_kb as f64 {
            return (DpiStatus::Tcp16Range, Detail::Kb { head: Box::new(Detail::TimeoutWord), kb });
        }
        if bytes > 0 {
            return (DpiStatus::ReadTimeout, Detail::Kb { head: Box::new(Detail::ReadTimeoutWord), kb });
        }
        return (DpiStatus::ReadTimeout, Detail::ReadTimeoutWord);
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
    stage: &Arc<Mutex<String>>,
) -> (DpiStatus, Detail, usize) {
        *stage.lock() = "tls_connected".to_string();
        let alpn_h2 = negotiated_h2(&tls_stream);
        let io = TokioIo::new(tls_stream);
        let mut sender = match HttpSender::handshake(io, alpn_h2, fingerprint).await {
            Ok(sender) => sender,
            Err(e) => {
                let (s, d) = inner_hyper(&e, "tls_connected", 0, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                return (s, d, 0usize);
            }
        };

        // GET with Host = domain, fresh socket per probe (Connection: close).
        // The headers are the profile's identity, so a probe that looks like
        // `curl_chrome107` at the TLS layer looks like it here too.
        let user_agent = cfg.user_agent_for(fingerprint);
        let req = HttpRequest {
            method: Method::GET,
            host: domain,
            path: "/",
            headers: request_headers(
                &http_identity(fingerprint),
                user_agent,
                [("Connection", "close".to_string())],
            ),
        };

        *stage.lock() = "sending_data".to_string();
        let resp = match timeout(Duration::from_secs_f64(cfg.read_timeout), sender.send(req)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                let st = stage.lock().clone();
                let (s, d) = inner_hyper(&e, &st, 0, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                return (s, d, 0usize);
            }
            Err(_) => {
                return (DpiStatus::ReadTimeout, Detail::ReadTimeoutWord, 0usize);
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
        *stage.lock() = "reading_data".to_string();
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
                    let (s, d) = inner_hyper(&e, "reading_data", bytes_read, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                    return (s, d, bytes_read);
                }
                Ok(None) => break,
                Err(_) => {
                    let kb = bytes_read as f64 / 1024.0;
                    if kb >= cfg.tcp_block_min_kb as f64 && kb <= cfg.tcp_block_max_kb as f64 {
                        return (DpiStatus::Tcp16Range, Detail::Kb { head: Box::new(Detail::TimeoutWord), kb }, bytes_read);
                    }
                    if bytes_read > 0 {
                        return (DpiStatus::ReadTimeout, Detail::Kb { head: Box::new(Detail::ReadTimeoutWord), kb }, bytes_read);
                    }
                    return (DpiStatus::ReadTimeout, Detail::ReadTimeoutWord, bytes_read);
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

    fn request() -> HttpRequest<'static> {
        HttpRequest {
            method: Method::GET,
            host: "example.com",
            path: "/x",
            headers: vec![
                ("user-agent", "ua".to_string()),
                ("accept-encoding", "identity".to_string()),
                ("connection", "close".to_string()),
            ],
        }
    }

    /// HTTP/2 takes the authority from the URI and rejects the headers HTTP/1.1
    /// needs, so the same request description has to produce two different ones.
    #[test]
    fn http2_builds_an_absolute_uri_and_drops_connection_headers() {
        let request = build_request(request(), true);
        assert_eq!(request.uri().to_string(), "https://example.com/x");
        assert_eq!(request.headers().get("accept-encoding").expect("kept"), "identity");
        assert!(request.headers().get("connection").is_none(), "HTTP/2 forbids Connection");
        assert!(request.headers().get(HOST).is_none(), "authority comes from the URI");
        assert_eq!(request.headers().get("user-agent").expect("ua"), "ua");
    }

    #[test]
    fn http1_keeps_the_path_host_and_connection_headers() {
        let request = build_request(request(), false);
        assert_eq!(request.uri().to_string(), "/x");
        assert_eq!(request.headers().get(HOST).expect("host"), "example.com");
        assert_eq!(request.headers().get("connection").expect("close"), "close");
    }
}
