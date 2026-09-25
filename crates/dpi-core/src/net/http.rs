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
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use http2::frame::{
    PseudoId, PseudoOrder as ClientPseudoOrder, SettingId, SettingsOrder, StreamDependency,
    StreamId,
};
use http2::RecvStream;
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::ext::HeaderCaseMap;
use hyper::header::{HeaderName, HeaderValue, HOST};
use hyper::http::request::Builder;
use hyper::{Method, Request, Response, Uri, Version};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use tokio::time::timeout;

use crate::classify::{
    classify_connect_error_full, classify_ssl_error, ConnectionStage, Detail, DpiProbeStream,
    DpiStatus, ProbeStage,
};
use crate::config::AppConfig;

use crate::net::fingerprint::{
    h2_fingerprint, http_identity, H2Fingerprint, HttpIdentity, PseudoOrder, TlsFingerprint,
    BASELINE_H2,
};

/// The error a request died of.
///
/// A type of ours rather than either client's, so both crates stay inside this
/// module: the callers that only print it (`examples/tls_fingerprint.rs`) need
/// nothing more, and replacing a client again would not change them.
#[derive(Debug)]
pub struct HttpError(ErrorKind);

/// Which client raised the error. Private on purpose — the variants are two
/// other crates' types, and neither belongs in dpi-core's API.
#[derive(Debug)]
pub(crate) enum ErrorKind {
    /// HTTP/1.1, hyper's own error.
    H1(hyper::Error),
    /// HTTP/2, from the h2 client the probes drive directly.
    H2(http2::Error),
}

impl HttpError {
    /// Whether the client itself gave up on a deadline.
    pub(crate) fn is_timeout(&self) -> bool {
        match &self.0 {
            ErrorKind::H1(e) => e.is_timeout(),
            // The h2 client sets no read deadline of its own — every read in
            // this crate runs under `tokio::time::timeout` — so an `io` error is
            // the only thing left that can name one.
            ErrorKind::H2(e) => e
                .get_io()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::TimedOut),
        }
    }

    /// Whether the connection went away under the request, which the fat probe
    /// answers by opening a new one and sending the chunk again.
    pub(crate) fn is_canceled(&self) -> bool {
        match &self.0 {
            ErrorKind::H1(e) => e.is_canceled(),
            // The h2 client has no single "canceled" flag: a stream the peer
            // reset, a `GOAWAY`, and an `io` error that says the pipe is gone
            // are the same situation from here. A deadline of ours is not — it
            // is a verdict, and this is the retry question.
            ErrorKind::H2(e) => {
                e.is_reset()
                    || e.is_go_away()
                    || e.get_io()
                        .is_some_and(|io| io.kind() != std::io::ErrorKind::TimedOut)
            }
        }
    }
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            ErrorKind::H1(e) => e.fmt(f),
            ErrorKind::H2(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for HttpError {}

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

/// [`hyper_err_info`] for either protocol's error; the h2 client hands its `io`
/// error over directly instead of leaving it to a source chain.
pub(crate) fn http_err_info(e: &HttpError) -> (String, Option<i32>, Option<std::io::ErrorKind>) {
    match &e.0 {
        ErrorKind::H1(e) => hyper_err_info(e),
        ErrorKind::H2(e) => {
            let mut msg = e.to_string();
            match e.get_io() {
                Some(io_err) => {
                    msg.push_str(&format!(" | {}", io_err));
                    (msg, io_err.raw_os_error(), Some(io_err.kind()))
                }
                None => (msg, None, None),
            }
        }
    }
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

/// A sender over whichever protocol the connection agreed on.
///
/// Opaque on purpose: the two arms hold two different clients' request senders
/// (hyper's for HTTP/1.1, the h2 client's for HTTP/2), and a caller names the
/// sender and its methods, never a variant.
pub struct HttpSender(Sender);

/// The two client connections, one per protocol.
///
/// Private: each arm is another crate's `SendRequest`. The h2 one also holds the
/// flag its driver task sets when the connection ends — hyper's HTTP/1.1 sender
/// tracks that itself, the h2 client's does not.
enum Sender {
    H1(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    H2 {
        sender: http2::client::SendRequest<Bytes>,
        ended: Arc<AtomicBool>,
    },
}

impl HttpSender {
    /// Runs the HTTP handshake over `io` and spawns the connection driver.
    ///
    /// `io` is the established stream — for a probe that is the TLS stream over
    /// [`DpiProbeStream`], so the stages past the handshake are still this
    /// crate's — and `alpn_h2` must be what the TLS handshake negotiated: it is
    /// the only thing that decides which client starts. `fingerprint` pins the
    /// HTTP/2 preface and the shape of the requests on it; the baseline profile
    /// takes `BASELINE_H2`, which is what hyper's own h2 client sent.
    pub async fn handshake<T>(io: T, alpn_h2: bool, fingerprint: TlsFingerprint) -> Result<Self, HttpError>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        if alpn_h2 {
            let h2 = h2_fingerprint(fingerprint).unwrap_or(BASELINE_H2);
            let (sender, connection) = h2_builder(&h2)
                .handshake::<_, Bytes>(io)
                .await
                .map_err(|e| HttpError(ErrorKind::H2(e)))?;
            let ended = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&ended);
            tokio::spawn(async move {
                let _ = connection.await;
                flag.store(true, Ordering::Relaxed);
            });
            Ok(Self(Sender::H2 { sender, ended }))
        } else {
            let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
                .await
                .map_err(|e| HttpError(ErrorKind::H1(e)))?;
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
            Sender::H2 { ended, .. } => ended.load(Ordering::Relaxed),
        }
    }

    /// Sends one request, built for the protocol in use.
    ///
    /// A request the builder refuses falls back instead of aborting: an h1 one
    /// to `build_request_lenient`, an h2 one to a request the layer itself
    /// rejects (`rejected_h2_request`). `send` also serves callers that do not
    /// validate their identity first, and under `panic = "abort"` an `expect`
    /// here would kill the whole run.
    pub async fn send(&mut self, req: HttpRequest<'_>) -> Result<Response<HttpBody>, HttpError> {
        match &mut self.0 {
            Sender::H1(sender) => {
                let request =
                    build_request(&req, false).unwrap_or_else(|_| build_request_lenient(&req));
                let request = request.map(|()| Full::new(Bytes::new()));
                sender
                    .send_request(request)
                    .await
                    .map(|response| response.map(|body| HttpBody(BodyKind::H1(body))))
                    .map_err(|e| HttpError(ErrorKind::H1(e)))
            }
            Sender::H2 { sender, .. } => {
                let request = build_request(&req, true).unwrap_or_else(|_| rejected_h2_request());
                // The probe's requests carry no body, so the `HEADERS` frame ends
                // the stream and the `SendStream` is dropped unsent: `h2` sends
                // the body through it, and there is none.
                let (response, _send_stream) =
                    sender.send_request(request, true).map_err(|e| HttpError(ErrorKind::H2(e)))?;
                response
                    .await
                    .map(|response| response.map(|body| HttpBody(BodyKind::H2(body))))
                    .map_err(|e| HttpError(ErrorKind::H2(e)))
            }
        }
    }
}

/// The response body of either protocol, as one `Body`.
///
/// hyper hands HTTP/1.1 a body that decodes chunked framing itself, and the h2
/// client hands HTTP/2 a `RecvStream`; `check_http` and the DoH client read
/// both with `frame()` in a loop, so the two meet here instead of in each
/// reader. Like [`HttpError`], the variants stay private.
pub struct HttpBody(pub(crate) BodyKind);

/// Which client's body this is. Private on purpose, for [`ErrorKind`]'s reason.
pub(crate) enum BodyKind {
    H1(Incoming),
    H2(RecvStream),
}

impl Body for HttpBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, HttpError>>> {
        match &mut self.get_mut().0 {
            BodyKind::H1(body) => Pin::new(body)
                .poll_frame(cx)
                .map_err(|e| HttpError(ErrorKind::H1(e))),
            BodyKind::H2(stream) => match stream.poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => Poll::Ready(Some(Ok(Frame::data(data)))),
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(HttpError(ErrorKind::H2(e))))),
                Poll::Pending => Poll::Pending,
                // The data half ended; whatever trailers the peer sent (the DoH
                // resolvers send none) come after it.
                Poll::Ready(None) => match stream.poll_trailers(cx) {
                    Poll::Ready(Ok(Some(trailers))) => {
                        Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                    }
                    Poll::Ready(Ok(None)) => Poll::Ready(None),
                    Poll::Ready(Err(e)) => Poll::Ready(Some(Err(HttpError(ErrorKind::H2(e))))),
                    Poll::Pending => Poll::Pending,
                },
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.0 {
            BodyKind::H1(body) => body.is_end_stream(),
            BodyKind::H2(stream) => stream.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.0 {
            BodyKind::H1(body) => body.size_hint(),
            // h2's receive half knows nothing before the first frame: the
            // `content-length` header is the caller's to read.
            BodyKind::H2(_) => SizeHint::default(),
        }
    }
}

/// An h2 client builder carrying a profile's preface.
///
/// Every setting is optional because an absent one and a present one differ on
/// the wire, and this client sends what it was told to send and nothing else:
/// `None` is "this profile advertises nothing here", which is what Firefox's
/// bundle does with `SETTINGS_MAX_HEADER_LIST_SIZE`, not a fallback to h2's
/// 65 535. The two windows are not optional — a profile that named none would
/// otherwise take the protocol's 65 535 instead of this one's.
///
/// Shared with the DoH client (`dns/doh.rs`), which asks a resolver with
/// [`BASELINE_H2`].
pub(crate) fn h2_builder(h2: &H2Fingerprint) -> http2::client::Builder {
    let mut builder = http2::client::Builder::new();
    builder
        .initial_window_size(h2.initial_window_size)
        .initial_connection_window_size(h2.connection_window);
    if let Some(size) = h2.header_table_size {
        builder.header_table_size(size);
    }
    if let Some(max) = h2.max_concurrent_streams {
        builder.max_concurrent_streams(max);
    }
    if let Some(max) = h2.max_frame_size {
        builder.max_frame_size(max);
    }
    if let Some(max) = h2.max_header_list_size {
        builder.max_header_list_size(max);
    }
    if let Some(enable) = h2.enable_push {
        builder.enable_push(enable);
    }
    if let Some(enable) = h2.enable_connect_protocol {
        builder.enable_connect_protocol(enable);
    }
    if let Some(enable) = h2.no_rfc7540_priorities {
        builder.no_rfc7540_priorities(enable);
    }
    if !h2.settings_order.is_empty() {
        builder.settings_order(
            SettingsOrder::builder()
                .extend(h2.settings_order.iter().map(|id| SettingId::from(*id)))
                .build(),
        );
    }
    builder.headers_pseudo_order(pseudo_order(h2.pseudo_order));
    if let Some((weight, exclusive)) = h2.priority {
        // The profile names the weight the way the wrapper's flag does (Chrome's
        // `256`), one more than the byte the frame carries.
        builder.headers_stream_dependency(StreamDependency::new(
            StreamId::ZERO,
            u8::try_from(weight.saturating_sub(1)).unwrap_or(u8::MAX),
            exclusive,
        ));
    }
    builder
}

/// A profile's pseudo-header order as the h2 client's own order type.
fn pseudo_order(order: PseudoOrder) -> ClientPseudoOrder {
    let fields = match order {
        PseudoOrder::MethodAuthoritySchemePath => {
            [PseudoId::Method, PseudoId::Authority, PseudoId::Scheme, PseudoId::Path]
        }
        PseudoOrder::MethodSchemeAuthorityPath => {
            [PseudoId::Method, PseudoId::Scheme, PseudoId::Authority, PseudoId::Path]
        }
        PseudoOrder::MethodSchemePathAuthority => {
            [PseudoId::Method, PseudoId::Scheme, PseudoId::Path, PseudoId::Authority]
        }
        PseudoOrder::MethodPathAuthorityScheme => {
            [PseudoId::Method, PseudoId::Path, PseudoId::Authority, PseudoId::Scheme]
        }
    };
    ClientPseudoOrder::builder().extend(fields).build()
}

/// Builds the wire request for one of the two protocols, without a body — the
/// caller attaches what its protocol's client wants (`Full::new(Bytes::new())`
/// for hyper, `()` for the h2 client, which sends the body through the
/// `SendStream` the request returns).
///
/// The h1 header casing is attached here, because it is a property of the
/// message; the h2 shape is not, because it is a property of the *connection*
/// the profile opened (`apply_preface`).
///
/// Returns the error `http` reports for a value it will not put on the wire. Not
/// every value is a constant: the user-agent comes from `config.yml` verbatim
/// (`config.rs::user_agent_for`), and a `USER_AGENT: |` block scalar leaves a
/// trailing newline that `http` rejects. That used to reach an `expect` here,
/// which under `panic = "abort"` killed the process; `check_http` now reports it
/// as a run error before this point, and [`HttpSender::send`] falls back for the
/// callers that do not validate first ([`build_request_lenient`] for h1,
/// [`rejected_h2_request`] for h2).
fn build_request(req: &HttpRequest<'_>, h2: bool) -> Result<Request<()>, hyper::http::Error> {
    let case_map = (!h2).then(|| header_case_map(req));
    let mut builder = Request::builder().method(req.method.clone());
    if h2 {
        builder = builder.uri(format!("https://{}{}", req.host, req.path));
    } else {
        builder = builder.uri(req.path).header(HOST, req.host);
    }
    builder = add_headers(builder, req, h2, false)?;
    let mut request = builder.body(())?;
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
fn build_request_lenient(req: &HttpRequest<'_>) -> Request<()> {
    let uri = Uri::try_from(req.path).unwrap_or_else(|_| Uri::from_static("/"));
    let mut builder = Request::builder().method(req.method.clone()).uri(uri);
    if let Ok(host) = HeaderValue::from_str(req.host) {
        builder = builder.header(HOST, host);
    }
    // Every header value is validated before it is added, so the builder has
    // nothing left to refuse; `body` reports a `Result` only because the API
    // does. The floor is unreachable, not a fallback in use.
    let mut request = add_headers(builder, req, false, true)
        .and_then(|builder| builder.body(()))
        .unwrap_or_else(|_| Request::new(()));
    request.extensions_mut().insert(header_case_map(req));
    request
}

/// A request the h2 layer refuses before anything reaches the wire.
///
/// An h2 request's `:authority` comes from its URI alone (the client builds the
/// pseudo-header from the URI), so a host `http` will not take as one has no
/// equivalent request to fall back to. Handing the layer a request with no
/// scheme or authority makes it report `MissingUriSchemeAndAuthority`, which
/// [`HttpSender::send`] returns the way it returns every other send failure —
/// instead of aborting the process under `panic = "abort"`.
fn rejected_h2_request() -> Request<()> {
    let mut request = Request::new(());
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
    const FORBIDDEN: [&str; 6] = [
        "connection",
        "proxy-connection",
        "host",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
    ];
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
/// detail names the offset (`Read timeout at N KB`). Before the window opens it is
/// a plain read timeout that still says the offset, because where it died is the
/// useful part either way. One function for the h1 and h2 paths, which asked the
/// same question and used to answer it with two copies of the same eight lines.
pub(crate) fn fat_read_verdict(bytes: usize, min_kb: u64, max_kb: u64) -> (DpiStatus, Detail) {
    let kb = bytes as f64 / 1024.0;
    if kb >= min_kb as f64 && kb <= max_kb as f64 {
        return (
            DpiStatus::Tcp16Range,
            Detail::at_kb(Detail::ReadTimeoutWord, kb),
        );
    }
    if bytes > 0 {
        return (
            DpiStatus::ReadTimeout,
            Detail::at_kb(Detail::ReadTimeoutWord, kb),
        );
    }
    (DpiStatus::ReadTimeout, Detail::at_kb(Detail::ReadTimeoutWord, 0.0))
}

/// The verdict for an HTTP/1.1 client error — the call sites that start a
/// connection with hyper directly (`probe/domains.rs`) name this one.
pub(crate) fn inner_hyper(
    e: &hyper::Error,
    stage: ProbeStage,
    bytes: usize,
    min_kb: u64,
    max_kb: u64,
) -> (DpiStatus, Detail) {
    let (msg, os_code, os_kind) = hyper_err_info(e);
    verdict_from_client_error(&msg, os_code, os_kind, e.is_timeout(), stage, bytes, min_kb, max_kb)
}

/// [`inner_hyper`] for either protocol's client error: a request that went out
/// through [`HttpSender`] dies of one variant or the other, and the verdict is
/// the same question either way.
pub(crate) fn inner_http(
    e: &HttpError,
    stage: ProbeStage,
    bytes: usize,
    min_kb: u64,
    max_kb: u64,
) -> (DpiStatus, Detail) {
    let (msg, os_code, os_kind) = http_err_info(e);
    verdict_from_client_error(&msg, os_code, os_kind, e.is_timeout(), stage, bytes, min_kb, max_kb)
}

/// The verdict for a client error, whichever client raised it.
#[allow(clippy::too_many_arguments, reason = "one client error's parts, the stage it died in and the fat window's bounds; both callers already hold them as locals, and a bundle struct would exist for two calls")]
fn verdict_from_client_error(
    msg: &str,
    os_code: Option<i32>,
    os_kind: Option<std::io::ErrorKind>,
    timed_out: bool,
    stage: ProbeStage,
    bytes: usize,
    min_kb: u64,
    max_kb: u64,
) -> (DpiStatus, Detail) {
    let lower = msg.to_ascii_lowercase();

    // Read timeout inside the fat window → the 16KB DROP badge, and the detail
    // names the offset the way the fat probe does: `READ TIMEOUT at N KB`. The
    // badge is the same in every test but test 3; the window is the detail's job.
    if (timed_out || lower.contains("timed out")) && stage == ProbeStage::ReadingData {
        return fat_read_verdict(bytes, min_kb, max_kb);
    }

    let (s, d) = classify_ssl_error(msg, bytes, ConnectionStage::TlsClientHelloSent);
    if s != DpiStatus::Unknown {
        return (s, d);
    }
    classify_connect_error_full(msg, os_code, os_kind, bytes, stage)
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
        let mut sender = match HttpSender::handshake(tls_stream, alpn_h2, fingerprint).await {
            Ok(sender) => sender,
            Err(e) => {
                let (s, d) = inner_http(&e, ProbeStage::TlsConnected, 0, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
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
                let (s, d) = inner_http(&e, st, 0, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                return (s, d, 0usize);
            }
            Err(_) => {
                return (DpiStatus::ReadTimeout, Detail::at_kb(Detail::ReadTimeoutWord, 0.0), 0usize);
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
                    let (s, d) = inner_http(&e, ProbeStage::ReadingData, bytes_read, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
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

    /// The client's own bytes, per profile: the connection preface and the
    /// request's `HEADERS` frame, exactly as they reach the wire.
    ///
    /// Past TLS this is the whole of what a probe imitates — the `SETTINGS`
    /// values and their order, the connection window, the pseudo-header order,
    /// and whether the request's `HEADERS` frame carries the PRIORITY flag with
    /// which weight. No hash of the ClientHello sees any of it, so a client that
    /// gets it wrong is a client a middlebox can tell apart; this is the test
    /// that says the data in `fingerprint::h2` reaches the wire unchanged, and it
    /// is pinned as bytes rather than as fields because that is what the peer
    /// sees.
    ///
    /// The four rows are the baseline (`BASELINE_H2`, which the DoH client also
    /// opens with — no PRIORITY, `SETTINGS` ascending from `ENABLE_PUSH`),
    /// Chrome 146 (`masp`, weight 256 exclusive, four settings), Firefox 133
    /// (`mpas`, weight 42, no `MAX_HEADER_LIST_SIZE`) and Safari 18.0 (`msap`,
    /// five settings including the two the wrapper names). A diff here is a
    /// change to what every probe sends.
    ///
    /// The listener is a plain socket that records what arrives, and the request
    /// is [`request`]'s — three headers and a `GET`, small enough to read.
    #[tokio::test]
    async fn the_h2_wire_is_what_the_profiles_pin() {
        use tokio::io::AsyncReadExt;

        let expected = [
            (
                TlsFingerprint::Rustls,
                "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a00001804000000000000020000000000040020\
                 0000000500004000000600004000000004080000000000004f000100001c010500000001828741882f91d35d055c\
                 87a7048263cf7a82b47f50863485a9264faf",
            ),
            (
                TlsFingerprint::Chrome146,
                "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a0000180400000000000001000100000002000000\
                 0000040060000000060004000000000408000000000000ef000100002101250000000180000000ff8241882f91d3\
                 5d055c87a787048263cf7a82b47f50863485a9264faf",
            ),
            (
                TlsFingerprint::Firefox133,
                "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a0000180400000000000001000100000002000000\
                 0000040002000000050000400000000408000000000000bf0001000021012500000001000000002982048263cf41\
                 882f91d35d055c87a7877a82b47f50863485a9264faf",
            ),
            (
                TlsFingerprint::Safari180,
                "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a00001e0400000000000002000000000003000000\
                 64000400200000000800000001000900000001000004080000000000009f000100002101250000000100000000ff\
                 828741882f91d35d055c87a7048263cf7a82b47f50863485a9264faf",
            ),
        ];

        for (fingerprint, want) in expected {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let capture = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.expect("accept");
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match tokio::time::timeout(Duration::from_millis(250), sock.read(&mut chunk)).await
                    {
                        Ok(Ok(0)) | Err(_) => break,
                        Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                        Ok(Err(_)) => break,
                    }
                }
                buf
            });
            let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            let mut sender = HttpSender::handshake(stream, true, fingerprint)
                .await
                .expect("handshake");
            // The reply never comes — the listener records and closes — so the
            // send is cut by the deadline; by then the preface and the request
            // are on the socket.
            let _ = tokio::time::timeout(Duration::from_millis(300), sender.send(request())).await;
            drop(sender);
            let got = capture.await.expect("capture");
            let got: String = got.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(got, want, "{fingerprint:?}");
        }
    }
}
