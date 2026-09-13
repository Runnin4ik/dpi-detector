//! HTTP over an established connection, in whichever protocol ALPN negotiated.
//!
//! Fingerprint profiles advertise `h2, http/1.1` (that is what Chrome, Safari
//! and Firefox offer), so every server that speaks HTTP/2 selects it. A probe
//! that then started an HTTP/1.1 client would fail on every h2-capable site and
//! report the mismatch as censorship, so the probes speak both: one enum over
//! hyper's two client connections, and a request builder that drops the headers
//! HTTP/2 forbids so a call site describes one request instead of two.

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HOST, USER_AGENT};
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioExecutor;

/// A request both protocols can carry.
///
/// `host` is the SNI name: the `Host` header in HTTP/1.1, the `:authority`
/// pseudo-header (taken from the URI) in HTTP/2. The helper is only ever handed
/// a connection that is already TLS, so the HTTP/2 form is `https://`.
pub struct HttpRequest<'a> {
    pub method: Method,
    pub host: &'a str,
    pub path: &'a str,
    pub user_agent: &'a str,
    /// Sent in both protocols, minus the connection-specific ones HTTP/2 rejects.
    pub headers: Vec<(&'a str, String)>,
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
    /// thing that decides which client to start.
    pub async fn handshake<T>(io: T, alpn_h2: bool) -> hyper::Result<Self>
    where
        T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        if alpn_h2 {
            let (sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake(io)
                .await?;
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
    builder = builder.header(USER_AGENT, req.user_agent);
    for (name, value) in req.headers {
        if h2 && is_connection_specific(name) {
            continue;
        }
        builder = builder.header(name, value);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> HttpRequest<'static> {
        HttpRequest {
            method: Method::GET,
            host: "example.com",
            path: "/x",
            user_agent: "ua",
            headers: vec![
                ("Accept-Encoding", "identity".to_string()),
                ("Connection", "close".to_string()),
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
        assert_eq!(request.headers().get(USER_AGENT).expect("ua"), "ua");
    }

    #[test]
    fn http1_keeps_the_path_host_and_connection_headers() {
        let request = build_request(request(), false);
        assert_eq!(request.uri().to_string(), "/x");
        assert_eq!(request.headers().get(HOST).expect("host"), "example.com");
        assert_eq!(request.headers().get("connection").expect("close"), "close");
    }
}
