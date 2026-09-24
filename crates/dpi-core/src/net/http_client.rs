//! The HTTP/HTTPS GET the net layer uses: one request per connection,
//! redirects followed up to four hops, every stage under the caller's
//! deadline.

use std::time::Duration;

use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper::header::{ACCEPT, HOST, USER_AGENT};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::net::tcp::set_no_delay;
use crate::net::tls::{create_tls_config, TlsProfile};

/// The callers of this client read a public-IP echo or a version manifest, so
/// a megabyte is generous; anything larger is a broken or hostile server.
const MAX_BODY: usize = 1 << 20;

/// Why [`http_get_text`] returned no body.
///
/// A type, not the bare `String` it used to be: neither caller (the public-IP
/// race and the release check) reads the cause, so nothing depended on the text,
/// and a caller that does want to branch on a failure now matches a variant
/// instead of parsing a message. Every `Display` string is the one the `String`
/// error carried, so a log line reads exactly as before.
#[derive(Debug, thiserror::Error)]
pub enum HttpGetError {
    /// The URL did not parse.
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    /// A redirect's `Location` did not resolve against the URL it came from.
    #[error("Bad redirect: {0}")]
    BadRedirect(#[source] url::ParseError),
    /// The chain ended on a status other than 200.
    #[error("HTTP status {0}")]
    Status(u16),
    /// The body was not UTF-8.
    #[error("Non-UTF8 response: {0}")]
    NonUtf8(#[source] std::string::FromUtf8Error),
    /// More than four redirect hops without landing on a 200.
    #[error("Too many redirects")]
    TooManyRedirects,
    /// The caller's deadline elapsed — over the whole chain or over one hop.
    #[error("HTTP request timeout")]
    Timeout,
    /// The URL carried no host.
    #[error("Missing host in URL")]
    MissingHost,
    /// The TCP connect failed.
    #[error("Connect to {addr} failed: {source}")]
    Connect {
        /// The `host:port` that was dialled.
        addr: String,
        /// The connect error.
        #[source]
        source: std::io::Error,
    },
    /// The request could not be built, i.e. a header value the caller supplied
    /// was not a valid one.
    #[error("{0}")]
    Request(#[source] hyper::http::Error),
    /// The host was not a valid DNS name.
    #[error("Invalid TLS server name: {0}")]
    ServerName(#[source] rustls::pki_types::InvalidDnsNameError),
    /// The TLS handshake failed.
    #[error("TLS connect failed: {0}")]
    Tls(#[source] std::io::Error),
    /// The HTTP/1.1 handshake failed.
    #[error("HTTP/1.1 handshake failed: {0}")]
    Handshake(#[source] hyper::Error),
    /// The request or the response failed mid-transfer.
    #[error("{0}")]
    Transport(#[source] hyper::Error),
    /// The body errored, or was larger than `MAX_BODY`.
    #[error("{0}")]
    Body(Box<dyn std::error::Error + Send + Sync>),
}

/// Simple, pure-Rust HTTP/HTTPS GET returning text content (capped at 64 KB).
pub async fn http_get_text(url_str: &str, timeout_dur: Duration) -> Result<String, HttpGetError> {
    // The timeout bounds the whole fetch, redirects included: `http_get_once`
    // applies it per hop, so four hops could spend four times what the caller
    // asked for and overrun its own deadline.
    match timeout(timeout_dur, http_get_chain(url_str, timeout_dur)).await {
        Ok(result) => result,
        Err(_) => Err(HttpGetError::Timeout),
    }
}

/// Follows up to four redirect hops, then returns the body of a 200 response.
async fn http_get_chain(url_str: &str, timeout_dur: Duration) -> Result<String, HttpGetError> {
    let mut url = Url::parse(url_str)?;
    for _ in 0..4 {
        let (status, location, body) = http_get_once(&url, timeout_dur).await?;
        if (300..400).contains(&status) {
            if let Some(loc) = location {
                url = url.join(&loc).map_err(HttpGetError::BadRedirect)?;
                continue;
            }
        }
        if status != 200 {
            return Err(HttpGetError::Status(status));
        }
        return String::from_utf8(body).map_err(HttpGetError::NonUtf8);
    }
    Err(HttpGetError::TooManyRedirects)
}

async fn http_get_once(url: &Url, timeout_dur: Duration) -> Result<(u16, Option<String>, Vec<u8>), HttpGetError> {
    let host = url.host_str().ok_or(HttpGetError::MissingHost)?.to_string();
    let is_https = url.scheme() == "https";
    let port = url.port().unwrap_or(if is_https { 443 } else { 80 });
    let path_and_query = match url.query() {
        Some(q) => format!("{}?{}", url.path(), q),
        None => url.path().to_string(),
    };

    let execute = async {
        let addr = format!("{}:{}", host, port);
        let tcp = crate::net::bind::connect_host(&host, port)
            .await
            .map_err(|source| HttpGetError::Connect { addr, source })?;
        set_no_delay(&tcp);

        let req = Request::builder()
            .method(Method::GET)
            .uri(path_and_query)
            .header(HOST, &host)
            .header(USER_AGENT, concat!("dpi-detector/", env!("CARGO_PKG_VERSION")))
            .header(ACCEPT, "*/*")
            .body(Empty::<Bytes>::new())
            .map_err(HttpGetError::Request)?;

        if is_https {
            let tls_config = create_tls_config(&TlsProfile::verifying());
            let connector = TlsConnector::from(tls_config);
            let server_name = ServerName::try_from(host.clone())
                .map_err(HttpGetError::ServerName)?;

            let tls_stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(HttpGetError::Tls)?;

            request_once(TokioIo::new(tls_stream), req).await
        } else {
            request_once(TokioIo::new(tcp), req).await
        }
    };

    timeout(timeout_dur, execute)
        .await
        .map_err(|_| HttpGetError::Timeout)?
}

/// One HTTP/1.1 request round-trip over any connected stream.
async fn request_once<T>(
    io: TokioIo<T>,
    req: Request<Empty<Bytes>>,
) -> Result<(u16, Option<String>, Vec<u8>), HttpGetError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(HttpGetError::Handshake)?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let resp = sender.send_request(req).await.map_err(HttpGetError::Transport)?;
    let status = resp.status().as_u16();
    let location = resp
        .headers()
        .get(hyper::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // The callers read a public-IP echo or a version manifest, so a cap costs
    // nothing and stops a hostile or broken server from making the tool buffer
    // a whole body in memory (Rule 2: never buffer a full stream).
    let body = Limited::new(resp.into_body(), MAX_BODY)
        .collect()
        .await
        .map_err(HttpGetError::Body)?
        .to_bytes()
        .to_vec();
    Ok((status, location, body))
}
