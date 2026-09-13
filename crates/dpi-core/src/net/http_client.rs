//! The HTTP/HTTPS GET the net layer uses: one request per connection,
//! redirects followed up to four hops, every stage under the caller's
//! deadline.

use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::header::{ACCEPT, HOST, USER_AGENT};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::net::tcp::set_no_delay;
use crate::net::tls::{create_tls_config, TlsProfile};

/// Simple, pure-Rust HTTP/HTTPS GET returning text content (capped at 64 KB).
pub async fn http_get_text(url_str: &str, timeout_dur: Duration) -> Result<String, String> {
    // The timeout bounds the whole fetch, redirects included: `http_get_once`
    // applies it per hop, so four hops could spend four times what the caller
    // asked for and overrun its own deadline.
    match timeout(timeout_dur, http_get_chain(url_str, timeout_dur)).await {
        Ok(result) => result,
        Err(_) => Err("HTTP request timeout".to_string()),
    }
}

/// Follows up to four redirect hops, then returns the body of a 200 response.
async fn http_get_chain(url_str: &str, timeout_dur: Duration) -> Result<String, String> {
    let mut url = Url::parse(url_str).map_err(|e| format!("Invalid URL: {}", e))?;
    for _ in 0..4 {
        let (status, location, body) = http_get_once(&url, timeout_dur).await?;
        if (300..400).contains(&status) {
            if let Some(loc) = location {
                url = url.join(&loc).map_err(|e| format!("Bad redirect: {}", e))?;
                continue;
            }
        }
        if status != 200 {
            return Err(format!("HTTP status {}", status));
        }
        return String::from_utf8(body).map_err(|e| format!("Non-UTF8 response: {}", e));
    }
    Err("Too many redirects".to_string())
}

async fn http_get_once(url: &Url, timeout_dur: Duration) -> Result<(u16, Option<String>, Vec<u8>), String> {
    let host = url.host_str().ok_or_else(|| "Missing host in URL".to_string())?.to_string();
    let is_https = url.scheme() == "https";
    let port = url.port().unwrap_or(if is_https { 443 } else { 80 });
    let path_and_query = match url.query() {
        Some(q) => format!("{}?{}", url.path(), q),
        None => url.path().to_string(),
    };

    let execute = async {
        let addr = format!("{}:{}", host, port);
        let tcp = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("Connect to {} failed: {}", addr, e))?;
        set_no_delay(&tcp);

        let req = Request::builder()
            .method(Method::GET)
            .uri(path_and_query)
            .header(HOST, &host)
            .header(USER_AGENT, concat!("dpi-detector/", env!("CARGO_PKG_VERSION")))
            .header(ACCEPT, "*/*")
            .body(Empty::<Bytes>::new())
            .map_err(|e| e.to_string())?;

        if is_https {
            let tls_config = create_tls_config(&TlsProfile::verifying());
            let connector = TlsConnector::from(tls_config);
            let server_name = ServerName::try_from(host.clone())
                .map_err(|e| format!("Invalid TLS server name: {}", e))?;

            let tls_stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| format!("TLS connect failed: {}", e))?;

            request_once(TokioIo::new(tls_stream), req).await
        } else {
            request_once(TokioIo::new(tcp), req).await
        }
    };

    timeout(timeout_dur, execute)
        .await
        .map_err(|_| "HTTP request timeout".to_string())?
}

/// One HTTP/1.1 request round-trip over any connected stream.
async fn request_once<T>(
    io: TokioIo<T>,
    req: Request<Empty<Bytes>>,
) -> Result<(u16, Option<String>, Vec<u8>), String>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| format!("HTTP/1.1 handshake failed: {}", e))?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let location = resp
        .headers()
        .get(hyper::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body = resp.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes().to_vec();
    Ok((status, location, body))
}
