//! Verification harness for the ClientHello profile patch (see
//! `vendor/rustls/README-PATCH.md`).
//!
//! Run this after any rustls rebase, and whenever a profile's data changes:
//!
//! ```text
//! cargo run --release --example tls_fingerprint dump rustls   # wire bytes only
//! cargo run --release --example tls_fingerprint dump custom
//! cargo run --release --example tls_fingerprint live custom   # real servers
//! cargo run --release --example tls_fingerprint live12 custom hub.docker.com
//! ```
//!
//! Both `live` forms take an optional host list; `live12` pins TLS 1.2 (the
//! probes' second TLS column) and `live` pins TLS 1.3.
//!
//! `dump` needs no network: it builds a ClientHello in memory and prints the JA3
//! and the extension list, so it can be diffed against a known-good capture.
//! `live` completes real handshakes and asks `tls.peet.ws` what it saw, which is
//! the only way to catch a profile that is well formed but that real servers
//! reject (that is how the GREASE-ECH problem and the certificate-compression
//! problem were found).

use std::sync::Arc;
use std::time::Instant;

use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::net::ja3;
use dpi_core::net::tls::{
    create_insecure_dpi_tls_config_tls12_with, create_insecure_dpi_tls_config_tls13_with,
    create_insecure_dpi_tls_config_with,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Hosts that must accept a browser-shaped hello, chosen because they exercise
/// different stacks: a fingerprint echo service, two ECH-aware frontends, and
/// three plain TLS servers.
const HOSTS: [&str; 6] = [
    "tls.peet.ws",
    "cloudflare.com",
    "www.google.com",
    "www.wikipedia.org",
    "www.microsoft.com",
    "dns.google",
];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "dump".into());
    let which = std::env::args().nth(2).unwrap_or_else(|| "custom".into());
    let extra: Vec<String> = std::env::args().skip(3).collect();
    let hosts: Vec<String> = if extra.is_empty() {
        HOSTS.iter().map(|h| (*h).to_string()).collect()
    } else {
        extra
    };
    let fingerprint = TlsFingerprint::parse(&which).expect("profile must be rustls|custom");

    match mode.as_str() {
        "dump" => dump(fingerprint),
        "live" => live(fingerprint, &hosts, false).await,
        "live12" => live(fingerprint, &hosts, true).await,
        other => panic!("unknown mode {other}, expected dump|live|live12"),
    }
}

fn client_hello(fingerprint: TlsFingerprint) -> Vec<u8> {
    // Same factory the probes use, so the dump reflects the real wire shape
    // (including the baseline compression policy) rather than a hand-built config.
    let config = (*create_insecure_dpi_tls_config_with(fingerprint)).clone();

    let name = rustls::pki_types::ServerName::try_from("example.com").expect("valid name");
    let mut conn = rustls::ClientConnection::new(Arc::new(config), name).expect("client conn");
    let mut buf = Vec::new();
    conn.write_tls(&mut buf).expect("write ClientHello");
    buf
}

fn dump(fingerprint: TlsFingerprint) {
    let buf = client_hello(fingerprint);
    println!("profile   = {}", fingerprint.code());
    println!("record    = {} bytes", buf.len() - 5);
    println!("ja3       = {}", ja3::client_hello_ja3(&buf));
    println!(
        "exts      = {}",
        ja3::extension_types(&buf)
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join("-")
    );
    println!("key_share = {}", ja3::key_share_groups(&buf));
}

async fn live(fingerprint: TlsFingerprint, hosts: &[String], tls12: bool) {
    let config = if tls12 {
        create_insecure_dpi_tls_config_tls12_with(fingerprint)
    } else {
        create_insecure_dpi_tls_config_tls13_with(fingerprint)
    };
    println!(
        "profile   = {} ({})",
        fingerprint.code(),
        if tls12 { "tls1.2 only" } else { "tls1.3 only" }
    );

    for host in hosts {
        let started = Instant::now();
        let tcp = match TcpStream::connect((host.as_str(), 443)).await {
            Ok(s) => s,
            Err(e) => {
                println!("{host:22} TCP FAILED: {e}");
                continue;
            }
        };
        let connector = TlsConnector::from(config.clone());
        let name = rustls::pki_types::ServerName::try_from(host.clone()).expect("valid host");
        let mut tls = match connector.connect(name, tcp).await {
            Ok(s) => s,
            Err(e) => {
                println!("{host:22} HANDSHAKE FAILED: {e}");
                continue;
            }
        };
        let alpn = tls
            .get_ref()
            .1
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).to_string())
            .unwrap_or_else(|| "-".into());
        println!(
            "{host:22} OK {:?} alpn={alpn} {}ms",
            tls.get_ref().1.protocol_version(),
            started.elapsed().as_millis()
        );

        if host.as_str() == "tls.peet.ws" {
            let request = "GET /api/all HTTP/1.1\r\nHost: tls.peet.ws\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            if tls.write_all(request.as_bytes()).await.is_ok() {
                let mut body = Vec::new();
                let _ = tls.read_to_end(&mut body).await;
                for line in String::from_utf8_lossy(&body).lines() {
                    let line = line.trim();
                    if line.starts_with("\"ja3\"")
                        || line.starts_with("\"ja3_hash\"")
                        || line.starts_with("\"ja4\"")
                        || line.starts_with("\"peetprint_hash\"")
                    {
                        println!("   {line}");
                    }
                }
            }
        }
    }
}

