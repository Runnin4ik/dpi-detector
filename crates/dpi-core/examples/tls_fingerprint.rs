//! Verification harness for the ClientHello profile patch (see
//! `vendor/rustls/README-PATCH.md`).
//!
//! Run this after any rustls rebase, and whenever a profile's data changes:
//!
//! ```text
//! cargo run --release --example tls_fingerprint dump rustls   # wire bytes only
//! cargo run --release --example tls_fingerprint dump13 chrome  # pinned to TLS 1.3
//! cargo run --release --example tls_fingerprint dump12 chrome  # pinned to TLS 1.2
//! cargo run --release --example tls_fingerprint live custom   # real servers
//! cargo run --release --example tls_fingerprint liveany custom # the unpinned offer
//! cargo run --release --example tls_fingerprint live12 custom hub.docker.com
//! ```
//!
//! Every `live` form takes an optional host list; `live`/`live13` pin TLS 1.3
//! (test 2's first column), `live12` pins 1.2, and `liveany` sends the browser's
//! own offer — the shape test 6's TLS 1.3 axis and tests 3/4 put on the wire, and
//! the one that can be compared with a bundle script run without version flags.
//!
//! `dump` needs no network: it builds a ClientHello in memory and prints the JA3
//! (`dump13`/`dump12` do the same on the version-pinned builders the probes use),
//! the JA4 and the extension list, so it can be diffed against a known-good
//! capture. `live` completes real handshakes and asks `tls.peet.ws` what it saw,
//! which is the only way to catch a profile that is well formed but that real
//! servers reject (that is how the GREASE-ECH problem and the certificate-
//! compression problem were found).
//!
//! ## Verifying a profile against the bundle it reproduces
//!
//! A fingerprint hash is a *summary*. JA3 never reads the signature-algorithms
//! list; JA3, JA4 and peetprint all drop GREASE by design, because its values
//! change every connection; and none of them covers the padding length or a
//! GREASE extension's body. A one-byte difference in either survives every hash,
//! every test and every `tls.peet.ws` comparison. So compare the *bytes both
//! clients put on the wire*, not a server's summary of them:
//!
//! 1. Run a throwaway TLS listener on `127.0.0.1:443` that reads the first
//!    handshake message and writes it to a file.
//! 2. Point the bundle at it (`--connect-to host:443:127.0.0.1:443`) and point a
//!    probe at it: `-d <name>.nip.io` makes test 6 dial the listener with the
//!    profile, the TLS axis and the ALPN the axis under test uses.
//! 3. Give both sides the *same* hostname, so the SNI matches — it is the only
//!    field a profile takes from the domain, and its length moves the padding.
//!    When only one side can be pointed at a name, rewrite the SNI in the
//!    captured bytes and grow or shrink the padding by the same amount; the
//!    extensions total and the handshake length are unchanged by that swap.
//! 4. Compare the cipher list in order, the extension type list in order with
//!    each body's length, then every body with GREASE words masked to zero. Only
//!    the client random, the session id and the key share's public key may
//!    differ.
//! 5. Take every expected value — the `bundle_versions_match_their_ja3`/`_ja4`
//!    constants included — from the *bundle's own capture*, never from our dump.
//!    A constant copied from our own output turns the test into a lock-in and
//!    hides exactly the difference it exists to catch: that is how the Safari
//!    profile kept a `rsa_pss_rsae_sha384` the bundle de-duplicates, and how the
//!    closing GREASE extension went without the byte BoringSSL writes into it.
//! 6. Check the HTTP layer separately. The h2 shape is the SETTINGS payload and
//!    its order, the window update, the priority and the pseudo-header order —
//!    what `tls.peet.ws` reports as the akamai fingerprint. A request *header*
//!    that differs is not a fingerprint difference, and neither is a chosen ALPN
//!    as long as both sides offer the same list.
//!
//! ## Comparing against an echo service (`live`, `tls.peet.ws`)
//!
//! An echo service reports what its own stack saw, which is the only way to
//! catch a profile that is well formed but that real servers reject. It measures
//! the *shape the far side reads*, not the bytes we send, so:
//!
//! 1. Point *both* clients at it — `live <profile>` for ours, and the bundle at
//!    `https://tls.peet.ws/api/all` — and compare like for like: `ja3`,
//!    `ja3_hash`, `ja4`, `peetprint_hash` and the akamai h2 fingerprint of one
//!    against the same field of the other. Comparing our dump with the service's
//!    report of our *own* probe proves nothing about the bundle.
//! 2. Offer the same protocol on both sides: the ALPN value is the first field of
//!    JA4, so a `--http2` bundle against a probe that offers `h2, http/1.1`
//!    differs for a reason the service reports faithfully and the profile has
//!    nothing to do with.
//! 3. Read each hash for what it covers. JA3 never reads the
//!    signature-algorithms list; JA4 hashes it; both drop GREASE, whose values
//!    change per connection. peetprint covers more — the repository measured the
//!    version list and the padding among its inputs — so a mismatch that shows
//!    up there and nowhere else points at the padded size or the offered
//!    versions, which is what `ClientHelloProfile::legacy_versions` fixes.
//! 4. Never conclude "identical" from an echo service alone. Both Safari bugs
//!    this harness later caught were missed by that route in the very runs that
//!    called the profile identical: the duplicated signature scheme *was* visible
//!    in JA4, but the pinned constant had been copied from our own dump instead
//!    of measured from the bundle, and the missing byte in the closing GREASE
//!    extension is invisible to all three hashes. Confirm on captured bytes
//!    (above) before pinning a value, and re-measure from the bundle whenever a
//!    profile's data changes.
//! 5. Remember what the service cannot see. It reports the connection the *path*
//!    delivered: a middlebox that rewrites or truncates a hello changes what the
//!    service reports, and the profile is then blamed for the network. When an
//!    echo result disagrees with a captured-byte comparison, trust the bytes.

use std::time::Instant;

use dpi_core::net::fingerprint::{http_identity, TlsFingerprint};
use dpi_core::net::{ja3, ja4};
use dpi_core::net::tls::{create_tls_config, TlsProfile, TlsVersion};
use dpi_core::probe::http::{request_headers, HttpRequest, HttpSender};
use http_body_util::BodyExt;
use hyper::Method;
use hyper_util::rt::TokioIo;
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
        "dump" => dump(fingerprint, TlsVersion::Any),
        "dump13" => dump(fingerprint, TlsVersion::Tls13),
        "dump12" => dump(fingerprint, TlsVersion::Tls12),
        "live" => live(fingerprint, &hosts, TlsVersion::Tls13).await,
        "live13" => live(fingerprint, &hosts, TlsVersion::Tls13).await,
        "live12" => live(fingerprint, &hosts, TlsVersion::Tls12).await,
        "liveany" => live(fingerprint, &hosts, TlsVersion::Any).await,
        "peet" => peet(fingerprint).await,
        other => panic!(
            "unknown mode {other}, expected dump|dump13|dump12|live|live13|live12|liveany"
        ),
    }
}

fn client_hello(fingerprint: TlsFingerprint, version: TlsVersion) -> Vec<u8> {
    // Same factory the probes use, so the dump reflects the real wire shape
    // (including the baseline compression policy and the version trim) rather
    // than a hand-built config.
    let profile = match version {
        TlsVersion::Tls12 => TlsProfile::insecure(fingerprint).tls12(),
        TlsVersion::Tls13 => TlsProfile::insecure(fingerprint).tls13(),
        TlsVersion::Any => TlsProfile::insecure(fingerprint),
    };
    let config = create_tls_config(&profile);

    let name = rustls::pki_types::ServerName::try_from("example.com").expect("valid name");
    let mut conn = rustls::ClientConnection::new(config, name).expect("client conn");
    let mut buf = Vec::new();
    conn.write_tls(&mut buf).expect("write ClientHello");
    buf
}

fn dump(fingerprint: TlsFingerprint, version: TlsVersion) {
    let buf = client_hello(fingerprint, version);
    println!("profile   = {}", fingerprint.code());
    println!("record    = {} bytes", buf.len() - 5);
    println!("ja3       = {}", ja3::client_hello_ja3(&buf));
    println!("ja4       = {}", ja4::client_hello_ja4(&buf));
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

async fn live(fingerprint: TlsFingerprint, hosts: &[String], version: TlsVersion) {
    let profile = match version {
        TlsVersion::Tls12 => TlsProfile::insecure(fingerprint).tls12(),
        TlsVersion::Tls13 => TlsProfile::insecure(fingerprint).tls13(),
        TlsVersion::Any => TlsProfile::insecure(fingerprint),
    };
    let config = create_tls_config(&profile);
    println!(
        "profile   = {} ({})",
        fingerprint.code(),
        match version {
            TlsVersion::Tls12 => "tls1.2 only",
            TlsVersion::Tls13 => "tls1.3 only",
            TlsVersion::Any => "the browser's own offer",
        }
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
            // The echo service reports the shape its stack read, HTTP/2 included:
            // the akamai string is SETTINGS payload | WINDOW_UPDATE | PRIORITY |
            // pseudo-header order, and the HEADERS frame carries every request
            // header in order — so a header that differs shows up here instead of
            // being mistaken for a fingerprint difference.
            let request = "GET /api/all HTTP/1.1\r\nHost: tls.peet.ws\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            if tls.write_all(request.as_bytes()).await.is_ok() {
                let mut body = Vec::new();
                let _ = tls.read_to_end(&mut body).await;
                // The hand-written request never unwraps the response either:
                // strip the status line and headers, then read the body as it
                // comes — plain, or chunk-framed if the service chose to.
                let body = strip_headers(&body);
                let report = serde_json::from_slice::<serde_json::Value>(body)
                    .or_else(|_| serde_json::from_slice::<serde_json::Value>(&dechunk(body)));
                match report {
                    Ok(report) => print_peet_report(&report),
                    Err(_) => println!(
                        "   (no JSON report in {} bytes: {:?})",
                        body.len(),
                        String::from_utf8_lossy(&body[..body.len().min(100)])
                    ),
                }
            }
        }
    }
}

/// The echo service, through the path the probes themselves use: the profile's
/// TLS hello, its ALPN, its HTTP/2 preface and request shape, and its header
/// list. `live` measures our TLS shape with a hand-written HTTP/1.1 request,
/// which is enough for the TLS hashes but leaves the service no HTTP/2 frames
/// to report — the akamai fingerprint needs this one.
async fn peet(fingerprint: TlsFingerprint) {
    const HOST: &str = "tls.peet.ws";
    let config = create_tls_config(&TlsProfile::insecure(fingerprint));
    let tcp = match TcpStream::connect((HOST, 443)).await {
        Ok(stream) => stream,
        Err(e) => return println!("{HOST:22} TCP FAILED: {e}"),
    };
    let name = rustls::pki_types::ServerName::try_from(HOST).expect("valid host");
    let tls = match TlsConnector::from(config).connect(name, tcp).await {
        Ok(stream) => stream,
        Err(e) => return println!("{HOST:22} HANDSHAKE FAILED: {e}"),
    };
    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    println!("profile   = {} (the browser's own offer)", fingerprint.code());
    println!("{HOST:22} alpn={}", if h2 { "h2" } else { "http/1.1" });
    let mut sender = match HttpSender::handshake(TokioIo::new(tls), h2, fingerprint).await {
        Ok(sender) => sender,
        Err(e) => return println!("HTTP handshake failed: {e}"),
    };
    let identity = http_identity(fingerprint);
    let user_agent = identity.user_agent.unwrap_or("");
    let request = HttpRequest {
        method: Method::GET,
        host: HOST,
        path: "/api/all",
        headers: request_headers(&identity, user_agent, Vec::new()),
    };
    let response = match sender.send(request).await {
        Ok(response) => response,
        Err(e) => return println!("request failed: {e}"),
    };
    let body = match response.into_body().collect().await {
        Ok(body) => body.to_bytes(),
        Err(e) => return println!("body failed: {e}"),
    };
    match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(report) => print_peet_report(&report),
        Err(_) => println!("   (no JSON report in {} bytes)", body.len()),
    }
}

/// Everything after the response's status line and headers.
fn strip_headers(response: &[u8]) -> &[u8] {
    response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| &response[at + 4..])
        .unwrap_or(response)
}

/// Strips HTTP/1.1 chunked framing, leaving the body the framing carried.
fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(end) = rest.windows(2).position(|w| w == b"\r\n") {
        let size = String::from_utf8_lossy(&rest[..end]);
        let digits = size.split(';').next().unwrap_or("").trim();
        let Ok(len) = usize::from_str_radix(digits, 16) else {
            break;
        };
        rest = &rest[end + 2..];
        if len == 0 || rest.len() < len {
            break;
        }
        out.extend_from_slice(&rest[..len]);
        rest = &rest[len.min(rest.len())..];
        rest = rest.strip_prefix(b"\r\n").unwrap_or(rest);
    }
    out
}

/// What `tls.peet.ws` saw, in the order a comparison reads it: the TLS hashes
/// first, then the HTTP/2 shape and every request header it received.
fn print_peet_report(report: &serde_json::Value) {
    if let Some(tls) = report.get("tls") {
        for key in ["ja3", "ja3_hash", "ja4", "peetprint_hash"] {
            if let Some(value) = tls.get(key) {
                println!("   tls.{key} = {value}");
            }
        }
    }
    let Some(http2) = report.get("http2") else {
        return;
    };
    for key in ["akamai_fingerprint", "akamai_fingerprint_hash"] {
        if let Some(value) = http2.get(key) {
            println!("   http2.{key} = {value}");
        }
    }
    if let Some(frames) = http2.get("sent_frames").and_then(|frames| frames.as_array()) {
        for frame in frames {
            let kind = frame.get("frame_type").and_then(|k| k.as_str()).unwrap_or("?");
            if let Some(headers) = frame.get("headers").and_then(|h| h.as_array()) {
                for header in headers {
                    println!("   {kind} {}", header.as_str().unwrap_or(""));
                }
            }
        }
    }
}

