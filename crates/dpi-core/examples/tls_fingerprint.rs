//! Verification harness for the ClientHello profile patch (see
//! `vendor/rustls/README-PATCH.md`).
//!
//! Run this after any rustls rebase, and whenever a profile's data changes:
//!
//! ```text
//! cargo run --release --example tls_fingerprint dump rustls   # wire bytes only
//! cargo run --release --example tls_fingerprint dump13 chrome  # pinned to TLS 1.3
//! cargo run --release --example tls_fingerprint dump12 chrome  # pinned to TLS 1.2
//! cargo run --release --example tls_fingerprint dump-alpn chrome107 h1  # ALPN pinned
//! cargo run --release --example tls_fingerprint dump-hex chrome107 > capture.hex
//! cargo run --release --example tls_fingerprint variant chrome107 sigalg-swap  # one delta
//! cargo run --release --example tls_fingerprint hello capture.hex  # bytes from elsewhere
//! cargo run --release --example tls_fingerprint replay capture.hex host  # send those bytes
//! cargo run --release --example tls_fingerprint diff a.hex b.hex   # two captures, compared
//! cargo run --release --example tls_fingerprint live firefox  # real servers
//! cargo run --release --example tls_fingerprint liveany firefox # the unpinned offer
//! cargo run --release --example tls_fingerprint live12 firefox hub.docker.com
//! cargo run --release --example tls_fingerprint peet firefox   # the h2 shape, echoed
//! cargo run --release --example tls_fingerprint headers firefox localhost # the h1 request
//! cargo run --release --example tls_fingerprint peet chrome146 www.google.com \
//!     --connect-to www.google.com:443=127.0.0.1:443   # the h2 shape through a tap
//! ```
//!
//! `dump-alpn`, `variant` and `hello` are the shape-probing half of the same
//! instrument. `dump-alpn` pins the ALPN offer (it moves JA4's ALPN field and
//! nothing else), `variant` applies one delta to the profile's own hello
//! (`sigalg-swap`, `+grease`, `+ext:<id>`, `-ext:<id>`, `+group:<id>`,
//! `padding:<n>`, `no-padding`, `alpn-reverse`) so a difference in a verdict can
//! only come from that one change, and `hello` reads a ClientHello captured
//! anywhere else — a live browser, a uTLS build, a bundle `.hex` — and prints
//! its JA3/JA4 without needing a profile of ours or a network.
//! `tools/fingerprint/utls` produces such a capture from a named uTLS profile
//! (`go run . dump HelloChrome_133 -o capture.hex`), which is what a
//! circumvention tool puts on the wire — a different question from what a
//! browser sends. `diff <a.hex> <b.hex>` compares two captures field by field,
//! under the same rule `tools/fingerprint/fingerprint.py` applies in its
//! `hello_diff`, so a uTLS shape and ours can be told apart without Python, a
//! bundle or a network. `variant` needs a profile: the baseline (`rustls`)
//! presents none, so there is nothing to edit.
//!
//! Every `live` form takes an optional host list; `live`/`live13` pin TLS 1.3
//! (test 2's first column), `live12` pins 1.2, and `liveany` sends the browser's
//! own offer — the shape test 6's TLS 1.3 axis and tests 3/4 put on the wire, and
//! the one that can be compared with a bundle script run without version flags.
//! `peet` sends the profile's own h2 request and prints what the far side saw;
//! with `tls.peet.ws` (the default) that is the echo report, and with any other
//! host it is the profile's h2 request to that host — `GET /`, the same frames a
//! burst attempt sends — which is the mode to point at a real frontend.
//!
//! `--connect-to host:port=ip:port` makes the connection to `ip:port` while the
//! handshake still names `host` (curl's `--connect-to host:port:ip:port` spelled
//! with an `=`), so a probe can be aimed at a stand that taps the port without
//! changing the SNI or the `Host` the far side reads. A run that compares us with
//! the bundle must point both clients at the same host that way, or the two
//! hellos differ by the name they carry and the comparison measures that instead.
//! `headers` sends the profile's own header set over h1 to the host named on
//! the command line, which is the only way to see the header *names* — RFC 9113
//! lowercases every name over h2, so the casing a browser uses over h1 (a
//! fingerprint of its own) is invisible to every other mode.
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
//! Steps 1–6 below are scripted in `tools/fingerprint/`: `python
//! tools/fingerprint/fingerprint.py all` runs each of them for every profile and
//! prints the differences. Read the steps anyway — they are the reasons the tool
//! compares what it compares, and the two Safari bugs below are what happens when
//! one of them is skipped.
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
//! 7. Check that every handshake of the round is fresh. The session-ticket store
//!    lives in the `ClientConfig`, so a client that reuses one config across
//!    attempts resumes from the third one on: the hello grows by a
//!    `pre_shared_key` and stops being the shape the round claims to measure.
//!    Measured with the listener above, a round of five against a stand that
//!    sends tickets: attempt 1 = 517 bytes / 18 extensions, attempts 2–5 = 788
//!    bytes / 19 extensions with `pre_shared_key` (41). The bundle cannot show
//!    this — one curl process makes one connection — so it is invisible in every
//!    comparison against it.
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

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use dpi_core::net::fingerprint::{http_identity, HelloVariant, TlsFingerprint};
use dpi_core::net::tls::{create_tls_config, hello_record, hello_record_for, hello_record_with, TlsProfile, TlsVersion};
use dpi_core::net::{ja3, ja4};
use dpi_core::net::http::{request_headers, HttpRequest, HttpSender};
use http_body_util::BodyExt;
use hyper::Method;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// `padding` (RFC 7685): the extension a profile's `padding_to` floor writes, and
/// the one delta that can add a second JA4 to a shape.
const EXT_PADDING: u16 = 21;

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

/// The address override, `--connect-to host:port=ip:port`: the connection is made
/// to `ip:port` while the handshake still names `host`, so a probe can be pointed
/// at a local stand without changing the SNI or the `Host` the far side reads.
/// curl spells the same thing `--connect-to host:port:ip:port`; a run that puts
/// both clients through one tap needs the two to agree on the host they name.
#[derive(Clone, Debug)]
struct ConnectTo {
    host: String,
    port: u16,
    ip: String,
    ip_port: u16,
}

impl ConnectTo {
    fn parse(text: &str) -> Self {
        let (from, to) = text
            .split_once('=')
            .unwrap_or_else(|| panic!("--connect-to takes host:port=ip:port, got {text}"));
        let (host, port) = split_host_port(from);
        let (ip, ip_port) = split_host_port(to);
        Self { host: host.to_string(), port, ip: ip.to_string(), ip_port }
    }
}

/// Splits `host:port`, keeping an IPv6 literal's brackets out of the host.
fn split_host_port(text: &str) -> (&str, u16) {
    let (host, port) = text
        .rsplit_once(':')
        .unwrap_or_else(|| panic!("expected host:port, got {text}"));
    let port = port.parse().unwrap_or_else(|e| panic!("bad port in {text}: {e}"));
    (host.trim_start_matches('[').trim_end_matches(']'), port)
}

/// The address a probe dials for `host`:`port`, and the name the handshake must
/// still present — the override moves the connection, never the name, which is
/// the whole reason it exists.
fn dial_address<'a>(override_to: Option<&'a ConnectTo>, host: &'a str, port: u16) -> (&'a str, u16) {
    match override_to {
        Some(to) if to.host == host && to.port == port => (to.ip.as_str(), to.ip_port),
        _ => (host, port),
    }
}

/// Takes `--connect-to <spec>` (or `--connect-to=<spec>`) out of the arguments
/// wherever it sits, so a host list keeps its order around it.
fn take_connect_to(args: &mut Vec<String>) -> Option<ConnectTo> {
    let at = args.iter().position(|a| a == "--connect-to" || a.starts_with("--connect-to="))?;
    let arg = args.remove(at);
    let spec = match arg.split_once('=') {
        Some((_, spec)) => spec.to_string(),
        None => {
            assert!(at < args.len(), "--connect-to needs host:port=ip:port");
            args.remove(at)
        }
    };
    Some(ConnectTo::parse(&spec))
}

/// The config a probe dials with, with rustls' key log attached.
///
/// A tap shows the record boundaries of an exchange and nothing inside an
/// encrypted record, and the message a profile does or does not send after its
/// Finished is exactly the part that has to be read — so with `SSLKEYLOGFILE`
/// set, Wireshark decrypts both directions and the comparison stops being an
/// inference from record sizes. `KeyLogFile::new()` is inert when the variable
/// is unset, so the config is built the same way either way.
fn dial_config(profile: &TlsProfile) -> Arc<rustls::ClientConfig> {
    let mut config = (*create_tls_config(profile)).clone();
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    Arc::new(config)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "dump".into());
    let which = std::env::args().nth(2).unwrap_or_else(|| "firefox".into());
    let mut extra: Vec<String> = std::env::args().skip(3).collect();
    let connect_to = take_connect_to(&mut extra);

    // `hello` and `diff` take paths where every other mode takes a profile code,
    // and they need no config of ours at all: the bytes are the whole input.
    match mode.as_str() {
        "hello" => {
            hello_file(&which);
            return;
        }
        "replay" => {
            let host = extra.first().cloned().unwrap_or_else(|| panic!("replay takes a capture and a host"));
            replay(&which, &host, connect_to.as_ref()).await;
            return;
        }
        "diff" => {
            let b = extra
                .first()
                .unwrap_or_else(|| panic!("diff takes two capture paths: diff <a.hex> <b.hex>"));
            diff_files(&which, b);
            return;
        }
        _ => {}
    }

    let hosts: Vec<String> = if extra.is_empty() {
        HOSTS.iter().map(|h| (*h).to_string()).collect()
    } else {
        extra.clone()
    };
    let fingerprint =
        TlsFingerprint::parse(&which).expect("profile must be one of the codes --legend prints");

    match mode.as_str() {
        "dump" => dump(fingerprint, TlsVersion::Any),
        "dump13" => dump(fingerprint, TlsVersion::Tls13),
        "dump12" => dump(fingerprint, TlsVersion::Tls12),
        "dump-alpn" => dump_alpn(fingerprint, extra.first().map(String::as_str).unwrap_or("h1")),
        "dump-hex" => {
            // `dump-hex <profile> [sni] [variant]`: the name a capture is made
            // for is part of the shape — its length moves the padding — and so is
            // the edit, so both are arguments rather than assumptions.
            let variant = extra
                .get(1)
                .map(|text| HelloVariant::parse(text).expect("a variant the help lists"));
            let profile = profile_for(fingerprint, TlsVersion::Any);
            let record = match extra.first() {
                Some(sni) => hello_record_for(&profile, variant.as_ref(), sni),
                None => match variant.as_ref() {
                    Some(variant) => hello_record_with(&profile, Some(variant)),
                    None => client_hello(fingerprint, TlsVersion::Any),
                },
            };
            println!("{}", hex(&record));
        }
        "variant" => variant(fingerprint, extra.first().map(String::as_str).unwrap_or("sigalg-swap")),
        "live" => live(fingerprint, &hosts, TlsVersion::Tls13, connect_to.as_ref()).await,
        "live13" => live(fingerprint, &hosts, TlsVersion::Tls13, connect_to.as_ref()).await,
        "live12" => live(fingerprint, &hosts, TlsVersion::Tls12, connect_to.as_ref()).await,
        "liveany" => live(fingerprint, &hosts, TlsVersion::Any, connect_to.as_ref()).await,
        "peet" => {
            peet(
                fingerprint,
                hosts.first().map(String::as_str).unwrap_or("tls.peet.ws"),
                connect_to.as_ref(),
            )
            .await
        }
        "headers" => {
            headers(fingerprint, hosts.first().map(String::as_str).unwrap_or("localhost"), connect_to.as_ref())
                .await
        }
        other => panic!(
            "unknown mode {other}, expected dump|dump13|dump12|dump-alpn|variant|hello|diff|live|live13|live12|liveany|peet|headers"
        ),
    }
}

/// The profile a mode presents: `version` pins the offer where the mode pins one
/// (test 2's two columns, test 6's TLS axis), `Any` is the browser's own offer.
fn profile_for(fingerprint: TlsFingerprint, version: TlsVersion) -> TlsProfile {
    match version {
        TlsVersion::Tls12 => TlsProfile::insecure(fingerprint).tls12(),
        TlsVersion::Tls13 => TlsProfile::insecure(fingerprint).tls13(),
        TlsVersion::Any => TlsProfile::insecure(fingerprint),
    }
}

fn client_hello(fingerprint: TlsFingerprint, version: TlsVersion) -> Vec<u8> {
    // The crate's own builder, so the dump reflects the real wire shape
    // (the baseline compression policy, the version trim, the GREASE ECH body and
    // the padding floor drawn for this hello) rather than a hand-built config —
    // and so the hashes printed here are the ones `--legend` prints.
    hello_record(&profile_for(fingerprint, version))
}

/// `replay <capture.hex> <host>`: send a captured ClientHello from our own socket
/// and report what came back.
///
/// The question a profile cannot ask: whether a verdict belongs to the *bytes* or
/// to the client that sent them. The record goes out exactly as it was captured
/// and the handshake is never completed — there is no key material to continue it
/// — so the only answers are "the peer spoke" and "it stayed silent", which is
/// precisely what a middlebox decides on a ClientHello. A control is another
/// capture: the same shape replayed against the same host in the same window.
async fn replay(path: &str, host: &str, connect_to: Option<&ConnectTo>) {
    let (label, record) = capture(path);
    let (addr, port) = dial_address(connect_to, host, 443);
    println!("capture   = {label}");
    println!("record    = {} bytes, ja4 {}", record.len(), ja4::client_hello_ja4(&record));
    println!("target    = {host}, dialing {addr}:{port}");
    let mut tcp = match TcpStream::connect((addr, port)).await {
        Ok(stream) => stream,
        Err(err) => {
            println!("{host:22} TCP FAILED: {err}");
            return;
        }
    };
    if let Err(err) = tcp.write_all(&record).await {
        println!("{host:22} WRITE FAILED: {err}");
        return;
    }
    let started = Instant::now();
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(std::time::Duration::from_secs(8), tcp.read(&mut buf)).await {
        Ok(Ok(0)) => {
            println!("{host:22} closed without an answer ({} ms)", started.elapsed().as_millis())
        }
        Ok(Ok(n)) => println!(
            "{host:22} answered: {n} bytes, first record type {} ({} ms)",
            buf[0],
            started.elapsed().as_millis()
        ),
        Ok(Err(err)) => println!("{host:22} read failed: {err}"),
        Err(_) => println!(
            "{host:22} silent after the ClientHello ({} ms)",
            started.elapsed().as_millis()
        ),
    }
}

/// The record as lowercase hex, one line — what `hello` reads back, so a shape
/// can be saved, diffed and re-measured without a network:
/// `dump-hex chrome107 > capture.hex && hello capture.hex`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The dump every shape-printing mode shares: the record size, both hashes, and
/// the two lists neither hash names.
fn print_dump(title: &str, record: &[u8]) {
    println!("{title}");
    println!("record    = {} bytes", record.len() - 5);
    println!("ja3       = {}", ja3::client_hello_ja3(record));
    println!("ja4       = {}", ja4::client_hello_ja4(record));
    println!(
        "exts      = {}",
        ja3::extension_types(record)
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join("-")
    );
    println!("key_share = {}", ja3::key_share_groups(record));
}

fn dump(fingerprint: TlsFingerprint, version: TlsVersion) {
    let record = client_hello(fingerprint, version);
    print_dump(&format!("profile   = {}", fingerprint.code()), &record);
}

/// `dump-alpn <profile> <h2|h1|h1h2>`: the same hello with the ALPN offer pinned.
///
/// The pin moves the ALPN extension's body and JA4's two-character ALPN field and
/// nothing else, which is the point: `h1` turns `chrome107`'s
/// `t13d1516h2_8daaf6152771_e5627efa2ab1` into `t13d1516h1_8daaf6152771_e5627efa2ab1`
/// with the same cipher hash, the same extension hash, the same counts and the
/// same record size. `h1h2` keeps both protocols and reverses them, which moves
/// JA4's field to `h1` while the ALPN *list* still names h2.
fn dump_alpn(fingerprint: TlsFingerprint, alpn: &str) {
    let offered: Vec<Vec<u8>> = match alpn {
        "h2" | "http2" | "http/2" => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        "h1" | "http1.1" | "http/1.1" => vec![b"http/1.1".to_vec()],
        "h1h2" | "reverse" => vec![b"http/1.1".to_vec(), b"h2".to_vec()],
        other => panic!("unknown alpn {other}, expected h2|h1|h1h2"),
    };
    let record = hello_record(&profile_for(fingerprint, TlsVersion::Any).alpn(offered));
    print_dump(&format!("profile   = {} (alpn {alpn})", fingerprint.code()), &record);
}

/// `variant <profile> <delta>`: one delta off the profile's own hello.
///
/// The probes ask what a middlebox does with a shape; a variant asks what it
/// reads *in* one. Each delta changes exactly one thing, so a verdict or a hash
/// that moves can only have moved because of it:
///
/// * `sigalg-swap` — swaps the first two signature schemes. JA3 hashes extension
///   *types* and cannot see it; JA4 appends the schemes in wire order and changes.
/// * `+grease` — one more GREASE extension slot. Both hashes filter GREASE, so a
///   verdict that moves here means the matcher reads raw bytes rather than a hash.
/// * `+ext:<id>` / `-ext:<id>` — an unassigned extension added with an empty body,
///   or one dropped (and suppressed, so rustls does not re-add it later).
/// * `+group:<id>` — one more `supported_groups` entry, key share unchanged.
/// * `padding:<n>` / `no-padding` — the floor the 512-byte pad is computed from.
///   The JA4s cannot see the padding *length*, only the extension's presence.
/// * `alpn-reverse` — which protocol JA4 names, with the list untouched.
fn variant(fingerprint: TlsFingerprint, delta: &str) {
    let delta = HelloVariant::parse(delta).unwrap_or_else(|err| panic!("{err}"));
    let profile = profile_for(fingerprint, TlsVersion::Any);
    // A variant is a real hello: the edit goes through the same encoder the
    // probes use, so what is printed is what goes on the wire rather than a
    // second implementation of the encoder. The baseline presents no profile —
    // nothing to edit.
    let record = hello_record_with(&profile, Some(&delta));
    print_dump(&format!("profile   = {} ({})", fingerprint.code(), delta.name()), &record);
}

/// `hello <file>`: the hashes of a ClientHello captured elsewhere.
///
/// The input is hex — a `tcpdump`/Wireshark dump of the first flight, one of the
/// bundle's own `.hex` captures, a uTLS or live-browser recording — with
/// whitespace, `0x` prefixes and `#` comments ignored. A file that starts with
/// the handshake record type (`0x16`) is used as it is; anything else is a bare
/// handshake message and gets a record header, since both JA3 and JA4 read the
/// record as it would go on the wire.
///
/// This is the offline half of every comparison in the header above: it needs no
/// network, no profile of ours, and no echo service's opinion.
fn hello_file(path: &str) {
    let (_, record) = capture(path);
    print_dump(&format!("profile   = {path} (captured bytes)"), &record);
}

/// A capture file as `(label, record)`: the `#` header line when it has one (the
/// uTLS dumper writes one), the path otherwise, and the bytes with a record
/// header added when the file carries a bare handshake message.
fn capture(path: &str) -> (String, Vec<u8>) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|err| panic!("{path}: {err}"));
    let label = text
        .lines()
        .find_map(|line| line.strip_prefix('#').map(|rest| rest.trim().to_owned()))
        .unwrap_or_else(|| path.to_owned());
    let bytes = decode_hex(&text);
    let record = if bytes.first() == Some(&0x16) {
        bytes
    } else {
        let mut record = vec![0x16, 0x03, 0x01, (bytes.len() >> 8) as u8, bytes.len() as u8];
        record.extend_from_slice(&bytes);
        record
    };
    (label, record)
}

// ---------------------------------------------------------------------------
// `diff`: two captures, compared
// ---------------------------------------------------------------------------

/// Extension types `body_diff` branches on.
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_PRE_SHARED_KEY: u16 = 41;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_KEY_SHARE: u16 = 51;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 65037;

/// Bodies two hellos are never compared on: the name itself (0), an empty body
/// (5, 18, 23), a ticket that is fresh per connection (35), renegotiation (65281).
const BODIES_NOT_COMPARED: [u16; 6] = [0, 5, 18, 23, 35, 65281];

/// The payload lengths a GREASE ECH body declares: BoringSSL's four estimates of
/// an encoded inner hello, rounded to 32 (`setup_ech_grease()` in its
/// `ssl/encrypted_client_hello.cc`). Two independent draws from the same four are
/// the same shape; a body of any other size identifies the build.
const ECH_PAYLOAD_LENGTHS: [usize; 4] = [144, 176, 208, 240];

/// `diff <a.hex> <b.hex>`: two ClientHellos from anywhere, compared.
///
/// The rule is the one `tools/fingerprint/fingerprint.py` applies in its
/// `hello_diff`, so both tools agree on what "the same shape" means. What is new
/// here is the input: any two captures — ours, the bundle's, a uTLS build's, a
/// live browser's — with no network, no Python and no bundle.
fn diff_files(a_path: &str, b_path: &str) {
    let (a_label, a_record) = capture(a_path);
    let (b_label, b_record) = capture(b_path);
    let a = ja3::client_hello(&a_record).unwrap_or_else(|| panic!("{a_path}: not a ClientHello"));
    let b = ja3::client_hello(&b_record).unwrap_or_else(|| panic!("{b_path}: not a ClientHello"));

    println!("a          = {a_label}");
    println!("b          = {b_label}");
    println!("record     = a {} bytes, b {} bytes", a_record.len(), b_record.len());
    println!("ja3        = a {}", ja3::client_hello_ja3(&a_record));
    println!("             b {}", ja3::client_hello_ja3(&b_record));
    println!("ja4        = a {}", ja4::client_hello_ja4(&a_record));
    println!("             b {}", ja4::client_hello_ja4(&b_record));

    let mut found: Vec<String> = Vec::new();
    report(
        &mut found,
        a.record_version == b.record_version,
        "record version",
        &format!("{} vs {}", hex(&a.record_version), hex(&b.record_version)),
    );
    report(
        &mut found,
        a.legacy_version == b.legacy_version,
        "legacy version",
        &format!("{} vs {}", hex(&a.legacy_version), hex(&b.legacy_version)),
    );
    report(
        &mut found,
        a.session_id_len == b.session_id_len,
        "session id",
        &format!("length {} vs {}", a.session_id_len, b.session_id_len),
    );

    let (a_ciphers, b_ciphers) = (masked(a.ciphers.iter().copied()), masked(b.ciphers.iter().copied()));
    let same = a_ciphers == b_ciphers;
    report(&mut found, same, "ciphers", &format!("{} vs {}", a.ciphers.len(), b.ciphers.len()));
    if !same {
        println!("      a   {}", a_ciphers.join("-"));
        println!("      b   {}", b_ciphers.join("-"));
    }
    let same = a.compressions == b.compressions;
    report(&mut found, same, "compression", &format!("{} vs {}", a.compressions.len(), b.compressions.len()));
    if !same {
        println!("      a   {:?}", a.compressions);
        println!("      b   {:?}", b.compressions);
    }
    let (a_types, b_types) = (ext_types(&a), ext_types(&b));
    let mut a_set = a_types.clone();
    a_set.sort_unstable();
    let mut b_set = b_types.clone();
    b_set.sort_unstable();
    let same_set = a_set == b_set;
    // The set and the order are reported apart, the way the Python `hello_labels`
    // splits them: a shuffling profile permutes the same extensions on every
    // connection, so calling that "a missing extension" would be wrong.
    report(&mut found, same_set, "extensions", &format!("{} vs {}", a_types.len(), b_types.len()));
    if !same_set {
        println!("      a   {}", a_types.join("-"));
        println!("      b   {}", b_types.join("-"));
    } else {
        report(&mut found, a_types == b_types, "ext order", "");
    }

    // The bodies, which is what the hashes above cannot see. GREASE slots are
    // skipped here: their values are drawn per connection, and the extension list
    // above already reports a slot that only one side has.
    let a_bodies: BTreeMap<u16, &[u8]> =
        a.extensions.iter().map(|(kind, body)| (*kind, body.as_slice())).collect();
    let b_bodies: BTreeMap<u16, &[u8]> =
        b.extensions.iter().map(|(kind, body)| (*kind, body.as_slice())).collect();
    let mut kinds: Vec<u16> = a_bodies.keys().chain(b_bodies.keys()).copied().collect();
    kinds.sort_unstable();
    kinds.dedup();
    for kind in kinds.into_iter().filter(|kind| !ja3::is_grease(*kind)) {
        let label = format!("body {}", name(kind));
        match (a_bodies.get(&kind), b_bodies.get(&kind)) {
            (None, Some(body)) => report(&mut found, false, &label, &format!("only b ({} bytes)", body.len())),
            (Some(body), None) => report(&mut found, false, &label, &format!("only a ({} bytes)", body.len())),
            (Some(a_body), Some(b_body)) => {
                if let Some(what) = body_diff(kind, a_body, b_body) {
                    report(&mut found, false, &label, &what);
                }
            }
            // Not reachable: `kind` comes from the union of the two maps.
            (None, None) => unreachable!("kind comes from the union of both extension maps"),
        }
    }

    match found.len() {
        0 => println!("result     = SAME"),
        n => println!("result     = {n} difference(s): {}", found.join(", ")),
    }
}

/// One comparison line, and the label of a difference for the closing summary.
fn report(found: &mut Vec<String>, same: bool, label: &str, detail: &str) {
    println!("  {label:24} {:4}  {detail}", if same { "SAME" } else { "DIFF" });
    if !same {
        found.push(label.to_owned());
    }
}

/// What differs between two extension bodies, `None` when the difference is
/// per-connection randomness rather than shape.
fn body_diff(kind: u16, a: &[u8], b: &[u8]) -> Option<String> {
    if BODIES_NOT_COMPARED.contains(&kind) {
        return None;
    }
    match kind {
        EXT_ENCRYPTED_CLIENT_HELLO => {
            let (a_len, b_len) = (ech_payload_len(a), ech_payload_len(b));
            let drawn = |len: Option<usize>| len.is_some_and(|len| ECH_PAYLOAD_LENGTHS.contains(&len));
            (!(drawn(a_len) && drawn(b_len))).then(|| {
                format!("payloads {a_len:?} vs {b_len:?}, one of {ECH_PAYLOAD_LENGTHS:?} expected")
            })
        }
        EXT_PADDING | EXT_PRE_SHARED_KEY => {
            (a.len() != b.len()).then(|| format!("length {} vs {}", a.len(), b.len()))
        }
        EXT_KEY_SHARE => {
            let (a_shares, b_shares) = (key_shares(a), key_shares(b));
            (a_shares != b_shares).then(|| format!("{} vs {}", a_shares.join("-"), b_shares.join("-")))
        }
        EXT_SUPPORTED_GROUPS => list_diff(masked_u16s(a, 2), masked_u16s(b, 2), "groups"),
        EXT_SUPPORTED_VERSIONS => list_diff(masked_u16s(a, 1), masked_u16s(b, 1), "versions"),
        EXT_SIGNATURE_ALGORITHMS => list_diff(plain_u16s(a, 2), plain_u16s(b, 2), "schemes"),
        _ => (a != b).then(|| format!("{} vs {}", brief(a), brief(b))),
    }
}

/// `None` when two masked lists are equal, else what differs.
fn list_diff(a: Vec<String>, b: Vec<String>, what: &str) -> Option<String> {
    (a != b).then(|| format!("{what} {} vs {}", a.join("-"), b.join("-")))
}

/// The payload length a GREASE ECH body declares: `type(1) kdf(2) aead(2)
/// config_id(1) enc<2+len> payload<2+len>`, X25519, outer hello.
fn ech_payload_len(body: &[u8]) -> Option<usize> {
    for off in [1usize, 0] {
        if body.len() < off + 9 || body[off] != 0 || body[off + 1] != 1 {
            continue;
        }
        let enc_len = be16(body, off + 5)? as usize;
        if let Some(len) = be16(body, off + 7 + enc_len) {
            return Some(len as usize);
        }
    }
    None
}

/// `(group, key length)` pairs of a `key_share` body, GREASE masked: the key is
/// fresh per connection, its length is not.
fn key_shares(body: &[u8]) -> Vec<String> {
    let end = (2 + be16(body, 0).unwrap_or(0) as usize).min(body.len());
    let mut out = Vec::new();
    let mut at = 2;
    while at + 4 <= end {
        let group = be16(body, at).unwrap_or(0);
        let len = be16(body, at + 2).unwrap_or(0) as usize;
        let group = if ja3::is_grease(group) { "GREASE".to_owned() } else { format!("{group:#06x}") };
        out.push(format!("{group}:{len}"));
        at += 4 + len;
    }
    out
}

/// A `u16` list with GREASE masked, in decimal — the spelling `dump` prints
/// ciphers and extension types in. Two draws from the GREASE set are the same
/// shape, and the count is still compared.
fn masked(values: impl IntoIterator<Item = u16>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| if ja3::is_grease(value) { "GREASE".to_owned() } else { value.to_string() })
        .collect()
}

fn masked_u16s(body: &[u8], at: usize) -> Vec<String> {
    u16s(body, at).into_iter().map(mask).collect()
}

fn plain_u16s(body: &[u8], at: usize) -> Vec<String> {
    u16s(body, at).into_iter().map(|value| format!("{value:#06x}")).collect()
}

fn mask(value: u16) -> String {
    if ja3::is_grease(value) {
        "GREASE".to_owned()
    } else {
        format!("{value:#06x}")
    }
}

/// Every big-endian `u16` of `body` from `at`, stopping at a short tail.
fn u16s(body: &[u8], at: usize) -> Vec<u16> {
    let mut out = Vec::new();
    let mut at = at;
    while let Some(value) = be16(body, at) {
        out.push(value);
        at += 2;
    }
    out
}

/// A big-endian `u16` at `at`, `None` when the slice is short of one — the
/// fallible twin of the crate's own reader, because these bodies come from a
/// capture rather than from our builder.
fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

/// The extension types the rules above name, for the lines a reader has to
/// recognise; anything else is printed by number alone.
fn name(kind: u16) -> String {
    let known = match kind {
        EXT_PADDING => "padding",
        EXT_SUPPORTED_GROUPS => "supported_groups",
        EXT_SIGNATURE_ALGORITHMS => "signature_algorithms",
        EXT_PRE_SHARED_KEY => "pre_shared_key",
        EXT_SUPPORTED_VERSIONS => "supported_versions",
        EXT_KEY_SHARE => "key_share",
        EXT_ENCRYPTED_CLIENT_HELLO => "encrypted_client_hello",
        _ => return kind.to_string(),
    };
    format!("{kind} ({known})")
}

/// Extension types of a hello, in wire order, GREASE masked.
fn ext_types(hello: &ja3::ClientHello) -> Vec<String> {
    masked(hello.extensions.iter().map(|(kind, _)| *kind))
}

/// A body as hex, cut short: a body no rule above names is short, and a long one
/// would bury the line it appears on.
fn brief(body: &[u8]) -> String {
    const LIMIT: usize = 48;
    if body.len() <= LIMIT {
        return hex(body);
    }
    format!("{}... ({} bytes)", hex(&body[..LIMIT]), body.len())
}

/// The hex in `text`, ignoring whitespace, `0x` prefixes and `#` comments.
fn decode_hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .flat_map(|line| line.chars())
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c as u8)
        .collect();
    let (pairs, remainder) = digits.as_chunks::<2>();
    assert!(remainder.is_empty(), "hex input has an odd number of digits");
    pairs
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hex digits are ASCII");
            u8::from_str_radix(pair, 16).expect("filtered to hex digits")
        })
        .collect()
}

async fn live(
    fingerprint: TlsFingerprint,
    hosts: &[String],
    version: TlsVersion,
    connect_to: Option<&ConnectTo>,
) {
    let config = dial_config(&profile_for(fingerprint, version));
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
        let (addr, port) = dial_address(connect_to, host, 443);
        if addr != host {
            println!("{host:22} dialing {addr}:{port}, SNI stays {host}");
        }
        let tcp = match TcpStream::connect((addr, port)).await {
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

/// The profile's own header set over HTTP/1.1, to `host:443`.
///
/// `live` sends a hand-written request, which is enough for the TLS hashes but
/// says nothing about the HTTP layer, and `peet` measures the h2 shape, where
/// RFC 9113 lowercases every header name and hides the casing a browser uses
/// over h1. This mode sends [`request_headers`] — the same identity the probes
/// send — down an h1 connection, so a local listener can compare the request
/// block with the bundle's (`tools/fingerprint/fingerprint.py headers`).
async fn headers(fingerprint: TlsFingerprint, host: &str, connect_to: Option<&ConnectTo>) {
    let config = dial_config(&TlsProfile::insecure(fingerprint));
    let (addr, port) = dial_address(connect_to, host, 443);
    if addr != host {
        println!("{host:22} dialing {addr}:{port}, SNI stays {host}");
    }
    let tcp = match TcpStream::connect((addr, port)).await {
        Ok(stream) => stream,
        Err(e) => return println!("{host:22} TCP FAILED: {e}"),
    };
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).expect("valid host");
    let tls = match TlsConnector::from(config).connect(name, tcp).await {
        Ok(stream) => stream,
        Err(e) => return println!("{host:22} HANDSHAKE FAILED: {e}"),
    };
    // h1 whatever ALPN says: this mode exists to see the h1 request block.
    let mut sender = match HttpSender::handshake(TokioIo::new(tls), false, fingerprint).await {
        Ok(sender) => sender,
        Err(e) => return println!("HTTP handshake failed: {e}"),
    };
    let identity = http_identity(fingerprint);
    let user_agent = identity.user_agent.unwrap_or("");
    let request = HttpRequest {
        method: Method::GET,
        host,
        path: "/",
        headers: request_headers(&identity, user_agent, Vec::new(), false),
        priority_on_h1: identity.priority_on_h1,
    };
    println!("profile   = {} -> {host} over HTTP/1.1", fingerprint.code());
    match sender.send(request).await {
        Ok(response) => println!("{host:22} {}", response.status()),
        Err(e) => println!("{host:22} request failed: {e}"),
    }
}

/// The echo service, through the path the probes themselves use: the profile's
/// TLS hello, its ALPN, its HTTP/2 preface and request shape, and its header
/// list. `live` measures our TLS shape with a hand-written HTTP/1.1 request,
/// which is enough for the TLS hashes but leaves the service no HTTP/2 frames
/// to report — the akamai fingerprint needs this one.
///
/// Any other host takes the same path — the profile's own h2 request, `GET /`,
/// headers and all — which is what a burst attempt sends, and the reason this
/// mode is the one to point at a real frontend through a tap (`--connect-to`).
async fn peet(fingerprint: TlsFingerprint, host: &str, connect_to: Option<&ConnectTo>) {
    let echo = host == "tls.peet.ws";
    let config = dial_config(&TlsProfile::insecure(fingerprint));
    let (addr, port) = dial_address(connect_to, host, 443);
    if addr != host {
        println!("{host:22} dialing {addr}:{port}, SNI stays {host}");
    }
    let tcp = match TcpStream::connect((addr, port)).await {
        Ok(stream) => stream,
        Err(e) => return println!("{host:22} TCP FAILED: {e}"),
    };
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).expect("valid host");
    let tls = match TlsConnector::from(config).connect(name, tcp).await {
        Ok(stream) => stream,
        Err(e) => return println!("{host:22} HANDSHAKE FAILED: {e}"),
    };
    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    println!("profile   = {} (the browser's own offer)", fingerprint.code());
    println!("{host:22} alpn={}", if h2 { "h2" } else { "http/1.1" });
    let mut sender = match HttpSender::handshake(TokioIo::new(tls), h2, fingerprint).await {
        Ok(sender) => sender,
        Err(e) => return println!("HTTP handshake failed: {e}"),
    };
    let identity = http_identity(fingerprint);
    let user_agent = identity.user_agent.unwrap_or("");
    let request = HttpRequest {
        method: Method::GET,
        host,
        path: if echo { "/api/all" } else { "/" },
        headers: request_headers(&identity, user_agent, Vec::new(), false),
        priority_on_h1: identity.priority_on_h1,
    };
    let response = match sender.send(request).await {
        Ok(response) => response,
        Err(e) => return println!("request failed: {e}"),
    };
    let status = response.status();
    let body = match response.into_body().collect().await {
        Ok(body) => body.to_bytes(),
        Err(e) => return println!("body failed: {e}"),
    };
    if !echo {
        return println!("{host:22} {status}, {} bytes", body.len());
    }
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
///
/// Every frame the service received is printed, not only the headers: the
/// preface's `SETTINGS` payload and its order, the `WINDOW_UPDATE` increment and
/// the priority a `HEADERS` frame carries are the rest of the h2 shape, and a
/// comparison that reads only the akamai string cannot tell whether the request
/// went out with the priority flag the wrapper names.
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
    let Some(frames) = http2.get("sent_frames").and_then(|frames| frames.as_array()) else {
        return;
    };
    for frame in frames {
        let kind = frame.get("frame_type").and_then(|k| k.as_str()).unwrap_or("?");
        let mut shape = String::new();
        if let Some(settings) = frame.get("settings").and_then(|s| s.as_array()) {
            shape.push_str(
                &settings
                    .iter()
                    .filter_map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(";"),
            );
        }
        if let Some(increment) = frame.get("increment") {
            shape.push_str(&format!("increment {increment}"));
        }
        if let Some(flags) = frame.get("flags").and_then(|f| f.as_array()) {
            shape.push_str(
                &flags
                    .iter()
                    .filter_map(|f| f.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if let Some(priority) = frame.get("priority") {
            shape.push_str(&format!(
                " weight {} depends_on {} exclusive {}",
                priority.get("weight").and_then(|w| w.as_u64()).unwrap_or(0),
                priority.get("depends_on").and_then(|d| d.as_u64()).unwrap_or(0),
                priority.get("exclusive").and_then(|e| e.as_u64()).unwrap_or(0),
            ));
        }
        println!("   {kind} {shape}");
        if let Some(headers) = frame.get("headers").and_then(|h| h.as_array()) {
            for header in headers {
                println!("   HEADERS {}", header.as_str().unwrap_or(""));
            }
        }
    }
}

