//! Fingerprint profiles: the TLS and HTTP shape a probe presents.
//!
//! # Why this exists
//!
//! Russian censorship (see the "сибирское ограничение" scheme) classifies TLS
//! clients by their ClientHello: Chrome/Safari/iOS-shaped fingerprints are
//! treated as suspicious, Firefox-shaped ones usually are not. A detector that
//! only ever presents one shape — rustls' own — cannot tell whether a block it
//! observes is caused by the destination or by its own fingerprint.
//!
//! # How a profile is written
//!
//! A profile is **data**, not code: one record in [`shapes::SHAPES`] holds its
//! names, its provenance and its TLS lists, and one entry in
//! [`TlsFingerprint::ALL`] makes it selectable. The HTTP identity
//! ([`identity`]) and the HTTP/2 preface ([`h2`]) are the same kind of record,
//! referenced from the row. Nothing else enumerates the variants — the parsers,
//! the builder, `--legend` and the profile-subset-of-provider gate all read the
//! table.
//!
//! * [`TlsFingerprint::Rustls`] — the untouched default. Every measurement the
//!   tool has ever taken was taken with this, so it stays the baseline.
//! * [`TlsFingerprint::Firefox`], [`TlsFingerprint::Chrome`],
//!   [`TlsFingerprint::Safari`] — the shapes the Russian TSPU has been
//!   *reported* to block, and the Firefox-shaped client reportedly not to: the
//!   JA3s of the `curl-impersonate` bundles the forum report names. They exist
//!   to answer "is this site blocked for me, or only for clients that look like
//!   `curl_chrome107`?".
//! * [`TlsFingerprint::Chrome133`], [`TlsFingerprint::Safari18`],
//!   [`TlsFingerprint::Edge`] — current releases of the same clients: Chrome
//!   133's hello is a different shape (hybrid post-quantum group, ALPS at its
//!   new code point), while Safari 18 and Edge send the TLS shape their older
//!   rows already reproduce behind a current identity.
//!
//! # What "shape" means here
//!
//! Three layers, all taken from the same `curl-impersonate` wrapper, so a probe
//! that looks like `curl_chrome107` in one of them looks like it in all:
//!
//! * **TLS** — cipher-suite list and order, `supported_groups`,
//!   `signature_algorithms`, ALPN, exact extension order, extensions rustls does
//!   not normally emit, and the hybrid `X25519MLKEM768` group. That is what JA3
//!   and JA4 hash; the tests pin both against the bundle.
//! * **HTTP** — the `User-Agent` and header set of the impersonated client, in
//!   its order ([`http_identity`]), `accept-encoding` included; the byte-counting
//!   probes override that one header to `identity` (see there). A `user_agent`
//!   set in `config.yml` wins over the profile's.
//! * **HTTP/2** — the `SETTINGS` values, which of them are sent, and the
//!   connection window that becomes the `WINDOW_UPDATE` increment
//!   ([`h2_fingerprint`]).
//!
//! It is **not** a byte-for-byte browser. What is left, and why:
//!
//! * ECH is omitted entirely (see [`shapes`] — synthesizing it makes Google and
//!   Cloudflare abort the handshake), and record-layer splitting is rustls'.
//! * A hello whose version is pinned for isolation — test 2's two columns and
//!   test 6's TLS 1.2 axis — advertises one version where the client it
//!   imitates sends two or more (`[GREASE, 0x0304]` instead of
//!   `[GREASE, 0x0304, 0x0303, 0x0302, 0x0301]`): rustls writes
//!   `supported_versions` from the config, and a build that cannot speak 1.2
//!   must not claim it. JA3 and JA4 do not hash versions; a middlebox reading the
//!   body can. Everywhere else — tests 3 and 4, and test 6's TLS 1.3 axis, which
//!   is the one that asks whether a *browser shape* is blocked — the offer is
//!   the browser's own, fallbacks included: Safari 15.5 lists TLS 1.1 and 1.0
//!   behind 1.2 (`legacy_versions`), and a peer that actually selects one is
//!   refused by the config and reported `NO TLS1.3`, not as a block.
//! * HTTP/2 pseudo-headers are ordered `m,s,a,p` (hyper's order; the clients
//!   send `m,a,s,p` for Chrome, `m,p,a,s` for Firefox, `m,s,p,a` for Safari) and
//!   the request `HEADERS` frame carries no priority (h2 0.4 dropped priority
//!   support; Chrome weight 256 / exclusive, Firefox 42 / 0, Safari 255 / 0).
//!
//! Measured against `tls.peet.ws` the TLS hashes, the header list and order, the
//! UA and the whole HTTP/2 `SETTINGS`/`WINDOW_UPDATE` pair match the bundle
//! exactly; `peetprint` — which folds in the priority and the pseudo-header
//! order — does not.
//!
//! # Adding a profile
//!
//! Write the record, add the alias set and the `curl_*` names it reproduces,
//! pin its JA3 **and** JA4 against the source the record claims, and run
//! `examples/tls_fingerprint.rs` (`dump`, then `live`). The gate in
//! `tests::every_advertised_code_point_is_served_or_named` refuses a record
//! whose cipher, group or signature scheme this build cannot serve unless the
//! gap is named and has a reason — the provider is the second half of a
//! profile, and a shape it cannot execute is a shape the probe does not send.

mod h2;
mod identity;
mod shapes;

#[cfg(test)]
mod tests;

use std::sync::{Arc, LazyLock};

use rustls::client::ClientHelloProfile;
use rustls::ClientConfig;

use crate::net::tls::TlsVersion;

pub use h2::{h2_fingerprint, H2Fingerprint};
pub use identity::{http_identity, HttpIdentity};

use shapes::{TlsShape, SHAPES};

/// Which ClientHello shape the probes present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsFingerprint {
    /// Untouched rustls: the historical baseline.
    #[default]
    Rustls,
    /// `curl_firefox133`-shaped: Firefox 133's own ClientHello.
    Firefox,
    /// `curl_chrome99..116` / `curl_edge99,101`-shaped (reported TSPU trigger).
    Chrome,
    /// `curl_safari15.5..18.4`-shaped (reported TSPU trigger).
    Safari,
    /// `curl_chrome133a`-shaped: the newest Chrome the bundle reproduces.
    Chrome133,
    /// `curl_safari180`-shaped: Safari 18.0 — the same hello as [`Self::Safari`],
    /// the identity and preface of the current release.
    Safari18,
    /// `curl_edge99,101`-shaped: Chromium's hello behind Edge's identity.
    Edge,
}

impl TlsFingerprint {
    /// This profile's record. `SHAPES` holds one row per variant, which
    /// `tests::fingerprint_table_is_total` pins in both directions: a variant
    /// without a row is a suite failure, not a silent fallback.
    fn spec(self) -> &'static TlsShape {
        &SHAPES[shape_index(self)]
    }

    /// Canonical uppercase token for tables and logs. Never translated (rule 4).
    pub fn token(self) -> &'static str {
        self.spec().token
    }

    /// Token plus the version it reproduces ("CHROME 107"). Latin like `token`
    /// and never translated (rule 4): a table header or a progress line that
    /// says only "CHROME" hides which shape was actually sent.
    pub fn display_label(self) -> &'static str {
        self.spec().label
    }

    /// Stable value for machine JSON and the config file.
    pub fn code(self) -> &'static str {
        self.spec().code
    }

    /// Where the shape's numbers came from, version included. Reads in
    /// `--legend`, and is what makes a pin re-measurable instead of folklore.
    pub fn source(self) -> &'static str {
        self.spec().source
    }

    /// Parses a configured value. `None` for anything unknown, so callers can
    /// warn and fall back instead of silently changing what gets measured.
    ///
    /// Both the canonical names and the `curl-impersonate` ones are accepted,
    /// the latter only where this build reproduces the shape they name: a
    /// bundle profile whose JA3 differs (`curl_chrome110+` shuffles the
    /// extension order, `curl_safari260` offers the post-quantum group,
    /// `curl_firefox135+` adds SCT) is rejected rather than mapped to a
    /// neighbouring profile.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim().to_ascii_lowercase();
        SHAPES
            .iter()
            .find(|shape| shape.matches_name(&value))
            .map(|shape| shape.variant)
    }

    /// Values accepted by the config validator and the CLI, in report order.
    ///
    /// The single hand-written list on this side of the table: `spec()` panics
    /// on a variant missing from `SHAPES`, and the totality test compares this
    /// list with the table, so the two cannot drift apart unnoticed.
    pub const ALL: [TlsFingerprint; 7] = [
        Self::Rustls,
        Self::Firefox,
        Self::Chrome,
        Self::Safari,
        Self::Chrome133,
        Self::Safari18,
        Self::Edge,
    ];

    /// The profiles a run presents when nothing asked for a specific set: test
    /// 6 with no `--burst-profiles`, and the same default behind the menu.
    ///
    /// Kept apart from [`Self::ALL`] because the network budget of test 6 is
    /// `profiles × hosts × 2 version axes`: every shape added here is paid for
    /// on every run, so a profile joins the default set deliberately and `all`
    /// stays the explicit way to ask for everything, however many that is.
    pub const DEFAULT_SET: [TlsFingerprint; 7] = [
        Self::Rustls,
        Self::Firefox,
        Self::Chrome,
        Self::Safari,
        Self::Chrome133,
        Self::Safari18,
        Self::Edge,
    ];

    /// Parses a profile list for test 6: `all`, or comma/space separated names
    /// (including the `curl_*` aliases). Unknown tokens come back separately so
    /// the caller can warn instead of silently running a different test than the
    /// one that was asked for; an empty or all-unknown list means `all`.
    pub fn parse_list(value: &str) -> (Vec<Self>, Vec<String>) {
        let mut out: Vec<Self> = Vec::new();
        let mut unknown: Vec<String> = Vec::new();
        let mut all = false;
        for token in value.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if token.eq_ignore_ascii_case("all") {
                all = true;
                continue;
            }
            match Self::parse(token) {
                Some(fingerprint) => {
                    if !out.contains(&fingerprint) {
                        out.push(fingerprint);
                    }
                }
                None => unknown.push(token.to_string()),
            }
        }
        if all || out.is_empty() {
            out = Self::ALL.to_vec();
            if !all {
                // Nothing recognised at all is a mistake, not a request for all.
                unknown.clear();
                unknown.push(value.trim().to_string());
            }
        }
        (out, unknown)
    }
}

impl std::fmt::Display for TlsFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

/// The index of a variant's record. Every variant has one.
fn shape_index(fingerprint: TlsFingerprint) -> usize {
    SHAPES
        .iter()
        .position(|shape| shape.variant == fingerprint)
        .expect("every variant has a shape record")
}

/// The ClientHello profile of `fingerprint`, `None` for the baseline.
///
/// Built once per profile per process: `create_tls_config` runs for every
/// connection a probe opens, and the profile is a handful of heap vectors that
/// would otherwise be rebuilt for each one.
pub fn hello_profile(fingerprint: TlsFingerprint) -> Option<Arc<ClientHelloProfile>> {
    static CACHE: LazyLock<Vec<Option<Arc<ClientHelloProfile>>>> =
        LazyLock::new(|| SHAPES.iter().map(|shape| shape.build().map(Arc::new)).collect());
    CACHE[shape_index(fingerprint)].clone()
}

/// True when the profile needs the post-quantum provider, so the advertised
/// group list and the actual key share agree.
///
/// Only the shapes that offer `X25519MLKEM768`: the curl shapes pinned to
/// Chrome 99–116 / Safari 15.5–18.4 predate it, and adding a group the original
/// does not send would change the fingerprint being reproduced.
pub fn needs_pq(fingerprint: TlsFingerprint) -> bool {
    fingerprint.spec().pq
}

/// True when this selection advertises `compress_certificate` (extension 27).
///
/// The decompressors behind it are ours, not rustls's features (see
/// [`crate::net::cert_compression`]), and the decompressor list is exactly what
/// makes rustls offer the extension. Installing it for every profile would
/// advertise extension 27 in *every* ClientHello — a silent change to the
/// baseline fingerprint that all previous measurements were taken with — so the
/// default profile keeps rustls's empty list and sends the wire shape this tool
/// has always sent.
pub fn advertises_cert_compression(fingerprint: TlsFingerprint) -> bool {
    !fingerprint.spec().cert_compression.is_empty()
}

/// The extensions a browser leaves out of a hello that offers one version alone.
///
/// A ClientHello is not one fixed set: a client offering a single version drops
/// what belongs to the other one, and the pinned hello this tool sends is what a
/// probe column measures. Read off the `curl-impersonate` bundles pinned the
/// same way (`--tlsv1.3 --tls-max 1.3`, `--tls-max 1.2`):
///
/// * no 1.3-only hello carries `ec_point_formats`, Chrome 107 and Safari 15.5
///   also drop `extended_master_secret` and `renegotiation_info`, and Chrome
///   drops `session_ticket`;
/// * no 1.2-only hello carries `supported_versions`, and none carries padding —
///   the extension exists to lift a hello over 256 bytes, and a 1.2 hello is
///   already under that floor, which is where BoringSSL stops padding — nor ALPS
///   (17513), a 1.3 extension.
///
/// Firefox 133 keeps `extended_master_secret` and `renegotiation_info` at 1.3,
/// which is why the lists are per record (`drop13`/`drop12`) rather than one
/// rule for all of them.
///
/// Without it a pinned hello advertises one version while still carrying the
/// other's extensions and cipher suites — a shape no client sends. Measured on
/// `standby-rezka.tv`: Chrome 107 and Safari 15.5 pinned to 1.3 got
/// `alert_illegal_parameter`, while the same shapes from the pinned bundle —
/// which drops these — got `200`.
pub fn pinned_drop(fingerprint: TlsFingerprint, version: TlsVersion) -> &'static [u16] {
    let shape = fingerprint.spec();
    match version {
        TlsVersion::Tls13 => shape.drop13,
        TlsVersion::Tls12 => shape.drop12,
        TlsVersion::Any => &[],
    }
}

/// Installs the profile on a client config, if the selection has one.
pub fn apply(config: &mut ClientConfig, fingerprint: TlsFingerprint) {
    config.hello_profile = hello_profile(fingerprint);
}
