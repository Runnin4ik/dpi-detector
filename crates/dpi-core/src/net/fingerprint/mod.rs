//! Fingerprint profiles: the TLS and HTTP shape a probe presents.
//!
//! # Why this exists
//!
//! Russian censorship (see the "сибирское ограничение" scheme) classifies TLS
//! clients by their ClientHello. What a censor on the path carries is a *table of
//! keys*, one per shape it refuses: a shape is answered with a reset when the JA4
//! it sends — `--legend` prints every one of them — is in that table, and the
//! entries measured so far are the generations a live client no longer sends:
//! Chrome before ECH, Safari 15.3–18.4, and the Firefox-ESR shape the Tor wrapper
//! reproduces. Two things follow, and both shape this module: a shape that
//! shuffles its extension order is caught all the same, because the key is
//! order-insensitive, and the way out of the table is another *generation*, not
//! another order or one more extension. A detector that only ever presents one
//! shape — rustls' own — cannot tell whether a block it observes is caused by the
//! destination or by its own fingerprint.
//!
//! # How a profile is written
//!
//! A profile is **data**, not code: one record in `shapes::SHAPES` holds its
//! names, its provenance and its TLS lists, and one entry in
//! [`TlsFingerprint::ALL`] makes it selectable. The HTTP identity
//! (`identity`) and the HTTP/2 preface (`h2`) are the same kind of record,
//! referenced from the row. Nothing else enumerates the variants — the parsers,
//! the builder, `--legend` and the profile-subset-of-provider gate all read the
//! table.
//!
//! * [`TlsFingerprint::Rustls`] — the untouched default. Every measurement the
//!   tool has ever taken was taken with this, so it stays the baseline.
//! * [`TlsFingerprint::Chrome107`], [`TlsFingerprint::Safari155`],
//!   [`TlsFingerprint::Tor145`] — the shapes the Russian TSPU has been
//!   *reported* to block: the JA3s of the `curl-impersonate` bundles the forum
//!   report names. Measured, the report's family list holds — Chrome 99–107 and
//!   116, Edge 99–101 and Safari 15.3–18.4 were refused on every attempt, and so
//!   was the Tor row — while the clients it expected to pass did pass
//!   (`firefox133`, `firefox147`, and the newest Safari and Chrome). They exist
//!   to answer "is this site blocked for me, or only for clients that look like
//!   `curl_chrome107`?".
//! * [`TlsFingerprint::Chrome146`] — current releases of the same client: Chrome
//!   133's hello is a different shape (hybrid post-quantum group, ALPS at its new
//!   code point), which is why the newest generation answers with a key the table
//!   does not carry. [`TlsFingerprint::Safari180`] and
//!   [`TlsFingerprint::Edge101`] send the TLS shape their older rows already
//!   reproduce, behind a current identity.
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
//! * The eight shapes whose client sends `encrypted_client_hello` send it as
//!   GREASE, because that is what their own references send: curl needs DoH or
//!   an explicit `--ecl:` for a real ECHConfigList and no wrapper passes
//!   either, and the eighth — `firefox120`, whose reference is the uTLS ladder
//!   rather than a wrapper — sends it as GREASE in its own spec
//!   (`net::tls` installs `EchMode::Grease`, `net::hpke` is the HPKE suite
//!   behind it). A real config would have to come from the target's own HTTPS
//!   record, which is per *host* where every other field of a record is per
//!   *client* — and the reference client does not do it. The extension's body is
//!   rebuilt per connection, so its bytes are never comparable: `enc` is a fresh
//!   ephemeral key and the payload is random. Its *length* is, and it is drawn
//!   from the same four values BoringSSL draws from — 128, 160, 192 or 224 bytes
//!   of estimated inner hello, each rounded to 32, plus the AEAD tag — so a body
//!   of any other size would be a stable identifier of this build.
//! * A Chrome 110 or later profile shuffles its extension order per connection,
//!   as the browser does (`TlsShape::permute_extensions`), so its JA3 is one
//!   sample of a distribution and JA4 — which hashes the sorted set — is the
//!   stable key. The order is the only thing that moves: the set, the ciphers,
//!   the groups, the signature schemes, the key shares a `--tls-key-shares-limit`
//!   asks for, the h2 preface including the settings Safari names and the
//!   request's priority are the client's own.
//! * `chrome123` and `chrome131android` are the only shapes whose hello can fall
//!   under the 512-byte floor a browser pads to — 497 bytes with the shortest
//!   GREASE ECH body — and both are padded there the way BoringSSL does it: the
//!   padding slot counts the extensions that follow it (the ECH the encoder
//!   appends last), so the message lands on 512 exactly, and the other three body
//!   lengths leave it above the floor with no padding at all. Both outcomes are
//!   the client's own: it pads on one connection in four.
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
//!
//! Measured against `tls.peet.ws` with `tools/fingerprint/`, the TLS hashes, the
//! header list and order, the UA, the whole HTTP/2 `SETTINGS`/`WINDOW_UPDATE`
//! pair, the pseudo-header order, the priority, and the HTTP/1.1 request block
//! with its header spellings match the bundle exactly on every profile whose
//! extension order is fixed. On the five that shuffle, JA4 matches and JA3 does
//! not — the bundle's own JA3 moves per connection for the same reason.
//!
//! # Adding a profile
//!
//! Write the record, pin its JA3 **and** JA4 against the source the record
//! claims, and run `python tools/fingerprint/fingerprint.py all <code>` — it
//! drives the bundle the record copies and diffs the two clients three ways. The
//! gate in `tests::every_advertised_code_point_is_served_or_named` refuses a
//! record whose cipher, group or signature scheme this build cannot serve unless
//! the gap is named and has a reason — the provider is the second half of a
//! profile, and a shape it cannot execute is a shape the probe does not send.

mod h2;
mod identity;
mod shapes;
mod variant;

#[cfg(test)]
mod tests;

use std::sync::{Arc, LazyLock};

use rustls::client::ClientHelloProfile;
use rustls::ClientConfig;

use crate::net::tls::TlsVersion;

pub use h2::{h2_fingerprint, H2Fingerprint};
pub use identity::{http_identity, HttpIdentity};
pub use variant::{install_variant, HelloVariant};

pub(crate) use shapes::{
    EXT_APPLICATION_SETTINGS, EXT_APPLICATION_SETTINGS_NEW, EXT_FAKE_CHANNEL_ID,
};
use shapes::{TlsShape, SHAPES};

/// Which ClientHello shape the probes present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsFingerprint {
    /// Untouched rustls: the historical baseline.
    #[default]
    Rustls,
    /// Firefox 133's own ClientHello (`curl_firefox133` in the bundle).
    Firefox133,
    /// Chrome 107's (`curl_chrome107`): the reported TSPU trigger.
    Chrome107,
    /// Chrome 87's own ClientHello (uTLS `HelloChrome_87`), also Chrome 83's.
    Chrome87,
    /// Chrome 72's own ClientHello (uTLS `HelloChrome_72`).
    Chrome72,
    /// Chrome 70's own ClientHello (uTLS `HelloChrome_70`), also 360Browser 11.0's.
    Chrome70,
    /// Safari 15.5's (`curl_safari155`), 20 ciphers and no `zstd`.
    Safari155,
    /// Safari 18.0's (`curl_safari180`): Safari 15.5's hello with the 18.x
    /// signature schemes, the newer identity and Safari's own preface.
    Safari180,
    /// Edge 101's (`curl_edge101`): Chromium's hello behind Edge's identity.
    Edge101,
    /// Chrome 99's on Android (`curl_chrome99_android`): Chrome 107's hello
    /// behind a Pixel 6's identity.
    Chrome99Android,
    /// Chrome 115's post-quantum ClientHello (uTLS `HelloChrome_115_PQ`).
    Chrome115Pq,
    /// Chrome 116's (`curl_chrome116`): Chrome 107's hello with the extension
    /// order shuffled, which Chromium turned on at 110 and has kept since.
    Chrome116,
    /// Chrome 123's (`curl_chrome123`): the first release here whose hello
    /// carries ECH (as GREASE) and shuffles its extension order per connection.
    /// Chrome 119 through 123 send this one hello; the record carries the newest
    /// identity, whose `accept-encoding` gained `zstd` at this release.
    Chrome123,
    /// Chrome 131's (`curl_chrome131`): the hybrid group, ALPS at 17513.
    Chrome131,
    /// Chrome 131's on Android (`curl_chrome131_android`): the same shape
    /// without the hybrid group, behind the phone's identity.
    Chrome131Android,
    /// Chrome 146's (`curl_chrome146`): the newest desktop Chromium in the
    /// bundle. Chrome 133 through 146 send one hello — same JA4, same extension
    /// set, same h2 preface — so a single record covers them, under the newest
    /// identity; keeping four names for it would only multiply the report.
    Chrome146,
    /// Chrome 133's (`curl_chrome133a`): Chrome 146's hello under the 133
    /// identity. The bundle sends one hello for 133 through 146, so this record
    /// is a deliberate second name for it — the one that asks whether a censor's
    /// table reads the identity or the ClientHello.
    Chrome133,
    /// Firefox 147's (`curl_firefox147`): Firefox 133's hello plus a certificate
    /// timestamp extension. Firefox 135, 144 and 147 send this one hello, so the
    /// record carries the newest identity.
    Firefox147,
    /// Firefox 120's own ClientHello (uTLS `HelloFirefox_120`).
    Firefox120,
    /// Firefox 105's own ClientHello (uTLS `HelloFirefox_105`).
    Firefox105,
    /// Firefox 99's own ClientHello (uTLS `HelloFirefox_99`).
    Firefox99,
    /// Firefox 65's own ClientHello (uTLS `HelloFirefox_65`).
    Firefox65,
    /// Go 1.27's `crypto/tls` ClientHello, through uTLS `HelloGolang`.
    Go127,
    /// Safari 15.3's (`curl_safari153`): 15.5's hello with six more suites and
    /// no `compress_certificate`.
    Safari153,
    /// Safari 17.0's (`curl_safari170`): Safari 15.5's hello with
    /// `SETTINGS_ENABLE_PUSH` ahead of the rest and 17.0's fuller identity.
    Safari170,
    /// Safari 17.2's on iOS (`curl_safari172_ios`): 17.0's shape with a 2 MiB
    /// stream window behind the phone's identity.
    Safari172Ios,
    /// Safari 18.4's on iOS (`curl_safari184_ios`): Safari 18's hello behind an
    /// iPhone's identity.
    Safari184Ios,
    /// Safari 26.0's (`curl_safari260`): the hybrid group, no padding and no
    /// request priority.
    Safari260,
    /// Safari 26.0's on iOS (`curl_safari260_ios`): X25519 first, padding back.
    Safari260Ios,
    /// Tor Browser 14.5's (`curl_tor145`): Firefox 128 ESR's hello, ungreased.
    Tor145,
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
    /// One name per record, and the name is the `code` `--legend` prints and
    /// `--json` carries — `chrome146`, `firefox147`, `tor145`. The bundle's
    /// `curl_*` wrapper names are not accepted: a name that resolves to a
    /// different client version than it says (the wrappers name 133, 135, 142,
    /// 145 … for hellos this build sends as a single newest profile) is worse
    /// than a name that does not resolve, and the wrappers disagree with each
    /// other below the hello as well (`curl_safari170` sends a different h2
    /// preface than `curl_safari155`).
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim().to_ascii_lowercase();
        SHAPES
            .iter()
            .find(|shape| shape.matches_name(&value))
            .map(|shape| shape.variant)
    }

    /// Values accepted by the config validator and the CLI, in report order:
    /// the baseline, then Go — the one shape that impersonates nothing and is no
    /// browser — then one browser at a time alphabetically, newest version
    /// first inside each browser (a desktop shape before the phone shape of the
    /// same version). A new record goes where its browser and version put it —
    /// `chrome146` heads the Chromium block, `safari153` closes Safari's.
    ///
    /// The single hand-written list on this side of the table: `spec()` panics
    /// on a variant missing from `SHAPES`, and the totality test compares this
    /// list with the table, so the two cannot drift apart unnoticed.
    ///
    /// The seven in [`Self::DEFAULT_SET`] are the profiles a run presents by
    /// default; the rest are older and newer releases of the same clients plus
    /// the mobile, Tor and missing-version shapes, selectable one at a time
    /// (`--fingerprint`) or as a burst list (`--burst-profiles all`).
    pub const ALL: [TlsFingerprint; 30] = [
        Self::Rustls,
        Self::Go127,
        Self::Chrome146,
        Self::Chrome133,
        Self::Chrome131,
        Self::Chrome131Android,
        Self::Chrome123,
        Self::Chrome116,
        Self::Chrome115Pq,
        Self::Chrome107,
        Self::Chrome99Android,
        Self::Chrome87,
        Self::Chrome72,
        Self::Chrome70,
        Self::Edge101,
        Self::Firefox147,
        Self::Firefox133,
        Self::Firefox120,
        Self::Firefox105,
        Self::Firefox99,
        Self::Firefox65,
        Self::Safari260,
        Self::Safari260Ios,
        Self::Safari184Ios,
        Self::Safari180,
        Self::Safari172Ios,
        Self::Safari170,
        Self::Safari155,
        Self::Safari153,
        Self::Tor145,
    ];

    /// The profiles a run presents when nothing asked for a specific set: test
    /// 6 with no `--burst-profiles`, and the same default behind the menu.
    ///
    /// Chosen for what each shape *answers*, not for version coverage: the
    /// baseline, the newest release of each family, the one pair that isolates a
    /// generation boundary (`chrome116` without `encrypted_client_hello` against
    /// `chrome123` with it — the two differ by one extension), and one refused
    /// shape per key family, so a run says both whether a site is reachable and
    /// whether the censor on the path is carrying a table at all. The other
    /// fourteen shapes are a flag away (`--burst-profiles`), and the rows the
    /// measurements named as duplicates of these — `edge101` and
    /// `chrome99android` answer with `chrome107`'s key, `safari170`,
    /// `safari172ios` and `safari184ios` with another Safari row's — are not in
    /// the default set for exactly that reason.
    ///
    /// Kept apart from [`Self::ALL`] because the network budget of test 6 is
    /// `profiles × hosts × 2 version axes`: every shape added here is paid for
    /// on every run, so a profile joins the default set deliberately and `all`
    /// stays the explicit way to ask for everything, however many that is.
    ///
    /// Ordered like [`Self::ALL`] — baseline, then browser, newest first — so a
    /// column of the burst table reads the same way as the legend behind it.
    pub const DEFAULT_SET: [TlsFingerprint; 7] = [
        Self::Rustls,
        Self::Chrome146,
        Self::Chrome123,
        Self::Chrome116,
        Self::Firefox147,
        Self::Safari260,
        Self::Tor145,
    ];

    /// Parses a profile list for test 6: `all`, or comma/space separated names.
    /// Unknown tokens come back separately so the caller can warn instead of
    /// silently running a different test than the one that was asked for; an
    /// empty or all-unknown list means `all`.
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

/// True when this shape carries `encrypted_client_hello` (65037) as GREASE.
///
/// Eight shapes do: the seven wrappers that name `--ech true` —
/// `curl_chrome123`, `curl_chrome131`, `curl_chrome131_android`,
/// `curl_chrome146`, `curl_firefox133`, `curl_firefox147` and `curl_tor145` —
/// plus `firefox120`, whose reference is the uTLS ladder rather than a wrapper
/// and whose own spec pins GREASE ECH. The first seven send it as grease because
/// curl needs DoH or an explicit `--ecl:` to have a real config at all; the
/// wrappers' own flags, and `firefox120`'s spec, are the source, and the
/// captures agree
/// (`encrypted_client_hello` in `firefox_133.0.3_linux.yaml`,
/// `chrome_136.0.7103.93.yaml` and the rest).
pub fn sends_ech(fingerprint: TlsFingerprint) -> bool {
    fingerprint.spec().ech
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
