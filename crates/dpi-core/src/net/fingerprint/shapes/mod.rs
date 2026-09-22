//! Every profile's shape, as data.
//!
//! One record per selectable shape: its names, where the shape came from, and
//! the TLS lists a ClientHello is built from. The builder in [`super`] turns a
//! record into the `ClientHelloProfile` rustls writes; the accessors read the
//! same record, so nothing here is duplicated in a `match` arm.
//!
//! A record whose TLS shape is another record's — Edge is Chromium, Safari 18.0
//! is Safari 15.5's hello — names the shared lists instead of copying them, so
//! the family's shape lives in one place and the record carries only what makes
//! it a different client (its identity and its HTTP/2 preface). What each field
//! means is in [`TlsShape`]; the provenance of a record's numbers goes in its
//! `source`, so updating an upstream release is a deliberate revision of a shape
//! rather than a silent change of one.

mod baseline;
mod chrome;
mod edge;
mod firefox;
mod go;
mod safari;
mod tor;

use rustls::client::ClientHelloProfile;

use super::h2::H2Fingerprint;
use super::TlsFingerprint;

/// One selectable shape.
///
/// The lists are raw IANA identifiers in wire order, so a record can be written
/// straight from a captured ClientHello. `ciphers`, `groups` and `sig_algs` are
/// what the profile *advertises*; a code point this build's provider cannot
/// serve is allowed in the list (browsers list more than they use) but has to
/// be named in `tests::UNIMPLEMENTED`, which is what keeps the gap between the
/// shape and the provider an explicit decision.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TlsShape {
    /// The variant this record describes. Every variant has exactly one record.
    pub(crate) variant: TlsFingerprint,
    /// Stable value for machine JSON and the config file.
    pub(crate) code: &'static str,
    /// Canonical uppercase token for tables and logs. Never translated (rule 4).
    pub(crate) token: &'static str,
    /// Token plus the version the shape reproduces ("CHROME 133"), for the
    /// places that have room for it (burst table headers, the settings screen,
    /// the live line). Latin like `token` and never translated (rule 4): a table
    /// header that says only "CHROME" hides which shape was actually sent.
    pub(crate) label: &'static str,
    /// Where the numbers were taken from, versions included: the reference
    /// bundle a shape is pinned to, and the capture it was read out of. Reads in
    /// `--legend`, and is the reason a pin can be re-measured.
    pub(crate) source: &'static str,
    /// The untouched rustls hello: no profile is installed, nobody is
    /// impersonated, and every earlier measurement was taken with it.
    pub(crate) baseline: bool,
    /// Cipher suites, in wire order.
    pub(crate) ciphers: &'static [u16],
    /// `supported_groups`, in wire order. The first entry is the group the
    /// provider shares a key with — `tests::the_advertised_group_list_opens_with_the_group_we_share`
    /// pins that, because a list that opens with another group is a shape no
    /// client sends.
    pub(crate) groups: &'static [u16],
    /// `signature_algorithms`, in wire order.
    pub(crate) sig_algs: &'static [u16],
    /// The full extension list, in the order the client sends it.
    /// `GREASE_EXTENSION_MARKER` marks a GREASE slot (RFC 8701).
    pub(crate) ext_order: &'static [u16],
    /// Extensions emitted verbatim as `(type, body)`, for what rustls has no
    /// typed field for or for a body the client shapes itself (session ticket,
    /// padding, ALPS, secure renegotiation, SCT).
    pub(crate) raw_exts: &'static [(u16, &'static [u8])],
    /// Extensions the client never sends, which rustls otherwise would.
    pub(crate) suppress: &'static [u16],
    /// Extensions a hello pinned to TLS 1.3 alone drops — the 1.2-era ones. See
    /// [`super::pinned_drop`].
    pub(crate) drop13: &'static [u16],
    /// Extensions a hello pinned to TLS 1.2 alone drops: `supported_versions`,
    /// the 1.3-only ALPS, and padding (a 1.2 hello is under the 256-byte floor
    /// where BoringSSL stops padding).
    pub(crate) drop12: &'static [u16],
    /// ALPN protocols, in wire order.
    pub(crate) alpn: &'static [&'static [u8]],
    /// Pad the hello to at least this many bytes (RFC 7685).
    pub(crate) padding_to: Option<u16>,
    /// Emit GREASE values. Chrome and Safari grease, Firefox does not.
    pub(crate) grease: bool,
    /// Whether the impersonated client carries `encrypted_client_hello` (65037).
    ///
    /// Nine of the nineteen shapes do, and every one of them does it as GREASE:
    /// their wrappers say `--ech true`, and curl can only fetch an ECHConfigList
    /// through DoH or `--ecl:`, neither of which the wrappers pass — so what
    /// reaches the wire is a grease extension. Measured on the bundle's own
    /// hello: `curl_chrome136`, `curl_firefox133` and `curl_tor145` all send the
    /// same kind of body — `outer`, suite `0001 0001`, a random `config_id`, a
    /// 32-byte `enc` and a random payload of 144, 176, 208 or 240 bytes, which is
    /// an extension of 186, 218, 250 or 282 bytes — the same shape on three
    /// different browsers, which a real config never is.
    ///
    /// This is what `net::tls` turns into `EchMode::Grease`; a real
    /// `EchMode::Enable` would need the host's own HTTPS record, which is a
    /// different kind of fidelity than these records promise (see
    /// `docs/ADDING_A_PROFILE.md`).
    pub(crate) ech: bool,
    /// Shuffle the extension order once per connection.
    ///
    /// Measured twice, because it decides whether a shape can be pinned at all:
    /// the bundle's own wrappers name `--tls-permute-extensions` for
    /// `curl_chrome123` through `curl_chrome146` and for nothing older, and the
    /// fork's captures carry `tls_permute_extensions: true` for every Chromium
    /// from 110 up (Edge from 118). Chromium enables it unconditionally
    /// (`SSL_set_permute_extensions` in `ssl_client_socket_impl.cc`), and
    /// BoringSSL's `ssl_setup_extension_permutation` draws a fresh Fisher–Yates
    /// pass per connection — so two hellos from one Chrome are never ordered
    /// alike, and a profile that pins one order is the one thing Chrome 110+
    /// never sends.
    pub(crate) permute_extensions: bool,
    /// Whether the impersonated client sends its `priority` header over
    /// HTTP/1.1 as well as HTTP/2.
    ///
    /// Measured on the bundle's own h1 request (`tools/fingerprint`, stage
    /// `headers`): `curl_firefox133`, `curl_firefox147` and
    /// `curl_tor145` carry `Priority` on both protocols, every Chrome, Edge and
    /// Safari wrapper carries it on HTTP/2 only. curl decides that per
    /// impersonation profile, not per `-H` line — the four wrappers name it
    /// exactly as the others do.
    pub(crate) priority_on_h1: bool,
    /// RFC 8879 code points this shape advertises; empty means rustls's own
    /// empty list and no `compress_certificate` extension.
    pub(crate) cert_compression: &'static [u16],
    /// The groups a key share is sent for, in wire order, `None` for rustls's
    /// own choice of one share plus a hybrid component.
    ///
    /// `curl_firefox133`, `curl_firefox147` and `curl_tor145`
    /// pass `--tls-key-shares-limit 3`, which puts three shares on the wire
    /// (measured: `tools/fingerprint`, stage `hello`); every other wrapper
    /// leaves the count where rustls puts it. A hybrid group named here brings
    /// its component's share with it, so Firefox's list is
    /// `[X25519MLKEM768, secp256r1]` — three entries on the wire, not two.
    pub(crate) key_share_groups: Option<&'static [u16]>,
    /// Needs the provider that carries `X25519MLKEM768`, because the shape
    /// offers the hybrid group and its key share has to be the first group's.
    pub(crate) pq: bool,
    /// Versions offered *behind* 1.2, in wire order. Empty for every shape whose
    /// client offers 1.3 and 1.2 only.
    pub(crate) legacy_versions: &'static [u16],
    /// The HTTP header set, `None` for the baseline.
    pub(crate) headers: Option<&'static [(&'static str, &'static str)]>,
    /// The HTTP/2 preface, `None` for the baseline (hyper's own defaults).
    pub(crate) h2: Option<&'static H2Fingerprint>,
}

/// Both protocols, exactly what every Chromium profile offers; the probes
/// branch on the negotiated protocol (see `probe::tls`).
const H2_AND_HTTP11: &[&[u8]] = &[b"h2", b"http/1.1"];

/// brotli, exactly what Chrome 107, Chrome 133 and Edge 101 advertise.
const BROTLI: &[u16] = &[2];

/// Every selectable shape, in report order: the baseline first, then one browser
/// at a time alphabetically with the newest version of each first, and the phone
/// shape of a version right after its desktop sibling (`chrome146` … `chrome70`,
/// `edge101`, `firefox147` … `firefox65`, `go127`, `safari260` … `safari153`,
/// `tor145`).
/// `tests::fingerprint_table_is_total` pins the table against
/// [`TlsFingerprint::ALL`] in both directions, so a variant without a record
/// fails the suite instead of silently falling back to the baseline, and a
/// record added out of order is a one-line move here and in `ALL`.
pub(crate) static SHAPES: &[TlsShape] = &[
    baseline::RUSTLS,
    chrome::CHROME146,
    chrome::CHROME131,
    chrome::CHROME131_ANDROID,
    chrome::CHROME123,
    chrome::CHROME116,
    chrome::CHROME115_PQ,
    chrome::CHROME107,
    chrome::CHROME99_ANDROID,
    chrome::CHROME87,
    chrome::CHROME72,
    chrome::CHROME70,
    edge::EDGE101,
    firefox::FIREFOX147,
    firefox::FIREFOX133,
    firefox::FIREFOX120,
    firefox::FIREFOX105,
    firefox::FIREFOX99,
    firefox::FIREFOX65,
    go::GO127,
    safari::SAFARI260,
    safari::SAFARI260_IOS,
    safari::SAFARI184_IOS,
    safari::SAFARI180,
    safari::SAFARI172_IOS,
    safari::SAFARI170,
    safari::SAFARI155,
    safari::SAFARI153,
    tor::TOR145,
];

impl TlsShape {
    /// True when `value` (already lowercased and trimmed) names this record.
    ///
    /// One name per record: the `code`, which is also what the config file, the
    /// JSON and `--legend` carry, so there is nothing here that can resolve to a
    /// different version than it says.
    pub(crate) fn matches_name(&self, value: &str) -> bool {
        self.code == value
    }

    /// The ClientHello shape rustls writes for this record, `None` for the
    /// baseline — the one row that installs no profile at all.
    pub(crate) fn build(&self) -> Option<ClientHelloProfile> {
        if self.baseline {
            return None;
        }
        Some(ClientHelloProfile {
            cipher_suites: Some(self.ciphers.to_vec()),
            groups: Some(self.groups.to_vec()),
            key_share_groups: self.key_share_groups.map(|groups| groups.to_vec()),
            signature_schemes: Some(self.sig_algs.to_vec()),
            alpn: Some(self.alpn.iter().map(|protocol| protocol.to_vec()).collect()),
            extension_order: Some(self.ext_order.to_vec()),
            raw_extensions: self.raw_exts.iter().map(|(ext, body)| (*ext, body.to_vec())).collect(),
            suppress_extensions: self.suppress.to_vec(),
            grease: self.grease,
            permute_extensions: self.permute_extensions,
            cert_compression: Some(self.cert_compression.to_vec()),
            padding_to: self.padding_to,
            legacy_versions: self.legacy_versions.to_vec(),
        })
    }
}

/// Extension type ids referenced by the shapes above.
pub(crate) const EXT_SERVER_NAME: u16 = 0;
pub(crate) const EXT_STATUS_REQUEST: u16 = 5;
pub(crate) const EXT_SUPPORTED_GROUPS: u16 = 10;
pub(crate) const EXT_EC_POINT_FORMATS: u16 = 11;
pub(crate) const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub(crate) const EXT_ALPN: u16 = 16;
pub(crate) const EXT_SCT: u16 = 18;
pub(crate) const EXT_PADDING: u16 = 21;
pub(crate) const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
pub(crate) const EXT_COMPRESS_CERTIFICATE: u16 = 27;
pub(crate) const EXT_RECORD_SIZE_LIMIT: u16 = 28;
pub(crate) const EXT_DELEGATED_CREDENTIALS: u16 = 34;
pub(crate) const EXT_SESSION_TICKET: u16 = 35;
pub(crate) const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub(crate) const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
pub(crate) const EXT_KEY_SHARE: u16 = 51;
pub(crate) const EXT_RENEGOTIATION_INFO: u16 = 65281;
/// `encrypted_client_hello` (draft-ietf-tls-esni), the extension seven shapes
/// carry as GREASE.
pub(crate) const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 65037;
/// Chrome's ALPS (draft-vvv-tls-alps), as Chrome 107 and Safari send it.
pub(crate) const EXT_APPLICATION_SETTINGS: u16 = 17513;
/// The same extension at the code point Chrome 133 moved it to
/// (`--tls-use-new-alps-codepoint`, and `utlsExtensionApplicationSettingsNew`).
pub(crate) const EXT_APPLICATION_SETTINGS_NEW: u16 = 17613;
/// `channel_id`, as the placeholder Chrome 70 sent it: uTLS's
/// `FakeChannelIDExtension{}` writes a zero-length body at the new code point
/// (30032; 30031 was the old one, which no shape here sends).
pub(crate) const EXT_FAKE_CHANNEL_ID: u16 = 30032;
