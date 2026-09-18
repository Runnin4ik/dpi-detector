//! ClientHello profile override (dpi-detector patch).
//!
//! Upstream rustls fixes the ClientHello shape: the cipher-suite list and its
//! order come from the [`CryptoProvider`], extension order is randomized per
//! connection, and browser-only extensions (signed certificate timestamps,
//! secure-renegotiation info, ALPS, padding, GREASE) are never emitted.
//!
//! That is the right default — it resists fingerprinting by accident, not by
//! design. But a diagnostic tool that measures *whether a censor reacts to a
//! given client fingerprint* needs the opposite: one call site that pins the
//! wire shape to a known profile, so the same probe can be repeated with a
//! different one and the outcomes compared.
//!
//! This module adds that opt-in. Nothing changes unless
//! [`ClientConfig::hello_profile`] is set; with it unset the ClientHello is
//! byte-for-byte upstream rustls.
//!
//! # Scope of the override
//!
//! * cipher-suite list and order
//! * `supported_groups` list and order
//! * `signature_algorithms` list and order
//! * ALPN list
//! * exact extension order (raw type ids)
//! * extra extensions emitted verbatim, for what rustls has no typed field for
//! * optional GREASE values (RFC 8701)
//!
//! It deliberately does NOT touch: record-layer splitting, ECH payloads,
//! HTTP/2 frame layout or the TLS key schedule. A profile reproduces the
//! *shape* hashed by JA3/JA4 — it is not a byte-for-byte browser.
//!
//! [`ClientConfig::hello_profile`]: crate::client::ClientConfig::hello_profile
//! [`CryptoProvider`]: crate::crypto::CryptoProvider

use alloc::vec::Vec;

use crate::CipherSuite;
use crate::NamedGroup;
use crate::SignatureScheme;
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{ClientExtensions, ProtocolName};

/// A ClientHello shape to present on the wire.
///
/// Every field is optional; `None` leaves the corresponding rustls default in
/// place. Lists are raw IANA identifiers so a profile can be written from a
/// JA3 string without depending on internal enums.
#[derive(Clone, Debug, Default)]
pub struct ClientHelloProfile {
    /// Cipher suites in wire order. Replaces the provider-derived list
    /// entirely, including the TLS 1.2 renegotiation SCSV.
    pub cipher_suites: Option<Vec<u16>>,

    /// `supported_groups` entries in wire order.
    pub groups: Option<Vec<u16>>,

    /// The groups a key share is sent for, in wire order — the shape a browser's
    /// `--tls-key-shares-limit` produces.
    ///
    /// `None`, the default, is rustls's own choice: one share for the first
    /// usable group (the resumption hint's when there is one) plus, when that
    /// group is hybrid, the component's share. A list overrides both: one
    /// exchange per named group, each contributing its own share and — for a
    /// hybrid group — its component's share directly afterwards, unless the list
    /// names that component as a group of its own. So `[X25519MLKEM768,
    /// secp256r1]` sends three shares, which is what `curl_firefox133`'s
    /// `--tls-key-shares-limit 3` puts on the wire.
    ///
    /// Every group named here has to be one the provider serves and one this
    /// handshake offers (`groups`); the handshake fails otherwise rather than
    /// sending a share the client cannot complete.
    pub key_share_groups: Option<Vec<u16>>,

    /// `signature_algorithms` entries in wire order.
    pub signature_schemes: Option<Vec<u16>>,

    /// ALPN protocols in wire order.
    pub alpn: Option<Vec<Vec<u8>>>,

    /// Exact extension order by type id. Extensions rustls still needs to send
    /// but which are not listed here are appended afterwards (except
    /// EncryptedClientHello and PreSharedKey, which the specification requires
    /// last). Entries that rustls neither tracks nor finds in
    /// [`Self::raw_extensions`] are skipped.
    pub extension_order: Option<Vec<u16>>,

    /// Extensions emitted verbatim as `(type, body)`.
    ///
    /// Used for extensions rustls has no typed field for — signed certificate
    /// timestamp (18), secure renegotiation (65281), ALPS (17513), padding
    /// (21) — and for replacing an optional typed extension (session ticket)
    /// with a browser-shaped body. A raw entry is emitted only when rustls has
    /// no typed value for that type in this handshake, so it can never be
    /// duplicated.
    pub raw_extensions: Vec<(u16, Vec<u8>)>,

    /// Extensions that must NOT be sent, by type id.
    ///
    /// Needed because rustls sends extensions a given browser does not: a fresh
    /// rustls hello carries `psk_key_exchange_modes` (45) and `session_ticket`
    /// (35), neither of which Firefox 148 sends. Suppressing them is what makes
    /// the extension *set* — and therefore the JA4 count and hash — match.
    pub suppress_extensions: Vec<u16>,

    /// Emit GREASE values (RFC 8701): one cipher, one supported group, one
    /// version and two extensions. Browsers differ here — Chrome greases,
    /// Firefox does not — so this is opt-in per profile. GREASE values change
    /// every connection, which makes JA3 unstable by design (JA4 ignores them).
    pub grease: bool,

    /// Shuffle [`Self::extension_order`] once per connection, as Chromium 110+
    /// does: BoringSSL's `ssl_setup_extension_permutation` runs one Fisher–Yates
    /// pass over its extension table, seeded from `RAND_bytes`, so two
    /// ClientHellos from one browser never share an order. Chrome's JA3 is
    /// therefore different on every connection, and a build that pins one order
    /// is the one shape a modern Chromium never sends.
    ///
    /// The GREASE slots, the trailing padding and the extensions TLS 1.3
    /// requires last (ECH, PSK) keep their positions — BoringSSL adds those
    /// outside the loop it shuffles.
    pub permute_extensions: bool,

    /// Certificate compression algorithms to advertise (`compress_certificate`).
    pub cert_compression: Option<Vec<u16>>,

    /// Pad the ClientHello handshake message to at least this many bytes
    /// (RFC 7685), as Chrome and Firefox both do. The extension is omitted when
    /// the hello is already that large, which is also what BoringSSL does.
    ///
    /// Requires `21` (padding) in [`Self::extension_order`] — the order names
    /// the position, this field computes the length.
    pub padding_to: Option<u16>,

    /// Versions this client offers *behind* 1.2 as fallbacks, in wire order.
    ///
    /// Safari 15.5 advertises TLS 1.1 and 1.0 after 1.2 — a hello without them
    /// is a shape no Safari sends, and its `supported_versions` body is what a
    /// middlebox reads. The entries are written verbatim and change nothing
    /// about what can be negotiated: rustls still refuses a peer that selects
    /// anything outside the config's own set, with
    /// `PeerIncompatible::ServerDoesNotSupportTls12Or13`, which callers can tell
    /// apart from a real block.
    pub legacy_versions: Vec<u16>,
}

/// Marker for a GREASE extension (RFC 8701) inside a profile's extension order.
///
/// Chrome opens and closes its extension list with one, and the value has to be
/// drawn from the per-connection seed, so an order cannot name it directly.
pub const GREASE_EXTENSION_MARKER: u16 = 0x0a0a;

impl ClientHelloProfile {
    /// The GREASE group value this profile greases with, if it greases at all.
    ///
    /// The `grease` flag already puts this value at the head of
    /// `supported_groups`; a caller that emits key shares uses the same value, so
    /// the share list opens with the group list's first entry exactly as a
    /// browser's does.
    pub(crate) fn grease_group(&self, seed: u16) -> Option<NamedGroup> {
        self.grease.then(|| NamedGroup::from(grease_value(seed, 1)))
    }

    /// The GREASE value this profile writes at the head of `supported_versions`,
    /// if it greases at all.
    ///
    /// The slot sits after the GREASE extensions (`2 + one per marker`), so no
    /// two positions of one hello share a value — as in a browser, whose
    /// `supported_versions` GREASE differs from the one in its key share.
    pub(crate) fn grease_supported_versions(&self, seed: u16) -> Option<u16> {
        if !self.grease {
            return None;
        }
        let markers = self
            .extension_order
            .as_ref()
            .map(|order| order.iter().filter(|t| **t == GREASE_EXTENSION_MARKER).count() as u8)
            .unwrap_or(0);
        Some(grease_value(seed, 2 + markers))
    }
}

impl ClientHelloProfile {
    /// Applies the profile to a freshly built ClientHello.
    ///
    /// `grease_seed` selects the GREASE values (mirrors the per-connection
    /// randomization rustls already uses for extension order), and
    /// `permute_seed` drives [`Self::permute_extensions`].
    pub(crate) fn apply(
        &self,
        exts: &mut ClientExtensions<'_>,
        cipher_suites: &mut Vec<CipherSuite>,
        grease_seed: u16,
        permute_seed: [u8; 16],
        tls13: bool,
    ) {
        if let Some(ciphers) = &self.cipher_suites {
            let mut out: Vec<CipherSuite> = ciphers
                .iter()
                .copied()
                .filter(|c| *c == 0x00ff || CipherSuite::from(*c) != CipherSuite::Unknown(*c))
                .map(CipherSuite::from)
                .collect();
            if self.grease {
                out.insert(0, CipherSuite::from(grease_value(grease_seed, 0)));
            }
            *cipher_suites = out;
        }

        if let Some(groups) = &self.groups {
            let mut out: Vec<NamedGroup> = groups.iter().copied().map(NamedGroup::from).collect();
            if self.grease {
                out.insert(0, NamedGroup::from(grease_value(grease_seed, 1)));
            }
            exts.named_groups = Some(out);
        }

        if let Some(schemes) = &self.signature_schemes {
            exts.signature_schemes = Some(
                schemes
                    .iter()
                    .copied()
                    .map(SignatureScheme::from)
                    .collect(),
            );
        }

        if let Some(alpn) = &self.alpn {
            exts.protocols = Some(alpn.iter().cloned().map(ProtocolName::from).collect());
        }

        // The fallbacks a browser advertises behind 1.2 ride in the same list the
        // config fills; the GREASE slot stays ahead of them (see `hs.rs`).
        if !self.legacy_versions.is_empty() {
            if let Some(versions) = exts.supported_versions.as_mut() {
                versions.legacy = self.legacy_versions.clone();
            }
        }

        // RFC 8879: `compress_certificate` is a TLS 1.3 extension. rustls sets it
        // only for a hello that offers 1.3, so a profile must not reintroduce it
        // into a 1.2-only hello (the probes pin 1.2 for their second TLS column).
        //
        // An empty list means "this client advertises no algorithm" — Safari
        // 15.3 and Tor 14.5 send no such extension — and it has to clear the
        // typed value rather than set an empty one, which would put a
        // `compress_certificate` with zero entries on the wire: a hello with an
        // extension the client does not send, which is exactly what the profiles
        // exist to avoid.
        if tls13 {
            exts.certificate_compression_algorithms =
                match &self.cert_compression {
                    Some(algorithms) if !algorithms.is_empty() => Some(
                        algorithms
                            .iter()
                            .copied()
                            .map(crate::CertificateCompressionAlgorithm::from)
                            .collect(),
                    ),
                    _ => None,
                };
        }

        let mut raw: Vec<(ExtensionType, Vec<u8>)> = self
            .raw_extensions
            .iter()
            .map(|(t, body)| (ExtensionType::from(*t), body.clone()))
            .collect();

        // A profile places GREASE extensions by putting `GREASE_EXTENSION_MARKER`
        // in its order: each occurrence takes the next value from the
        // per-connection seed and is emitted at that exact position. The body
        // follows BoringSSL: the last GREASE the hello carries has one zero byte
        // (`2300 01 00`), the opening one is empty — measured on the
        // `curl-impersonate v2.2.2` bundles, whose closing GREASE is the only
        // thing that differs in size from ours in an otherwise identical hello.
        let order = self.extension_order.as_ref().map(|order| {
            // The shuffle runs on the order as written, before the GREASE slots
            // take their per-connection values: BoringSSL permutes its table of
            // extensions and then emits the GREASE pair around the result, so a
            // GREASE marker keeps the position the profile gave it.
            let order = if self.permute_extensions {
                permuted_order(order, permute_seed)
            } else {
                order.clone()
            };
            let markers = order.iter().filter(|t| **t == GREASE_EXTENSION_MARKER).count();
            let mut nth = 0u8;
            order
                .iter()
                .map(|ext_type| {
                    if *ext_type == GREASE_EXTENSION_MARKER {
                        let value = grease_value(grease_seed, 2 + nth);
                        nth += 1;
                        let mut body = Vec::new();
                        if nth as usize == markers {
                            body.push(0);
                        }
                        raw.push((ExtensionType::from(value), body));
                        value
                    } else {
                        *ext_type
                    }
                })
                .collect::<Vec<u16>>()
        });

        exts.raw_extensions = raw;

        exts.suppress_extensions = self
            .suppress_extensions
            .iter()
            .copied()
            .map(ExtensionType::from)
            .collect();

        exts.profile_order = order.map(|order| {
            order
                .into_iter()
                .map(ExtensionType::from)
                .collect::<Vec<_>>()
        });

        exts.padding_to = self.padding_to;
    }
}

/// The profile's order with its movable entries shuffled, per connection.
///
/// This is BoringSSL's `ssl_setup_extension_permutation` in miniature: one
/// Fisher–Yates pass from the end of the list, each step swapping entry `i` with
/// a uniformly drawn earlier one. Three classes stay where the profile put them,
/// because BoringSSL adds them outside the loop it shuffles:
///
/// * GREASE slots — its pair is written around the permuted table;
/// * padding (21) — appended last, which is also where RFC 7685 padding belongs;
/// * `encrypted_client_hello` (65037) and `pre_shared_key` (41) — TLS 1.3
///   requires them last, and rustls places them there regardless.
///
/// The seed is 128 bits drawn from the CSPRNG per connection and expanded by a
/// splitmix64 stream. BoringSSL draws one random byte per position, so its space
/// is `2^(8·(n-1))`; this one is bounded by the seed, `2^128`, which for the
/// fifteen-odd entries a browser sends is the same statement: no two connections
/// repeat an order. An observer sees the resulting permutation, not the stream
/// that produced it, so the next connection's order is not predictable from
/// this one's.
fn permuted_order(order: &[u16], seed: [u8; 16]) -> Vec<u16> {
    let mut out = order.to_vec();
    let mut rng = SplitMix64::new(seed);
    let movable: Vec<usize> = (0..out.len())
        .filter(|i| is_movable(out[*i]))
        .collect();

    for i in (1..movable.len()).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        out.swap(movable[i], movable[j]);
    }
    out
}

/// Whether BoringSSL's shuffle is free to move this entry.
fn is_movable(ext_type: u16) -> bool {
    const PADDING: u16 = 21;
    const PRE_SHARED_KEY: u16 = 41;
    const ENCRYPTED_CLIENT_HELLO: u16 = 65037;

    ext_type != GREASE_EXTENSION_MARKER
        && ext_type != PADDING
        && ext_type != PRE_SHARED_KEY
        && ext_type != ENCRYPTED_CLIENT_HELLO
}

/// A splitmix64 stream over a 128-bit seed: the permutation's only randomness,
/// and the reason it needs no dependency of its own.
struct SplitMix64 {
    state: u64,
    key: u64,
}

impl SplitMix64 {
    fn new(seed: [u8; 16]) -> Self {
        let hi = u64::from_be_bytes(seed[..8].try_into().unwrap_or([0; 8]));
        let lo = u64::from_be_bytes(seed[8..].try_into().unwrap_or([0; 8]));
        Self {
            state: hi ^ 0x9e37_79b9_7f4a_7c15,
            key: lo,
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        (z ^ (z >> 31)) ^ self.key
    }
}

/// RFC 8701 GREASE values: `0x?a?a` with both bytes equal.
///
/// `slot` picks one of the eight values per position class, so a connection
/// uses distinct values in ciphers, groups and extensions — as browsers do.
fn grease_value(seed: u16, slot: u8) -> u16 {
    const GREASE: [u16; 16] = [
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
        0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];
    let index = (seed as usize).wrapping_add(slot as usize * 3) % GREASE.len();
    GREASE[index]
}

/// Convenience: extension ids a caller may want to reference by name.
pub mod ext {
    /// `server_name`
    pub const SERVER_NAME: u16 = 0;
    /// `status_request`
    pub const STATUS_REQUEST: u16 = 5;
    /// `supported_groups`
    pub const SUPPORTED_GROUPS: u16 = 10;
    /// `ec_point_formats`
    pub const EC_POINT_FORMATS: u16 = 11;
    /// `signature_algorithms`
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    /// `alpn`
    pub const ALPN: u16 = 16;
    /// `signed_certificate_timestamp`
    pub const SCT: u16 = 18;
    /// `padding`
    pub const PADDING: u16 = 21;
    /// `extended_master_secret`
    pub const EXTENDED_MASTER_SECRET: u16 = 23;
    /// `compress_certificate`
    pub const COMPRESS_CERTIFICATE: u16 = 27;
    /// `session_ticket`
    pub const SESSION_TICKET: u16 = 35;
    /// `supported_versions`
    pub const SUPPORTED_VERSIONS: u16 = 43;
    /// `psk_key_exchange_modes`
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 45;
    /// `key_share`
    pub const KEY_SHARE: u16 = 51;
    /// `application_settings` (ALPS)
    pub const ALPS: u16 = 17513;
    /// `renegotiation_info`
    pub const RENEGOTIATION_INFO: u16 = 65281;
}
