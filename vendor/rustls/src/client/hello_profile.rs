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
    /// randomization rustls already uses for extension order).
    pub(crate) fn apply(
        &self,
        exts: &mut ClientExtensions<'_>,
        cipher_suites: &mut Vec<CipherSuite>,
        grease_seed: u16,
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
        if let (true, Some(algorithms)) = (tls13, &self.cert_compression) {
            exts.certificate_compression_algorithms = Some(
                algorithms
                    .iter()
                    .copied()
                    .map(crate::CertificateCompressionAlgorithm::from)
                    .collect(),
            );
        }

        let mut raw: Vec<(ExtensionType, Vec<u8>)> = self
            .raw_extensions
            .iter()
            .map(|(t, body)| (ExtensionType::from(*t), body.clone()))
            .collect();

        // A profile places GREASE extensions by putting `GREASE_EXTENSION_MARKER`
        // in its order: each occurrence takes the next value from the
        // per-connection seed and gets a verbatim (empty) body so the encoder
        // emits it at that exact position.
        let order = self.extension_order.as_ref().map(|order| {
            let mut nth = 0u8;
            order
                .iter()
                .map(|ext_type| {
                    if *ext_type == GREASE_EXTENSION_MARKER {
                        let value = grease_value(grease_seed, 2 + nth);
                        nth += 1;
                        raw.push((ExtensionType::from(value), Vec::new()));
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
