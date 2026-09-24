//! JA3 extraction from a ClientHello.
//!
//! Two consumers: the regression tests that pin each profile to the JA3 of the
//! client it reproduces, and the `tls_fingerprint` verification harness. Nothing
//! in the probe path calls this, so it costs nothing at runtime.
//!
//! GREASE values (RFC 8701) are stripped from all four lists, which is what
//! published JA3s — Chrome's, Firefox's and the `curl-impersonate` profiles' —
//! look like. The strings here are therefore directly comparable with the ones a
//! fingerprinting service reports.

/// Length of the TLS record header that precedes the handshake message.
pub(crate) const RECORD_HEADER: usize = 5;
/// Extensions the JA3 string carries values from.
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_KEY_SHARE: u16 = 51;

pub(crate) fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

/// GREASE: `0x0a0a`, `0x1a1a`, … `0xfafa`.
pub fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a
}

/// Walks a ClientHello handshake message and yields its extensions in order.
pub(crate) fn extensions(message: &[u8]) -> Vec<(u16, &[u8])> {
    if message.len() < 4 + 2 + 32 + 1 {
        return Vec::new();
    }
    let mut at = 4 + 2 + 32; // handshake header, legacy version, random
    let session_id = message[at] as usize;
    at += 1 + session_id;
    if at + 2 > message.len() {
        return Vec::new();
    }
    let cipher_len = u16_at(message, at) as usize;
    at += 2 + cipher_len;
    if at >= message.len() {
        return Vec::new();
    }
    let compression_len = message[at] as usize;
    at += 1 + compression_len;
    if at + 2 > message.len() {
        return Vec::new();
    }
    let total = u16_at(message, at) as usize;
    at += 2;

    let end = (at + total).min(message.len());
    let mut out = Vec::new();
    while at + 4 <= end {
        let ext_type = u16_at(message, at);
        let len = u16_at(message, at + 2) as usize;
        let body_at = at + 4;
        if body_at + len > message.len() {
            break;
        }
        out.push((ext_type, &message[body_at..body_at + len]));
        at = body_at + len;
    }
    out
}

/// Cipher suites of a ClientHello, in wire order, GREASE stripped.
pub(crate) fn cipher_suites(message: &[u8]) -> Vec<u16> {
    let session_id_at = 4 + 2 + 32;
    if session_id_at + 1 > message.len() {
        return Vec::new();
    }
    let ciphers_at = session_id_at + 1 + message[session_id_at] as usize;
    if ciphers_at + 2 > message.len() {
        return Vec::new();
    }
    let len = u16_at(message, ciphers_at) as usize;
    // The length is the peer's claim, not a fact: `u16_at` reads two bytes
    // blind, and a truncated hello would index past the message — which under
    // `panic = "abort"` is the whole process. The same bound is what
    // `extensions` applies to every extension body.
    if ciphers_at + 2 + len > message.len() {
        return Vec::new();
    }
    (0..len / 2)
        .map(|i| u16_at(message, ciphers_at + 2 + i * 2))
        .filter(|suite| !is_grease(*suite))
        .collect()
}

/// The JA3 string of a TLS record that carries a ClientHello.
///
/// `record` is what `ClientConnection::write_tls` produces on a fresh
/// connection, record header included.
pub fn client_hello_ja3(record: &[u8]) -> String {
    let message = record.get(RECORD_HEADER..).unwrap_or(record);
    if message.len() < 6 {
        return String::new();
    }

    let mut ext_types = Vec::new();
    let mut curves = Vec::new();
    let mut point_formats = Vec::new();
    for (ext_type, body) in extensions(message) {
        if is_grease(ext_type) {
            continue;
        }
        ext_types.push(ext_type.to_string());
        match ext_type {
            EXT_SUPPORTED_GROUPS => {
                curves = (0..body.len().saturating_sub(2) / 2)
                    .map(|i| u16_at(body, 2 + i * 2))
                    .filter(|group| !is_grease(*group))
                    .map(|group| group.to_string())
                    .collect();
            }
            EXT_EC_POINT_FORMATS => {
                point_formats = body
                    .get(1..)
                    .unwrap_or_default()
                    .iter()
                    .map(|format| format.to_string())
                    .collect();
            }
            _ => {}
        }
    }

    let ciphers = cipher_suites(message)
        .iter()
        .map(|suite| suite.to_string())
        .collect::<Vec<_>>();

    format!(
        "{},{},{},{},{}",
        u16_at(message, 4),
        ciphers.join("-"),
        ext_types.join("-"),
        curves.join("-"),
        point_formats.join("-")
    )
}

/// Extension types of a ClientHello, in wire order, GREASE stripped.
pub fn extension_types(record: &[u8]) -> Vec<u16> {
    let message = record.get(RECORD_HEADER..).unwrap_or(record);
    extensions(message)
        .into_iter()
        .map(|(ext_type, _)| ext_type)
        .filter(|ext_type| !is_grease(*ext_type))
        .collect()
}

/// Groups offered in `key_share`, in wire order, GREASE stripped.
pub fn key_share_groups(record: &[u8]) -> String {
    let message = record.get(RECORD_HEADER..).unwrap_or(record);
    let body = extensions(message)
        .into_iter()
        .find(|(ext_type, _)| *ext_type == EXT_KEY_SHARE)
        .map(|(_, body)| body);
    let Some(body) = body else {
        return "-".into();
    };
    // A body too short to hold its own list length carries no group at all, and
    // `u16_at` would read past it (see `cipher_suites`).
    let Some(list_len) = be16(body, 0) else {
        return "-".into();
    };
    let end = (2 + list_len as usize).min(body.len());
    let mut at = 2;
    let mut groups = Vec::new();
    while at + 4 <= end {
        let group = u16_at(body, at);
        if !is_grease(group) {
            groups.push(group.to_string());
        }
        at += 4 + u16_at(body, at + 2) as usize;
    }
    groups.join(",")
}

/// A ClientHello as the fields a comparison reads: the record and legacy
/// versions, the session id length, the cipher suites, the compression methods,
/// and every extension with its body, in wire order.
///
/// This is the parse behind the harness's `diff`. Two captures — ours, the
/// bundle's, a uTLS build's, a live browser's — are compared field by field,
/// which is the only comparison that sees what no hash does: an extension body,
/// the padding length, the GREASE draw. GREASE is **not** filtered here, because
/// a comparison masks it itself and a GREASE slot on one side only is a
/// difference.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// The version in the record header (`0301` on every current client).
    pub record_version: [u8; 2],
    /// `legacy_version` in the handshake message (`0303`).
    pub legacy_version: [u8; 2],
    /// Length of the session id — the id itself is fresh per connection, so its
    /// length is what two hellos can be compared on.
    pub session_id_len: usize,
    /// Cipher suites, in wire order, GREASE included.
    pub ciphers: Vec<u16>,
    /// Compression methods, in wire order.
    pub compressions: Vec<u8>,
    /// `(type, body)` pairs, in wire order, GREASE included.
    pub extensions: Vec<(u16, Vec<u8>)>,
}

/// Parses a TLS record that carries a ClientHello, `None` when it does not parse
/// as one.
///
/// A bare handshake message has to be wrapped in a record first — the harness
/// wraps it, so `record_version` is always the real one.
pub fn client_hello(record: &[u8]) -> Option<ClientHello> {
    let message = record.get(RECORD_HEADER..)?;
    if message.first() != Some(&1) {
        return None;
    }
    let declared = usize::from(*message.get(1)?) << 16
        | usize::from(*message.get(2)?) << 8
        | usize::from(*message.get(3)?);
    let hello = message.get(..4 + declared)?;

    let mut at = 4 + 2 + 32; // handshake header, legacy version, random
    let session_id_len = usize::from(*hello.get(at)?);
    at += 1 + session_id_len;
    let cipher_len = usize::from(be16(hello, at)?);
    at += 2;
    let ciphers = hello
        .get(at..at + cipher_len)?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .collect();
    at += cipher_len;
    let compression_len = usize::from(*hello.get(at)?);
    at += 1;
    let compressions = hello.get(at..at + compression_len)?.to_vec();
    at += compression_len;

    let ext_len = usize::from(be16(hello, at)?);
    let end = (at + 2 + ext_len).min(hello.len());
    let extensions = extensions(&hello[..end])
        .into_iter()
        .map(|(ext_type, body)| (ext_type, body.to_vec()))
        .collect();

    Some(ClientHello {
        record_version: [*record.get(1)?, *record.get(2)?],
        // `hello` starts at the handshake header, so the body's own fields begin
        // at 4: type, three-byte length, then `legacy_version`.
        legacy_version: [*hello.get(4)?, *hello.get(5)?],
        session_id_len,
        ciphers,
        compressions,
        extensions,
    })
}

/// A big-endian `u16` at `at`, `None` when the slice is short of one.
fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::fingerprint::TlsFingerprint;
    use crate::net::tls::{hello_record, TlsProfile};

    /// The two versions live in different places — one in the record header, one
    /// in the handshake body — and reading the body one off the handshake header
    /// instead is invisible in a comparison, because both sides are wrong the
    /// same way. Only a pin on a real hello catches it.
    #[test]
    fn client_hello_reads_both_versions() {
        let record = hello_record(&TlsProfile::insecure(TlsFingerprint::Chrome107));
        let hello = client_hello(&record).expect("a built hello parses");
        assert_eq!(hello.record_version, [0x03, 0x01], "the record opens at TLS 1.0");
        assert_eq!(hello.legacy_version, [0x03, 0x03], "the body's legacy version is TLS 1.2");
    }

    /// A bare ClientHello handshake message with the lengths the caller asks for:
    /// header, legacy version, random, session id, cipher list, compression
    /// methods, extension list. The declared cipher and extension lengths are
    /// arguments rather than `len()`s, so a test can declare more than it appends.
    fn hello_with(cipher_len: u16, ciphers: &[u8], extensions: &[u8]) -> Vec<u8> {
        let mut m = vec![0x01, 0x00, 0x00, 0x00]; // handshake type + 3-byte length
        m.extend_from_slice(&[0x03, 0x03]); // legacy version
        m.extend_from_slice(&[0u8; 32]); // random
        m.push(0x00); // session id length
        m.extend_from_slice(&cipher_len.to_be_bytes());
        m.extend_from_slice(ciphers);
        m.push(0x01); // one compression method
        m.push(0x00); // ... null
        m.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        m.extend_from_slice(extensions);
        m
    }

    /// The record that carries `message`: the functions that take a record strip
    /// these five bytes before parsing.
    fn record_of(message: &[u8]) -> Vec<u8> {
        let mut r = vec![0x16, 0x03, 0x01, (message.len() >> 8) as u8, (message.len() & 0xFF) as u8];
        r.extend_from_slice(message);
        r
    }

    /// A length in a hello is the peer's claim, not a fact. Every walk over one
    /// stops where the message does: without that, `u16_at` reads two bytes blind
    /// and the slice past the end is an index out of bounds — a panic, and under
    /// the release profile's `panic = "abort"` the whole process rather than one
    /// parse. The bytes here are what a hostile or broken server answers with.
    #[test]
    fn a_truncated_hello_stops_at_the_message() {
        // Cipher list: two suites carried, 65535 declared.
        let truncated = hello_with(0xFFFF, &[0x13, 0x01, 0xC0, 0x2F], &[]);
        assert!(
            cipher_suites(&truncated).is_empty(),
            "a cipher list longer than the message carries no suite"
        );

        // The same hello with the honest length is what the bound must not break.
        let honest = hello_with(4, &[0x13, 0x01, 0xC0, 0x2F], &[]);
        assert_eq!(cipher_suites(&honest), vec![0x1301, 0xC02F]);

        // Extension list: one `key_share` extension declaring 65535 bytes with four
        // present.
        let truncated =
            hello_with(2, &[0x13, 0x01], &[0x00, 0x33, 0xFF, 0xFF, 0x00, 0x1D, 0x00, 0x01]);
        assert!(extensions(&truncated).is_empty(), "the walk ends where the message does");
        assert_eq!(key_share_groups(&record_of(&truncated)), "-");

        // And the honest form of that one still parses, so the bound is not simply
        // refusing every extension list: a six-byte list holding x25519 (29) with a
        // two-byte key.
        let honest = hello_with(
            2,
            &[0x13, 0x01],
            &[0x00, 0x33, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1D, 0x00, 0x02, 0x00, 0x01],
        );
        assert_eq!(extensions(&honest).len(), 1);
        assert_eq!(key_share_groups(&record_of(&honest)), "29");
    }

    /// One level down from the list length: a `key_share` body too short to hold
    /// its own two-byte list length carries no group. Reading it with `u16_at`
    /// would be an index out of bounds on a one-byte body.
    #[test]
    fn a_short_key_share_body_carries_no_group() {
        // Extension 51, declared length 1, one byte present: the list length itself
        // is missing.
        let message = hello_with(2, &[0x13, 0x01], &[0x00, 0x33, 0x00, 0x01, 0x00]);
        assert_eq!(extensions(&message).len(), 1, "the extension itself is well formed");
        assert_eq!(key_share_groups(&record_of(&message)), "-");
    }
}
