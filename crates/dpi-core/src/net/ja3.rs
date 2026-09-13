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
pub(crate) fn is_grease(value: u16) -> bool {
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
    let end = (2 + u16_at(body, 0) as usize).min(body.len());
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
