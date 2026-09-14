//! JA4 (FoxIO) extraction from a ClientHello.
//!
//! JA3 hashes extension *types*; JA4 hashes more of the hello and is what
//! Cloudflare and other frontends match on, so a profile that reproduces a JA3
//! can still miss its JA4. Two things it sees that JA3 cannot, both of which
//! were real gaps here:
//!
//! * the `signature_algorithms` list — Safari 15.5 sends `ecdsa_sha1`, and the
//!   Safari profile was missing it while its JA3 stayed identical;
//! * the ALPN value, which is why the profiles offer `h2, http/1.1` and the
//!   probes speak HTTP/2.
//!
//! The rules follow FoxIO's JA4 reference implementation:
//! GREASE is filtered everywhere, ciphers and extensions
//! are sorted before hashing, `server_name` (0x0000) and `alpn` (0x0010) are
//! removed from the extension hash but stay in the extension *count*, the
//! signature algorithms are appended to the extension hash in wire order, each
//! count is two digits capped at 99, and the ALPN field is the first and last
//! character of the first protocol offered.

use sha2::{Digest, Sha256};

use crate::net::ja3::{cipher_suites, extensions, is_grease, RECORD_HEADER};

const EXT_SERVER_NAME: u16 = 0;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_SUPPORTED_VERSIONS: u16 = 43;

/// The JA4 string of a TLS record that carries a ClientHello.
///
/// `record` is what `ClientConnection::write_tls` produces on a fresh
/// connection, record header included.
pub fn client_hello_ja4(record: &[u8]) -> String {
    let message = record.get(RECORD_HEADER..).unwrap_or(record);
    if message.len() < 6 {
        return String::new();
    }

    let ciphers = cipher_suites(message);
    let parsed = extensions(message);
    let ext_types: Vec<u16> = parsed
        .iter()
        .map(|(ext_type, _)| *ext_type)
        .filter(|ext_type| !is_grease(*ext_type))
        .collect();
    let body_of = |wanted: u16| {
        parsed
            .iter()
            .find(|(ext_type, _)| *ext_type == wanted)
            .map(|(_, body)| *body)
    };

    let mut hashed_ciphers: Vec<String> = ciphers.iter().map(|suite| format!("{suite:04x}")).collect();
    hashed_ciphers.sort();
    let mut hashed_extensions: Vec<String> = ext_types
        .iter()
        .filter(|ext_type| **ext_type != EXT_SERVER_NAME && **ext_type != EXT_ALPN)
        .map(|ext_type| format!("{ext_type:04x}"))
        .collect();
    hashed_extensions.sort();
    let mut extension_hash_input = hashed_extensions.join(",");
    if ext_types.contains(&EXT_SIGNATURE_ALGORITHMS) {
        let schemes: Vec<String> = body_of(EXT_SIGNATURE_ALGORITHMS)
            .map(signature_schemes)
            .unwrap_or_default()
            .iter()
            .map(|scheme| format!("{scheme:04x}"))
            .collect();
        extension_hash_input = format!("{extension_hash_input}_{}", schemes.join(","));
    }

    format!(
        "t{}{}{:02}{:02}{}_{}_{}",
        version_field(
            body_of(EXT_SUPPORTED_VERSIONS).map(supported_versions).unwrap_or_default(),
            u16::from_be_bytes([message[4], message[5]]),
        ),
        if ext_types.contains(&EXT_SERVER_NAME) { 'd' } else { 'i' },
        ciphers.len().min(99),
        ext_types.len().min(99),
        body_of(EXT_ALPN).and_then(first_protocol).unwrap_or_else(|| "00".to_string()),
        short_hash(&hashed_ciphers.join(",")),
        short_hash(&extension_hash_input),
    )
}

/// Truncated SHA-256 of a comma-joined list, which is all JA4 hashes carry.
fn short_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().take(6).map(|byte| format!("{byte:02x}")).collect()
}

/// The `supported_versions` a ClientHello advertises, GREASE stripped.
fn supported_versions(body: &[u8]) -> Vec<u16> {
    body.get(1..)
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .filter(|version| !is_grease(*version))
        .collect()
}

/// The `signature_algorithms` list, in wire order, GREASE stripped.
fn signature_schemes(body: &[u8]) -> Vec<u16> {
    body.get(2..)
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .filter(|scheme| !is_grease(*scheme))
        .collect()
}

/// The first ALPN protocol, in JA4's two-character form.
fn first_protocol(body: &[u8]) -> Option<String> {
    let list = body.get(2..)?;
    let length = *list.first()? as usize;
    let name = list.get(1..1 + length)?;
    if name.is_empty() {
        return Some("00".to_string());
    }
    // A non-ASCII first byte is reported as 99 rather than mangled, which is
    // what the reference implementation does.
    if !name[0].is_ascii() {
        return Some("99".to_string());
    }
    Some(match name.len() {
        1 | 2 => String::from_utf8_lossy(name).to_string(),
        _ => format!("{}{}", name[0] as char, *name.last()? as char),
    })
}

/// JA4's two-character TLS version field: the highest version offered, or the
/// ClientHello's own legacy version when `supported_versions` is not there at
/// all — which is what a browser pinned to TLS 1.2 sends, and what the JA4
/// specification reads in that case. A hello without the extension is not a
/// TLS 1.0 client, so the legacy `0x0301` record version is not a fallback.
fn version_field(versions: Vec<u16>, legacy_version: u16) -> &'static str {
    match versions.iter().copied().max().unwrap_or(legacy_version) {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}
