//! QUIC v1 Initial packets: build one, protect it, take a server's reply apart.
//!
//! Only what a probe needs lives here: the v1 long header (RFC 9000 §17.2), the
//! Initial secrets and the two protections (RFC 9001 §5.2–§5.4), and the frames
//! a server can put in a packet sent before its handshake completes (§12.4).
//! Nothing in this module knows what a TLS message is — a ClientHello is opaque
//! bytes inside one `CRYPTO` frame.
//!
//! The Initial keys are derived from the *client's* destination connection ID
//! (RFC 9001 §5.2), and that value is on the wire, so a probe can both build a
//! protected Initial and read the server's first reply without any TLS state at
//! all. That is the whole reason the module exists: it answers "does the QUIC
//! path work", not "what did the site answer" — the latter needs a handshake,
//! and the provider in this tree declares `quic: None` for every suite
//! (`docs/ADDING_A_PROFILE.md` §6).
//!
//! The vectors of RFC 9001 Appendix A pin every byte-level decision here:
//! A.1 the key schedule, A.2 the client header protection, A.3 a whole server
//! Initial in both directions, A.4 the Retry integrity tag.

use std::collections::BTreeMap;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::aes::cipher::generic_array::GenericArray;
use aes_gcm::aes::cipher::BlockEncrypt;
use aes_gcm::aes::Aes128;
use aes_gcm::{Aes128Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// The version a probe offers, and the only one this module can protect.
pub const VERSION_1: u32 = 0x0000_0001;

/// The smallest datagram a client may send in an Initial (RFC 9000 §14.1): a
/// server may — and several do — drop anything shorter.
pub const INITIAL_DATAGRAM: usize = 1200;

/// The sample length header protection reads (RFC 9001 §5.4.2) and the AEAD tag
/// length, which the three Initial-suite AEADs share.
const SAMPLE_LEN: usize = 16;
const TAG_LEN: usize = 16;

/// How many bytes of packet number this module writes. Two is legal (§17.1) and
/// still leaves the four-byte sample of §5.4.2 well inside the payload.
const PN_LEN: usize = 2;

/// The longest connection ID a v1 header can carry (§17.2).
const MAX_CID: usize = 20;

/// `initial_salt` for v1 (RFC 9001 §5.2).
const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// The key and nonce the Retry integrity tag is computed with (RFC 9001 §5.8).
/// Fixed by the RFC, because a client has no key material before the handshake.
const RETRY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// Handshake type of a ServerHello (RFC 8446 §4.1.3). A `CRYPTO` stream that
/// starts with this byte is a server that answered the handshake, which is the
/// strongest thing an Initial-only probe can see.
pub const SERVER_HELLO: u8 = 0x02;

/// The `ServerHello.random` a HelloRetryRequest carries in place of its own
/// (RFC 8446 §4.1.4). A retry means the server wants another key share, not that
/// the path is broken.
pub const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum QuicError {
    #[error("datagram is {len} bytes, too short for a {wanted}-byte field")]
    Short { len: usize, wanted: usize },
    #[error("a connection ID is {len} bytes, over the {MAX_CID} a v1 header carries")]
    ConnectionId { len: usize },
    #[error("QUIC version {version:#010x} is not v1")]
    Version { version: u32 },
    #[error("a varint does not fit in the bytes that are left")]
    Varint,
    #[error("the Initial key schedule could not be expanded")]
    Keys,
    #[error("packet protection did not authenticate")]
    Protected,
    #[error("{frame} bytes of frames do not fit in a {datagram}-byte datagram")]
    Oversized { frame: usize, datagram: usize },
    #[error("frame type {frame_type:#x} is not parsed")]
    Frame { frame_type: u64 },
}

/// One direction's Initial secrets (RFC 9001 §5.2): the AEAD key, the nonce
/// base, and the header-protection key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Secrets {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

/// The two directions of one Initial packet number space.
///
/// Both halves come from the same destination connection ID, so a caller that
/// built the packet can read the reply to it and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitialKeys {
    client: Secrets,
    server: Secrets,
}

impl InitialKeys {
    /// Derives both directions from the client's chosen destination connection
    /// ID (RFC 9001 §5.2). The ID is the one the *client* sent, whatever the
    /// server echoes back.
    pub fn derive(dcid: &[u8]) -> Result<Self, QuicError> {
        let (prk, _) = Hkdf::<Sha256>::extract(Some(&INITIAL_SALT), dcid);
        let mut client_secret = [0u8; 32];
        let mut server_secret = [0u8; 32];
        expand_label(prk.as_slice(), "client in", &mut client_secret)?;
        expand_label(prk.as_slice(), "server in", &mut server_secret)?;
        Ok(Self {
            client: Secrets::from_secret(&client_secret)?,
            server: Secrets::from_secret(&server_secret)?,
        })
    }
}

impl Secrets {
    fn from_secret(secret: &[u8]) -> Result<Self, QuicError> {
        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        let mut hp = [0u8; 16];
        expand_label(secret, "quic key", &mut key)?;
        expand_label(secret, "quic iv", &mut iv)?;
        expand_label(secret, "quic hp", &mut hp)?;
        Ok(Self { key, iv, hp })
    }
}

/// The `HkdfLabel` of RFC 8446 §7.1 with an empty context, which is every label
/// QUIC derives: `length || "tls13 " + label || 0`.
fn label_info(label: &str, length: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(full.len() + 4);
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    info
}

/// `HKDF-Expand-Label(secret, label, "", length)` (RFC 8446 §7.1).
fn expand_label(secret: &[u8], label: &str, out: &mut [u8]) -> Result<(), QuicError> {
    // The secret is the PRK from the extract step, and every length here is
    // inside one SHA-256 block, so neither failure can happen with the labels
    // and sizes this module uses — both are errors rather than panics because
    // the sizes come from the caller's slice.
    let hkdf = Hkdf::<Sha256>::from_prk(secret).map_err(|_| QuicError::Keys)?;
    hkdf.expand(&label_info(label, out.len()), out).map_err(|_| QuicError::Keys)
}

/// The AEAD nonce of RFC 9001 §5.3: the packet number, big-endian, XORed into
/// the low eight bytes of the nonce base.
fn nonce_for(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    for (slot, byte) in nonce[4..].iter_mut().zip(packet_number.to_be_bytes()) {
        *slot ^= byte;
    }
    nonce
}

fn aead(secrets: &Secrets) -> Aes128Gcm {
    Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&secrets.key))
}

/// The five mask bytes of RFC 9001 §5.4.3: one AES-ECB block over the sample.
fn hp_mask(secrets: &Secrets, sample: &[u8]) -> Result<[u8; 5], QuicError> {
    if sample.len() < SAMPLE_LEN {
        return Err(QuicError::Short { len: sample.len(), wanted: SAMPLE_LEN });
    }
    let cipher = Aes128::new(GenericArray::from_slice(&secrets.hp));
    let mut block = GenericArray::clone_from_slice(&sample[..SAMPLE_LEN]);
    cipher.encrypt_block(&mut block);
    let mut mask = [0u8; 5];
    mask.copy_from_slice(&block[..5]);
    Ok(mask)
}

/// Applies header protection (RFC 9001 §5.4.1) to a protected packet in place.
fn protect_header(secrets: &Secrets, packet: &mut [u8], pn_offset: usize) -> Result<(), QuicError> {
    let sample_at = pn_offset + 4;
    if sample_at + SAMPLE_LEN > packet.len() {
        return Err(QuicError::Short { len: packet.len(), wanted: sample_at + SAMPLE_LEN });
    }
    let sample = packet[sample_at..sample_at + SAMPLE_LEN].to_vec();
    let mask = hp_mask(secrets, &sample)?;
    packet[0] ^= mask[0] & 0x0f;
    for (slot, mask_byte) in packet[pn_offset..pn_offset + PN_LEN].iter_mut().zip(&mask[1..]) {
        *slot ^= mask_byte;
    }
    Ok(())
}

/// Removes header protection and returns the packet number plus the offset the
/// packet number field starts at, with the packet's header now in the clear.
fn unprotect_header(
    secrets: &Secrets,
    packet: &mut [u8],
    pn_offset: usize,
    largest_pn: u64,
) -> Result<(u64, usize), QuicError> {
    let sample_at = pn_offset + 4;
    if sample_at + SAMPLE_LEN > packet.len() {
        return Err(QuicError::Short { len: packet.len(), wanted: sample_at + SAMPLE_LEN });
    }
    let sample = packet[sample_at..sample_at + SAMPLE_LEN].to_vec();
    let mask = hp_mask(secrets, &sample)?;
    packet[0] ^= mask[0] & 0x0f;
    let pn_len = (packet[0] & 0x03) as usize + 1;
    if pn_offset + pn_len > packet.len() {
        return Err(QuicError::Short { len: packet.len(), wanted: pn_offset + pn_len });
    }
    let mut truncated = 0u64;
    for (index, slot) in packet[pn_offset..pn_offset + pn_len].iter_mut().enumerate() {
        *slot ^= mask[1 + index];
        truncated = (truncated << 8) | u64::from(*slot);
    }
    Ok((decode_packet_number(largest_pn, truncated, pn_len), pn_len))
}

/// `DecodePacketNumber` of RFC 9000 §A.3.
fn decode_packet_number(largest_pn: u64, truncated: u64, pn_len: usize) -> u64 {
    let expected = largest_pn.wrapping_add(1);
    let window = 1u64 << (pn_len * 8);
    let half = window / 2;
    let candidate = (expected & !(window - 1)) | truncated;
    if candidate + half <= expected {
        candidate + window
    } else if candidate > expected + half {
        candidate.wrapping_sub(window)
    } else {
        candidate
    }
}

/// Appends `value` in the shortest of the four varint forms (RFC 9000 §16).
pub fn write_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=63 => out.push(value as u8),
        64..=16_383 => out.extend_from_slice(&(0x4000u16 | value as u16).to_be_bytes()),
        16_384..=1_073_741_823 => {
            out.extend_from_slice(&(0x8000_0000u32 | value as u32).to_be_bytes());
        }
        _ => out.extend_from_slice(&(0xc000_0000_0000_0000u64 | value).to_be_bytes()),
    }
}

/// Reads one varint at `at`, returning it and the offset after it.
pub fn read_varint(buf: &[u8], at: usize) -> Result<(u64, usize), QuicError> {
    let first = *buf.get(at).ok_or(QuicError::Varint)?;
    let width = 1usize << (first >> 6);
    let end = at + width;
    if end > buf.len() {
        return Err(QuicError::Varint);
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &buf[at + 1..end] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, end))
}

/// The client's first flight: `crypto` split across as many Initial datagrams as
/// it takes, each padded to [`INITIAL_DATAGRAM`].
///
/// A browser-shaped ClientHello is usually larger than one datagram — a
/// post-quantum key share alone is 1216 bytes — and the RFC's answer is not a
/// smaller hello: every Initial is padded to at least 1200 bytes (RFC 9000
/// §14.1) and the handshake data continues in the next packet's `CRYPTO` frame
/// at its own offset (§19.6). A single-datagram builder would have to truncate
/// the ClientHello or drop part of the shape, and both send something no client
/// sends.
///
/// The packet numbers start at `first_pn`: a retransmission is the same CRYPTO
/// data under new numbers (RFC 9002 §6.2.4), so a caller that repeats its flight
/// passes the next block rather than resealing packet 0.
pub fn client_initials(
    keys: &InitialKeys,
    dcid: &[u8],
    scid: &[u8],
    crypto: &[u8],
    first_pn: u64,
) -> Result<Vec<Vec<u8>>, QuicError> {
    for cid in [dcid, scid] {
        if cid.len() > MAX_CID {
            return Err(QuicError::ConnectionId { len: cid.len() });
        }
    }

    // The length field is a two-byte varint for any packet padded to 1200 bytes,
    // which every packet here is, so the header's size is known before the
    // frames are built and the padding can go straight into them.
    let header_len = 1 + 4 + 1 + dcid.len() + 1 + scid.len() + 1 + 2 + PN_LEN;
    let capacity = INITIAL_DATAGRAM
        .checked_sub(header_len + TAG_LEN)
        .ok_or(QuicError::Oversized { frame: header_len + TAG_LEN, datagram: INITIAL_DATAGRAM })?;

    let mut out = Vec::new();
    let mut offset = 0usize;
    let mut packet_number = first_pn;
    loop {
        let remaining = crypto.len() - offset;
        // Shrink the chunk until its own CRYPTO frame header fits beside it: the
        // offset and length varints grow with the values, so this is a small
        // fixed point rather than a formula.
        let mut chunk = remaining.min(capacity);
        loop {
            let need = 1 + varint_len(offset as u64) + varint_len(chunk as u64) + chunk;
            if need <= capacity || chunk == 0 {
                break;
            }
            chunk -= need - capacity;
        }

        let mut frames = Vec::with_capacity(capacity);
        frames.push(0x06); // CRYPTO
        write_varint(&mut frames, offset as u64);
        write_varint(&mut frames, chunk as u64);
        frames.extend_from_slice(&crypto[offset..offset + chunk]);
        frames.resize(capacity, 0x00); // PADDING frames, §19.1

        out.push(seal_initial(keys, dcid, scid, packet_number, frames)?);
        offset += chunk;
        packet_number += 1;
        if offset >= crypto.len() {
            break;
        }
    }
    Ok(out)
}

/// One protected Initial datagram: header, packet number, `frames` sealed and
/// the header protection applied.
fn seal_initial(
    keys: &InitialKeys,
    dcid: &[u8],
    scid: &[u8],
    packet_number: u64,
    frames: Vec<u8>,
) -> Result<Vec<u8>, QuicError> {
    let mut packet = Vec::with_capacity(INITIAL_DATAGRAM);
    packet.push(0xc0 | (PN_LEN as u8 - 1)); // long header, Initial, fixed bit
    packet.extend_from_slice(&VERSION_1.to_be_bytes());
    packet.push(dcid.len() as u8);
    packet.extend_from_slice(dcid);
    packet.push(scid.len() as u8);
    packet.extend_from_slice(scid);
    packet.push(0x00); // no token
    write_varint(&mut packet, (PN_LEN + frames.len() + TAG_LEN) as u64);
    let pn_offset = packet.len();
    packet.extend_from_slice(&packet_number.to_be_bytes()[8 - PN_LEN..]);

    // The AEAD covers header + packet number as associated data (RFC 9001 §5.3).
    let aad = packet.clone();
    let mut payload = frames;
    seal(&keys.client, &aad, packet_number, &mut payload)?;
    packet.extend_from_slice(&payload);
    protect_header(&keys.client, &mut packet, pn_offset)?;
    Ok(packet)
}

/// How many bytes `value` takes in the shortest varint form (§16).
pub fn varint_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// Seals `payload` in place, leaving the tag at its end — which is the order the
/// wire wants, and why the detached API is not used here.
fn seal(
    secrets: &Secrets,
    aad: &[u8],
    packet_number: u64,
    payload: &mut Vec<u8>,
) -> Result<(), QuicError> {
    let nonce = nonce_for(&secrets.iv, packet_number);
    aead(secrets)
        .encrypt_in_place(Nonce::from_slice(&nonce), aad, payload)
        .map_err(|_| QuicError::Protected)
}

/// Opens `ciphertext` (payload and tag) in place, returning the plaintext
/// length. `aad` is the unprotected header.
fn open(
    secrets: &Secrets,
    aad: &[u8],
    packet_number: u64,
    ciphertext: &mut Vec<u8>,
) -> Result<usize, QuicError> {
    let plain_len = ciphertext.len().checked_sub(TAG_LEN).ok_or(QuicError::Protected)?;
    let nonce = nonce_for(&secrets.iv, packet_number);
    aead(secrets)
        .decrypt_in_place(Nonce::from_slice(&nonce), aad, ciphertext)
        .map_err(|_| QuicError::Protected)?;
    Ok(plain_len)
}

/// The Retry integrity tag of RFC 9001 §5.8: an AEAD over the original
/// destination connection ID and the Retry packet without its tag.
fn retry_tag(original_dcid: &[u8], retry_without_tag: &[u8]) -> Result<[u8; TAG_LEN], QuicError> {
    let mut pseudo = Vec::with_capacity(1 + original_dcid.len() + retry_without_tag.len());
    pseudo.push(original_dcid.len() as u8);
    pseudo.extend_from_slice(original_dcid);
    pseudo.extend_from_slice(retry_without_tag);
    let secrets = Secrets { key: RETRY_KEY, iv: RETRY_NONCE, hp: [0u8; 16] };
    let mut tag = Vec::new();
    seal(&secrets, &pseudo, 0, &mut tag)?;
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// What a server sent in reply to an Initial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerReply {
    /// A v1 Initial: its protection came off, and these are its frames in order.
    Initial(Vec<Frame>),
    /// A Retry (§17.2.5). `authenticated` is the integrity tag of §5.8 having
    /// matched, which is what separates the endpoint's own Retry from an
    /// off-path packet that merely looks like one.
    Retry { token: Vec<u8>, authenticated: bool },
    /// Version Negotiation: the endpoint does not speak v1 (§6).
    VersionNegotiation { versions: Vec<u32> },
    /// A short header — a 1-RTT packet, which cannot belong to a handshake this
    /// probe never started, or a stateless reset (§10.3).
    ShortHeader,
}

/// The frames this module reads; anything else is [`Frame::Other`] with its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A run of `PADDING` frames, which are one byte each.
    Padding(usize),
    Ping,
    Ack,
    Crypto {
        offset: u64,
        data: Vec<u8>,
    },
    /// `CONNECTION_CLOSE` (§19.19). `frame_type` is present only in the
    /// transport-error form; the application form has none.
    ConnectionClose {
        error_code: u64,
        frame_type: Option<u64>,
        reason: String,
    },
    HandshakeDone,
    Other(u64),
}

/// Takes one datagram apart.
///
/// `largest_pn` is the largest packet number already read from this endpoint —
/// the packet number is truncated on the wire, and §A.3 needs something to
/// reconstruct it around. A probe reading the server's first Initial passes 0.
pub fn open_datagram(
    keys: &InitialKeys,
    original_dcid: &[u8],
    datagram: &[u8],
    largest_pn: u64,
) -> Result<ServerReply, QuicError> {
    let first = *datagram.first().ok_or(QuicError::Short { len: 0, wanted: 1 })?;
    if first & 0x80 == 0 {
        return Ok(ServerReply::ShortHeader);
    }
    let version_bytes = datagram.get(1..5).ok_or(QuicError::Short { len: datagram.len(), wanted: 5 })?;
    let version = u32::from_be_bytes([version_bytes[0], version_bytes[1], version_bytes[2], version_bytes[3]]);
    let mut at = 5;
    take_cid(datagram, &mut at)?; // destination: the server's own ID, opaque here
    take_cid(datagram, &mut at)?; // source: the ID the server chose

    // Version 0 is the negotiation packet (§6): the same header, then a list of
    // the versions the endpoint does speak, with 0 first by construction.
    if version == 0 {
        let versions = datagram[at..]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|quad| u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]]))
            .collect();
        return Ok(ServerReply::VersionNegotiation { versions });
    }
    if version != VERSION_1 {
        return Err(QuicError::Version { version });
    }

    match (first & 0x30) >> 4 {
        // Initial
        0 => {
            let (token_len, after_token_len) = read_varint(datagram, at)?;
            let after_token = after_token_len
                .checked_add(token_len as usize)
                .ok_or(QuicError::Varint)?;
            let (length, pn_offset) = read_varint(datagram, after_token)?;
            let length = length as usize;
            if length < TAG_LEN + 1 || pn_offset + length > datagram.len() {
                return Err(QuicError::Short { len: datagram.len(), wanted: pn_offset + length });
            }
            let mut packet = datagram[..pn_offset + length].to_vec();
            let (packet_number, pn_len) = unprotect_header(&keys.server, &mut packet, pn_offset, largest_pn)?;
            let aad_end = pn_offset + pn_len;
            let aad = packet[..aad_end].to_vec();
            let mut ciphertext = packet[aad_end..].to_vec();
            let plain_len = open(&keys.server, &aad, packet_number, &mut ciphertext)?;
            Ok(ServerReply::Initial(parse_frames(&ciphertext[..plain_len])?))
        }
        // Retry
        3 => {
            if datagram.len() < at + TAG_LEN {
                return Err(QuicError::Short { len: datagram.len(), wanted: at + TAG_LEN });
            }
            let (body, tag) = datagram.split_at(datagram.len() - TAG_LEN);
            let authenticated = retry_tag(original_dcid, body)? == tag;
            Ok(ServerReply::Retry { token: body[at..].to_vec(), authenticated })
        }
        // 0-RTT and Handshake carry protection this module has no keys for.
        other => Err(QuicError::Frame { frame_type: u64::from(other) << 4 }),
    }
}

/// Reads a length-prefixed connection ID (§17.2: one byte of length, then bytes).
fn take_cid(buf: &[u8], at: &mut usize) -> Result<(), QuicError> {
    let len = usize::from(*buf.get(*at).ok_or(QuicError::Short { len: buf.len(), wanted: *at + 1 })?);
    if len > MAX_CID {
        return Err(QuicError::ConnectionId { len });
    }
    *at += 1 + len;
    if *at > buf.len() {
        return Err(QuicError::Short { len: buf.len(), wanted: *at });
    }
    Ok(())
}

/// The CRYPTO stream of one endpoint, reassembled in order (§19.6).
///
/// A server may split the ServerHello across packets, and the offsets are
/// absolute, so the chunks are kept by offset and read back from 0.
#[derive(Debug, Default)]
pub struct CryptoStream {
    chunks: BTreeMap<u64, Vec<u8>>,
    /// Bytes held, so `push` can refuse to grow past [`CRYPTO_CAP`] without
    /// walking the map.
    held: usize,
}

/// How much of one reply's CRYPTO stream is kept. The probe reads the handshake
/// type off the first message and a ServerHello is a couple of kilobytes, so
/// this is generous for its purpose — and finite for a hostile endpoint: the map
/// is keyed by offset, so without a cap every datagram it sends inside the
/// window buys another entry.
const CRYPTO_CAP: usize = 16 * 1024;

impl CryptoStream {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one chunk. A chunk that is already held is ignored, so a
    /// retransmitted packet does not duplicate the stream; a chunk that would
    /// take the stream past `CRYPTO_CAP` is dropped whole.
    pub fn push(&mut self, offset: u64, data: &[u8]) {
        if data.is_empty() || self.held + data.len() > CRYPTO_CAP {
            return;
        }
        if let std::collections::btree_map::Entry::Vacant(slot) = self.chunks.entry(offset) {
            slot.insert(data.to_vec());
            self.held += data.len();
        }
    }

    /// Everything the stream holds from offset 0 up to the first gap.
    pub fn assembled(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut at = 0u64;
        for (offset, data) in &self.chunks {
            if *offset > at {
                break;
            }
            let skip = (at - offset) as usize;
            if skip < data.len() {
                out.extend_from_slice(&data[skip..]);
                at += (data.len() - skip) as u64;
            }
        }
        out
    }

    /// The TLS handshake type the stream opens with, if any — see
    /// [`SERVER_HELLO`].
    pub fn handshake_type(&self) -> Option<u8> {
        self.assembled().first().copied()
    }
}

/// Parses the frames of one packet's payload (§12.4), in order.
fn parse_frames(payload: &[u8]) -> Result<Vec<Frame>, QuicError> {
    let mut frames = Vec::new();
    let mut at = 0usize;
    while at < payload.len() {
        let frame_type_end = read_varint(payload, at)?;
        let frame_type = frame_type_end.0;
        at = frame_type_end.1;
        match frame_type {
            // PADDING, one byte each.
            0x00 => {
                let start = at;
                while payload.get(at) == Some(&0x00) {
                    at += 1;
                }
                frames.push(Frame::Padding(1 + at - start));
            }
            0x01 => frames.push(Frame::Ping),
            // ACK: largest, delay, range count, first range, then the ranges.
            0x02 | 0x03 => {
                let ranges = {
                    let (_, next) = read_varint(payload, at)?; // largest acknowledged
                    let (_, next) = read_varint(payload, next)?; // ack delay
                    let (count, next) = read_varint(payload, next)?;
                    let (_, next) = read_varint(payload, next)?; // first range
                    let mut next = next;
                    for _ in 0..count {
                        let (_, after_gap) = read_varint(payload, next)?;
                        let (_, after_range) = read_varint(payload, after_gap)?;
                        next = after_range;
                    }
                    next
                };
                at = ranges;
                if frame_type == 0x03 {
                    // ECN counts: total, then the two per-marking counts.
                    for _ in 0..3 {
                        let (_, next) = read_varint(payload, at)?;
                        at = next;
                    }
                }
                frames.push(Frame::Ack);
            }
            // RESET_STREAM: stream ID, application error, final size.
            0x04 | 0x05 => {
                let (_, next) = read_varint(payload, at)?;
                let fields = if frame_type == 0x04 { 2 } else { 1 };
                let mut next = next;
                for _ in 0..fields {
                    let (_, after) = read_varint(payload, next)?;
                    next = after;
                }
                at = next;
                frames.push(Frame::Other(frame_type));
            }
            0x06 => {
                let (offset, next) = read_varint(payload, at)?;
                let (len, next) = read_varint(payload, next)?;
                let end = next.checked_add(len as usize).ok_or(QuicError::Varint)?;
                if end > payload.len() {
                    return Err(QuicError::Short { len: payload.len(), wanted: end });
                }
                frames.push(Frame::Crypto { offset, data: payload[next..end].to_vec() });
                at = end;
            }
            // NEW_TOKEN: a length and that many bytes.
            0x07 => {
                let (len, next) = read_varint(payload, at)?;
                at = next.checked_add(len as usize).ok_or(QuicError::Varint)?;
                if at > payload.len() {
                    return Err(QuicError::Short { len: payload.len(), wanted: at });
                }
                frames.push(Frame::Other(frame_type));
            }
            // STREAM: ID, [offset], [length], data (§19.8).
            0x08..=0x0f => {
                let (_, next) = read_varint(payload, at)?;
                let mut next = next;
                if frame_type & 0x04 != 0 {
                    let (_, after) = read_varint(payload, next)?;
                    next = after;
                }
                if frame_type & 0x02 != 0 {
                    let (len, after) = read_varint(payload, next)?;
                    next = after.checked_add(len as usize).ok_or(QuicError::Varint)?;
                } else {
                    next = payload.len();
                }
                if next > payload.len() {
                    return Err(QuicError::Short { len: payload.len(), wanted: next });
                }
                at = next;
                frames.push(Frame::Other(frame_type));
            }
            // MAX_DATA, MAX_STREAMS, DATA_BLOCKED, STREAMS_BLOCKED: one varint.
            0x10 | 0x12 | 0x13 | 0x14 | 0x16 | 0x17 => {
                let (_, next) = read_varint(payload, at)?;
                at = next;
                frames.push(Frame::Other(frame_type));
            }
            // MAX_STREAM_DATA, STREAM_DATA_BLOCKED: two varints.
            0x11 | 0x15 => {
                let (_, next) = read_varint(payload, at)?;
                let (_, next) = read_varint(payload, next)?;
                at = next;
                frames.push(Frame::Other(frame_type));
            }
            // NEW_CONNECTION_ID: sequence, retire-prior, one length byte, the ID
            // itself, then a sixteen-byte stateless-reset token.
            0x18 => {
                let (_, next) = read_varint(payload, at)?;
                let (_, next) = read_varint(payload, next)?;
                let cid_len = usize::from(*payload.get(next).ok_or(QuicError::Varint)?);
                at = next + 1 + cid_len + 16;
                if at > payload.len() {
                    return Err(QuicError::Short { len: payload.len(), wanted: at });
                }
                frames.push(Frame::Other(frame_type));
            }
            // RETIRE_CONNECTION_ID: one varint.
            0x19 => {
                let (_, next) = read_varint(payload, at)?;
                at = next;
                frames.push(Frame::Other(frame_type));
            }
            // PATH_CHALLENGE and PATH_RESPONSE carry eight bytes.
            0x1a | 0x1b => {
                at += 8;
                if at > payload.len() {
                    return Err(QuicError::Short { len: payload.len(), wanted: at });
                }
                frames.push(Frame::Other(frame_type));
            }
            0x1c | 0x1d => {
                let (error_code, next) = read_varint(payload, at)?;
                let (frame_type_field, next) = if frame_type == 0x1c {
                    let (inner, after) = read_varint(payload, next)?;
                    (Some(inner), after)
                } else {
                    (None, next)
                };
                let (reason_len, next) = read_varint(payload, next)?;
                let end = next.checked_add(reason_len as usize).ok_or(QuicError::Varint)?;
                if end > payload.len() {
                    return Err(QuicError::Short { len: payload.len(), wanted: end });
                }
                frames.push(Frame::ConnectionClose {
                    error_code,
                    frame_type: frame_type_field,
                    reason: String::from_utf8_lossy(&payload[next..end]).into_owned(),
                });
                at = end;
            }
            0x1e => frames.push(Frame::HandshakeDone),
            other => return Err(QuicError::Frame { frame_type: other }),
        }
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC prints its vectors as hex; the tests read them the same way so a
    /// transcription slip is a failing assertion rather than a typo nobody sees.
    fn unhex(hex: &str) -> Vec<u8> {
        let digits: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..digits.len() / 2)
            .map(|i| u8::from_str_radix(&digits[i * 2..i * 2 + 2], 16).expect("the vector is hex"))
            .collect()
    }

    /// The connection ID every Appendix A vector is built from.
    const DCID: &str = "8394c8f03e515708";

    #[test]
    fn the_a1_labels_are_what_the_rfc_prints() {
        // A.1 lists the HkdfLabel bytes, which is the one place the label format
        // is pinned against something outside this file.
        assert_eq!(
            label_info("client in", 32),
            unhex("00200f746c73313320636c69656e7420696e00")
        );
        assert_eq!(
            label_info("server in", 32),
            unhex("00200f746c7331332073657276657220696e00")
        );
        assert_eq!(label_info("quic key", 16), unhex("00100e746c7331332071756963206b657900"));
        assert_eq!(label_info("quic iv", 12), unhex("000c0d746c733133207175696320697600"));
        assert_eq!(label_info("quic hp", 16), unhex("00100d746c733133207175696320687000"));
    }

    #[test]
    fn the_a1_initial_keys_are_derived_from_the_connection_id() {
        let keys = InitialKeys::derive(&unhex(DCID)).expect("a key schedule");
        assert_eq!(keys.client.key, unhex("1f369613dd76d5467730efcbe3b1a22d").as_slice());
        assert_eq!(keys.client.iv, unhex("fa044b2f42a3fd3b46fb255c").as_slice());
        assert_eq!(keys.client.hp, unhex("9f50449e04a0e810283a1e9933adedd2").as_slice());
        assert_eq!(keys.server.key, unhex("cf3a5331653c364c88f0f379b6067e37").as_slice());
        assert_eq!(keys.server.iv, unhex("0ac1493ca1905853b0bba03e").as_slice());
        assert_eq!(keys.server.hp, unhex("c206b8d9b9f0f37644430b490eeaa314").as_slice());
    }

    #[test]
    fn the_a2_header_protection_produces_the_masked_header() {
        // A.2 gives the unprotected header, the sample, and the masked result, so
        // this pins the mask and where it lands without rebuilding the packet.
        let keys = InitialKeys::derive(&unhex(DCID)).expect("a key schedule");
        let mut header = unhex("c300000001088394c8f03e5157080000449e00000002");
        let sample = unhex("d1b1c98dd7689fb8ec11d242b123dc9b");
        let mask = hp_mask(&keys.client, &sample).expect("a sample of the right length");
        assert_eq!(mask, unhex("437b9aec36").as_slice());
        header[0] ^= mask[0] & 0x0f;
        for (slot, byte) in header[18..22].iter_mut().zip(&mask[1..]) {
            *slot ^= byte;
        }
        assert_eq!(header, unhex("c000000001088394c8f03e5157080000449e7b9aec34"));
    }

    /// The A.3 server Initial, protected, exactly as the RFC prints it.
    const A3_PACKET: &str = "cf000000010008f067a5502a4262b500\
4075c0d95a482cd0991cd25b0aac406a\
5816b6394100f37a1c69797554780bb3\
8cc5a99f5ede4cf73c3ec2493a1839b3\
dbcba3f6ea46c5b7684df3548e7ddeb9\
c3bf9c73cc3f3bded74b562bfb19fb84\
022f8ef4cdd93795d77d06edbb7aaf2f\
58891850abbdca3d20398c276456cbc4\
2158407dd074ee";

    /// The A.3 plaintext payload: an ACK, then the CRYPTO frame with the
    /// ServerHello.
    const A3_PAYLOAD: &str = "02000000000600405a020000560303ee\
fce7f7b37ba1d1632e96677825ddf739\
88cfc79825df566dc5430b9a045a1200\
130100002e00330024001d00209d3c94\
0d89690b84d08a60993c144eca684d10\
81287c834d5311bcf32bb9da1a002b00\
020304";

    /// The A.3 header, with packet number 1 in two bytes.
    const A3_HEADER: &str = "c1000000010008f067a5502a4262b50040750001";

    #[test]
    fn the_a3_server_initial_opens_into_an_ack_and_the_server_hello() {
        let keys = InitialKeys::derive(&unhex(DCID)).expect("a key schedule");
        let reply = open_datagram(&keys, &unhex(DCID), &unhex(A3_PACKET), 0).expect("a readable reply");
        let ServerReply::Initial(frames) = reply else {
            panic!("the vector is an Initial, got {reply:?}");
        };
        assert_eq!(frames[0], Frame::Ack);

        let mut stream = CryptoStream::new();
        for frame in &frames {
            if let Frame::Crypto { offset, data } = frame {
                stream.push(*offset, data);
            }
        }
        assert_eq!(stream.handshake_type(), Some(SERVER_HELLO));
        // The CRYPTO frame's payload is the ServerHello itself: handshake type
        // 0x02, length 0x000056, then the message — 90 bytes, as the frame's own
        // `405a` length field says.
        assert_eq!(stream.assembled(), unhex("020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304"));
        assert_eq!(stream.assembled().len(), 90);
    }

    #[test]
    fn the_a3_header_and_payload_seal_to_the_published_packet() {
        // The other direction, on the same vector: the header and payload of
        // A.3 through the AEAD and the header protection must reproduce the
        // RFC's protected bytes exactly. `A3_HEADER` is the *unprotected* header
        // A.3 prints (packet number 1 in two bytes), and `A3_PACKET` the result.
        let keys = InitialKeys::derive(&unhex(DCID)).expect("a key schedule");
        let header = unhex(A3_HEADER);
        let mut payload = unhex(A3_PAYLOAD);
        seal(&keys.server, &header, 1, &mut payload).expect("a sealable payload");
        let mut packet = header;
        packet.extend_from_slice(&payload);
        protect_header(&keys.server, &mut packet, 18).expect("a protected header");
        assert_eq!(packet, unhex(A3_PACKET));
    }

    #[test]
    fn the_a4_retry_integrity_tag_is_reproduced() {
        let retry = unhex("ff000000010008f067a5502a4262b5746f6b656e");
        let tag = retry_tag(&unhex(DCID), &retry).expect("a tag");
        assert_eq!(tag, unhex("04a265ba2eff4d829058fb3f0f2496ba").as_slice());
        // And the same value read off a whole Retry packet: the tag is the last
        // sixteen bytes, and the check is what a probe trusts the reply with.
        let mut packet = retry.clone();
        packet.extend_from_slice(&tag);
        let keys = InitialKeys::derive(&unhex(DCID)).expect("a key schedule");
        let reply = open_datagram(&keys, &unhex(DCID), &packet, 0).expect("a Retry");
        assert_eq!(
            reply,
            ServerReply::Retry { token: b"token".to_vec(), authenticated: true }
        );
    }

    #[test]
    fn a_datagram_that_is_not_the_endpoints_retry_fails_the_check() {
        // A tag that does not match is the one thing that separates a router's
        // injected packet from the endpoint's own Retry.
        let mut packet = unhex("ff000000010008f067a5502a4262b5746f6b656e");
        packet.extend_from_slice(&[0u8; 16]);
        let keys = InitialKeys::derive(&unhex(DCID)).expect("a key schedule");
        let reply = open_datagram(&keys, &unhex(DCID), &packet, 0).expect("a Retry");
        assert_eq!(
            reply,
            ServerReply::Retry { token: b"token".to_vec(), authenticated: false }
        );
    }

    /// Reads one of our own Initials back the way a server would: clear the
    /// header protection, then open the payload with the client's keys.
    fn open_our_initial(keys: &InitialKeys, dcid: &[u8], scid: &[u8], packet: &[u8]) -> (u64, Vec<Frame>) {
        let mut copy = packet.to_vec();
        let pn_offset = 1 + 4 + 1 + dcid.len() + 1 + scid.len() + 1 + 2;
        let (pn, pn_len) = unprotect_header(&keys.client, &mut copy, pn_offset, 0).expect("a header");
        let aad = copy[..pn_offset + pn_len].to_vec();
        let mut ciphertext = copy[pn_offset + pn_len..].to_vec();
        let plain_len = open(&keys.client, &aad, pn, &mut ciphertext).expect("an openable packet");
        (pn, parse_frames(&ciphertext[..plain_len]).expect("parseable frames"))
    }

    #[test]
    fn a_small_hello_goes_in_one_1200_byte_datagram() {
        let dcid = unhex("0011223344556677");
        let scid = unhex("8899aabbccddeeff");
        let hello = unhex("010000200303") // a stand-in for a ClientHello
            .into_iter()
            .chain(std::iter::repeat_n(0x41u8, 0x20))
            .collect::<Vec<u8>>();
        let keys = InitialKeys::derive(&dcid).expect("a key schedule");
        let flight = client_initials(&keys, &dcid, &scid, &hello, 0).expect("a datagram");
        assert_eq!(flight.len(), 1, "a 38-byte hello fits one datagram");
        assert_eq!(flight[0].len(), INITIAL_DATAGRAM);

        let (pn, frames) = open_our_initial(&keys, &dcid, &scid, &flight[0]);
        assert_eq!(pn, 0);
        assert_eq!(frames[0], Frame::Crypto { offset: 0, data: hello.clone() });
        let pn_offset = 1 + 4 + 1 + dcid.len() + 1 + scid.len() + 1 + 2;
        assert_eq!(
            frames[1],
            Frame::Padding(INITIAL_DATAGRAM - pn_offset - PN_LEN - TAG_LEN - (3 + hello.len()))
        );
        // §17.2: the destination is ours, the source is the one we chose.
        assert_eq!(flight[0][5], dcid.len() as u8);
        assert_eq!(&flight[0][6..6 + dcid.len()], dcid.as_slice());
        assert_eq!(flight[0][6 + dcid.len()], scid.len() as u8);
    }

    /// A retransmission is the same CRYPTO data under new packet numbers
    /// (RFC 9002 §6.2.4): the offsets must not move — a repeat that renumbered
    /// *and* re-split would be a different handshake — and the numbers must not
    /// repeat, or the endpoint reads the second flight as the first one again.
    #[test]
    fn a_retransmission_keeps_the_offsets_and_moves_the_numbers() {
        let dcid = unhex("0011223344556677");
        let scid = unhex("8899aabbccddeeff");
        let hello = std::iter::repeat_n(0x41u8, 1800).collect::<Vec<u8>>();
        let keys = InitialKeys::derive(&dcid).expect("a key schedule");
        let first = client_initials(&keys, &dcid, &scid, &hello, 0).expect("a flight");
        assert!(first.len() > 1, "a 1800-byte hello does not fit one datagram");
        let again = client_initials(&keys, &dcid, &scid, &hello, first.len() as u64).expect("a flight");
        assert_eq!(again.len(), first.len(), "a repeat has the same shape");

        for (index, (before, after)) in first.iter().zip(&again).enumerate() {
            let (pn_before, frames_before) = open_our_initial(&keys, &dcid, &scid, before);
            let (pn_after, frames_after) = open_our_initial(&keys, &dcid, &scid, after);
            assert_eq!(pn_before, index as u64);
            assert_eq!(pn_after, (first.len() + index) as u64);
            assert_eq!(frames_before, frames_after, "the same CRYPTO, only the number moved");
        }
    }

    #[test]
    fn a_hello_larger_than_a_datagram_continues_in_the_next_packet() {
        // A browser-shaped hello carries a 1216-byte post-quantum key share, so
        // this is the ordinary case, not an edge one: the CRYPTO stream runs on
        // into the next Initial at its own offset (RFC 9000 §19.6).
        let dcid = unhex("0011223344556677");
        let scid = unhex("8899aabbccddeeff");
        let hello: Vec<u8> = (0..1700).map(|i| (i % 251) as u8).collect();
        let keys = InitialKeys::derive(&dcid).expect("a key schedule");
        let flight = client_initials(&keys, &dcid, &scid, &hello, 0).expect("a flight");
        assert_eq!(flight.len(), 2, "1700 bytes do not fit one 1200-byte datagram");
        assert!(flight.iter().all(|packet| packet.len() == INITIAL_DATAGRAM));

        let mut stream = CryptoStream::new();
        for (index, packet) in flight.iter().enumerate() {
            let (pn, frames) = open_our_initial(&keys, &dcid, &scid, packet);
            assert_eq!(pn, index as u64, "each packet carries the next number");
            for frame in frames {
                if let Frame::Crypto { offset, data } = frame {
                    stream.push(offset, &data);
                }
            }
        }
        assert_eq!(stream.assembled(), hello, "the stream reassembles in order");
    }

    #[test]
    fn a_very_large_hello_keeps_splitting_rather_than_truncating() {
        let dcid = [0x01; 8];
        let scid = [0x02; 8];
        let hello: Vec<u8> = (0..5000).map(|i| (i % 253) as u8).collect();
        let keys = InitialKeys::derive(&dcid).expect("a key schedule");
        let flight = client_initials(&keys, &dcid, &scid, &hello, 0).expect("a flight");
        assert_eq!(flight.len(), 5, "5000 bytes need five 1200-byte datagrams");
        let mut stream = CryptoStream::new();
        for packet in &flight {
            let (_, frames) = open_our_initial(&keys, &dcid, &scid, packet);
            for frame in frames {
                if let Frame::Crypto { offset, data } = frame {
                    stream.push(offset, &data);
                }
            }
        }
        assert_eq!(stream.assembled(), hello);
    }

    #[test]
    fn a_short_header_alone_is_a_stateless_reset_candidate() {
        let keys = InitialKeys::derive(&unhex(DCID)).expect("a key schedule");
        let reply = open_datagram(&keys, &unhex(DCID), &[0x40, 0x00, 0x01, 0x02], 0)
            .expect("a short header is not an error");
        assert_eq!(reply, ServerReply::ShortHeader);
    }

    #[test]
    fn a_zero_version_header_reads_as_a_negotiation_list() {
        let mut packet = vec![0xc0, 0x00, 0x00, 0x00, 0x00];
        packet.push(8);
        packet.extend_from_slice(&unhex(DCID));
        packet.push(0);
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(&VERSION_1.to_be_bytes());
        packet.extend_from_slice(&0x6b33_43cfu32.to_be_bytes());
        let keys = InitialKeys::derive(&unhex(DCID)).expect("a key schedule");
        let reply = open_datagram(&keys, &unhex(DCID), &packet, 0).expect("a negotiation packet");
        assert_eq!(
            reply,
            ServerReply::VersionNegotiation { versions: vec![0, VERSION_1, 0x6b33_43cf] }
        );
    }

    #[test]
    fn varints_round_trip_through_every_form() {
        for value in [0u64, 37, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824, (1 << 62) - 1] {
            let mut out = Vec::new();
            write_varint(&mut out, value);
            let (read, next) = read_varint(&out, 0).expect("a readable varint");
            assert_eq!(read, value, "value {value}");
            assert_eq!(next, out.len(), "value {value}");
            assert!(out.len().is_power_of_two(), "value {value} uses one of the four forms");
        }
        // 63 is the last one-byte form; 0x7f announces a two-byte form and is
        // therefore short on its own.
        assert_eq!(read_varint(&[0x3f], 0), Ok((63, 1)));
        assert_eq!(read_varint(&[0x7f], 0), Err(QuicError::Varint), "a two-byte form cut short");
        assert_eq!(read_varint(&[], 0), Err(QuicError::Varint));
    }

    #[test]
    fn packet_numbers_decode_the_way_the_rfc_works_the_example() {
        // RFC 9000 §A.3 works exactly this case.
        assert_eq!(decode_packet_number(0xa82f30ea, 0x9b32, 2), 0xa82f9b32);
        // Nothing seen yet: the truncated value is the number itself.
        assert_eq!(decode_packet_number(0, 1, 1), 1);
        assert_eq!(decode_packet_number(0, 0x1234, 2), 0x1234);
    }

    #[test]
    fn a_connection_id_over_twenty_bytes_is_refused() {
        let keys = InitialKeys::derive(&unhex(DCID)).expect("a key schedule");
        let long = [0u8; 21];
        assert_eq!(
            client_initials(&keys, &long, &[0u8; 8], b"hello", 0),
            Err(QuicError::ConnectionId { len: 21 })
        );
    }

    #[test]
    fn the_crypto_stream_reassembles_by_offset() {
        let mut stream = CryptoStream::new();
        stream.push(4, &[0x05, 0x06]);
        stream.push(0, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(stream.assembled(), vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(stream.handshake_type(), Some(0x01));

        // A gap stops the read where it starts.
        let mut gapped = CryptoStream::new();
        gapped.push(0, &[0x02]);
        gapped.push(4, &[0x03]);
        assert_eq!(gapped.assembled(), vec![0x02]);

        // A retransmission is not a duplicate.
        let mut repeated = CryptoStream::new();
        repeated.push(0, &[0x01, 0x02]);
        repeated.push(0, &[0x01, 0x02]);
        assert_eq!(repeated.assembled(), vec![0x01, 0x02]);
    }

    /// Rule 2: an endpoint inside the window can send as many datagrams as it
    /// likes, and every distinct offset used to buy a map entry.
    #[test]
    fn the_crypto_stream_stops_at_its_cap() {
        let mut stream = CryptoStream::new();
        for chunk in 0..64 {
            stream.push(chunk * 1024, &[0x16; 1024]);
        }
        assert_eq!(stream.assembled().len(), CRYPTO_CAP);

        // A chunk that would cross the cap is dropped whole rather than cut.
        let mut one_short = CryptoStream::new();
        let cap = CRYPTO_CAP as u64;
        one_short.push(0, &[0x16; CRYPTO_CAP - 1]);
        one_short.push(cap - 1, &[0x16; 2]);
        assert_eq!(one_short.assembled().len(), CRYPTO_CAP - 1);
        one_short.push(cap - 1, &[0x16; 1]);
        assert_eq!(one_short.assembled().len(), CRYPTO_CAP);
    }

    #[test]
    fn a_transport_close_carries_its_error_code_and_reason() {
        // type 0x1c, error 0x08 (TRANSPORT_PARAMETER_ERROR), frame type 0x06,
        // reason "bad params" — the shape a server sends when the ClientHello
        // lacks the transport parameters extension.
        let mut payload = vec![0x1c, 0x08, 0x06, 0x0a];
        payload.extend_from_slice(b"bad params");
        let frames = parse_frames(&payload).expect("a close frame");
        assert_eq!(
            frames,
            vec![Frame::ConnectionClose {
                error_code: 8,
                frame_type: Some(6),
                reason: "bad params".to_string(),
            }]
        );
    }

    #[test]
    fn an_unknown_frame_type_is_an_error_rather_than_a_silent_skip() {
        // A frame this module does not know cannot be skipped — its length is
        // unknown — so it ends the parse instead of derailing the cursor.
        assert_eq!(parse_frames(&[0x30, 0x00]), Err(QuicError::Frame { frame_type: 0x30 }));
    }

    #[test]
    fn a_truncated_frame_ends_the_parse() {
        // A CRYPTO frame declaring 32 bytes with four present.
        assert!(matches!(parse_frames(&[0x06, 0x00, 0x20, 1, 2, 3, 4]), Err(QuicError::Short { .. })));
    }
}
