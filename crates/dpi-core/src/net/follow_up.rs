//! The client-side follow-up a shaped hello owes a server that acknowledged its
//! application extension.
//!
//! Two of the extensions this project's profiles advertise are *stateful*: the
//! client offers them in its ClientHello, the server acknowledges them in its
//! EncryptedExtensions, and the client then owes the server one handshake
//! message ahead of its Finished. ALPS (`application_settings`, 17513/17613) is
//! answered with a client-side EncryptedExtensions (type 8) that echoes the
//! acknowledged code point and carries an empty settings body; `channel_id`
//! (30032) with a `ChannelId` message (type 203) carrying a P-256 assertion. A
//! server that acknowledged one and then reads the Finished instead aborts with
//! `unexpected_message` — which is what `www.google.com` does to every shape
//! here that carries one, measured in `target/lab/decrypted-evidence.txt`.
//!
//! The messages are built here, in the client, because rustls has no typed field
//! for either extension and no opinion about their bodies; the patched rustls
//! keeps what the server acknowledged and sends what
//! [`ClientFollowUp::messages`] returns (see `vendor/rustls/README-PATCH.md`).
//!
//! Nothing is sent unless the shape actually advertised the extension the server
//! acknowledged: rustls tolerates an *unsolicited* unknown extension in an
//! EncryptedExtensions, and answering one would put a message on the wire the
//! server never asked for.

use rustls::client::ClientFollowUp;
use sha2::{Digest, Sha256};

use crate::net::fingerprint::{
    EXT_APPLICATION_SETTINGS, EXT_APPLICATION_SETTINGS_NEW, EXT_FAKE_CHANNEL_ID,
};

/// Handshake message type of a client-side EncryptedExtensions (RFC 8446 §4.3.1).
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
/// BoringSSL's `SSL3_MT_CHANNEL_ID`.
const HS_CHANNEL_ID: u8 = 203;

/// The P-256 private key the `channel_id` assertion is signed with.
///
/// BoringSSL verifies the assertion against the public key *inside the message*
/// (`tls1_verify_channel_id`), so the key is not a trust decision and any valid
/// P-256 key answers: this is a fixed throwaway (`SHA-256` of a label), not a
/// secret, and not drawn per connection — which keeps the whole message
/// reproducible.
const CHANNEL_ID_KEY: [u8; 32] = [
    0x9f, 0x71, 0x8a, 0x31, 0x47, 0x02, 0x29, 0x8e, 0x9a, 0xd1, 0x51, 0x11, 0xeb, 0x6d, 0x74, 0xbc,
    0x9b, 0xcf, 0xc5, 0x8a, 0x49, 0x5a, 0x92, 0xb9, 0x16, 0x86, 0x80, 0x8e, 0xe6, 0x37, 0xda, 0x33,
];

/// Builds the follow-up messages for the shapes this project ships.
#[derive(Debug)]
pub struct ProbeFollowUp {
    /// The shape advertised ALPS, so an acknowledged `application_settings` is
    /// one this client owes an answer for.
    application_settings: bool,
    /// The shape advertised `channel_id`.
    channel_id: bool,
}

impl ProbeFollowUp {
    /// A follow-up for a shape whose ClientHello advertised `advertised` (the
    /// raw extension type ids, in wire order), or `None` for a shape that
    /// advertises neither extension — it can never be acknowledged, so it has
    /// nothing to answer.
    pub fn for_shape(advertised: &[u16]) -> Option<Self> {
        let application_settings = advertised
            .iter()
            .any(|ext| matches!(*ext, EXT_APPLICATION_SETTINGS | EXT_APPLICATION_SETTINGS_NEW));
        let channel_id = advertised.contains(&EXT_FAKE_CHANNEL_ID);
        (application_settings || channel_id).then_some(Self {
            application_settings,
            channel_id,
        })
    }
}

impl ClientFollowUp for ProbeFollowUp {
    fn messages(&self, acknowledged: &[u16], transcript_hash: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        // ALPS first: BoringSSL sends the client EncryptedExtensions before the
        // (absent) client certificate, and the `channel_id` message after it.
        if self.application_settings {
            if let Some(codepoint) = acknowledged.iter().copied().find(|ext| {
                matches!(*ext, EXT_APPLICATION_SETTINGS | EXT_APPLICATION_SETTINGS_NEW)
            }) {
                out.push((
                    HS_ENCRYPTED_EXTENSIONS,
                    application_settings_message(codepoint),
                ));
            }
        }
        if self.channel_id && acknowledged.contains(&EXT_FAKE_CHANNEL_ID) {
            out.push((HS_CHANNEL_ID, channel_id_message(transcript_hash)));
        }
        out
    }
}

/// The body of the client's EncryptedExtensions for ALPS: a two-byte
/// extension-list length, the acknowledged code point, and a zero-length
/// settings body.
///
/// BoringSSL sends the settings it configured for the negotiated protocol —
/// empty for a client that configured none, which is what these profiles are.
/// The measured bytes for the 17613 code point are `00 04 44 cd 00 00`
/// (`target/lab/decrypted-evidence.txt`), and the code point echoed is the one
/// the *server* used: its EncryptedExtensions and the message it expects back
/// are written from one config flag, so they can only agree.
fn application_settings_message(codepoint: u16) -> Vec<u8> {
    let mut body = Vec::with_capacity(6);
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&codepoint.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body
}

/// The body of the `ChannelId` message: the extension header BoringSSL's
/// `tls1_write_channel_id` writes, then the P-256 assertion.
fn channel_id_message(transcript_hash: &[u8]) -> Vec<u8> {
    let assertion = channel_id_assertion(transcript_hash);
    let mut body = Vec::with_capacity(4 + assertion.len());
    body.extend_from_slice(&EXT_FAKE_CHANNEL_ID.to_be_bytes());
    body.extend_from_slice(&(assertion.len() as u16).to_be_bytes());
    body.extend_from_slice(&assertion);
    body
}

/// The 128-byte `channel_id` assertion: the public key coordinates and the
/// ECDSA signature, each padded to 32 bytes, in BoringSSL's order.
fn channel_id_assertion(transcript_hash: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let key = p256::ecdsa::SigningKey::from_slice(&CHANNEL_ID_KEY)
        .expect("a fixed, valid P-256 scalar");
    let signature: p256::ecdsa::Signature = key
        .sign_prehash(&channel_id_digest(transcript_hash))
        .expect("a P-256 key signs a 32-byte digest");
    let point = key
        .verifying_key()
        .as_affine()
        .to_encoded_point(false);

    let mut assertion = Vec::with_capacity(128);
    assertion.extend_from_slice(point.x().expect("an uncompressed point has x"));
    assertion.extend_from_slice(point.y().expect("an uncompressed point has y"));
    assertion.extend_from_slice(&signature.to_bytes());
    assertion
}

/// BoringSSL's `tls1_channel_id_hash` for TLS 1.3: SHA-256 over 64 spaces, the
/// context string with its NUL separator, and the handshake hash
/// (`tls13_get_cert_verify_signature_input` with `ssl_cert_verify_channel_id`).
fn channel_id_digest(transcript_hash: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x20u8; 64]);
    hasher.update(b"TLS 1.3, Channel ID\0");
    hasher.update(transcript_hash);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The message a server that acknowledged ALPS at 17613 must receive: one
    /// client EncryptedExtensions whose body is the six measured bytes. A
    /// regression in the code point, the body or the message type is caught
    /// here, without a network.
    #[test]
    fn alps_follow_up_pins_the_measured_bytes() {
        let follow_up = ProbeFollowUp::for_shape(&[EXT_APPLICATION_SETTINGS_NEW]).unwrap();
        let messages = follow_up.messages(&[EXT_APPLICATION_SETTINGS_NEW], &[0u8; 32]);
        assert_eq!(messages.len(), 1);
        let (typ, body) = &messages[0];
        assert_eq!(*typ, 8, "a client EncryptedExtensions");
        assert_eq!(
            body,
            &[0x00, 0x04, 0x44, 0xcd, 0x00, 0x00],
            "extensions length 4, application_settings, length 0"
        );
        assert_eq!(body.len(), 6, "the handshake message length field");
    }

    /// The draft code point is echoed as itself, not rewritten to the new one.
    #[test]
    fn alps_follow_up_echoes_the_acknowledged_codepoint() {
        let follow_up = ProbeFollowUp::for_shape(&[EXT_APPLICATION_SETTINGS]).unwrap();
        let messages = follow_up.messages(&[EXT_APPLICATION_SETTINGS], &[0u8; 32]);
        assert_eq!(messages[0].1, [0x00, 0x04, 0x44, 0x69, 0x00, 0x00]);
    }

    /// Nothing acknowledged, nothing sent — the local stand answers every shape
    /// this way (its `crypto/tls` knows neither extension), and the record must
    /// stay the Finished alone.
    #[test]
    fn no_acknowledgement_sends_nothing() {
        for advertised in [
            &[EXT_APPLICATION_SETTINGS][..],
            &[EXT_APPLICATION_SETTINGS_NEW][..],
            &[EXT_FAKE_CHANNEL_ID][..],
        ] {
            let follow_up = ProbeFollowUp::for_shape(advertised).unwrap();
            // The extensions a plain server acknowledges: ALPN, SNI, key_share.
            let messages = follow_up.messages(&[0x0010, 0x0000, 0x0033], &[0u8; 32]);
            assert!(messages.is_empty(), "advertised {advertised:?}");
        }
    }

    /// A shape that advertises neither extension has no follow-up at all, so an
    /// unsolicited acknowledgement cannot make it send one.
    #[test]
    fn a_shape_without_the_extensions_has_no_follow_up() {
        assert!(ProbeFollowUp::for_shape(&[0x0000, 0x0010, 0x0033]).is_none());
        assert!(ProbeFollowUp::for_shape(&[]).is_none());
    }

    /// The `channel_id` message is the extension header plus a 128-byte
    /// assertion: a P-256 point and a signature that verifies against it.
    #[test]
    fn channel_id_message_carries_a_verifiable_assertion() {
        use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
        use p256::elliptic_curve::sec1::FromEncodedPoint;

        let follow_up = ProbeFollowUp::for_shape(&[EXT_FAKE_CHANNEL_ID]).unwrap();
        let transcript_hash = [0x11u8; 32];
        let messages = follow_up.messages(&[EXT_FAKE_CHANNEL_ID], &transcript_hash);
        assert_eq!(messages.len(), 1);
        let (typ, body) = &messages[0];
        assert_eq!(*typ, 203, "SSL3_MT_CHANNEL_ID");
        assert_eq!(&body[..2], &EXT_FAKE_CHANNEL_ID.to_be_bytes());
        assert_eq!(&body[2..4], &128u16.to_be_bytes());
        assert_eq!(body.len(), 4 + 128);

        let assertion = &body[4..];
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&assertion[..64]);
        let point = p256::EncodedPoint::from_bytes(&sec1).unwrap();
        let key = VerifyingKey::from_affine(
            p256::AffinePoint::from_encoded_point(&point).unwrap(),
        )
        .unwrap();
        let signature = Signature::from_slice(&assertion[64..]).unwrap();
        key.verify_prehash(&channel_id_digest(&transcript_hash), &signature)
            .expect("the assertion verifies against the key it carries");
    }
}
