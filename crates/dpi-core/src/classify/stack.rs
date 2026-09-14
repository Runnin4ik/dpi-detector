//! The TLS-stack table: an error message to the rustls variant it names.
//!
//! Where `alert.rs` reads what the *peer* said, this reads what our own stack
//! said about the peer's bytes. The two never overlap: an alert arrives as
//! `received fatal alert: …`, a stack failure as rustls's own wording, and both
//! tables match on the same lowercased, separator-stripped message.
//!
//! Matching happens on the words with their separators removed, so
//! `peer misbehaved: …`, `PeerMisbehaved` and `peermisbehaved` reach the same
//! value. The needles are the `Display` texts of `rustls::Error` as the vendored
//! rustls spells them (`vendor/rustls/src/error.rs`); a rustls upgrade that
//! rewords one is a change to this table, and the tests below pin the wording so
//! that upgrade fails loudly instead of silently unclassifying the case.
//!
//! A message the table does not know is left to the caller, which keeps its own
//! words (`Detail::Other`) — the long tail of OS and library text stays as it
//! came.
//!
//! Ordering matters at the call sites: the classifier's "our stack does not
//! implement this" early-out runs first, so a server using certificate
//! compression is not read as a peer that misbehaved.

use super::detail::{Detail, StackKind};

use StackKind::*;

/// `(needle without separators, kind)`, matched in order against a lowercased,
/// separator-stripped message.
///
/// The longer wording comes first where one needle is a prefix of another
/// (`receivedunexpectedhandshakemessage` before `receivedunexpectedmessage`).
const TABLE: &[(&str, StackKind)] = &[
    ("receivedunexpectedhandshakemessage", InappropriateHandshakeMessage),
    ("receivedunexpectedmessage", InappropriateMessage),
    ("receivedcorruptmessageoftype", InvalidMessage),
    ("cannotdecryptpeer'smessage", DecryptError),
    ("peermisbehaved", PeerMisbehaved),
    ("doesn'tsupportanyknownprotocol", NoApplicationProtocol),
];

/// The rustls failure a message names, or `None` when it names none.
///
/// `msg_lower` is the message already lowercased by the caller — the classifier
/// keeps one lowercased copy of every error it classifies.
pub fn from_message(msg_lower: &str) -> Option<StackKind> {
    let flat: String = msg_lower
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != '-')
        .collect();
    TABLE.iter().find(|(needle, _)| flat.contains(needle)).map(|(_, kind)| *kind)
}

/// The detail a message reports as.
pub fn detail_for(kind: StackKind) -> Detail {
    Detail::StackFailure(kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wording rustls puts on the wire, as the probes see it: the stack's
    /// own text, appended after hyper's `connection error` (see
    /// `probe::http::hyper_err_info`).
    #[test]
    fn the_rustls_spelling_names_the_failure() {
        for (msg, kind) in [
            ("connection error | cannot decrypt peer's message", DecryptError),
            ("cannot decrypt peer's message", DecryptError),
            ("received corrupt message of type ChangeCipherSpec", InvalidMessage),
            (
                "received unexpected message: got Alert when expecting Handshake",
                InappropriateMessage,
            ),
            (
                "received unexpected handshake message: got ServerHello when expecting ClientHello",
                InappropriateHandshakeMessage,
            ),
            ("peer misbehaved: UnsolicitedServerHelloExtension", PeerMisbehaved),
            ("peer doesn't support any known protocol", NoApplicationProtocol),
        ] {
            let lower = msg.to_ascii_lowercase();
            assert_eq!(from_message(&lower), Some(kind), "{msg}");
        }
    }

    /// An alert is not a stack failure: its wording belongs to `alert.rs`, and
    /// the two tables must not claim the same message.
    #[test]
    fn an_alert_wording_is_not_a_stack_failure() {
        for msg in [
            "connection error | received fatal alert: UnexpectedMessage",
            "received fatal alert: IllegalParameter",
            "peer sent no certificates",
            "invalid peer certificate: Expired",
        ] {
            assert_eq!(from_message(&msg.to_ascii_lowercase()), None, "{msg}");
        }
    }

    /// A stack failure is still not interception: the status stays unclassified
    /// while the detail says what rustls objected to.
    #[test]
    fn the_detail_is_the_kind() {
        assert_eq!(detail_for(DecryptError).code(), "tls_decrypt_error");
        assert_eq!(
            detail_for(InappropriateHandshakeMessage).code(),
            "tls_inappropriate_handshake_message"
        );
    }
}
