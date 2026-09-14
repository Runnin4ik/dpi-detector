//! The alert-description table: a TLS error message to the alert it names.
//!
//! Every stack words a received alert differently for the same IANA value —
//! rustls prints its Rust spelling (`received fatal alert: UnexpectedMessage`),
//! OpenSSL-derived stacks the spaced one (`sslv3 alert bad certificate`), some
//! wrap it as `alert(handshake_failure)`. Matching therefore happens on the
//! description with its separators removed, so all of those reach the same
//! value: the verdict follows the description, not the wording.
//!
//! A description the table does not know is left to the caller: the verdict then
//! stays the generic alert one, which is what an unnamed alert deserves.

use super::detail::{AlertKind, Detail};

use AlertKind::*;

/// `(description without separators, alert)`, matched in order against a
/// lowercased, separator-stripped message.
///
/// Longer names come first where one is a prefix of another
/// (`badcertificatestatusresponse` before `badcertificate`, `certificaterequired`
/// before `certificate` — which no entry uses on its own).
const TABLE: &[(&str, AlertKind)] = &[
    ("badcertificatestatusresponse", BadCertificateStatusResponse),
    ("badcertificatehashvalue", BadCertificateHashValue),
    ("encryptedclienthellorequired", EncryptedClientHelloRequired),
    ("unsupportedcertificate", UnsupportedCertificate),
    ("certificateunobtainable", CertificateUnobtainable),
    ("unsupportedextension", UnsupportedExtension),
    ("noapplicationprotocol", NoApplicationProtocol),
    ("certificateexpired", CertificateExpired),
    ("certificaterequired", CertificateRequired),
    ("certificateunknown", CertificateUnknown),
    ("certificaterevoked", CertificateRevoked),
    ("unrecognisedname", UnrecognisedName),
    ("unrecognizedname", UnrecognisedName),
    ("insufficientsecurity", InsufficientSecurity),
    ("inappropriatefallback", InappropriateFallback),
    ("unknownpskidentity", UnknownPskIdentity),
    ("decompressionfailure", DecompressionFailure),
    ("unexpectedmessage", UnexpectedMessage),
    ("handshakefailure", HandshakeFailure),
    ("decryptionfailed", DecryptionFailed),
    ("missingextension", MissingExtension),
    ("recordoverflow", RecordOverflow),
    ("exportrestriction", ExportRestriction),
    ("badcertificate", BadCertificate),
    ("badrecordmac", BadRecordMac),
    ("illegalparameter", IllegalParameter),
    ("protocolversion", ProtocolVersion),
    ("internalerror", InternalError),
    ("nocertificate", NoCertificate),
    ("norenegotiation", NoRenegotiation),
    ("accessdenied", AccessDenied),
    ("unknownca", UnknownCa),
    ("decodeerror", DecodeError),
    ("decrypterror", DecryptError),
    ("usercanceled", UserCanceled),
    ("closenotify", CloseNotify),
];

/// The description a message names, or `None` when it names none.
///
/// `msg_lower` is the message already lowercased by the caller — the classifier
/// keeps one lowercased copy of every error it classifies. Separators are
/// dropped here, so `bad certificate`, `bad_certificate` and `BadCertificate`
/// all name the same alert.
pub fn from_message(msg_lower: &str) -> Option<AlertKind> {
    let flat: String = msg_lower
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != '-')
        .collect();
    TABLE.iter().find(|(needle, _)| flat.contains(needle)).map(|(_, kind)| *kind)
}

/// What a named description reports as.
///
/// Three descriptions keep the code the vocabulary gave them when they were the
/// only ones it could tell apart; the rest name themselves through
/// [`Detail::Alert`].
pub fn detail_for(kind: AlertKind) -> Detail {
    match kind {
        HandshakeFailure => Detail::DpiAlertHandshakeFailure,
        UnrecognisedName => Detail::SniBlockUnrecognizedName,
        ProtocolVersion => Detail::ProtocolVersionAlert,
        named => Detail::Alert(named),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wording rustls puts on the wire for a received fatal alert, as the
    /// probes see it: `AlertReceived`'s `Debug` name, appended after hyper's own
    /// text (see `probe::http::hyper_err_info`).
    #[test]
    fn the_rustls_spelling_names_the_description() {
        for (msg, kind) in [
            ("connection error | received fatal alert: UnexpectedMessage", UnexpectedMessage),
            ("received fatal alert: IllegalParameter", IllegalParameter),
            ("received fatal alert: UnrecognisedName", UnrecognisedName),
            ("received fatal alert: UnknownCA", UnknownCa),
            ("received fatal alert: NoApplicationProtocol", NoApplicationProtocol),
            ("received fatal alert: EncryptedClientHelloRequired", EncryptedClientHelloRequired),
            ("received fatal alert: InternalError", InternalError),
        ] {
            assert_eq!(from_message(&msg.to_ascii_lowercase()), Some(kind), "{msg}");
        }
    }

    /// OpenSSL-derived stacks spell the same values snake_case or with spaces,
    /// with or without the `alert(...)` wrapper.
    #[test]
    fn the_other_spellings_name_the_same_values() {
        for (msg, kind) in [
            ("tlsv1 alert unknown ca", UnknownCa),
            ("sslv3 alert bad certificate", BadCertificate),
            ("alert(handshake_failure)", HandshakeFailure),
            ("tls alert record_overflow", RecordOverflow),
            ("alert(unrecognized_name)", UnrecognisedName),
            ("tlsv1 alert access denied", AccessDenied),
            ("tlsv1 alert no application protocol", NoApplicationProtocol),
            ("sslv3 alert unexpected message", UnexpectedMessage),
        ] {
            assert_eq!(from_message(&msg.to_ascii_lowercase()), Some(kind), "{msg}");
        }
    }

    /// `bad_certificate` is a prefix of `bad_certificate_status_response`: the
    /// table has to reach the longer one first.
    #[test]
    fn a_longer_name_wins_over_its_prefix() {
        assert_eq!(
            from_message("received fatal alert: bad_certificate_status_response"),
            Some(BadCertificateStatusResponse)
        );
        assert_eq!(from_message("received fatal alert: bad_certificate"), Some(BadCertificate));
    }

    /// An alert whose description the peer did not name (or named with a value
    /// outside the registry) reports as nothing, and the caller keeps the
    /// generic verdict.
    #[test]
    fn an_unnamed_alert_names_nothing() {
        assert_eq!(from_message("received fatal alert"), None);
        assert_eq!(from_message("alert received from peer"), None);
        assert_eq!(from_message("received fatal alert: Unknown(5)"), None);
    }

    /// The three descriptions the vocabulary already had a code for keep it;
    /// every other one carries its IANA name.
    #[test]
    fn the_detail_code_is_the_iana_name() {
        assert_eq!(detail_for(HandshakeFailure).code(), "dpi_alert_handshake_failure");
        assert_eq!(detail_for(UnrecognisedName).code(), "sni_block_unrecognized_name");
        assert_eq!(detail_for(ProtocolVersion).code(), "protocol_version_alert");
        assert_eq!(detail_for(IllegalParameter).code(), "alert_illegal_parameter");
        assert_eq!(detail_for(UnexpectedMessage).code(), "alert_unexpected_message");
        assert_eq!(detail_for(NoApplicationProtocol).code(), "alert_no_application_protocol");
    }
}
