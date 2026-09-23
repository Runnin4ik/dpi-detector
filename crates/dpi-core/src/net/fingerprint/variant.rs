//! One edit to a profile's ClientHello, applied to a live connection or printed
//! for inspection.
//!
//! The question a variant answers is "does this one field decide the verdict": a
//! shape a network drops and its near neighbour that it answers differ in a
//! handful of places, and a delta moves exactly one of them. JA4 hides several of
//! those places — it sorts the extension set, ignores the order inside
//! `supported_groups` and `key_share`, and hashes neither a body nor a length —
//! so two shapes with one JA4 can still be told apart by whatever is reading
//! them, and only an edit that changes one field at a time says which field it
//! was.
//!
//! The edits land on the same [`ClientHelloProfile`] the builder filled — the
//! fields the rustls patch reads — so what goes on the wire is what the encoder
//! makes of the change rather than a second implementation of the encoder.

use std::sync::Arc;

use rustls::client::hello_profile::GREASE_EXTENSION_MARKER;
use rustls::client::ClientHelloProfile;
use rustls::ClientConfig;

/// The padding extension's code point: its position comes from the profile's
/// extension order, its length from `padding_to`.
const EXT_PADDING: u16 = 21;

/// One edit to the installed ClientHello.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelloVariant {
    /// Swap the first two `signature_algorithms`.
    SigalgSwap,
    /// Open the extension list with a GREASE slot, as Chrome does.
    GreaseExtra,
    /// Append an extension, sent as an empty body.
    AddExtension(u16),
    /// Remove an extension from the order, the raw list and the hello.
    DropExtension(u16),
    /// Append a `supported_groups` entry.
    AddGroup(u16),
    /// Pad the hello to at least this many bytes.
    Padding(u16),
    /// Drop the padding extension.
    NoPadding,
    /// Reverse the ALPN list (and the config's copy, which rustls validates
    /// the server's choice against).
    AlpnReverse,
    /// The exact extension order, with the per-connection shuffle turned off:
    /// one order rather than the set of orders a Chromium draws. A GREASE slot is
    /// named with [`GREASE_EXTENSION_MARKER`] (`0x0a0a`), since the value itself
    /// is drawn per connection.
    ExtOrder(Vec<u16>),
    /// `supported_groups` in wire order.
    Groups(Vec<u16>),
    /// The groups a key share is sent for, in wire order.
    KeyShares(Vec<u16>),
}

impl HelloVariant {
    /// Parses `name[:argument]`. The names are the ones the help lists, and every
    /// code point is decimal or `0x`-prefixed hex.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (name, argument) = text.split_once(':').unwrap_or((text, ""));
        let number = |part: &str| -> Result<u16, String> {
            let part = part.trim();
            let parsed = match part.strip_prefix("0x") {
                Some(hex) => u16::from_str_radix(hex, 16),
                None => part.parse::<u16>(),
            };
            parsed.map_err(|_| format!("{text}: `{part}` is not a code point"))
        };
        let one = || number(argument);
        let list = || -> Result<Vec<u16>, String> {
            if argument.is_empty() {
                return Err(format!("{text} wants a comma-separated list of code points"));
            }
            argument.split(',').map(number).collect()
        };
        match name {
            "sigalg-swap" => Ok(Self::SigalgSwap),
            "+grease" => Ok(Self::GreaseExtra),
            "+ext" => one().map(Self::AddExtension),
            "-ext" => one().map(Self::DropExtension),
            "+group" => one().map(Self::AddGroup),
            "padding" => one().map(Self::Padding),
            "no-padding" => Ok(Self::NoPadding),
            "alpn-reverse" => Ok(Self::AlpnReverse),
            "ext-order" => list().map(Self::ExtOrder),
            "groups" => list().map(Self::Groups),
            "key-shares" => list().map(Self::KeyShares),
            other => Err(format!("unknown variant `{other}`")),
        }
    }

    /// The variant's own spelling, the one [`Self::parse`] accepts.
    pub fn name(&self) -> String {
        fn list(ids: &[u16]) -> String {
            ids.iter().map(u16::to_string).collect::<Vec<_>>().join(",")
        }
        match self {
            Self::SigalgSwap => "sigalg-swap".into(),
            Self::GreaseExtra => "+grease".into(),
            Self::AddExtension(id) => format!("+ext:{id}"),
            Self::DropExtension(id) => format!("-ext:{id}"),
            Self::AddGroup(id) => format!("+group:{id}"),
            Self::Padding(n) => format!("padding:{n}"),
            Self::NoPadding => "no-padding".into(),
            Self::AlpnReverse => "alpn-reverse".into(),
            Self::ExtOrder(order) => format!("ext-order:{}", list(order)),
            Self::Groups(groups) => format!("groups:{}", list(groups)),
            Self::KeyShares(groups) => format!("key-shares:{}", list(groups)),
        }
    }

    /// Applies the edit. `alpn_protocols` is the config's own copy of the list
    /// rustls validates the server's choice against; it is kept in step because a
    /// hello that offers what the config does not makes every server answer
    /// `SelectedUnofferedApplicationProtocol`.
    pub fn apply(&self, hello: &mut ClientHelloProfile, alpn_protocols: &mut Vec<Vec<u8>>) {
        match self {
            Self::SigalgSwap => {
                if let Some(schemes) = hello.signature_schemes.as_mut() {
                    if schemes.len() > 1 {
                        schemes.swap(0, 1);
                    }
                }
            }
            Self::GreaseExtra => {
                if let Some(order) = hello.extension_order.as_mut() {
                    order.insert(0, GREASE_EXTENSION_MARKER);
                }
                hello.grease = true;
            }
            Self::AddExtension(id) => {
                if let Some(order) = hello.extension_order.as_mut() {
                    order.push(*id);
                }
                // A body the profile supplies verbatim is written before rustls
                // looks for a typed value, so an id rustls has no encoder for is
                // emitted as an empty extension rather than refused.
                hello.raw_extensions.push((*id, Vec::new()));
            }
            Self::DropExtension(id) => {
                if let Some(order) = hello.extension_order.as_mut() {
                    order.retain(|ext| ext != id);
                }
                hello.raw_extensions.retain(|(ext, _)| ext != id);
                // An extension missing from the order is still sent, only later.
                hello.suppress_extensions.push(*id);
            }
            Self::AddGroup(id) => {
                if let Some(groups) = hello.groups.as_mut() {
                    groups.push(*id);
                }
            }
            Self::Padding(floor) => {
                hello.padding_to = Some(*floor);
                if let Some(order) = hello.extension_order.as_mut() {
                    if !order.contains(&EXT_PADDING) {
                        order.push(EXT_PADDING);
                    }
                }
            }
            Self::NoPadding => hello.padding_to = None,
            Self::AlpnReverse => {
                if let Some(protocols) = hello.alpn.as_mut() {
                    protocols.reverse();
                    *alpn_protocols = protocols.clone();
                }
            }
            Self::ExtOrder(order) => {
                hello.extension_order = Some(order.clone());
                // A shuffle would overwrite the order on the way out, so pinning
                // one order means the shuffle goes off with it.
                hello.permute_extensions = false;
            }
            Self::Groups(groups) => hello.groups = Some(groups.clone()),
            Self::KeyShares(groups) => hello.key_share_groups = Some(groups.clone()),
        }
    }
}

/// Installs `variant` on the config's ClientHello, in place.
///
/// `false` when the config presents no profile — the rustls baseline is its own
/// hello, which has no fields to edit.
pub fn install_variant(config: &mut ClientConfig, variant: &HelloVariant) -> bool {
    let Some(shared) = config.hello_profile.as_ref() else {
        return false;
    };
    // The factory hands out an `Arc` (a verifying shape is cached and shared),
    // and this edit is private to the run: unwrap it into an owned profile.
    let mut edited = (**shared).clone();
    variant.apply(&mut edited, &mut config.alpn_protocols);
    config.hello_profile = Some(Arc::new(edited));
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::fingerprint::TlsFingerprint;
    use crate::net::ja3::{extensions, is_grease};
    use crate::net::ja4::client_hello_ja4;
    use crate::net::tls::{hello_record_with, TlsProfile};

    /// The hello `fingerprint` sends with `variant` applied.
    fn shaped(fingerprint: TlsFingerprint, variant: &str) -> Vec<u8> {
        let variant = HelloVariant::parse(variant).expect("a variant the help lists");
        hello_record_with(&TlsProfile::insecure(fingerprint), Some(&variant))
    }

    /// The bodies of one extension in a hello.
    fn body(record: &[u8], wanted: u16) -> Vec<u8> {
        extensions(&record[5..])
            .into_iter()
            .find(|(ext_type, _)| *ext_type == wanted)
            .map(|(_, body)| body.to_vec())
            .unwrap_or_default()
    }

    /// `supported_groups` as the wire order of its entries, GREASE filtered —
    /// a greasing profile opens the list with a GREASE group of its own.
    fn groups(record: &[u8]) -> Vec<u16> {
        let body = body(record, 10);
        body[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
            .filter(|group| !is_grease(*group))
            .collect()
    }

    /// The groups a key share is sent for, in wire order, GREASE filtered.
    fn shares(record: &[u8]) -> Vec<u16> {
        let body = body(record, 51);
        let mut out = Vec::new();
        let mut i = 2; // the vector's own length
        while i + 4 <= body.len() {
            out.push(u16::from_be_bytes([body[i], body[i + 1]]));
            i += 4 + u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        }
        out.into_iter().filter(|group| !is_grease(*group)).collect()
    }

    /// The extension type order, GREASE slots kept as their own value.
    fn order(record: &[u8]) -> Vec<u16> {
        extensions(&record[5..]).into_iter().map(|(ext_type, _)| ext_type).collect()
    }

    #[test]
    fn dropping_an_extension_takes_it_out_of_the_hello() {
        // `chrome107` sends ALPS (17513) and padding; dropping the ALPS entry
        // leaves the rest of the hello as it was and moves the JA4 with it, which
        // is what makes a one-field edit readable in a verdict.
        let plain = shaped(TlsFingerprint::Chrome107, "no-padding");
        let dropped = shaped(TlsFingerprint::Chrome107, "-ext:17513");
        assert!(order(&plain).contains(&17513));
        assert!(!order(&dropped).contains(&17513));
        assert_eq!(order(&plain).len(), order(&dropped).len() + 1);
        assert_ne!(client_hello_ja4(&plain), client_hello_ja4(&dropped));
    }

    #[test]
    fn a_group_list_is_written_in_wire_order() {
        let record = shaped(TlsFingerprint::Chrome146, "groups:29,4588,23");
        assert_eq!(groups(&record), vec![29, 4588, 23]);
    }

    #[test]
    fn a_key_share_list_is_what_the_hello_carries() {
        let drawn = shaped(TlsFingerprint::Chrome146, "groups:4588,29,23");
        let named = shaped(TlsFingerprint::Chrome146, "key-shares:29");
        // The hybrid group's share and its component's against the one the list
        // names: the body is the only place the difference shows.
        assert_eq!(shares(&named), vec![29]);
        assert!(shares(&drawn).len() > shares(&named).len());
    }

    #[test]
    fn an_extension_order_is_pinned_without_the_shuffle() {
        // `chrome146` shuffles its order per connection, so the pinned order is
        // the only one it can be asked to send twice.
        let first = shaped(TlsFingerprint::Chrome146, "ext-order:0,23,65281,10,11,35,16,5,13,18,51,45,43,27,17613,65037");
        let second = shaped(TlsFingerprint::Chrome146, "ext-order:0,23,65281,10,11,35,16,5,13,18,51,45,43,27,17613,65037");
        assert_eq!(order(&first), order(&second));
        // ECH and PSK are required last by the specification and are placed
        // outside the profile's order, so the tail is theirs in both.
        let tail = &order(&first)[order(&first).len() - 2..];
        assert!(tail.contains(&65037) || tail.contains(&41));
    }

    #[test]
    fn a_variant_names_itself_the_way_it_parses() {
        for text in [
            "sigalg-swap",
            "+grease",
            "+ext:65037",
            "-ext:17513",
            "+group:29",
            "padding:1200",
            "no-padding",
            "alpn-reverse",
            "ext-order:0,23,65281",
            "groups:29,4588,23",
            "key-shares:29",
        ] {
            let variant = HelloVariant::parse(text).expect("a variant the help lists");
            assert_eq!(variant.name(), text);
            assert_eq!(HelloVariant::parse(&variant.name()).expect("round trip"), variant);
        }
        assert!(HelloVariant::parse("nonsense").is_err());
        assert!(HelloVariant::parse("+ext:banana").is_err());
        assert!(HelloVariant::parse("groups:").is_err());
    }
}
