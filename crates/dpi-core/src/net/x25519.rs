//! The `X25519` group this crate supplies to rustls, with the check the provider's
//! own group leaves out.
//!
//! RFC 8446 §4.2.8.2 requires the handshake to abort when a peer's X25519 key has
//! low order: the Diffie-Hellman result is then the identity, i.e. a shared secret
//! the peer can predict, and the connection would be keyed on a value it chose.
//! `x25519-dalek` returns that as an all-zero secret and only *reports* it through
//! `was_contributory()`, and upstream RustCrypto reads the report nowhere — not in
//! `0.0.2-alpha`, not in `master` — so `rustls-rustcrypto`'s `X25519` completes a
//! handshake there. `ring` and `aws-lc-rs` reject it; this file makes the pure-Rust
//! provider do the same.
//!
//! Where the check lives is the point of the module. It used to be the one
//! *semantic* change inside `vendor/rustls-rustcrypto/src/kx.rs`, i.e. a hunk
//! upstream does not carry — the project's tracker has never mentioned
//! `was_contributory`, so it is a gap rather than a decision — and which therefore
//! had to be re-applied by hand on every rebase of that fork. It is now ours, in
//! the crate that pays for it, and the vendored copy keeps only the
//! `rustls-webpki` import swap and the two lint edits its workspace membership
//! costs (`vendor/rustls-rustcrypto/README-PATCH.md`).
//!
//! The group is offered under the same name, in the same position in
//! `CryptoProvider::kx_groups`, and produces the same shape — a 32-byte share from
//! an `EphemeralSecret`, exactly as the provider's `X25519` does — so no
//! ClientHello changes and the fingerprint shapes stay pinned
//! (`net::fingerprint`): the only difference is that this one refuses a peer key
//! whose result is the identity.

use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// X25519, refusing a peer key whose Diffie-Hellman result is the identity.
#[derive(Debug)]
pub struct ContributoryX25519;

impl SupportedKxGroup for ContributoryX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        Ok(Box::new(ActiveX25519 { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
}

struct ActiveX25519 {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl ActiveKeyExchange for ActiveX25519 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer_pub_key.try_into().map_err(|_| invalid_key_share())?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
        // The whole reason this group exists: a low-order peer key yields the
        // all-zero secret, and dalek reports that rather than failing.
        if !shared.was_contributory() {
            return Err(invalid_key_share());
        }
        Ok(shared.as_ref().into())
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

fn invalid_key_share() -> Error {
    Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seven encodings of a low-order point (libsodium's `has_small_order`
    /// table): the identity, the points of order 2, 4 and 8, and the three
    /// non-canonical encodings above the field prime that reduce to them. Each one
    /// makes the shared secret the identity, so each one has to abort — a check
    /// that only rejected the all-zero key would pass a peer key of order 2.
    const LOW_ORDER: [[u8; 32]; 7] = [
        // 0 (order 4)
        [0; 32],
        // 1 (order 1)
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        // order 8
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
            0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
            0xb8, 0x00,
        ],
        // order 8
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
            0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
            0x11, 0x57,
        ],
        // p - 1 (order 2)
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x7f,
        ],
        // p (order 4), non-canonical
        [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x7f,
        ],
        // p + 1 (order 1), non-canonical
        [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x7f,
        ],
    ];

    /// The share is the 32 bytes a server expects, under the name the provider
    /// used: the group replaces another one in the same slot, and the ClientHello
    /// must not move because of it.
    #[test]
    fn the_share_is_x25519_shaped() {
        let active = ContributoryX25519.start().expect("a key exchange starts");
        assert_eq!(active.pub_key().len(), 32);
        assert_eq!(active.group(), NamedGroup::X25519);
        assert_eq!(ContributoryX25519.name(), NamedGroup::X25519);
    }

    /// RFC 8446 §4.2.8.2 on this group: every low-order peer key aborts.
    #[test]
    fn a_low_order_peer_key_is_rejected() {
        for key in LOW_ORDER {
            let active = ContributoryX25519.start().expect("a key exchange starts");
            let err = match active.complete(&key) {
                Ok(secret) => panic!(
                    "a low-order peer key was accepted: {:02x?} -> {} bytes",
                    key,
                    secret.secret_bytes().len()
                ),
                Err(err) => err,
            };
            assert!(
                matches!(err, Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)),
                "unexpected error for {:02x?}: {err:?}",
                key
            );
        }
    }

    /// A peer key of the wrong length is a key share error, not a panic.
    #[test]
    fn a_short_peer_key_is_rejected() {
        let active = ContributoryX25519.start().expect("a key exchange starts");
        assert!(matches!(
            active.complete(&[0u8; 31]),
            Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
        ));
    }

    /// The control for the two tests above: a real peer completes, with a 32-byte
    /// secret that is not the identity. A group that rejected every key would pass
    /// them too.
    #[test]
    fn a_real_peer_completes() {
        let ours = ContributoryX25519.start().expect("a key exchange starts");
        let theirs = ContributoryX25519.start().expect("a key exchange starts");
        let peer_key = theirs.pub_key().to_vec();
        let secret = ours.complete(&peer_key).expect("a real peer key completes");
        assert_eq!(secret.secret_bytes().len(), 32);
        assert!(
            secret.secret_bytes().iter().any(|byte| *byte != 0),
            "the identity is not a completed key exchange"
        );
    }
}
