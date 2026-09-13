//! `X25519MLKEM768` key exchange, pure Rust (draft-ietf-tls-ecdhe-mlkem).
//!
//! rustls ships this group only in its `aws-lc-rs` provider, which links C code
//! and therefore cannot be used here (rule 1: no C dependencies). The protocol
//! side already exists in rustls — `NamedGroup::X25519MLKEM768` is in its enum —
//! and `CryptoProvider::kx_groups` is a public field, so the group can be
//! supplied without forking the provider.
//!
//! # Wire layout (PQ first, per the draft)
//!
//! * client key share: ML-KEM-768 encapsulation key (1184) ‖ X25519 public (32)
//! * server key share: ML-KEM-768 ciphertext (1088) ‖ X25519 public (32)
//! * shared secret: ML-KEM-768 shared secret (32) ‖ X25519 shared secret (32)
//!
//! `hybrid_component`/`complete_hybrid_component` are implemented so rustls
//! also offers the bare X25519 share and can complete it if the server picks
//! that group instead — the same two-share shape browsers send.
//!
//! # Scope
//!
//! Used by fingerprint profiles (see [`crate::net::tls::crypto_provider_with_pq`])
//! and, in future, by probes that must satisfy a server requiring PQ. The base
//! provider is deliberately left alone: adding this group there would change the
//! ClientHello of every connection, including the DNS truth probes.

use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{Ciphertext, DecapsulationKey, MlKem768};
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Length of an X25519 public key.
pub const X25519_LEN: usize = 32;
/// Length of an ML-KEM-768 encapsulation key (FIPS 203).
pub const MLKEM768_ENCAP_LEN: usize = 1184;
/// Length of an ML-KEM-768 ciphertext (FIPS 203).
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
/// Size of the seed ML-KEM-768 expands into a key pair.
const MLKEM768_SEED_LEN: usize = 64;

/// The hybrid `X25519MLKEM768` group (IANA code point 0x11ec).
#[derive(Debug)]
pub struct X25519MlKem768;

impl SupportedKxGroup for X25519MlKem768 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let x_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let x_public = PublicKey::from(&x_secret);

        let mut seed = [0u8; MLKEM768_SEED_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let mlkem = DecapsulationKey::<MlKem768>::from_seed(seed.into());

        // PQ first: ML-KEM encapsulation key then X25519.
        let encapsulation_key = mlkem.encapsulation_key().to_bytes();
        let mut pub_key = Vec::with_capacity(MLKEM768_ENCAP_LEN + X25519_LEN);
        pub_key.extend_from_slice(encapsulation_key.as_ref());
        pub_key.extend_from_slice(x_public.as_bytes());

        Ok(Box::new(ActiveX25519MlKem768 {
            x_secret,
            x_public,
            mlkem: Box::new(mlkem),
            pub_key,
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct ActiveX25519MlKem768 {
    x_secret: EphemeralSecret,
    x_public: PublicKey,
    mlkem: Box<DecapsulationKey<MlKem768>>,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for ActiveX25519MlKem768 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != MLKEM768_CIPHERTEXT_LEN + X25519_LEN {
            return Err(invalid_key_share());
        }
        let (ct, x_peer) = peer_pub_key.split_at(MLKEM768_CIPHERTEXT_LEN);

        let ct = Ciphertext::<MlKem768>::try_from(ct).map_err(|_| invalid_key_share())?;
        let mlkem_secret = self.mlkem.decapsulate(&ct);

        let x_peer: [u8; X25519_LEN] = x_peer.try_into().map_err(|_| invalid_key_share())?;
        let x_dh = self.x_secret.diffie_hellman(&PublicKey::from(x_peer));

        // PQ first, matching the key-share layout above.
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(mlkem_secret.as_ref());
        secret.extend_from_slice(x_dh.as_bytes());
        Ok(SharedSecret::from(secret))
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::X25519, self.x_public.as_bytes()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        let peer: [u8; X25519_LEN] = peer_pub_key.try_into().map_err(|_| invalid_key_share())?;
        Ok(self.x_secret.diffie_hellman(&PublicKey::from(peer)).as_ref().into())
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

fn invalid_key_share() -> Error {
    Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client share must be exactly the size servers expect, PQ part first.
    #[test]
    fn key_share_layout_is_draft_shaped() {
        let group = X25519MlKem768;
        let active = group.start().expect("start");
        assert_eq!(active.pub_key().len(), MLKEM768_ENCAP_LEN + X25519_LEN);
        assert_eq!(active.group(), NamedGroup::X25519MLKEM768);

        let (component, pub_key) = active.hybrid_component().expect("hybrid component");
        assert_eq!(component, NamedGroup::X25519);
        assert_eq!(pub_key.len(), X25519_LEN);
    }

    /// A full round trip against ourselves: our own key pair must decapsulate
    /// what the peer encapsulates, and the secrets must match byte for byte.
    #[test]
    fn completes_against_a_peer() {
        let group = X25519MlKem768;
        let active = group.start().expect("start");
        let client_share = active.pub_key().to_vec();

        // Peer side: encapsulate to our ML-KEM key and use its own X25519 key.
        let peer_x = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let peer_x_public = PublicKey::from(&peer_x);

        let (ek_bytes, _) = client_share.split_at(MLKEM768_ENCAP_LEN);
        let ek_bytes: [u8; MLKEM768_ENCAP_LEN] = ek_bytes.try_into().expect("ek len");
        let ek = ml_kem::EncapsulationKey::<MlKem768>::new(&ek_bytes.into()).expect("valid ek");
        let mut m = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut m);
        let (ct, peer_secret) = ek.encapsulate_deterministic(&m.into());

        let mut server_share = Vec::with_capacity(MLKEM768_CIPHERTEXT_LEN + X25519_LEN);
        server_share.extend_from_slice(ct.as_ref());
        server_share.extend_from_slice(peer_x_public.as_bytes());

        let client_secret = active.complete(&server_share).expect("complete");
        let peer_x_shared = peer_x.diffie_hellman(&PublicKey::from(
            <[u8; X25519_LEN]>::try_from(
                &client_share[MLKEM768_ENCAP_LEN..],
            )
            .expect("x25519 len"),
        ));

        let mut expected = Vec::new();
        expected.extend_from_slice(peer_secret.as_ref());
        expected.extend_from_slice(peer_x_shared.as_bytes());
        assert_eq!(client_secret.secret_bytes(), expected.as_slice());
    }

    /// A truncated share must be rejected, not silently accepted.
    #[test]
    fn rejects_short_share() {
        let active = X25519MlKem768.start().expect("start");
        assert!(active.complete(&[0u8; 10]).is_err());
    }
}
