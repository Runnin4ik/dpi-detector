//! HPKE (RFC 9180) in base mode, for the ECH a browser profile carries.
//!
//! rustls ships the ECH client — `EchConfig`, `EchGreaseConfig` and the inner
//! hello — but leaves the `Hpke` trait to the crypto provider, and the provider
//! this build uses, `rustls-rustcrypto`, has no HPKE: rustls itself implements it
//! only against `aws-lc-rs`, which Rule 1 puts out of reach. This module is that
//! implementation.
//!
//! The suites are the ones an ECH config in the wild is published with, all
//! sharing one KEM and one KDF: DHKEM(X25519, HKDF-SHA256) with HKDF-SHA256 and
//! AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305. None of this is new crypto —
//! `x25519-dalek` is in the tree for the group, `hkdf` and `hmac` for the KDF and
//! `aes-gcm`/`chacha20poly1305` for the AEAD, because the provider uses all of
//! them for TLS itself — so what is written here is the RFC's plumbing, pinned
//! against the RFC's own vectors: appendix A.1 (X25519, HKDF-SHA256, AES-128-GCM)
//! and appendix A.2, which is the same KEM and KDF under ChaCha20-Poly1305 and so
//! pins the 32-byte key the AES-256-GCM suite also takes.
//!
//! A client only ever seals: the sealer path is what ECH needs, and the opener
//! exists because the trait requires it and because the vectors exercise both.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeAead, HpkeKdf, HpkeKem, HpkeOpener, HpkePrivateKey, HpkePublicKey,
    HpkeSealer, HpkeSuite, HpkeSymmetricCipherSuite,
};
use rustls::Error;

/// The KEM of every suite here: DHKEM(X25519, HKDF-SHA256).
const KEM: HpkeKem = HpkeKem::DHKEM_X25519_HKDF_SHA256;
/// The KDF of every suite here: HKDF-SHA256.
const KDF: HpkeKdf = HpkeKdf::HKDF_SHA256;
/// The length of an X25519 public key, and of a shared secret.
const N_SECRET: usize = 32;
/// The length of an AEAD nonce for all three of these AEADs.
const N_NONCE: usize = 12;
/// The AEAD tag length for all three of these AEADs.
#[cfg(test)]
const N_TAG: usize = 16;

/// The suites this build can offer, in the order an ECH config is scanned.
///
/// `EchConfig::new` is handed these and picks the first the server's config
/// names. The first is also what the bundle's own GREASE extension carries
/// (`0001 0001` — HKDF-SHA256 with AES-128-GCM), as does every Cloudflare-issued
/// ECH config today.
pub static SUITES: &[&dyn Hpke] = &[&AES_128_GCM, &AES_256_GCM, &CHACHA20_POLY1305];

/// DHKEM(X25519, HKDF-SHA256) with HKDF-SHA256 and AES-128-GCM.
pub(crate) static AES_128_GCM: X25519HkdfSha256 = X25519HkdfSha256::new(AeadSuite::Aes128Gcm);
/// DHKEM(X25519, HKDF-SHA256) with HKDF-SHA256 and AES-256-GCM.
pub static AES_256_GCM: X25519HkdfSha256 = X25519HkdfSha256::new(AeadSuite::Aes256Gcm);
/// DHKEM(X25519, HKDF-SHA256) with HKDF-SHA256 and ChaCha20-Poly1305.
pub static CHACHA20_POLY1305: X25519HkdfSha256 = X25519HkdfSha256::new(AeadSuite::ChaCha20Poly1305);

/// One HPKE suite: one shared KEM and KDF, with an AEAD that differs.
#[derive(Debug)]
pub struct X25519HkdfSha256 {
    aead: AeadSuite,
}

impl X25519HkdfSha256 {
    const fn new(aead: AeadSuite) -> Self {
        Self { aead }
    }

    /// Seal from a *given* sender key, so the RFC's vectors can be replayed:
    /// production draws a fresh one every time.
    fn sealer_with(
        &self,
        sender_secret: &[u8; 32],
        recipient_public: &[u8],
        info: &[u8],
    ) -> Result<(EncapsulatedSecret, Sealer), Error> {
        let (enc, shared_secret) = encap(sender_secret, recipient_public)?;
        Ok((enc, Sealer(Context::new(self.aead, &shared_secret, info))))
    }

    /// The mirror of [`Self::sealer_with`].
    fn opener_with(
        &self,
        recipient_secret: &[u8],
        enc: &[u8],
        info: &[u8],
    ) -> Result<Opener, Error> {
        let shared_secret = decap(recipient_secret, enc)?;
        Ok(Opener(Context::new(self.aead, &shared_secret, info)))
    }
}

impl Hpke for X25519HkdfSha256 {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let (enc, mut sealer) = self.sealer_with(&random_secret(), &pub_key.0, info)?;
        Ok((enc, sealer.seal(aad, plaintext)?))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let (enc, sealer) = self.sealer_with(&random_secret(), &pub_key.0, info)?;
        Ok((enc, Box::new(sealer)))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        self.opener_with(secret_key.secret_bytes(), &enc.0, info)?
            .open(aad, ciphertext)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        Ok(Box::new(
            self.opener_with(secret_key.secret_bytes(), &enc.0, info)?,
        ))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let (secret, public) = keygen();
        Ok((
            HpkePublicKey(public.to_vec()),
            HpkePrivateKey::from_bytes(secret.to_vec()),
        ))
    }

    fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: KEM,
            sym: HpkeSymmetricCipherSuite {
                kdf_id: KDF,
                aead_id: self.aead.id(),
            },
        }
    }
}

/// A sealer holding an open context: `SetupBaseS` followed by `ContextS.Seal`.
#[derive(Debug)]
struct Sealer(Context);

impl HpkeSealer for Sealer {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.seal(aad, plaintext)
    }
}

/// The receiver's half of the same context.
#[derive(Debug)]
struct Opener(Context);

impl HpkeOpener for Opener {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.open(aad, ciphertext)
    }
}

/// The AEAD of a suite, as the crates that implement it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AeadSuite {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadSuite {
    fn id(self) -> HpkeAead {
        match self {
            Self::Aes128Gcm => HpkeAead::AES_128_GCM,
            Self::Aes256Gcm => HpkeAead::AES_256_GCM,
            Self::ChaCha20Poly1305 => HpkeAead::CHACHA20_POLY_1305,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    fn seal(
        self,
        key: &[u8],
        nonce: [u8; N_NONCE],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match self {
            Self::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| bad_parameters())?
                .encrypt(&nonce.into(), payload),
            Self::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| bad_parameters())?
                .encrypt(&nonce.into(), payload),
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| bad_parameters())?
                .encrypt(&nonce.into(), payload),
        }
        .map_err(|_| Error::General("HPKE sealing failed".into()))
    }

    fn open(
        self,
        key: &[u8],
        nonce: [u8; N_NONCE],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        match self {
            Self::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| bad_parameters())?
                .decrypt(&nonce.into(), payload),
            Self::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| bad_parameters())?
                .decrypt(&nonce.into(), payload),
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| bad_parameters())?
                .decrypt(&nonce.into(), payload),
        }
        .map_err(|_| Error::General("HPKE opening failed".into()))
    }
}

/// A key-schedule context: the key, the base nonce and a sequence number.
#[derive(Debug)]
struct Context {
    aead: AeadSuite,
    key: Vec<u8>,
    base_nonce: [u8; N_NONCE],
    sequence: u64,
}

impl Context {
    /// RFC 9180 §5.1 in base mode: no PSK, so `psk` and `psk_id` are empty.
    fn new(aead: AeadSuite, shared_secret: &[u8; N_SECRET], info: &[u8]) -> Self {
        let suite = suite_id(aead);
        let psk_id_hash = labeled_extract(&[], b"psk_id_hash", &[], &suite);
        let info_hash = labeled_extract(&[], b"info_hash", info, &suite);

        let mut key_schedule_context = Vec::with_capacity(1 + 2 * N_SECRET);
        key_schedule_context.push(0x00); // mode_base
        key_schedule_context.extend_from_slice(&psk_id_hash);
        key_schedule_context.extend_from_slice(&info_hash);

        let secret = labeled_extract(shared_secret, b"secret", &[], &suite);
        let key = labeled_expand(&secret, b"key", &key_schedule_context, &suite, aead.key_len());
        let base_nonce = labeled_expand(
            &secret,
            b"base_nonce",
            &key_schedule_context,
            &suite,
            N_NONCE,
        );

        let mut nonce = [0u8; N_NONCE];
        nonce.copy_from_slice(&base_nonce);
        Self {
            aead,
            key,
            base_nonce: nonce,
            sequence: 0,
        }
    }

    /// The nonce for `sequence`: the base nonce with the sequence number XORed
    /// into its last bytes (§5.2).
    fn nonce_at(&self, sequence: u64) -> [u8; N_NONCE] {
        let mut nonce = self.base_nonce;
        let bytes = sequence.to_be_bytes();
        for (byte, sequence_byte) in nonce[N_NONCE - bytes.len()..].iter_mut().zip(bytes) {
            *byte ^= sequence_byte;
        }
        nonce
    }

    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.nonce_at(self.sequence);
        self.sequence += 1;
        self.aead.seal(&self.key, nonce, aad, plaintext)
    }

    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.nonce_at(self.sequence);
        self.sequence += 1;
        self.aead.open(&self.key, nonce, aad, ciphertext)
    }
}

/// `suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`.
fn suite_id(aead: AeadSuite) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    out.extend_from_slice(b"HPKE");
    out.extend_from_slice(&u16::from(KEM).to_be_bytes());
    out.extend_from_slice(&u16::from(KDF).to_be_bytes());
    out.extend_from_slice(&u16::from(aead.id()).to_be_bytes());
    out
}

/// `suite_id_kem = "KEM" || I2OSP(kem_id, 2)`.
fn kem_suite_id() -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.extend_from_slice(b"KEM");
    out.extend_from_slice(&u16::from(KEM).to_be_bytes());
    out
}

/// `labeled_extract(salt, label, ikm) = Extract(salt, "HPKE-v1" || suite_id ||
/// label || ikm)`.
fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8], suite_id: &[u8]) -> [u8; N_SECRET] {
    let mut info = Vec::with_capacity(7 + suite_id.len() + label.len() + ikm.len());
    info.extend_from_slice(b"HPKE-v1");
    info.extend_from_slice(suite_id);
    info.extend_from_slice(label);
    info.extend_from_slice(ikm);

    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &info);
    prk.into()
}

/// `labeled_expand(prk, label, info, L) = Expand(prk, I2OSP(L, 2) || "HPKE-v1" ||
/// suite_id || label || info, L)`.
fn labeled_expand(
    prk: &[u8; N_SECRET],
    label: &[u8],
    info: &[u8],
    suite_id: &[u8],
    len: usize,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(2 + 7 + suite_id.len() + label.len() + info.len());
    context.extend_from_slice(&(len as u16).to_be_bytes());
    context.extend_from_slice(b"HPKE-v1");
    context.extend_from_slice(suite_id);
    context.extend_from_slice(label);
    context.extend_from_slice(info);

    let mut out = vec![0u8; len];
    Hkdf::<Sha256>::from_prk(prk)
        .expect("32 bytes is a valid SHA-256 PRK")
        .expand(&context, &mut out)
        .expect("every length here is inside HKDF's output limit");
    out
}

/// `DHKEM(X25519, HKDF-SHA256).Encap`: a fresh sender key against the
/// recipient's public key.
fn encap(
    sender_secret: &[u8; 32],
    recipient_public: &[u8],
) -> Result<(EncapsulatedSecret, [u8; N_SECRET]), Error> {
    let recipient_public: [u8; 32] = recipient_public.try_into().map_err(|_| bad_parameters())?;
    let enc = x25519(*sender_secret, X25519_BASEPOINT_BYTES);
    let dh = x25519(*sender_secret, recipient_public);

    let mut kem_context = Vec::with_capacity(2 * N_SECRET);
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(&recipient_public);

    Ok((
        EncapsulatedSecret(enc.to_vec()),
        shared_secret(&dh, &kem_context),
    ))
}

/// `DHKEM(X25519, HKDF-SHA256).Decap`, the receiver's half.
fn decap(recipient_secret: &[u8], enc: &[u8]) -> Result<[u8; N_SECRET], Error> {
    let recipient_secret: [u8; 32] = recipient_secret.try_into().map_err(|_| bad_parameters())?;
    let enc: [u8; 32] = enc.try_into().map_err(|_| bad_parameters())?;
    let dh = x25519(recipient_secret, enc);

    let mut kem_context = Vec::with_capacity(2 * N_SECRET);
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(&x25519(recipient_secret, X25519_BASEPOINT_BYTES));

    Ok(shared_secret(&dh, &kem_context))
}

/// `ExtractAndExpand`: the DH output with the KEM context bound into it.
fn shared_secret(dh: &[u8; N_SECRET], kem_context: &[u8]) -> [u8; N_SECRET] {
    let kem_suite = kem_suite_id();
    let eae_prk = labeled_extract(&[], b"eae_prk", dh, &kem_suite);
    let secret = labeled_expand(
        &eae_prk,
        b"shared_secret",
        kem_context,
        &kem_suite,
        N_SECRET,
    );

    let mut out = [0u8; N_SECRET];
    out.copy_from_slice(&secret);
    out
}

/// A fresh X25519 secret, and its public key.
fn keygen() -> ([u8; 32], [u8; 32]) {
    let secret = random_secret();
    (secret, x25519(secret, X25519_BASEPOINT_BYTES))
}

fn random_secret() -> [u8; 32] {
    use rand::RngCore;

    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    secret
}

fn bad_parameters() -> Error {
    Error::General("HPKE key material of the wrong length".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9180 appendix A.1: `DHKEM(X25519, HKDF-SHA256)` with `HKDF-SHA256` and
    /// `AES-128-GCM`, base mode. The `info` is the RFC's own.
    const INFO: &[u8] = &[
        0x4f, 0x64, 0x65, 0x20, 0x6f, 0x6e, 0x20, 0x61, 0x20, 0x47, 0x72, 0x65, 0x63, 0x69, 0x61,
        0x6e, 0x20, 0x55, 0x72, 0x6e,
    ];
    const SK_EM: [u8; 32] = [
        0x52, 0xc4, 0xa7, 0x58, 0xa8, 0x02, 0xcd, 0x8b, 0x93, 0x6e, 0xce, 0xea, 0x31, 0x44, 0x32,
        0x79, 0x8d, 0x5b, 0xaf, 0x2d, 0x7e, 0x92, 0x35, 0xdc, 0x08, 0x4a, 0xb1, 0xb9, 0xcf, 0xa2,
        0xf7, 0x36,
    ];
    const PK_EM: [u8; 32] = [
        0x37, 0xfd, 0xa3, 0x56, 0x7b, 0xdb, 0xd6, 0x28, 0xe8, 0x86, 0x68, 0xc3, 0xc8, 0xd7, 0xe9,
        0x7d, 0x1d, 0x12, 0x53, 0xb6, 0xd4, 0xea, 0x6d, 0x44, 0xc1, 0x50, 0xf7, 0x41, 0xf1, 0xbf,
        0x44, 0x31,
    ];
    const SK_RM: [u8; 32] = [
        0x46, 0x12, 0xc5, 0x50, 0x26, 0x3f, 0xc8, 0xad, 0x58, 0x37, 0x5d, 0xf3, 0xf5, 0x57, 0xaa,
        0xc5, 0x31, 0xd2, 0x68, 0x50, 0x90, 0x3e, 0x55, 0xa9, 0xf2, 0x3f, 0x21, 0xd8, 0x53, 0x4e,
        0x8a, 0xc8,
    ];
    const PK_RM: [u8; 32] = [
        0x39, 0x48, 0xcf, 0xe0, 0xad, 0x1d, 0xdb, 0x69, 0x5d, 0x78, 0x0e, 0x59, 0x07, 0x71, 0x95,
        0xda, 0x6c, 0x56, 0x50, 0x6b, 0x02, 0x73, 0x29, 0x79, 0x4a, 0xb0, 0x2b, 0xca, 0x80, 0x81,
        0x5c, 0x4d,
    ];
    const SHARED_SECRET: [u8; 32] = [
        0xfe, 0x0e, 0x18, 0xc9, 0xf0, 0x24, 0xce, 0x43, 0x79, 0x9a, 0xe3, 0x93, 0xc7, 0xe8, 0xfe,
        0x8f, 0xce, 0x9d, 0x21, 0x88, 0x75, 0xe8, 0x22, 0x7b, 0x01, 0x87, 0xc0, 0x4e, 0x7d, 0x2e,
        0xa1, 0xfc,
    ];
    const KEY: [u8; 16] = [
        0x45, 0x31, 0x68, 0x5d, 0x41, 0xd6, 0x5f, 0x03, 0xdc, 0x48, 0xf6, 0xb8, 0x30, 0x2c, 0x05,
        0xb0,
    ];
    const BASE_NONCE: [u8; 12] = [
        0x56, 0xd8, 0x90, 0xe5, 0xac, 0xca, 0xaf, 0x01, 0x1c, 0xff, 0x4b, 0x7d,
    ];
    const PT: &[u8] = &[
        0x42, 0x65, 0x61, 0x75, 0x74, 0x79, 0x20, 0x69, 0x73, 0x20, 0x74, 0x72, 0x75, 0x74, 0x68,
        0x2c, 0x20, 0x74, 0x72, 0x75, 0x74, 0x68, 0x20, 0x62, 0x65, 0x61, 0x75, 0x74, 0x79,
    ];
    /// Appendix A.1.1's encryptions: sequence 0 under the base nonce, then
    /// sequence 1, whose nonce is one lower in its last byte.
    const VECTOR: [(&[u8], &[u8], [u8; N_NONCE]); 2] = [
        (
            b"Count-0",
            &[
                0xf9, 0x38, 0x55, 0x8b, 0x5d, 0x72, 0xf1, 0xa2, 0x38, 0x10, 0xb4, 0xbe, 0x2a, 0xb4,
                0xf8, 0x43, 0x31, 0xac, 0xc0, 0x2f, 0xc9, 0x7b, 0xab, 0xc5, 0x3a, 0x52, 0xae, 0x82,
                0x18, 0xa3, 0x55, 0xa9, 0x6d, 0x87, 0x70, 0xac, 0x83, 0xd0, 0x7b, 0xea, 0x87, 0xe1,
                0x3c, 0x51, 0x2a,
            ],
            BASE_NONCE,
        ),
        (
            b"Count-1",
            &[
                0xaf, 0x2d, 0x7e, 0x9a, 0xc9, 0xae, 0x7e, 0x27, 0x0f, 0x46, 0xba, 0x1f, 0x97, 0x5b,
                0xe5, 0x3c, 0x09, 0xf8, 0xd8, 0x75, 0xbd, 0xc8, 0x53, 0x54, 0x58, 0xc2, 0x49, 0x4e,
                0x8a, 0x6e, 0xab, 0x25, 0x1c, 0x03, 0xd0, 0xc2, 0x2a, 0x56, 0xb8, 0xca, 0x42, 0xc2,
                0x06, 0x3b, 0x84,
            ],
            [
                0x56, 0xd8, 0x90, 0xe5, 0xac, 0xca, 0xaf, 0x01, 0x1c, 0xff, 0x4b, 0x7c,
            ],
        ),
    ];

    /// The KEM and the key schedule, against the RFC's own numbers: the
    /// encapsulated secret, the shared secret, and the key and base nonce
    /// derived from it.
    #[test]
    fn the_rfc_vector_survives_encap_and_the_key_schedule() {
        let (enc, shared) = encap(&SK_EM, &PK_RM).expect("encap");
        assert_eq!(enc.0, PK_EM, "enc is the sender's public key");
        assert_eq!(shared, SHARED_SECRET);

        let context = Context::new(AeadSuite::Aes128Gcm, &shared, INFO);
        assert_eq!(context.key, KEY);
        assert_eq!(context.base_nonce, BASE_NONCE);

        // The receiving end lands on the same secret from the other side.
        assert_eq!(decap(&SK_RM, &enc.0).expect("decap"), SHARED_SECRET);
    }

    /// Seal and open both directions, with the RFC's ciphertexts: the nonce is
    /// the base nonce with the sequence number XORed in, and the ciphertext is
    /// the plaintext plus the AEAD's tag.
    #[test]
    fn the_rfc_vector_survives_sealing_and_opening() {
        let suite = &AES_128_GCM;
        let (_, mut sealer) = suite.sealer_with(&SK_EM, &PK_RM, INFO).expect("sealer");
        let mut opener = suite.opener_with(&SK_RM, &PK_EM, INFO).expect("opener");

        for (sequence, (aad, ciphertext, nonce)) in VECTOR.into_iter().enumerate() {
            assert_eq!(sealer.0.nonce_at(sequence as u64), nonce, "the nonce for {sequence}");
            let sealed = sealer.seal(aad, PT).expect("seal");
            assert_eq!(sealed.len(), PT.len() + N_TAG);
            assert_eq!(sealed, ciphertext, "the ciphertext for {sequence}");
            assert_eq!(opener.open(aad, &sealed).expect("open"), PT);
        }
    }

    /// RFC 9180 appendix A.2: `DHKEM(X25519, HKDF-SHA256)` with `HKDF-SHA256` and
    /// `ChaCha20Poly1305`, base mode. The `info` and the plaintext are the ones
    /// above — the RFC reuses both across its X25519 vectors — and the KEM key
    /// pairs are A.2's own.
    ///
    /// This is the arm A.1 never reaches: a 32-byte key. `AES-256-GCM`, the third
    /// suite this build carries, has no vector of its own in the RFC: AES-256-GCM
    /// appears only in A.6, under `DHKEM(P-521, HKDF-SHA512)` with `HKDF-SHA512`,
    /// a different KEM and a different KDF, so replaying it would pin nothing this
    /// module computes. What it shares with A.2 is the schedule: both take
    /// `Nk = 32` and `Nn = 12`, so the key and base nonce below are derived by the
    /// same arm the AES-256 suite takes, and the AEAD itself is the upstream
    /// crate's own, covered by its vectors rather than by these.
    const A2_SK_EM: [u8; 32] = [
        0xf4, 0xec, 0x9b, 0x33, 0xb7, 0x92, 0xc3, 0x72, 0xc1, 0xd2, 0xc2, 0x06, 0x35, 0x07, 0xb6,
        0x84, 0xef, 0x92, 0x5b, 0x8c, 0x75, 0xa4, 0x2d, 0xbc, 0xbf, 0x57, 0xd6, 0x3c, 0xcd, 0x38,
        0x16, 0x00,
    ];
    const A2_PK_EM: [u8; 32] = [
        0x1a, 0xfa, 0x08, 0xd3, 0xde, 0xc0, 0x47, 0xa6, 0x43, 0x88, 0x51, 0x63, 0xf1, 0x18, 0x04,
        0x76, 0xfa, 0x7d, 0xdb, 0x54, 0xc6, 0xa8, 0x02, 0x9e, 0xa3, 0x3f, 0x95, 0x79, 0x6b, 0xf2,
        0xac, 0x4a,
    ];
    const A2_SK_RM: [u8; 32] = [
        0x80, 0x57, 0x99, 0x1e, 0xef, 0x8f, 0x1f, 0x1a, 0xf1, 0x8f, 0x4a, 0x94, 0x91, 0xd1, 0x6a,
        0x1c, 0xe3, 0x33, 0xf6, 0x95, 0xd4, 0xdb, 0x8e, 0x38, 0xda, 0x75, 0x97, 0x5c, 0x44, 0x78,
        0xe0, 0xfb,
    ];
    const A2_PK_RM: [u8; 32] = [
        0x43, 0x10, 0xee, 0x97, 0xd8, 0x8c, 0xc1, 0xf0, 0x88, 0xa5, 0x57, 0x6c, 0x77, 0xab, 0x0c,
        0xf5, 0xc3, 0xac, 0x79, 0x7f, 0x3d, 0x95, 0x13, 0x9c, 0x6c, 0x84, 0xb5, 0x42, 0x9c, 0x59,
        0x66, 0x2a,
    ];
    const A2_SHARED_SECRET: [u8; 32] = [
        0x0b, 0xbe, 0x78, 0x49, 0x04, 0x12, 0xb4, 0xbb, 0xea, 0x48, 0x12, 0x66, 0x6f, 0x79, 0x16,
        0x93, 0x2b, 0x82, 0x8b, 0xba, 0x79, 0x94, 0x24, 0x24, 0xab, 0xb6, 0x52, 0x44, 0x93, 0x0d,
        0x69, 0xa7,
    ];
    const A2_KEY: [u8; 32] = [
        0xad, 0x27, 0x44, 0xde, 0x8e, 0x17, 0xf4, 0xeb, 0xba, 0x57, 0x5b, 0x3f, 0x5f, 0x5a, 0x8f,
        0xa1, 0xf6, 0x9c, 0x2a, 0x07, 0xf6, 0xe7, 0x50, 0x0b, 0xc6, 0x0c, 0xa6, 0xe3, 0xe3, 0xec,
        0x1c, 0x91,
    ];
    const A2_BASE_NONCE: [u8; N_NONCE] = [
        0x5c, 0x4d, 0x98, 0x15, 0x06, 0x61, 0xb8, 0x48, 0x85, 0x3b, 0x54, 0x7f,
    ];
    /// Appendix A.2.1's first two encryptions: sequence 0 under the base nonce,
    /// then sequence 1, whose nonce is one lower in its last byte.
    const A2_VECTOR: [(&[u8], &[u8], [u8; N_NONCE]); 2] = [
        (
            b"Count-0",
            &[
                0x1c, 0x52, 0x50, 0xd8, 0x03, 0x4e, 0xc2, 0xb7, 0x84, 0xba, 0x2c, 0xfd, 0x69, 0xdb,
                0xdb, 0x8a, 0xf4, 0x06, 0xcf, 0xe3, 0xff, 0x93, 0x8e, 0x13, 0x1f, 0x0d, 0xef, 0x8c,
                0x8b, 0x60, 0xb4, 0xdb, 0x21, 0x99, 0x3c, 0x62, 0xce, 0x81, 0x88, 0x3d, 0x2d, 0xd1,
                0xb5, 0x1a, 0x28,
            ],
            A2_BASE_NONCE,
        ),
        (
            b"Count-1",
            &[
                0x6b, 0x53, 0xc0, 0x51, 0xe4, 0x19, 0x9c, 0x51, 0x8d, 0xe7, 0x95, 0x94, 0xe1, 0xc4,
                0xab, 0x18, 0xb9, 0x6f, 0x08, 0x15, 0x49, 0xd4, 0x5c, 0xe0, 0x15, 0xbe, 0x00, 0x20,
                0x90, 0xbb, 0x11, 0x9e, 0x85, 0x28, 0x53, 0x37, 0xcc, 0x95, 0xba, 0x5f, 0x59, 0x99,
                0x2d, 0xc9, 0x8c,
            ],
            [
                0x5c, 0x4d, 0x98, 0x15, 0x06, 0x61, 0xb8, 0x48, 0x85, 0x3b, 0x54, 0x7e,
            ],
        ),
    ];

    /// The KEM and the key schedule, against A.2's own numbers.
    #[test]
    fn the_a2_vector_survives_encap_and_the_key_schedule() {
        let (enc, shared) = encap(&A2_SK_EM, &A2_PK_RM).expect("encap");
        assert_eq!(enc.0, A2_PK_EM, "enc is the sender's public key");
        assert_eq!(shared, A2_SHARED_SECRET);

        let context = Context::new(AeadSuite::ChaCha20Poly1305, &shared, INFO);
        assert_eq!(context.key, A2_KEY);
        assert_eq!(context.base_nonce, A2_BASE_NONCE);

        // The receiving end lands on the same secret from the other side.
        assert_eq!(decap(&A2_SK_RM, &enc.0).expect("decap"), A2_SHARED_SECRET);
    }

    /// Seal and open both directions against A.2's ciphertexts. A.1 pins the
    /// 16-byte key of AES-128-GCM; this is the 32-byte arm the AES-256 suite
    /// shares with ChaCha20-Poly1305.
    #[test]
    fn the_a2_vector_survives_sealing_and_opening() {
        let suite = &CHACHA20_POLY1305;
        let (_, mut sealer) = suite.sealer_with(&A2_SK_EM, &A2_PK_RM, INFO).expect("sealer");
        let mut opener = suite.opener_with(&A2_SK_RM, &A2_PK_EM, INFO).expect("opener");

        for (sequence, (aad, ciphertext, nonce)) in A2_VECTOR.into_iter().enumerate() {
            assert_eq!(sealer.0.nonce_at(sequence as u64), nonce, "the nonce for {sequence}");
            let sealed = sealer.seal(aad, PT).expect("seal");
            assert_eq!(sealed.len(), PT.len() + N_TAG);
            assert_eq!(sealed, ciphertext, "the ciphertext for {sequence}");
            assert_eq!(opener.open(aad, &sealed).expect("open"), PT);
        }
    }

    /// A second handshake is a second `enc` and a second ciphertext, from the
    /// same recipient key: which is why a greased ECH body can never be compared
    /// byte for byte between two connections — not even two of a real browser's.
    #[test]
    fn every_sealer_draws_its_own_keys() {
        let suite = &AES_128_GCM;
        let recipient = HpkePublicKey(PK_RM.to_vec());
        let (first, _) = suite.setup_sealer(INFO, &recipient).expect("sealer");
        let (second, _) = suite.setup_sealer(INFO, &recipient).expect("sealer");
        assert_ne!(first.0, second.0);
        assert_eq!(first.0.len(), N_SECRET);
    }

    /// The trait's single-shot `seal` and `open` round trip on a generated pair —
    /// the path `EchMode::Enable` takes — and a wrong key opens nothing.
    #[test]
    fn sealer_and_opener_agree_on_a_generated_key_pair() {
        let suite = &CHACHA20_POLY1305;
        let (public, secret) = suite.generate_key_pair().expect("key pair");
        let (enc, sealed) = suite.seal(INFO, b"aad", PT, &public).expect("seal");
        assert_eq!(
            suite
                .open(&enc, INFO, b"aad", &sealed, &secret)
                .expect("open"),
            PT
        );

        let (_, other) = suite.generate_key_pair().expect("key pair");
        assert!(suite.open(&enc, INFO, b"aad", &sealed, &other).is_err());
    }

    /// Every suite names the ids an ECH config is matched against, and the ids
    /// this build implements are exactly the three it carries.
    #[test]
    fn the_suites_name_their_own_ids() {
        let expected = [
            (HpkeAead::AES_128_GCM, 16),
            (HpkeAead::AES_256_GCM, 32),
            (HpkeAead::CHACHA20_POLY_1305, 32),
        ];
        assert_eq!(SUITES.len(), expected.len());
        for (suite, (aead, key_len)) in SUITES.iter().zip(expected) {
            let named = suite.suite();
            assert_eq!(named.kem, KEM);
            assert_eq!(named.sym.kdf_id, KDF);
            assert_eq!(named.sym.aead_id, aead);
            let carried = match aead {
                HpkeAead::AES_128_GCM => AeadSuite::Aes128Gcm,
                HpkeAead::AES_256_GCM => AeadSuite::Aes256Gcm,
                _ => AeadSuite::ChaCha20Poly1305,
            };
            assert_eq!(carried.key_len(), key_len);
        }
    }
}
