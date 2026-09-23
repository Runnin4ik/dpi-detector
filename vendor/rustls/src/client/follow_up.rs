//! Client-side follow-up messages (dpi-detector patch).
//!
//! A handful of extensions work the other way round from the rest: the client
//! advertises one in its ClientHello, the server *acknowledges* it in its
//! EncryptedExtensions, and the client then owes the server a handshake message
//! of its own before its Finished. Two do this — ALPS (`application_settings`,
//! 17513 and 17613) and `channel_id` (30032) — and a server that acknowledged
//! one refuses a client that does not answer: BoringSSL's server reads the
//! client's second flight as `EncryptedExtensions` (ALPS) or `ChannelId`
//! (`channel_id`) and aborts with `unexpected_message` when it finds the
//! Finished there instead (measured against `www.google.com`; see
//! `target/lab/decrypted-evidence.txt`).
//!
//! Upstream rustls neither keeps the server's EncryptedExtensions around nor
//! offers any way to add a message to the client's second flight, so a
//! browser-shaped hello that carries one of these extensions — as every profile
//! this project ships does — is refused by such a server.
//!
//! This module adds the hook. [`ClientFollowUp::messages`] is called once, after
//! the server's EncryptedExtensions has been processed and after any client
//! authentication has been emitted, and every `(type, body)` it returns is
//! encoded as one handshake message and appended to the client's second flight
//! ahead of the Finished — hashed into the transcript exactly like the messages
//! around it, because the server hashes what it reads the same way. That is
//! where BoringSSL puts both messages, so the TLS record that carries the
//! Finished carries them too.
//!
//! Nothing changes unless [`ClientConfig::client_follow_up`] is set, and the
//! hook is only consulted when the server acknowledged something; with it unset
//! the client's second flight is byte-for-byte upstream rustls.
//!
//! [`ClientConfig::client_follow_up`]: crate::client::ClientConfig::client_follow_up

use alloc::vec::Vec;
use core::fmt::Debug;

/// Builds the handshake messages a client owes a server that acknowledged one of
/// its application extensions.
///
/// Implemented by the client that knows what its ClientHello advertised (this
/// project's profiles) rather than by rustls, which has no typed field for ALPS
/// or `channel_id` and no opinion about their bodies.
pub trait ClientFollowUp: Send + Sync + Debug {
    /// `acknowledged` is every extension type id the server sent in its
    /// EncryptedExtensions (in no particular order), `transcript_hash` is the
    /// handshake hash at the point the messages are built — after any client
    /// authentication, before the Finished.
    ///
    /// Each returned `(type, body)` becomes one handshake message of that type
    /// with that body, sent in the order returned. An empty list sends nothing,
    /// which is the right answer for a server that acknowledged nothing this
    /// client's shape owes it.
    fn messages(&self, acknowledged: &[u16], transcript_hash: &[u8]) -> Vec<(u8, Vec<u8>)>;
}
