# vendor/rustls — patched rustls 0.23.45

This directory is the **upstream `rustls` 0.23.45 source** (copied verbatim from
crates.io) plus one small patch: a ClientHello profile hook, and a second hook
that lets a profile answer a server which acknowledged one of the application
extensions its hello carries. It is wired in the root `Cargo.toml` as

```toml
[patch.crates-io]
rustls = { path = "vendor/rustls" }
```

so that `tokio-rustls`, `hyper` and `rustls-rustcrypto` all resolve to this one
instance. `exclude = ["vendor/rustls"]` keeps it out of the workspace (its tests
and examples are upstream's, not ours).

## Why vendor a TLS crate

The detector needs to present more than one ClientHello shape: Russian
censorship classifies clients by fingerprint (Chrome/Safari-shaped fingerprints
are treated as suspicious, Firefox-shaped ones usually are not), so a tool that
only ever sends one shape cannot tell whether a block comes from the destination
or from its own fingerprint.

Upstream rustls deliberately gives no control over this: the cipher list comes
from the `CryptoProvider`, extension order is randomized per connection, and
browser-only extensions are never emitted (rustls maintainers rejected such hooks
in rustls#1421 and rustls#1932).

The ready-made crates were evaluated and each one fails a hard requirement of
this project (pure Rust, no C toolchain, `mipsel-unknown-linux-musl` targets, and
`DpiProbeStream` stage tracking must survive):

| Candidate | Why not |
| --- | --- |
| `wreq`, `rquest`, `reqwest-impersonate` | BoringSSL via `boring-sys` — C code, rules out the router targets; they are HTTP clients, so the probe stream (and with it stage classification) is lost |
| `impit` (Apify) | A full HTTP client on a patched rustls; patches four crates (`h2`, `rustls`, `tower-http`, `hyper-util`) and replaces the transport |
| `craftls` | Rustls **0.22** fork, last commit 2024-01-19 — cannot patch into our 0.23 stack |
| `apify/rustls` | Tracks **0.24.0-dev**; incompatible with `tokio-rustls 0.26` / `rustls-rustcrypto 0.0.2-alpha`; profiles live in `impit`, not in the crate |
| `ja-tools` + `XOR-op/rustls.delta` | Works, but pins rustls to a fork at **0.23.12** (~2 years behind) with no `X25519MLKEM768` support, i.e. no JA3 parity with a modern browser |

`webclaw-tls` is the cautionary precedent: its author archived the project after
patching five crates, noting that keeping them in sync was unsustainable and that
their patched rustls rejected valid server configurations.

## What the patch adds

`PATCH.diff` is the exact diff against pristine 0.23.45 — 1533 lines across 11
files, two of them new (`src/client/hello_profile.rs` and
`src/client/follow_up.rs`). It applies to a pristine copy with `patch -p1`
(`patch -p1 --binary` was run against the crates.io source before this file was
replaced, and the result compared against this tree with `diff -r
--strip-trailing-cr`: identical apart from these two files) and reproduces this
tree byte for byte, up to the line endings git checks out. Three of the changes
are not about the profile hook itself but about making a *browser-shaped* hello
survive real servers; they are described under "findings" below.

| File | Change |
| --- | --- |
| `src/client/hello_profile.rs` | **new**: public `ClientHelloProfile` (cipher list, groups, the key-share group list, signature schemes, ALPN, extension order with `GREASE_EXTENSION_MARKER` placeholders, verbatim extra extensions, suppressed extensions, GREASE, the per-connection shuffle, certificate compression, `padding_to`, `legacy_versions`, `quic`) and its `apply`. An empty certificate-compression list clears the typed value instead of setting an empty one: the profiles whose client advertises no algorithm (Safari 15.3, Tor 14.5) must send no extension 27 at all, not one with zero entries. `permute_extensions` shuffles the order the way BoringSSL's `ssl_setup_extension_permutation` does — one Fisher–Yates pass from the end, seeded by `hs.rs`, with the GREASE slots, the padding and the extensions TLS 1.3 requires last left in place |
| `src/client/follow_up.rs` | **new**: public `ClientFollowUp` (one method, `messages(acknowledged, transcript_hash) -> Vec<(u8, Vec<u8>)>`) and the place it is called from. A browser hello advertises ALPS or `channel_id`, the server acknowledges it in its EncryptedExtensions, and the client then owes the server a handshake message before its Finished; upstream rustls has neither a typed field for either extension nor a way to add a message to the second flight |
| `src/client/client_conn.rs` | `ClientConfig::hello_profile: Option<Arc<ClientHelloProfile>>`, `ClientConfig::client_follow_up: Option<Arc<dyn ClientFollowUp>>`, `ClientConnectionData::server_extensions` (the extension ids the server sent in its EncryptedExtensions) and `ClientConnection::server_encrypted_extensions()`, which reads that set back |
| `src/client/builder.rs` | initializes both hooks to `None`; `with_ech_mode` sets the ECH mode on a builder that has already chosen its versions — upstream's `with_ech` forces TLS 1.3 alone, and a profile that keeps its 1.2 fallback (Chrome 120) still carries the extension |
| `src/crypto/hpke.rs` | re-exports `HpkeKem`, `HpkeKdf`, `HpkeAead` and `HpkeSymmetricCipherSuite` — an `Hpke` implementation outside the crate cannot name the suite it implements otherwise — and gives `HpkePrivateKey` the `from_bytes` constructor its private field implies |
| `src/client/hs.rs` | applies the profile while building the ClientHello, with a per-connection GREASE seed and a 128-bit shuffle seed from the provider's CSPRNG; adds the GREASE key share and the GREASE `supported_versions` entry for a greasing profile; carries a *list* of key exchanges (`offered_key_shares`) instead of one, so a profile can send the shares a browser's `--tls-key-shares-limit` produces, and handles the HelloRetryRequest against that list; records the *encoded* extension set as `sent_extensions`; gates `compress_certificate` on the hello offering TLS 1.3; and leaves `legacy_session_id` empty for a profile with `quic` set, since the QUIC rule for that field (RFC 9001 §8.4) is decided from the *connection*'s protocol, which a TCP client cannot reach |
| `src/client/tls13.rs` | `initial_key_shares` builds one exchange per group `key_share_groups` names; `KeyExchangeChoice::new` looks the server's group up among every share the client sent (whole or hybrid component); `ExpectEncryptedExtensions` records the server's extension set, and `ExpectFinished` calls `client_follow_up` and appends what it returns to the client's second flight ahead of the Finished, hashed into the transcript |
| `src/client/ech.rs` | `EchGreaseConfig::grease_ext` sizes the GREASE payload the way BoringSSL does — one of 128, 160, 192 or 224 bytes, a rounded estimate of the inner hello, plus the AEAD tag (`setup_ech_grease()` in its `ssl/encrypted_client_hello.cc`) — instead of encoding the inner hello this client would really send, which is 441 bytes and a length no browser produces. The outer hello is no longer needed to size the body, so that argument is gone |
| `src/msgs/handshake.rs` | `SupportedProtocolVersions` gains `grease: Option<u16>` (written ahead of the real versions) and `legacy: Vec<u16>` (the fallbacks a browser advertises behind 1.2, written after them); `ClientExtensions` gains `profile_order`, `raw_extensions`, `suppress_extensions`, `padding_to`; the encoder honours them, computes RFC 7685 padding to the profile's target size, and still keeps ECH/PSK last; a certificate entry carrying SCTs (type 18) is accepted and ignored; `ServerExtensions::extension_types()` lists every extension id the server sent, typed fields and unknown ones together |
| `src/lib.rs` | exports the two modules, `ClientHelloProfile` and `ClientFollowUp` |
| `src/server/test.rs` | upstream's own test constructor uses `..Default::default()` now that the version carrier has a field it does not care about |

With `hello_profile` unset the ClientHello is byte-for-byte upstream rustls, so
every existing measurement stays comparable.

## Rebasing onto a new rustls

1. `cargo update -p rustls --precise <new version>`-style check of what changed
   is not enough: replace the source, then re-apply the patch.

```bash
# from a clean checkout, with the new upstream source available
rm -rf vendor/rustls
cp -r <path-to-upstream-rustls-<version>> vendor/rustls
rm -f vendor/rustls/.cargo-ok vendor/rustls/.cargo_vcs_info.json vendor/rustls/Cargo.lock
patch -p1 -d vendor/rustls < PATCH.diff      # expect hunks only in the files above
```

2. Conflicts are expected in exactly one region: the ClientHello assembly in
   `client/hs.rs` and the extension encoder in `msgs/handshake.rs`. The hook
   points are named in the table above; nothing else in the crate is touched.

   The 0.23.43 → 0.23.45 rebase (2026-09-25) is what that looked like in
   practice: it was forced by
   [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html) — a
   TLS 1.3 message sent at the
   wrong encryption level was accepted, `patched = [">= 0.23.45"]` — and `patch`
   applied every hunk with no rejects, at offsets equal to the upstream
   insertions (`client/hs.rs` +11, `server/test.rs` +125). The regenerated
   `PATCH.diff` differs from the previous one only in its hunk positions: not one
   line of the patch's own content changed. `cargo deny` did not catch the
   advisory by itself — a `[patch.crates-io]` path dependency has no `source` in
   the lock, so the advisory check skipped the crate it was pinning;
   `scripts/vendor-advisories.sh` asks the same database about the vendored
   crates by their published names and versions, and runs in the `policy` job.

   One thing that rebase made visible, and that is deliberately left alone:
   upstream's TLS-1.2 signature-scheme filter (in `emit_client_hello_for_retry`)
   runs *before* the hook installs the shape, so a shaped 1.2 hello carries the
   shape's `signature_algorithms` unfiltered. Measured on the shipped shapes: not
   one of them advertises a code outside 0.23.45's `SignatureScheme::algorithm()`
   set — `rsa_pss_pss_*`, `0x0809`–`0x080b`, is what that filter drops — so the
   wire is unchanged and `cargo test -p dpi-core fingerprint` still pins the same
   JA4. Re-applying the filter after `profile.apply` was tried and reverted: it
   would make a shaped 1.2 hello differ from the browser's, and this probe exists
   to report what a browser would get.

3. Re-verify — this is the part that matters (see below).

## How the patch is verified

* `cargo test --workspace` — the profile unit tests cover the extension order,
  the suppressed set, the Firefox 133 shape and the PQ group round trip.
* `cargo test -p dpi-core follow_up` pins the follow-up without a network: the
  ALPS message's type, length and measured six-byte body, the draft code point
  echoed as itself, the empty answer to a server that acknowledged nothing, and a
  `channel_id` assertion that verifies against the public key it carries.
* `cargo run --release --example tls_fingerprint dump <profile>` prints the JA3,
  the JA4 and the extension list straight from the wire bytes — no network
  needed, so the output can be diffed against a known-good capture.
* `dump chrome`, `dump safari` and `dump custom` must equal the JA3 **and JA4** of
  the pinned `curl-impersonate v2.2.2` versions they reproduce
  (`curl_chrome107`, `curl_safari155`, `curl_firefox133`), measured with a local
  ClientHello sniffer. `cargo test -p dpi-core fingerprint` pins both strings for
  both TLS config builders, so a regression is caught without network access.
  JA4 is the stricter of the two — it hashes the signature-algorithms list — and
  that is how both Safari shape errors were found while the JA3s matched:
  `rsa_pss_rsae_sha384` is on the wire *twice* (BoringSSL does not collapse the
  wrapper's duplicate list) and Safari 18 dropped `ecdsa_sha1`, so the 15.5 and
  18.x records need two different lists even though every other one is shared.
* The one JA4 difference from the bundle is Firefox's extension count and hash:
  `curl_firefox133` sends `encrypted_client_hello` and this profile cannot (see
  the ECH bullet above).
* `cargo run --release --example tls_fingerprint live custom` completes real TLS
  1.3 handshakes against `tls.peet.ws`, `cloudflare.com`, `www.google.com`,
  `www.wikipedia.org`, `www.microsoft.com` and `dns.google`; all six must
  succeed and `tls.peet.ws` must report the expected JA3/JA4 (currently
  `t13d1714h1_…`). A profile that is well formed but rejected by real servers
  shows up here and nowhere else.
* `… live12 custom <hosts>` does the same pinned to TLS 1.2 — the probes' second
  TLS column — and is the only way to see the `sent_extensions` defect below.
* Both forms take extra hosts, and two of them must stay in the sweep because
  only they exercise the certificate-entry path: `hub.docker.com` and
  `danbooru.donmai.us` (Fastly/CT-logging frontends). They fail loudly on a
  regression of the SCT tolerance or of `sent_extensions`.
* Regression: with the default profile the JSON of tests 1–6 must match the
  pre-patch binary byte for byte on the local stand (verified: identical in all
  three stand modes apart from the new additive `tls_fingerprint` key).

Binary size, measured (release, `opt-level = "z"`, LTO): pre-patch 3.17 MB;
with this patch and `ml-kem` but without the compression features 3.25 MB; with
`brotli` + `zlib` enabled — which the profile needs to decode the
`CompressedCertificate` Cloudflare sends once extension 27 is advertised —
4.32 MB. The budget is 3–6 MB. Dropping the two features is possible: it costs
1.07 MB less and one extension of fidelity, because the profile must then stop
advertising `compress_certificate`.

Findings worth keeping in mind when editing the profile — each one was a real
failing handshake or a real mismatched fingerprint, not a theoretical concern:

* **Padding is part of the fingerprint.** Chrome pads the ClientHello to 512
  bytes (RFC 7685), so extension 21 appears in its JA3; Firefox 133 sends no
  padding extension and the Firefox profile sets `padding_to: None`. For the
  padded profiles rustls computes the body length — `ClientConfig`-level
  post-processing cannot, because only the encoder knows how long the message is.
  The extension is omitted when the hello is already that large, as BoringSSL
  does. Reproducing the `curl-impersonate` chrome/safari JA3s exactly depends on
  this. The slot counts the extensions written *after* it, too: ECH is appended
  last (TLS 1.3 requires it) and Chrome shuffles the order, so the encoder writes
  the tail into a scratch buffer first and sizes the pad against the finished
  hello — without that it overshot by the whole ECH body, which is how the two
  Chrome shapes that fall under the floor came to send an unpadded hello.
* **GREASE extensions need positions, not just a flag.** The `grease` flag adds a
  GREASE cipher and group, but a GREASE *extension* has to sit at an exact spot in
  the order (Chrome opens and closes its list with one), and its value is drawn
  per connection. A profile writes `GREASE_EXTENSION_MARKER` in
  `extension_order`; `apply` replaces each occurrence with the next GREASE value
  and registers a verbatim body. Listing GREASE only in `raw_extensions` — as the
  first version did — silently drops it, because the encoder iterates the order.

* **The GREASE key share is load-bearing on a censored link, and the GREASE
  version is not.** A greasing profile also offers a key share for its GREASE
  group (one dummy byte, Chrome's placement at the head of the list) and puts a
  GREASE code point at the head of `supported_versions`, both of which
  `curl_chrome107`/`curl_safari155` do.
  Measured against `standby-rezka.tv` over TLS 1.3: with the share our
  chrome/safari hellos get a fatal alert every time (12/12 across three
  interleaved rounds), without it they complete, while the bundle's own
  `curl_chrome107` — which also carries a GREASE share — completes. Adding the
  GREASE version does not move that verdict (A/B on the same host, same minute:
  `[GREASE, 0x0304]` and `[0x0304]` both 0/4 with the alert; the live harness
  still reports the pinned JA3 and JA4 and all six hosts complete).
  So the peer reads something else that the bundle has and we still do not: the
  TLS 1.2 fallback in `supported_versions` (`0x0303`, which the bundle sends and
  this build cannot honestly advertise because its TLS 1.3 builder cannot speak
  1.2) and, coupled to it by `padding_to`, a padding extension two bytes longer
  than the bundle's. Until that is settled, a chrome/safari block on such a host
  is *our* hello being refused, not evidence that the pinned browser shape is.
  A run of the whole shipped list before/after the GREASE version found no
  regression (140 profile-runs; the only verdict changes were one host's
  transient TCP SYN timeouts and three flips between two failure modes on hosts
  that were blocked in both runs).
* **`sent_extensions` must be the set that reaches the wire.** rustls builds
  `ClientHelloDetails::sent_extensions` from its typed fields, but a profile can
  add extensions rustls has no typed field for (`ec_point_formats`,
  `signed_certificate_timestamp`, …). A server that echoes one of those then
  looked like it had sent an unsolicited extension and rustls failed the
  handshake with `PeerMisbehaved::UnsolicitedServerHelloExtension` — which the
  report shows as an unclassified TLS cell. Fixed by recording
  `used_extensions_in_encoding_order()` instead of `collect_used()`; the set is
  unchanged for an unpatched hello, so the default profile is unaffected.
* **A certificate entry may carry SCTs.** Advertising
  `signed_certificate_timestamp` (18) makes CT-logging servers attach SCTs to the
  TLS 1.3 certificate entry (RFC 6962 §4.5). rustls rejects any certificate-entry
  extension it does not implement with `UnknownCertificateExtension`, which kills
  the handshake — reproduced against `hub.docker.com` and `danbooru.donmai.us`.
  The patch accepts and ignores type 18; every other unknown type stays fatal, so
  a delegated credential (34) still fails loudly instead of being silently
  skipped. Servers that answer extension 34 with a credential would still break
  the handshake — rustls cannot consume one — but none of the twelve hosts in the
  verification sweep does.
* **A server that acknowledges ALPS or `channel_id` requires a follow-up before
  the Finished.** Every browser-shaped hello here advertises a *stateful*
  application extension — ALPS (`application_settings`, 17513/17613) or the
  `channel_id` placeholder (30032) — and a server that implements it
  acknowledges it in its EncryptedExtensions and then reads the client's second
  flight as one more handshake message: an EncryptedExtensions (type 8) carrying
  the acknowledged code point, or a `ChannelId` message (type 203) carrying a
  P-256 assertion. BoringSSL sends them ahead of its Finished, in the same record
  (measured: `www.google.com` against `curl_chrome146` — a 63-byte record where
  the Finished alone is 53); upstream rustls has neither a field for the server's
  EncryptedExtensions nor a way to add a message to the flight, so the first
  thing google read after our Finished was the HTTP/2 preface and it aborted with
  `unexpected_message` — for exactly the shapes that carry one of the two, while
  chrome87, firefox147, safari260, go127 and rustls were answered. The patch
  keeps the server's extension set, exposes it, and calls
  `ClientConfig::client_follow_up` once the EncryptedExtensions has been
  processed, adding what it returns to the second flight. The messages themselves
  are built in the client (`crates/dpi-core/src/net/follow_up.rs`), the only
  place that knows what the hello advertised. A server that acknowledges nothing
  — the local Go stand, whose `crypto/tls` knows neither extension — gets no
  follow-up, and the hook is additionally gated on the shape having advertised
  the extension the server named, so an unsolicited acknowledgement is not
  answered either.
* **A QUIC ClientHello must leave `legacy_session_id` empty.** RFC 8446
  Appendix D.4 puts 32 random bytes there for middlebox compatibility over TCP,
  and RFC 9001 §8.4 removes the mode for QUIC: a server treats a non-empty field
  as `PROTOCOL_VIOLATION`. rustls decides it from `cx.common.is_quic()`, which a
  TCP-shaped client cannot reach without a QUIC-capable cipher suite — the
  provider here declares `quic: None` for every suite
  (`docs/ADDING_A_PROFILE.md` §6) — so the hello a profile builds over TCP
  carries the field and a QUIC endpoint refuses it. Measured against
  `cloudflare.com`: `CRYPTO_ERROR 0x12f` (`illegal_parameter`, the alert the
  server puts in a `CONNECTION_CLOSE`) with the field present, a ServerHello in
  0.1 s with `quic: true`. The flag is the whole fix; the
  `quic_transport_parameters` extension a QUIC endpoint also requires is a raw
  extension the caller supplies.
* **A browser ClientHello does not fit one QUIC datagram.** The post-quantum key
  share alone is 1216 bytes (`X25519MLKEM768`), so a Chrome-shaped hello is
  ~1700 bytes: the client's first flight has to be split across Initial packets,
  each padded to 1200 bytes, with the `CRYPTO` frame's offset carrying the
  stream on (`crates/dpi-core/src/net/quic.rs::client_initials`). Dropping the
  PQ group or the shape to make one datagram fit would send a hello no client
  sends.
* **`compress_certificate` belongs to TLS 1.3 only.** rustls sets the extension
  only when the hello offers 1.3; the profile hook runs after that and must not
  put it back into a 1.2-only hello (RFC 8879), which is exactly the hello the
  probes' TLS 1.2 column sends.

* **ALPN offers `h2, http/1.1`, and the probes speak both.** The profiles
  reproduce browsers, which all offer h2 first, so a probe that could only speak
  HTTP/1.1 would fail on every h2-capable site and report its own protocol
  mismatch as censorship. `crates/dpi-core/src/probe/http.rs` starts a hyper
  HTTP/2 client when the handshake negotiated `h2` and an HTTP/1.1 client
  otherwise, and builds the request for the protocol in use (absolute URI and no
  connection-specific headers for h2). rustls validates the server's selection
  against `ClientConfig::alpn_protocols`, so a profile that offers ALPN must
  mirror it into the config (see `apply_fingerprint` in
  `crates/dpi-core/src/net/tls.rs`).

* **GREASE ECH needs a real HPKE provider, and now has one.** `curl_firefox133`
  — and the eight other wrappers naming `--ech true` — carries
  `encrypted_client_hello` (65037) as GREASE: the body is a freshly generated
  HPKE encapsulation plus a random payload, which is why no two connections share
  one. rustls builds that shape in `ClientHelloProfile`'s ECH path only when it
  can reach an `Hpke` implementation, and this build's provider
  (`rustls-rustcrypto`) has none — so `crates/dpi-core/src/net/hpke.rs`
  implements RFC 9180 base mode over the primitives already in the graph
  (`x25519-dalek`, `hkdf`, `aes-gcm`, `chacha20poly1305`), verified against the
  RFC's appendix A.1 vectors. A *hand-built* substitute does not work: three
  bodies tried here made Cloudflare, Google and `dns.google` answer `fatal
  alert: DecodeError`, while the rustls path is accepted by all four hosts of the
  live sweep (`tls_fingerprint liveany firefox cloudflare.com www.google.com
  dns.google tls.peet.ws`). The extension's bytes are never comparable between
  connections — `enc` is a fresh ephemeral key and the payload is random — but
  its length is: rustls sizes the payload by encoding the inner hello it would
  really send, which gave 441 bytes where Chrome sends 186 to 282, so the patch
  draws the length from the four estimates BoringSSL draws from
  (`setup_ech_grease()`) instead, leaving the body a length no censor can pin to
  this build.

* **Certificate compression is advertised only if it can be decoded.** The
  profile asks for `compress_certificate` (extension 27) because a browser sends
  it; that requires the `brotli` and `zlib` features of rustls (enabled in the
  workspace `Cargo.toml`). Without them Cloudflare answers with a
  `CompressedCertificate` we cannot read and the handshake dies — i.e. the probe
  would report its own bug as censorship. The features must stay on: they are
  what separates "our profile is broken" from a real verdict.
