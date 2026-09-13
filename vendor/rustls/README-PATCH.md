# vendor/rustls — patched rustls 0.23.43

This directory is the **upstream `rustls` 0.23.43 source** (copied verbatim from
crates.io) plus one small patch: a ClientHello profile hook. It is wired in the
root `Cargo.toml` as

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

`PATCH.diff` is the exact diff against pristine 0.23.43 — 533 lines across 6
files, one of them new (`src/client/hello_profile.rs`, 266 lines). It applies to
a pristine copy with `patch -p1` and reproduces this tree byte for byte. Two of the changes are not
about the profile hook itself but about making a *browser-shaped* hello survive
real servers; they are described under "findings" below.

| File | Change |
| --- | --- |
| `src/client/hello_profile.rs` | **new**: public `ClientHelloProfile` (cipher list, groups, signature schemes, ALPN, extension order with `GREASE_EXTENSION_MARKER` placeholders, verbatim extra extensions, suppressed extensions, GREASE, certificate compression, `padding_to`) and its `apply` |
| `src/client/client_conn.rs` | `ClientConfig::hello_profile: Option<Arc<ClientHelloProfile>>` |
| `src/client/builder.rs` | initializes it to `None` |
| `src/client/hs.rs` | applies the profile while building the ClientHello, with a per-connection GREASE seed from the provider's CSPRNG; records the *encoded* extension set as `sent_extensions`; gates `compress_certificate` on the hello offering TLS 1.3 |
| `src/msgs/handshake.rs` | `ClientExtensions` gains `profile_order`, `raw_extensions`, `suppress_extensions`, `padding_to`; the encoder honours them, computes RFC 7685 padding to the profile's target size, and still keeps ECH/PSK last; a certificate entry carrying SCTs (type 18) is accepted and ignored |
| `src/lib.rs` | exports the module and `ClientHelloProfile` |

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
patch -p1 -d vendor/rustls < PATCH.diff      # expect hunks only in the 6 files above
```

2. Conflicts are expected in exactly one region: the ClientHello assembly in
   `client/hs.rs` and the extension encoder in `msgs/handshake.rs`. The hook
   points are named in the table above; nothing else in the crate is touched.
3. Re-verify — this is the part that matters (see below).

## How the patch is verified

* `cargo test --workspace` — the profile unit tests cover the extension order,
  the suppressed set, the Firefox 133 shape and the PQ group round trip.
* `cargo run --release --example tls_fingerprint dump <profile>` prints the JA3,
  the JA4 and the extension list straight from the wire bytes — no network
  needed, so the output can be diffed against a known-good capture.
* `dump chrome`, `dump safari` and `dump custom` must equal the JA3 **and JA4** of
  the pinned `curl-impersonate v2.2.2` versions they reproduce
  (`curl_chrome107`, `curl_safari155`, `curl_firefox133`), measured with a local
  ClientHello sniffer. `cargo test -p dpi-core fingerprint` pins both strings for
  both TLS config builders, so a regression is caught without network access.
  JA4 is the stricter of the two: it hashes the signature-algorithms list, which
  is how Safari's missing `ecdsa_sha1` was found while its JA3 matched.
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
  this.
* **GREASE extensions need positions, not just a flag.** The `grease` flag adds a
  GREASE cipher and group, but a GREASE *extension* has to sit at an exact spot in
  the order (Chrome opens and closes its list with one), and its value is drawn
  per connection. A profile writes `GREASE_EXTENSION_MARKER` in
  `extension_order`; `apply` replaces each occurrence with the next GREASE value
  and registers a verbatim body. Listing GREASE only in `raw_extensions` — as the
  first version did — silently drops it, because the encoder iterates the order.

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

* **GREASE ECH (extension 65037) is left out, and the patch cannot fix that.**
  uTLS — and therefore `curl_firefox133` — builds its GREASE ECH payload by
  encrypting a fake inner hello with a freshly generated HPKE key, so the bytes
  are a well-formed HPKE ciphertext that no server can decrypt. rustls can only
  produce that with an HPKE provider, and this build's provider
  (`rustls-rustcrypto`) has none. Every hand-built substitute tried (three
  bodies, `config_id` 0, 1, 255, 0xa7) made Cloudflare, Google and `dns.google`
  answer `fatal alert: DecodeError` — those servers parse the extension strictly
  and abort. Since Google and Cloudflare front much of what this tool probes,
  the Firefox profile omits the extension rather than shipping a hello that
  fails on most of the internet; the cost is one extension of fidelity (16 vs 17
  in a JA4 count, the JA3 string loses its trailing `-65037`).

* **Certificate compression is advertised only if it can be decoded.** The
  profile asks for `compress_certificate` (extension 27) because a browser sends
  it; that requires the `brotli` and `zlib` features of rustls (enabled in the
  workspace `Cargo.toml`). Without them Cloudflare answers with a
  `CompressedCertificate` we cannot read and the handshake dies — i.e. the probe
  would report its own bug as censorship. The features must stay on: they are
  what separates "our profile is broken" from a real verdict.
