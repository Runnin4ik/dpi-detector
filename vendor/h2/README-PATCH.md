# vendor/h2 — patched h2 0.4.19

This directory is the **upstream `h2` 0.4.19 source** (copied verbatim from
crates.io) plus one patch: control over the shape of the client's HTTP/2
preface. It is wired in the root `Cargo.toml` as

```toml
[patch.crates-io]
h2 = { path = "vendor/h2" }
```

so that `hyper`'s h2 client resolves to this instance, and
`exclude = ["vendor/h2"]` keeps it out of the workspace (its tests and examples
are upstream's, not ours).

## Why vendor an HTTP/2 crate

An HTTP/2 client's request is part of its fingerprint, and h2 sends every request
in one fixed shape: pseudo-headers `:method, :scheme, :authority, :path` and a
`HEADERS` frame **without** the PRIORITY flag. No hash of the ClientHello sees it
— JA3 and JA4 stop at TLS — so a probe can match a browser's JA4 and still be
distinguishable on the very next frame. Measured against the
`curl-impersonate v2.2.2` bundles (decrypted with each bundle's
`SSLKEYLOGFILE`), the same request from the three browsers is:

| Shape | `HEADERS` flags | weight | exclusive | dependency | pseudo-headers |
| --- | --- | --- | --- | --- | --- |
| `curl_chrome107` | `0x25` | 256 | yes | 0 | `:method, :authority, :scheme, :path` |
| `curl_firefox133` | `0x25` | 42 | no | 0 | `:method, :path, :authority, :scheme` |
| `curl_safari155` | `0x25` | 255 | no | 0 | `:method, :scheme, :path, :authority` |
| h2 (unpatched) | `0x05` | — | — | — | `:method, :scheme, :authority, :path` |

The wrappers state two of the orders outright (`--http2-pseudo-headers-order
"mpas"` for Firefox, `"mspa"` for Safari); Chrome's is the bundle's default and
was read off the wire.

h2 offers no hook for either: the order is a hard-coded `take()` chain in
`frame::headers::Iter::next`, and 0.4 has no API that puts a priority on a
request's HEADERS frame (the decoder still parses the five priority bytes, the
encoder never writes them).

The ready-made alternative was evaluated and rejected: `impit` patches four
crates (`h2`, `rustls`, `tower-http`, `hyper-util`) and replaces the transport
with a full HTTP client, which loses the `DpiProbeStream` stage tracking every
probe in this project is built on (Rule 3).

## What the patch adds

`PATCH.diff` is the exact diff against pristine 0.4.19 — **368 lines across 5
files**. It applies to a pristine copy with `patch -p1` (`patch -p1 --dry-run`
was run against the crates.io source, and the applied result was compared with
this tree byte for byte).

* **`RequestShape`** (`frame::headers`, re-exported as `h2::client::RequestShape`)
  is what a request may ask for: `pseudo_order` and `priority: Option<(weight,
  exclusive)>`. It travels in the request's extensions and is read by
  `proto::streams::streams::send_request` *before* the extensions are cleared —
  the route h2 itself uses for `ext::Protocol`. Nothing else in the API changes,
  and a request that carries no shape goes out exactly as before, which is why
  every existing caller (including the DNS/DoH clients) is unaffected.
* **`PseudoOrder`** has four values: h2's own (the default), Chrome's, Firefox's
  and Safari's. `Iter::next` yields the four pseudo-headers in the chosen order.
* **The PRIORITY flag** is set through the `stream_dep` field the decoder already
  fills; `StreamDependency::encode` writes the five bytes the encoder previously
  left out, and `EncodingHeaderBlock::encode`'s existing callback carries them,
  so the frame length stays computed from the buffer (the same mechanism
  PUSH_PROMISE uses for its promised id). The weight is the client's own minus
  one: Chrome's `256` is the frame's `255`.
* `frame::EncodeBuf` became `pub(crate)` so the priority frame can write into it.

`hyper` needs **no** patch: its h2 client rebuilds the outgoing request with
`http::Request::from_parts(head, ())` and forwards the extensions untouched, so
the shape reaches h2 on any request hyper sends. This is the difference from the
rsTLS patch, which had to reach `ClientConfig`.

## Notes for maintainers

* Two behaviours the patch can produce are outside HTTP/2's requirements but
  inside every browser's: priority on a request HEADERS (deprecated in RFC 9113,
  still sent by Chrome, Firefox and Safari) and a pseudo-header order none of
  them agrees on. Both are per-request, so a run that fires several fingerprint
  profiles never mixes them.
* When regenerating `PATCH.diff`: copy the pristine crates.io source into `a/`,
  this directory into `b/` (dropping `PATCH.diff`, `README-PATCH.md`,
  `Cargo.lock`, `.cargo-ok`, `.cargo_vcs_info.json`), run `diff -ruN a b`, rewrite
  the header paths to `a/…` and `b/…`, and validate with `patch -p1 --dry-run` in
  a pristine copy. Unlike the rustls patch, no LF normalisation is applied — the
  tree keeps upstream's line endings so the diff reproduces it exactly.
