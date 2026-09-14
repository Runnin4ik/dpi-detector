# vendor/hyper — patched hyper 1.11.1

This directory is the **upstream `hyper` 1.11.1 source** (copied verbatim from
crates.io) plus one patch: two settings of the HTTP/2 connection preface became
optional. It is wired in the root `Cargo.toml` as

```toml
[patch.crates-io]
hyper = { path = "vendor/hyper" }
```

so that `hyper-util` and the binary resolve to this instance, and
`exclude = ["vendor/hyper"]` keeps it out of the workspace (its tests and
examples are upstream's, not ours).

## Why patch hyper at all

hyper's HTTP/2 client builds the connection preface unconditionally: its
`proto::h2::client::new_builder` always calls `h2`'s `max_header_list_size` and
`enable_push(false)`, so every client hyper starts advertises both
`SETTINGS_MAX_HEADER_LIST_SIZE` and `SETTINGS_ENABLE_PUSH = 0`. The browsers do
not agree on either, and `tls.peet.ws` echoes the settings (and their order) in
its akamai fingerprint, so a profile that imitates Firefox or Safari was still
distinguishable on the first frame it sent:

| Preface | `SETTINGS` the bundle sends |
| --- | --- |
| `curl_chrome107` | `1:65536;2:0;3:1000;4:6291456;6:262144` |
| `curl_firefox133` | `1:65536;2:0;4:131072;5:16384` |
| `curl_safari155` | `4:4194304;3:100` |

No hyper API can express "leave this setting out": `max_header_list_size` takes a
plain `u32`, and `enable_push` has no setter at all.

## What the patch adds

`PATCH.diff` is the exact diff against pristine 1.11.1 — **93 lines across 2
files**. It applies to a pristine copy with `patch -p1` (`patch -p1 --dry-run`
was run against the crates.io source, and the applied result was compared with
this tree byte for byte).

* `proto::h2::client::Config` carries `max_header_list_size: Option<u32>`, a new
  `enable_push: Option<bool>` and a new `settings_order: Vec<u16>`, defaulting to
  the values hyper sent before (`Some(16 KB)`, `Some(false)`, empty), and
  `new_builder` only calls the matching `h2` setter when it has something to say.
* `client::conn::http2::Builder` follows: `max_header_list_size` now takes
  `impl Into<Option<u32>>` — hyper's own idiom for its other settings — and the
  new `enable_push(impl Into<Option<bool>>)` and
  `settings_order(impl IntoIterator<Item = u16>)` were added.

Nothing else changes: a caller that touches neither setter gets byte-identical
behaviour to upstream, which is what the DNS/DoH paths and the rustls baseline
profile rely on.

`h2` itself needed two patches for all this: the `Option`-based `Settings` makes
"omitted" expressible without one, but the *order* of the entries is an `h2`
encoder concern — `Settings::set_order` and `client::Builder::settings_order`
come from `vendor/h2/README-PATCH.md`. Leaving `MAX_HEADER_LIST_SIZE` out also
leaves the receive-side cap at h2's own default (`codec::framed_read`'s
`DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE`) rather than at 16 KB — both bounded.

## Notes for maintainers

* All three knobs are per-connection and optional; a caller that sets none of
  them gets upstream's wire byte for byte, which is what the DNS/DoH paths and
  the rustls baseline profile rely on.
* When regenerating `PATCH.diff`: copy the pristine crates.io source into `a/`,
  this directory into `b/` (dropping `PATCH.diff`, `README-PATCH.md`,
  `Cargo.lock`, `.cargo-ok`, `.cargo_vcs_info.json`), run `diff -ruN a b`, rewrite
  the header paths to `a/…` and `b/…`, and validate with `patch -p1 --dry-run` in
  a pristine copy. As with `vendor/h2`, no LF normalisation is applied — the tree
  keeps upstream's line endings so the diff reproduces it exactly.
