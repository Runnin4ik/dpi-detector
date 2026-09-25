# vendor/hyper — patched hyper 1.11.1

This directory is the **upstream `hyper` 1.11.1 source** (copied verbatim from
crates.io) plus one patch: `ext::HeaderCaseMap` became public. It is wired in the
root `Cargo.toml` as

```toml
[patch.crates-io]
hyper = { path = "vendor/hyper" }
```

so that `hyper-util` and the binary resolve to this instance, and
`exclude = ["vendor/hyper"]` keeps it out of the workspace (its tests and
examples are upstream's, not ours).

## Why patch hyper at all

An HTTP/1.1 request's header *casing* is part of what a browser looks like, and
`http::HeaderName` is lowercase: a request built from a `HeaderMap` goes out
lowercased, and no browser writes `Sec-Fetch-Site`, `TE` or `Accept-Encoding`
that way. hyper's h1 encoder has written the spelling of a name it is given since
0.12 (`write_headers_original_case`, driven by the request's extensions), but only
a *parsed* message or the C API could build that map — a client that has to write
its own casing had no way to say so.

That is what the probes need: a request that claims to be Chrome 146 sends
`sec-ch-ua`, `Sec-Fetch-Site` and `TE` spelled the way Chrome 146 spells them.

## What the patch adds

`PATCH.diff` is the exact diff against pristine 1.11.1 — **45 lines in one file**.
It applies to a pristine copy with `patch -p1` (`patch -p1 --dry-run` was run
against the crates.io source, and the applied result was compared with this tree
byte for byte).

* `ext::HeaderCaseMap` is public (its field stays private, so the internals can
  still change), with a public `Default` and a public
  `append<N: IntoHeaderName>(name: N, orig: Bytes)` — the two calls a client needs
  to build one. A request without a map is unaffected: the encoder falls back to
  the lowercase name, which is upstream's behaviour byte for byte.

The read side (`get_all`, `get_all_internal`, `insert`) stays `pub(crate)`: this
build only writes requests, and the API upstream is still designing is the
reader's half.

## What left, and why

Two hunks used to be here, in `proto::h2::client` and `client::conn::http2`:
`SETTINGS_MAX_HEADER_LIST_SIZE` and `SETTINGS_ENABLE_PUSH` became optional, the
settings order became a caller's list, and the two settings Safari 18 sends
(`ENABLE_CONNECT_PROTOCOL`, `NO_RFC7540_PRIORITIES`) got client setters. They
existed because hyper drove the h2 client, and hyper's builder cannot leave a
setting out.

The probes drive the h2 client themselves now — `http2`, the fork that carries
the whole request shape as published API (root `Cargo.toml`) — and hyper is built
with `features = ["client", "http1"]`, so it never compiles its h2 client and
those hunks were dead code. The numbers they configured live in
`crates/dpi-core/src/net/fingerprint/h2.rs` (`H2Fingerprint`, `BASELINE_H2`) and
are applied by `net::http::h2_builder`, which is also where the DoH client asks
for the baseline preface.

## Upstream

The one remaining hunk is submitted as
[hyperium/hyper#4203](https://github.com/hyperium/hyper/pull/4203) — the minimal
exposure [`#2695`](https://github.com/hyperium/hyper/issues/2695) asked for
("just figuring out the minimal methods needed to expose the existing
`hyper::ext::HeaderCaseMap`"), which also answers
[`#3971`](https://github.com/hyperium/hyper/issues/3971). When a hyper release
carries it, this directory and its `[patch]` entry both go.

## Notes for maintainers

* A caller that touches nothing gets upstream's wire byte for byte, which is what
  the baseline profile and the DoH client rely on.
* When regenerating `PATCH.diff`: copy the pristine crates.io source into `a/`,
  this directory into `b/` (dropping `PATCH.diff`, `README-PATCH.md`,
  `Cargo.lock`, `.cargo-ok`, `.cargo_vcs_info.json`), run
  `diff -ruN --strip-trailing-cr -x .cargo-ok -x .cargo_vcs_info.json -x Cargo.lock -x Cargo.toml.orig a b`,
  rewrite the header paths to `a/…` and `b/…`, and validate with
  `patch -p1 --dry-run` in a pristine copy. As with `vendor/rustls`, no LF
  normalisation is applied — the tree keeps upstream's line endings so the diff
  reproduces it exactly.
