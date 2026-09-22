# tools/fingerprint — checking a profile against the client it copies

`crates/dpi-core/examples/tls_fingerprint.rs` dumps what *we* send. This tool is
the other half: it drives the `curl-impersonate` bundle each profile is
transcribed from and diffs the two clients, so a profile can be re-checked
whenever its data changes.

```
python tools/fingerprint/fingerprint.py all                 # every stage, every profile
python tools/fingerprint/fingerprint.py all safari180        # one profile
python tools/fingerprint/fingerprint.py hello-diff --summary
python tools/fingerprint/fingerprint.py echo-diff chrome131
python tools/fingerprint/fingerprint.py headers-diff --summary
python tools/fingerprint/fingerprint.py flags chrome146     # what the wrapper itself names
```

Outputs land in `target/fingerprint/` (dumps, captured bytes, echo reports, the
fork's captures) and are never committed: re-running is cheap, and a stale
capture is worse than none.

The example also measures a *changed* shape rather than one of the profiles,
which is how a blocked shape is asked what a matcher actually reads:

```
cargo run --release --example tls_fingerprint dump-alpn chrome107 h1
cargo run --release --example tls_fingerprint variant chrome107 sigalg-swap
cargo run --release --example tls_fingerprint dump-hex chrome107 > capture.hex
cargo run --release --example tls_fingerprint hello capture.hex
```

`dump-alpn` pins the ALPN offer (which moves JA4's ALPN field and nothing
else), `variant` applies one delta to the profile's own hello (`sigalg-swap`,
`+grease`, `+ext:<id>`, `-ext:<id>`, `+group:<id>`, `padding:<n>`,
`no-padding`, `alpn-reverse`), and `dump-hex`/`hello` move one shape out of the
process and back so a capture from anywhere — a live browser, a uTLS build —
can be measured without a profile of ours and without a network. The deltas
whose JA4 does not move (`+grease`, `padding:<n>`, `sigalg-swap` for JA3) are
the controls: a verdict that changes on one of them says the matcher reads more
than the hash.

## uTLS captures (`utls/`)

The Python tool above compares us against the browser we copy. This one answers
the other question — what a *circumvention tool* sends — by dumping the
ClientHello of a named uTLS profile, which is what the tools that ship uTLS put
on the wire:

```
cd tools/fingerprint/utls
go run . list                                         # the library's own identifiers
go run . dump HelloChrome_133 -o ../../../target/fingerprint/utls-chrome133.hex
go run . dump HelloRandomized -seed 0001…1f -o ../../../target/fingerprint/utls-random.hex
cargo run --release --example tls_fingerprint -- hello target/fingerprint/utls-chrome133.hex
```

It prints hex and nothing else — no JA3, no JA4, no verdict — so a uTLS capture
and a live-browser capture are read by the one implementation in
`tls_fingerprint.rs` instead of two that can drift apart. The names are uTLS's
(`HelloChrome_133`), not ours (`chrome146`), because the two are not the same
hello: measured, uTLS `HelloChrome_133` and our `chrome146` answer with the same
JA4 (`t13d1516h2_8daaf6152771_d8a2da3f94cd`) and the same extension set, and
differ in the extension order, the GREASE draw and the
`encrypted_client_hello` body (218 bytes against 282 — both a BoringSSL payload
size plus 42 bytes of ECH framing). None of those three is visible to any hash,
which is what a capture is for.

`-seed` fixes the PRNG the `HelloRandomized*` profiles draw their spec from (32
bytes of hex, echoed in the capture's header line, so a shape can be rebuilt);
the client random, the session id and the GREASE values stay per-connection, so
compare a seeded pair by JA3/JA4 and not by bytes. The module pins uTLS v1.8.2 —
the release `docs/ADDING_A_PROFILE.md` lists as the source of our extension
lists — so a capture and a transcription cannot come from two different ones.

## The three comparisons

Weakest to strongest. A profile is done when it is `SAME` in `hello-diff`, or
when every remaining difference is named below and in `docs/ADDING_A_PROFILE.md`.

| stage | what it compares | what it can see | what it misses |
| --- | --- | --- | --- |
| `captures` | our `dump` against the fork's own recording of the client (`tests/signatures/*.yaml` at the bundle's tag) | ciphers, extension list and order, groups, key shares, JA3, JA4 | what the *bundle* sends today; the capture is a third party's sample |
| `echo` | both clients against `tls.peet.ws/api/all` | JA3/JA4/peetprint hashes, the akamai h2 fingerprint, every h2 frame the service received (SETTINGS payload and order, WINDOW_UPDATE, HEADERS priority), the pseudo-header order, and every request header | extension bodies (compression list, padding length, key shares); header *name case*, which h2 lowercases by rule; and the service measures the shape it read, not the bytes we sent |
| `headers` | the HTTP/1.1 request block each client sends to a local TLS listener that offers `http/1.1` alone | the request line, and every header name with its **case**, order and value — the surface no h2 comparison can see | nothing about TLS, and nothing about h2 |
| `hello` | the bytes each client puts on the wire, captured by a local listener with the same SNI on both sides | every extension body, the padding length, the compression list, the key shares, the record version | nothing about what a server does with it |

`hello` is what proves a shape: JA3, JA4 and peetprint all drop what its diff
prints. A one-byte difference in an extension body survives every hash — that is
how Safari's duplicated `rsa_pss_rsae_sha384` and its dropped `ecdsa_sha1` went
unnoticed for a release, and how the h2 pseudo-header order of Safari 18 survived
the sampled tests that pinned everything else.

## Adding or re-checking a profile

`docs/ADDING_A_PROFILE.md` is the full procedure — where the numbers come from,
what has to be pinned, what the tests gate and what is out of scope. This is the
part of it that the tool itself drives.

1. Add the wrapper, the capture and the code name to `PROFILES` in
   `fingerprint.py` (one line).
2. `python tools/fingerprint/fingerprint.py flags <code>` — the wrapper's own
   flags are the source of truth for the h2 preface, the header list and the TLS
   lists. `--http2-settings`, `--http2-window-update`,
   `--http2-pseudo-headers-order`, `--http2-stream-weight` / `-exclusive`,
   `--http2-no-priority` map one to one onto `H2Fingerprint`.
3. Transcribe the record, then run `all` and diff:
   - `captures` must be `SAME` except for what the profile deliberately omits;
   - `echo` must be `SAME` on every hash, the akamai string and the header list;
   - `hello` must be `SAME` except per-connection randomness (GREASE values, the
     client random, the session id, key share bodies, the padding's content) —
     all of which the diff masks;
   - `headers` must be `SAME` except for the two h1 items listed below.
4. Pin the new values in `crates/dpi-core/src/net/fingerprint/tests.rs` **from
   the bundle**, never from our own dump: a constant copied from our output turns
   the test into a lock-in and hides exactly the difference it exists to catch.
5. Land code, tests, `README.md` and `docs/ADDING_A_PROFILE.md` in one commit.

## Differences the tool will keep reporting

These are deliberate. Anything *else* it reports is a bug.

* **ECH body content.** The seven shapes whose wrapper names `--ech true` send
  `encrypted_client_hello` (65037) as GREASE, like the wrapper does. `enc` and the
  payload are rebuilt per connection, so the extension's *bytes* always differ —
  for a real browser too. What `hello-diff` compares instead is the length the
  body declares, which both sides draw from BoringSSL's four values (144, 176,
  208 or 240 bytes: a 32-byte-rounded estimate of the inner hello plus the AEAD
  tag, `setup_ech_grease()` in its `ssl/encrypted_client_hello.cc`). A body of
  any other size — the 400 bytes an inner-hello encoding produced here before —
  is reported as a difference.
* **Padding under the 512-byte floor, on two shapes.** `chrome123` and
  `chrome131android` reach 497 bytes with the shortest GREASE ECH body, and
  `curl_chrome123`/`curl_chrome131_android` pad there — to 517 — as this build
  now does too: the padding slot counts the extensions that follow it. Which of
  the four body lengths a run draws is per-connection randomness on both sides,
  so the two clients pad on different connections and `hello-diff` reports one
  extension more on whichever side padded — `extensions DIFF` with sizes 517
  against 561, never a smaller hello on our side. The same coin flip makes
  `echo-diff` report a JA3 difference for these two shapes more often than for
  the other shufflers, since the padding extension is part of JA3 and JA4.
* **Extension order, in the byte diff only.** The five Chrome 110+ records
  shuffle their extension order per connection because their wrapper names
  `--tls-permute-extensions`, and the bundle's own captures do too. `hello-diff`
  compares the two lists in the order they went out, so it reports `extensions
  DIFF` on every run even when the sets are identical; `captures` compares the
  set and reports a differing order as `ext order`. JA3 is a fresh sample on both
  sides for the same reason (`echo-diff` reports it), while JA4, which hashes the
  sorted set, is stable and matches.
* **Tor's third key share, against the capture only.** `curl_tor145` passes
  `--tls-key-shares-limit 3`, so the bundle and our record send X25519, P-256 and
  P-521; the fork's capture of Tor 14.5 itself stops after P-256. The `captures`
  stage reports that difference — the record follows its wrapper, which is what
  it names.

## Requirements

Python 3.8+ with PyYAML (only the `captures` stage needs it), `openssl` (only
`headers`, for the listener's throwaway certificate), the Rust toolchain, and a
bundle directory — pass `--bundle DIR`, set `$CURL_IMPERSONATE_DIR`, or keep it
under `~/Downloads` where the tool finds it. The `echo` stage reaches
`tls.peet.ws`; `headers` and `hello` bind `127.0.0.1:443` and drive both clients
at it, so they need no network.

Go 1.27+ is needed only by `utls/`, which is a module of its own: it is outside
the workspace, is not part of `cargo test`, and builds a binary only when asked.
