# tools/fingerprint — checking a profile against the client it copies

`crates/dpi-core/examples/tls_fingerprint.rs` dumps what *we* send. This tool is
the other half: it drives the `curl-impersonate` bundle each profile is
transcribed from and diffs the two clients, so a profile can be re-checked
whenever its data changes.

```
python tools/fingerprint/fingerprint.py all                 # every stage, every profile
python tools/fingerprint/fingerprint.py all safari18        # one profile
python tools/fingerprint/fingerprint.py hello-diff --summary
python tools/fingerprint/fingerprint.py echo-diff chrome131
python tools/fingerprint/fingerprint.py headers-diff --summary
python tools/fingerprint/fingerprint.py flags chrome136     # what the wrapper itself names
```

Outputs land in `target/fingerprint/` (dumps, captured bytes, echo reports, the
fork's captures) and are never committed: re-running is cheap, and a stale
capture is worse than none.

## The three comparisons

Weakest to strongest. A profile is done when it is `SAME` in `hello-diff`, or
when every remaining difference is named below and in `docs/FINGERPRINT_PLAN.md`.

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
5. Land code, tests, `README.md` and `docs/FINGERPRINT_PLAN.md` in one commit.

## Differences the tool will keep reporting

These are deliberate. Anything *else* it reports is a bug.

* **ECH.** `chrome120`, `chrome131`, `chrome131android`, `chrome133`,
  `chrome136`, `firefox`, `firefox135`, `firefox144` and `tor145` carry no
  `encrypted_client_hello` (65037): a synthesized body makes real servers reject
  the handshake. Their JA3/JA4/peetprint therefore differ from the bundle's, and
  their JA4 extension count is one lower.
* **Permuted extension order.** Chrome 110 and later shuffle their extensions per
  connection; a profile has one order, so its JA3 is one sample of the
  distribution (JA4 hashes the sorted set and is stable).
* **Compression list (Firefox family, Tor).** The build has no zstd decompressor,
  so `compress_certificate` stops at `zlib, brotli` where the bundle sends
  `zlib, brotli, zstd`.
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
