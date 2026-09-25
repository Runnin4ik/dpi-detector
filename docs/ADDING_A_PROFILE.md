# Adding a fingerprint profile

How a new shape gets into the repository: a new browser version, a new client, a new
platform. Where the numbers come from, what checks them, and what must fail on its own
if a shape stops matching its source.

A profile is **data**, not code. One record in a table, and everything else — the
builder, the parsers, `--legend`, JSON, the config, test 6 — reads it.

---

## 1. What a profile is

| Element | Where | What it describes |
|---|---|---|
| `TlsShape` + `SHAPES` | `crates/dpi-core/src/net/fingerprint/shapes/` (`mod.rs` — the struct and the table, one file per client family) | the shape: names, `source`, ciphers, groups, signature schemes, extension order, `raw_exts`, `suppress`, `drop13`/`drop12`, ALPN, `padding_to`, certificate compression, key shares, GREASE/ECH/shuffling |
| `HttpIdentity` | `.../fingerprint/identity.rs` | `User-Agent`, the set, the order and the **case** of header names |
| `H2Fingerprint` | `.../fingerprint/h2.rs` | the preface: SETTINGS with order, connection window, pseudo-header order, priority |
| `TlsFingerprint` | `.../fingerprint/mod.rs` | the variant, `code` (JSON and config), `token` (badge, Latin), `label` ("CHROME 133"), `parse`, `ALL`, `DEFAULT_SET` |
| Pins and structural tests | `.../fingerprint/tests.rs` | JA3/JA4 against the source and the §4 gates |
| The harness row | `tools/fingerprint/fingerprint.py` (`PROFILES`) | the code, the bundle wrapper and the fork's capture file — or `utls:HelloX` in place of the wrapper when the bundle does not wrap this client |

The rules this rests on:

* **A variant without a record is an error.** `spec()` panics, and
  `fingerprint_table_is_total` checks `ALL` and `SHAPES` against each other in both
  directions.
* **`ALL` is the only hand-written list.** A new profile is added there, not into
  `match` arms all over the code.
* **The name = the client version.** `chrome146`, `firefox147`, `tor145`; only
  `rustls` has no version — it is the baseline shape, not a client. Wrapper names
  (`curl_*`) and names without a version are rejected: a name that resolves to a
  version other than the one it claims silently measures a different client.
* **One profile per shape.** Of several versions whose hellos coincide (checked
  through `tls.peet.ws` for each wrapper), the newest is kept: Chrome 133–146 share
  JA4, peetprint, the akamai h2 fingerprint, the preface frames and the header names
  — only the version in `User-Agent` and `sec-ch-ua` differs. A record that differs
  from an existing one only in UA is not a profile but a second row with the same
  key. **The single exception is `chrome133`.** It was added deliberately and repeats
  the hello of `chrome146`: two records that agree on everything except `sec-ch-ua`
  and `User-Agent` give the run a way to ask whether the censor reads identity. An
  identical verdict says it does not; a diverging one says it does, and that would be
  the first difference between shapes that shows up outside the hello. There must be
  no second such record: the exception is valuable precisely because it is the only
  one.
* **i18n is not touched.** The tokens are Latin (Rule 4), the profile list is printed
  by `--legend` from the table, and the JA4 key comes from the same builder as the
  probe (`hello_ja4_variants`), so adding a language or a profile does not mean
  editing strings.

## 2. Where to get the numbers

| Source | What it gives | What it is |
|---|---|---|
| The `curl-impersonate` bundle (the wrapper) | wrapper flags: h2 preface, header set, TLS lists, `--ech`, `--tls-permute-extensions`, `--tls-key-shares-limit` | **the source of truth**: the wrapper is the client |
| Its own captures (`tests/signatures/*.yaml` at the bundle tag) | ciphers, extension set and order, groups, shares, JA3/JA4 | proof (someone else's recording of the client) |
| uTLS (pinned to `v1.8.2`, `tools/fingerprint/utls`) | reference hello specs: lists, order, curves, schemes, ALPN, extension bodies (ALPS, certificate compression, `psk_key_exchange_modes`, `record_size_limit`, delegated credentials, channel ID stub) | **the source of the spec, not proof**: uTLS lacks what the wrapper sends — and **the source of truth instead of the wrapper** when there is no wrapper at all |
| The same spec, captured by our dumper (`go run . dump <HelloSpec> -o capture.hex`; the `HelloGolang` library builds through `crypto/tls`, so it needs `-handshake`) | the hello bytes: extension bodies, order, key shares, ALPN, declared lengths | **proof** for a client without a wrapper: the module's spec at the pinned version, read against our dump (`hello capture.hex`, `diff a.hex b.hex`) |
| A live client (`hello <file.hex>`, mitmproxy/Wireshark) | "how it really sends" for a version no library covers yet | proof, when a capture exists |
| `bogdanfinn/tls-client`, JA4 databases (ja4db, FoxIO) | "does such a profile exist at all" and JA4 cross-checking | cross-check |

When the bundle has no wrapper — which is the case for nine records (`chrome87`,
`chrome72`, `chrome70`, `chrome115pq`, `firefox120`, `firefox105`, `firefox99`,
`firefox65`, `go127`) — the reference becomes the uTLS spec itself: the literal in
the module at the pinned version `v1.8.2`, read against a capture taken by our
dumper. Two consequences are visible right in the record. The HTTP identity of such a
record is a **minimum**: the library has no HTTP layer, so there is exactly the
`User-Agent` of its version and `accept-encoding`, with no `sec-ch-*` and no h1
priority — and that is not a measurement but a declared boundary. The h2 preface
stays hyper's default: the spec has none of its own, and inventing one would already
stop being transcription. In the harness such rows are marked `utls:HelloX` in
`PROFILES`, and only `hello` and `hello-diff` apply to them — bytes against bytes;
`captures`, `echo`, `echo-diff`, `headers`, `headers-diff` and `flags` skip them,
because there is nothing to compare against and they have no wrapper flags.

Tools: `python tools/fingerprint/fingerprint.py flags <code>` (wrapper flags),
`... versions` (JA4 and the mobility of each bundle version: where JA3 shuffles,
where the padding coin lands), `... utls` (all profiles of the uTLS library against
the nearest bundle wrapper — what exactly the uTLS client sends), `go run . dump
<HelloSpec> -o capture.hex` in `tools/fingerprint/utls` (the uTLS spec), `cargo run
--release --example tls_fingerprint -- hello capture.hex` (reading any capture),
`... -- diff a.hex b.hex` (comparing any two captures field by field, without the
network) and `--legend` (what we send right now). The `utls:<HelloX>` rows in
`PROFILES` have a counterpart in the `UTLS_PAIRS` table — it is `ours:<code>`, that
is, a check of the spec against our record.

The bundle is looked up through `$CURL_IMPERSONATE_DIR`, then in `~/Downloads`; the
path can be set with `--bundle DIR`. The bundle directory name carries the version
(`curl-impersonate-v2.2.2.x86_64-win32`) — `capture_ref()` takes the fork tag from
it, which is why the directory is not renamed.

In a record, `source` names the release of the source: updating the source is a
deliberate revision of the pins, not a silent change of the shape.

## 3. Procedure

1. **Pick the client and the generation.** Verify that the shape is new: `--legend`
   and `fingerprint.py all` show the key of every existing record, and a record with
   the same JA4 is the same client.
2. **Obtain the source.** `flags <code>` → preface, headers, flags; the fork's
   capture, if there is one; the uTLS spec, if the wrapper is not enough — and if the
   client has no wrapper at all, then the spec is the reference: the literal at the
   pinned version is read against a capture taken by the dumper (§2), and the record
   is transcribed from that pair; a live capture, if no one has the version. Check
   that the shape agrees across the two sources where they overlap.
3. **Write the record** in the file of its family (`shapes/chrome.rs`, `shapes/firefox.rs`, …)
   and add its name to the `SHAPES` table in `shapes/mod.rs` — the order there and in
   `ALL` is the same. The lists are raw IANA identifiers in wire order, so that the
   record can be read straight out of a capture. If the shape coincides with an
   existing one (Edge is Chromium, Safari 18.0 is the 15.5 hello), **reference its
   lists** rather than copy them: what must differ is the identity and the preface.
   Behavioural traits (`grease`, `ech`, `permute_extensions`, `priority_on_h1`,
   `pq`, `key_share_groups`, `padding_to`) are record data too, not a per-family
   rule.
4. **Register it**: a variant in `TlsFingerprint`, a row in `ALL`, `code`,
   `token`, `label`, and `parse` if needed. Decide about `DEFAULT_SET` — seven
   slots, each answering its own question (the baseline shape, the newest in each
   family, a pair at a generation boundary, one closed shape per key family).
5. **Nail down the expectations** in `tests.rs`: JA3 **and** JA4 of both pinned
   builders (1.3 and 1.2), taken **from the source** — a constant copied from our own
   dump pins our own mistake and hides exactly the difference the test exists for.
   Add a row to the tables that enumerate all profiles (identities, key shares, h2
   prefaces, labels, tokens). If a shape advertises a code point the provider cannot
   do, name it in `UNIMPLEMENTED` with a reason.
   If a profile needs an extension rustls cannot do, that is a patch in `vendor/rustls`
   plus a row in `vendor/rustls/README-PATCH.md` and a regenerated `PATCH.diff`
   (the same for `hyper` if the request block is what is at stake; an h2 preface
   goes through the `http2` crate's own API, so a knob it does not expose is a
   question for that crate, not a patch here).
6. **Run the ladder** (§3.1) and commit the code, tests and documentation as one
   piece: `README.md` (the profile list), this document, `tools/fingerprint/README.md`
   (if a new divergence appeared). A record without a wrapper — `utls:HelloX` in
   `PROFILES` and an `ours:<code>` row in `UTLS_PAIRS` — is added in the same piece,
   otherwise there will be nothing to check the spec against.

### 3.1 The verification ladder

| Step | What it checks | What it does not see |
|---|---|---|
| `cargo test --workspace` + `clippy` | the §4 gates and the JA3/JA4 pins | anything about the wire |
| `fingerprint.py captures <code>` | the dump against the fork's own record: ciphers, extension set and order, groups, shares, JA4 | what the bundle sends today; the capture is someone else's sample |
| `fingerprint.py echo-diff <code>` | both clients against `tls.peet.ws`: hashes, akamai string, every preface frame, pseudo-header order, every header | extension bodies and the case of names; it is the service's opinion of what it read |
| `fingerprint.py hello-diff <code>` | **the bytes of both clients** through one local listener: extension bodies, padding length, compression list, key shares; for a record without a wrapper (`utls:` in `PROFILES`) the opponent is the spec bytes taken by the dumper | what the server does with them |
| `fingerprint.py headers-diff <code>` | the HTTP/1.1 request block: names with case, order, values | anything about TLS and h2 |
| `live` / `liveany <code>` | real handshakes: base hosts, `hub.docker.com` and `danbooru.donmai.us` (SCT in the certificate entry), `standby-rezka.tv` | — |
| `peet <code>` | the akamai fingerprint of the preface | — |
| `diff <a.hex> <b.hex>` | any two captures — ours, the bundle's, uTLS, a live browser — field by field, without the network | what the server does with them |

`fingerprint.py all` ends with a **verdict table**: one row per profile, which
comparisons diverged and which of them the record's own client explains. It judges by
measurement, not by declaration: a profile's hello is taken 24 times, so a drifting
extension *order* marks a shuffling shape, while a drifting *set* marks the padding
coin; a wrapper with `--tls-key-shares-limit` explains its own key shares. Everything
else is printed as `to look at` — only the list of intentional divergences in
`tools/fingerprint/README.md` can rule on it. A full run goes over twenty-eight
profiles: the nineteen bundle rows produce the same `13 clean, 6 explained by their
own client, 0 to look at` as before, while the nine uTLS rows are judged by a single
`hello` comparison — they have no wrapper flags, there is nothing to explain there,
and all the list forgives is the GREASE body length in `firefox120` and the second
key share of `chrome115pq` (§5).

A profile is considered done when `hello-diff` says `SAME`, or when every remaining
difference is named in `tools/fingerprint/README.md` and in §5 of this document.

About `standby-rezka.tv`: the host answers `fatal alert: IllegalParameter` to **all**
shapes that advertise GREASE, and `OK` to those that do not. This is host behaviour,
not a regression of the records: the set of failing shapes exactly matches the set of
advertising ones, and the bytes of those records have not changed. That is precisely
why the host stays in the live sweep.

## 4. Gates that fail on their own

| Test | What it catches |
|---|---|
| `fingerprint_table_is_total` | a variant without a record and a record without a variant, the order of the table |
| `profile_names_are_unique_lowercase_and_versioned` | a duplicate name, a name without a version, a name that is not lowercase |
| `fingerprint_parses_known_values_and_rejects_others` | acceptance of a new name and rejection of wrapper names and names without a version |
| `default_set_is_a_subset_of_all` | the default set: non-empty, without duplicates, drawn from `ALL` |
| `the_baseline_is_the_only_shape_that_impersonates_nobody` | a record that impersonates nothing but is not `rustls` |
| `every_advertised_code_point_is_served_or_named` | profile ⊆ provider: every cipher, group and scheme is either served or named in `UNIMPLEMENTED` with a reason; a stale record fails the test too |
| `the_advertised_group_list_opens_with_the_group_we_share` | a group list that opens with a group other than the one the share is sent for |
| `only_the_chromium_profiles_shuffle_their_extension_order` | shuffling where there is none, and its absence where there is; non-shuffling shapes must be reproducible byte for byte |
| `the_ech_shapes_carry_the_grease_extension_and_the_others_do_not` | ECH in those whose wrapper names `--ech true`, and in `firefox120` from the uTLS spec; the body length comes from four BoringSSL values, while for `firefox120` the source pins one (recorded in §5) |
| `every_identity_is_spelled_the_way_its_client_writes_it` | `User-Agent` and the spelling of header names |
| `every_profile_sends_the_key_shares_its_wrapper_asks_for` | key shares against `--tls-key-shares-limit` |
| `every_h2_preface_matches_the_wrapper_it_copies` | SETTINGS with order, window, pseudo-header order, priority |
| `display_labels_name_the_pinned_version`, `fingerprint_tokens_are_stable` | a label without a version, a change of a token (Rule 4) |
| `bundle_versions_match_their_ja3` / `_ja4`, `chrome_146_matches_the_utls_list_it_is_derived_from` | the pins: any change of a shape — an extension added/removed, a cipher reordered, padding lost |
| `utls_shapes_match_their_ja3` | the pins of the nine uTLS records: JA3 (for the shuffling `chrome115pq`, with the extension order sorted) and JA4, taken from the captures in `target/fingerprint/utls-ladder/`; a cipher reordered, an extension added/removed, a group lost — the test fails |
| `profiles_that_share_a_tls_shape_send_the_same_hello` | a record that claims shared lists but sends its own |

## 5. Intentional divergences

The list and the reasons are in `tools/fingerprint/README.md`, section "Differences the tool
will keep reporting". In short: the GREASE-ECH body is rebuilt on every connection
(the declared length is what gets compared), padding in `chrome123`/`chrome131android` is a
per-connection coin (the shape has two keys), the extension order of Chrome 110+
shuffles (JA4 matches, JA3 does not), and `tor145` has one key share more than the
browser in the fork's capture — the record follows its own wrapper.

The nine records transcribed from uTLS specs have divergences of their own, and all four
are named here so the reader does not have to look for them elsewhere:

* **`firefox120` and the GREASE-ECH length.** The spec pins the length of the
  `encrypted_client_hello` body (`CandidatePayloadLens = {223}`, that is 239 bytes
  of payload and a 281-byte extension body on the wire), while our builder, as in
  all the other records, draws it from four BoringSSL values (bodies
  186/218/250/282). The hashes do not move because of this, but `hello-diff` against
  the spec's capture prints a length divergence on every throw — and that is what
  the list of intentional divergences in `tools/fingerprint/README.md` forgives.
* **`chrome115pq` and the second key share.** The spec sends shares for
  `X25519Kyber768Draft00` (25497) and X25519, while the provider has no group for
  that draft (§6), so the record advertises 25497 for the sake of the group list but
  sends a share only for X25519. `hello-diff` prints one share where the capture has
  two — the provider created this divergence, not the transcription, and JA3/JA4
  (they read the group list, not the shares) do not move because of it. The second
  consequence of the same hole is the length: without the hybrid share's body our
  hello is shorter than the original 1524 bytes and falls under the 512-byte padding
  threshold, which a real Chrome 115 never falls under, which is also why the record
  has no padding slot (the extension bodies and the set remain the capture's, and
  only the key share body differs).
* **No h2 preface at all.** All nine send HTTP/2 with hyper's default settings: the
  spec has no preface of its own, and inventing one is no longer transcription. The
  other records have their preface taken from the wrapper, and the difference is
  visible only on the wire: `hello` does not carry the preface, and `echo` is not
  run for the nine.
* **The HTTP identity is a minimum, not a measurement.** The library has no HTTP
  layer, so the record holds exactly the `User-Agent` of its version and
  `accept-encoding` (`gzip, deflate, br` for the browsers, `gzip` for `go127`) in the
  client's own spelling: Chromium's names are lowercase, Firefox's and `go127`'s are
  capitalized. None of the nine advertises an h1 priority.

Separately: `chrome87` also covers Chrome 83 — the specs of those versions coincide
entirely — while `chrome70` covers 360Browser 11.0, where the extension bodies and
JA4 coincide and only the order differs. This is the same "one record per shape" case
as Chrome 133–146 in §1, not a divergence from the source.

## 6. What is out of scope

* **QUIC/HTTP-3.** In `vendor/rustls-rustcrypto/src/quic.rs` there are stubs, and
  every TLS 1.3 suite has `quic: None`. As long as that is so, no h3 profile is
  possible, regardless of `quinn`/`h3`. The order of work, if one takes this on:
  header protection per RFC 9001 §5.4 with the §A.2 test vectors, `quinn` without the
  default `rustls-ring`, a transport parameters patch, and an `http3` feature
  (off by default — Rule 2).
* **Real ECH configured from DNS.** Deliberately not done: it makes the hello depend
  on the *host*, whereas the rest of a record's fields depend on the client, and the
  wrapper does not send it. It adds nothing for diagnostics (a censor cannot tell
  GREASE-ECH from a real one by construction), while it costs a DNS request in the
  classified path. The shape is GREASE, as in the wrappers.
* **Record-level tricks** (splitting the ClientHello across records, record size limit,
  middlebox CCS) — a known divergence, not reproduced.
* **Delegated credentials (34)** — do not advertise it as a served code point: the
  provider cannot sign with them. The extension in a record is another matter, and three
  Firefox records from uTLS (`firefox99`, `firefox105`, `firefox120`) do advertise it:
  that is how the spec is written, and the body is its own bytes.
* **Provider gaps** (P-521, DHE, SHA-1, CBC, `X25519Kyber768Draft00`
  `0x6399`, which `chrome115pq` advertises) — not a record error but a row in
  `UNIMPLEMENTED` with a reason: the §4 gate checks the converse too, that what is named
  is no longer stale.

## 7. Decisions worth knowing

* **Data instead of code.** Per-profile builders (~100 lines each) have been replaced
  by a table: an error in one constant used to be twenty places to make it — now it
  is one.
* **Key, not bytes.** A censor carries a table of JA4 keys, so a shape falls under a
  block by key rather than by extension order: leaving the table means a different
  *generation*, not a different permutation.
* **GREASE-ECH, not real.** curl obtains a real `ECHConfigList` only via DoH or
  `--ecl:`, and no wrapper passes either; a hand-made body made Google and Cloudflare
  answer `DecodeError`, whereas rustls's path (`EchMode::Grease` through `net::hpke`)
  is accepted by every host in the sweep.
* **Padding is a frequency, not a shape.** `chrome123` and `chrome131android` pad on
  one connection in four (the shortest ECH body), and this is reproduced; the other
  three lengths go out without padding — exactly like the client.
* **Shuffling is a distribution.** Byte-for-byte equality with a real Chrome 110+
  will never happen: its shape is new on every connection. What can be compared is
  JA4 and the set of extensions.
* **A spec instead of a wrapper when there is no wrapper.** The wrapper remains the
  source of truth, but its absence is no reason not to have a profile: nine records
  are transcribed from uTLS specs and are checked against the bytes our dumper takes
  from them (§2). What has to be declared rather than measured in that case is the
  HTTP layer: the library lacks it, so the identity of these records is minimal and
  the h2 preface is hyper's. Such a boundary is named in the record itself and in
  §5, so that no one later mistakes it for a measurement.
