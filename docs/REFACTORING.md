# Refactoring plan

This document describes work on the structure of the codebase. Phases P0–P8 are
**done** (their commits are in §2), P9 was deliberately decided against; section §1
remains a list of invariants, and §4 is the history of the phases: what exactly
changed, how it was verified, and which deviations were accepted knowingly. Each
phase was conceived as a single commit that can be reverted as a whole without
changing behaviour (except for the phases where the behaviour change is the goal
itself).

The project is at status `5.0.0-alpha`: there are no rigid contracts that cannot be
changed. The CLI, the `--json` shape and the module layout change freely — all that
matters is that the codebase becomes smaller and clearer, and that the documentation
does not describe a shape the binary no longer produces.

## 1. Project invariants

They MUST NOT be violated in any phase:

* **Rust only.** No crates with a C/C++ build (`openssl`, `curl-sys`,
  `ring`-compatible wrappers) — the target devices are
  `mipsel-unknown-linux-musl` routers with no dynamic linker.
* **Memory budget.** Release binary 3–6 MB (`opt-level = "z"`, `lto = true`,
  `codegen-units = 1`, `panic = "abort"`, `strip = true`), RSS 3–6 MB. No
  unbounded allocations, no temporary files without an explicit CLI argument.
* **Stage classification.** Every TCP/TLS probe is wrapped in `DpiProbeStream`;
  a reset or EOF after ClientHello is `DpiStatus::TlsRst`, a connect timeout is
  `DpiStatus::SynDropped`.
* **Badges and protocols are Latin-script** in every language (`OK`, `BLOCKED`,
  `TLS RST`, `SNI`, `ClientHello`); only headings, banners, menus and `--legend`
  are translated.
* **All interface text lives in `dpi-detector::i18n`** (four blocks: `En`, `Ru`,
  `Zh`, `Fa`); not a single human-facing string is written at the call site. There
  is no text in the core — see phase **P5** below.
* **The TUI draws only through `render::frame_repaint`** with `render::frame_home`:
  manually padding a line to a fixed width is forbidden (a CJK font counts
  `│`, `↑`, `←` as two columns), the screen is not cleared and the cursor is not
  moved to `(0,0)`.

## 2. What has already been done

All phases of the plan except P9 (typed config) are done. One commit — one phase,
except for the noted exceptions.

| Commit | Phase | Content |
| --- | --- | --- |
| `9339a6b` | — | Common helpers in one place, `main.rs` 1778 → 670 (`runner.rs`, `terminal.rs`, `menu.rs` appeared) |
| `3fc734a` | — | A single `dial_tcp`, named target loaders, system queries moved into `spawn_blocking` |
| `60c682a` | — | Documented the deviation on TLS versions in the pinned ClientHello |
| `83ca592` | — | The menu and the test 6 screen are drawn by the shared `panel_to_string`, the test table comes from `Messages::menu_test_label` |
| `2abd399` | — | The README and the rules no longer present the `--json` shape and the badges as a frozen contract |
| `1722e16` | — | ~150 comments describe behaviour rather than "mirroring" the decommissioned prototype |
| `21bb1e8` | — | This plan was written down |
| `1aebf22` | P1.5 (part), P4 (part) | Removed the dead `probe/tls.rs` (196 lines), `TCP_NODELAY` is enabled by a single helper on every dial |
| `bdd9186` | **P1** | `net/version.rs` moved to `dpi-detector::update`; the core no longer depends on `i18n` |
| `6337df1` | **P1.5** | Public surface of the core: 30 re-exports of `dns/mod.rs` → 3, `RustlsConnector`/`DpiTlsConnector` lowered to `pub(crate)`, removed `DpiProbeStream::{into_inner,get_ref,get_mut}`, `QTYPE_{NS,SOA,PTR,MX}`, `Language::{code,name,is_rtl}`, three dead `profile` accessors, `#![warn(unreachable_pub)]` enabled |
| `50afd0e` | **P2** | `dns/availability.rs` (1146) → `probe/dns_avail.rs`; the core lost the `dns → probe` and `dns → classify` edges |
| `6ff72e5` | **P2.5** | `detail` became the enum `classify::Detail` with `code()`; `classify/constants.rs` removed, classification no longer parses prose, `i18n::detail_text` is an exhaustive `match` |
| `81bd6bc` | **P2.6** | `--json` is assembled by the structures in `src/json.rs`; `runner.rs` no longer knows about `json!` |
| `8724e7e` | **P2.7** | `i18n/mod.rs` (1711) → `mod.rs` + `messages.rs` + `en/ru/zh/fa` |
| `750e185` | **P4 + P4.5 + P7** | `net/netinfo.rs` (988) → `http_client` + `public_ip` + `sysinfo/{os,bypass}`, Cymru moved to `probe/cymru.rs` (the `net → dns` cycle is broken); nine TLS factories → `TlsProfile` + `create_tls_config`; core panics justified or removed |
| `c7660fb` | **P3** | `render.rs` (3013) and `menu.rs` (1532) → `tui/{backend,widgets,progress,input,screens}` + `views/*`; the markup layer removed |
| `ce546e3` | **P6** | CI gate `.github/workflows/check.yml` (build + test + clippy on push and PR) |
| `0dc0fa7` | **P5** | `i18n` moved into the binary; `Messages` slimmed from 213 fields to 206 (dead strings and the runtime coverage test removed) |
| `ac53995` | **P8** | `selection_flags` → `TestSelection::parse` with named fields |

Deviations from the plan, recorded deliberately:

* **P4, P4.5 and P7-core landed in a single commit** (`750e185`): they are coupled
  through `net/http_client.rs` and the new `TlsProfile`, and on their own not one
  part compiles.
* **P4.5 did not shrink the file**: `net/tls.rs` 273 → 296 lines. The surface
  shrank (nine factories → one), while the two crypto providers, the insecure
  verifier and the version parsing stayed in place.
* **`profile::blockpage_signatures` was removed** in P1.5: after `probe/tls.rs`
  was deleted nobody read it, and the signature list remains in git history until
  a consumer appears.
* **`Messages` slimmed down**: seven fields were read by nobody (`banner_subtitle`,
  `stage`, `bytes`, `duration`, `bypass_tools`, `gateway`, `detail_write_timeout`),
  five were read only by the coverage test. The test itself was dropped: four
  literals in four languages will not compile anyway if a field is forgotten.
* **P7 does not reduce panics to zero**: 11 `unwrap`/`expect` remain outside tests,
  each with a written reason why it is impossible (the TLS provider, a constant
  HTTP request, the fingerprint spec table, `serde_yaml` on an empty mapping, an
  example utility).
* **P4 decomposed differently from the plan**: instead of `sysinfo/{os,bypass}.rs`,
  `net/public_ip.rs` and `net/sysinfo/mod.rs` also appeared.

## 3. Target layering

Right now the core has three cycles, each with exactly one guilty import:

* `net → dns` — `net/netinfo.rs:21` (`query_doh_txt`);
* `dns → probe` — `dns/availability.rs:23` (`fake_ip_type`);
* `dns → classify` — `dns/availability.rs:98-99` (both lines are inside `availability`).

The goal is an acyclic graph:

```
classify  ←  net  ←  dns  ←  probe
   (leaf: stages and verdicts)  (7 diagnostic tests)
config, profile, i18n — off to the side; the binary is presentation and orchestration only
```

## 4. Phases

### P0 — Reference output snapshot ✅

* Capture `--json` for `-t 1`, `-t 2 -d example.com`, `-t 5` into a file and the
  set of keys (`jq 'paths(scalars)|join(".")'`) — this is a **reference for the
  eyes**, not a contract.
* Why: P2.5 and P2.6 change the shape of `detail` and the shape of the JSON; the
  comparison must be deliberate, not byte-for-byte.
* Risk: none. Nothing blocks.

### P1 — `net/version.rs` leaves the core for the binary ✅ (`bdd9186`)

* What: 244 lines — `fetch_latest_version` (GitHub Releases API), `version_badge_lang`,
  `ReleaseInfo`, `CURRENT_VERSION`, `is_newer` → `crates/dpi-detector/src/update.rs`.
* Why: it is an application-level service utility, and it is the **only** module
  of the core that uses `i18n` at all (`net/version.rs:1,160`), and it also pulls
  in `netinfo::http_get_text`.
* Cost: two imports in the binary (`main.rs:9`, `menu.rs:17`) and an edit to `net/mod.rs`.
* Verification: the gate + a live run of the menu (version badge in the banner).

### P1.5 — Public surface of the core ✅ (`6337df1`)

The audit showed ~63 `pub` items with not a single reference outside their own file.
In a library crate the compiler does not catch such things, hence a cleanup plus
protection against recurrence:

* **Done** (`1aebf22`): `probe/tls.rs` removed entirely.
* Remaining — lower to `pub(crate)` or remove: `net/version.rs:154` `version_badge`
  (called only from its own test), 27 unused re-exports of `dns/mod.rs:10-17`
  (exactly one is live through a re-export, `parse_socks_proxy`),
  `net/tls.rs` `create_insecure_dpi_tls_config_tls13/tls12`,
  `probe/connector.rs` `new_insecure_tls13`/`new_insecure_tls12`/`new_verifying`,
  `classify/stream.rs` `ProbeState` and `DpiProbeStream::{into_inner,get_ref,get_mut}`,
  `dns/wire.rs` `QTYPE_NS/SOA/PTR/MX`, `net/cert_compression.rs` `covers` (tests only),
  `i18n` `Language::{code,name,is_rtl}`,
  `profile` `default_resolvers`/`default_doh`/`blockpage_signatures` (tests only),
  `lib.rs` aliases `PhaseSwitch`/`BlocksSwitch`.
* Protection: `unreachable_pub` is enforced from the workspace lint table
  (`Cargo.toml`, `[workspace.lints.rust]`), which `dpi-core` opts into with
  `[lints] workspace = true`; work through the output so the surface does not
  creep again. The binary crate carries a dated local `allow` for it until the
  `pub` → `pub(crate)` sweep over `dpi-detector` lands — its modules are private,
  so the lint fires on every `pub` item there.

### P2 — Test 1 moves from `dns/` to `probe/` ✅ (`50afd0e`)

* `dns/availability.rs` (1146 lines, test 1) → `probe/dns_avail.rs`; `dns/` remains
  pure protocol (`wire`, `udp`, `doh`, `dot`, `socks`, `resolve`, `types`).
* Removes the `dns → probe` and `dns → classify` edges.
* Cost: 9 imports in the binary (`render.rs`, `runner.rs`) and `dns/mod.rs:11`.

### P2.5 — `detail` from strings to a type ✅ (`6ff72e5`)

Today classification **parses prose**: `i18n/details.rs:32,33,51` splits the detail on
`" at "` and strips `"KB"`, `probe/whitelist.rs:86,225` checks
`detail.contains(DET_AT_KB_MARKER)`, and assembly goes through
`format!("{}{}{}{}", …, DET_AT_KB_MARKER, kb, DET_KB_SUFFIX)` in
`probe/tcp16.rs:177,260,273,286` and `probe/domains.rs:238,241,401,404`.
`DET_*` occurs in 276 lines, and `classify/constants.rs:44-46` outright calls the
marker part of the wire format.

* Target: `enum Detail` in `classify` (`TlsDrop`, `ReadTimeout { kb }`,
  `Tcp16Range { kb }`, `Spoof(…)`, `CertIssue(…)`, `DnsError(…)`, …) with `code()` for
  JSON and rendering through `i18n::detail_text(Detail)` — an exhaustive `match`
  instead of a runtime coverage test.
* Effect: comparing variants instead of strings, a snake_case token in JSON, prose
  only in i18n; `ALL_DET_DETAILS` and `i18n/details.rs` shrink to a table of variants.
* Risk: medium (it touches every error path). Verification: the gate + a live `-t 2/3/4/5`
  with a `--json` diff against the P0 snapshot.

### P2.6 — Typed `--json` ✅ (`81bd6bc`)

* Today `runner.rs` assembles the output by hand — 14 sites of `serde_json::json!`.
  The core reports are already structs (`DnsAvailReport`, `DomainStats`, `BurstReport`,
  `TelegramFullReport`), `DpiStatus` is already `Serialize` (`classify/types.rs:30-31`).
* Target: `#[derive(Serialize)]` on the reports + one top-level wrapper;
  `status` and `detail` go into JSON through serde.
* Effect: the schema is described in one place; the class of bugs "the field is in
  the table but not in the JSON" disappears.

### P2.7 — `i18n` split by language files ✅ (`8724e7e`, later moved into the binary) 

`i18n/mod.rs` — 1739 lines, `Messages` — 212 fields × 4 blocks. Split into
`i18n/{mod,en,ru,zh,fa,details}.rs`. The field parity test is kept: adding a
language is one new file.

### P3 — Split `render.rs` and `menu.rs` ✅ (`c7660fb`)

* `tui/backend.rs` — VT/Win32 FFI, `output_str`, `frame_home`, modes (`ascii`,
  `plain`, `has_vt`).
* `tui/widgets.rs` — panels and frames (`panel_with`, `box_chars`, `asc`, `cell_color`,
  `status_color`), width and wrapping (`strip_ansi_len`, `wrap_ansi`), `frame_repaint`.
* `tui/progress.rs` — `LiveProgress`, `Spinner`, `progress_line`, `Refresher`.
* `views/*` — along the already existing section markers `// ─── Test N ───`
  (`netinfo`, `dns`, `domains`, `tcp`, `whitelist`, `telegram`, `burst`, `summary`).
* `menu.rs` → `tui/screens/{main,burst,legend,post_run}.rs` + `tui/input.rs`
  (keyboard-layout normalisation and `nav_key`).
* Hard rule: the width maths and `frame_repaint` stay in one module.
* Also P3.5: remove the internal markup layer — 16 sites of `[green]…[/]`
  (`render.rs:2238-2289`) and the `markup_to_ansi` converter (`render.rs:2362-2371`):
  write SGR directly.
* Verification: a live TUI in a pty (main menu and the test 6 screen) + the gate.

### P4 — Split `net/netinfo.rs` ✅ (`750e185`)

* `net/http_client.rs` — `http_get_text`, `http_get_chain`, `http_get_once`,
  `request_once` (needed both by public IP and by Cymru).
* `sysinfo/os.rs`, `sysinfo/bypass.rs` — the Windows registry, adapters, route,
  `get_system_dns`, `detect_bypass_tools`, `resolv.conf`/`getprop`.
* Breaks `net → dns` (`net/netinfo.rs:21`) and makes the graph acyclic.
* **Done** (`1aebf22`): `TCP_NODELAY` is enabled on every dial through
  `net::tcp::set_no_delay` — DoH, DoT, SOCKS5, the GET in `netinfo`, the three
  Telegram paths and `dial_tcp`, so the rule from `net/tcp.rs:22` ("это требование, а не оптимизация")
  holds for every dial, not for four out of ten.

### P4.5 — Collapse the TLS factories ✅ (`750e185`)

`net/tls.rs` — nine `pub fn create_*`; `probe/connector.rs` — seven constructors
(`new_insecure`, `…_tls13`, `…_tls13_with`, `…_tls12`, `…_tls12_with`,
`…_versioned_with`, `new_verifying`). Target: one
`TlsProfile { fingerprint, version, alpn, verify }` and one
`RustlsConnector::from(profile)`. Required tests: `grease_version_leads_supported_versions`,
`bundle_versions_match_their_ja3`, `bundle_versions_match_their_ja4`.

### P5 — `i18n` from the core into the binary ✅ (`0dc0fa7`)

Decision made. The order is mandatory: after **P1** (otherwise the core still needs
`i18n` for `net/version.rs`) and after **P2.5/P2.6** (so that the detail prose does
not have to be moved twice): first `detail` becomes a type with `code()`, then the
texts move to `dpi-detector/src/i18n/`.

* What moves: `Messages` (4 blocks), `legend_sections*()`, `details.rs`,
  `fingerprint_label`, `fmt_speed`/`fmt_size`, `Messages::{config_warning, phase_text}`.
* What stays in the core: `PhaseId`/`ProgressBlock` (language-independent identifiers)
  and the detail constants; the `i18n` in the binary imports them — the dependency
  direction becomes one-way.
* Along with the move, the project rules are amended (§1 of this document and the
  README): the entry point for a new string is the binary crate, not the core.
* Verification: the four-block parity tests (`test_messages_coverage`,
  `test_finglish_is_latin_only`, `i18n::details::tests`) move together with the module;
  a live run of the menu and `--legend` in two languages (`--lang en`, `--lang fa`).

### P6 — CI gate ✅ (`ce546e3`)

In `.github/workflows/` there is currently only `release.yml` (a matrix of 12 targets,
on tag). Add a `check` job on push/PR: `cargo test --workspace`,
`cargo clippy --workspace --all-targets`, `cargo build --locked`.
As a separate item (by decision) — comparing the vendored `vendor/rustls` with the
current crates.io release.

### P7 — Audit of `unwrap()`/`expect()` outside tests ✅ (`750e185`, breakdown below) 

39 places in 9 files: `profile/mod.rs` 15, `dns/availability.rs` 8, `probe/domains.rs` 5,
`net/tls.rs` 4, `config.rs` 3, and one each in `render.rs`/`tcp16.rs`/`http.rs`/`fingerprint.rs`.
With `panic = "abort"` a panic kills the whole run: every case must either be justified
by a comment (an invariant proven by construction) or turned into `?`/a default.

### P8 — `TestSelection` instead of a 9-bool tuple ✅ (`ac53995`)

`selection_flags` (`main.rs:34-46`) returns nine `bool`s; a transposition in such a
tuple compiles silently. Introduce a `struct TestKind`/bit set, with `menu.rs` and
`runner.rs` as consumers.

### P9 — Typed config (decided: not doing it)

The tolerance layer for "dirty" hand-written `config.yml` (numbers as strings, key
case and nesting, unknown keys as warnings) stays: it is covered by tests, including
parity with `config.yml`, and removing it would save ~300 lines at the cost of
refusing to accept configs that work today. Decision made 2026-09-14: no typing.

## 5. Rejected (do not propose again)

| Proposal | Reason |
| --- | --- |
| A `DiagnosticTask` trait for all seven tests | The tests have different signatures and reports by design (`check_dns_availability(&AppConfig, Option<PhaseProgress>, usize)` versus `burst_targets(&AppConfig, &[BurstTarget], &BurstSettings, usize)`), and the progress and cancellation seam already exists: `PhaseProgress`/`ProgressTick`/`BlockTick` and the language-independent `PhaseId`/`ProgressBlock` |
| Rename `probe/` to `engine/` and introduce a `protocols/` layer | A rearrangement with no boundary: `probe/` holds six engines and three small primitives (`connector.rs` 91, `http.rs` 172, `tls.rs` 196) |
| Move `probe/connector.rs` into `net/` | The trait takes and returns `DpiProbeStream`, and `net/` today knows nothing about `classify` (zero references) — the move would create a new bottom-up edge |
| Move `probe/http.rs` into `protocols/` | There are no consumers outside the probes, and the move would spread probe support across two layers |
| `enum DiagnosticVerdict` instead of `DpiStatus` | `DpiStatus` is already an enum; it was `detail` that needed typing — done in P2.5 (`classify::Detail`) |

## 6. How to verify each phase

```bash
cargo test --workspace
cargo clippy --workspace --all-targets      # exactly 0 warnings
```

* One commit — one phase. Do not mix moves and edits in one commit:
  a move must read as a move.
* Do not run `cargo fmt`: in the tree 48 of 54 files are CRLF, rustfmt writes only
  LF, `cargo fmt --all --check` complains about 39 files — a single run would rewrite
  and reformat almost the whole tree. Format by hand.
* Live verification by surface: TUI — a run in a pty (menu and the test 6 screen);
  CLI — the `release-local` binary with `--json`; for output changes — a diff against
  the P0 snapshot.
* Fast build for iterations:
  `cargo build --profile release-local --target x86_64-pc-windows-msvc -p dpi-detector`.
* The release artifact is built only when it is really needed:
  `RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-pc-windows-msvc`.
  `dist/` is updated on an explicit request.
