# Repository Guidelines

## Project Overview

`dpi-detector`: Rust engine classifying network censorship (TCP/TLS/DNS). Targets:
desktop to 16–32 MB embedded routers. Rewrite of a Python prototype — hence the
Python-shaped `config.yml` (UPPER_SNAKE keys, Russian comments). This tree = source of
truth for behaviour.

Pre-1.0: CLI, `--json` shape, module layout unstable — change whenever it makes the code
smaller, clearer or cheaper. Such a change MUST land as ONE commit with code, tests,
`README.md`.

Terms overloaded here — read from context:

- `test`: diagnostic 0–6 (`--tests 2`), NOT unit test (`cargo test`). "test 2 is broken" = the diagnostic.
- `profile`: censorship region (`--profile ru|ir|cn|global`), build profile (`--profile release-local`), TLS fingerprint (`--fingerprint chrome146`, 30 total).

## Architecture & Data Flow

Acyclic: `classify` (stage tracking, `DpiStatus`, `Detail`) → `net` (TCP/TLS,
fingerprints) → `dns` (UDP/DoH/DoT/SOCKS) → `probe` (tests 0–6); `config`/`profile`
beside. `net/` NEVER reaches `dns/`; `dns/` NEVER reaches `probe/`. Binary owns the
interface — CLI, TUI, `--json`, i18n — NEVER implements probing.

Flow: `main.rs` (clap, `AppConfig`, `Messages`, panic hook) → `runner::run_test_suite`
(concurrency gate `Arc<Semaphore>` via `probe::permit`) → `dpi_core::probe::*` per test →
`views::render_*` table or `json::Results` → `json::Report` to stdout/`--output`.

Runtime: a multi-thread tokio builder — two workers on the router targets (`--cfg dpi_router`) and one per core elsewhere, `DPI_WORKERS` overrides (`main.rs::worker_threads`); blocking work ⇒ `spawn_blocking`.
Locks: `parking_lot`; `tokio::sync::Mutex` ONLY across `.await`. Errors: `thiserror` in
core, no `anyhow`, no `unwrap()` outside tests. Logs: `tracing` (`WARN`; `-v` ⇒ `DEBUG`).

## Key Directories

- `crates/dpi-core/src/classify/` — `types.rs` (`DpiStatus`, 33 variants, `ConnectionStage`), `detail.rs` (`Detail`, `AlertKind`, `StackKind`), `classifier.rs` (error ⇒ verdict), `stream.rs` (`DpiProbeStream`).
- `crates/dpi-core/src/net/` — `tcp.rs`, `tls.rs` (`TlsProfile`, cert verifier), `fingerprint/` (30 profiles: `shapes/`, `identity.rs`, `h2.rs`, `variant.rs`), `http.rs` (the h1/h2 sender with the fingerprint on it), `connector.rs` (`DpiTlsConnector`), `ja3.rs`/`ja4.rs`, `pq_kx.rs`, `cert_compression.rs`, `hpke.rs`, `follow_up.rs`, `bind.rs`, `sysinfo/`, `netinfo.rs`.
- `crates/dpi-core/src/dns/` — `wire.rs` (RFC 1035), `udp.rs`, `doh.rs`, `dot.rs`, `socks.rs`, `resolve.rs`, `cymru.rs` (Team Cymru ASN/org over DoH TXT).
- `crates/dpi-core/src/probe/` — one module per test: `dns_avail.rs` (1), `domains.rs` (2), `tcp16.rs` (3), `whitelist.rs` (4), `telegram.rs` (5), `burst.rs` (6), and nothing else — the transport those tests drive lives in `net/` and `dns/`.
- `crates/dpi-core/src/config.rs` — `AppConfig` (`config.yml` schema), `ConfigWarning`, embedded data lists.
- `crates/dpi-detector/src/i18n/` — ONLY location for user-facing strings.
- `crates/dpi-detector/src/tui/`, `views/` — terminal backend, width math, one renderer per test.
- `vendor/` — patched upstream crates; each carries `README-PATCH.md` + `PATCH.diff`.
- `docs/` — English. `CI.md` (CI, release, supply chain), `ADDING_A_PROFILE.md` (profile procedure), `REFACTORING.md` (invariants + phases), `OPTIMIZATIONS.md` (size log), `i18n-fa.tsv|csv` (dev-only worksheet, Russian header). `README.md` is the only Russian document: it is the user manual.
- `tools/`, `scripts/` — `fingerprint/` (profile harness), `diag/dns-ca-report.ps1`, `bench-strategies.sh` (router benchmark).

## Development Commands

Toolchain from `rust-toolchain.toml` (rustup, cargo, CI read it).

| Goal | Command |
| --- | --- |
| Build | `cargo build --workspace --locked` |
| Test | `cargo test --workspace --locked` |
| One test | `cargo test -p dpi-core test_parse_dns_response_a` |
| Live-network test | `cargo test -p dpi-core --features live-network test_doh_connect_h2` (the only one that dials `dns.google`) |
| Lint | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| Doc links | `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps` |
| Supply chain | `cargo deny --locked check bans licenses sources advisories` (cargo-deny 0.20.2) |
| Run | `cargo run -p dpi-detector -- --tests 2 --lang en` |
| Example harness | `cargo run --release --example tls_fingerprint -- diff a.hex b.hex` |

```powershell
cargo build --profile release-local --target x86_64-pc-windows-msvc -p dpi-detector  # iterate, ~1.5 s
$env:RUSTFLAGS = '-C target-feature=+crt-static'
cargo build --release --target x86_64-pc-windows-msvc                              # artifact only, ~55 s
```

- Iterate with `release-local`; `--release` ONLY for an artifact. Measurements + flag-set/cache trap: `[profile.release-local]` comment in `Cargo.toml`.
- `cargo test`/`clippy` = third unit set, no shared cache. Dev `opt-level = 0` ⇒ **false timeouts**; timing runs MUST use `release-local`.
- NEVER run a formatter — house style ≠ rustfmt default. Format by hand; NEVER commit whitespace-only reformat of untouched files.
- NEVER commit, NEVER post to GitHub, unless asked: show target + exact text, wait for confirmation. "Fix the PR feedback" = draft, not post.

## Code Conventions & Common Patterns

### Systems rules (non-negotiable)

**Rule 1 — Pure Rust, zero C/C++.** Router targets (`mipsel-unknown-linux-musl`) lack a
working C cross-compiler; `ring` has no MIPS target. NEVER add a crate building
C/C++/ASM/CMake/NASM/Perl (`openssl`, `boringssl`, `aws-lc-rs`, `rquest`, `wreq`,
`curl-sys`, `zstd-sys`). Crypto: `rustls` + pure-Rust `rustls-rustcrypto`. Enforced by the
`policy` CI job (`cargo tree --target all -e normal,build -i <crate>`); `deny.toml`'s
`bans` cannot express it.

**Rule 2 — Low-memory ceilings.** 3–6 MB binary + RSS. Stream/slice, NEVER buffer whole
streams; no `tmpfs` temp files without an explicit CLI path; decoders capped —
`net/cert_compression.rs` refuses a zstd window > 1 MiB before `ruzstd` allocates.

**Rule 3 — Classification fidelity.** Every TCP/TLS probe wraps in `DpiProbeStream`,
stages `TcpConnecting → TcpConnected → TlsClientHelloSent → TlsHandshakeDone →
HttpPayload`. Reset/EOF at `TlsClientHelloSent && bytes_recv == 0` MUST be
`DpiStatus::TlsRst`, never a generic connection error; connect timeout MUST be
`SynDropped`. Middlebox accuracy = the product.

**Rule 4 — Signals stay Latin.** Badges (`DpiStatus::display_label()`) + RFC protocol
tokens (`TCP`, `TLS`, `DoH`, `SNI`, `ClientHello`) NEVER translated — RTL keeps numbers
and IPs in reading order, one log line greps alike for all users. Headers, banners,
prompts, `--legend` prose *are* translated.

**Rule 5 — `--json` language-independent.** `status` = snake_case
`DpiStatus::as_str()` (`ok`, `syn_dropped`, `tls_rst`, `no_ca_bundle`); `detail` =
`Detail::code()` (`tls_drop_handshake`, `http_403`). serde MUST agree with `as_str()` — a
test pins that. `--lang` NEVER reaches machine output.

**Rule 6 — User-facing strings in `i18n`.** No display text at a call site: add a
`Messages` field (`i18n/messages.rs`), fill all four languages — struct literals fail to
compile otherwise. `i18n/details.rs` = exhaustive `match` over `Detail`. Farsi = Latin
"Finglish". Allowed literals: badges, protocol tokens, JSON keys, file names, OS
registry/env keys, `Detail` codes, raw error text appended after a localized label.

### Patterns worth copying

- TUI repaints ONLY via `render::frame_repaint`/`render::frame_home`; padding and erase rules, and why they exist, in `frame_repaint`'s doc comment. NEVER hand-pad a row, NEVER home to `(0, 0)`, NEVER clear the screen first.
- Totality tables synced by tests: `DpiStatus::ALL`, `TlsFingerprint::ALL` ↔ `SHAPES`, `TELEGRAM_DCS`, `KNOWN_KEYS`. A profile without a `TlsShape` record panics in `spec()`.
- Shipped defaults live in the root data files (`config.yml`, `domains.txt`, `burst-domains.txt`, `tcp16.json`, `whitelist_sni.txt`), embedded via `include_str!`; precedence and key handling documented in `config.rs`.
- stdout = machine channel: `--json` writes a parseable document, nothing else may. Human output via `print_out`/`println_out`/`Emitter::emit` (`--json`-aware); diagnostics via `tracing` (stderr); TUI owns the screen. A stray `println!` breaks a consumer's `jq` and a frame at once.
- Sanitize server-controlled bytes (TLS alert text, `Detail::Other`, HTTP status lines, cert fields) through `tui` helpers on EVERY render path, error branches included.
- Search before writing a helper: two implementations = a bug even when both work. Central: `clean_domain`, `netinfo` facade, `probe::permit`, `render::frame_repaint`/`frame_home`, `i18n::{fmt_speed, fmt_size, detail_text}`, `tui::widgets` width math. Missing capability ⇒ extend the central helper, NEVER fork locally.
- Fixtures carry no device data: RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 3849 (`2001:db8::/32`), RFC 7042 (`00-00-5E-00-53-xx`). Captured `/proc`/conntrack/route output ONLY after replacing every address and MAC — repo is public, history cannot be taken back.
- Edit sources with `edit`/`write`, NEVER a script: a Python one-liner hides the diff and silently rewrites line endings. Python fine for reading, filtering, hashing, driving a router over SSH.

## Important Files

- `crates/dpi-detector/src/main.rs` — entry: CLI parse, config, i18n, panic hook, menu, per-run loop.
- `crates/dpi-detector/src/runner.rs` — `run_test_suite`: orchestration, list loaders, `Report` serialization.
- `crates/dpi-detector/src/json.rs` — `--json` payload, `SCHEMA_VERSION`.
- `crates/dpi-detector/src/args.rs` — `CliArgs` + runtime-built clap `Command` (localized help).
- `crates/dpi-core/src/classify/classifier.rs` — error ⇒ verdict decisions.
- `config.yml` (root, 430 lines) — shipped default runtime config, embedded via `include_str!`.
- `domains.txt`, `burst-domains.txt`, `tcp16.json`, `whitelist_sni.txt` — per-test target lists, all embedded; test 6 keeps its own on purpose.
- `README.md` — user manual (**Russian**), authoritative CLI reference. MUST update in the same commit as a CLI/`--json`/`Detail` change.
- `Cargo.toml`, `rust-toolchain.toml`, `deny.toml`, `Cross.toml`, `.cargo/config.toml` — build, toolchain, supply-chain, cross-compile policy.
- `.github/workflows/`, `.omp/rules/`, `.omp/agents/` — what CI runs (explained in `docs/CI.md`); repo-local agent rules and profiles.

## Runtime/Tooling Preferences

- Rust only, via cargo. Exactly one feature exists — `dpi-core`'s `live-network`, which gates the one test that needs egress (Testing & QA); everything else is a curated selection in `[workspace.dependencies]` — e.g. `brotli-decompressor`/`ruzstd` for decode-only RFC 8879/8878 support instead of rustls's compressor-linking features.
- `vendor/` = patched upstream, not ours: read the crate's `README-PATCH.md` before touching it; a change goes back to the fork, NEVER into the vendored copy. `rustls-rustcrypto` = the one vendored crate that is a workspace member; root `Cargo.toml` explains why, and which two are not.
- Auxiliary tooling lives outside the workspace, writes ONLY under `target/`, NEVER invoked by cargo: Python 3 (`tools/fingerprint/fingerprint.py`), Go (`tools/fingerprint/utls`, uTLS v1.8.2), `tools/diag/*.ps1`, `scripts/*.sh`.
- CI, release, toolchain rows, supply chain: `docs/CI.md` — read it when changing a dependency, an installer or the build matrix. Nothing there needs running by hand before a push.

## Testing & QA

Inline unit tests ONLY in `#[cfg(test)] mod tests` beside the code — one test module per
source module; no `tests/`, no `benches/`, no snapshot or mocking framework, no test
runner. Plain `#[test]` plus a few `#[tokio::test]`; names are full sentences
(`test_reset_classified_from_os_code_not_text`).

- Dev-dependencies ONLY in `dpi-core` (`tokio`/`test-util`, `brotli` for the `cert_compression` round trip). Keep it that way; no mocking crate.
- Bar: 100% pass, `cargo clippy --workspace --all-targets -- -D warnings` = 0 warnings — Linux AND Windows (the Linux runner cannot see `cfg(windows)` code; `check.yml` has the detail).
- Fixtures: root data files via `include_str!` (several tests re-parse the shipped `config.yml`, so it cannot drift); DER certificates in `crates/dpi-core/src/net/testdata/` with `generate.py` as the regenerator; inline literals for synthetic wire bytes, `/proc`/nfqws2 text and update JSON.
- Network: EXACTLY one test touches the real internet (`dns/doh.rs::test_doh_connect_h2` → `dns.google`), and it sits behind `dpi-core`'s non-default `live-network` feature so that the plain `cargo test --workspace --locked` — the CI command — needs no egress at all; run it deliberately with `cargo test -p dpi-core --features live-network test_doh_connect_h2`. Five async tests use `127.0.0.1:0`; `net/tls.rs` handshakes run in-process with fixture certs. No `#[ignore]`d tests — platform differences via `cfg`.
- MUST name the failure mode before adding a test: cannot say what a consumer observes on regression ⇒ not a test yet; a regression test MUST trigger the real prior failure path. NEVER assert on source text — reading shipped *data* (`include_str!("config.yml")`) is fine, grepping a `.rs` file for a call or comment is not. Tests MUST be full-suite safe: MUST NOT leave env vars, cwd or console mode changed.
- CI adds installer smoke tests, a Windows runner, the pure-Rust policy and an artifact round trip; `release.yml` gates the tag before the 11-row matrix — job by job in `docs/CI.md`. Nothing needs running by hand before a push: a *new dependency*, an installer edit or a broken doc link is what fails it.
- Fingerprint profiles verified by the out-of-workspace harness, not `cargo test`:

  ```
  python tools/fingerprint/fingerprint.py all [profile]
  python tools/fingerprint/fingerprint.py echo-diff chrome131
  ```

  Re-check a profile whenever its data changes; a difference the harness reports that `tools/fingerprint/README.md` does not name as deliberate = a bug. `docs/ADDING_A_PROFILE.md` lists the five artifact locations a new profile touches.

### Verifying a fix, and running an audit

Two passes over the same external guideline (`RUST_GUIDELINES.md`, `andrico21/rmcp-server-kit`) produced the same classes of mistake. Each rule below names the case it came from, so the claim can be checked rather than trusted.

- **A fix is confirmed by the absence of the old pattern, not the presence of the new one.** Grep for what was removed. A search for the new code that finds nothing proves nothing: `net/bind.rs` kept `push` + `last_mut().expect("just pushed")` while a check for `push_mut` found none and read that as done, and `cast_lossless` was recorded as declared on a hit in the vendored provider's crate root.
- **While another writer holds a file, the working tree is not evidence.** `git diff HEAD -- <path>` answers "what changed" and "what was there" at once. Reading a file mid-edit made four correctly capped, deadlined response-body reads look unbounded, and the refutation was wrong.
- **A measurement is not refuted by an argument.** A report said the brotli decoder could be made to ask for a gibibyte; RFC 7932 caps a conforming window at 16 MiB, so the number was "corrected" — and the correction was wrong: `brotli_decompressor` enables Large-Window-Brotli, and a window-30 stream was measured asking its allocator for `(1 << 30) + 66` bytes.
- **One cargo process at a time.** Concurrent builds over one `target/` leave metadata-only stubs, and the next build fails with `only metadata stub found for rlib dependency core` — which reads as a broken toolchain. Never build during a parallel-edit phase; build once, at integration. On that failure, check `rustc --print sysroot` and a plain `rustc` link before re-diagnosing, and clear `target/`.
- **Frozen outputs are pinned before the type behind them changes.** `--json` tokens and `display_label()` strings are contracts; the pinning in `detail.rs` covers one stage string of the set, so a typo in the rest is silent today.
- **Removing an indirection is not free.** Count call sites and owners first: the `i18n::format_bidi` wrappers had 35 call sites in seven files, and removing them moved no allocation — the call sites need a `String` either way. Record the decision with its measurement, the way `cast_lossless` and `cargo fmt` are recorded.
- **An audit pass hands its dismissals forward, with reasons.** The second pass was productive only because every agent was given the first pass's verdicts: what was fixed, and what was examined and deliberately left alone. Write them where the next pass can find them — the commit message, or a context artifact handed to the agents.
- **One writer per file.** Route cross-file edits — a signature that moved, a doc link a narrowing broke — through the integration owner. Two writers in one file lose one writer's work silently; the compile error is the only reason it is ever noticed.
