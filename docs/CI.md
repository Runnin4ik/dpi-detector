# CI and release

Reference for `.github/workflows/`. Everything needed for local work is in `AGENTS.md`;
this file is read when changing a dependency, an installer or the build matrix. The
workflow files are the source of truth — only what they do not make obvious is below.

## `check.yml` — on every push and PR

Exact commands (all `--locked`):

```
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy -p dpi-core --features live-network --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps
```

The fourth command is the one step that compiles the `live-network` test: the feature is
off everywhere else, and this is the only place it is ever linted. `--all-features` would
have covered it in the command above, and is not used: the only other feature it turns on
is `vendor/rustls-rustcrypto`'s `logging`, a configuration nothing ships.

| Job | What it checks beyond that |
| --- | --- |
| `check` (ubuntu) | installer smoke tests: `install.sh` under `dash` and under BusyBox against a local release fixture, comparing the published `SHA256SUMS.txt` line and the `--version` of the installed file; `shellcheck -s sh --severity=warning`; mirror-list parity between `install.sh` and `install.ps1` (a host added to one file and forgotten in the other is a source a whole platform cannot reach) |
| `windows` | the same build/test/clippy on `windows-2025`: `cfg(windows)` is dead on the Linux runner, so the Win32 console-mode probe, the keyboard layouts and the Windows adapters compile nowhere else |
| `artifacts` | the `actions/upload-artifact` + `download-artifact` pair — they are bumped together, and a mismatch shows up only on a tag |
| `policy` | pure Rust: `cargo tree --workspace --target all -e normal,build -i <crate>` over the ban list, then `cargo deny`; and `scripts/vendor-advisories.sh`, because a `[patch.crates-io]` path dependency has no `source` in the lock and the advisory check skips it — the vendored crates are asked about by the published names and versions of the sources they carry |

Every job sets `timeout-minutes`: a stalled `cross` pull or a hung installer MUST NOT hold
a runner for the six-hour default.

## `release.yml` — on a `v*` tag (and manually)

1. **`version`** — fails in seconds on what would otherwise fail the whole matrix: the tag
   MUST match both `workspace.package.version` and the `VERSION` constant in each
   installer. An installer one release behind downloads the previous tag — and its own
   check passes, because it compares the download against its own constant.
2. **`build`** — 11 targets: Windows (x86_64, win7), Linux musl (x86_64, arm64, armv7,
   mipsel, mips), macOS (intel, arm64), Android (arm64, armv7). Some rows build through
   `cross` in a container. Three rows build on `nightly-2026-09-17` with `-Z build-std`
   (win7 and both MIPS — the flag is nightly-only; `+toolchain` overrides
   `rust-toolchain.toml`, so the rest of the matrix stays on 1.98.1). That date lives in
   four places — the win7 row's `cargo_args`, both MIPS rows' `cross_args`, and the
   `rustup toolchain install` step — move them together. Every built binary is
   smoke-tested by running it (`--version` and `--legend`); foreign architectures run
   under `qemu-user`.
3. **Packing** — three rows are additionally compressed with UPX pinned to **4.2.4**: the
   5.x unpack stub needs `memfd_create`, i.e. Linux ≥ 3.17. Only router targets are packed
   (armv7, mipsel, mips); desktop builds are not — the gain there does not pay for the
   unpack delay on every start.
4. **`release`** — a draft first, then `gh release edit --draft=false`, so a run
   that fails in between leaves a draft rather than half a release. (`--latest` is
   deliberately not passed: the action sets `prerelease` from the tag — `v5.0.0-alpha.19`
   is one — and GitHub marks the latest *non*-prerelease as latest by itself, so forcing
   the flag would put a pre-release there.) Publishes
   `SHA256SUMS.txt` and counts its assets (11 plain + 3 packed), because
   `fail_on_unmatched_files` catches only a pattern that matches nothing at all.

Third-party actions (`softprops/action-gh-release`, `crazy-max/ghaction-upx`) are pinned
by commit: a tag can be moved, and one of them publishes the release from a job holding
`contents: write`. `actions/*` stay on their major tags — they come from the platform the
workflow runs on.

## Supply chain

- `cargo-deny` **0.20.2**, config `deny.toml`, four checks: `licenses` (the repository
  redistributes four patched forks, so a new licence carrying an obligation we cannot meet
  MUST fail here rather than in a release note), `sources` (crates.io only: a git
  dependency would make the six `cross` builds — arm64, armv7, mipsel, mips,
  android-arm64, android-armv7 — irreproducible), `advisories` (RustSec;
  `yanked = "deny"`, because a withdrawn release is not merely old), `bans`
  (`wildcards = "deny"`, with `allow-wildcard-paths` so the intra-workspace path
  dependencies stay legal; `multiple-versions = "warn"`, because nine crates in the lock
  legitimately ship two majors). Two exceptions are documented in the file itself.
- The pure-Rust rule is **deliberately not expressed** in `deny.toml`: `bans` evaluates the
  resolved lock, where `ring` and `cc` hang as optional `rustls-webpki` edges that no build
  enables. So the ban is asked of `cargo tree`, which is feature- and target-resolved.
- `.github/dependabot.yml` moves GitHub Actions only: weekly, branch `rust`, limit 3 PRs,
  prefix `ci`.

## Nothing needs running by hand

Neither `policy` nor the installer smoke tests are run manually before a push. Four
things actually fail the job: a new dependency, an installer edit, a broken doc link
(`cargo doc` with `-D warnings` is the only thing that reads intra-doc links at all), and
a vendored crate whose *published* version is affected by an advisory
(`scripts/vendor-advisories.sh` — the `cargo deny` step cannot see a path dependency).
