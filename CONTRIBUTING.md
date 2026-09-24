# Contributing

The rules below are not bureaucracy — they are what CI and review actually check.

## What gets accepted

- **Small changes** — a bug fix, a typo, documentation, a narrow improvement: open a pull request directly.
- **Large changes** — a new subsystem, an architectural shift, a new dependency, edits spanning several modules: discuss first (an issue or the [chat](https://t.me/DPI_detector)), then write code. An issue is not a substitute for that discussion, and a discussion does not guarantee the pull request will be merged.

**Do not open an issue for work you are about to submit** — link the existing one from your pull request instead. A new issue makes sense for reporting a problem, or for work you are not going to do yourself.

**One pull request, one logical change.** Incidental cleanup, drive-by refactoring and anything outside the agreed scope belongs in its own change.

## AI agents: a tool, not an author

Using agents is fine. Handing an agent a vague goal and submitting whatever comes out is not.

Before opening a pull request you MUST:

- constrain the agent to the agreed scope and reject everything else;
- read every changed hunk and understand the resulting behaviour;
- run the checks and **verify the changed behaviour yourself**;
- open the pull request after that review, rather than letting an agent publish it on its own.

You are responsible for the code, regardless of who or what generated it.

## What is checked before a pull request

```bash
cargo build  --workspace --locked
cargo test   --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps
```

- **100% of tests pass, 0 clippy warnings** — on Linux *and* Windows. Part of the code lives behind `cfg(windows)` and does not compile on the Linux runner at all, so breakage there is visible only on Windows.
- **A test MUST name the failure mode.** If you cannot say what a consumer observes when it regresses, it is not a test yet. A regression test MUST reproduce the prior failure. Tests that assert on source text, copy a literal into a struct, or merely assert that output is non-empty do not qualify.
- **Verify by hand.** A test run does not prove the behaviour works: for a bug, reproduce it and show the reproduction no longer fires; for a new capability, launch the binary and use it; for an output change, show what you actually saw. State the exact scenario and its result in the pull request description.
- **One honest sentence in your own words** about what changed and why. A generated summary or a pasted agent transcript does not replace it.

## What will not be merged

Six system rules — in full in `AGENTS.md`, in brief here:

1. **No C/C++ in the dependency graph.** Target devices are `mipsel-unknown-linux-musl` routers with no working C cross-compiler, and `ring` has no MIPS target. `openssl`, `aws-lc-rs`, `curl-sys`, `zstd-sys` and the like are rejected.
2. **No unbounded allocations, no temporary files.** The budget is 3–6 MB for the binary and for RSS.
3. **No error classification outside the connection stages.** Every TCP/TLS probe wraps its connection in `DpiProbeStream`: a reset or EOF after ClientHello is `TlsRst`, a connect timeout is `SynDropped`.
4. **No translated badges or protocol tokens.** `OK`, `TLS RST`, `SNI` stay Latin in every language.
5. **No language in machine output.** `--json` does not depend on `--lang`.
6. **No interface strings outside `i18n`.** New text means a `Messages` field filled in all four languages; otherwise it does not compile.

## Documentation

Update documentation in the same commit as the code:

- `README.md` — when CLI flags, the `--json` shape or the detail codes change;
- `AGENTS.md` and `docs/` — when conventions, the build or CI change.

Build, release matrix and CI are described in `docs/CI.md`; adding a fingerprint profile is covered by `docs/ADDING_A_PROFILE.md`.

## Licence

By submitting a change you agree to license it under MIT, the licence of this project. No CLA or DCO signature is required.
