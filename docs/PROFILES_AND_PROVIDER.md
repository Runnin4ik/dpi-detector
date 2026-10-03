# Cargo profiles and the crypto provider: what is measured

Everything here was measured on 2026-10-01 on this project's own tree, router and
toolchain. It exists to answer two questions without re-running the experiments:

* **How should the Cargo profiles be configured?** (desktop wants speed, routers
  want CPU first and memory second)
* **Should the crypto provider be `ring` instead of the pure-Rust
  `rustls-rustcrypto`?** (what it buys, what it costs, and what `ring` does not
  have at all)

Numbers marked *(measured)* are from the runs described in §11. Anything not
measured is marked as such; there is no extrapolated figure presented as data.

> **Decision, 2026-10-01.** The switch was made. The provider is `ring`
> (`crates/dpi-core/src/net/tls.rs::crypto_provider()` is
> `rustls::crypto::ring::default_provider()`), `vendor/rustls-rustcrypto/` and
> `crates/dpi-core/src/net/x25519.rs` are deleted, `AGENTS.md` Rule 1 (pure Rust,
> zero C/C++) is retired, `check.yml`'s `policy` job and its 6 MiB size step are
> gone, and the profiles of §8 are in the root `Cargo.toml` — `release` for the
> desktop rows, `release-router` for the three 32-bit router rows. Everything
> below stands as the record of why.
>
> **Verified after the switch (2026-10-01, this tree):** `cargo build --workspace`,
> `cargo test --workspace --locked` (280 + 88 tests, 0 failed) and
> `cargo clippy --workspace --all-targets --locked -- -D warnings` are clean;
> `cross +nightly-2026-09-17 build --profile release-router --target
> mipsel-unknown-linux-musl` produces a **5 140 576 B** binary — the same number
> §5 recorded for `ring` with its C at `-O3` — and the desktop artifacts are
> 6 955 520 B under `release` (matching §6) and 6 157 312 B under
> `release-local`. A live `--tests 2` run of the `release-router` binary
> classified 35 domains with `tls12`/`tls13` `ok` on all but one (`youtube`'s
> TLS 1.2 timed out — network noise, not the provider), so the handshake path
> works end to end.

---

## 1. Versions this document describes

| Component | Version | Where |
| --- | --- | --- |
| `rustls` | 0.23.45, vendored | `vendor/rustls` (patch: ClientHello-profile hook), applied via `[patch.crates-io]` |
| Provider (now) | `ring` 0.17.14 | enabled by `rustls`'s `ring` feature; `crypto_provider()` returns `rustls::crypto::ring::default_provider()` |
| Provider (until 2026-10-01) | `rustls-rustcrypto` 0.0.2-alpha, vendored, **workspace member** | `vendor/rustls-rustcrypto` — patch: removes its `rustls-webpki 0.102` dependency (OID constants come from `rustls-pki-types`), 2 lint edits; 131 lines, 6 files. **Deleted** with the switch |
| `rustls-webpki` | 0.103.15 | in the lock as a `rustls` dependency in both configurations: it builds the certificate path, while the signature algorithms come from the provider — `webpki::ring` under the `ring` feature, the provider's own `verify/*` under `rustls-rustcrypto` |
| `webpki-roots` | 1.0 | trust anchors; independent of the provider |
| `ring` | 0.17.14 | the provider: a normal dependency of `dpi-core` since the switch |
| `cc` | 1.4.4 in this lock (1.5.1 resolved elsewhere) | `ring`'s build-dependency — enters the graph with `ring` |
| Toolchain | 1.99.0 (pinned) | `rust-toolchain.toml`; MIPS rows additionally use `nightly-2026-09-17` (`-Z build-std`) |
| `cross` | 0.2.5 | MIPS/ARM release rows |
| Cross GCC | `mipsel-linux-muslsf-gcc (GCC) 9.2.0` | inside `ghcr.io/cross-rs/mipsel-unknown-linux-musl:0.2.5` |
| Router under test | Keenetic, MediaTek MT7621, mipsel, 4 cores, Linux 4.9 | binaries run from `/tmp`, measured with busybox `/opt/bin/time -v` |

Direct crypto dependencies of `dpi-core` (workspace dependencies): `ml-kem 0.3`,
`x25519-dalek 2`, `p256 0.13`, `sha2 0.10`, `aes-gcm 0.10`,
`chacha20poly1305 0.10`, `hkdf 0.12`, `rand 0.8`.

---

## 2. What `ring` 0.17.14 has, and what it does not

Verified by reading the crate source, not the documentation:

**Has:** `agreement::{X25519, ECDH_P256, ECDH_P384}`; `aead::{AES_128_GCM,
AES_256_GCM, CHACHA20_POLY1305}`; `hkdf` (SHA-1/256/384/512); `hmac`;
`digest` (SHA-1, SHA-256/384/512, SHA-512/256); `signature` (ECDSA P-256/P-384,
Ed25519, RSA PKCS#1 and PSS with SHA-256/384/512); `rsa`; `pbkdf2`; `rand`;
`aead::quic` (QUIC header protection key builder); an `Hpke`-shaped RFC 9180
module of its own.

**Does not have** (this is the part that decides the question):

| Missing | Consequence for this tree |
| --- | --- |
| **No `kem` module at all** — no ML-KEM, in 0.17.14 or in `main` | `net/pq_kx.rs` (`X25519MLKEM768`) stays, and so does the `ml-kem` dependency. `rustls` offers `X25519MLKEM768` only through `crypto/aws_lc_rs/pq/`; the ring provider's `ALL_KX_GROUPS` is `[X25519, SECP256R1, SECP384R1]` |
| No `Hpke` implementation in `rustls`'s ring provider | `net/hpke.rs` (RFC 9180, for ECH grease) stays; the only `impl Hpke` in the vendored rustls is `crypto/aws_lc_rs/hpke.rs` |
| No raw AES block/ECB API (only `pub(super)` internals) | `net/quic.rs` keeps the `aes` crate for the RFC 9001 header protection |
| No P-521 (group or verifier) | unchanged: P-521 is already listed as unimplemented in `net/fingerprint/tests.rs` |
| No MD5 | irrelevant: JA3's digest is computed outside the probe path |
| No AES-CCM, no X448/Ed448 | unused here |

**Licences:** `ring` is `Apache-2.0 AND ISC` (its C and assembly are
BoringSSL-derived, per-file notices); `cc` is MIT/Apache-2.0. `deny.toml`'s
`licenses` and `sources` need no change — both crates are already in the lock and
already pass `cargo deny`.

**Does `ring` build for the router targets?** Yes, and it is now measured rather
than inferred:

* `ring/build.rs:330–337` looks the target up in `ASM_TARGETS`, which lists only
  linux aarch64/arm/x86/x86_64 (plus Apple/Windows) — for `mipsel`/`mips` there is
  no entry, so no perlasm assembly is generated and the generic-C sources are used.
* `include/ring-core/target.h:50` explicitly names `__MIPSEL__`/`__MIPSEB__` →
  `OPENSSL_32_BIT`, i.e. the C side expects MIPS.
* Measured: a `mipsel-unknown-linux-musl` build with `cross` (see §11) links and
  runs on the MT7621 — tests 0, 1 and 2 complete with the same `--json` counters
  as the pure-Rust build.
* Independent corroboration: `valnesfjord/tg-ws-proxy-rs` v2.5.0 pins
  `rustls = { features = ["ring", …] }` and publishes `mips`/`mipsel` musl
  archives.

**Upstream status (as of 2026-10-01):** latest release 0.17.14 (2025-03-11);
README self-describes as "An experiment" and warns about C toolchains and targets
"not supported by other projects, especially BoringSSL"; the only third-party
audit (Cure53 TLS-01, 2020) covered the 0.16-era code; RUSTSEC-2025-0010
(unmaintained) applies to `<0.17`, RUSTSEC-2025-0009 (AES/QUIC panic) is fixed in
`>=0.17.12`.

### What a switch changes in the tree (applied 2026-10-01)

| Item | Effect |
| --- | --- |
| `crates/dpi-core/Cargo.toml`, root `Cargo.toml` | `rustls` feature `ring`; drop the `rustls-rustcrypto` dependency and its workspace membership; `rustls-webpki` returns to upstream under `webpki/ring` |
| `net/tls.rs::crypto_provider()` | `rustls::crypto::ring::default_provider()`, the X25519 substitution disappears |
| `net/x25519.rs` | **deleted** — `ring` rejects a low-order X25519 peer key itself (`src/ec/curve25519/x25519.rs:158–160`), and the module's own doc already says so |
| `net/pq_kx.rs`, `net/hpke.rs`, `net/quic.rs`, `net/follow_up.rs`, `net/ja4.rs` | unchanged — `ring` has no ML-KEM, no `Hpke`, no AES-ECB; `p256`/`sha2`/`aes`/`aes-gcm`/`chacha20poly1305`/`hkdf`/`x25519-dalek`/`ml-kem` therefore stay in the graph |
| Rule 1 (`AGENTS.md`), `check.yml:639` ban list, `deny.toml:19–26`, `docs/CI.md:86–88`, `CONTRIBUTING.md:45` | all must be rewritten: they currently state that no C toolchain may enter the build |
| `check.yml:623–632` comment | rewritten |
| CI/release | `cc` becomes a real (non-optional) dependency; every release row needs a C compiler (the `cross` images, MSVC and Xcode already have one) |

So the honest summary: a switch removes one vendored fork (`rustls-rustcrypto`
and its `verify/*`) and one 192-line module (`net/x25519.rs`), and it **does not**
make the tree pure Rust — `ml-kem`, `p256`, `x25519-dalek`, `aes-gcm`,
`chacha20poly1305`, `hkdf`, `sha2` and `aes` remain for PQ, HPKE, QUIC,
`channel_id` and JA4.

Measured with `cargo tree -p dpi-core -e normal,build`: **176 unique crates today
against 162 with `ring`**.

* **Gone (18):** `rustls-rustcrypto` itself, plus the RSA/Ed25519/P-384
  verification stack only it pulled — `rsa`, `num-bigint-dig`, `num-integer`,
  `num-iter`, `ed25519-dalek`, `ed25519`, `p384`, `pkcs1`, `pkcs5`, `pkcs8`,
  `pem-rfc7468`, `spki`, `base64ct`, `lazy_static`, `libm`, `paste`, `spin`.
* **New (4):** `ring` at runtime, and `cc` with `shlex` / `find-msvc-tools` at
  build time.
* **Everything our own code uses stays:** `ml-kem`, `p256`, `x25519-dalek`,
  `curve25519-dalek`, `aes-gcm`, `chacha20poly1305`, `hkdf`, `sha2`, `aes`, `rand`
  and their dependencies (`elliptic-curve`, `ecdsa`, `sec1`, `der`, `digest`,
  `hmac`, `ghash`, `polyval`, `universal-hash`, `crypto-bigint`, `primeorder`,
  `signature`, `rfc6979`, `subtle`, `zeroize`, `typenum`) — because
  `pq_kx`/`hpke`/`quic`/`follow_up`/`ja4` keep using them, and `ring` has no
  ML-KEM, no `Hpke` and no raw AES block API to replace them with.

In one line: `ring` removes the RustCrypto **provider** and the crates only it
needed, not RustCrypto **crates** from the tree — so the binary still carries two
crypto stacks, and it gains a C toolchain.

One wire-visible side effect, measured: the provider's cipher-suite *order*
differs (ring lists TLS 1.3 first and AES-256 before AES-128; `rustls-rustcrypto`
lists TLS 1.2 first and AES-128 before AES-256), so the **base-form** ClientHello
(`TLS_FINGERPRINT=rustls`, used by the DoH/DoT truth probes and by the TLS columns
of tests 2–5 by default) changes, and a measured handshake negotiated
`TLS13_AES_256_GCM_SHA384` under ring against `TLS13_AES_128_GCM_SHA256` under
`rustls-rustcrypto`. The browser-shaped profiles are unaffected: their ClientHello
comes from the static `net/fingerprint/shapes` table, so their JA3/JA4 pins do not
move, and the two provider-vs-shape gates in `net/fingerprint/tests.rs` compare
code points that both providers serve identically (same nine suites, same three
groups, same nine signature schemes).

---

## 3. The `cc`/`OPT_LEVEL` mechanism: the one profile knob that matters with `ring`

`ring`'s build script sets no optimisation flags of its own (no `opt_level`, no
`-O` in `ring-0.17.14/build.rs`). The `cc` crate takes the level from Cargo's
`OPT_LEVEL` environment variable (`cc-1.5.1/src/lib.rs:4292`) and maps it
(`cc-1.5.1/src/lib.rs:2346–2367`):

| `opt-level` | MSVC (`cl`) | GNU/Clang (gcc, cross, Xcode) |
| --- | --- | --- |
| `"z"`, `"s"`, `"1"` | `/O1` | `-Os` (gcc) / `-Oz` (clang) |
| `"2"`, `"3"` | `/O2` | `-O2` / `-O3` |

Consequence: under the profile shipped today (`opt-level = "z"`), **`ring`'s C
code is compiled for size**, which is the opposite of what a router wants.
`[profile.<name>.package.ring] opt-level = 3` is a one-line change to gcc's `-O3`
and is measured to be worth **−9 % CPU** on the router's heaviest test (§5).
Note that with a whole-profile `opt-level = 3` no override is needed at all — the
profile's level is what reaches `cc`.

---

## 4. Measurements: profiles with the pure-Rust provider (no `ring`)

Bench: 200 TLS 1.3 handshakes, client and server in one process over an in-memory
duplex, against the repo's fixture chain (ECDSA P-256 leaf, `net/testdata`), in a
throwaway crate that depends on the *vendored* `rustls` — identical code in every
arm, only the provider and the profile change (§11).

| Profile | Handshake | Scratch binary | App binary (x86_64-msvc) | Build (scratch / app) |
| --- | --- | --- | --- | --- |
| **shipped today:** `z` + fat LTO + cgu 1 | 7.319 ms | 1 047 552 B | 4 225 024 B | — / 138 s |
| crypto crates `opt-level 2` + fat + cgu 1 | 0.968 ms | 1 191 424 B | 4 393 984 B | — / 94 s |
| crypto crates `opt-level 3` + fat + cgu 1 | 0.976 ms | 1 220 096 B | 4 419 072 B | — / 99 s |
| all dependencies `opt-level 3` + fat + cgu 1 | 0.937 ms | 1 377 280 B | 4 849 664 B | — / 199 s |
| `opt-level 3` + **thin** LTO + cgu 16 | **0.885 ms** | 1 716 736 B | 7 023 104 B | 30 s / 108 s |
| `opt-level 2` + thin LTO + cgu 16 | 0.937 ms | 1 731 584 B | 7 066 112 B | 25 s / 96 s |
| `opt-level 3`, no LTO, cgu 16 | 1.162 ms | 1 674 240 B | — | 33 s |
| crypto `opt-level 2` + **thin** + cgu 16 | 0.992 ms | 1 298 944 B | — | — |
| crypto `opt-level 3` + **thin** + cgu 16 | 0.975 ms | 1 324 032 B | — | — |

Readings:

* **The whole desktop win is the `z → 2/3` step** (×8.3 measured): 7.319 ms →
  0.885 ms. Going from `opt-level 2` to `3` changes nothing measurable
  (0.968 vs 0.976 ms).
* **`thin` LTO + `codegen-units = 16` is the fastest shape on desktop**
  (0.885 ms) and also the cheapest to build (§7). Thin LTO applied *only* to the
  crypto crates while everything else stays `-Oz` is worse on both axes
  (0.992/0.975 ms, +107 KB) — so either go all the way or keep `-Oz` + fat.
* **Without LTO the handshake costs 31 % more** (1.162 ms vs 0.885 ms): thin LTO
  is worth its link time.
* **`codegen-units = 1` is not automatically faster**: fat LTO + cgu 1 (0.937 ms
  with all dependencies at O3) is slower than thin LTO + cgu 16 (0.885 ms).

### Router, pure Rust (MT7621; CPU = user+sys, mean of interleaved passes)

| Arm | `--tests 1` CPU | `--tests 2` CPU | RSS (`tests 1`) | mipsel artifact |
| --- | --- | --- | --- | --- |
| shipped: `z` + fat + cgu 1 | 33.7–35.1 s | 6.69–6.94 s | 6.79–7.09 MB | 5 181 324 B |
| crypto `opt-level 2` + fat + cgu 1 | **30.3 s (−14 %)** | 6.31 s (−9 %) | 7.25–7.31 MB | 5 517 224 B |
| crypto `opt-level 3` + fat + cgu 1 | 29.9 s (−14 %) | 5.94 s (−11 %) | 7.42–7.44 MB | 5 549 996 B |
| all dependencies `opt-level 3` + fat | 29.3 s (−14 %) | 6.01 s (−14 %) | 7.91–8.03 MB | 6 205 300 B |
| whole profile `opt-level 2` + fat | 28.3 s (−16 %) | — | 8.64–8.68 MB | 6 942 628 B |
| crypto `opt-level 2` + **thin** + cgu 16 | 32.0 s (−8 %) | — | 8.71–8.80 MB | 7 394 016 B |

Readings (each percentage is against the base measured in the *same* interleaved
session — the base itself ranged 33.7–35.1 s across sessions, so percentages that
differ by a couple of points are the same result):

* **The pure-Rust ceiling on the crypto-heavy test is about −14 %.** No
  combination of `opt-level` and LTO goes further, because the limit is the
  implementations, not the codegen.
* **`opt-level 3` buys nothing over `opt-level 2`** for the crypto crates
  (29.9 vs 30.3 s), and costs RSS and flash.
* **The desktop winner is the router loser**: thin LTO + cgu 16 gives −8 %
  instead of −14 %, +1.8 MB RSS and +1.9 MB artifact.
* **Optimising our own crates too** (whole profile at `opt-level 2`) adds only
  −5 % CPU while costing +1.3 MB RSS and +1.4 MB artifact.
* RSS grows with every override: 6.8–7.1 MB shipped → 7.25 → 7.9 → 8.6 MB.

---

## 5. Measurements: with `ring`

Bench as in §4 (same code, same vendored rustls, only the provider differs):

| Profile | Handshake | Scratch binary | App binary (x86_64-msvc) | Build (app) |
| --- | --- | --- | --- | --- |
| `z` + fat + cgu 1 | 0.457 ms | 1 154 560 B | 4 400 640 B | 104 s |
| `z` + fat + cgu 1 + `package.ring = 3` | 0.427 ms | 1 190 400 B | — | — |
| `opt-level 3` + thin + cgu 16 | **0.399 ms** | 1 570 304 B | 6 955 520 B | 66 s |

Router (same methodology as §4; the two ring arms differ only in the C compiler's
`-O` flag):

| Arm | `--tests 1` CPU | `--tests 2` CPU | RSS (`tests 1`) | mipsel artifact |
| --- | --- | --- | --- | --- |
| ring, C at `-Os` (profile `-Oz`) | 19.8 s | 6.13 s | 6.67–6.73 MB | 4 935 756 B |
| ring, C at `-O3` (`package.ring = 3`) | **18.0 s (−9 %)** | 6.35 s (noise) | 6.77 MB | 5 140 576 B |

### The comparison that decides it

| | `--tests 1` CPU | RSS | mipsel artifact |
| --- | --- | --- | --- |
| best pure-Rust profile (crypto `opt-level 2`) | 30.3 s | 7.25–7.31 MB | 5 517 224 B |
| shipped pure-Rust profile | 33.7–35.1 s | 6.79–7.09 MB | 5 181 324 B |
| **`ring`, C at `-O3`** | **18.0 s** | 6.77 MB | 5 140 576 B |

`ring` is better on all three axes at once — CPU (1.7× the best pure-Rust
profile), memory (lowest RSS of any arm) and flash (only the `-O3` variant is
slightly larger than the shipped pure-Rust build, and it is still smaller than
every tuned pure-Rust arm). It is also smaller and faster to build than the
pure-Rust stack on desktop (6 955 520 B / 66 s against 7 023 104 B / 108 s).

What it costs is not performance but policy and risk: Rule 1 has to be redefined
(a C toolchain becomes part of every release row), the vendored provider and
`net/x25519.rs` go, PQ and HPKE stay ours anyway, and the upstream project is
dormant, self-labelled experimental, and has no audit for the 0.17 code.

### When to switch, and when not

* **Switch to `ring` if** router CPU on the crypto-heavy test is the pain: it is
  the only configuration measured that reaches 18 s on `--tests 1`, and it does so
  while *lowering* RSS and flash. The `--tests 2` gain is small (−13 %), so that
  test alone is not a reason.
* **Stay on the pure-Rust provider if** the −14 % of the crypto-crate override is
  enough: it costs one profile table and no policy change, no C toolchain and no
  new upstream dependency.
* **Do not switch expecting any of these:** hybrid PQ from the provider
  (`rustls` offers `X25519MLKEM768` only through `aws-lc-rs`, and `ring` has no
  ML-KEM at all), an `Hpke` implementation, an end to the second crypto stack, or
  a smaller dependency review surface — the `ml-kem`/`p256`/`x25519-dalek`/`aes-gcm`
  crates stay, and `cc` plus `ring`'s BoringSSL-derived C arrive.
* **If a switch happens**, take the profile changes with it in the same commit:
  `package.ring = 3` on the router rows is worth −9 % CPU there and is otherwise
  silently lost to `-Oz`.

---

## 6. The third provider: `aws-lc-rs`

**Upstream.** `aws-lc-rs` 1.18.1 with `aws-lc-sys` 0.45.0 (plus a separate
`aws-lc-fips-sys`). It is rustls's *default* provider — `vendor/rustls/Cargo.toml`
`default = ["aws_lc_rs", "logging", "prefer-post-quantum", "std", "tls12"]`, and
the `aws_lc_rs` feature pulls `dep:aws-lc-rs`, `webpki/aws-lc-rs`,
`aws-lc-rs/aws-lc-sys` and `aws-lc-rs/prebuilt-nasm`. MIPS as an architecture is
supported since v1.15.3 (PR #986, 2026-01-14, which closed issue #522), and since
that release **CMake is not required for any target** — a C compiler is enough.
Upstream's Platform Support lists `mips-unknown-linux-{gnu,musl}` and the mips64
variants but **not `mipsel-unknown-linux-musl`**, our router triplet, and their
CI matrix does not build it either. Licences (ISC/Apache-2.0/MIT/BSD-3-Clause) are
already allowed by `deny.toml`; `aws-lc-sys` has five RustSec advisories, all
fixed before 0.45.0.

**What it gives that `ring` does not.** `kx_group::{MLKEM768, MLKEM1024,
SECP256R1MLKEM768, X25519MLKEM768}`, ML-DSA verification (`ML_DSA_44/65/87`),
P-521 verification, and the only `impl Hpke` in the tree
(`crypto/aws_lc_rs/hpke.rs`). It is the one provider under which `net/pq_kx.rs`
and `net/hpke.rs` could be deleted — and with them `ml-kem`, `x25519-dalek` and
`chacha20poly1305` — instead of being kept as they must be under `ring`.

**Measured, desktop bench (shipped profile, x86_64-msvc):**

| Arm | Handshake | Scratch binary |
| --- | --- | --- |
| `aws-lc-rs`, C at `/O1` (profile `-Oz`) | 1.922 ms | 1 603 584 B |
| `aws-lc-rs`, C at `/O2` (`package.aws-lc-sys = 3`) | 0.917 ms | 2 163 200 B |
| same, plus `prefer-post-quantum` (`X25519MLKEM768` first) | 1.140 ms | 2 163 200 B |

So the C flag is worth 2.1× here, and a post-quantum handshake costs +24 % over a
classical one. Assembly *was* used (40 NASM objects from `prebuilt-nasm`), and
with it `aws-lc-rs` is still about twice as slow as `ring` on this bench
(0.917 ms against 0.457 ms).

**Measured, router (MT7621):**

| Arm | `--tests 1` CPU | `--tests 2` CPU | RSS (`tests 1`) | mipsel artifact |
| --- | --- | --- | --- | --- |
| base (`rustls-rustcrypto`) | 32.6 s | 6.89 s | 6.84–6.87 MB | 5 181 324 B |
| `ring`, C at `-Os` | 19.8 s | **6.13 s** | 6.67–6.73 MB | 4 935 756 B |
| `ring`, C at `-O3` | 18.0 s | 6.35 s | 6.77 MB | 5 140 576 B |
| `aws-lc-rs`, C at `-Os` | **16.2 s (−50 %)** | 8.00 s (+16 %) | 7.30–7.35 MB | 5 435 380 B |
| `aws-lc-rs`, C at `-O3` | 22.7 s (+40 % against its own `-Os`) | 7.01 s | 7.66–7.80 MB | 5 861 368 B |

It builds for `mipsel-unknown-linux-musl` with `cross` and runs on the router
(tests 0/1/2).

Two things to read out of that table:

* **`aws-lc-rs` is the fastest provider on the crypto-heavy test** (16.2 s against
  `ring`'s 18.0 s and the base's 32.6 s) and the slowest on the mixed one, where
  it is worse than the *base*. The `--tests 2` figures for this arm are not
  like-for-like, though: the wire changed (see below) and 19 of 105 endpoints
  took different paths, so part of that difference is the instrument, not the
  CPU.
* **Raising the C compiler's optimisation level is not a universal win.** For
  `ring` on MIPS it bought −9 % on `--tests 1`; for `aws-lc-rs` on MIPS the same
  knob costs **+40 %** there (and −12 % on `--tests 2`), while on the Windows
  bench the equivalent change was worth 2.1×. Both directions were measured on
  the same router with interleaved passes, so the knob has to be measured per
  provider per target — it cannot be inherited from another platform.

**It also changes the probe's own wire signature.** Dumping the first flight of
each provider (same code, same vendored rustls):

| | `rustls-rustcrypto` | `ring` | `aws-lc-rs` |
| --- | --- | --- | --- |
| cipher suites | TLS 1.2 first, AES-128 first | TLS 1.3 first, AES-256 first | as `ring` |
| signature_algorithms | 9 (no P-521) | the same 9, different order | **12: adds `ecdsa_secp521r1_sha512` and `ml_dsa_44/65/87`** |
| supported_groups | x25519, secp256r1, secp384r1 | the same | **adds `x25519mlkem768`** |
| ClientHello | 236 B | 236 B | 246 B |

For a censorship detector this matters more than the CPU figures: the base-form
hello *is* part of the instrument. On the test network the `aws-lc-rs` arm moved
19 of 105 endpoint verdicts (8 `tls_rst` in the TLS 1.3 column, 11 `http`
`read_timeout`) where the `ring` arm moved none — i.e. the middlebox reacts to the
advertised PQ group and/or the ML-DSA schemes. Any provider switch has to be
treated as a change of the probe's fingerprint, which is the same concern
`net/tls.rs` records when it refuses to add the hybrid group to the shared
provider.

That change is fixable in our own code, and the fix is the shape `net/tls.rs`
already uses: `CryptoProvider`'s fields are public, so a wrapper can keep
`aws-lc-rs` for the algorithms while presenting a classical hello — drop
`X25519MLKEM768` from `kx_groups` and trim
`signature_verification_algorithms` (`.all` and `.mapping`) to the nine classical
schemes. The provider is the implementation; the hello is policy, and the crate
already composes providers per profile for exactly this reason. Any measurement
of a new provider must say which hello it was taken with.

## 7. Build time

Measured on the same 12-core machine, x86_64-msvc, after a profile switch (so all
dependencies are rebuilt) and then for a one-file edit (recompile + relink):

| Profile | Full build | edit → build |
| --- | --- | --- |
| `opt-level 3` + thin LTO + cgu 16 | 66 s | **37 s** |
| `z` + fat LTO + cgu 1 + `package.ring = 3` | 95 s | **57 s** |

Cause: `lto = true` (fat) is a **single whole-program pass at link time** — with
`codegen-units = 1` there is one LLVM module and nothing to parallelise.
`lto = "thin"` parallelises that pass, and `codegen-units = 16` additionally lets
rustc generate code for each crate in parallel. `opt-level` itself barely affects
build time: the `O3 + thin` build, which recompiled all ~250 dependencies at
`O3`, finished faster than the `-Oz + fat` build.

The repository already records this: the `[profile.release-local]` comment in the
root `Cargo.toml` ("the whole-program LTO pass, which alone costs ~1.5 min of
every edit→build cycle here") and `AGENTS.md` (`--release` ≈ 55 s per artifact).

Practical consequence: the desktop profile is the *fastest* to build, and the
router profile (`-Oz` + fat + cgu 1) is the slowest — that is the price of the
smallest code and lowest RSS, paid once per release, not per edit.

---

## 8. Recommended profiles (applied)

Profiles cannot be conditional on the target, so the split is by profile name and
the release matrix picks one per row (`--profile release-router` for
`armv7`/`mipsel`/`mips`, `--release` for everything else). `package` overrides
inside a custom profile are accepted by Cargo — verified with
`cargo check --profile release-router`.

```toml
# Desktop and every non-router row: speed first.
[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 16
panic = "abort"
strip = true

# Routers (armv7 / mipsel / mips): CPU first, then RSS. Our own crates and
# rustls stay small; fat LTO keeps the code smallest.
[profile.release-router]
inherits = "release"
opt-level = "z"
lto = true
codegen-units = 1

# --- without ring: give the pure-Rust crypto crates codegen effort the release
# profile denies them. This is the measured −14 % on `--tests 1`.
[profile.release-router.package.p256]
opt-level = 2
# … and the same for: p384, elliptic-curve, primeorder, ecdsa, sec1,
# curve25519-dalek, ed25519-dalek, rsa, num-bigint-dig, aes-gcm, aes,
# chacha20poly1305, chacha20, poly1305, ghash, polyval, universal-hash, sha2,
# digest, hmac, crypto-bigint, rustls-rustcrypto

# --- with ring: no crypto list is needed (the provider's Rust crates are gone),
# but the C compiler's -O flag is, because Cargo's OPT_LEVEL is what reaches cc.
[profile.release-router.package.ring]
opt-level = 3
```

Do **not**:

* put `lto = "thin"` / `codegen-units = 16` on the router rows — measured worse
  there on every axis (−8 % CPU instead of −14 %, +1.8 MB RSS, +1.9 MB artifact);
* keep the long crypto list when the provider is `ring` — those crates are off the
  DoH/DoT handshake path (they serve `pq_kx`/`hpke`/`quic`/`follow_up`/`ja4`);
* set `-Oz` for `package.ring` — that is `-Os`/`/O1` for its C code.

Note on the CI size step: `check.yml` used to compare the linux x86_64
`--release` binary against 6 MiB. The measured desktop artifact grows to ~7.0 MB
under `opt-level 3` + thin LTO (4.2 MB under the old `-Oz` + fat LTO), so that
step — a tripwire derived from the retired budget — was removed in the same
change as the profile; `docs/OPTIMIZATIONS.md` keeps the measurement.

---

## 9. Open questions (not measured)

* A shorter crypto override list — only the crates on the handshake path
  (`rustls-rustcrypto`, `p256`, `curve25519-dalek`, `aes-gcm`, `sha2`, `hmac`,
  `digest`, `ghash`, `polyval`) — might hold the CPU win with less RSS growth.
* `ring`'s C at `-O2` versus `-O3` (only `-Os` versus `-O3` was measured).
* `release-router` at `opt-level 2` with `ring` (the C side would drop to `-O2`).
* The CPU share of `pq_kx`/`hpke` under `ring` (they are off the DoH/DoT path but
  are used by the PQ and ECH fingerprint shapes).
* ARMv7 router rows: every router figure here is MT7621-specific (no FPU, no AES
  acceleration). `ring` does ship ARM assembly, so the balance there will differ.

---

## 10. Side finding fixed on the same day

`vendor/rustls-rustcrypto/src/kx.rs` carried an `was_contributory()` low-order
X25519 check that `PATCH.diff` did not contain and that `README-PATCH.md` and
`net/x25519.rs` explicitly said was *not* there. It was reverted to pristine:

* `diff -rq` against the pristine 0.0.2-alpha source now reports exactly the six
  files `README-PATCH.md` declares;
* `patch -p1 -i PATCH.diff` applied to pristine reproduces the vendored tree
  byte-for-byte;
* `cargo test -p rustls-rustcrypto` passes, and so do the three low-order guards
  (`net::x25519::tests::a_low_order_peer_key_is_rejected`,
  `net::pq_kx::tests::rejects_a_low_order_x25519_share`,
  `net::tls::tests::provider_x25519_group_rejects_a_low_order_peer_key`), which
  live where the documentation says they do — in `net/x25519.rs`, reached through
  the composed provider in `net/tls.rs`.

---

## 11. Methodology (how to reproduce or extend any number here)

**Handshake bench (desktop numbers).** A throwaway crate outside the workspace
depending on the *vendored* `rustls` through `[patch.crates-io]`, with two
features selecting the provider (`p_rustcrypto` → `rustls_rustcrypto::provider()`,
`p_ring` → `rustls::crypto::ring::default_provider()`). It builds a client and a
server config from the repository's fixtures (`crates/dpi-core/src/net/testdata/
{ca,ecdsa,ecdsa.key}.der`) and completes a TLS 1.3 handshake in memory
(`complete_io` in a loop, `negotiated_cipher_suite().is_some()` as the completion
signal), 200 times, timed with `Instant`. Provider identity is checked per build
with `cargo tree -i ring` and `cargo tree -i rustls-rustcrypto` (each must be
absent from the other arm). Build:

```
RUSTFLAGS='-C target-feature=+crt-static' \
  cargo build --release --features <p_ring|p_rustcrypto> \
  --target x86_64-pc-windows-msvc
```

**Application builds.** `cargo build --release --target
x86_64-pc-windows-msvc -p dpi-detector` with the same `RUSTFLAGS`, mirroring the
recipe the repository's own artifact measurement used. For MIPS:

```
docker run --rm -v "$PWD/target/static-unwind-mipsel-unknown-linux-musl:/out" \
  ghcr.io/cross-rs/mipsel-unknown-linux-musl:0.2.5 \
  sh -c 'for cc in /usr/local/bin/*muslsf-gcc; do cp "$(dirname "$($cc -print-libgcc-file-name)")/libgcc_eh.a" /out/libunwind.a; done'
RUSTFLAGS='-C target-feature=+crt-static -C link-self-contained=no \
  -L /target/static-unwind-mipsel-unknown-linux-musl' \
  cross +nightly-2026-09-17 build --release \
  --target mipsel-unknown-linux-musl -p dpi-detector
```

**Router runs.** The artifact is copied to `/tmp` (never over `/opt/bin`) and run
under busybox `/opt/bin/time -v`, which reports `User time`, `System time`,
`Elapsed` and `Maximum resident set size` — the same tool the repository's own
router measurements use. Arms alternate A/B/A/B so that network drift cannot be
attributed to one arm. `--tests 1` (about 120 DoH/DoT endpoints) is the
crypto-heavy workload and the discriminating one; `--tests 2` (35 hosts × TLS 1.2
+ 1.3) is dominated by other work. **CPU time is the metric**; wall clock is
network-bound (the same binary varied 14–36 s across passes). Verdicts are
compared between arms through the `--json` counters: on `--tests 1` the counters
(`doh_ok`/`dot_ok`/`udp_ok` and the failure statuses) came out identical for the
pure-Rust and ring arms, and on `--tests 2` the two arms differed in at most one
host, in both directions — i.e. network flips, not provider effects.

**Noise.** Within an arm, repeated passes vary by about ±2 %. Differences smaller
than that are reported here as equal, which is why "29.9 s vs 30.3 s" and
"6.13 s vs 6.35 s" are called ties.
