# Binary Size Optimization

This document records the architectural decisions and compilation profiles applied to minimize the size of the `dpi-detector` executable on desktop and embedded platforms (Windows, Linux x86_64, ARM, MIPS / OpenWrt / Keenetic).

---

## 1. Summary Results (Windows x86_64)

| Metric | Before optimization | After optimization | Difference |
|---|---|---|---|
| **Total `.exe` file size** | **4 662 784 bytes (4.45 MB)** | **3 333 632 bytes (3.17 MB)** | **-1 329 152 bytes (-28.5%)** |
| **Code section `.text`** | 2 772 480 bytes | 2 248 192 bytes | **-524 288 bytes (-18.9%)** |
| **Data section `.rdata`** | 861 184 bytes | 798 208 bytes | **-62 976 bytes (-7.3%)** |
| **Resource section `.rsrc` (icon)** | 944 128 bytes | 198 144 bytes | **-745 984 bytes (-79.0%)** |

---

## 2. Applied Measures

### 2.1. Windows Resource Optimization (`crates/dpi-detector/assets/icon.ico`)
* **Problem:** The `.ico` file contained an uncompressed 256x256 BMP (270 KB) and a 512x512 frame (531 KB) that is not used by the Windows Shell. The icon occupied 920 KB (20% of the entire binary).
* **Solution:** The file was rebuilt with the standard matrix of crisp resolutions: `16x16, 24x24, 32x32, 48x48, 64x64, 128x128, 256x256` with PNG compression.
* **Result:** The `.ico` size was reduced from 920 KB to 191 KB; the savings in the `.rsrc` section amounted to **~746 KB**.

### 2.2. Compiler Profile: `opt-level = "z"`
* **File:** `Cargo.toml`
* **Setting:**
  ```toml
  [profile.release]
  opt-level = "z"
  lto = true
  codegen-units = 1
  panic = "abort"
  strip = true
  ```
* **Mechanics:** The `"z"` mode makes LLVM aggressively cut code bloat (loop unrolling, vectorization, excessive function inlining), targeting the minimum instruction weight.
* **Result:** Compression of the machine code section `.text` by **~500 KB**.
* **Rejected:** `opt-level = "s"` — the previous variant, superseded by `"z"`. In `docs/REFACTORING.md` it is still named as the active one; `"z"` is what gets built, do not revert.
* **Re-checked on the target, and it stands.** All three settings were built for
  `mipsel-unknown-linux-musl` and run on the router (MT7621, four hardware
  threads), two passes each, interleaved, resident memory sampled from
  `/proc/<pid>/status` and processor time from `/proc/<pid>/stat`:

| `opt-level` | file | peak RSS: test 0 / 2 / 1 | processor time: test 0 / 1 |
| --- | --- | --- | --- |
| `"z"` (ships) | 5.37 MB | 7120 / 8344 / 8244 kB | 2.7–3.8 s / 36.0 s |
| `"s"` | 5.81 MB | 7384 / 8816 / 8876 kB | 2.4–3.0 s / 31.2 s |
| `3` | 7.64 MB | 8672 / 10020 / 10208 kB | 1.7–2.7 s / 27.6 s |

* The two axes point opposite ways, and the exchange is close to one for one.
  Peak-RSS deltas against file deltas: `"z"` → `"s"` is +264/+472/+632 kB for
  +0.44 MB of file (mean 1.04), `"s"` → `3` is +1288/+1204/+1332 kB for +1.83 MB
  (mean 0.70) — so 0.6–1.4 MB of resident memory per MB of code, test by test.
  §2.6's flag lands in the same band (0.35 MB of file, ~0.34 MB of steady RSS).
  The tool is a diagnostic on a router that is routing at the same time, and the
  constraint recorded in §3.2 is memory, so `"z"` is the right end of that trade.
  Re-open this only if the router-side goal changes from memory to time.
* The RSS tracks the file because the ELF is demand-paged (§3.1): what becomes
  resident is the pages the run touches, and a larger file leaves more of them
  touched. That is also why the file-size knobs below are memory knobs.
* **Re-checked 

### 2.3. Eliminating Duplicate Dependencies in `Cargo.lock`
* **`crossterm`:** Updated to `0.29` in the root `Cargo.toml`. Double compilation of versions `0.28.1` (from `dpi-detector`) and `0.29.0` (from `comfy-table`) has been eliminated.
* **`webpki-roots`:** Switched to version `1.0`. The `0.26.11` shim dependency has been eliminated.
* **Result:** Reduced volume of duplicated code, faster build times.

### 2.4. Minimizing CLI Parser Features (`clap`)
* **File:** `Cargo.toml`
* **Before:** `clap = { version = "4.5", features = ["derive", "cargo"] }`
* **After:** `clap = { version = "4.5", default-features = false, features = ["std", "derive", "help", "usage"] }`
* **Mechanics:** Disabled the heavy fuzzy typo-search algorithms (Levenshtein distance tables in `suggestions`), contextual error formatting and versioning macros.
* **Result:** Savings of **~35 KB** in `clap_builder` machine code.

### 2.5. Runtime: two workers on a router, one per core elsewhere

* **Files:** `crates/dpi-detector/src/main.rs` (the policy), `crates/dpi-detector/build.rs` (which target is a router — `cargo:rustc-cfg=dpi_router` for the four router triples, so a hand-built router binary gets it too), `.github/workflows/release.yml` (the rows that build them)
* **History:** `rt-multi-thread` was replaced with `current_thread`
  (`features = ["rt"]`) on the argument that one thread is what the 1–2 core
  routers this targets can afford: it cuts **~50–120 KB** of machine code, and it
  was believed to cut RSS by not allocating a stack per thread.
* **Measured on the target** — MT7621, four hardware threads, musl; tests 1 and 6,
  two passes each, interleaved. Each cell is CPU time / wall, in seconds:

| workers | test 1 | test 6 | peak load | peak RSS |
| --- | --- | --- | --- | --- |
| 1 (`current_thread`) | 34.6/40.6, 33.3/45.6 | 18.9/21.9, 17.8/20.9 | ~1 core | 7.8–9.1 MB |
| 2 | 38.8/32.6, 36.6/24.2 | 20.4/13.8, 19.2/12.7 | ~2 cores | 8.2–8.5 MB |
| 4 | 44.5/23.6, 47.7/25.4 | 27.6/13.2, 25.1/13.2 | ~3.9 cores | 8.0–8.3 MB |

* **Result:** two workers take the whole gain on test 6 and most of it on test 1,
  for +3–8% processor time. Four take nothing further (test 6: 13.2 s either way)
  and cost +33–45% plus a peak of ~3.9 cores against ~2 — the half of a router
  that has to keep routing and serving Wi-Fi.
* The RSS claim above is **not** supported: the thread stacks are virtual, and
  resident memory measured the same at one, two and four workers.
* **Choice:** the count is a build decision, not a constant
  (`crates/dpi-detector/src/main.rs::worker_threads`). On the router targets —
  the triples `build.rs` marks with `--cfg dpi_router`: musl on mips, mips64, arm
  or aarch64 — it is
  `min(2, available_parallelism())`: derived, so the one-core routers this section
  was about keep one worker and their measured behaviour is unchanged, which a
  fixed `worker_threads = 2` would not give (the attribute takes a constant and
  would put two workers on a single core). Everywhere else the builder is left at
  tokio's default, one worker per core.
* **Why the router is capped and a desktop is not.** A desktop is not the machine
  above. Measured on a 12-thread box (Windows, `--release`, test 1, three passes,
  interleaved, `DPI_WORKERS` 1 / 2 / 12): wall 15.2, 14.7, 14.5 s at one worker
  against 14.8, 14.9, 14.6 s at twelve, processor time 0.5–1.1 s either way — the
  same code there is network-bound, so more workers buy nothing. They are not
  free: the peak working set was 15.7–16.0 MB at one and two workers against
  17.3–17.5 MB at twelve, ~150 KB per thread, consistently across all three
  passes. Two is what a fast machine needs; twelve is what it can afford.
* `DPI_WORKERS=<n>` overrides both rules, and is the only override: a value that
  cannot be a worker count is ignored rather than fatal, and the value is capped
  at four per core — this runs before the panic hook exists, so a large one would
  otherwise abort inside tokio's `build()` with nothing of ours on screen. On a
  router `TOKIO_WORKER_THREADS` is deliberately ignored, for the same reason: that
  variable is read by tokio only when the builder says nothing, and it checks the
  value for nothing but `> 0`. A desktop still gets tokio's own reading of it,
  because the router branch is the one that returns a count.

### 2.6. Cutting Stack Unwind Tables on Linux (`-C force-unwind-tables=no`)
* **File:** `.github/workflows/release.yml` — the `Build with cross` step, whose `RUSTFLAGS` is `--cfg rustix_use_libc -C force-unwind-tables=no ${{ matrix.rustflags }}`. Every `use_cross` row gets it, the four router rows and the two Android ones alike, and `Cross.toml` passes `RUSTFLAGS` into the container. It came in with 2597cc2 and is in the released tag; the x86_64-musl row sets the same flag by itself, because that row does not go through `cross`.
* **Mechanics:** With `panic = "abort"` the stack unwind tables (`.eh_frame` and `.eh_frame_hdr`) are not used while the program runs, so the flag stops codegen from emitting them.
* **What it is worth:** measured on the target for `mipsel-unknown-linux-musl` as a local A/B — one tree, built and run with and without the flag, three interleaved passes: the file drops from 5 370 720 to 5 018 392 bytes (**−352 KB**), and the resident memory with it — steady RSS −216, −408 and −388 KB, peak RSS −180, −456 and −696 KB. Processor time unchanged, as it must be for tables that are never executed. No shipped row changed here; the measurement is what the flag is worth.
* The Windows and macOS rows do not set it, and nothing measured says they should: their tables are the platform's own (SEH on MSVC), produced from the target's CFI rather than by this flag.

### 2.7. Keeping the `config.yml` Format (YAML)
* The YAML format was deliberately kept for user convenience: comment support (`#`), no strict restrictions on trailing commas, as well as 100% compatibility with already existing configuration files.

### 2.8. What the Router's Resident Memory Is Made Of

Measured on the target (MT7621, musl, `--release`). §2.5's two guesses about where the RSS goes — a stack per thread, a worker per core — were both wrong, and this is what replaced them.

* **The code mapping is 5096 kB on every test; the RSS is 6.4–9.4 MB.** Peak / steady RSS and processor time per test: 0 — 7308/6632 kB, 3.4 s; 2 — 8628/6812 kB, 5.9 s; 4 — 9368/6652 kB, 11.7 s; 1 — 8264/7704 kB, 35.3 s. These are one run of the shipping build; §2.2's `"z"` row is another on the same box, and the shared tests differ by up to 3.4% (+188/+284/+20 kB) — the spread to expect from a single sample.
* **The resident memory tracks the file, close to one for one.** §2.2's matrix moves the file by 0.44 MB and the peak RSS by 0.26–0.63 MB (`"z"` → `"s"`, mean 0.46), then by 1.83 MB and 1.20–1.33 MB (`"s"` → `3`, mean 1.28). §2.6's flag moves the file by 0.35 MB and the steady RSS by ~0.34 MB. The file is the lever, the profile and the linker flags are its two knobs, and both now sit at their memory-best setting.
* **Threads are not the lever.** tokio's default stack is 2 MiB per thread and test 2 runs 38 of them, so `thread_stack_size(128 * 1024)` was measured: 8364 vs 8388 kB (test 2), 8020 vs 7980 kB (test 1) — inside the noise. On musl the stacks are mapped lazily and only a shallow frame is ever touched. The setting is not in the tree.
* **The split is readable after all, from `/proc/<pid>/status`.** `smaps` does not exist on this kernel (`CONFIG_PROC_PAGE_MONITOR=n`), but `RssAnon`/`RssFile`/`RssShmem` do. Test 1, binary on ext4: `VmRSS` 7284 kB = `RssAnon` 1588 + `RssFile` 5696 + `RssShmem` 0. So the resident memory is the code, and nearly all of it: 5696 kB of file-backed pages against a 5096 kB `VmExe` mapping — a run executes essentially every page of the binary, and nothing evicts it while the run is on.
* **The same binary on tmpfs shows the same pages under another name.** Run from `/tmp` (tmpfs on this router): `RssShmem` 4776 + `RssFile` 796, the same ~5.6 MB counted as shared memory. That matters, because tmpfs pages cannot be reclaimed at all: a binary placed in `/tmp` costs its own size in RAM twice, once as the file and once as the process's resident pages. The installer puts it in `/opt/bin`, which is ext4.
* **What that does and does not mean.** File-backed pages are clean, so under memory pressure the kernel drops them and re-faults them from flash — the code is elastic memory, and the file size is the cheap kind of it. `echo 3 > /proc/sys/vm/drop_caches` does *not* demonstrate that on a running process, because `invalidate_mapping_pages` skips pages that are still mapped: the eviction is the kernel's documented behaviour here, not something this measurement showed. What cannot be reclaimed without swap is the anonymous part, 1.3–1.6 MB per run, and that is where an OOM kill would come from.
* **`VmData` is virtual, not resident:** 19–79 MB per test, and reading it as memory use would overstate the tool by an order of magnitude. `VmExe` is likewise the size of the mapping, not what is resident.
* **The code is diffuse: no single big win is left.** `cargo bloat` on the release build — `.text` is 2.7 MiB of the 4.0 MiB file, and the largest crates are `std` 528 KiB, `dpi_detector` 411 KiB, `dpi_core` 241 KiB, `rustls` 198 KiB, `tokio` 179 KiB, `h2` 173 KiB, then 125 crates at 93 KiB and below. The largest single function is `runner::run_test_suite`'s future at 124 KiB, followed by `run`'s at 103 KiB — the two async state machines, whose size is the sum of every branch they await. Cutting the resident memory further means removing features, not codegen settings; the YAML config (98 KiB with libyaml) and the `h2`/`hyper` stack (256 KiB) are both deliberate (§2.7, §3.3).).

### 2.9. The Clock in the Report File Name (`chrono`)

* **Files:** `Cargo.toml` (`[workspace.dependencies]`), `crates/dpi-detector/Cargo.toml`, `crates/dpi-detector/src/tui/screens/post_run.rs`
* **What it buys:** the report the binary writes for itself — the post-run `S` export, when no `-o` path was given — is named `dpi_detector_results-20260925-020115.txt`, so a second export is a second file instead of the first one overwritten. The offset has to come from the OS: a fixed one is wrong across a DST change, and this is the only clock in the tree that has to agree with the one on the desk.
* **Features:** `default-features = false, features = ["clock"]`. `formatting`, `serde` and `wasmbind` stay off: the stamp is six integer fields read off `Local::now()`, and the formatting machinery with its tables is what a default build would have carried.
* **Measured (`release-local`, x86_64-pc-windows-msvc, one tree, A/B):** 6 233 600 bytes with the clock in use against 6 242 304 bytes with `default_report_name()` stubbed to a literal and the dependency unused — 8 704 bytes *smaller* with the clock, which is linker layout rather than code, and is below the smallest win this document records (§2.4's 35 KB). The shipping profile is not measured; the reasoning, not the measurement, says it costs no more there: `release-local` has no LTO and 16 codegen units, so it is the profile that keeps the most of a crate's unused monomorphised code, and the release build strips at least as much.
* **Rejected:** a hand-rolled `GetLocalTime`/`localtime_r`, i.e. two new platform blocks of `unsafe`, which would stop `src/tui/backend.rs` being the crate's only FFI module (both the lint posture in `Cargo.toml` and that module's own comment name it as the one) — more code, two platforms, the same information. Rejected too: a UTC stamp, which reads at an offset from the wall clock of the machine the report is opened on.

---

## 3. Router Specifics (MIPS, ARM, OpenWrt, Keenetic, Entware)

1. **UPX is a fallback, not the default:**
   * The plain binary is what the installer prefers. Three router targets (`armv7`, `mipsel`, `mips`) additionally ship a `-upx` variant, and `install.sh` switches to it only when the target has less than 200 MB free (`DPI_UPX=1` forces it, `DPI_UPX=0` forbids it).
   * On routers the SquashFS filesystem compresses binaries with the **XZ / LZMA** algorithm directly on the Flash memory, so the plain ELF is already stored compactly.
   * A normal Linux ELF is loaded by the kernel page by page (4 KB demand-paging via `mmap`), while a UPX binary unpacks its whole image before `main`. **Measured on the target** — the same router (MT7621, 512 MB), one session, the two `mipsel` artifacts of `v5.0.0-alpha.20` (`install.sh` with `DPI_UPX=1` for the packed one), `/opt/bin/time -v` for the rusage numbers (peak RSS is `ru_maxrss`, not a sample), tests 0 / 2 / 4 / 1:

| build | peak RSS, 0 / 2 / 4 / 1 | file | anon | CPU (user+sys), 0 / 2 / 4 / 1 |
| --- | --- | --- | --- | --- |
| `dpi-detector-linux-mipsel` (4.94 MB) | 6216 / 6704 / 7692 / 6764 kB | 3996 kB | 2096 kB | 2.3 / 5.3 / 9.8 / 34.6 s |
| `dpi-detector-linux-mipsel-upx` (1.57 MB) | 6392 / 6740 / 7792 / 7100 kB | 4 kB | 6820 kB | 4.5 / 6.0 / 10.6 / 34.5 s |

   * The `file` and `anon` columns are one-second samples of `/proc/<pid>/status` during test 2, and they are the finding: **the peak is the same within a few hundred kB, but the pages are a different kind.** The packed build's ~4.7 MB of code is anonymous and dirty — the part §2.8 names as what an OOM kill comes from — where the plain build's ~4 MB is file-backed and clean, which the kernel drops and re-faults from flash under pressure. So the claim that stood here ("instantly inflates RSS by several megabytes") is not what this box shows; the cost of UPX is the reclaimability of the code plus the unpack's processor time, ~0.7–2.2 s per run (2.1 s against a 2.3 s test 0, and nothing measurable against the 35 s test 1). UPX stays reserved for flash-tight devices, which is the trade this section is about.
2. **100% self-containment (Static Musl):**
   * Builds for `mipsel-unknown-linux-musl`, `mips-unknown-linux-musl` and `armv7-unknown-linux-musleabihf` are built with static Musl libc (`+crt-static`), which allows running the utility on any firmware without installing external libraries into `/opt/lib`.
3. **Keeping DoH HTTP/2 (`h2`):**
   * The HTTP/2 stack is kept for authentic emulation of modern browser requests to DoH resolvers (Cloudflare, Google, AdGuard, Quad9).
