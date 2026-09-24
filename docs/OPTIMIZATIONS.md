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

* The two axes point opposite ways, and the exchange rate is steady: each
  megabyte of code costs about 0.85 MB of resident memory and buys back 13%
  (`"s"`) to 30% (`3`) of the processor time. The tool is a diagnostic on a
  router that is routing at the same time, and the constraint recorded in §3.2 is
  memory, so `"z"` is the right end of that trade. Re-open this only if the
  router-side goal changes from memory to time.
* The RSS tracks the file because the ELF is demand-paged (§3.1): what becomes
  resident is the pages the run touches, and a larger file leaves more of them
  touched. That is also why the file-size knobs below are memory knobs.

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

### 2.5. Runtime: one worker thread per core, capped at two

* **Files:** `Cargo.toml`, `crates/dpi-detector/src/main.rs`
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
* **Choice:** the count is a platform decision, not a constant
  (`crates/dpi-detector/src/main.rs::worker_threads`). On the embedded targets —
  `cfg!(target_env = "musl")`, which is what all four router rows build — it is
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
* `DPI_WORKERS=<n>` overrides both rules. That is how the numbers above were
  taken, and how a user pins the count on an unusual device.

### 2.6. Cutting Stack Unwind Tables on Linux (`-C force-unwind-tables=no`)
* **File:** `.github/workflows/release.yml`
* **Mechanics:** With `panic = "abort"` the stack unwind tables (`.eh_frame` and `.eh_frame_hdr`) are not used while the program runs, so the flag stops codegen from emitting them. All Linux/musl rows now set it: the four router rows (aarch64, armv7, mipsel, mips) were added to it, having been missing while this section already claimed them.
* **Result:** measured on the target for `mipsel-unknown-linux-musl`: the file drops from 5 370 720 to 5 018 392 bytes (**−352 KB**), and the resident memory with it — three interleaved passes against the same build without the flag: steady RSS −216, −408 and −388 KB, peak RSS −180, −456 and −696 KB. Processor time unchanged, as it must be for tables that are never executed.
* The Windows and macOS rows deliberately do not set it: their exception handling is not the Itanium unwinder, and `panic = "abort"` does not make those tables unused there.

### 2.7. Keeping the `config.yml` Format (YAML)
* The YAML format was deliberately kept for user convenience: comment support (`#`), no strict restrictions on trailing commas, as well as 100% compatibility with already existing configuration files.

### 2.8. What the Router's Resident Memory Is Made Of

Measured on the target (MT7621, musl, `--release`). §2.5's two guesses about where the RSS goes — a stack per thread, a worker per core — were both wrong, and this is what replaced them.

* **The code mapping is 5096 kB on every test; the RSS is 6.4–9.4 MB.** Peak / steady RSS and processor time per test: 0 — 7308/6632 kB, 3.4 s; 2 — 8628/6812 kB, 5.9 s; 4 — 9368/6652 kB, 11.7 s; 1 — 8264/7704 kB, 35.3 s.
* **The resident memory tracks the file at ~0.85.** §2.2's matrix moves the file by 0.44 MB and the peak RSS by 0.37 MB (`"z"` → `"s"`), then by 1.83 MB and 1.6 MB (`"s"` → `3`). §2.6's flag moves the file by 0.35 MB and the steady RSS by ~0.34 MB. The file is the lever, the profile and the linker flags are its two knobs, and both now sit at their memory-best setting.
* **Threads are not the lever.** tokio's default stack is 2 MiB per thread and test 2 runs 38 of them, so `thread_stack_size(128 * 1024)` was measured: 8364 vs 8388 kB (test 2), 8020 vs 7980 kB (test 1) — inside the noise. On musl the stacks are mapped lazily and only a shallow frame is ever touched. The setting is not in the tree.
* **`/proc/<pid>/smaps` does not exist on this target** (`CONFIG_PROC_PAGE_MONITOR=n`), so the file/anon split could not be read directly; every number above comes from changing one thing and measuring the total.
* **`VmData` is virtual, not resident:** 19–79 MB per test, and reading it as memory use would overstate the tool by an order of magnitude. `VmExe` is likewise the size of the mapping, not what is resident.
* **The code is diffuse: no single big win is left.** `cargo bloat` on the release build — `.text` is 2.7 MiB of the 4.0 MiB file, and the largest crates are `std` 528 KiB, `dpi_detector` 411 KiB, `dpi_core` 241 KiB, `rustls` 198 KiB, `tokio` 179 KiB, `h2` 173 KiB, then 125 crates at 93 KiB and below. The largest single function is `runner::run_test_suite`'s future at 124 KiB, followed by `run`'s at 103 KiB — the two async state machines, whose size is the sum of every branch they await. Cutting the resident memory further means removing features, not codegen settings; the YAML config (98 KiB with libyaml) and the `h2`/`hyper` stack (256 KiB) are both deliberate (§2.7, §3.3).

---

## 3. Router Specifics (MIPS, ARM, OpenWrt, Keenetic, Entware)

1. **UPX is a fallback, not the default:**
   * The plain binary is what the installer prefers. Three router targets (`armv7`, `mipsel`, `mips`) additionally ship a `-upx` variant, and `install.sh` switches to it only when the target has less than 200 MB free (`DPI_UPX=1` forces it, `DPI_UPX=0` forbids it).
   * On routers the SquashFS filesystem compresses binaries with the **XZ / LZMA** algorithm directly on the Flash memory, so the plain ELF is already stored compactly.
   * A normal Linux ELF is loaded by the kernel page by page (4 KB demand-paging via `mmap`), while a UPX binary must fully unpack itself into RAM on startup. On routers with 64–128 MB RAM this instantly inflates RSS by several megabytes and provokes the OOM-killer — which is why UPX is reserved for flash-tight devices, where the trade is deliberate.
2. **100% self-containment (Static Musl):**
   * Builds for `mipsel-unknown-linux-musl`, `mips-unknown-linux-musl` and `armv7-unknown-linux-musleabihf` are built with static Musl libc (`+crt-static`), which allows running the utility on any firmware without installing external libraries into `/opt/lib`.
3. **Keeping DoH HTTP/2 (`h2`):**
   * The HTTP/2 stack is kept for authentic emulation of modern browser requests to DoH resolvers (Cloudflare, Google, AdGuard, Quad9).
