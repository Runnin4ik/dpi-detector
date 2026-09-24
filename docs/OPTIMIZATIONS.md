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
* **Choice:** `min(2, available_parallelism())` — derived, so the one-core routers
  this section was about keep one worker and their measured behaviour is
  unchanged. A fixed `worker_threads = 2` would not give that: the attribute takes
  a constant, and would put two workers on a single core.

### 2.6. Cutting Stack Unwind Tables on Linux (`-C force-unwind-tables=no`)
* **File:** `.github/workflows/release.yml`
* **Mechanics:** With `panic = "abort"` the stack unwind tables (`.eh_frame` and `.eh_frame_hdr`) are not used while the program runs. The flag completely disables their generation for all Linux/MIPS/ARM targets.
* **Result:** Savings of **~300 KB** in ELF binaries for MIPS and ARM.

### 2.7. Keeping the `config.yml` Format (YAML)
* The YAML format was deliberately kept for user convenience: comment support (`#`), no strict restrictions on trailing commas, as well as 100% compatibility with already existing configuration files.

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
