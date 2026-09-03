# AGENTS.md — DPI Detector (Rust Native Engine)

Repository conventions, systems programming constraints, and development rules for AI agents working on `dpi-detector-rust`.

---

## 1. Project Architecture

A dual-crate Cargo workspace designed for high-performance, low-memory network censorship diagnostics:

```
crates/
├── dpi-core/               # Pure-Rust diagnostic engine & protocol library
│   ├── src/
│   │   ├── dns/            # RFC 1035 wire builder/parser, UDP, DoH (H2), SOCKS5 UDP relay
│   │   ├── classify/       # DpiProbeStream, DpiProbeTracker, OS error -> DpiStatus
│   │   ├── probe/          # DpiTlsConnector abstraction, TLS L7 probe, TCP16 fat ping
│   │   ├── net/            # InsecureDpiCertVerifier, WebPKI root certificates
│   │   ├── config/         # YAML configuration loader & domain normalizer
│   │   ├── i18n/           # Multi-language localization (En, Ru, Fa, Zh, Es, Ar)
│   │   ├── profile/        # Regional censorship profiles (Ru, Ir, Cn, Global)
│   │   └── lib.rs
│   └── Cargo.toml
└── dpi-detector/           # CLI binary & terminal output
    ├── src/
    │   ├── args.rs         # Clap CLI argument parser
    │   ├── render.rs       # comfy-table formatting with RTL support
    │   └── main.rs         # Orchestration loop & JSON output
    └── Cargo.toml
```

---

## 2. Inviolable Systems Rules

### Rule 1: Zero C Dependencies (Pure Rust Only)
- **Constraint**: Target devices include Keenetic, OpenWrt, and Entware routers (`mipsel-unknown-linux-musl`) with no dynamic linker and broken C cross-compilers.
- **Rule**: NEVER introduce crates that depend on C/C++ builds (e.g. `openssl`, `boringssl`, `rquest`, `wreq`, `curl-sys`).
- **Allowed Crypto**: Pure Rust only — `rustls`, `ring`, `RustCrypto`.

### Rule 2: Low-Memory Ceilings (16–32 MB RAM Target)
- **Binary Size Budget**: 3–6 MB release stripped (`opt-level = "s"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = true`).
- **Runtime Memory Budget**: RSS <= 3–6 MB.
- **Rule**: Zero unconstrained heap allocations. Never buffer full streams in memory when streaming or slicing is possible.
- **Zero Disk Writes**: In-memory caching only (for ASN and DNS). Never create temporary files in `tmpfs` without explicit CLI file arguments.

### Rule 3: Error Classification Fidelity (`DpiProbeStream`)
- **Rule**: Every TCP and TLS connection probe MUST be wrapped in `DpiProbeStream`.
- Connection stages MUST be tracked: `TcpConnecting` $\to$ `TcpConnected` $\to$ `TlsClientHelloSent` $\to$ `TlsHandshakeDone` $\to$ `HttpPayload`.
- A connection reset (`ConnectionReset` / 10054 / 104) or premature EOF occurring after ClientHello transmission (`stage == TlsClientHelloSent && bytes_recv == 0`) MUST be classified as **`DpiStatus::TlsRst`**, NEVER masked as a generic connection error.
- A connection timeout during connect MUST be classified as **`DpiStatus::SynDropped`**.

### Rule 4: Technical Entities & Protocol Signals Are Never Translated
- **Rule**: Badges in table cells and log tokens MUST remain canonical uppercase Latin tokens across ALL languages:
  `OK`, `AVAILABLE`, `BLOCKED`, `SYN DROP`, `TCP RST`, `TLS RST`, `TLS DROP`, `TLS ALERT`, `HTTP BLOCK`, `TCP16 DROP`, `UNREACHABLE`.
- RFC protocol names (`TCP`, `UDP`, `TLS`, `DoH`, `DoT`, `SNI`, `ClientHello`) MUST NOT be translated.
- Translate UI headers, banners, menu prompts, and `--legend` explanations, but preserve signal labels.
- In RTL languages (Farsi, Arabic), Latin badges ensure numbers and IP addresses do not invert direction.

### Rule 5: Machine JSON Contract Stability
- **Rule**: The `--json` machine-readable output schema MUST remain stable:
  - All `status` values must strictly match the snake_case enum representations (`"ok"`, `"syn_dropped"`, `"tcp_rst"`, `"tls_rst"`, `"tls_dropped"`, `"http_blocked"`).
  - Localization (`--lang`) alters only human-facing tables and `--legend`, never machine JSON keys.

---

## 3. Rust Code Style & Idioms

1. **Locks**: Use `parking_lot::Mutex` and `parking_lot::RwLock` for synchronous thread-safe state. Use `tokio::sync::Mutex` ONLY when the lock must be held across an `.await` boundary.
2. **Match Ergonomics**: Match by borrowing the scrutinee (`match &res { Ok(val) => ... }`), never use explicit `ref` patterns (`match res { Ok(ref val) => ... }`).
3. **Future Imports**: Add `use std::future::Future;` once at the top of the file; use `impl Future<...>` instead of `impl std::future::Future<...>`.
4. **Error Handling**: Use `thiserror` for library errors in `dpi-core`. Avoid `unwrap()` in production paths; reserve unwraps strictly for verified unit test assertions.

---

## 4. Verification Workflow

Before yielding or committing any change, run:

```powershell
$env:PATH = 'C:\Users\runnin\.cargo\bin;' + $env:PATH
cargo test --workspace
cargo clippy --workspace
```

- **Tests**: 100% pass rate required.
- **Clippy**: Exactly 0 warnings required (`--workspace`).
