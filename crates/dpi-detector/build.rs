/// The PE version resource wants four numbers, and the tag's numeric part is
/// what a user reads in the file's properties: `5.0.0-alpha.19` becomes
/// `5.0.0.0`. Taken from `CARGO_PKG_VERSION` so a version bump moves it too —
/// it used to be a literal, which would have kept saying `5.0.0.0` at `5.1.0`.
#[cfg(windows)]
fn numeric_version() -> String {
    let mut parts: Vec<String> = std::env::var("CARGO_PKG_VERSION")
        .unwrap_or_default()
        .split(['-', '+'])
        .next()
        .unwrap_or("0.0.0")
        .split('.')
        .map(|p| {
            if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
                p.to_string()
            } else {
                "0".to_string()
            }
        })
        .collect();
    parts.truncate(4);
    while parts.len() < 4 {
        parts.push("0".to_string());
    }
    parts.join(".")
}

fn main() {
    // A router is a role, and the target triple is what declares it: the four
    // router rows of the release matrix, and nothing else. `main.rs` reads this
    // for its runtime policy (`docs/OPTIMIZATIONS.md` §2.5). Derived here rather
    // than passed in on the command line, so a hand-built router binary gets it
    // too: `cross build --release --target mipsel-unknown-linux-musl` is how the
    // router is measured, and a flag that has to be remembered would silently
    // produce a binary on the desktop policy.
    //
    // The arch list is what separates a router from the rest: `aarch64` with musl
    // is a router or an SBC, while `x86_64` with musl is the desktop artifact and
    // the Android targets carry no musl at all.
    println!("cargo:rustc-check-cfg=cfg(dpi_router)");
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if env == "musl" && matches!(arch.as_str(), "mips" | "mips64" | "arm" | "aarch64") {
        println!("cargo:rustc-cfg=dpi_router");
    }
    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let version = numeric_version();
        let mut res = winresource::WindowsResource::new();
        res.set("FileDescription", "DPI Detector — Network Censorship Diagnostic Engine");
        res.set("ProductName", "DPI Detector");
        res.set("ProductVersion", version.as_str());
        res.set("FileVersion", version.as_str());
        res.set("LegalCopyright", "Copyright (c) 2024-2026 Runni");
        res.set("CompanyName", "Runni");
        res.set("OriginalFilename", "dpi-detector.exe");
        res.set("InternalName", "dpi-detector");
        res.set_manifest(&format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="dpi-detector" version="{version}" processorArchitecture="*"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#
        ));
        if std::path::Path::new("assets/icon.ico").exists() {
            res.set_icon("assets/icon.ico");
        }
        if let Err(e) = res.compile() {
            eprintln!("cargo:warning=Failed to compile Windows PE resources: {}", e);
        }
    }
}
