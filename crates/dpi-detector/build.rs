fn main() {
    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let mut res = winresource::WindowsResource::new();
        res.set("FileDescription", "DPI Detector — Network Censorship Diagnostic Engine");
        res.set("ProductName", "DPI Detector");
        res.set("ProductVersion", "5.0.0.0");
        res.set("FileVersion", "5.0.0.0");
        res.set("LegalCopyright", "Copyright (c) 2024-2026 Runni");
        res.set("CompanyName", "Runni");
        res.set("OriginalFilename", "dpi-detector.exe");
        res.set("InternalName", "dpi-detector");
        res.set_manifest(r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="dpi-detector" version="5.0.0.0" processorArchitecture="*"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#);
        if std::path::Path::new("assets/icon.ico").exists() {
            res.set_icon("assets/icon.ico");
        }
        if let Err(e) = res.compile() {
            eprintln!("cargo:warning=Failed to compile Windows PE resources: {}", e);
        }
    }
}
