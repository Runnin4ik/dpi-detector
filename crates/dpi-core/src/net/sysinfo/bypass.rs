//! Local bypass/proxy tool detection: the running process names are matched
//! against the signatures from config.

use std::collections::HashSet;
#[cfg(target_os = "windows")]
use std::time::Duration;

#[cfg(target_os = "windows")]
use super::run_cmd;

/// Detects running local bypass / proxy tools.
/// Signatures come from config (BYPASS_TOOLS): (display name, lowercase patterns).
pub fn detect_bypass_tools(signatures: &[(String, Vec<String>)]) -> Vec<String> {

    let mut running_processes = HashSet::new();

    #[cfg(target_os = "windows")]
    {
        if let Some(text) = run_cmd("tasklist", &["/FO", "CSV", "/NH"], Duration::from_secs(5)) {
            for line in text.lines() {
                if let Some(first_col) = line.split(',').next() {
                    let mut name = first_col.trim_matches('"').trim().to_lowercase();
                    if name.ends_with(".exe") {
                        name.truncate(name.len() - 4);
                    }
                    running_processes.insert(name);
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Entware on a Keenetic ships BusyBox `ps`, which takes neither `-e`
        // nor `-o` (`ps: invalid option -- 'e'`), so the process names come
        // from `/proc` directly: no subprocess at all, and no dependence on
        // which `ps` the PATH happens to resolve to.
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                match entry.file_name().to_str() {
                    Some(pid) if !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) => {}
                    _ => continue,
                }
                if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
                    let name = comm.trim().to_lowercase();
                    if !name.is_empty() {
                        running_processes.insert(name);
                    }
                }
            }
        }
    }

    let mut detected = Vec::new();
    for (tool_name, patterns) in signatures {
        for pattern in patterns {
            // By substring, not equality: one tool ships under several names
            // (`nfqws` beside `nfqws2`), and `comm` is truncated to 15 bytes.
            if running_processes.iter().any(|name| name.contains(pattern.as_str())) {
                detected.push(tool_name.clone());
                break;
            }
        }
    }

    detected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_bypass_tools() {
        let sigs = vec![("xray".to_string(), vec!["xray".to_string()])];
        let tools = detect_bypass_tools(&sigs);
        println!("Detected bypass tools: {:?}", tools);
    }
}
