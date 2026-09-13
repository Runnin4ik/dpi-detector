//! Local bypass/proxy tool detection: the running process names are matched
//! against the signatures from config.

use std::collections::HashSet;
use std::time::Duration;

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
        if let Some(text) = run_cmd("ps", &["-e", "-o", "comm="], Duration::from_secs(5)) {
            for line in text.lines() {
                let name = line.trim().to_lowercase();
                if !name.is_empty() {
                    running_processes.insert(name);
                }
            }
        }
    }

    let mut detected = Vec::new();
    for (tool_name, patterns) in signatures {
        for pattern in patterns {
            if running_processes.contains(pattern.as_str()) {
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
