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
    match_tools(&running_processes(), signatures)
}

/// Names of the running processes, lowercased: `tasklist` on Windows,
/// `/proc/<pid>/comm` everywhere else. Empty when the source is unreadable —
/// "nothing detected" is then the answer, as it is on a clean router.
fn running_processes() -> HashSet<String> {
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

    running_processes
}

/// The config's signatures read against one process list: each tool once, in
/// signature order, as soon as one of its patterns is a substring of one of the
/// names.
fn match_tools(processes: &HashSet<String>, signatures: &[(String, Vec<String>)]) -> Vec<String> {
    let mut detected = Vec::new();
    for (tool_name, patterns) in signatures {
        for pattern in patterns {
            // By substring, not equality: one tool ships under several names
            // (`nfqws` beside `nfqws2`), and `comm` is truncated to 15 bytes.
            if processes.iter().any(|name| name.contains(pattern.as_str())) {
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

    /// The two halves of the rule the panel and test 0 report as a fact: a
    /// pattern matches by *substring* (the config says `nfqws`, the process is
    /// `nfqws2`), and a tool is named *once* however many of its patterns are
    /// running.
    ///
    /// Fails on: `contains` replaced by `==` (the `nfqws` row disappears — the
    /// process is `nfqws2`), the `break` dropped (`zapret` has two patterns
    /// running and would be named twice), an empty pattern list treated as a
    /// match (the `empty` row appears), and a signature nothing is running being
    /// named anyway (the `absent` row appears).
    #[test]
    fn a_signature_matches_a_running_name_by_substring_once() {
        let processes: HashSet<String> = ["nfqws2", "xray", "zapret"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let signatures = vec![
            ("zapret".to_string(), vec!["nfqws".to_string(), "zapret".to_string()]),
            ("Xray".to_string(), vec!["v2ray".to_string(), "xray".to_string()]),
            ("absent".to_string(), vec!["sing-box".to_string()]),
            ("empty".to_string(), Vec::new()),
        ];

        assert_eq!(match_tools(&processes, &signatures), vec!["zapret", "Xray"]);
    }

    /// The result names tools, not processes, and in the config's order rather
    /// than the set's: the list is what the panel and test 0 print, so a walk over
    /// the process set instead of the signatures would reorder it between runs.
    ///
    /// Fails on: the iteration swapped to the process set (one of 24 orders would
    /// have to come up by chance), and a process list that is empty producing a
    /// detection anyway.
    #[test]
    fn the_result_is_the_config_names_in_config_order() {
        let processes: HashSet<String> =
            ["a", "b", "c", "d"].iter().map(|s| (*s).to_string()).collect();
        let signatures = vec![
            ("fourth".to_string(), vec!["d".to_string()]),
            ("third".to_string(), vec!["c".to_string()]),
            ("second".to_string(), vec!["b".to_string()]),
            ("first".to_string(), vec!["a".to_string()]),
        ];

        assert_eq!(
            match_tools(&processes, &signatures),
            vec!["fourth", "third", "second", "first"]
        );
        assert!(match_tools(&HashSet::new(), &signatures).is_empty(), "no processes, no tools");
    }
}
