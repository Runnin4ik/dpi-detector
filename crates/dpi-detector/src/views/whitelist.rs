//! Test 4: SNI discovery per autonomous system.

use crate::i18n::Messages;
use dpi_core::probe::whitelist::{AsVerdict, NO_SNI_TAG, WhitelistReport};

use crate::tui::widgets::{asc, warn_mark};

pub(crate) fn render_whitelist(report: &WhitelistReport, targets_total: usize, msg: &Messages) -> String {
    let mut out = String::new();
    if targets_total == 0 {
        out.push_str(msg.no_port_443_targets);
        return out;
    }
    if report.detected_as == 0 {
        out.push_str(msg.no_as_blocked);
        return out;
    }
    for row in &report.rows {
        match &row.verdict {
            AsVerdict::Found { snis, ban_after } => {
                let parts: Vec<String> = snis
                    .iter()
                    .map(|(label, n)| {
                        let disp = if label == NO_SNI_TAG {
                            msg.no_sni_label
                        } else {
                            label.as_str()
                        };
                        if *n > 0 {
                            format!("\x1b[1;32m{}\x1b[0m \x1b[2m#{}\x1b[0m", disp, n)
                        } else {
                            format!("\x1b[1;32m{}\x1b[0m", disp)
                        }
                    })
                    .collect();
                let suffix = if *ban_after {
                    format!("\x1b[2;33m{}\x1b[0m", msg.ban_after_label)
                } else {
                    String::new()
                };
                out.push_str(&asc(&format!(
                    "  \x1b[36m{}\x1b[0m \x1b[2m{}\x1b[0m  \x1b[32m✓\x1b[0m {}{}\n",
                    row.provider,
                    row.asn_str,
                    parts.join("  "),
                    suffix
                )));
            }
            AsVerdict::Banned { detail } => {
                let clean = strip_brackets(detail);
                out.push_str(&asc(&format!(
                    "  \x1b[36m{}\x1b[0m \x1b[2m{}\x1b[0m  \x1b[33m{} {}\x1b[0m \x1b[2m({})\x1b[0m\n",
                    row.provider,
                    row.asn_str,
                    warn_mark(),
                    msg.ban_rate_limit,
                    clean
                )));
            }
            AsVerdict::NotFound => {
                out.push_str(&asc(&format!(
                    "  \x1b[36m{}\x1b[0m \x1b[2m{}\x1b[0m  \x1b[31m{}\x1b[0m\n",
                    row.provider, row.asn_str, msg.sni_not_found
                )));
            }
        }
    }
    out.push('\n');
    if report.found_as > 0 {
        let s = msg.whitelist_found_summary.replacen("{}", &report.found_as.to_string(), 1).replacen("{}", &report.detected_as.to_string(), 1);
        out.push_str(&format!("\x1b[32m{}\x1b[0m\n", s));
    } else {
        let s = msg.whitelist_none_summary.replace("{}", &report.detected_as.to_string());
        out.push_str(&format!("\x1b[33m{}\x1b[0m\n", s));
    }
    out
}

fn strip_brackets(s: &str) -> String {
    let mut out = String::new();
    let mut depth: usize = 0;
    for c in s.chars() {
        if c == '[' {
            depth += 1;
        } else if c == ']' {
            depth = depth.saturating_sub(1);
        } else if depth == 0 {
            out.push(c);
        }
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::widgets::asc_with;
    /// The SNI discovery rows are colour-coded: found is green, a ban is yellow,
    /// a miss is red, and every one of those codes is what the legacy (non-VT)
    /// console translator maps onto a Win32 attribute — a row that loses its SGR
    /// goes monochrome on Windows 7.
    #[test]
    fn whitelist_rows_carry_their_status_colors() {
        use crate::i18n::{get_messages, Language};
        use dpi_core::probe::whitelist::AsRow;
        let msg = get_messages(Language::Ru);
        let report = WhitelistReport {
            rows: vec![
                AsRow {
                    provider: "EXAMPLE".to_string(),
                    asn_str: "AS64500".to_string(),
                    verdict: AsVerdict::Found {
                        snis: vec![("www.example.org".to_string(), 3)],
                        ban_after: true,
                    },
                },
                AsRow {
                    provider: "EXAMPLE".to_string(),
                    asn_str: "AS64501".to_string(),
                    verdict: AsVerdict::Banned { detail: "read timed out [connect]".to_string() },
                },
                AsRow {
                    provider: "EXAMPLE".to_string(),
                    asn_str: "AS64502".to_string(),
                    verdict: AsVerdict::NotFound,
                },
            ],
            detected_as: 3,
            found_as: 1,
        };
        let out = render_whitelist(&report, 3, &msg);
        assert!(
            out.contains("\x1b[36mEXAMPLE\x1b[0m \x1b[2mAS64500\x1b[0m  \x1b[32m✓\x1b[0m "),
            "found row: {out}"
        );
        assert!(out.contains("\x1b[1;32mwww.example.org\x1b[0m \x1b[2m#3\x1b[0m"), "found label: {out}");
        assert!(out.contains("\x1b[2;33m"), "ban-after suffix is dim yellow: {out}");
        assert!(out.contains("\x1b[33m"), "ban row is yellow: {out}");
        assert!(out.contains("\x1b[31m"), "miss row is red: {out}");
        assert!(out.contains("\x1b[32m"), "found summary is green: {out}");
        // ASCII mode swaps the glyphs but must keep the colors.
        let ascii = asc_with(&out, true);
        assert!(ascii.contains("\x1b[32m[OK]\x1b[0m"), "ascii mark: {ascii}");
        assert!(ascii.contains("\x1b[31mx SNI"), "ascii miss: {ascii}");
        assert!(ascii.contains("\x1b[2;33m  ! "), "ascii ban-after: {ascii}");
        assert!(!ascii.contains('✓') && !ascii.contains('×'), "glyphs left: {ascii}");
    }
}
