//! The banner and the fingerprint header: what a report opens with.

use crate::i18n::{Messages, fingerprint_label};
use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::net::sysinfo::intercept::{Intercept, Verdict, MARK_EXCLUDE};
use dpi_core::profile::RegionProfile;

use crate::tui::widgets::{BOX_WIDTH, panel_with, strip_ansi_len};

/// What the header needs to know about local interception of our own traffic.
///
/// Filled by a background probe so the banner never waits on it; every state
/// has its own wording, because "no tool" and "tool that skips us" mean
/// opposite things for how the numbers below should be read.
#[derive(Debug, Clone, Default)]
pub struct InterceptState {
    /// The probe has not answered yet.
    pub pending: bool,
    /// `Some` only when the `nfqws2` package was found on this device.
    pub result: Option<Intercept>,
    /// Bypass tools found by name, used when the package probe does not apply.
    pub tools: Vec<String>,
}

/// The header line: whether a local bypass takes this process's traffic.
///
/// The tool name and the mark stay Latin (rule 4), the sentence around them
/// comes from `i18n`. `Excluded` is the one verdict that changes what a report
/// means, so it is the one drawn undimmed.
pub fn render_intercept(msg: &Messages, state: &InterceptState) -> String {
    let line = if state.pending {
        msg.intercept_checking.to_string()
    } else {
        match &state.result {
            Some(found) => {
                let queue = found.queue.map(|q| q.to_string()).unwrap_or_else(|| "?".to_string());
                match found.verdict {
                    Verdict::Processed => {
                        msg.intercept_processed.replacen("{}", "nfqws2", 1).replacen("{}", &queue, 1)
                    }
                    Verdict::Excluded => msg
                        .intercept_excluded
                        .replacen("{}", "nfqws2", 1)
                        .replacen("{}", &format!("0x{:08x}", found.mark.unwrap_or(MARK_EXCLUDE)), 1),
                    Verdict::NotQueued => {
                        msg.intercept_not_queued.replacen("{}", "nfqws2", 1).replacen("{}", &queue, 1)
                    }
                    Verdict::Unknown => msg.intercept_unknown.replacen("{}", "nfqws2", 1),
                }
            }
            None if state.tools.is_empty() => msg.intercept_none.to_string(),
            None => msg.intercept_unmeasurable.replacen("{}", &state.tools.join(", "), 1),
        }
    };
    if state.result.as_ref().map(|r| r.verdict) == Some(Verdict::Excluded) {
        format!("\x1b[1;33m{}\x1b[0m", line)
    } else {
        format!("\x1b[2m{}\x1b[0m", line)
    }
}

pub fn render_banner(msg: &Messages, _profile: RegionProfile, badge: &str, intercept: &str) -> String {
    let badge_colored = if badge.starts_with("✓") {
        format!("\x1b[38;2;90;247;142m{}\x1b[0m", badge)
    } else if badge.starts_with("↑") {
        format!("\x1b[33m{}\x1b[0m", badge)
    } else {
        format!("\x1b[2m{}\x1b[0m", badge)
    };
    let version_line = format!("DPI Detector v{}", env!("CARGO_PKG_VERSION"));
    let row1 = format!(
        "  \x1b[2m{}\x1b[0m \x1b[38;2;214;180;255mRunni\x1b[0m \x1b[36m•\x1b[0m \x1b[2mGitHub:\x1b[0m Runnin4ik/dpi-detector",
        msg.author
    );
    let row2 = format!(
        "  \x1b[2m{}\x1b[0m t.me/DPI_detector \x1b[36m•\x1b[0m {}",
        msg.chat, badge_colored
    );
    let rows = banner_rows(row1, row2, intercept);
    // A row wider than the box would be drawn over its right border: the
    // interception line carries a tool name and a mark whose width nothing
    // here controls, so the box grows instead — the same measure-then-pad
    // rule the netinfo panel follows.
    let mut width = BOX_WIDTH;
    for row in &rows {
        let w = strip_ansi_len(row) + 6;
        if w > width {
            width = w;
        }
    }
    panel_with(&version_line, &rows, width, false, "36")
}

/// The banner's content rows: the two it always carries, plus the interception
/// line when there is one to show (the line is empty on a host with no bypass
/// tool and no measurement, which keeps the header at its old height).
fn banner_rows(row1: String, row2: String, intercept: &str) -> Vec<String> {
    let mut rows = vec![row1, row2];
    if !intercept.is_empty() {
        rows.push(intercept.to_string());
    }
    rows
}

/// Active TLS fingerprint line(s) for the human report header (text mode only).
/// Always one line with the profile (`Fingerprint: FIREFOX (firefox 133)`) using the
/// canonical token and label; the translated caveat follows on a second line for every
/// non-default profile (with RUSTLS it is irrelevant noise). The `[!]` prefix
/// and colors are added here, never stored in i18n (rule 4 keeps
/// JA3/JA4/ClientHello/TLS/RUSTLS/FIREFOX/CHROME/SAFARI untranslated there too).
pub fn render_fingerprint_header(fp: TlsFingerprint, msg: &Messages) -> String {
    let label = fingerprint_label(fp, msg.lang);
    // The default profile's label repeats its code ("rustls (default)" against
    // the RUSTLS token), which read as "RUSTLS (rustls (default))": a label
    // that starts with the code keeps only the qualifier.
    let head = match label.strip_prefix(fp.code()) {
        Some(qualifier) => format!("{}: {}{}", msg.fingerprint_label, fp.token(), qualifier),
        None => format!("{}: {} ({})", msg.fingerprint_label, fp.token(), label),
    };
    if fp != TlsFingerprint::Rustls {
        let note = format!("\x1b[33m[!]\x1b[0m \x1b[2m{}\x1b[0m", msg.fingerprint_note);
        format!("{}\n{}", head, note)
    } else {
        head
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header grows by exactly one row when there is something to say, so
    /// a host without a bypass tool keeps the banner it always had.
    #[test]
    fn intercept_row_appears_only_when_the_line_is_not_empty() {
        let plain = banner_rows("a".into(), "b".into(), "");
        assert_eq!(plain.len(), 2);
        let with_line = banner_rows("a".into(), "b".into(), "x");
        assert_eq!(with_line, vec!["a", "b", "x"]);
    }

    /// An excluded flow is the state a reader must not miss: it says the
    /// numbers below were taken with the bypass out of the path.
    #[test]
    fn excluded_is_the_loud_state_and_names_the_mark() {
        use crate::i18n::{get_messages, Language};
        let msg = get_messages(Language::En);
        let state = InterceptState {
            pending: false,
            result: Some(Intercept { queue: Some(300), mark: Some(MARK_EXCLUDE), verdict: Verdict::Excluded }),
            tools: Vec::new(),
        };
        let excluded = render_intercept(&msg, &state);
        assert!(excluded.contains("0x20000000"), "{excluded}");
        assert!(excluded.starts_with("\x1b[1;33m"), "undimmed: {excluded:?}");

        let processed = InterceptState {
            result: Some(Intercept { queue: Some(300), mark: Some(0), verdict: Verdict::Processed }),
            ..Default::default()
        };
        let line = render_intercept(&msg, &processed);
        assert!(line.contains("300"), "{line}");
        assert!(line.starts_with("\x1b[2m"), "dim: {line:?}");
    }

    /// A pending probe must not read as "no tool": they mean opposite things.
    #[test]
    fn pending_and_absent_tool_are_different_lines() {
        use crate::i18n::{get_messages, Language};
        let msg = get_messages(Language::En);
        let pending = render_intercept(&msg, &InterceptState { pending: true, ..Default::default() });
        let none = render_intercept(&msg, &InterceptState::default());
        assert_ne!(pending, none);
        assert!(pending.contains(msg.intercept_checking), "{pending}");
        assert!(none.contains(msg.intercept_none), "{none}");
    }

    /// A row wider than the box must widen it: the tool name and the mark are
    /// not fixed width, and drawing over the right border was visible on a real
    /// Keenetic before this rule.
    #[test]
    fn a_long_intercept_line_widens_the_box() {
        use crate::i18n::{get_messages, Language};
        use crate::render::strip_ansi;
        let msg = get_messages(Language::En);
        let long = "x".repeat(BOX_WIDTH * 2);
        let banner = render_banner(&msg, RegionProfile::Global, "up", &long);
        let widths: Vec<usize> = strip_ansi(&banner).lines().map(|l| l.chars().count()).collect();
        assert!(widths.len() >= 4, "border, two rows, border: {widths:?}");
        assert!(widths.iter().all(|w| *w == widths[0]), "ragged box: {widths:?}");
        assert!(widths[0] > BOX_WIDTH, "the box grew: {}", widths[0]);
    }

    #[test]
    fn fingerprint_header_never_repeats_the_profile_code() {
        use crate::i18n::{get_messages, Language};
        let en = get_messages(Language::En);
        // The default label ("rustls (default)") carried the token as well, so
        // the header read "RUSTLS (rustls (default))".
        assert_eq!(render_fingerprint_header(TlsFingerprint::Rustls, &en), "Fingerprint: RUSTLS (default)");
        let fa = get_messages(Language::Fa);
        assert_eq!(render_fingerprint_header(TlsFingerprint::Rustls, &fa), "Fingerprint: RUSTLS (pishfarz)");
        // A label that does not repeat the code keeps the full parenthetical.
        // The label already carries the code (`firefox 133` holds `firefox`), so
        // the parenthetical is dropped and the line stays one token shorter.
        let firefox = render_fingerprint_header(TlsFingerprint::Firefox, &en);
        assert!(firefox.starts_with("Fingerprint: FIREFOX 133"), "{firefox}");
        assert!(firefox.contains("FIREFOX = firefox133"), "the caveat still follows");
    }
}
