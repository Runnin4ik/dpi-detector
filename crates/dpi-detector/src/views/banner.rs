//! The banner and the fingerprint header: what a report opens with.

use crate::i18n::{Messages, fingerprint_label};
use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::net::sysinfo::intercept::{Intercept, NotCovered, Verdict};
use dpi_core::profile::RegionProfile;

use crate::tui::widgets::{BOX_WIDTH, panel_with};

/// What to print about interception before a run, if anything.
///
/// Silence in the two states that do not need a reader's attention: the traffic
/// *is* intercepted, or the package is not running at all. The three states
/// where a run means something different from what it looks like get a block
/// with a blank line above and below it, so it separates from the header and
/// from the results.
///
/// The restart command is appended here rather than stored per language: it is
/// one path, and it must read the same in all four.
pub fn render_intercept_notice(msg: &Messages, found: Option<&Intercept>) -> Option<String> {
    let found = found?;
    let body = match &found.verdict {
        Verdict::Processed => return None,
        Verdict::ListMode { filter, from_mode } => {
            let template = if *from_mode { msg.intercept_list_mode } else { msg.intercept_list_mode_own };
            template.replacen("{}", &filter.profile, 1).replacen("{}", &filter.option, 1)
        }
        Verdict::Excluded => match found.policy.as_deref() {
            Some(policy) => msg.intercept_excluded.replacen("{}", policy, 1),
            None => msg.intercept_excluded_unnamed.to_string(),
        },
        Verdict::NotQueued(NotCovered::Interface) => {
            let rules = if found.rules_interfaces.is_empty() {
                "?".to_string()
            } else {
                found.rules_interfaces.join(", ")
            };
            let ours = found.our_interface.clone().unwrap_or_else(|| "?".to_string());
            msg.intercept_interface.replacen("{}", &rules, 1).replacen("{}", &ours, 1)
        }
        Verdict::NotQueued(NotCovered::Port) => msg.intercept_ports.to_string(),
        Verdict::NotQueued(NotCovered::Ipv6) => msg.intercept_ipv6.to_string(),
        Verdict::NotQueued(NotCovered::Tunnel) => msg.intercept_tunnel.to_string(),
        Verdict::Unknown => msg.intercept_unchecked.to_string(),
    };
    Some(format!("\n\x1b[33m{}\x1b[0m\n{}\n", body, RESTART_HINT))
}

/// The one command every notice ends with. A path, not prose, so it is not a
/// translation string.
const RESTART_HINT: &str = "    /opt/etc/init.d/S51nfqws2 restart";

pub fn render_banner(msg: &Messages, _profile: RegionProfile, badge: &str) -> String {
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
    panel_with(&version_line, &[row1, row2], BOX_WIDTH, false, "36")
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
    use crate::i18n::{get_messages, Language};

    fn found(verdict: Verdict) -> Intercept {
        Intercept {
            verdict,
            policy: Some("nfqws".to_string()),
            rules_interfaces: vec!["wan0".to_string()],
            our_interface: Some("wwan1".to_string()),
        }
    }

    /// The two states that need no reader attention print nothing at all.
    #[test]
    fn a_working_bypass_and_a_missing_package_stay_silent() {
        let msg = get_messages(Language::En);
        assert_eq!(render_intercept_notice(&msg, None), None, "package not running");
        assert_eq!(
            render_intercept_notice(&msg, Some(&found(Verdict::Processed))),
            None,
            "traffic is intercepted"
        );
    }

    /// A notice is a block: a blank line above and below, the text in between,
    /// and the restart command last.
    #[test]
    fn a_notice_is_a_block_with_the_restart_command() {
        let msg = get_messages(Language::En);
        let notice = render_intercept_notice(&msg, Some(&found(Verdict::Excluded))).unwrap();
        assert!(notice.starts_with('\n'), "{notice:?}");
        assert!(notice.ends_with(RESTART_HINT) || notice.ends_with(&format!("{RESTART_HINT}\n")));
        assert!(notice.contains("nfqws"), "the policy the package looks for: {notice}");
        assert!(notice.trim_end().ends_with("restart") || notice.contains(RESTART_HINT));
        assert_eq!(notice.lines().filter(|l| l.is_empty()).count(), 2, "{notice}");
    }

    /// The interface case names both interfaces, so the reader knows what to
    /// move where; the port case names neither.
    #[test]
    fn the_interface_case_shows_both_interfaces() {
        let msg = get_messages(Language::En);
        let notice = render_intercept_notice(&msg, Some(&found(Verdict::NotQueued(NotCovered::Interface)))).unwrap();
        assert!(notice.contains("wan0"), "{notice}");
        assert!(notice.contains("wwan1"), "{notice}");
        assert!(notice.contains("ISP_INTERFACE"), "with the key to change: {notice}");
        let ports = render_intercept_notice(&msg, Some(&found(Verdict::NotQueued(NotCovered::Port)))).unwrap();
        assert!(ports.contains("TCP_PORTS"), "{ports}");
    }

    /// A package whose config never named a policy must not print empty quotes.
    #[test]
    fn an_unnamed_policy_has_its_own_wording() {
        let msg = get_messages(Language::En);
        let mut state = found(Verdict::Excluded);
        state.policy = None;
        let notice = render_intercept_notice(&msg, Some(&state)).unwrap();
        assert!(!notice.contains("\"\""), "no empty quotes: {notice}");
        assert!(notice.contains("access policy"), "{notice}");
    }

    /// The Russian blocks are the ones a Keenetic owner reads: the wording and
    /// the blank lines are what the report shows, so both are pinned.
    #[test]
    fn russian_notice_reads_as_written() {
        use crate::render::strip_ansi;
        let msg = get_messages(Language::Ru);
        let notice = render_intercept_notice(&msg, Some(&found(Verdict::Excluded))).unwrap();
        let body: Vec<String> = strip_ansi(&notice)
            .lines()
            .filter(|line| !line.contains("init.d"))
            .map(str::to_string)
            .collect();
        assert_eq!(
            body,
            vec![
                "",
                "Обнаружен включённый nfqws2, но трафик детектора он не видит:",
                "соединение исключено политикой доступа «nfqws».",
                "",
                "Чтобы обход применялся и к самому роутеру, временно поставьте POLICY_EXCLUDE=1",
                "или укажите свой POLICY_NAME, которого нет среди политик роутера, затем:",
            ],
            "{notice}"
        );
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
