//! The banner and the fingerprint header: what a report opens with.

use crate::i18n::{Messages, fingerprint_label};
use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::net::sysinfo::intercept::{Intercept, ListSource, Problem, Unchecked};
use dpi_core::profile::RegionProfile;

use crate::tui::widgets::{asc, panel_with, BOX_WIDTH};

/// What to print about interception before a run, if anything.
///
/// Silence in the two states that do not need a reader's attention: the traffic
/// *is* intercepted, or the package is not running at all. Everything else is
/// one header and a list, where each entry carries its own fix on the lines
/// under it — so a reader who has two problems fixes both in one pass, and a
/// reader whose check did not complete is not left reading an empty list as a
/// clean bill.
///
/// The bullet, the indent and the restart command are added here rather than
/// stored per language: they are layout and one path, and they must read the
/// same in all four.
pub fn render_intercept_notice(msg: &Messages, found: Option<&Intercept>) -> Option<String> {
    let found = found?;
    if found.problems.is_empty() && found.unchecked.is_empty() {
        return None;
    }
    let mut body = String::from(msg.intercept_header);
    for problem in &found.problems {
        body.push('\n');
        body.push_str(&entry(&problem_text(msg, found, problem)));
    }
    for unchecked in &found.unchecked {
        body.push('\n');
        body.push_str(&entry(&unchecked_text(msg, *unchecked)));
    }
    // A family the device has no route for is worth saying out loud, but there
    // is nothing in the package to change about it, so the command stays out.
    let restart =
        !found.problems.is_empty() || found.unchecked.iter().any(|u| *u != Unchecked::Route);
    let lead = if restart { format!("\n\n{}:", msg.intercept_then) } else { String::new() };
    let command = if restart { format!("\n{RESTART_HINT}") } else { String::new() };
    Some(format!("\n\x1b[33m{body}{lead}\x1b[0m{command}\n"))
}

/// One entry: the problem behind a bullet, its fix indented under it.
fn entry(text: &str) -> String {
    let bullet = asc("•");
    let mut out = String::new();
    for (n, line) in text.lines().enumerate() {
        if n == 0 {
            out.push_str(&format!("  {} {}", bullet, line));
        } else {
            out.push_str(&format!("\n    {}", line));
        }
    }
    out
}

/// One problem as it reads, with the values only the core knows filled in.
fn problem_text(msg: &Messages, found: &Intercept, problem: &Problem) -> String {
    match problem {
        Problem::Excluded => match found.policy.as_deref() {
            Some(policy) => msg.intercept_excluded.replacen("{}", policy, 1),
            None => msg.intercept_excluded_unnamed.to_string(),
        },
        Problem::Interface => {
            let rules = if found.rules_interfaces.is_empty() {
                "?".to_string()
            } else {
                found.rules_interfaces.join(", ")
            };
            let ours = found.our_interface.clone().unwrap_or_else(|| "?".to_string());
            msg.intercept_interface.replacen("{}", &rules, 1).replacen("{}", &ours, 1)
        }
        Problem::Tunnel => msg.intercept_tunnel.to_string(),
        Problem::Port => msg.intercept_ports.to_string(),
        Problem::Ipv6 => msg.intercept_ipv6.to_string(),
        Problem::ListMode { filter, source } => {
            let template = match source {
                ListSource::Mode => msg.intercept_list_mode,
                ListSource::Variable(_) | ListSource::Unknown => msg.intercept_list_mode_own,
            };
            let advice = match source {
                ListSource::Variable(name) => name.as_str(),
                _ => msg.intercept_strategy,
            };
            template
                .replacen("{}", &filter.profile, 1)
                .replacen("{}", &filter.option, 1)
                .replacen("{}", advice, 1)
        }
    }
}

/// One reason the check did not complete.
fn unchecked_text(msg: &Messages, unchecked: Unchecked) -> String {
    match unchecked {
        Unchecked::Config => msg.intercept_unchecked_config.to_string(),
        Unchecked::Queue => msg.intercept_unchecked_queue.to_string(),
        Unchecked::Route => msg.intercept_unchecked_route.to_string(),
    }
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
    use dpi_core::net::sysinfo::intercept::ListFilter;

    fn found(problems: Vec<Problem>) -> Intercept {
        Intercept {
            problems,
            unchecked: Vec::new(),
            policy: Some("nfqws".to_string()),
            rules_interfaces: vec!["wan0".to_string()],
            our_interface: Some("wwan1".to_string()),
        }
    }

    /// The same, with the check itself incomplete.
    fn unchecked(reasons: Vec<Unchecked>) -> Intercept {
        Intercept { unchecked: reasons, ..found(Vec::new()) }
    }

    /// The two states that need no reader attention print nothing at all.
    #[test]
    fn a_working_bypass_and_a_missing_package_stay_silent() {
        let msg = get_messages(Language::En);
        assert_eq!(render_intercept_notice(&msg, None), None, "package not running");
        assert_eq!(
            render_intercept_notice(&msg, Some(&found(Vec::new()))),
            None,
            "traffic is intercepted"
        );
    }

    /// A notice is a block: a blank line above and below, the text in between,
    /// and the restart command last.
    #[test]
    fn a_notice_is_a_block_with_the_restart_command() {
        let msg = get_messages(Language::En);
        let notice = render_intercept_notice(&msg, Some(&found(vec![Problem::Excluded]))).unwrap();
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
        let notice =
            render_intercept_notice(&msg, Some(&found(vec![Problem::Interface]))).unwrap();
        assert!(notice.contains("wan0"), "{notice}");
        assert!(notice.contains("wwan1"), "{notice}");
        assert!(notice.contains("ISP_INTERFACE"), "with the key to change: {notice}");
        let ports = render_intercept_notice(&msg, Some(&found(vec![Problem::Port]))).unwrap();
        assert!(ports.contains("TCP_PORTS"), "{ports}");
    }

    /// Two problems hold at once and the block says both, under one header: a
    /// reader who fixes one should not have to run the detector again to meet
    /// the next.
    #[test]
    fn several_problems_share_one_header() {
        use crate::render::strip_ansi;
        let msg = get_messages(Language::En);
        let notice =
            render_intercept_notice(&msg, Some(&found(vec![Problem::Ipv6, Problem::Port]))).unwrap();
        let body = strip_ansi(&notice);
        assert_eq!(
            body.matches(msg.intercept_header).count(),
            1,
            "the header is printed once: {body}"
        );
        assert!(body.contains("IPV6_ENABLED=0"), "{body}");
        assert!(body.contains("TCP_PORTS"), "{body}");
        // Both entries are bullets of the same list, and the fixes sit under
        // them rather than in a paragraph of their own.
        assert_eq!(body.matches("  • ").count(), 2, "{body}");
        assert!(body.contains("\n    set IPV6_ENABLED=1"), "{body}");
        assert_eq!(body.matches(msg.intercept_then).count(), 1, "one command: {body}");
    }

    /// A check that did not complete is not a problem on the list, and an empty
    /// list must not read as "clean".
    #[test]
    fn an_incomplete_check_is_stated_beside_the_problems() {
        use crate::render::strip_ansi;
        let msg = get_messages(Language::En);
        let mut state = found(vec![Problem::Ipv6]);
        state.unchecked = vec![Unchecked::Queue];
        let body = strip_ansi(&render_intercept_notice(&msg, Some(&state)).unwrap());
        assert!(body.contains("IPV6_ENABLED=0"), "{body}");
        assert!(body.contains("nothing is bound to its queue"), "{body}");
    }

    /// A family the device has no route for is the one state with nothing to
    /// change in the package, so it does not send the reader to the init script.
    #[test]
    fn an_unknown_route_alone_has_no_restart_command() {
        let msg = get_messages(Language::En);
        let notice = render_intercept_notice(&msg, Some(&unchecked(vec![Unchecked::Route]))).unwrap();
        assert!(!notice.contains(RESTART_HINT), "{notice}");
        assert!(notice.contains("could not be determined"), "{notice}");
    }

    /// The list-mode notice names the profile, the option and the variable the
    /// option lives in: an ipset list is appended to a profile it is not written
    /// in, so pointing a reader at `NFQWS_ARGS_CUSTOM` sends them to a line that
    /// does not hold it. When the config names no variable, the wording still
    /// has to read as a sentence.
    #[test]
    fn the_list_mode_notice_names_the_variable_the_filter_lives_in() {
        let msg = get_messages(Language::En);
        let filter = ListFilter {
            profile: "tcp=443 l7=tls".to_string(),
            option: "--ipset=/opt/etc/nfqws2/lists/ipset.list".to_string(),
        };
        let named = found(vec![Problem::ListMode {
            filter: filter.clone(),
            source: ListSource::Variable("NFQWS_ARGS_IPSET".to_string()),
        }]);
        let notice = render_intercept_notice(&msg, Some(&named)).unwrap();
        assert!(notice.contains("tcp=443 l7=tls"), "{notice}");
        assert!(notice.contains("--ipset=/opt/etc/nfqws2/lists/ipset.list"), "{notice}");
        assert!(notice.contains("NFQWS_ARGS_IPSET"), "{notice}");
        assert!(!notice.contains("{}"), "every placeholder is filled: {notice}");

        let unknown = found(vec![Problem::ListMode { filter, source: ListSource::Unknown }]);
        let notice = render_intercept_notice(&msg, Some(&unknown)).unwrap();
        assert!(notice.contains(msg.intercept_strategy), "{notice}");
        assert!(!notice.contains("{}"), "every placeholder is filled: {notice}");

        let from_mode = found(vec![Problem::ListMode {
            filter: ListFilter {
                profile: "tcp=80,443 l7=http,tls".to_string(),
                option: "--hostlist=/opt/etc/nfqws2/lists/user.list".to_string(),
            },
            source: ListSource::Mode,
        }]);
        let notice = render_intercept_notice(&msg, Some(&from_mode)).unwrap();
        assert!(notice.contains("MODE_ALL"), "the mode recipe: {notice}");
        assert!(!notice.contains("{}"), "every placeholder is filled: {notice}");
    }

    /// A package whose config never named a policy must not print empty quotes.
    #[test]
    fn an_unnamed_policy_has_its_own_wording() {
        let msg = get_messages(Language::En);
        let mut state = found(vec![Problem::Excluded]);
        state.policy = None;
        let notice = render_intercept_notice(&msg, Some(&state)).unwrap();
        assert!(!notice.contains("\"\""), "no empty quotes: {notice}");
        assert!(notice.contains("access policy"), "{notice}");
    }

    /// The Russian blocks are the ones a Keenetic owner reads: the wording, the
    /// bullets and the blank lines are what the report shows, so all three are
    /// pinned — with two problems, under one header.
    #[test]
    fn russian_notice_reads_as_written() {
        use crate::render::strip_ansi;
        let msg = get_messages(Language::Ru);
        let state = found(vec![Problem::Excluded, Problem::Ipv6]);
        let notice = render_intercept_notice(&msg, Some(&state)).unwrap();
        let body: Vec<String> = strip_ansi(&notice)
            .lines()
            .filter(|line| !line.contains("init.d"))
            .map(str::to_string)
            .collect();
        assert_eq!(
            body,
            vec![
                "",
                "Обнаружен включённый nfqws2, но есть проблемы:",
                "  • Соединение исключено политикой доступа «nfqws»",
                "    временно поставьте POLICY_EXCLUDE=1 или укажите свой POLICY_NAME,",
                "    которого нет среди политик роутера",
                "  • Детектор запущен в режиме IPv6, но правила для IPv6 не ставятся:",
                "    в конфиге пакета IPV6_ENABLED=0",
                "    поставьте IPV6_ENABLED=1 в /opt/etc/nfqws2/nfqws2.conf",
                "",
                "Затем:",
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
