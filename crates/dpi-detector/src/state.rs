//! The menu settings that survive a restart.
//!
//! The menu is where a run is configured, and a user who picks `Русский`, a
//! fingerprint or an interface expects the next start to open on it rather than
//! on the shipped default. What is remembered is exactly what the menu asks:
//! language, IP version, concurrency, fingerprint, the test selection and the
//! interface.
//!
//! **The file is written where a run starts, not where the menu is left.** A
//! choice confirmed by pressing Enter is a choice; one made and then abandoned
//! with `Q` is not, and a run that is interrupted halfway — Ctrl-C, a closed
//! terminal, a router that reboots — has already been recorded. A
//! non-interactive run writes nothing either: `--json` from a cron job must not
//! decide what the menu opens on next.
//!
//! The directory is the platform's own, then the two a router leaves behind:
//!
//! | platform | directory |
//! |---|---|
//! | Windows | `%APPDATA%\dpi-detector` |
//! | macOS | `~/Library/Application Support/dpi-detector` |
//! | Linux, BSD, Termux | `$XDG_CONFIG_HOME/dpi-detector`, else `~/.config/dpi-detector` |
//! | OpenWrt, Entware | the above, else `$PREFIX/etc/dpi-detector`, else beside the binary |
//!
//! The first of those that already holds the file, or else the first that
//! accepts a write, is the one used. `$HOME` is not enough on a router: it can
//! exist and still be read-only firmware, which is why the candidates are tried
//! rather than assumed. The last one is the directory the binary was installed
//! into — where `config.rs` already reads the shipped lists from, and which the
//! installer only picks when it can be written to.
//!
//! **Nothing here may fail a run.** A state file that cannot be read, parsed or
//! written means a menu that opens on its defaults, not an error: it records a
//! convenience, and what it starts from is `config.yml`, which the operator edits
//! by hand. That is also why the write is best-effort — a read-only installation
//! directory is a normal router setup, not a fault to report.
//!
//! Precedence, highest first: the command line, this file, `config.yml`. The file
//! is a record of what was *chosen*, so it sits above the configuration the
//! operator wrote and below a flag typed for this run.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::i18n::Language;
use crate::screens::main::MenuSelection;

/// File name inside the per-platform directory.
const FILE: &str = "state.json";
/// Directory name inside the per-platform root.
const APP: &str = "dpi-detector";
/// File written and removed to find out whether a directory accepts a write.
const PROBE: &str = ".probe";

/// What the menu last returned. Every field is optional: a key that is absent
/// was never chosen, and the menu falls back to `config.yml` for it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct SavedState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<usize>,
    /// The profile's own code (`chrome146`), which is the token `--fingerprint`
    /// takes and the one `--json` carries, not a debug spelling of the variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// The menu's selection string, e.g. `023` — the same shape `--tests` takes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tests: Option<String>,
    /// Seconds one phase of a probe waits — the menu's Timeout row. One value for
    /// HTTP, TLS and QUIC, so there is one field and not three.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<f64>,
    /// `None` is the routing table; `Some` is a named interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

impl SavedState {
    /// Records the selection a run was started with, so the next start opens on
    /// it. Called where the menu hands the run over, not where the menu is left.
    pub(crate) fn remember(selection: &MenuSelection) -> Self {
        Self {
            language: Some(selection.language),
            ip_version: Some(selection.ip_version.clone()),
            concurrency: Some(selection.concurrency),
            fingerprint: Some(selection.tls_fingerprint.code().to_string()),
            tests: Some(selection.selected_tests.clone()),
            timeout: Some(selection.timeout),
            interface: selection.interface.clone(),
        }
    }

    /// The IP version to start from, ignoring anything the config would not
    /// accept: a hand-edited state file must not put a run on a family the
    /// probes cannot use.
    pub(crate) fn ip_version(&self) -> Option<String> {
        match self.ip_version.as_deref() {
            Some("ipv4") => Some("ipv4".to_string()),
            Some("ipv6") => Some("ipv6".to_string()),
            _ => None,
        }
    }

    /// The timeout to start from, ignoring a value the menu could not have
    /// produced (1–60 seconds): the same rule as `ip_version`, and the window a
    /// probe waits is not a place for a hand-edited zero or a negative.
    pub(crate) fn timeout(&self) -> Option<f64> {
        self.timeout
            .filter(|secs| (crate::screens::main::TIMEOUT_MIN_SECS..=crate::screens::main::TIMEOUT_MAX_SECS).contains(secs))
    }
}

/// An environment variable that is set to something, or `None`.
fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Windows: `%APPDATA%`, the roaming profile directory.
///
/// Compiled on Windows, and under `test` everywhere. An order that is compiled
/// only on its own platform is an order nobody checks on any other, and the
/// macOS one has no runner in this project's CI at all.
#[cfg(any(windows, test))]
fn platform_dirs_windows(appdata: Option<&str>) -> Vec<PathBuf> {
    match appdata {
        Some(root) => vec![PathBuf::from(root).join(APP)],
        None => Vec::new(),
    }
}

/// macOS: `~/Library/Application Support`, the platform's own place for this.
#[cfg(any(target_os = "macos", test))]
fn platform_dirs_macos(home: Option<&str>) -> Vec<PathBuf> {
    match home {
        Some(root) => vec![PathBuf::from(root).join("Library/Application Support").join(APP)],
        None => Vec::new(),
    }
}

/// Linux, BSD and Termux: XDG, then `~/.config`, then an Entware prefix.
///
/// Pure: the values are passed in rather than read here, so a test can pin what
/// a router leaves in the environment — which is what decides whether the
/// settings survive a reboot — instead of pinning the machine it runs on.
#[cfg(any(all(unix, not(target_os = "macos")), test))]
fn platform_dirs_unix(xdg: Option<&str>, home: Option<&str>, prefix: Option<&str>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    // Absolute here means a leading `/`, and deliberately not
    // `Path::is_absolute`: that answers for the *host*, so a Windows test run
    // would judge this Unix path by Windows rules and drop the candidate.
    if let Some(xdg) = xdg.filter(|v| v.starts_with('/')) {
        out.push(PathBuf::from(xdg).join(APP));
    }
    if let Some(home) = home {
        out.push(PathBuf::from(home).join(".config").join(APP));
    }
    // Entware exports `PREFIX=/opt` and keeps configuration in `/opt/etc`, which
    // is the storage that survives a reboot when `$HOME` is a firmware root.
    // Termux exports a prefix too, and there `$HOME` is the user's own directory
    // while the prefix is the package tree — so `$HOME` stays in front of it.
    if let Some(prefix) = prefix {
        out.push(PathBuf::from(prefix).join("etc").join(APP));
    }
    out
}

/// The directories this build may use, most preferred first.
///
/// One `cfg_select!` block rather than three attribute pairs: the arms are the
/// same call shape, and a half-migrated pair is what a reader cannot see — the
/// argument `classify/classifier.rs` records for its constant table.
fn platform_dirs() -> Vec<PathBuf> {
    cfg_select! {
        windows => {
            platform_dirs_windows(var("APPDATA").as_deref())
        },
        target_os = "macos" => {
            platform_dirs_macos(var("HOME").as_deref())
        },
        _ => {
            platform_dirs_unix(
                var("XDG_CONFIG_HOME").as_deref(),
                var("HOME").as_deref(),
                var("PREFIX").as_deref(),
            )
        }
    }
}

/// Every directory the file may live in, most preferred first.
fn candidates() -> Vec<PathBuf> {
    let mut out = platform_dirs();
    // Last resort, and the one a router ends up on: the directory the binary was
    // installed into. `config.rs` reads the shipped lists from there, and the
    // installer only chooses a directory it can write to.
    out.push(dpi_core::config::base_dir());
    out
}

/// Whether `dir` can be created and written into.
///
/// The probe is a real write. A directory that exists can still refuse one — a
/// read-only firmware root on a router — and the permission bits do not answer
/// the same question: root ignores them, and a read-only mount does not show up
/// in them at all.
fn accepts_write(dir: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(PROBE);
    let ok = std::fs::write(&probe, b"").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

/// The first candidate that already holds the file, or else the first that
/// accepts a write.
fn pick(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.iter().find(|dir| dir.join(FILE).is_file() || accepts_write(dir)).cloned()
}

/// The directory the file lives in, or `None` when no candidate is usable.
fn dir() -> Option<PathBuf> {
    pick(&candidates())
}

/// Where the file is, or `None` when this build has nowhere to put it.
pub(crate) fn path() -> Option<PathBuf> {
    dir().map(|dir| dir.join(FILE))
}

/// Reads the saved settings. Anything unreadable, unparseable or absent is the
/// empty state — the menu then opens on `config.yml`, which is where it started
/// before this file existed.
pub(crate) fn load() -> SavedState {
    let Some(path) = path() else { return SavedState::default() };
    let Ok(text) = std::fs::read_to_string(&path) else { return SavedState::default() };
    serde_json::from_str(&text).unwrap_or_default()
}

/// Writes the settings, best-effort. The directory is created when it is
/// missing, and a failure at any step leaves the previous file in place and is
/// not reported, because a read-only directory is a normal installation, not a
/// fault.
pub(crate) fn save(state: &SavedState) {
    let Some(path) = path() else { return };
    if let Ok(text) = serde_json::to_string_pretty(state) {
        let _ = std::fs::write(&path, text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpi_core::net::fingerprint::TlsFingerprint;

    #[test]
    fn test_a_broken_state_file_is_the_empty_state_not_a_panic() {
        // The failure this pins: `unwrap` on the parse. A hand-edited or
        // truncated file is not a reason to refuse to start, and the state is
        // only a convenience over `config.yml`.
        for text in ["", "{", "not json", "{\"concurrency\": \"fifty\"}", "[]"] {
            let parsed: Result<SavedState, _> = serde_json::from_str(text);
            assert!(parsed.is_err() || parsed.expect("checked").concurrency.is_none(), "{text:?}");
        }
        assert_eq!(serde_json::from_str::<SavedState>("{}").expect("an empty object"), SavedState::default());
    }

    #[test]
    fn test_the_round_trip_keeps_every_field() {
        let state = SavedState {
            language: Some(Language::Ru),
            ip_version: Some("ipv6".to_string()),
            concurrency: Some(20),
            fingerprint: Some("chrome146".to_string()),
            tests: Some("023".to_string()),
            timeout: Some(15.0),
            interface: Some("eth0".to_string()),
        };
        let text = serde_json::to_string(&state).expect("serializes");
        // The language is its code, because that is what `--lang` takes.
        assert!(text.contains("\"language\":\"ru\""), "{text}");
        assert_eq!(serde_json::from_str::<SavedState>(&text).expect("parses"), state);
    }

    #[test]
    fn test_an_unknown_language_or_family_falls_back_instead_of_arming_a_run() {
        // `Language` is a closed enum, so an unknown code is a parse error and
        // the whole file is ignored — the menu opens on the config. The IP
        // version is a string, so it is checked rather than trusted.
        assert!(serde_json::from_str::<SavedState>("{\"language\":\"klingon\"}").is_err());
        let odd = SavedState { ip_version: Some("ipv7".to_string()), ..SavedState::default() };
        assert_eq!(odd.ip_version(), None);
        let ok = SavedState { ip_version: Some("ipv6".to_string()), ..SavedState::default() };
        assert_eq!(ok.ip_version().as_deref(), Some("ipv6"));
    }

    #[test]
    fn test_only_the_chosen_keys_are_written() {
        // A key that was never chosen must not appear: the file is read by a
        // human when something looks wrong, and `null` for "not chosen" is noise.
        let state = SavedState { language: Some(Language::En), ..SavedState::default() };
        let text = serde_json::to_string(&state).expect("serializes");
        assert!(text.contains("\"language\":\"en\""), "{text}");
        for absent in ["ip_version", "concurrency", "fingerprint", "tests", "interface", "timeout"] {
            assert!(!text.contains(absent), "{absent} in {text}");
        }
    }

    /// The timeout is checked the way the IP version is: the value a hand-edited
    /// file could carry (zero, negative, an hour) is not one the menu can leave
    /// behind, and it never reaches a probe.
    #[test]
    fn test_a_timeout_outside_the_row_range_is_ignored() {
        let inside = SavedState { timeout: Some(15.0), ..SavedState::default() };
        assert_eq!(inside.timeout(), Some(15.0));
        for outside in [0.0, -5.0, 0.5, 61.0, 3600.0] {
            let odd = SavedState { timeout: Some(outside), ..SavedState::default() };
            assert_eq!(odd.timeout(), None, "{outside}");
        }
    }

    #[test]
    fn test_a_run_start_records_the_tokens_the_file_carries() {
        // What pressing Enter writes: the tokens a user could type back, not a
        // debug spelling of the enum. `--fingerprint` takes the code, so the file
        // has to hold the code, and the routing table is an absent key rather
        // than an empty name.
        let selection = MenuSelection {
            selected_tests: "023".to_string(),
            ip_version: "ipv6".to_string(),
            concurrency: 20,
            timeout: 12.0,
            language: Language::Zh,
            tls_fingerprint: TlsFingerprint::ALL[1],
            interface: None,
        };
        let state = SavedState::remember(&selection);
        assert_eq!(state.language, Some(Language::Zh));
        assert_eq!(state.ip_version.as_deref(), Some("ipv6"));
        assert_eq!(state.concurrency, Some(20));
        assert_eq!(state.timeout, Some(12.0));
        assert_eq!(state.fingerprint.as_deref(), Some(TlsFingerprint::ALL[1].code()));
        assert_eq!(state.tests.as_deref(), Some("023"));
        assert_eq!(state.interface, None, "the routing table is an absent key");
    }

    #[test]
    fn test_a_candidate_that_refuses_a_write_is_skipped_for_the_next_one() {
        // The failure this pins: a router whose `$HOME` exists but is read-only
        // firmware, which is the normal Keenetic and OpenWrt root. The file has
        // to land in the next candidate — the Entware prefix, or the directory
        // the binary was installed into — instead of nowhere.
        let base = std::env::temp_dir().join(format!("dpi-detector-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("a temporary directory");
        // A file where a directory is expected: `create_dir_all` refuses it.
        let blocked = base.join("blocked");
        std::fs::write(&blocked, b"not a directory").expect("a file in the way");
        let open = base.join("open");
        assert_eq!(pick(&[blocked, open.clone()]), Some(open.clone()));
        // A directory that already holds the file wins over a later one that is
        // merely writable: the file is read from where it was written, so the
        // two must not disagree about which directory is in use.
        let holds = base.join("holds");
        std::fs::create_dir_all(&holds).expect("a directory");
        std::fs::write(holds.join(FILE), b"{}").expect("a state file");
        assert_eq!(pick(&[holds.clone(), open]), Some(holds));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_windows_keeps_the_file_under_appdata() {
        // The failure this pins: a `%USERPROFILE%\.config` of our own invention,
        // which no other Windows tool reads, or the local cache directory, which
        // a roaming profile does not carry. A Windows box can have `$HOME` set —
        // Git Bash sets it — and it must not decide anything.
        assert_eq!(
            platform_dirs_windows(Some(r"C:\Users\a\AppData\Roaming")),
            vec![PathBuf::from(r"C:\Users\a\AppData\Roaming").join(APP)]
        );
        assert!(platform_dirs_windows(None).is_empty(), "nothing is guessed without the variable");
    }

    #[test]
    fn test_macos_keeps_the_file_under_application_support() {
        // The platform's own place, not `~/.config`: a macOS user looks for this
        // under Application Support, and `$XDG_CONFIG_HOME` is not a macOS
        // convention even when a shell exports one.
        assert_eq!(
            platform_dirs_macos(Some("/Users/a")),
            vec![PathBuf::from("/Users/a/Library/Application Support").join(APP)]
        );
        assert!(platform_dirs_macos(None).is_empty(), "nothing is guessed without the variable");
    }

    #[test]
    fn test_unix_order_is_xdg_then_home_then_the_entware_prefix() {
        // A desktop: the directory the user asked for, then the one every other
        // tool uses, then Entware's convention.
        assert_eq!(
            platform_dirs_unix(Some("/xdg"), Some("/home/a"), Some("/opt")),
            vec![
                PathBuf::from("/xdg").join(APP),
                PathBuf::from("/home/a/.config").join(APP),
                PathBuf::from("/opt/etc").join(APP),
            ]
        );
        // Termux, in its own spelling: it exports both, and `$HOME` is the user's
        // own directory while `$PREFIX` is the package tree that a reset wipes.
        assert_eq!(
            platform_dirs_unix(
                None,
                Some("/data/data/com.termux/files/home"),
                Some("/data/data/com.termux/files/usr")
            ),
            vec![
                PathBuf::from("/data/data/com.termux/files/home/.config").join(APP),
                PathBuf::from("/data/data/com.termux/files/usr/etc").join(APP),
            ]
        );
        // OpenWrt with Entware and no login shell, which is how an init script
        // starts the binary: nothing but the prefix.
        assert_eq!(
            platform_dirs_unix(None, None, Some("/opt")),
            vec![PathBuf::from("/opt/etc").join(APP)]
        );
        // A relative `XDG_CONFIG_HOME` is not a path, and an empty environment
        // leaves the decision to the directory the binary sits in.
        assert_eq!(platform_dirs_unix(Some("config"), None, None), Vec::<PathBuf>::new());
        assert_eq!(platform_dirs_unix(None, None, None), Vec::<PathBuf>::new());
    }
}
