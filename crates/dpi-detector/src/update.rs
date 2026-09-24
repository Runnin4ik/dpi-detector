use crate::i18n::Language;

use std::time::Duration;

use dpi_core::net::netinfo::http_get_text;

pub(crate) const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
pub(crate) const GITHUB_REPO: &str = "Runnin4ik/dpi-detector";

/// The part of a GitHub release the update check cares about: its version with
/// the `v` prefix stripped, which is what `is_newer` compares.
#[derive(Debug, Clone, Default)]
pub(crate) struct ReleaseInfo {
    pub version: String,
}

/// True when the version carries a semver prerelease part (`-alpha.8`,
/// `-beta.1`, `-rc.2`). It selects the update channel: a prerelease build is
/// offered every published release, a stable build only stable ones.
fn is_prerelease(v: &str) -> bool {
    v.trim().trim_start_matches(['v', 'V']).contains('-')
}

/// Prerelease identifier. Per semver a numeric identifier ranks below an
/// alphanumeric one, and numeric identifiers compare numerically, so the
/// derived order (`Num < Text`, `u64` inside `Num`) is the semver order.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Pre {
    Num(u64),
    Text(String),
}

/// Parsed version: the numeric triple plus an optional prerelease part.
#[derive(Debug, PartialEq, Eq)]
struct Ver {
    nums: (u64, u64, u64),
    pre: Option<Vec<Pre>>,
}

impl Ver {
    /// Tolerant parse: accepts `v`/`V`, build metadata and trailing junk after
    /// the digits of each part. `None` when no numeric part can be read.
    fn parse(v: &str) -> Option<Self> {
        let clean = v.trim().trim_start_matches(['v', 'V']);
        // Build metadata (`+...`) never affects precedence.
        let clean = clean.split('+').next().unwrap_or("");
        let (main, pre) = match clean.split_once('-') {
            Some((main, pre)) => (main, Some(pre)),
            None => (clean, None),
        };
        let mut parts = Vec::new();
        for part in main.split('.') {
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                return None;
            }
            parts.push(digits.parse::<u64>().ok()?);
        }
        while parts.len() < 3 {
            parts.push(0);
        }
        let pre = pre.map(|pre| {
            pre.split('.')
                .map(|id| match id.parse::<u64>() {
                    Ok(n) => Pre::Num(n),
                    Err(_) => Pre::Text(id.to_string()),
                })
                .collect()
        });
        Some(Self { nums: (parts[0], parts[1], parts[2]), pre })
    }
}

impl Ord for Ver {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        // Destructured instead of read field by field: `PartialEq` is derived, so
        // it compares every field, and a field added later (build metadata is the
        // obvious candidate) would silently make `cmp` disagree with `==` — an
        // `Ord` contract violation the derive cannot catch. Naming the fields here
        // makes that a compile error.
        let Ver { nums, pre } = self;
        let Ver { nums: other_nums, pre: other_pre } = other;
        nums.cmp(other_nums).then_with(|| match (pre, other_pre) {
            (None, None) => Ordering::Equal,
            // A prerelease precedes its own release: 5.0.0-alpha.8 < 5.0.0.
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => a.cmp(b),
        })
    }
}

impl PartialOrd for Ver {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Semver compare: `latest > current`. Tolerant of `v`,
/// build metadata and junk; prereleases order per semver, so a beta beats an
/// alpha, `alpha.10` beats `alpha.9`, and the release beats its prereleases.
pub(crate) fn is_newer(latest: &str, current: &str) -> bool {
    match (Ver::parse(latest), Ver::parse(current)) {
        (Some(l), Some(c)) => {
            if l.nums == (0, 0, 0) || c.nums == (0, 0, 0) {
                return false;
            }
            l > c
        }
        _ => false,
    }
}

/// Fetches the newest release the running channel may move to (verifying TLS,
/// 4 s budget).
///
/// A stable build is only offered stable releases: `/releases/latest` is
/// defined as the latest non-draft, non-prerelease release. A prerelease build
/// (alpha/beta/rc) would never see its own successors there, so it lists the
/// recent releases and takes the highest version, prereleases included.
pub(crate) async fn fetch_latest_version() -> Option<ReleaseInfo> {
    let base = format!("https://api.github.com/repos/{}", GITHUB_REPO);
    let prerelease = is_prerelease(CURRENT_VERSION);
    let url = if prerelease {
        format!("{base}/releases?per_page=10")
    } else {
        format!("{base}/releases/latest")
    };
    let text = http_get_text(&url, Duration::from_secs(4)).await.ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    if prerelease {
        newest_release(v.as_array()?)
    } else {
        release_from(&v)
    }
}

/// One release object -> `ReleaseInfo`, or `None` when it carries no tag.
fn release_from(release: &serde_json::Value) -> Option<ReleaseInfo> {
    let version = release.get("tag_name")?.as_str()?.trim_start_matches(['v', 'V']);
    if version.is_empty() {
        return None;
    }
    Some(ReleaseInfo { version: version.to_string() })
}

/// Highest version among release objects. The list arrives newest-created
/// first, which is not the same as highest version after a hotfix re-tag, so
/// the tags are compared rather than the first one taken.
fn newest_release(releases: &[serde_json::Value]) -> Option<ReleaseInfo> {
    releases
        .iter()
        .filter_map(release_from)
        .filter_map(|info| Ver::parse(&info.version).map(|ver| (ver, info)))
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, info)| info)
}

/// Localized banner badge text.
pub(crate) fn version_badge_lang(latest: Option<&ReleaseInfo>, lang: Language) -> String {
    let msg = crate::i18n::get_messages(lang);
    match latest {
        None => msg.update_failed.to_string(),
        Some(info) if !info.version.is_empty() && is_newer(&info.version, CURRENT_VERSION) => {
            msg.update_available.replacen("{}", &info.version, 1)
        }
        _ => msg.update_current.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer() {
        assert!(is_newer("4.2.0", "4.1.0"));
        assert!(is_newer("v4.2.0", "4.1.0"));
        assert!(!is_newer("4.1.0", "4.2.0"));
        assert!(!is_newer("4.1.0", "4.1.0"));
        assert!(!is_newer("garbage", "4.1.0"));
        assert!(!is_newer("", ""));
        // A pre-release of the same triple does not beat its own release.
        assert!(is_newer("4.2.2", "4.2.2-rc1"));
        assert!(!is_newer("4.2.2-rc1", "4.2.2"));
    }

    #[test]
    fn test_is_prerelease() {
        assert!(is_prerelease("5.0.0-alpha.8"));
        assert!(is_prerelease("v5.0.0-beta.1"));
        assert!(is_prerelease("6.0.0-rc.2"));
        assert!(!is_prerelease("5.0.0"));
        assert!(!is_prerelease("v4.2.4"));
    }

    #[test]
    fn test_prerelease_ordering_is_semver() {
        // The channel-aware check must see the next alpha/beta, not just a
        // different numeric triple.
        assert!(is_newer("5.0.0-beta.1", "5.0.0-alpha.8"));
        assert!(is_newer("5.0.0-alpha.10", "5.0.0-alpha.9"));
        assert!(!is_newer("5.0.0-alpha.8", "5.0.0-beta.1"));
        assert!(!is_newer("5.0.0-alpha.8", "5.0.0-alpha.8"));
        assert!(is_newer("5.0.0", "5.0.0-alpha.8"));
    }

    #[test]
    fn test_newest_release_picks_the_highest_version() {
        let releases = vec![
            serde_json::json!({ "tag_name": "v5.0.0-alpha.8" }),
            serde_json::json!({ "tag_name": "v5.0.0-beta.1" }),
            serde_json::json!({ "tag_name": "v4.9.0" }),
            serde_json::json!({ "tag_name": "" }),
            serde_json::json!({ "name": "no tag here" }),
        ];
        assert_eq!(newest_release(&releases).unwrap().version, "5.0.0-beta.1");
        assert!(newest_release(&[]).is_none());
        let stable = vec![
            serde_json::json!({ "tag_name": "v4.9.0" }),
            serde_json::json!({ "tag_name": "v5.0.0" }),
        ];
        assert_eq!(newest_release(&stable).unwrap().version, "5.0.0");
    }

    #[test]
    fn test_release_from_reads_a_single_object() {
        // The stable channel consumes one `/releases/latest` object.
        let v = serde_json::json!({ "tag_name": "v4.2.4" });
        let info = release_from(&v).unwrap();
        assert_eq!(info.version, "4.2.4");
        assert!(release_from(&serde_json::json!({ "tag_name": "" })).is_none());
        assert!(release_from(&serde_json::json!({})).is_none());
    }

    #[test]
    fn test_version_badge() {
        let ru = Language::Ru;
        assert_eq!(version_badge_lang(None, ru), "× Не удалось проверить обновления");
        let info = ReleaseInfo { version: "9.9.9".into() };
        assert!(version_badge_lang(Some(&info), ru).starts_with("↑"));
        let same = ReleaseInfo { version: CURRENT_VERSION.into() };
        assert_eq!(version_badge_lang(Some(&same), ru), "✓ Актуальная версия");
    }
}
