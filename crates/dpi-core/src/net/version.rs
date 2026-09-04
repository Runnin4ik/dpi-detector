use crate::i18n::Language;

use std::time::Duration;

use super::netinfo::http_get_text;

pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GITHUB_REPO: &str = "Runnin4ik/dpi-detector";

#[derive(Debug, Clone, Default)]
pub struct ReleaseInfo {
    pub tag: String,
    pub version: String,
}

/// Tolerant semver compare: latest > current (mirrors `is_newer`).
pub fn is_newer(latest: &str, current: &str) -> bool {
    fn parse(v: &str) -> Option<(u64, u64, u64)> {
        let clean = v.trim().trim_start_matches(['v', 'V']);
        let main = clean.split(['-', '+']).next().unwrap_or("");
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
        Some((parts[0], parts[1], parts[2]))
    }
    match (parse(latest), parse(current)) {
        (Some(l), Some(c)) => {
            if l == (0, 0, 0) || c == (0, 0, 0) {
                return false;
            }
            l > c
        }
        _ => false,
    }
}

/// Fetches the latest GitHub release (verifying TLS, 4 s budget).
pub async fn fetch_latest_version() -> Option<ReleaseInfo> {
    let url = format!("https://api.github.com/repos/{}/releases/latest", GITHUB_REPO);
    let text = http_get_text(&url, Duration::from_secs(4)).await.ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let tag = v.get("tag_name")?.as_str()?.to_string();
    if tag.is_empty() {
        return None;
    }
    let version = tag.trim_start_matches(['v', 'V']).to_string();
    Some(ReleaseInfo { tag, version })
}

/// Banner badge text (mirrors `version_badge`).
pub fn version_badge(latest: Option<&ReleaseInfo>) -> String {
    version_badge_lang(latest, Language::Ru)
}

/// Localized banner badge text.
pub fn version_badge_lang(latest: Option<&ReleaseInfo>, lang: Language) -> String {
    match latest {
        None => match lang {
            Language::Ru => "× Не удалось проверить обновления".to_string(),
            Language::Zh => "× 检查更新失败".to_string(),
            Language::Fa => "× خطا در بررسی به‌روزرسانی‌ها".to_string(),
            Language::Es => "× Error al buscar actualizaciones".to_string(),
            Language::Ar => "× فشل التحقق من التحديثات".to_string(),
            Language::En => "× Failed to check for updates".to_string(),
        },
        Some(info) if !info.version.is_empty() && is_newer(&info.version, CURRENT_VERSION) => {
            match lang {
                Language::Ru => format!("↑ Доступна новая версия {}", info.version),
                Language::Zh => format!("↑ 发现新版本 {}", info.version),
                Language::Fa => format!("↑ نسخه جدید در دسترس است {}", info.version),
                Language::Es => format!("↑ Nueva versión disponible {}", info.version),
                Language::Ar => format!("↑ يتوفر إصدار جديد {}", info.version),
                Language::En => format!("↑ New version available {}", info.version),
            }
        }
        _ => match lang {
            Language::Ru => "✓ Актуальная версия".to_string(),
            Language::Zh => "✓ 已是最新版本".to_string(),
            Language::Fa => "✓ آخرین نسخه".to_string(),
            Language::Es => "✓ Versión actual".to_string(),
            Language::Ar => "✓ أحدث إصدار".to_string(),
            Language::En => "✓ Up to date".to_string(),
        },
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
    }

    #[test]
    fn test_version_badge() {
        assert_eq!(version_badge(None), "× Не удалось проверить обновления");
        let info = ReleaseInfo { tag: "v9.9.9".into(), version: "9.9.9".into() };
        assert!(version_badge(Some(&info)).starts_with("↑"));
        let same = ReleaseInfo { tag: format!("v{}", CURRENT_VERSION), version: CURRENT_VERSION.into() };
        assert_eq!(version_badge(Some(&same)), "✓ Актуальная версия");
    }
}
