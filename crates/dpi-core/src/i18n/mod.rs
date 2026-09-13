use std::env;
use serde::{Deserialize, Serialize};

mod details;
mod en;
mod fa;
mod messages;
mod ru;
mod zh;

pub use details::detail_text;
pub use messages::Messages;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    #[default]
    En,
    Ru,
    Zh,
    Fa,
}

impl Language {
    pub const ALL: [Self; 4] = [
        Self::En,
        Self::Ru,
        Self::Zh,
        Self::Fa,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Ru => "Русский",
            Self::Zh => "中文",
            Self::Fa => "Farsi",
        }
    }
    pub fn label_ascii(&self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Ru => "Русский",
            Self::Zh => "Chinese",
            Self::Fa => "Farsi",
        }
    }
    pub fn from_code(code: &str) -> Option<Self> {
        match code.trim().to_lowercase().as_str() {
            "en" | "en_us" | "en_gb" | "english" => Some(Self::En),
            "ru" | "ru_ru" | "russian" => Some(Self::Ru),
            "zh" | "zh_cn" | "zh_hans" | "chinese" => Some(Self::Zh),
            "fa" | "fa_ir" | "farsi" | "persian" => Some(Self::Fa),
            _ => None,
        }
    }

    /// Autodetects system language from environment variables (LANG, LC_ALL, LC_MESSAGES).
    pub fn autodetect() -> Self {
        for var in &["LC_ALL", "LANG", "LC_MESSAGES"] {
            if let Ok(val) = env::var(var) {
                let code = val.split('.').next().unwrap_or(&val);
                let lang_prefix = code.split('_').next().unwrap_or(code);
                if let Some(lang) = Self::from_code(lang_prefix) {
                    return lang;
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            if let Some(lang) = detect_windows_language() {
                return lang;
            }
        }
        Self::En
    }
}

/// Returns the text as-is. Kept for backwards compatibility with UI rendering callsites.
pub fn format_bidi(text: &str, _lang: Language) -> String {
    text.to_string()
}

/// Returns the text as-is. Kept for backwards compatibility with UI rendering callsites.
pub fn format_bidi_str(text: &str) -> String {
    text.to_string()
}

#[cfg(target_os = "windows")]
fn detect_windows_language() -> Option<Language> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let intl = hkcu.open_subkey("Control Panel\\International").ok()?;
    let locale_name: String = intl.get_value("LocaleName").ok()?;
    let prefix = locale_name.split('-').next().unwrap_or(&locale_name);
    Language::from_code(prefix)
}

pub fn get_messages(lang: Language) -> Messages {
    match lang {
        Language::En => en::messages(),
        Language::Ru => ru::messages(),
        Language::Zh => zh::messages(),
        Language::Fa => fa::messages(),
    }
}

/// Full diagnostic status legend as text.
/// Terms stay Latin; descriptions follow the selected language (en/ru full,
/// other languages fall back to English descriptions).
///
/// Returns the text instead of printing it: the caller owns the console, and on
/// a legacy (non-VT) Windows console raw `println!` bytes land on screen as
/// `?[36m` garbage — the SGR has to go through the binary's output writer, which
/// translates it into console attributes.
pub fn legend_text(lang: Language, msg: &Messages) -> String {
    let mut out = format!("{}\n", format_bidi(msg.legend_title, lang));
    let sections = match lang {
        Language::Ru => ru::legend_sections(),
        Language::Zh => zh::legend_sections_zh(),
        Language::Fa => fa::legend_sections_fa(),
        Language::En => en::legend_sections_en(),
    };
    for (section, items) in &sections {
        out.push_str(&format!("  {}\n", format_bidi(section, lang)));
        for (term, desc) in items {
            out.push_str(&format!(
                "    \x1b[36m{:<14}\x1b[0m \x1b[2m{}\x1b[0m\n",
                term,
                format_bidi(desc, lang)
            ));
        }
        out.push('\n');
    }
    out
}

/// Display label for a TLS ClientHello profile. The canonical token and the
/// profile names stay Latin (rule 4); only the default profile is spelled out
/// per language ("pishfarz" is the Finglish for "default").
pub fn fingerprint_label(fp: crate::net::fingerprint::TlsFingerprint, lang: Language) -> &'static str {
    use crate::net::fingerprint::TlsFingerprint as F;
    match (fp, lang) {
        (F::Rustls, Language::Fa) => "rustls (pishfarz)",
        (F::Rustls, _) => "rustls (default)",
        (F::Custom, _) => "firefox 133",
        (F::Chrome, _) => "curl chrome 107",
        (F::Safari, _) => "curl safari 155",
    }
}

/// Transfer rate in the interface's speed units (Ru uses Cyrillic units).
pub fn fmt_speed(bps: f64, lang: Language) -> String {
    let msg = get_messages(lang);
    if bps >= 1024.0 * 1024.0 {
        format!("{:>6.2} {}", bps / (1024.0 * 1024.0), msg.unit_mb_s)
    } else if bps >= 1024.0 {
        format!("{:>6.1} {}", bps / 1024.0, msg.unit_kb_s)
    } else {
        format!("{:>6.0} {}", bps, msg.unit_b_s)
    }
}

/// Byte count in the interface's size units.
pub fn fmt_size(bytes: u64, lang: Language) -> String {
    let msg = get_messages(lang);
    if bytes >= 1024 * 1024 {
        format!("{:.2} {}", bytes as f64 / (1024.0 * 1024.0), msg.unit_mb)
    } else if bytes >= 1024 {
        format!("{:.1} {}", bytes as f64 / 1024.0, msg.unit_kb)
    } else {
        format!("{} {}", bytes, msg.unit_b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_parsing() {
        assert_eq!(Language::from_code("ru"), Some(Language::Ru));
        assert_eq!(Language::from_code("en"), Some(Language::En));
        assert_eq!(Language::from_code("zh"), Some(Language::Zh));
        assert_eq!(Language::from_code("fa"), Some(Language::Fa));
        assert_eq!(Language::from_code("unknown"), None);
    }

    /// The live progress line must name what it is counting. Test 1 is labelled
    /// with the block tokens UDP/DoH/DoT/EGRESS, so it needs no wording of its
    /// own; the TCP window test names itself instead of a generic "Checking...".
    #[test]
    fn test_phase_text_names_each_phase() {
        for lang in [Language::En, Language::Ru, Language::Zh, Language::Fa] {
            let msg = get_messages(lang);
            assert_eq!(msg.phase_text(crate::PhaseId::DnsAvailability), "DNS");
        }
        assert_eq!(
            get_messages(Language::En).phase_text(crate::PhaseId::Tcp16),
            "TCP 16–20 KB Block Check"
        );

        // Tokens are canonical Latin across every language (rule 4).
        assert_eq!(crate::ProgressBlock::Udp.token(), "UDP");
        assert_eq!(crate::ProgressBlock::Doh.token(), "DoH");
        assert_eq!(crate::ProgressBlock::Dot.token(), "DoT");
        assert_eq!(crate::ProgressBlock::Egress.token(), "EGRESS");
    }

    #[test]
    fn test_messages_coverage() {
        for lang in [
            Language::En,
            Language::Ru,
            Language::Zh,
            Language::Fa,
        ] {
            let msg = get_messages(lang);
            assert!(!msg.banner_subtitle.is_empty());
            assert!(!msg.dns_title.is_empty());
            assert!(!msg.domain_title.is_empty());
            assert!(!msg.update_failed.is_empty());
            assert!(!msg.proxy_in_use.is_empty());
            assert!(!msg.tui_unavailable.is_empty());
            assert!(!msg.crash_title.is_empty());
            assert!(!msg.detail_read_timeout.is_empty());
            assert!(!msg.cli_about.is_empty());
            assert!(!msg.cfg_warn_invalid_value.is_empty());
            assert!(!msg.cfg_warn_unknown_key.is_empty());
            assert!(!msg.menu_title.is_empty());
            assert!(!msg.menu_language.is_empty());
            assert!(!msg.menu_ip_version.is_empty());
            assert!(!msg.menu_concurrency.is_empty());
            assert!(!msg.menu_hw_row.is_empty());
            assert!(!msg.menu_hw_change.is_empty());
            assert!(!msg.menu_hw_tests.is_empty());
            assert!(!msg.menu_hw_start.is_empty());
            assert!(!msg.menu_hw_quit.is_empty());
            assert!(!msg.menu_line_prompt.is_empty());
            assert!(!msg.menu_invalid_line.is_empty());
            assert!(!msg.menu_need_one.is_empty());
            assert!(!msg.latest_version.is_empty());
            assert!(!msg.author.is_empty());
            assert!(!msg.chat.is_empty());
            assert!(!msg.os.is_empty());
            assert!(!msg.system_dns.is_empty());
            assert!(!msg.active_interface.is_empty());
            assert!(!msg.dns_check_title.is_empty());
            assert!(!msg.doh_endpoints.is_empty());
            assert!(!msg.doh_min.is_empty());
            assert!(!msg.telegram_check_title.is_empty());
            assert!(!msg.summary_title.is_empty());
            for (d, field) in [
                ('0', msg.menu_test_netinfo),
                ('1', msg.menu_test_dns),
                ('2', msg.menu_test_domains),
                ('3', msg.menu_test_tcp),
                ('4', msg.menu_test_sni),
                ('5', msg.menu_test_telegram),
                ('6', msg.menu_test_burst),
                ('7', msg.menu_test_legend),
            ] {
                assert!(!field.is_empty());
                assert_eq!(msg.menu_test_label(d), field);
            }
            assert_eq!(msg.menu_test_label('8'), "");
        }
    }
}
