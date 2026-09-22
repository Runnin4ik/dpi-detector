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
    out.push_str(&profile_section(msg, lang));
    out
}

/// Display label for a TLS ClientHello profile: the canonical token plus the
/// version the shape reproduces ("CHROME 133"), Latin in every language
/// (rule 4). Only the baseline needs prose rather than a token, and only there
/// is a language involved ("pishfarz" is the Finglish for "default").
///
/// The list of profiles is not spelled out here: `--legend` builds its table
/// from the profile table ([`profile_section`]), so a profile added to the
/// probe needs no new text in any language.
pub fn fingerprint_label(fp: dpi_core::net::fingerprint::TlsFingerprint, lang: Language) -> String {
    use dpi_core::net::fingerprint::TlsFingerprint as F;
    if fp != F::Rustls {
        return fp.display_label().to_string();
    }
    // The baseline's name is its token plus a translated qualifier: there is no
    // client version to name, so the prose says what the profile does instead.
    let qualifier = match lang {
        Language::Fa => "pishfarz",
        _ => "default",
    };
    format!("{} ({})", fp.token(), qualifier)
}

/// The profile rows of `--legend`, built from the profile table instead of
/// being written out per language: the names, the version each shape
/// reproduces and the bundle it came from stay Latin (rule 4), so only the
/// heading and the "default" marker are translated. A profile added to the
/// table appears here with no new text anywhere.
///
/// Every row carries the JA4 the shape answers with — the key a fingerprint
/// matcher can carry, and the one piece of a profile that a user comparing two
/// runs of test 6 needs on screen. The strings come from the same builder the
/// probes use ([`dpi_core::net::tls::hello_ja4_variants`]), so a row cannot
/// describe a hello the binary does not send; building twenty hellos, plus a
/// few more for the two shapes whose padding is a coin flip, is the price of
/// that, paid once per legend.
fn profile_section(msg: &Messages, lang: Language) -> String {
    use dpi_core::net::fingerprint::TlsFingerprint;
    let mut out = format!("  {}\n", format_bidi(msg.legend_profiles_heading, lang));
    for fingerprint in TlsFingerprint::ALL {
        let marker = if TlsFingerprint::DEFAULT_SET.contains(&fingerprint) {
            format!(" · {}", msg.legend_profiles_default)
        } else {
            String::new()
        };
        out.push_str(&format!(
            "    \x1b[36m{:<16}\x1b[0m \x1b[2m{} - {}{}\x1b[0m\n",
            fingerprint.code(),
            fingerprint.display_label(),
            fingerprint.source(),
            marker
        ));
        for ja4 in dpi_core::net::tls::hello_ja4_variants(fingerprint) {
            out.push_str(&format!("    \x1b[2m{:16} JA4 {ja4}\x1b[0m\n", ""));
        }
    }
    out.push('\n');
    out.push_str(&format!(
        "    \x1b[2m{}\x1b[0m\n\n",
        format_bidi(msg.legend_profiles_ja4, lang)
    ));
    out
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
            assert_eq!(msg.phase_text(dpi_core::PhaseId::DnsAvailability), "DNS");
        }
        assert_eq!(
            get_messages(Language::En).phase_text(dpi_core::PhaseId::Tcp16),
            "TCP 16–20 KB Block Check"
        );

        // Tokens are canonical Latin across every language (rule 4).
        assert_eq!(dpi_core::ProgressBlock::Udp.token(), "UDP");
        assert_eq!(dpi_core::ProgressBlock::Doh.token(), "DoH");
        assert_eq!(dpi_core::ProgressBlock::Dot.token(), "DoT");
        assert_eq!(dpi_core::ProgressBlock::Egress.token(), "EGRESS");
    }

    /// Every badge a report can show has a row in `--legend`, in every
    /// language: the term column is written as `{: <14}` between colour codes,
    /// so the row is asserted as that exact cell. The vocabulary is walked
    /// through `DpiStatus::ALL`, which after the removal of the four variants
    /// that had no producer is exactly the set of badges a report can carry.
    #[test]
    fn legend_explains_every_badge() {
        for lang in Language::ALL {
            let msg = get_messages(lang);
            let text = legend_text(lang, &msg);
            for status in dpi_core::classify::DpiStatus::ALL {
                let cell = format!("\x1b[36m{:<14}\x1b[0m", status.display_label());
                assert!(
                    text.contains(&cell),
                    "{} has no legend row for {}",
                    lang.label(),
                    status.display_label()
                );
            }
        }
    }

    /// Every profile row carries the JA4 its shape answers with, so two runs a
    /// user compares — one blocked, one not — can be read against the key a
    /// matcher carries rather than against the shape's name. The values
    /// themselves are pinned in the core
    /// (`net::fingerprint::tests::bundle_versions_match_their_ja4`); what this
    /// asserts is that the legend prints every one of them, under its row.
    #[test]
    fn every_profile_row_prints_its_ja4() {
        let lang = Language::En;
        let text = legend_text(lang, &get_messages(lang));
        for fingerprint in dpi_core::net::fingerprint::TlsFingerprint::ALL {
            let ja4s = dpi_core::net::tls::hello_ja4_variants(fingerprint);
            assert!(!ja4s.is_empty(), "{}", fingerprint.code());
            for ja4 in ja4s {
                assert!(text.contains(&ja4), "{} prints no {ja4}", fingerprint.code());
            }
        }
        // The note that explains what the key is, in every language: it is the
        // only place a reader learns why one row can carry two strings.
        for lang in Language::ALL {
            let msg = get_messages(lang);
            assert!(msg.legend_profiles_ja4.contains("JA4"), "{}", lang.label());
        }
    }
}
