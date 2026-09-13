use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegionProfile {
    #[default]
    Ru,
    Ir,
    Cn,
    Global,
}

impl RegionProfile {
    pub fn from_code(code: &str) -> Option<Self> {
        match code.trim().to_lowercase().as_str() {
            "ru" | "russia" => Some(Self::Ru),
            "ir" | "iran" => Some(Self::Ir),
            "cn" | "china" => Some(Self::Cn),
            "global" | "default" | "world" => Some(Self::Global),
            _ => None,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Ru => "ru",
            Self::Ir => "ir",
            Self::Cn => "cn",
            Self::Global => "global",
        }
    }

    /// Target domains representative of blocking in this region.
    pub fn default_domains(&self) -> Vec<&'static str> {
        match self {
            Self::Ru => vec![
                "rutracker.org",
                "instagram.com",
                "meduza.io",
                "eais.rkn.gov.ru",
                "youtube.com",
                "x.com",
                "linkedin.com",
            ],
            Self::Ir => vec![
                "twitter.com",
                "instagram.com",
                "bbc.com",
                "radiofarda.com",
                "t.me",
                "youtube.com",
                "whatsapp.com",
            ],
            Self::Cn => vec![
                "google.com",
                "wikipedia.org",
                "youtube.com",
                "nytimes.com",
                "x.com",
                "facebook.com",
            ],
            Self::Global => vec![
                "google.com",
                "cloudflare.com",
                "wikipedia.org",
                "torproject.org",
                "archive.org",
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_parsing() {
        assert_eq!(RegionProfile::from_code("ru"), Some(RegionProfile::Ru));
        assert_eq!(RegionProfile::from_code("ir"), Some(RegionProfile::Ir));
        assert_eq!(RegionProfile::from_code("cn"), Some(RegionProfile::Cn));
        assert_eq!(RegionProfile::from_code("global"), Some(RegionProfile::Global));
        assert_eq!(RegionProfile::from_code("unknown"), None);
    }
}
