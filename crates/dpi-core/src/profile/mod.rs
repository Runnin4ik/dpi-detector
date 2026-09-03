use std::net::SocketAddr;
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

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Ru => "Russia (ТСПУ / RKN)",
            Self::Ir => "Iran (Filternet / TIC)",
            Self::Cn => "China (GFW / Great Firewall)",
            Self::Global => "Global Baseline",
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

    /// Primary DNS resolvers (local national + global) to probe for poisoning and availability.
    pub fn default_resolvers(&self) -> Vec<(&'static str, SocketAddr)> {
        match self {
            Self::Ru => vec![
                ("Yandex (77.88.8.8)", "77.88.8.8:53".parse().unwrap()),
                ("NSDI (195.208.4.1)", "195.208.4.1:53".parse().unwrap()),
                ("Cloudflare (1.1.1.1)", "1.1.1.1:53".parse().unwrap()),
                ("Google (8.8.8.8)", "8.8.8.8:53".parse().unwrap()),
            ],
            Self::Ir => vec![
                ("Shecan (178.22.122.100)", "178.22.122.100:53".parse().unwrap()),
                ("Electro (78.157.42.101)", "78.157.42.101:53".parse().unwrap()),
                ("Cloudflare (1.1.1.1)", "1.1.1.1:53".parse().unwrap()),
                ("Google (8.8.8.8)", "8.8.8.8:53".parse().unwrap()),
            ],
            Self::Cn => vec![
                ("114DNS (114.114.114.114)", "114.114.114.114:53".parse().unwrap()),
                ("AliDNS (223.5.5.5)", "223.5.5.5:53".parse().unwrap()),
                ("Cloudflare (1.1.1.1)", "1.1.1.1:53".parse().unwrap()),
                ("Google (8.8.8.8)", "8.8.8.8:53".parse().unwrap()),
            ],
            Self::Global => vec![
                ("Cloudflare (1.1.1.1)", "1.1.1.1:53".parse().unwrap()),
                ("Google (8.8.8.8)", "8.8.8.8:53".parse().unwrap()),
                ("Quad9 (9.9.9.9)", "9.9.9.9:53".parse().unwrap()),
            ],
        }
    }

    /// DoH resolver endpoints to probe.
    pub fn default_doh(&self) -> Vec<(&'static str, &'static str)> {
        match self {
            Self::Cn => vec![
                ("AliDNS DoH", "https://dns.alidns.com/dns-query"),
                ("Cloudflare DoH", "https://1.1.1.1/dns-query"),
            ],
            _ => vec![
                ("Cloudflare DoH", "https://1.1.1.1/dns-query"),
                ("Google DoH", "https://dns.google/dns-query"),
            ],
        }
    }

    /// Signatures of regional blockpages and censorship redirect pages.
    pub fn blockpage_signatures(&self) -> &'static [&'static str] {
        match self {
            Self::Ru => &[
                "warning.rt.ru",
                "blocked.rt.ru",
                "block.mts.ru",
                "eais.rkn.gov.ru",
                "blackhole",
                "zapret",
                "megafon.ru/blocked",
                "beeline.ru/blocked",
            ],
            Self::Ir => &[
                "10.10.34.34",
                "10.10.34.35",
                "peyvandha.ir",
                "filternet",
                "filter",
            ],
            Self::Cn => &[
                "127.0.0.1",
                "0.0.0.0",
                "block",
                "notice",
            ],
            Self::Global => &[
                "blocked",
                "blockpage",
                "access denied",
                "captive",
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

    #[test]
    fn test_profile_domains_not_empty() {
        for p in [RegionProfile::Ru, RegionProfile::Ir, RegionProfile::Cn, RegionProfile::Global] {
            assert!(!p.default_domains().is_empty());
            assert!(!p.default_resolvers().is_empty());
            assert!(!p.default_doh().is_empty());
            assert!(!p.blockpage_signatures().is_empty());
        }
    }
}
