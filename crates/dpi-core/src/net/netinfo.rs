//! Import paths for the network helpers the binary uses.
//!
//! The implementations live in `net::http_client`, `net::public_ip` and
//! `net::sysinfo`; these re-exports keep the call sites on the paths they
//! already import.

pub use crate::net::http_client::http_get_text;
pub use crate::net::public_ip::fetch_public_ips;
pub use crate::net::sysinfo::{
    detect_bypass_tools, flag_emoji, get_system_dns, ipv6_supported, is_tun_name, SystemDnsInfo,
};
