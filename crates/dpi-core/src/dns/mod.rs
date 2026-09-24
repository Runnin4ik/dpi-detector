pub mod socks;
pub mod doh;
pub mod dot;
pub mod types;
pub mod udp;
pub mod wire;
pub mod resolve;
pub mod cymru;

pub use doh::query_doh_txt;
pub use resolve::resolve_host;
pub use socks::parse_socks_proxy;
