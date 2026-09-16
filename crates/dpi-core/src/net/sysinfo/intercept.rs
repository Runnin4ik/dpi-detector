//! Whether a local DPI-bypass tool takes *this* process's traffic.
//!
//! The Keenetic package (`nfqws2-keenetic`) hooks `mangle POSTROUTING` and
//! `PREROUTING` on the provider interface, and it decides a packet's fate by
//! three things that have nothing to do with the destination: the interface it
//! leaves by, the mark the access policy left on its connection, and the
//! address family it belongs to. Two probes of the same host can therefore end
//! up in different worlds — one queued to the desync, one going straight out —
//! and a report that does not say which world it measured is unreadable.
//!
//! Everything here is read from the tool's own state, never guessed:
//!
//! * `/opt/etc/nfqws2/nfqws2.conf.run` — what the init script resolved on
//!   start: the queue number, the policy it looks for, the interfaces it hooked,
//!   the ports it queues, and whether the IPv6 half is on at all;
//! * `/opt/var/run/nfqws2.pid` — liveness;
//! * `/proc/net/netfilter/nfnetlink_queue` — that the queue is actually bound;
//! * `/proc/net/route` and `/proc/net/ipv6_route` — the interface our own
//!   traffic leaves by, one file per address family;
//! * `/proc/net/nf_conntrack` — the `ctmark` of our own flow, where the
//!   policy's `CONNMARK --set-xmark` shows up.
//!
//! The queue's packet counter is deliberately *not* used as evidence: measured
//! on a Keenetic, its idle rate is around 97 packets/s of other people's
//! traffic, so five probes of our own are indistinguishable from the noise and
//! the verdict flickered between runs. The mark is per-flow and exact; the
//! port and interface coverage is static configuration. Together they answer
//! the question without a coin flip.
//!
//! Nothing is written anywhere, and the only packets sent are the SYNs of one
//! or two TCP connections to the caller's target — the same first packet the
//! tests send.

use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use super::is_tun_name;

/// The mark the package stamps on connections its access policy leaves alone
/// (`MARK_EXCLUDE` in `etc/init.d/common`): the first packet of such a
/// connection is marked and returned *above* the queue, so the desync never
/// sees it.
pub const MARK_EXCLUDE: u32 = 0x2000_0000;

const CONF_RUN: &str = "/opt/etc/nfqws2/nfqws2.conf.run";
const PIDFILE: &str = "/opt/var/run/nfqws2.pid";
const ROUTE_PROC: &str = "/proc/net/route";
const ROUTE6_PROC: &str = "/proc/net/ipv6_route";
const QUEUE_PROC: &str = "/proc/net/netfilter/nfnetlink_queue";
const CONNTRACK_PROC: &str = "/proc/net/nf_conntrack";

/// How long a probe connect is allowed to sit before the next attempt. Below
/// the kernel's initial retransmit timeout, so a probe is one SYN and no retry.
const PROBE_WAIT: Duration = Duration::from_millis(150);
/// Attempts to get a readable mark: the first entry can be missed while the
/// connection is still being created.
const PROBE_ATTEMPTS: usize = 2;

/// Why the rules do not take our traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotCovered {
    /// Our traffic leaves by an interface the rules were not attached to — a
    /// tunnel, a second uplink. The common case on a router that routes its own
    /// traffic somewhere else.
    Interface,
    /// The port our probe uses is not in the package's `TCP_PORTS`.
    Port,
    /// Our traffic is IPv6 and the package installs no IPv6 rules at all
    /// (`IPV6_ENABLED=0`). The v4 rules can be perfect and this still holds.
    Ipv6,
    /// Our traffic does not leave through any netfilter interface: it goes
    /// through a tunnel. Measured, not inferred — the kernel's own record for
    /// our flow says so (`no_if` beside `nmark=`/`sc=`, where an ordinary flow
    /// carries `ifw=`/`ifl=`). A per-destination route into a VPN is invisible
    /// to the default-route comparison, which is why this is read per flow.
    Tunnel,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The tool's rules cover the port and interface our traffic uses, and the
    /// policy did not mark the connection: the desync sees these packets.
    Processed,
    /// The access policy excluded our connection before the queue.
    Excluded,
    /// The tool is running, but its rules do not cover us.
    NotQueued(NotCovered),
    /// The rules take our traffic, but the strategy applies the desync to 80/443
    /// only for targets on its own lists — so a run's numbers are a mixture of
    /// bypassed and unbypassed, and a reader should know that before reading
    /// them. Nothing is broken; this is a property of the strategy.
    ListMode,
    /// The tool is running and its queue is not bound, or nothing could be read
    /// back about our flow.
    Unknown,
}

/// Address family a run uses. The package covers the two with separate rules,
/// so the verdict has to be asked for one of them by name: an IPv6 run must not
/// be judged by what the v4 rules do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

/// The state of the `nfqws2` package on this device, as far as it concerns the
/// detector's own traffic. Everything the notice can name is here; the queue
/// number and the connection mark stay inside — they decide the verdict, they
/// are not something to show a reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intercept {
    pub verdict: Verdict,
    /// The policy the package looks for (`POLICY_NAME`), when its config names
    /// one. `None` means the policy part of the verdict is unknown.
    pub policy: Option<String>,
    /// Interfaces the rules were attached to (`ISP_INTERFACE`, space separated).
    pub rules_interfaces: Vec<String>,
    /// The interface our own traffic leaves by — the kernel's default route for
    /// the family, which is where a probe to a routable host goes.
    pub our_interface: Option<String>,
}

/// Measures how the `nfqws2` package treats a connection of `family` to
/// `target`.
///
/// `None` when the package is not running on this device — there is nothing to
/// say about interception, and the caller says nothing.
///
/// `target` is optional and only feeds the mark probe: a run whose family has
/// no address for the chosen domain still gets a verdict from the package's own
/// configuration, which is the half that says whether that family is covered at
/// all. The caller resolves addresses — `net/` does not reach into `dns/`.
pub async fn nfqws2(family: Family, target: Option<SocketAddr>) -> Option<Intercept> {
    let pid = pidfile_pid()?;
    let v6 = family == Family::V6;
    // Where our traffic actually goes for this target, then the tunnel question
    // answers itself: a per-destination route into a VPN leaves the interface
    // the rules were hooked to.
    let our_interface = match target {
        Some(target) => route_interface_for(target.ip()),
        None => route_interface_for(if v6 { IpAddr::V6(Ipv6Addr::UNSPECIFIED) } else { IpAddr::V4(Ipv4Addr::UNSPECIFIED) }),
    };
    let Some(conf) = conf_run() else {
        // The package is up but its resolved config is unreadable: say so
        // rather than claim a verdict the numbers do not support.
        return Some(Intercept {
            verdict: Verdict::Unknown,
            policy: None,
            rules_interfaces: Vec::new(),
            our_interface,
        });
    };

    let flow = match target {
        Some(target) => probe_flow(target).await,
        None => Flow::default(),
    };
    let verdict = if flow.mark == Some(MARK_EXCLUDE) {
        Verdict::Excluded
    } else if !conf.queue.is_some_and(queue_bound) {
        // Running, but nothing is listening on its queue: our packets would be
        // accepted straight back out, which is not "processed".
        Verdict::Unknown
    } else if v6 && !conf.ipv6_enabled {
        // The v4 rules can be perfect and this still holds: with IPV6_ENABLED=0
        // the init script installs no ip6tables rules at all.
        Verdict::NotQueued(NotCovered::Ipv6)
    } else if our_interface.is_none() {
        // Without knowing where our traffic leaves by, coverage cannot be
        // judged at all.
        Verdict::Unknown
    } else if !conf.interfaces.contains(our_interface.as_ref()?) {
        // Same verdict either way, different advice: a tunnel is a routing
        // decision, another provider interface is a configuration one.
        let ours = our_interface.as_deref().unwrap_or_default();
        if is_tun_name(ours) {
            Verdict::NotQueued(NotCovered::Tunnel)
        } else {
            Verdict::NotQueued(NotCovered::Interface)
        }
    } else if !target.is_none_or(|addr| conf.ports.contains(&addr.port())) {
        Verdict::NotQueued(NotCovered::Port)
    } else if list_mode(pid) {
        // Interception is fine; the strategy is what decides which targets get
        // the desync. Saying so before a run is the difference between "the
        // bypass does not work" and "these numbers are a mixture".
        Verdict::ListMode
    } else {
        Verdict::Processed
    };
    Some(Intercept { verdict, policy: conf.policy, rules_interfaces: conf.interfaces, our_interface })
}

/// What the kernel says about the probe's own connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Flow {
    /// `ctmark`, when the entry had one.
    mark: Option<u32>,
}

/// Opens a probe connection and reads its own record back.
///
/// A failed or blocked connection is fine: the mark is set on the first packet,
/// so the answer does not depend on the handshake completing. The socket's
/// family is the target's: an IPv6 run must be judged by the IPv6 path, which
/// the package covers separately.
async fn probe_flow(target: SocketAddr) -> Flow {
    for _ in 0..PROBE_ATTEMPTS {
        let v6 = target.is_ipv6();
        let Ok(socket) = (if v6 {
            tokio::net::TcpSocket::new_v6()
        } else {
            tokio::net::TcpSocket::new_v4()
        }) else {
            return Flow::default();
        };
        let bind = if v6 {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        };
        if socket.bind(bind).is_err() {
            return Flow::default();
        }
        let Ok(local) = socket.local_addr() else {
            return Flow::default();
        };
        let _ = tokio::time::timeout(PROBE_WAIT, socket.connect(target)).await;
        if let Some(mark) = conntrack_mark(local.port(), target) {
            return Flow { mark: Some(mark) };
        }
    }
    Flow::default()
}

/// The pid of the package's process, when its pidfile names a live one.
fn pidfile_pid() -> Option<u32> {
    let text = std::fs::read_to_string(PIDFILE).ok()?;
    let pid: String = text.trim().chars().filter(char::is_ascii_digit).collect();
    let pid = pid.parse::<u32>().ok()?;
    std::path::Path::new(&format!("/proc/{pid}")).exists().then_some(pid)
}

/// Whether the running strategy applies the desync to 80/443 only for targets
/// on its own lists.
///
/// Read from the live argv rather than the config: the config holds
/// `NFQWS_EXTRA_ARGS="$MODE_AUTO"`, and it is the argv that shows what that
/// expanded to — plus whatever a custom strategy added on its own, which is the
/// only place a hand-written `--ipset` appears at all. Nothing is written and no
/// packet is sent for this: it is one small file.
fn list_mode(pid: u32) -> bool {
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let args: Vec<String> = raw
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    list_mode_in(&args)
}

/// The parsing half of [`list_mode`], on an argv in memory.
///
/// The package's argument model has profiles: `--new` ends one and starts the
/// next, the `--filter-*` options that follow are the profile's own filters and
/// they all have to match (a `--filter-tcp=443 --filter-l7=tls` profile takes
/// TLS on 443, nothing else). Profiles are tried in order and the first one that
/// matches a connection handles it, so the question is asked of that profile
/// alone: if it desyncs everything it takes, a run's numbers are all from one
/// world, whatever the later profiles do.
fn list_mode_in(args: &[String]) -> bool {
    for profile in profiles(args) {
        if !takes_web(&profile.filters) {
            continue;
        }
        return profile.listed;
    }
    false
}

/// One profile of the argument model.
#[derive(Debug, Default)]
struct Profile {
    filters: Vec<String>,
    /// Carries a positive hostlist or ipset filter.
    listed: bool,
}

/// Splits an argv into profiles on `--new`. Options before the first `--new`
/// are the first profile, which is also where the daemon's own options sit.
fn profiles(args: &[String]) -> Vec<Profile> {
    let mut profiles = vec![Profile::default()];
    for arg in args {
        if arg == "--new" {
            profiles.push(Profile::default());
            continue;
        }
        let profile = profiles.last_mut().expect("at least one profile");
        if arg.starts_with("--filter-") {
            profile.filters.push(arg.clone());
        } else if is_list_filter(arg) {
            profile.listed = true;
        }
    }
    profiles
}

/// Whether a profile's filters would take a TLS connection to port 443 or an
/// HTTP one to port 80 — what a web test sends.
///
/// A profile with no filters of its own takes everything. Ports and L7 are
/// required to match when they are stated; a UDP-only filter is a different
/// protocol from what the tests use.
fn takes_web(filters: &[String]) -> bool {
    let mut tcp = false;
    let mut web_port = false;
    let mut udp_only = false;
    let mut l7 = false;
    let mut web_l7 = false;
    for filter in filters {
        if let Some(ports) = filter.strip_prefix("--filter-tcp=") {
            tcp = true;
            web_port |= ports.split(',').any(|port| matches!(port.trim(), "80" | "443"));
        } else if filter.starts_with("--filter-udp=") {
            udp_only |= !filter.starts_with("--filter-udp=0");
        } else if let Some(names) = filter.strip_prefix("--filter-l7=") {
            l7 = true;
            web_l7 |= names.split(',').any(|name| matches!(name.trim(), "tls" | "http"));
        }
    }
    if udp_only && !tcp {
        return false;
    }
    if tcp && !web_port {
        return false;
    }
    if l7 && !web_l7 {
        return false;
    }
    true
}

/// A *positive* list filter: the exclusions only ever widen what is desynced,
/// and `--ipset-ip=0.0.0.0` is how a strategy says "no single addresses".
fn is_list_filter(arg: &str) -> bool {
    if arg.starts_with("--hostlist-exclude=") || arg.starts_with("--ipset-exclude=") {
        return false;
    }
    if let Some(ip) = arg.strip_prefix("--ipset-ip=") {
        return !matches!(ip, "0.0.0.0" | "::");
    }
    ["--hostlist=", "--hostlist-auto=", "--hostlist-domains=", "--ipset="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

/// The resolved config the init script writes: `KEY=value` or `KEY="value"`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ConfRun {
    queue: Option<u32>,
    /// The access policy the package looks for (`POLICY_NAME`).
    policy: Option<String>,
    /// Interfaces the rules were attached to (`ISP_INTERFACE`, space separated).
    interfaces: Vec<String>,
    /// Destination ports the rules queue (`TCP_PORTS`, `80,443` or `590:600`).
    ports: Vec<u16>,
    /// `IPV6_ENABLED`: with it off, the init script installs no ip6tables rules
    /// and IPv6 traffic goes out untouched no matter what the v4 side does.
    ipv6_enabled: bool,
}

fn conf_run() -> Option<ConfRun> {
    let text = std::fs::read_to_string(CONF_RUN).ok()?;
    Some(parse_conf_run(&text))
}

/// Reads the values this module needs out of the shell-sourced config.
fn parse_conf_run(text: &str) -> ConfRun {
    let mut conf = ConfRun::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        match key.trim() {
            "NFQUEUE_NUM" => conf.queue = value.parse::<u32>().ok(),
            "IPV6_ENABLED" => conf.ipv6_enabled = value.trim() != "0" && !value.trim().is_empty(),
            "POLICY_NAME" => conf.policy = (!value.is_empty()).then(|| value.to_string()),
            "ISP_INTERFACE" => {
                conf.interfaces = value.split_whitespace().map(str::to_string).collect();
            }
            "TCP_PORTS" => conf.ports = parse_ports(value),
            _ => {}
        }
    }
    conf
}

/// `80,443,2053` and `590:600` both appear in the package's config.
fn parse_ports(value: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if let Some((from, to)) = part.split_once([':', '-']) {
            if let (Ok(from), Ok(to)) = (from.trim().parse::<u16>(), to.trim().parse::<u16>()) {
                ports.extend(from..=to);
            }
        } else if let Ok(port) = part.parse::<u16>() {
            ports.push(port);
        }
    }
    ports
}

/// Whether the package bound its queue: one line per bound queue, and the queue
/// number is the first field.
fn queue_bound(queue: u32) -> bool {
    let Ok(text) = std::fs::read_to_string(QUEUE_PROC) else {
        return false;
    };
    queue_lines_contain(&text, queue)
}

/// The parsing half of [`queue_bound`], on a table in memory.
fn queue_lines_contain(table: &str, queue: u32) -> bool {
    table.lines().any(|line| {
        line.split_whitespace().next().and_then(|q| q.parse::<u32>().ok()) == Some(queue)
    })
}

/// The interface our traffic to `target` will leave by.
///
/// A route lookup, not the default route: a VPN is often reached by a
/// per-destination route (`1.1.1.1 dev tun0`), and the default route still
/// points at the provider in that case. Both files below hold the main table,
/// the one our own traffic uses.
///
/// Not covered: policy routing (`ip rule` with a fwmark selecting another
/// table) and the `local` table, so a lookup here can disagree with
/// `ip route get` for the router's own addresses. Those are not the cases a
/// probe of a remote host meets.
fn route_interface_for(target: IpAddr) -> Option<String> {
    match target {
        IpAddr::V4(ip) => {
            let text = std::fs::read_to_string(ROUTE_PROC).ok()?;
            route_lookup_v4(&text, ip)
        }
        IpAddr::V6(ip) => {
            let text = std::fs::read_to_string(ROUTE6_PROC).ok()?;
            route_lookup_v6(&text, ip)
        }
    }
}

/// Longest-prefix match in `/proc/net/route`.
///
/// `Iface Destination Gateway Flags RefCnt Use Metric Mask …`, with the
/// addresses as 32-bit little-endian hex — `004DA8C0` is 192.168.77.0. Ties on
/// prefix length go to the lower metric, as the kernel does.
fn route_lookup_v4(table: &str, target: Ipv4Addr) -> Option<String> {
    let ip = u32::from_be_bytes(target.octets());
    let mut best: Option<(u32, u64, String)> = None;
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(iface), Some(destination), Some(metric), Some(mask)) =
            (fields.first(), fields.get(1), fields.get(6), fields.get(7))
        else {
            continue;
        };
        let (Some(destination), Some(mask)) = (le_hex_u32(destination), le_hex_u32(mask)) else {
            continue;
        };
        if ip & mask != destination {
            continue;
        }
        let metric = u64::from_str_radix(metric, 16).unwrap_or(u64::MAX);
        let prefix = mask.count_ones();
        let better = match &best {
            None => true,
            Some((best_prefix, best_metric, _)) => {
                prefix > *best_prefix || (prefix == *best_prefix && metric < *best_metric)
            }
        };
        if better {
            best = Some((prefix, metric, (*iface).to_string()));
        }
    }
    best.map(|(_, _, iface)| iface)
}

/// A 32-bit address written little-endian in hex, as both route files do it.
fn le_hex_u32(text: &str) -> Option<u32> {
    u32::from_str_radix(text, 16).ok().map(u32::swap_bytes)
}

/// Longest-prefix match in `/proc/net/ipv6_route`.
///
/// `destination/plen source/plen nexthop metric … flags iface`, with the
/// addresses as 32 hex digits in *network* order and the prefix length as two
/// digits, so no byte swapping is needed here.
fn route_lookup_v6(table: &str, target: Ipv6Addr) -> Option<String> {
    let ip = u128::from_be_bytes(target.octets());
    let mut best: Option<(u8, u64, String)> = None;
    for line in table.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(destination), Some(plen), Some(metric), Some(iface)) =
            (fields.first(), fields.get(1), fields.get(5), fields.get(9))
        else {
            continue;
        };
        let (Some(destination), Ok(prefix)) = (hex_u128(destination), u8::from_str_radix(plen, 16))
        else {
            continue;
        };
        if prefix > 128 {
            continue;
        }
        // A /0 route matches everything, and shifting by 128 is not defined.
        let matches = prefix == 0 || {
            let masked = ip >> (128 - prefix) << (128 - prefix);
            masked == destination
        };
        if !matches {
            continue;
        }
        let metric = u64::from_str_radix(metric, 16).unwrap_or(u64::MAX);
        let better = match &best {
            None => true,
            Some((best_prefix, best_metric, _)) => {
                prefix > *best_prefix || (prefix == *best_prefix && metric < *best_metric)
            }
        };
        if better {
            best = Some((prefix, metric, (*iface).to_string()));
        }
    }
    best.map(|(_, _, iface)| iface)
}

/// A 128-bit address written as 32 hex digits.
fn hex_u128(text: &str) -> Option<u128> {
    (text.len() == 32).then(|| u128::from_str_radix(text, 16).ok())?
}

/// `ctmark` of the connection from `local_port` to `target`, if conntrack has it.
fn conntrack_mark(local_port: u16, target: SocketAddr) -> Option<u32> {
    let file = std::fs::File::open(CONNTRACK_PROC).ok()?;
    let reader = BufReader::new(file);
    for line in reader.lines().map_while(Result::ok) {
        if let Some(mark) = parse_conntrack_mark(&line, local_port, target) {
            return Some(mark);
        }
    }
    None
}

/// The mark on the conntrack line describing our connection.
///
/// `None` for any line that is not ours: the entry carries both directions, so
/// the source port alone would also match the reply tuple, whose port is the
/// target's. Only a line of our own address family, for TCP, with our port and
/// the target's port and address, is the connection the probe opened.
///
/// Keenetic adds its own fields to these lines (`nmark=`, `ifw=`, `no_if`), and
/// they are deliberately *not* read as evidence of anything: `no_if` is printed
/// for every locally originated flow, tunnel or not, so it says nothing about
/// where the traffic went. Which interface it left by comes from the routing
/// table instead, per destination.
fn parse_conntrack_mark(line: &str, local_port: u16, target: SocketAddr) -> Option<u32> {
    let family = if target.is_ipv6() { "ipv6" } else { "ipv4" };
    if !line.starts_with(family) || !line.contains(" tcp ") {
        return None;
    }
    let field = |name: &str, value: &str| {
        let wanted = format!("{name}={value}");
        line.split_whitespace().any(|f| f == wanted)
    };
    if !field("sport", &local_port.to_string())
        || !field("dst", &target.ip().to_string())
        || !field("dport", &target.port().to_string())
    {
        return None;
    }
    line.split_whitespace()
        .find_map(|f| f.strip_prefix("mark=").and_then(|v| v.parse::<u32>().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The init script writes these lines verbatim; the queue number, the
    /// policy name, the interfaces and the port list are what this module needs.
    #[test]
    fn conf_run_yields_queue_policy_interfaces_and_ports() {
        let text = "ISP_INTERFACE=\"wan0\"\nIPV6_ENABLED=0\nPOLICY_NAME=\"nfqws\"\n\
                    TCP_PORTS=80,443,1984\nNFQUEUE_NUM=300\n";
        let conf = parse_conf_run(text);
        assert_eq!(conf.queue, Some(300));
        assert_eq!(conf.policy.as_deref(), Some("nfqws"));
        assert_eq!(conf.interfaces, ["wan0"]);
        assert_eq!(conf.ports, [80, 443, 1984]);
    }

    #[test]
    fn conf_run_handles_quote_less_values_and_multiple_interfaces() {
        let conf = parse_conf_run("ISP_INTERFACE=\"wwan0 nwg1\"\nNFQUEUE_NUM=\"512\"\n");
        assert_eq!(conf.queue, Some(512));
        assert_eq!(conf.interfaces, ["wwan0", "nwg1"]);
        assert!(conf.ports.is_empty(), "no TCP_PORTS line");
        assert_eq!(conf.policy, None, "no POLICY_NAME line");
        assert_eq!(parse_conf_run("POLICY_NAME=\"\"\n").policy, None, "an empty name is no name");
    }

    /// Both notations appear in the package's own config: `TCP_PORTS` is a plain
    /// list, `UDP_PORTS` uses ranges.
    #[test]
    fn port_lists_expand_ranges() {
        assert_eq!(parse_ports("80,443"), [80, 443]);
        assert_eq!(parse_ports("590:600"), (590..=600).collect::<Vec<u16>>());
        assert_eq!(parse_ports("590-592,1400"), [590, 591, 592, 1400]);
        assert_eq!(parse_ports(""), Vec::<u16>::new());
        assert_eq!(parse_ports("abc,443"), [443], "garbage is skipped, not fatal");
    }

    /// `IPV6_ENABLED` decides whether the package touches IPv6 at all, and the
    /// init script treats anything but `0` as on.
    #[test]
    fn ipv6_flag_follows_the_config() {
        assert!(parse_conf_run("IPV6_ENABLED=1\n").ipv6_enabled);
        assert!(!parse_conf_run("IPV6_ENABLED=0\n").ipv6_enabled);
        assert!(!parse_conf_run("ISP_INTERFACE=\"wan0\"\n").ipv6_enabled, "absent means off");
    }

    /// The queue file lists bound queues; a queue number that is not there means
    /// nothing is reading it.
    #[test]
    fn queue_bound_only_for_a_listed_queue() {
        let table = "64511    272     0 1     0     0     0    12388  1\n\
                       300    757     0 2 65531     0     0  1247390  1\n";
        assert!(queue_lines_contain(table, 300));
        assert!(queue_lines_contain(table, 64511));
        assert!(!queue_lines_contain(table, 301));
    }

    /// The package's own `MARK_EXCLUDE` is what identifies an excluded flow.
    #[test]
    fn excluded_mark_is_the_one_the_package_sets() {
        assert_eq!(MARK_EXCLUDE, 0x2000_0000);
    }

    /// A real entry from a router: the mark sits beside the tuples, and the same
    /// line carries the reply direction, so a port alone is not enough to
    /// identify the connection the probe opened.
    #[test]
    fn conntrack_mark_requires_the_whole_tuple() {
        let line = "ipv4 2 tcp 6 115 SYN_SENT src=100.64.0.7 dst=31.13.72.174 \
                    sport=56678 dport=443 packets=4 bytes=240 [UNREPLIED] \
                    src=31.13.72.174 dst=100.64.0.7 sport=443 dport=56678 \
                    packets=0 bytes=0 [FASTNAT] mark=0 nmark=256 sc=0 ifw=37 ifl=33 use=2";
        let target: SocketAddr = "31.13.72.174:443".parse().unwrap();
        assert_eq!(parse_conntrack_mark(line, 56678, target), Some(0));
        assert_eq!(parse_conntrack_mark(line, 4711, target), None, "another flow");
        let other_target: SocketAddr = "1.1.1.1:443".parse().unwrap();
        assert_eq!(parse_conntrack_mark(line, 56678, other_target), None, "another host");
        let udp = line.replace("tcp 6", "udp 17");
        assert_eq!(parse_conntrack_mark(&udp, 56678, target), None, "not TCP");
        let v6 = line.replace("ipv4", "ipv6");
        assert_eq!(parse_conntrack_mark(&v6, 56678, target), None, "not the family we probe");
    }

    /// Two records captured on a Keenetic, the provider one and a tunnelled one
    /// for the same kind of probe. Keenetic's own fields differ — `ifw=`/`ifl=`
    /// against `no_if` — and that difference is deliberately *not* used: `no_if`
    /// is printed for every locally originated flow. Only the mark is read here.
    #[test]
    fn keenetic_flow_fields_do_not_change_the_mark() {
        let routed = "ipv4 2 tcp 6 1174 ESTABLISHED src=192.168.77.5 dst=8.8.8.8 \
                      sport=44836 dport=443 packets=1555 bytes=403810 src=8.8.8.8 \
                      dst=100.64.0.7 sport=443 dport=44836 packets=2098 bytes=284515 \
                      [ASSURED] [FASTNAT] [RTCACHE o33/r37] mark=0 nmark=256 sc=0 \
                      ifw=37 ifl=33 mac=00:00:5e:00:53:01 slan attrs= use=2";
        let tunnelled = "ipv4 2 tcp 6 94 SYN_SENT src=172.16.9.2 dst=1.1.1.1 \
                         sport=51447 dport=443 packets=1 bytes=60 [UNREPLIED] src=1.1.1.1 \
                         dst=172.16.9.2 sport=443 dport=51447 packets=0 bytes=0 [FASTNAT] \
                         mark=0 nmark=0 sc=0 nomac swan no_if attrs= use=3";
        let routed_target: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let tunnelled_target: SocketAddr = "1.1.1.1:443".parse().unwrap();
        assert_eq!(parse_conntrack_mark(routed, 44836, routed_target), Some(0));
        assert_eq!(parse_conntrack_mark(tunnelled, 51447, tunnelled_target), Some(0));
    }

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_string()).collect()
    }

    /// The profile layout of a real strategy on a Keenetic: QUIC, then a
    /// discord hostlist on its own ports, then TLS on 443 with no list at all,
    /// then HTTP, and only at the end a profile filtered by ipset. The TLS
    /// profile is the one a web test meets, and it desyncs everything it takes —
    /// so this is *not* list mode, whatever the later profile does.
    #[test]
    fn the_first_profile_that_takes_our_traffic_decides() {
        let real = argv(&[
            "--daemon",
            "--qnum=300",
            "--filter-udp=443",
            "--filter-l7=quic",
            "--lua-desync=fake:blob=quic_initial:repeats=11",
            "--new",
            "--filter-tcp=2053,2083,2087,2096,5222,8443",
            "--hostlist-domains=discord.media",
            "--lua-desync=hostfakesplit:repeats=4",
            "--new",
            "--filter-tcp=443",
            "--filter-l7=tls",
            "--lua-desync=hostfakesplit:repeats=8",
            "--new",
            "--filter-tcp=80",
            "--filter-l7=http",
            "--lua-desync=multisplit:pos=1,3",
            "--new",
            "--ipset=/opt/etc/nfqws2/lists/ipset.list",
            "--ipset-exclude=/opt/etc/nfqws2/lists/ipset_exclude.list",
            "--ipset-ip=0.0.0.0",
            "--new",
        ]);
        assert!(!list_mode_in(&real), "the TLS profile has no list of its own");
    }

    /// The same layout with the list moved onto the TLS profile: now a web run
    /// is half bypassed and half not, which is what the reader has to be told.
    #[test]
    fn a_list_on_the_web_profile_is_list_mode() {
        let listed = argv(&[
            "--filter-udp=443",
            "--filter-l7=quic",
            "--new",
            "--filter-tcp=443",
            "--filter-l7=tls",
            "--ipset=/opt/etc/nfqws2/lists/ipset.list",
            "--lua-desync=hostfakesplit:repeats=8",
            "--new",
        ]);
        assert!(list_mode_in(&listed));
    }

    /// Filters of one profile are all required: a TLS-on-443 profile does not
    /// take what a profile for other ports does, and neither takes another
    /// protocol.
    #[test]
    fn profile_filters_are_taken_together() {
        let other_ports = argv(&["--filter-tcp=2053,5222", "--hostlist=/tmp/user.list"]);
        assert!(!list_mode_in(&other_ports), "not the ports a web test uses");
        let udp = argv(&["--filter-udp=443", "--filter-l7=quic", "--ipset=/tmp/quic.list"]);
        assert!(!list_mode_in(&udp), "a UDP profile is not what a web test meets");
        let other_l7 = argv(&["--filter-tcp=443", "--filter-l7=mtproto", "--ipset=/tmp/x.list"]);
        assert!(!list_mode_in(&other_l7), "not the protocol a web test speaks");
    }

    /// Exclusions never make a profile list-driven, and `--ipset-ip=0.0.0.0` is
    /// how a strategy spells "no single addresses".
    #[test]
    fn exclusions_and_empty_ip_lists_do_not_count() {
        let excluded = argv(&["--filter-tcp=443", "--hostlist-exclude=/tmp/exclude.list"]);
        assert!(!list_mode_in(&excluded));
        let empty_ip = argv(&["--filter-tcp=443", "--ipset-ip=0.0.0.0"]);
        assert!(!list_mode_in(&empty_ip));
        let named = argv(&["--filter-tcp=443", "--hostlist-domains=example.com"]);
        assert!(list_mode_in(&named), "a literal domain list is still a list");
    }

    /// A list in the profile before any `--new` — where the daemon's own options
    /// also live — covers whatever that profile takes.
    #[test]
    fn a_list_in_the_first_profile_counts() {
        let first = argv(&["--hostlist=/tmp/user.list", "--filter-tcp=443"]);
        assert!(list_mode_in(&first));
    }

    /// The main table captured on a Keenetic, with its provider host route and
    /// a VPN host route. A lookup for a destination must pick the interface the
    /// kernel would — the default route is *not* the answer for `1.1.1.1`.
    #[test]
    fn route_lookup_picks_the_interface_for_the_destination() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     ppp0\t00000000\t00000000\t0001\t0\t0\t1000\t00000000\t0\t0\t0\n\
                     tun0\t01010101\t00000000\t0005\t0\t0\t1000\tFFFFFFFF\t0\t0\t0\n\
                     br1\t00004D0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n\
                     ppp0\t097100CB\t00000000\t0005\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n\
                     br0\t004DA8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        let iface = |ip: &str| route_lookup_v4(table, ip.parse().unwrap()).unwrap();
        assert_eq!(iface("1.1.1.1"), "tun0", "a VPN host route wins over the default");
        assert_eq!(iface("194.67.78.213"), "ppp0", "the default route");
        assert_eq!(iface("203.0.113.9"), "ppp0", "its own host route");
        assert_eq!(iface("10.77.0.7"), "br1", "a /24 out of the LAN");
        assert_eq!(iface("192.168.77.50"), "br0");
    }

    /// A table with no matching route has no answer; the caller then says it
    /// cannot tell rather than guessing.
    #[test]
    fn route_lookup_without_a_match_is_none() {
        assert_eq!(route_lookup_v4("Iface\tDestination\n", "1.1.1.1".parse().unwrap()), None);
    }

    /// The v6 table is hex in network order with an explicit prefix length, and
    /// it carries a VPN host route of its own.
    #[test]
    fn ipv6_route_lookup_picks_the_interface_for_the_destination() {
        let table = "20010db8000100020003000400050006 80 00000000000000000000000000000000 00 \
                     00000000000000000000000000000000 00000100 00000000 00000000 00000001 tun0\n\
                     00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
                     00000000000000000000000000000000 000003e8 00000000 00000000 00000001 ppp0\n";
        let iface = |ip: &str| route_lookup_v6(table, ip.parse().unwrap()).unwrap();
        assert_eq!(iface("2001:db8:1:2:3:4:5:6"), "tun0");
        assert_eq!(iface("2001:db8:dead::1"), "ppp0", "anything else falls to ::/0");
    }

    /// An excluded connection is what the package stamps before the queue, so
    /// the mark has to survive parsing unchanged.
    #[test]
    fn excluded_connection_reports_the_exclude_mark() {
        let line = "ipv4 2 tcp 6 431 ESTABLISHED src=10.1.30.5 dst=142.250.74.14 \
                    sport=39122 dport=443 src=142.250.74.14 dst=10.1.30.5 sport=443 \
                    dport=39122 mark=536870912 use=1";
        let target: SocketAddr = "142.250.74.14:443".parse().unwrap();
        assert_eq!(parse_conntrack_mark(line, 39122, target), Some(MARK_EXCLUDE));
    }
}
