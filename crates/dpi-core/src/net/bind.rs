//! Which interface the probes leave through.
//!
//! By default the routing table decides, and that is what every run did before
//! this module existed: `target()` returns `None` and each dial takes the path it
//! always took, so nothing here can change a run that did not ask for it.
//!
//! A chosen interface binds every socket to one of its addresses before the
//! connect, and that address is the whole mechanism: the source of a packet is
//! what the OS routes by — the routing table on a plain box, the policy rules on a
//! router that splits traffic by source — so binding it is what makes the probes
//! leave through that interface. It needs no privilege and behaves the same on
//! Windows and on the Entware/MIPS builds.
//!
//! `SO_BINDTODEVICE` was tried as well and removed: it restricts the route lookup
//! to that device, which *overrides* the policy rules a Keenetic uses to send a
//! tunnel's traffic — a tunnel with no route of its own in the main table then
//! fails with `Network is unreachable` (measured on the router, 2026-09-18) where
//! the address bind alone lets the policy pick the tunnel. It also wants
//! `CAP_NET_RAW`, which the address bind does not.
//!
//! The choice is process-wide and set once at startup, the way the VT/ASCII mode
//! is: a run probes one network, and the probes that dial through
//! (`net::tcp::dial_tcp`, `net::http_client`, `dns::doh`, `dns::dot`,
//! `dns::udp`, `probe::telegram`) do not carry a config they could read it from.

// The interface list comes from OS calls — `getifaddrs` on unix,
// `GetAdaptersAddresses` and a Win32 wide-string read on Windows — so `unsafe`
// is the FFI boundary here rather than an escape hatch; every block names the
// invariant it holds in a SAFETY note.
#![allow(
    unsafe_code,
    reason = "OS FFI: getifaddrs/GetAdaptersAddresses and the Win32 string read, each guarded by a SAFETY note"
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::LazyLock;

use parking_lot::RwLock;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// One interface as the OS reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
    /// False for an interface the OS reports as down: listed, but a name that
    /// matches more than one interface prefers the up one.
    pub up: bool,
}

impl Interface {
    /// Every address a bind could use, v4 first — the order the menu offers them.
    pub fn addrs(&self) -> Vec<IpAddr> {
        self.v4
            .iter()
            .copied()
            .map(IpAddr::V4)
            .chain(self.v6.iter().copied().map(IpAddr::V6))
            .collect()
    }

    /// The line the menu shows: name, then the address a probe would leave from.
    pub fn label(&self) -> String {
        match self.addrs().first() {
            Some(addr) => format!("{} ({})", self.name, addr),
            None => self.name.clone(),
        }
    }
}

/// What a chosen interface means for a socket: the addresses to bind and the
/// device to name on Linux.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindTarget {
    pub name: String,
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
    /// Kept as the interface's label for the messages that report the choice.
    pub label: String,
}

impl BindTarget {
    /// The local address to bind for a destination of this family, if the
    /// interface has one.
    pub fn local(&self, dest: &SocketAddr) -> Option<SocketAddr> {
        match dest {
            SocketAddr::V4(_) => self.v4.map(|ip| SocketAddr::from((ip, 0))),
            SocketAddr::V6(_) => self.v6.map(|ip| SocketAddr::from((ip, 0))),
        }
    }
}

/// The address to bind `dest` from — `None` when nothing was chosen, or when the
/// choice has no address of the destination's family.
pub fn local_for(dest: &SocketAddr) -> Option<SocketAddr> {
    // Read through the guard: `local` only borrows, and this is the call every
    // dial and every UDP socket makes, so an owned copy of the target would be
    // two `String` allocations per probe for nothing.
    TARGET.read().as_ref().and_then(|t| t.local(dest))
}

/// The interface every socket should leave through, or `None` for the routing
/// table. The menu and the tests want the value, not a borrow of it; the dial
/// path reads the guard directly ([`local_for`]).
pub fn target() -> Option<BindTarget> {
    TARGET.read().clone()
}

/// Chooses the interface for this process. Called once at startup, before the
/// first probe; `None` puts the run back on the routing table.
pub fn set_target(next: Option<BindTarget>) {
    *TARGET.write() = next;
}

static TARGET: LazyLock<RwLock<Option<BindTarget>>> = LazyLock::new(|| RwLock::new(None));

/// Every interface the OS reports, the ones that are up first: a machine with
/// Hyper-V or WSL installed reports a dozen adapters nobody asked for, and the
/// one the user means is the one carrying traffic. Loopback and down interfaces
/// stay in the list — a selector that hides what the OS knows is a selector that
/// lies, and `resolve` has nothing to offer for an interface without an address
/// anyway.
pub fn interfaces() -> Vec<Interface> {
    let mut list = platform::interfaces();
    list.sort_by_key(|iface| !iface.up);
    list
}

#[cfg(unix)]
mod platform {
    use super::Interface;
    use std::ffi::CStr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    pub(super) fn interfaces() -> Vec<Interface> {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: `getifaddrs` either fails or fills `head` with a list that
        // `freeifaddrs` releases at the end of this function.
        if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
            return Vec::new();
        }
        let mut out: Vec<Interface> = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            // SAFETY: `cur` walks the list `getifaddrs` returned until its NULL end.
            let entry = unsafe { &*cur };
            if !entry.ifa_name.is_null() && !entry.ifa_addr.is_null() {
                // SAFETY: `ifa_name` is NUL-terminated and lives as long as the entry.
                let name = unsafe { CStr::from_ptr(entry.ifa_name) }.to_string_lossy().into_owned();
                // SAFETY: `ifa_addr` points at a sockaddr whose family is read first.
                let family = unsafe { (*entry.ifa_addr).sa_family } as libc::c_int;
                let up = flags_up(entry);
                let slot = match out.iter_mut().find(|i| i.name == name) {
                    Some(slot) => slot,
                    None => out.push_mut(Interface { name, v4: Vec::new(), v6: Vec::new(), up }),
                };
                match family {
                    // SAFETY: the family was just read from this same sockaddr.
                    libc::AF_INET => unsafe {
                        let sin = &*(entry.ifa_addr as *const libc::sockaddr_in);
                        slot.v4.push(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
                    },
                    // SAFETY: as above.
                    libc::AF_INET6 => unsafe {
                        let sin6 = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                        slot.v6.push(Ipv6Addr::from(sin6.sin6_addr.s6_addr));
                    },
                    _ => {}
                }
            }
            cur = entry.ifa_next;
        }
        // SAFETY: the list came from `getifaddrs` and nothing reads it past here.
        unsafe { libc::freeifaddrs(head) };
        out
    }

    #[cfg(target_os = "linux")]
    fn flags_up(entry: &libc::ifaddrs) -> bool {
        entry.ifa_flags & libc::IFF_UP as u32 != 0
    }

    /// The BSDs report the link state through `ioctl` rather than on the entry.
    /// This build only targets Linux and Windows; the arm exists so another unix
    /// target would claim less than it knows instead of more.
    #[cfg(not(target_os = "linux"))]
    fn flags_up(_entry: &libc::ifaddrs) -> bool {
        true
    }
}

#[cfg(windows)]
mod platform {
    use super::Interface;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    /// The adapter list the kernel itself reports — `GetAdaptersAddresses`, the
    /// same call `ipconfig` and every other tool on the box makes. The registry
    /// keeps `Connection` names and old leases, but a disabled adapter's stale
    /// address is still in there and two adapters can look like they own the same
    /// one; only the kernel knows which address is live right now, and a bind on
    /// a stale address is a silent failure.
    pub(super) fn interfaces() -> Vec<Interface> {
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let flags = flags | GAA_FLAG_INCLUDE_PREFIX;
        let mut size: u32 = 16 * 1024;
        let mut buf: Vec<u8> = vec![0; size as usize];
        // SAFETY: `buf` is `size` bytes and `GetAdaptersAddresses` writes no more
        // than it reports; the second call after ERROR_BUFFER_OVERFLOW gets the
        // size the first one asked for.
        let mut ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if ret == ERROR_BUFFER_OVERFLOW {
            buf = vec![0; size as usize];
            ret = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    flags,
                    std::ptr::null_mut(),
                    buf.as_mut_ptr().cast(),
                    &mut size,
                )
            };
        }
        if ret != NO_ERROR {
            return Vec::new();
        }

        // `IF_OPER_STATUS` from `windows-sys` is `i32`, and `IfOperStatusUp` is 1.
        const IF_OPER_STATUS_UP: i32 = 1;
        let mut out = Vec::new();
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            // SAFETY: `cur` walks the list the call wrote into `buf`.
            let adapter = unsafe { &*cur };
            // SAFETY: `FriendlyName` is a NUL-terminated wide string owned by `buf`.
            let name = unsafe {
                let mut len = 0usize;
                while *adapter.FriendlyName.add(len) != 0 {
                    len += 1;
                }
                String::from_utf16_lossy(std::slice::from_raw_parts(adapter.FriendlyName, len))
            };
            let mut iface = Interface {
                name,
                v4: Vec::new(),
                v6: Vec::new(),
                up: adapter.OperStatus == IF_OPER_STATUS_UP,
            };
            let mut unicast = adapter.FirstUnicastAddress;
            while !unicast.is_null() {
                // SAFETY: `unicast` walks the list the call wrote into `buf`.
                let entry = unsafe { &*unicast };
                let sockaddr = entry.Address.lpSockaddr;
                if !sockaddr.is_null() {
                    // SAFETY: `lpSockaddr` points at a sockaddr of the family it names.
                    match unsafe { (*sockaddr).sa_family } {
                        // SAFETY: the family was just read from this sockaddr.
                        AF_INET => unsafe {
                            let sin = &*(sockaddr as *const SOCKADDR_IN);
                            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.S_un.S_addr));
                            if !ip.is_unspecified() && !ip.is_loopback() {
                                iface.v4.push(ip);
                            }
                        },
                        // SAFETY: as above.
                        AF_INET6 => unsafe {
                            let sin6 = &*(sockaddr as *const SOCKADDR_IN6);
                            let ip = Ipv6Addr::from(sin6.sin6_addr.u.Byte);
                            if !ip.is_unspecified() {
                                iface.v6.push(ip);
                            }
                        },
                        _ => {}
                    }
                }
                unicast = entry.Next;
            }
            if !iface.v4.is_empty() || !iface.v6.is_empty() {
                out.push(iface);
            }
            cur = adapter.Next;
        }
        out
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::Interface;

    pub(super) fn interfaces() -> Vec<Interface> {
        Vec::new()
    }
}

/// Resolves what the user typed — an interface name, or one of its addresses —
/// into the bind every socket will use. `None` when nothing matches, which is
/// what makes a typo visible instead of silently testing the default route.
pub fn resolve(sel: &str) -> Option<BindTarget> {
    let want = sel.trim();
    if want.is_empty() {
        return None;
    }
    let list = interfaces();
    let by_name = |exact: bool| {
        list.iter()
            .filter(|i| {
                if exact {
                    i.name == want
                } else {
                    i.name.eq_ignore_ascii_case(want)
                }
            })
            // A name can repeat — two adapters, one of them down. The up one is
            // the one the user means.
            .max_by_key(|i| i.up)
    };
    let named = by_name(true).or_else(|| by_name(false));
    let by_addr = || {
        want.parse::<IpAddr>().ok().and_then(|ip| {
            list.iter().find(|i| match ip {
                IpAddr::V4(v4) => i.v4.contains(&v4),
                IpAddr::V6(v6) => i.v6.contains(&v6),
            })
        })
    };
    target_of(named.or_else(by_addr)?)
}

fn target_of(iface: &Interface) -> Option<BindTarget> {
    if iface.v4.is_empty() && iface.v6.is_empty() {
        return None;
    }
    Some(BindTarget {
        name: iface.name.clone(),
        v4: iface.v4.first().copied(),
        v6: iface.v6.first().copied(),
        label: iface.label(),
    })
}

/// Connects to `addr` through the chosen interface, or the way the OS would have
/// connected without one.
pub async fn tcp_connect(addr: &SocketAddr) -> std::io::Result<TcpStream> {
    let Some(local) = local_for(addr) else {
        return TcpStream::connect(addr).await;
    };
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.bind(local)?;
    socket.connect(*addr).await
}

/// Connects to a `host:port` through the chosen interface. Without a choice this
/// is the resolving connect the callers used before, name for name; with one it
/// resolves first and binds each candidate, which is the only way the bind can
/// happen before the connect.
pub async fn connect_host(host: &str, port: u16) -> std::io::Result<TcpStream> {
    // The guard answers the only question here — is an interface chosen — so
    // the target is not copied out of it.
    if TARGET.read().is_none() {
        return TcpStream::connect((host, port)).await;
    }
    let mut last: Option<std::io::Error> = None;
    for addr in tokio::net::lookup_host((host, port)).await? {
        match tcp_connect(&addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no address to connect to")
    }))
}

/// A UDP socket that will leave through the chosen interface when `peer` is the
/// destination. Without a choice it is the unspecified bind every caller did
/// before this module existed.
pub async fn udp_socket(peer: &SocketAddr) -> std::io::Result<UdpSocket> {
    let bind_addr = local_for(peer).unwrap_or_else(|| match peer {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    });
    let socket = UdpSocket::bind(bind_addr).await?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A selection that matches nothing resolves to nothing. That is what makes a
    /// typo fatal at startup instead of a run that quietly tested the default
    /// route while the user watched for the tunnel.
    #[test]
    fn an_unknown_selection_resolves_to_nothing() {
        assert!(resolve("").is_none());
        assert!(resolve("   ").is_none());
        assert!(resolve("no-such-interface-2791").is_none());
    }

    /// Whatever the OS lists with an address can be chosen by its name or by that
    /// address, and the two agree: the menu row and `--iface` are one choice
    /// spelled two ways.
    #[test]
    fn a_listed_interface_resolves_by_name_and_by_address() {
        for iface in interfaces() {
            let Some(target) = resolve(&iface.name) else {
                continue; // an interface with no address is not selectable
            };
            assert_eq!(target.name, iface.name);
            let addr = iface
                .addrs()
                .first()
                .copied()
                .expect("resolving means it had an address");
            let by_addr = resolve(&addr.to_string())
                .unwrap_or_else(|| panic!("{addr} belongs to {} and must resolve", iface.name));
            assert_eq!(by_addr.name, iface.name, "{addr}");
        }
    }

    /// Without a target no local address is produced, so every socket keeps the
    /// path it took before this module existed; with one, the address follows the
    /// destination's family and nothing is bound for the family the interface
    /// does not have.
    #[test]
    fn an_untargeted_run_binds_nothing() {
        set_target(None);
        let v4: SocketAddr = "192.0.2.1:443".parse().expect("documentation address");
        let v6: SocketAddr = "[2001:db8::1]:443".parse().expect("documentation address");
        assert!(local_for(&v4).is_none());
        assert!(local_for(&v6).is_none());

        let chosen = BindTarget {
            name: "example0".to_string(),
            v4: Some("192.0.2.7".parse().expect("documentation address")),
            v6: None,
            label: "example0 (192.0.2.7)".to_string(),
        };
        set_target(Some(chosen));
        assert_eq!(local_for(&v4), Some("192.0.2.7:0".parse().expect("documentation address")));
        assert!(local_for(&v6).is_none(), "this interface has no v6 address to bind");

        set_target(None);
        assert!(local_for(&v4).is_none(), "clearing the target puts the sockets back");
    }
}
