use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

use super::types::DnsError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksProxyConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Parses a socks5:// or socks5h:// proxy URL.
pub fn parse_socks_proxy(proxy_url: &str) -> Result<SocksProxyConfig, DnsError> {
    let parsed = Url::parse(proxy_url)
        .map_err(|e| DnsError::Socks5(format!("invalid proxy URL: {}", e)))?;

    let scheme = parsed.scheme();
    if scheme != "socks5" && scheme != "socks5h" {
        return Err(DnsError::Socks5(format!(
            "unsupported proxy scheme: '{}', expected socks5:// or socks5h://",
            scheme
        )));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| DnsError::Socks5("missing proxy host".to_string()))?
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();

    let port = parsed.port().unwrap_or(1080);
    let username = if !parsed.username().is_empty() {
        Some(urlencoding_decode(parsed.username()))
    } else {
        None
    };
    let password = parsed.password().map(urlencoding_decode);

    Ok(SocksProxyConfig {
        host,
        port,
        username,
        password,
    })
}

fn urlencoding_decode(s: &str) -> String {
    url::form_urlencoded::parse(s.as_bytes())
        .map(|(k, _)| k.into_owned())
        .next()
        .unwrap_or_else(|| s.to_string())
}

/// Wraps a raw DNS payload in an RFC 1928 SOCKS5 UDP request header.
pub fn wrap_socks_udp(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(10 + payload.len());
    packet.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV (2 bytes) + FRAG (0x00)

    match target {
        SocketAddr::V4(v4) => {
            packet.push(0x01); // ATYP IPv4
            packet.extend_from_slice(&v4.ip().octets());
            packet.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            packet.push(0x04); // ATYP IPv6
            packet.extend_from_slice(&v6.ip().octets());
            packet.extend_from_slice(&v6.port().to_be_bytes());
        }
    }

    packet.extend_from_slice(payload);
    packet
}

/// Unwraps an RFC 1928 SOCKS5 UDP relay response header, returning the raw payload.
pub fn unwrap_socks_udp(data: &[u8]) -> Result<&[u8], DnsError> {
    if data.len() < 7 {
        return Err(DnsError::Socks5("datagram too short for SOCKS5 UDP header".to_string()));
    }

    // Byte 0-1: RSV, Byte 2: FRAG
    let atyp = data[3];
    let payload_offset = match atyp {
        0x01 => 4 + 4 + 2, // IPv4: 4 bytes IP + 2 bytes port = 10
        0x04 => 4 + 16 + 2, // IPv6: 16 bytes IP + 2 bytes port = 22
        0x03 => {
            let domain_len = data[4] as usize;
            4 + 1 + domain_len + 2
        }
        _ => return Err(DnsError::Socks5(format!("unknown ATYP: {:#x}", atyp))),
    };

    if data.len() < payload_offset {
        return Err(DnsError::Socks5("truncated SOCKS5 UDP datagram".to_string()));
    }

    Ok(&data[payload_offset..])
}

/// Establishes SOCKS5 UDP association and returns the UDP relay endpoint address.
pub async fn associate_socks5_udp(
    proxy: &SocksProxyConfig,
) -> Result<(SocketAddr, TcpStream), DnsError> {
    let addr = format!("{}:{}", proxy.host, proxy.port);
    let mut tcp = TcpStream::connect(&addr)
        .await
        .map_err(|e| DnsError::Socks5(format!("TCP connect to {} failed: {}", addr, e)))?;

    // 1. Handshake
    if proxy.username.is_some() && proxy.password.is_some() {
        // Offer NO AUTH (0x00) and USER/PASS (0x02)
        tcp.write_all(&[0x05, 0x02, 0x00, 0x02])
            .await
            .map_err(|e| DnsError::Socks5(e.to_string()))?;
    } else {
        // Offer NO AUTH (0x00)
        tcp.write_all(&[0x05, 0x01, 0x00])
            .await
            .map_err(|e| DnsError::Socks5(e.to_string()))?;
    }

    let mut resp = [0u8; 2];
    tcp.read_exact(&mut resp)
        .await
        .map_err(|e| DnsError::Socks5(e.to_string()))?;

    if resp[0] != 0x05 {
        return Err(DnsError::Socks5("invalid SOCKS5 version in greeting response".to_string()));
    }

    if resp[1] == 0x02 {
        // User/password auth
        let u = proxy.username.as_deref().unwrap_or("");
        let p = proxy.password.as_deref().unwrap_or("");
        let mut auth_req = Vec::new();
        auth_req.push(0x01); // Auth sub-negotiation version
        auth_req.push(u.len() as u8);
        auth_req.extend_from_slice(u.as_bytes());
        auth_req.push(p.len() as u8);
        auth_req.extend_from_slice(p.as_bytes());

        tcp.write_all(&auth_req)
            .await
            .map_err(|e| DnsError::Socks5(e.to_string()))?;

        let mut auth_resp = [0u8; 2];
        tcp.read_exact(&mut auth_resp)
            .await
            .map_err(|e| DnsError::Socks5(e.to_string()))?;

        if auth_resp[1] != 0x00 {
            return Err(DnsError::Socks5("SOCKS5 authentication failed".to_string()));
        }
    } else if resp[1] != 0x00 {
        return Err(DnsError::Socks5(format!(
            "SOCKS5 server rejected auth methods: method {:#x}",
            resp[1]
        )));
    }

    // 2. Send UDP ASSOCIATE command: 0x05, 0x03, 0x00, 0x01, 0.0.0.0, port 0
    tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|e| DnsError::Socks5(e.to_string()))?;

    let mut reply_hdr = [0u8; 4];
    tcp.read_exact(&mut reply_hdr)
        .await
        .map_err(|e| DnsError::Socks5(e.to_string()))?;

    if reply_hdr[1] != 0x00 {
        return Err(DnsError::Socks5(format!(
            "SOCKS5 UDP ASSOCIATE rejected with error code {:#x}",
            reply_hdr[1]
        )));
    }

    let bnd_addr: IpAddr = match reply_hdr[3] {
        0x01 => {
            let mut ip_buf = [0u8; 4];
            tcp.read_exact(&mut ip_buf)
                .await
                .map_err(|e| DnsError::Socks5(e.to_string()))?;
            IpAddr::V4(Ipv4Addr::from(ip_buf))
        }
        0x04 => {
            let mut ip_buf = [0u8; 16];
            tcp.read_exact(&mut ip_buf)
                .await
                .map_err(|e| DnsError::Socks5(e.to_string()))?;
            IpAddr::V6(Ipv6Addr::from(ip_buf))
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            tcp.read_exact(&mut len_buf)
                .await
                .map_err(|e| DnsError::Socks5(e.to_string()))?;
            let mut domain_buf = vec![0u8; len_buf[0] as usize];
            tcp.read_exact(&mut domain_buf)
                .await
                .map_err(|e| DnsError::Socks5(e.to_string()))?;
            let domain = String::from_utf8_lossy(&domain_buf);
            return Err(DnsError::Socks5(format!(
                "SOCKS5 UDP BND.ADDR returned as domain '{}', expected IP",
                domain
            )));
        }
        atyp => return Err(DnsError::Socks5(format!("unexpected BND.ATYP: {:#x}", atyp))),
    };

    let mut port_buf = [0u8; 2];
    tcp.read_exact(&mut port_buf)
        .await
        .map_err(|e| DnsError::Socks5(e.to_string()))?;
    let bnd_port = u16::from_be_bytes(port_buf);

    let relay_addr = if bnd_addr.is_unspecified() {
        // If server returns 0.0.0.0, use the proxy server's IP
        let peer = tcp.peer_addr().map_err(|e| DnsError::Io(e.to_string()))?;
        SocketAddr::new(peer.ip(), bnd_port)
    } else {
        SocketAddr::new(bnd_addr, bnd_port)
    };

    Ok((relay_addr, tcp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socks_proxy_url() {
        let p1 = parse_socks_proxy("socks5://127.0.0.1:1080").unwrap();
        assert_eq!(p1.host, "127.0.0.1");
        assert_eq!(p1.port, 1080);
        assert_eq!(p1.username, None);

        let p2 = parse_socks_proxy("socks5h://user:pass@[::1]:9050").unwrap();
        assert_eq!(p2.host, "::1");
        assert_eq!(p2.port, 9050);
        assert_eq!(p2.username, Some("user".to_string()));
        assert_eq!(p2.password, Some("pass".to_string()));
    }

    #[test]
    fn test_wrap_and_unwrap_socks_udp() {
        let target: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let payload = b"hello dns wire";
        let wrapped = wrap_socks_udp(target, payload);

        assert_eq!(&wrapped[0..3], &[0x00, 0x00, 0x00]);
        assert_eq!(wrapped[3], 0x01); // IPv4
        assert_eq!(&wrapped[4..8], &[1, 1, 1, 1]);
        assert_eq!(&wrapped[8..10], &53u16.to_be_bytes());
        assert_eq!(&wrapped[10..], payload);

        let unwrapped = unwrap_socks_udp(&wrapped).unwrap();
        assert_eq!(unwrapped, payload);
    }
}
