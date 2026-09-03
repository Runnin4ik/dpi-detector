use std::net::{Ipv4Addr, Ipv6Addr};
use url::Host;

use super::types::{DnsError, DnsRecord, DnsResponse};

pub const QTYPE_A: u16 = 1;
pub const QTYPE_NS: u16 = 2;
pub const QTYPE_CNAME: u16 = 5;
pub const QTYPE_SOA: u16 = 6;
pub const QTYPE_PTR: u16 = 12;
pub const QTYPE_MX: u16 = 15;
pub const QTYPE_TXT: u16 = 16;
pub const QTYPE_AAAA: u16 = 28;

pub const CLASS_IN: u16 = 1;

/// Encode domain name labels to RFC 1035 wire format with length prefixes.
pub fn encode_dns_name(domain: &str) -> Result<Vec<u8>, DnsError> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() {
        return Ok(vec![0]);
    }

    // Convert internationalized domains to ASCII punycode
    let ascii_domain = match Host::parse(domain) {
        Ok(Host::Domain(d)) => d,
        _ => domain.to_string(),
    };

    let mut buf = Vec::with_capacity(ascii_domain.len() + 2);
    for label in ascii_domain.split('.') {
        let len = label.len();
        if len == 0 {
            continue;
        }
        if len > 63 {
            return Err(DnsError::LabelTooLong);
        }
        buf.push(len as u8);
        buf.extend_from_slice(label.as_bytes());
    }

    if buf.len() > 255 {
        return Err(DnsError::NameTooLong);
    }

    buf.push(0);
    Ok(buf)
}

/// Construct a raw RFC 1035 DNS query packet.
pub fn build_dns_query(domain: &str, qtype: u16, tx_id: Option<u16>) -> Result<Vec<u8>, DnsError> {
    let tx_id = tx_id.unwrap_or_else(rand::random);
    let qname = encode_dns_name(domain)?;

    let mut packet = Vec::with_capacity(12 + qname.len() + 4);
    // Header (12 bytes)
    packet.extend_from_slice(&tx_id.to_be_bytes()); // ID
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD = 1 (Recursion Desired)
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // Question
    packet.extend_from_slice(&qname);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());

    Ok(packet)
}

/// Skips a DNS name in wire format (including compression pointers).
/// Returns the offset immediately after the name field.
pub fn skip_dns_name(data: &[u8], mut offset: usize) -> Result<usize, DnsError> {
    let len = data.len();
    while offset < len {
        let length_byte = data[offset];
        if (length_byte & 0xC0) == 0xC0 {
            // Pointer is 2 bytes
            if offset + 2 > len {
                return Err(DnsError::Truncated(len));
            }
            return Ok(offset + 2);
        } else if length_byte == 0 {
            return Ok(offset + 1);
        } else {
            let label_len = length_byte as usize;
            offset += 1 + label_len;
            if offset > len {
                return Err(DnsError::Truncated(len));
            }
        }
    }
    Err(DnsError::Truncated(len))
}

/// Reads a DNS name, following compression pointers up to a maximum recursion depth.
/// Returns (decompressed_name, advanced_offset_after_root_pointer).
pub fn read_dns_name(data: &[u8], mut offset: usize) -> Result<(String, usize), DnsError> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next_offset = offset;
    let mut jumps = 0;
    const MAX_JUMPS: usize = 12;

    while offset < data.len() {
        let byte = data[offset];
        if (byte & 0xC0) == 0xC0 {
            if offset + 1 >= data.len() {
                return Err(DnsError::Truncated(data.len()));
            }
            if !jumped {
                next_offset = offset + 2;
                jumped = true;
            }
            let pointer = (((byte & 0x3F) as usize) << 8) | (data[offset + 1] as usize);
            if pointer >= data.len() {
                return Err(DnsError::InvalidPointer(pointer));
            }
            offset = pointer;
            jumps += 1;
            if jumps > MAX_JUMPS {
                return Err(DnsError::PointerLoop);
            }
        } else if byte == 0 {
            if !jumped {
                next_offset = offset + 1;
            }
            break;
        } else {
            let label_len = byte as usize;
            offset += 1;
            if offset + label_len > data.len() {
                return Err(DnsError::Truncated(data.len()));
            }
            let label_str = String::from_utf8_lossy(&data[offset..offset + label_len]).into_owned();
            labels.push(label_str);
            offset += label_len;
        }
    }

    Ok((labels.join("."), next_offset))
}

/// Parses an RFC 1035 DNS response packet.
pub fn parse_dns_response(data: &[u8], expected_tx_id: Option<u16>) -> Result<DnsResponse, DnsError> {
    if data.len() < 12 {
        return Err(DnsError::Truncated(data.len()));
    }

    let tx_id = u16::from_be_bytes([data[0], data[1]]);
    if let Some(expected) = expected_tx_id {
        if tx_id != expected {
            return Err(DnsError::MismatchedTxId {
                expected,
                actual: tx_id,
            });
        }
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let _nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let _arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let rcode = (flags & 0x000F) as u8;
    if rcode == 3 {
        return Err(DnsError::NxDomain);
    } else if rcode != 0 {
        return Err(DnsError::ServerFailure(rcode));
    }

    let mut offset = 12;

    // Skip Question section
    for _ in 0..qdcount {
        offset = skip_dns_name(data, offset)?;
        // skip QTYPE (2) and QCLASS (2)
        if offset + 4 > data.len() {
            return Err(DnsError::Truncated(data.len()));
        }
        offset += 4;
    }

    // Parse Answer section
    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        offset = skip_dns_name(data, offset)?;
        if offset + 10 > data.len() {
            return Err(DnsError::Truncated(data.len()));
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let _rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let _ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > data.len() {
            return Err(DnsError::Truncated(data.len()));
        }

        let rdata = &data[offset..offset + rdlength];

        match rtype {
            QTYPE_A if rdlength == 4 => {
                let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                answers.push(DnsRecord::A(ip));
            }
            QTYPE_AAAA if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                let ip = Ipv6Addr::from(octets);
                answers.push(DnsRecord::AAAA(ip));
            }
            QTYPE_CNAME => {
                let (cname, _) = read_dns_name(data, offset)?;
                answers.push(DnsRecord::CNAME(cname));
            }
            QTYPE_TXT => {
                let mut txt_parts = Vec::new();
                let mut txt_offset = 0;
                while txt_offset < rdlength {
                    let str_len = rdata[txt_offset] as usize;
                    txt_offset += 1;
                    if txt_offset + str_len <= rdlength {
                        let text = String::from_utf8_lossy(&rdata[txt_offset..txt_offset + str_len]).into_owned();
                        txt_parts.push(text);
                        txt_offset += str_len;
                    } else {
                        break;
                    }
                }
                answers.push(DnsRecord::TXT(txt_parts));
            }
            _ => {
                answers.push(DnsRecord::Other {
                    rtype,
                    data: rdata.to_vec(),
                });
            }
        }

        offset += rdlength;
    }

    Ok(DnsResponse {
        tx_id,
        flags,
        rcode,
        answers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dns_query_basic() {
        let query = build_dns_query("example.com", QTYPE_A, Some(0x1234)).unwrap();
        assert_eq!(&query[0..2], &[0x12, 0x34]); // ID
        assert_eq!(&query[2..4], &[0x01, 0x00]); // Flags (RD=1)
        assert_eq!(&query[4..6], &[0x00, 0x01]); // QDCOUNT=1
        assert_eq!(&query[6..12], &[0, 0, 0, 0, 0, 0]);

        // Question: 7'example' 3'com' 0
        assert_eq!(
            &query[12..25],
            &[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
        );
        assert_eq!(&query[25..27], &[0x00, 0x01]); // QTYPE A
        assert_eq!(&query[27..29], &[0x00, 0x01]); // QCLASS IN
    }

    #[test]
    fn test_build_dns_query_idn() {
        let query = build_dns_query("пример.рф", QTYPE_A, Some(0xABCD)).unwrap();
        assert_eq!(&query[0..2], &[0xAB, 0xCD]);
        // Punycode for пример.рф starts with xn--
        let qname = &query[12..query.len() - 4];
        let qname_str = String::from_utf8_lossy(qname);
        assert!(qname_str.contains("xn--"));
    }

    #[test]
    fn test_parse_dns_response_a() {
        let mut response = Vec::new();
        // Header
        response.extend_from_slice(&[0x12, 0x34]); // ID
        response.extend_from_slice(&[0x81, 0x80]); // Flags: QR=1, RD=1, RA=1
        response.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        response.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
        response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

        // Question
        response.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        // Answer
        response.extend_from_slice(&[0xC0, 0x0C]); // Pointer to question name
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TYPE A, CLASS IN
        response.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL 300
        response.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
        response.extend_from_slice(&[93, 184, 216, 34]); // 93.184.216.34

        let parsed = parse_dns_response(&response, Some(0x1234)).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(
            parsed.answers[0],
            DnsRecord::A(Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    #[test]
    fn test_parse_dns_response_aaaa() {
        let mut response = Vec::new();
        response.extend_from_slice(&[0x56, 0x78, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        response.extend_from_slice(&[0xC0, 0x0C]);
        response.extend_from_slice(&[0x00, 0x1C, 0x00, 0x01]); // AAAA, IN
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60
        response.extend_from_slice(&[0x00, 0x10]); // RDLENGTH 16
        // 2606:2800:220:1:248:1893:25c8:1946
        let ipv6 = [0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46];
        response.extend_from_slice(&ipv6);

        let parsed = parse_dns_response(&response, Some(0x5678)).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(
            parsed.answers[0],
            DnsRecord::AAAA(Ipv6Addr::from(ipv6))
        );
    }

    #[test]
    fn test_parse_dns_response_nxdomain() {
        let mut response = Vec::new();
        response.extend_from_slice(&[0x11, 0x22, 0x81, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let err = parse_dns_response(&response, Some(0x1122)).unwrap_err();
        assert_eq!(err, DnsError::NxDomain);
    }

    #[test]
    fn test_parse_dns_response_cname_chain() {
        let mut response = Vec::new();
        response.extend_from_slice(&[0xAA, 0xBB, 0x81, 0x80, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]);
        // Answer 1: CNAME
        response.extend_from_slice(&[3, b'f', b'o', b'o', 0]);
        response.extend_from_slice(&[0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C]);
        let cname_target = [3, b'b', b'a', b'r', 0];
        response.extend_from_slice(&[0x00, cname_target.len() as u8]);
        response.extend_from_slice(&cname_target);
        // Answer 2: A
        response.extend_from_slice(&[0xC0, 0x15]); // pointer to bar
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04]);
        response.extend_from_slice(&[1, 2, 3, 4]);

        let parsed = parse_dns_response(&response, Some(0xAABB)).unwrap();
        assert_eq!(parsed.answers.len(), 2);
        assert_eq!(parsed.answers[0], DnsRecord::CNAME("bar".to_string()));
        assert_eq!(parsed.answers[1], DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn test_parse_txt_response() {
        let mut response = Vec::new();
        response.extend_from_slice(&[0x33, 0x44, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        response.extend_from_slice(&[0xC0, 0x0C]);
        response.extend_from_slice(&[0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C]);
        // TXT rdata: length-prefixed strings: 11'v=spf1 ~all'
        let txt = b"v=spf1 ~all";
        let mut rdata = vec![txt.len() as u8];
        rdata.extend_from_slice(txt);
        response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        response.extend_from_slice(&rdata);

        let parsed = parse_dns_response(&response, Some(0x3344)).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(
            parsed.answers[0],
            DnsRecord::TXT(vec!["v=spf1 ~all".to_string()])
        );
    }
}
