//! Minimal IPv4 header inspection, plus the ICMP "fragmentation needed" message a router
//! sends when a packet with DF set is too big for the next link.

use std::net::Ipv4Addr;

const IPV4_HEADER_LEN: usize = 20;
const PROTO_ICMP: u8 = 1;
const ICMP_HEADER_LEN: usize = 8;
const ICMP_DEST_UNREACHABLE: u8 = 3;
const ICMP_FRAG_NEEDED: u8 = 4;
/// ICMP types 0, 8, 13-18 are queries; everything else reports an error.
const ICMP_QUERY_TYPES: [u8; 8] = [0, 8, 13, 14, 15, 16, 17, 18];
const FLAG_DF: u8 = 0x40;
/// Original datagram quoted back: its IP header plus the first 8 payload bytes (RFC 792),
/// which hold the ports and, for TCP, the sequence number the sender checks.
const QUOTED_PAYLOAD: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Addrs {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

pub fn is_ipv4(packet: &[u8]) -> bool {
    packet.first().is_some_and(|b| b >> 4 == 4)
}

/// Source and destination of an IPv4 packet; `None` for anything else or a truncated header.
pub fn ipv4_addrs(packet: &[u8]) -> Option<Ipv4Addrs> {
    if packet.len() < IPV4_HEADER_LEN || !is_ipv4(packet) {
        return None;
    }
    Some(Ipv4Addrs {
        src: addr_at(packet, 12),
        dst: addr_at(packet, 16),
    })
}

/// The ICMP "fragmentation needed" error for `packet`, advertising `mtu`, addressed back to
/// its sender and sourced from its destination (so it passes reverse-path filtering on the
/// interface it is injected into). `None` when no error may be sent: the packet is not a
/// well-formed IPv4 first fragment with DF set, goes to a broadcast or multicast address, or is
/// itself an ICMP error (RFC 1122 3.2.2).
pub fn frag_needed(packet: &[u8], mtu: u16) -> Option<Vec<u8>> {
    let addrs = ipv4_addrs(packet)?;
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < IPV4_HEADER_LEN || packet.len() < ihl {
        return None;
    }
    let fragment_offset = u16::from_be_bytes([packet[6] & 0x1f, packet[7]]);
    if packet[6] & FLAG_DF == 0 || fragment_offset != 0 {
        return None;
    }
    let unicast = |a: Ipv4Addr| !(a.is_broadcast() || a.is_multicast() || a.is_unspecified());
    if !unicast(addrs.src) || !unicast(addrs.dst) {
        return None;
    }
    if packet[9] == PROTO_ICMP {
        let icmp_type = *packet.get(ihl)?;
        if !ICMP_QUERY_TYPES.contains(&icmp_type) {
            return None;
        }
    }

    let quoted = &packet[..packet.len().min(ihl + QUOTED_PAYLOAD)];
    let total = IPV4_HEADER_LEN + ICMP_HEADER_LEN + quoted.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&[0x45, 0]);
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 64, PROTO_ICMP, 0, 0]);
    out.extend_from_slice(&addrs.dst.octets());
    out.extend_from_slice(&addrs.src.octets());
    let ip_sum = checksum(&out);
    out[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    out.extend_from_slice(&[ICMP_DEST_UNREACHABLE, ICMP_FRAG_NEEDED, 0, 0, 0, 0]);
    out.extend_from_slice(&mtu.to_be_bytes());
    out.extend_from_slice(quoted);
    let icmp_sum = checksum(&out[IPV4_HEADER_LEN..]);
    out[IPV4_HEADER_LEN + 2..IPV4_HEADER_LEN + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    Some(out)
}

fn addr_at(packet: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(packet[at], packet[at + 1], packet[at + 2], packet[at + 3])
}

/// RFC 1071 Internet checksum.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4 header with DF set, followed by `payload`.
    fn packet(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = (IPV4_HEADER_LEN + payload.len()) as u16;
        let mut p = vec![0x45, 0];
        p.extend(total.to_be_bytes());
        p.extend([0x12, 0x34, FLAG_DF, 0, 64, proto, 0, 0]);
        p.extend(src);
        p.extend(dst);
        let sum = checksum(&p);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        p.extend(payload);
        p
    }

    fn tcp(src: [u8; 4], dst: [u8; 4], len: usize) -> Vec<u8> {
        let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
        packet(6, src, dst, &payload)
    }

    #[test]
    fn reads_addresses() {
        let p = tcp([10, 88, 0, 2], [1, 1, 1, 1], 20);
        assert_eq!(
            ipv4_addrs(&p),
            Some(Ipv4Addrs {
                src: Ipv4Addr::new(10, 88, 0, 2),
                dst: Ipv4Addr::new(1, 1, 1, 1),
            })
        );
    }

    #[test]
    fn rejects_other_versions_and_short_packets() {
        let mut v6 = tcp([0; 4], [0; 4], 0);
        v6[0] = 0x60;
        assert_eq!(ipv4_addrs(&v6), None);
        assert!(!is_ipv4(&v6));
        assert_eq!(ipv4_addrs(&tcp([0; 4], [0; 4], 0)[..19]), None);
        assert_eq!(ipv4_addrs(&[]), None);
        assert!(!is_ipv4(&[]));
    }

    #[test]
    fn builds_frag_needed() {
        let original = tcp([10, 88, 0, 2], [198, 51, 100, 80], 1400);
        let icmp = frag_needed(&original, 1180).unwrap();

        assert_eq!(icmp.len(), 20 + 8 + 20 + 8);
        assert_eq!(checksum(&icmp[..20]), 0, "IP header checksum");
        assert_eq!(checksum(&icmp[20..]), 0, "ICMP checksum");
        let addrs = ipv4_addrs(&icmp).unwrap();
        assert_eq!(addrs.src, Ipv4Addr::new(198, 51, 100, 80));
        assert_eq!(addrs.dst, Ipv4Addr::new(10, 88, 0, 2));
        assert_eq!(icmp[9], PROTO_ICMP);
        assert_eq!(&icmp[20..22], &[ICMP_DEST_UNREACHABLE, ICMP_FRAG_NEEDED]);
        assert_eq!(u16::from_be_bytes([icmp[26], icmp[27]]), 1180);
        assert_eq!(&icmp[28..], &original[..28]);
    }

    #[test]
    fn quotes_short_packets_whole() {
        let original = tcp([10, 88, 0, 2], [1, 1, 1, 1], 3);
        let icmp = frag_needed(&original, 1180).unwrap();
        assert_eq!(&icmp[28..], &original[..]);
    }

    #[test]
    fn only_answers_where_a_router_would() {
        let (a, b) = ([10, 88, 0, 2], [1, 1, 1, 1]);
        let mut no_df = tcp(a, b, 100);
        no_df[6] = 0;
        assert_eq!(frag_needed(&no_df, 1180), None);

        let mut later_fragment = tcp(a, b, 100);
        later_fragment[7] = 1;
        assert_eq!(frag_needed(&later_fragment, 1180), None);

        assert_eq!(frag_needed(&tcp(a, [255; 4], 100), 1180), None);
        assert_eq!(frag_needed(&tcp(a, [224, 0, 0, 1], 100), 1180), None);

        let echo_request = packet(PROTO_ICMP, a, b, &[8, 0, 0, 0, 0, 1, 0, 1]);
        assert!(frag_needed(&echo_request, 1180).is_some());
        let unreachable = packet(PROTO_ICMP, a, b, &[3, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(frag_needed(&unreachable, 1180), None);

        let mut bad_ihl = tcp(a, b, 100);
        bad_ihl[0] = 0x44;
        assert_eq!(frag_needed(&bad_ihl, 1180), None);
        assert_eq!(frag_needed(&tcp(a, b, 0)[..19], 1180), None);
    }
}
