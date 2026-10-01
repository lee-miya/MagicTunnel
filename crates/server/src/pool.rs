//! Tunnel address pool of the exit: the first host address belongs to the exit TUN, every
//! other host address can be leased to one client at a time.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

#[derive(Debug)]
pub struct IpPool {
    net: Ipv4Net,
    first: u32,
    last: u32,
    /// Where the next search starts. Allocation moves forward through the pool instead of
    /// reusing the lowest free address, so a just-released address (which may still have
    /// packets in flight or conntrack entries) is not handed to the next client right away.
    next: u32,
    leased: HashSet<u32>,
}

impl IpPool {
    /// `net` must leave room for the gateway and at least one client (prefix length <= 30).
    pub fn new(net: Ipv4Net) -> Self {
        let net = net.trunc();
        assert!(net.prefix_len() <= 30, "pool {net} has no client addresses");
        let first = u32::from(net.network()) + 2;
        Self {
            net,
            first,
            last: u32::from(net.broadcast()) - 1,
            next: first,
            leased: HashSet::new(),
        }
    }

    pub fn net(&self) -> Ipv4Net {
        self.net
    }

    /// Address of the exit's own TUN interface.
    pub fn gateway(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.net.network()) + 1)
    }

    pub fn capacity(&self) -> usize {
        (self.last - self.first + 1) as usize
    }

    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        if self.leased.len() >= self.capacity() {
            return None;
        }
        let mut candidate = self.next;
        while self.leased.contains(&candidate) {
            candidate = self.wrap_next(candidate);
        }
        self.leased.insert(candidate);
        self.next = self.wrap_next(candidate);
        Some(Ipv4Addr::from(candidate))
    }

    /// Leases `addr` itself if it is a free client address of the pool.
    pub fn reserve(&mut self, addr: Ipv4Addr) -> bool {
        let addr = u32::from(addr);
        (self.first..=self.last).contains(&addr) && self.leased.insert(addr)
    }

    pub fn leased(&self) -> usize {
        self.leased.len()
    }

    pub fn release(&mut self, addr: Ipv4Addr) {
        self.leased.remove(&u32::from(addr));
    }

    fn wrap_next(&self, addr: u32) -> u32 {
        if addr >= self.last {
            self.first
        } else {
            addr + 1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(net: &str) -> IpPool {
        IpPool::new(net.parse().unwrap())
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn reserves_network_gateway_and_broadcast() {
        let mut p = pool("10.88.0.0/29");
        assert_eq!(p.gateway(), ip("10.88.0.1"));
        assert_eq!(p.capacity(), 5);
        let leased: Vec<_> = std::iter::from_fn(|| p.allocate()).collect();
        assert_eq!(
            leased,
            [
                "10.88.0.2",
                "10.88.0.3",
                "10.88.0.4",
                "10.88.0.5",
                "10.88.0.6"
            ]
            .map(ip)
        );
        assert_eq!(p.allocate(), None);
    }

    #[test]
    fn ignores_host_bits_in_config() {
        let p = pool("10.88.0.77/24");
        assert_eq!(p.net(), "10.88.0.0/24".parse().unwrap());
        assert_eq!(p.gateway(), ip("10.88.0.1"));
    }

    #[test]
    fn smallest_pool_has_one_client() {
        let mut p = pool("10.88.0.0/30");
        assert_eq!(p.allocate(), Some(ip("10.88.0.2")));
        assert_eq!(p.allocate(), None);
        p.release(ip("10.88.0.2"));
        assert_eq!(p.allocate(), Some(ip("10.88.0.2")));
    }

    #[test]
    fn reserves_only_free_client_addresses() {
        let mut p = pool("10.88.0.0/29");
        for outside in ["10.88.0.0", "10.88.0.1", "10.88.0.7", "10.88.1.2"] {
            assert!(!p.reserve(ip(outside)), "{outside}");
        }
        assert!(p.reserve(ip("10.88.0.4")));
        assert!(!p.reserve(ip("10.88.0.4")));
        assert_eq!(p.leased(), 1);
        // Next-fit allocation skips the reserved address.
        let rest: Vec<_> = std::iter::from_fn(|| p.allocate()).collect();
        assert_eq!(
            rest,
            ["10.88.0.2", "10.88.0.3", "10.88.0.5", "10.88.0.6"].map(ip)
        );
    }

    #[test]
    fn does_not_reuse_released_address_immediately() {
        let mut p = pool("10.88.0.0/29");
        let a = p.allocate().unwrap();
        let b = p.allocate().unwrap();
        p.release(a);
        assert_eq!(p.allocate(), Some(ip("10.88.0.4")));
        p.release(b);
        // Wraps around once the end of the pool is reached, skipping leased addresses.
        assert_eq!(p.allocate(), Some(ip("10.88.0.5")));
        assert_eq!(p.allocate(), Some(ip("10.88.0.6")));
        assert_eq!(p.allocate(), Some(a));
        assert_eq!(p.allocate(), Some(b));
        assert_eq!(p.allocate(), None);
    }
}
