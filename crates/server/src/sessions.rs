//! Session table of the exit: maps each leased tunnel address to the client connection that
//! owns it, so packets coming back out of the exit TUN find their way home.
//!
//! Every lease comes with a random token. A reconnecting client presents address and token to
//! get the same address back, even before the exit has noticed that the old connection is
//! dead. Keeping the address keeps the exit's NAT state valid, so the client's TCP
//! connections survive the reconnect.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock, RwLockReadGuard};

use ipnet::Ipv4Net;
use magictunnel_common::proto::Resume;
use magictunnel_transport::quinn::Connection;
use magictunnel_transport::quinn::rustls::crypto::ring::default_provider;

use crate::pool::IpPool;

const TOKEN_BYTES: usize = 16;

/// Generic over the connection type only so that tests can do without QUIC.
#[derive(Debug)]
pub struct Sessions<C = Connection> {
    net: Ipv4Net,
    gateway: Ipv4Addr,
    capacity: usize,
    inner: RwLock<Inner<C>>,
}

#[derive(Debug)]
struct Inner<C> {
    pool: IpPool,
    conns: HashMap<Ipv4Addr, Entry<C>>,
    next_lease: u64,
}

#[derive(Debug)]
struct Entry<C> {
    conn: C,
    lease: u64,
    token: String,
}

/// A granted tunnel address.
#[derive(Debug)]
pub struct Grant<C = Connection> {
    pub lease: Lease<C>,
    pub token: String,
    /// Whether the client got the address it asked to resume.
    pub resumed: bool,
    /// The previous holder of a resumed address, for the caller to disconnect.
    pub displaced: Option<C>,
}

impl<C: Clone> Sessions<C> {
    pub fn new(pool: IpPool) -> Arc<Self> {
        Arc::new(Self {
            net: pool.net(),
            gateway: pool.gateway(),
            capacity: pool.capacity(),
            inner: RwLock::new(Inner {
                pool,
                conns: HashMap::new(),
                next_lease: 0,
            }),
        })
    }

    pub fn net(&self) -> Ipv4Net {
        self.net
    }

    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    /// Leased and total client addresses.
    pub fn usage(&self) -> (usize, usize) {
        (self.read().pool.leased(), self.capacity)
    }

    /// Leases a tunnel address to `conn`: the one `resume` asks for if it is free or its
    /// token matches the current holder, otherwise the next free one. `None` when the pool
    /// is exhausted.
    ///
    /// A resumed address keeps the token the client presented: if the reply carrying the
    /// token is lost, the client still holds the one that gets the address back next time.
    pub fn register(self: &Arc<Self>, conn: C, resume: Option<&Resume>) -> Option<Grant<C>> {
        let mut inner = self.inner.write().expect("session table poisoned");
        let (addr, token, resumed, displaced) = match resume.and_then(|r| inner.claim(r)) {
            Some((addr, token, displaced)) => (addr, token, true, displaced),
            None => (inner.pool.allocate()?, new_token(), false, None),
        };
        let id = inner.next_lease;
        inner.next_lease += 1;
        let entry = Entry {
            conn,
            lease: id,
            token: token.clone(),
        };
        inner.conns.insert(addr, entry);
        Some(Grant {
            lease: Lease {
                sessions: Arc::clone(self),
                addr,
                id,
            },
            token,
            resumed,
            displaced,
        })
    }

    pub fn lookup(&self, addr: Ipv4Addr) -> Option<C> {
        self.read().conns.get(&addr).map(|e| e.conn.clone())
    }

    fn read(&self) -> RwLockReadGuard<'_, Inner<C>> {
        self.inner.read().expect("session table poisoned")
    }
}

impl<C: Clone> Inner<C> {
    /// The address `resume` asks for, its token, and the connection it is taken from, if any.
    fn claim(&mut self, resume: &Resume) -> Option<(Ipv4Addr, String, Option<C>)> {
        let addr = resume.tunnel_ip;
        if self.pool.reserve(addr) {
            let token = resume
                .token
                .clone()
                .filter(|t| is_token(t))
                .unwrap_or_else(new_token);
            return Some((addr, token, None));
        }
        let entry = self.conns.get(&addr)?;
        let owner = resume.token.as_deref() == Some(entry.token.as_str());
        owner.then(|| (addr, entry.token.clone(), Some(entry.conn.clone())))
    }
}

/// A client's claim on its tunnel address; dropping it ends the session's routing unless the
/// address has been handed to a resumed session in the meantime.
#[derive(Debug)]
pub struct Lease<C = Connection> {
    sessions: Arc<Sessions<C>>,
    addr: Ipv4Addr,
    id: u64,
}

impl<C> Lease<C> {
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }
}

impl<C> Drop for Lease<C> {
    fn drop(&mut self) {
        let mut inner = self.sessions.inner.write().expect("session table poisoned");
        if inner
            .conns
            .get(&self.addr)
            .is_some_and(|e| e.lease == self.id)
        {
            inner.conns.remove(&self.addr);
            inner.pool.release(self.addr);
        }
    }
}

fn new_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    default_provider()
        .secure_random
        .fill(&mut bytes)
        .expect("system random number generator failed");
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Whether `token` looks like one [`new_token`] makes.
fn is_token(token: &str) -> bool {
    token.len() == 2 * TOKEN_BYTES
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sessions() -> Arc<Sessions<&'static str>> {
        Sessions::new(IpPool::new("10.88.0.0/29".parse().unwrap()))
    }

    fn resume(ip: &str, token: Option<&str>) -> Resume {
        Resume {
            tunnel_ip: ip.parse().unwrap(),
            token: token.map(String::from),
        }
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn hands_out_unique_addresses_and_tokens() {
        let s = sessions();
        let a = s.register("a", None).unwrap();
        let b = s.register("b", None).unwrap();
        assert_ne!(a.lease.addr(), b.lease.addr());
        assert_ne!(a.token, b.token);
        assert_eq!(a.token.len(), 2 * TOKEN_BYTES);
        assert_eq!(s.lookup(a.lease.addr()), Some("a"));
        assert_eq!(s.usage(), (2, 5));
        drop(a);
        assert_eq!(s.usage(), (1, 5));
    }

    #[test]
    fn resumes_a_free_address_without_token() {
        let s = sessions();
        let g = s.register("a", Some(&resume("10.88.0.5", None))).unwrap();
        assert_eq!((g.lease.addr(), g.resumed), (ip("10.88.0.5"), true));
        assert!(g.displaced.is_none());
    }

    #[test]
    fn takes_over_a_live_address_only_with_its_token() {
        let s = sessions();
        let old = s.register("old", None).unwrap();
        let addr = old.lease.addr();

        let thief = s
            .register("thief", Some(&resume(&addr.to_string(), Some("guess"))))
            .unwrap();
        assert_ne!(thief.lease.addr(), addr);
        assert!(!thief.resumed);

        let new = s
            .register("new", Some(&resume(&addr.to_string(), Some(&old.token))))
            .unwrap();
        assert_eq!(
            (new.lease.addr(), new.resumed, new.displaced),
            (addr, true, Some("old"))
        );
        assert_eq!(new.token, old.token);
        assert_eq!(s.lookup(addr), Some("new"));

        // The old session ending must not take the address from the new one.
        drop(old);
        assert_eq!(s.lookup(addr), Some("new"));
        drop(new);
        assert_eq!(s.lookup(addr), None);
        assert_eq!(s.usage(), (1, 5));
    }

    #[test]
    fn resuming_keeps_the_token_when_a_reply_is_lost() {
        let s = sessions();
        let first = s.register("first", None).unwrap();
        let (addr, token) = (first.lease.addr().to_string(), first.token.clone());
        // The client never sees the reply to its first reconnect and retries with the same
        // token while that connection still holds the address.
        let lost = s
            .register("lost", Some(&resume(&addr, Some(&token))))
            .unwrap();
        let retry = s
            .register("retry", Some(&resume(&addr, Some(&token))))
            .unwrap();
        assert_eq!(
            (retry.lease.addr(), retry.resumed, retry.displaced),
            (first.lease.addr(), true, Some("lost"))
        );
        assert_eq!((&lost.token, &retry.token), (&token, &token));
    }

    #[test]
    fn a_free_address_adopts_a_well_formed_token() {
        let s = sessions();
        let token = "0123456789abcdef0123456789abcdef";
        let g = s
            .register("a", Some(&resume("10.88.0.5", Some(token))))
            .unwrap();
        assert_eq!(g.token, token);
        for bad in ["short", "0123456789ABCDEF0123456789ABCDEF"] {
            let g = s
                .register("b", Some(&resume("10.88.0.6", Some(bad))))
                .unwrap();
            assert!(g.resumed);
            assert_ne!(g.token, bad);
            assert!(is_token(&g.token));
            drop(g);
        }
    }

    #[test]
    fn falls_back_for_addresses_outside_the_pool() {
        let s = sessions();
        for addr in ["10.88.0.1", "10.88.0.7", "192.0.2.1"] {
            let g = s.register("a", Some(&resume(addr, None))).unwrap();
            assert!(!g.resumed, "{addr}");
            assert_ne!(g.lease.addr(), ip(addr));
        }
    }
}
