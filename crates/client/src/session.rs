//! Tunnel session: the QUIC connection to the first hop plus the handshake that carries the
//! rest of the route to the exit and returns the client's tunnel address.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use magictunnel_common::config::ClientConfig;
use magictunnel_common::proto::{HelloReply, Hop, Resume};
use magictunnel_transport::quinn::{Connection, Endpoint, VarInt};
use magictunnel_transport::{ControlStream, TlsMaterial, XorKey, client_endpoint, connect, hello};

const CLOSE_GRACE: Duration = Duration::from_secs(1);
/// A QUIC handshake needs a few round trips; without this, a dead first hop would only be
/// noticed after the full idle timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Session {
    endpoint: Endpoint,
    pub conn: Connection,
    /// Kept open for the lifetime of the session.
    _control: ControlStream,
    pub tunnel_ip: Ipv4Addr,
    pub prefix_len: u8,
    pub exit_mtu: u16,
    token: Option<String>,
}

impl Session {
    /// Dials the route. `resume` asks the exit for the address of an earlier session.
    pub async fn establish(cfg: &ClientConfig, resume: Option<Resume>) -> anyhow::Result<Self> {
        let tls = TlsMaterial::load(&cfg.tls).context("loading TLS material")?;
        let key = Arc::new(XorKey::new(cfg.obfs.xor_key.as_bytes())?);

        let first = &cfg.route[0];
        let endpoint = client_endpoint(first.addr, key, &tls, &cfg.quic)?;
        let conn = tokio::time::timeout(
            CONNECT_TIMEOUT,
            connect(&endpoint, first.addr, &first.server_name),
        )
        .await
        .map_err(|_| anyhow!("no answer within {}s", CONNECT_TIMEOUT.as_secs()))
        .and_then(|r| r.map_err(Into::into))
        .with_context(|| format!("connecting to {} ({})", first.server_name, first.addr))?;

        let remaining = cfg.route[1..]
            .iter()
            .map(|h| Hop {
                addr: h.addr,
                server_name: h.server_name.clone(),
            })
            .collect();
        let (control, reply) = hello(&conn, remaining, resume)
            .await
            .context("tunnel handshake")?;
        let (tunnel_ip, prefix_len, exit_mtu, token) = match reply {
            HelloReply::Ok {
                tunnel_ip,
                prefix_len,
                mtu,
                token,
            } => (tunnel_ip, prefix_len, mtu, token),
            // Relays prefix the hop they heard it from, so this reads as the path to the failure.
            HelloReply::Err { reason } => {
                bail!("tunnel rejected: {}: {reason}", first.server_name)
            }
        };
        if prefix_len > 32 {
            bail!("exit assigned an invalid prefix length /{prefix_len}");
        }

        Ok(Self {
            endpoint,
            conn,
            _control: control,
            tunnel_ip,
            prefix_len,
            exit_mtu,
            token,
        })
    }

    /// What to present on reconnect to get this session's address back.
    pub fn resume(&self) -> Resume {
        Resume {
            tunnel_ip: self.tunnel_ip,
            token: self.token.clone(),
        }
    }

    /// Closes the connection and gives the close frame a moment to reach the first hop.
    pub async fn close(self) {
        self.conn.close(VarInt::from_u32(0), b"client shutdown");
        let _ = tokio::time::timeout(CLOSE_GRACE, self.endpoint.wait_idle()).await;
    }
}
