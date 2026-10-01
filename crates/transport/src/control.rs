//! Reliable control channel: the single bidirectional stream of a connection, opened by the
//! dialing side. Messages are JSON, each prefixed with its length as a big-endian `u32`.

use std::time::Duration;

use magictunnel_common::proto::{Hello, HelloReply, Hop, PROTOCOL_VERSION};
use quinn::{Connection, ReadExactError, RecvStream, SendStream};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{Error, Result};

pub const MAX_FRAME_LEN: usize = 64 * 1024;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct ControlStream {
    send: SendStream,
    recv: RecvStream,
}

impl ControlStream {
    /// Opens the control stream. The peer only sees it once the first message is sent.
    pub async fn open(conn: &Connection) -> Result<Self> {
        let (send, recv) = conn.open_bi().await?;
        Ok(Self { send, recv })
    }

    pub async fn accept(conn: &Connection) -> Result<Self> {
        let (send, recv) = conn.accept_bi().await?;
        Ok(Self { send, recv })
    }

    pub async fn send<T: Serialize>(&mut self, msg: &T) -> Result<()> {
        let mut frame = vec![0; 4];
        serde_json::to_writer(&mut frame, msg)?;
        let len = frame.len() - 4;
        if len > MAX_FRAME_LEN {
            return Err(Error::FrameTooLarge(len));
        }
        frame[..4].copy_from_slice(&(len as u32).to_be_bytes());
        self.send.write_all(&frame).await?;
        Ok(())
    }

    pub async fn recv<T: DeserializeOwned>(&mut self) -> Result<T> {
        let mut len = [0; 4];
        self.recv.read_exact(&mut len).await.map_err(|e| match e {
            ReadExactError::FinishedEarly(0) => Error::ControlClosed,
            e => e.into(),
        })?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_FRAME_LEN {
            return Err(Error::FrameTooLarge(len));
        }
        let mut body = vec![0; len];
        self.recv.read_exact(&mut body).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    /// Gracefully ends our side of the stream.
    pub fn finish(&mut self) {
        let _ = self.send.finish();
    }
}

/// Dialing side of the handshake: tells the peer which hops follow it and waits for the
/// exit's reply (relayed back hop by hop).
pub async fn hello(conn: &Connection, remaining: Vec<Hop>) -> Result<(ControlStream, HelloReply)> {
    with_timeout(async {
        let mut control = ControlStream::open(conn).await?;
        control
            .send(&Hello {
                version: PROTOCOL_VERSION,
                remaining,
            })
            .await?;
        let reply = control.recv().await?;
        Ok((control, reply))
    })
    .await
}

/// Accepting side of the handshake: waits for the peer's [`Hello`]. A version mismatch is
/// answered with [`HelloReply::Err`] and returned as an error; any other reply is up to the
/// caller.
pub async fn accept_hello(conn: &Connection) -> Result<(ControlStream, Hello)> {
    with_timeout(async {
        let mut control = ControlStream::accept(conn).await?;
        let hello: Hello = control.recv().await?;
        if hello.version != PROTOCOL_VERSION {
            let reason = format!("unsupported protocol version {}", hello.version);
            control.send(&HelloReply::Err { reason }).await?;
            control.finish();
            return Err(Error::VersionMismatch(hello.version));
        }
        Ok((control, hello))
    })
    .await
}

async fn with_timeout<T>(fut: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| Error::HandshakeTimeout)?
}
