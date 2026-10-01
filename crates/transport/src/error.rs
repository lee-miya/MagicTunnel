pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Common(#[from] magictunnel_common::Error),

    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("TLS configuration error")]
    Tls(#[from] rustls::Error),

    #[error("invalid client certificate verifier")]
    ClientVerifier(#[from] rustls::server::VerifierBuilderError),

    #[error("TLS configuration is not usable for QUIC")]
    QuicCrypto(#[from] quinn::crypto::rustls::NoInitialCipherSuite),

    #[error("obfs.xor_key must not be empty")]
    EmptyXorKey,

    #[error("failed to start connecting")]
    Connect(#[from] quinn::ConnectError),

    #[error("connection failed")]
    Connection(#[from] quinn::ConnectionError),

    #[error("peer does not accept datagrams")]
    DatagramsUnsupported,

    #[error("failed to send datagram")]
    Datagram(#[from] quinn::SendDatagramError),

    #[error("control stream write failed")]
    ControlWrite(#[from] quinn::WriteError),

    #[error("control stream read failed")]
    ControlRead(#[from] quinn::ReadExactError),

    #[error("control stream closed by peer")]
    ControlClosed,

    #[error("control message of {0} bytes exceeds the frame limit")]
    FrameTooLarge(usize),

    #[error("malformed control message")]
    Codec(#[from] serde_json::Error),

    #[error("control handshake timed out")]
    HandshakeTimeout,

    #[error("peer speaks protocol version {0}, expected {expected}", expected = magictunnel_common::proto::PROTOCOL_VERSION)]
    VersionMismatch(u16),
}
