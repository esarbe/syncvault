use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid frame: {0}")]
    InvalidFrame(String),
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u16),
    #[error("unauthorized peer device: {0}")]
    UnauthorizedPeer(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ProtocolError>;
