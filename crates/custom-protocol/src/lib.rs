//! Standalone application protocol for Syncthing-compatible transports.
//!
//! This crate deliberately has no dependency on `bep-protocol`. It defines the
//! wire format and session semantics that a future custom transport can use.

pub mod connection;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod message;
pub mod session;

pub use connection::CustomConnection;
pub use error::{ProtocolError, Result};
pub use frame::{read_frame, write_frame, Frame, DEFAULT_MAX_FRAME_SIZE};
pub use handshake::{negotiate_client, negotiate_server, ClientHello, ServerHello};
pub use message::{Message, MessageType, PayloadAck, SendPayload};
pub use session::CustomSession;

pub const PROTOCOL_NAME: &str = "st-custom";
pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_SIZE: usize = 128 * 1024;
