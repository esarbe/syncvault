pub mod config;
pub mod direct;
pub mod discovery;
pub mod relay;
pub mod session;

pub const CUSTOM_ALPN: &[u8] = b"st-custom/1";
pub const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub const PROTOCOL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub const MAX_CONNECTIONS: usize = 64;
