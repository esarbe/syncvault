use syncthing_core::DeviceId;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::session::CustomSession;

/// A custom-protocol stream after its transport has authenticated the peer.
///
/// TLS and TCP setup stay outside this crate. The transport supplies the peer
/// identity, and this wrapper makes that identity available to the session.
pub struct CustomConnection<S> {
    stream: S,
    peer_id: DeviceId,
}

impl<S> CustomConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S, peer_id: DeviceId) -> Self {
        Self { stream, peer_id }
    }

    pub fn peer_id(&self) -> DeviceId {
        self.peer_id
    }

    pub fn into_session(self, local_id: DeviceId) -> CustomSession<S> {
        CustomSession::new(self.stream, self.peer_id, local_id)
    }
}
