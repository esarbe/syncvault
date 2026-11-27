use std::io;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use custom_protocol::{negotiate_client, negotiate_server, CustomSession, ProtocolError};
use syncthing_core::DeviceId;
use syncthing_net::tls::{accept_tls_stream_with_alpn, connect_tls_stream_with_alpn};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsStream;

use super::{config::RuntimeConfig, CUSTOM_ALPN, PROTOCOL_TIMEOUT};

pub type Session = CustomSession<TlsStream<TcpStream>>;

pub async fn establish(
    stream: TcpStream,
    runtime: &RuntimeConfig,
    expected_peer: Option<DeviceId>,
    server: bool,
) -> Result<Session> {
    timeout(PROTOCOL_TIMEOUT, async {
        let (mut stream, peer_id) = if server {
            let (stream, peer_id) =
                accept_tls_stream_with_alpn(stream, &runtime.tls, CUSTOM_ALPN).await?;
            (TlsStream::Server(stream), peer_id)
        } else {
            let (stream, peer_id) =
                connect_tls_stream_with_alpn(stream, &runtime.tls, expected_peer, CUSTOM_ALPN)
                    .await?;
            (TlsStream::Client(stream), peer_id)
        };
        if expected_peer.is_some_and(|expected| expected != peer_id) {
            bail!("TLS peer device ID mismatch: got {peer_id}");
        }
        if !runtime.is_trusted(peer_id) {
            bail!("peer {peer_id} is not configured or is paused");
        }
        if server {
            negotiate_server(
                &mut stream,
                runtime.local_id,
                Some(peer_id),
                vec!["text".to_string()],
            )
            .await?;
        } else {
            negotiate_client(
                &mut stream,
                runtime.local_id,
                Some(peer_id),
                vec!["text".to_string()],
            )
            .await?;
        }
        Ok(CustomSession::new(stream, peer_id, runtime.local_id))
    })
    .await
    .context("peer handshake timed out")?
}

pub async fn receive(mut session: Session) -> Result<()> {
    let peer_id = session.peer_id();
    loop {
        match timeout(Duration::from_secs(120), session.receive_payload())
            .await
            .context("idle peer timed out")?
        {
            Ok(payload) if payload.payload_type == "text" => {
                println!("[{peer_id}] {}", String::from_utf8(payload.payload)?);
            }
            Ok(payload) => {
                eprintln!("[{peer_id}] ignored payload type {}", payload.payload_type);
            }
            Err(ProtocolError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
    }
}
