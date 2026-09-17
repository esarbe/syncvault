use serde::{Deserialize, Serialize};
use syncthing_core::DeviceId;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{ProtocolError, Result};
use crate::frame::{read_frame, write_frame, Frame};
use crate::{MAX_FRAME_SIZE, PROTOCOL_NAME, PROTOCOL_VERSION};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientHello {
    pub protocol: String,
    pub version: u16,
    pub device_id: DeviceId,
    pub capabilities: Vec<String>,
    pub max_frame_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerHello {
    pub protocol: String,
    pub version: u16,
    pub device_id: DeviceId,
    pub capabilities: Vec<String>,
    pub max_frame_size: usize,
}

pub async fn negotiate_client<S>(
    stream: &mut S,
    local_device_id: DeviceId,
    expected_peer: Option<DeviceId>,
    capabilities: Vec<String>,
) -> Result<ServerHello>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hello = ClientHello {
        protocol: PROTOCOL_NAME.to_string(),
        version: PROTOCOL_VERSION,
        device_id: local_device_id,
        capabilities,
        max_frame_size: MAX_FRAME_SIZE,
    };
    send_json(stream, &hello).await?;
    let response: ServerHello = receive_json(stream).await?;
    validate_hello(
        &response.protocol,
        response.version,
        response.max_frame_size,
    )?;
    verify_peer(response.device_id, expected_peer)?;
    Ok(response)
}

pub async fn negotiate_server<S>(
    stream: &mut S,
    local_device_id: DeviceId,
    expected_peer: Option<DeviceId>,
    capabilities: Vec<String>,
) -> Result<ClientHello>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request: ClientHello = receive_json(stream).await?;
    validate_hello(&request.protocol, request.version, request.max_frame_size)?;
    verify_peer(request.device_id, expected_peer)?;

    let response = ServerHello {
        protocol: PROTOCOL_NAME.to_string(),
        version: PROTOCOL_VERSION,
        device_id: local_device_id,
        capabilities,
        max_frame_size: MAX_FRAME_SIZE,
    };
    send_json(stream, &response).await?;
    Ok(request)
}

fn validate_hello(protocol: &str, version: u16, max_frame_size: usize) -> Result<()> {
    if protocol != PROTOCOL_NAME {
        return Err(ProtocolError::Protocol(format!(
            "expected {}, got {}",
            PROTOCOL_NAME, protocol
        )));
    }
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    if max_frame_size == 0 || max_frame_size > MAX_FRAME_SIZE {
        return Err(ProtocolError::InvalidFrame(
            "peer frame limit is unacceptable".to_string(),
        ));
    }
    Ok(())
}

fn verify_peer(peer: DeviceId, expected: Option<DeviceId>) -> Result<()> {
    if expected.is_some_and(|expected| expected != peer) {
        return Err(ProtocolError::UnauthorizedPeer(peer.to_string()));
    }
    Ok(())
}

async fn send_json<S, T>(stream: &mut S, value: &T) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: Serialize,
{
    let frame = Frame::new(serde_json::to_vec(value)?)?;
    write_frame(stream, &frame).await
}

async fn receive_json<S, T>(stream: &mut S) -> Result<T>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let frame = read_frame(stream, MAX_FRAME_SIZE).await?;
    serde_json::from_slice(&frame.payload)
        .map_err(|error| ProtocolError::InvalidMessage(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn client_and_server_authorize_each_other() {
        let (mut client_stream, mut server_stream) = duplex(4096);
        let client_id = DeviceId::random();
        let server_id = DeviceId::random();

        let server = tokio::spawn(async move {
            negotiate_server(
                &mut server_stream,
                server_id,
                Some(client_id),
                vec!["payload".to_string()],
            )
            .await
        });
        let response = negotiate_client(
            &mut client_stream,
            client_id,
            Some(server_id),
            vec!["payload".to_string()],
        )
        .await
        .unwrap();

        assert_eq!(response.device_id, server_id);
        assert_eq!(server.await.unwrap().unwrap().device_id, client_id);
    }

    #[tokio::test]
    async fn rejects_unauthorized_peer() {
        let (mut client_stream, mut server_stream) = duplex(4096);
        let client_id = DeviceId::random();
        let server_id = DeviceId::random();

        let server = tokio::spawn(async move {
            negotiate_server(
                &mut server_stream,
                server_id,
                Some(DeviceId::random()),
                Vec::new(),
            )
            .await
        });
        let client_result = negotiate_client(&mut client_stream, client_id, None, Vec::new()).await;

        assert!(client_result.is_err());
        assert!(matches!(
            server.await.unwrap(),
            Err(ProtocolError::UnauthorizedPeer(_))
        ));
    }
}
