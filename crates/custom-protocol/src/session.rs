use serde::de::DeserializeOwned;
use serde::Serialize;
use syncthing_core::DeviceId;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{timeout, Duration};

use crate::error::{ProtocolError, Result};
use crate::frame::{read_frame, write_frame, Frame};
use crate::message::{Message, MessageType, PayloadAck, SendPayload};
use crate::MAX_FRAME_SIZE;

pub const SESSION_IO_TIMEOUT: Duration = Duration::from_secs(30);

pub struct CustomSession<S> {
    stream: S,
    peer_id: DeviceId,
    local_id: DeviceId,
    max_frame_size: usize,
    io_timeout: Duration,
}

impl<S> CustomSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S, peer_id: DeviceId, local_id: DeviceId) -> Self {
        Self {
            stream,
            peer_id,
            local_id,
            max_frame_size: MAX_FRAME_SIZE,
            io_timeout: SESSION_IO_TIMEOUT,
        }
    }

    pub fn with_io_timeout(mut self, io_timeout: Duration) -> Self {
        self.io_timeout = io_timeout;
        self
    }

    pub fn peer_id(&self) -> DeviceId {
        self.peer_id
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            timeout(self.io_timeout, self.handle_one())
                .await
                .map_err(|_| ProtocolError::Timeout("waiting for session message".to_string()))??;
        }
    }

    pub async fn handle_one(&mut self) -> Result<()> {
        let frame = read_frame(&mut self.stream, self.max_frame_size).await?;
        let message: Message = decode(&frame)?;
        message.validate()?;
        if message.sender != self.peer_id {
            return Err(ProtocolError::UnauthorizedPeer(message.sender.to_string()));
        }

        let response = match message.message_type {
            MessageType::SendPayload => {
                let payload: SendPayload = decode_payload(&message)?;
                if payload.payload_type.is_empty() {
                    return Err(ProtocolError::InvalidMessage(
                        "payload type must not be empty".to_string(),
                    ));
                }
                let ack_payload = encode(&PayloadAck {
                    message_id: message.id,
                })?;
                Message {
                    version: crate::message::MESSAGE_VERSION,
                    id: uuid::Uuid::new_v4(),
                    sender: self.local_id,
                    message_type: MessageType::PayloadAck,
                    flags: 0,
                    payload_length: ack_payload.len(),
                    payload: ack_payload,
                }
            }
            MessageType::PayloadAck => {
                return Err(ProtocolError::InvalidMessage(
                    "a session cannot acknowledge an acknowledgement".to_string(),
                ));
            }
        };

        write_frame(&mut self.stream, &Frame::new(encode(&response)?)?).await
    }

    pub async fn send_payload(
        &mut self,
        payload_type: String,
        payload: Vec<u8>,
    ) -> Result<PayloadAck> {
        timeout(
            self.io_timeout,
            self.send_payload_inner(payload_type, payload),
        )
        .await
        .map_err(|_| ProtocolError::Timeout("sending payload".to_string()))?
    }

    async fn send_payload_inner(
        &mut self,
        payload_type: String,
        payload: Vec<u8>,
    ) -> Result<PayloadAck> {
        let message = Message::send_payload(self.local_id, payload_type, payload)?;
        write_frame(&mut self.stream, &Frame::new(encode(&message)?)?).await?;

        let response = read_frame(&mut self.stream, self.max_frame_size).await?;
        let response: Message = decode(&response)?;
        response.validate()?;
        if response.sender != self.peer_id || response.message_type != MessageType::PayloadAck {
            return Err(ProtocolError::InvalidMessage(
                "expected a payload acknowledgement from the authenticated peer".to_string(),
            ));
        }

        let ack: PayloadAck = decode_payload(&response)?;
        if ack.message_id != message.id {
            return Err(ProtocolError::InvalidMessage(
                "payload acknowledgement does not match the request".to_string(),
            ));
        }
        Ok(ack)
    }
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

fn decode<T: DeserializeOwned>(frame: &Frame) -> Result<T> {
    serde_json::from_slice(&frame.payload)
        .map_err(|error| ProtocolError::InvalidMessage(error.to_string()))
}

fn decode_payload<T: DeserializeOwned>(message: &Message) -> Result<T> {
    serde_json::from_slice(&message.payload)
        .map_err(|error| ProtocolError::InvalidMessage(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::PayloadAck;
    use tokio::io::duplex;

    #[tokio::test]
    async fn sends_ack_for_payload() {
        let (mut client, server) = duplex(4096);
        let client_id = DeviceId::random();
        let server_id = DeviceId::random();
        let mut session = CustomSession::new(server, client_id, server_id);
        let message =
            Message::send_payload(client_id, "text".to_string(), b"hello".to_vec()).unwrap();

        let request = Frame::new(serde_json::to_vec(&message).unwrap()).unwrap();
        write_frame(&mut client, &request).await.unwrap();
        session.handle_one().await.unwrap();

        let response = read_frame(&mut client, MAX_FRAME_SIZE).await.unwrap();
        let response: Message = decode(&response).unwrap();
        assert_eq!(response.sender, server_id);
        assert_eq!(response.message_type, MessageType::PayloadAck);
        let ack: PayloadAck = decode_payload(&response).unwrap();
        assert_eq!(ack.message_id, message.id);
    }

    #[tokio::test]
    async fn terminates_idle_session_after_timeout() {
        let (_client, server) = duplex(4096);
        let session = CustomSession::new(server, DeviceId::random(), DeviceId::random())
            .with_io_timeout(Duration::from_millis(1));

        assert!(matches!(
            session.run().await,
            Err(ProtocolError::Timeout(_))
        ));
    }
}
