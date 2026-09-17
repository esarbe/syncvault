use serde::de::DeserializeOwned;
use serde::Serialize;
use syncthing_core::DeviceId;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{ProtocolError, Result};
use crate::frame::{read_frame, write_frame, Frame};
use crate::message::{Message, MessageType, PayloadAck, SendPayload};
use crate::MAX_FRAME_SIZE;

pub struct CustomSession<S> {
    stream: S,
    peer_id: DeviceId,
    local_id: DeviceId,
    max_frame_size: usize,
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
        }
    }

    pub fn peer_id(&self) -> DeviceId {
        self.peer_id
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            self.handle_one().await?;
        }
    }

    pub async fn handle_one(&mut self) -> Result<()> {
        let frame = read_frame(&mut self.stream, self.max_frame_size).await?;
        let message: Message = decode(&frame)?;
        if message.sender != self.peer_id {
            return Err(ProtocolError::UnauthorizedPeer(message.sender.to_string()));
        }

        let response = match message.message_type {
            MessageType::SendPayload => {
                let _: SendPayload = decode_payload(&message)?;
                Message {
                    id: uuid::Uuid::new_v4(),
                    sender: self.local_id,
                    message_type: MessageType::PayloadAck,
                    payload: encode(&PayloadAck {
                        message_id: message.id,
                    })?,
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
}
