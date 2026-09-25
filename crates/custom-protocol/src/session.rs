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
            self.receive_payload().await?;
        }
    }

    pub async fn handle_one(&mut self) -> Result<()> {
        self.receive_payload().await.map(|_| ())
    }

    /// Sends a typed payload and waits for the peer to acknowledge its message ID.
    pub async fn send_payload(
        &mut self,
        payload_type: String,
        payload: Vec<u8>,
    ) -> Result<PayloadAck> {
        let message = Message::send_payload(self.local_id, payload_type, payload)?;
        write_frame(&mut self.stream, &Frame::new(encode(&message)?)?).await?;

        let frame = read_frame(&mut self.stream, self.max_frame_size).await?;
        let response: Message = decode(&frame)?;
        if response.sender != self.peer_id {
            return Err(ProtocolError::UnauthorizedPeer(response.sender.to_string()));
        }
        if response.message_type != MessageType::PayloadAck {
            return Err(ProtocolError::InvalidMessage(
                "expected a payload acknowledgement".to_string(),
            ));
        }

        let ack: PayloadAck = decode_payload(&response)?;
        if ack.message_id != message.id {
            return Err(ProtocolError::InvalidMessage(
                "acknowledgement references a different message".to_string(),
            ));
        }
        Ok(ack)
    }

    /// Receives one payload, acknowledges it, and returns its decoded body.
    pub async fn receive_payload(&mut self) -> Result<SendPayload> {
        let frame = read_frame(&mut self.stream, self.max_frame_size).await?;
        let message: Message = decode(&frame)?;
        if message.sender != self.peer_id {
            return Err(ProtocolError::UnauthorizedPeer(message.sender.to_string()));
        }

        match message.message_type {
            MessageType::SendPayload => {
                let payload = decode_payload(&message)?;
                let response = Message {
                    id: uuid::Uuid::new_v4(),
                    sender: self.local_id,
                    message_type: MessageType::PayloadAck,
                    payload: encode(&PayloadAck {
                        message_id: message.id,
                    })?,
                };
                write_frame(&mut self.stream, &Frame::new(encode(&response)?)?).await?;
                Ok(payload)
            }
            MessageType::PayloadAck => Err(ProtocolError::InvalidMessage(
                "a session cannot acknowledge an acknowledgement".to_string(),
            )),
        }
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
    async fn sends_and_receives_payload() {
        let (client_stream, server_stream) = duplex(4096);
        let client_id = DeviceId::random();
        let server_id = DeviceId::random();
        let mut client = CustomSession::new(client_stream, server_id, client_id);
        let mut server = CustomSession::new(server_stream, client_id, server_id);

        let server_task = tokio::spawn(async move { server.receive_payload().await });
        client
            .send_payload("text".to_string(), b"hello".to_vec())
            .await
            .unwrap();

        let payload = server_task.await.unwrap().unwrap();
        assert_eq!(payload.payload_type, "text");
        assert_eq!(payload.payload, b"hello");
    }
}
