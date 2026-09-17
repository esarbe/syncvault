use serde::{Deserialize, Serialize};
use syncthing_core::DeviceId;
use uuid::Uuid;

use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageType {
    SendPayload,
    PayloadAck,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    pub id: Uuid,
    pub sender: DeviceId,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SendPayload {
    pub payload_type: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayloadAck {
    pub message_id: Uuid,
}

impl Message {
    pub fn send_payload(sender: DeviceId, payload_type: String, payload: Vec<u8>) -> Result<Self> {
        let body = SendPayload {
            payload_type,
            payload,
        };
        let payload = serde_json::to_vec(&body)?;
        Ok(Self {
            id: Uuid::new_v4(),
            sender,
            message_type: MessageType::SendPayload,
            payload,
        })
    }
}
