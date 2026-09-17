use serde::{Deserialize, Serialize};
use syncthing_core::DeviceId;
use uuid::Uuid;

use crate::error::ProtocolError;
use crate::error::Result;

pub const MESSAGE_VERSION: u16 = 1;
pub const VAULT_PROTOCOL_NAME: &str = "st-vault/1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VaultMessageType {
    VaultList,
    VaultInfo,
    AuthRequest,
    AuthResponse,
    SyncSummary,
    SyncInventory,
    SyncRequest,
    SyncEvents,
    SyncComplete,
    EventAck,
    EventReject,
    ConflictList,
    ConflictResolve,
    DeviceAdd,
    DeviceRevoke,
    KeyRotate,
    Error,
    Goodbye,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultMessage {
    pub version: u16,
    pub id: Uuid,
    pub sender: DeviceId,
    pub message_type: VaultMessageType,
    pub flags: u32,
    pub payload_length: usize,
    pub payload: Vec<u8>,
}

impl VaultMessage {
    pub fn new(sender: DeviceId, message_type: VaultMessageType, payload: Vec<u8>) -> Result<Self> {
        let message = Self {
            version: MESSAGE_VERSION,
            id: Uuid::new_v4(),
            sender,
            message_type,
            flags: 0,
            payload_length: payload.len(),
            payload,
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != MESSAGE_VERSION {
            return Err(ProtocolError::InvalidMessage(format!(
                "unsupported vault message version: {}",
                self.version
            )));
        }
        if self.id.is_nil() {
            return Err(ProtocolError::InvalidMessage(
                "vault message ID must not be nil".to_string(),
            ));
        }
        if self.payload_length != self.payload.len() {
            return Err(ProtocolError::InvalidMessage(format!(
                "vault payload length declares {}, received {}",
                self.payload_length,
                self.payload.len()
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageType {
    SendPayload,
    PayloadAck,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    pub version: u16,
    pub id: Uuid,
    pub sender: DeviceId,
    pub message_type: MessageType,
    pub flags: u32,
    pub payload_length: usize,
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
            version: MESSAGE_VERSION,
            id: Uuid::new_v4(),
            sender,
            message_type: MessageType::SendPayload,
            flags: 0,
            payload_length: payload.len(),
            payload,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != MESSAGE_VERSION {
            return Err(crate::error::ProtocolError::InvalidMessage(format!(
                "unsupported message version: {}",
                self.version
            )));
        }
        if self.id.is_nil() {
            return Err(crate::error::ProtocolError::InvalidMessage(
                "message ID must not be nil".to_string(),
            ));
        }
        if self.payload_length != self.payload.len() {
            return Err(crate::error::ProtocolError::InvalidMessage(format!(
                "payload length declares {}, received {}",
                self.payload_length,
                self.payload.len()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod vault_message_tests {
    use super::*;

    #[test]
    fn round_trips_every_vault_message_type() {
        let sender = DeviceId::random();
        let message_types = [
            VaultMessageType::VaultList,
            VaultMessageType::VaultInfo,
            VaultMessageType::AuthRequest,
            VaultMessageType::AuthResponse,
            VaultMessageType::SyncSummary,
            VaultMessageType::SyncInventory,
            VaultMessageType::SyncRequest,
            VaultMessageType::SyncEvents,
            VaultMessageType::SyncComplete,
            VaultMessageType::EventAck,
            VaultMessageType::EventReject,
            VaultMessageType::ConflictList,
            VaultMessageType::ConflictResolve,
            VaultMessageType::DeviceAdd,
            VaultMessageType::DeviceRevoke,
            VaultMessageType::KeyRotate,
            VaultMessageType::Error,
            VaultMessageType::Goodbye,
        ];

        for message_type in message_types {
            let message = VaultMessage::new(sender, message_type, b"payload".to_vec()).unwrap();
            let encoded = serde_json::to_vec(&message).unwrap();
            let decoded: VaultMessage = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(decoded, message);
            decoded.validate().unwrap();
        }
    }

    #[test]
    fn rejects_tampered_vault_envelope_length_and_version() {
        let mut message = VaultMessage::new(
            DeviceId::random(),
            VaultMessageType::AuthRequest,
            vec![1, 2, 3],
        )
        .unwrap();
        message.payload_length = 1;
        assert!(matches!(
            message.validate(),
            Err(ProtocolError::InvalidMessage(_))
        ));

        message.payload_length = message.payload.len();
        message.version = MESSAGE_VERSION + 1;
        assert!(matches!(
            message.validate(),
            Err(ProtocolError::InvalidMessage(_))
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_incorrect_payload_length() {
        let mut message =
            Message::send_payload(DeviceId::random(), "text".to_string(), vec![1]).unwrap();
        message.payload_length = 0;

        assert!(matches!(
            message.validate(),
            Err(crate::error::ProtocolError::InvalidMessage(_))
        ));
    }
}
