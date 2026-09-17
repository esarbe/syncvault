//! Immutable record mutation events.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::record::RecordId;
use crate::version_vector::VersionVector;
use syncthing_core::DeviceId;

pub type EventId = Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    Create,
    Update,
    Delete,
    Restore,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordMutation {
    event_type: EventType,
    encrypted_payload: Vec<u8>,
}

impl RecordMutation {
    pub fn new(event_type: EventType, encrypted_payload: Vec<u8>) -> Self {
        Self {
            event_type,
            encrypted_payload,
        }
    }

    pub fn event_type(&self) -> EventType {
        self.event_type
    }

    pub fn encrypted_payload(&self) -> &[u8] {
        &self.encrypted_payload
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EventError {
    #[error("event serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("event signature is invalid")]
    InvalidSignature,
    #[error("event signature has invalid length")]
    InvalidSignatureLength,
    #[error("event ID must not be nil")]
    NilEventId,
    #[error("record ID must not be nil")]
    NilRecordId,
    #[error("device sequence must be greater than zero")]
    InvalidDeviceSequence,
}

pub type Result<T> = std::result::Result<T, EventError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    event_id: EventId,
    record_id: RecordId,
    mutation: RecordMutation,
    causal_version: VersionVector,
    author: DeviceId,
    device_sequence: u64,
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct UnsignedEvent<'a> {
    event_id: EventId,
    record_id: RecordId,
    mutation: &'a RecordMutation,
    causal_version: &'a VersionVector,
    author: DeviceId,
    device_sequence: u64,
}

impl Event {
    pub fn sign(
        record_id: RecordId,
        mutation: RecordMutation,
        causal_version: VersionVector,
        author: DeviceId,
        device_sequence: u64,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        let event = Self {
            event_id: EventId::new_v4(),
            record_id,
            mutation,
            causal_version,
            author,
            device_sequence,
            signature: Vec::new(),
        };
        event.validate_unsigned()?;
        let signature = signing_key
            .sign(&event.signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(Self { signature, ..event })
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<()> {
        self.validate_unsigned()?;
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| EventError::InvalidSignatureLength)?;
        let signature = Signature::from_bytes(&signature);
        verifying_key
            .verify(&self.signing_bytes()?, &signature)
            .map_err(|_| EventError::InvalidSignature)
    }

    pub fn event_id(&self) -> EventId {
        self.event_id
    }

    pub fn record_id(&self) -> RecordId {
        self.record_id
    }

    pub fn mutation(&self) -> &RecordMutation {
        &self.mutation
    }

    pub fn causal_version(&self) -> &VersionVector {
        &self.causal_version
    }

    pub fn author(&self) -> DeviceId {
        self.author
    }

    pub fn device_sequence(&self) -> u64 {
        self.device_sequence
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    fn validate_unsigned(&self) -> Result<()> {
        if self.event_id.is_nil() {
            return Err(EventError::NilEventId);
        }
        if self.record_id.is_nil() {
            return Err(EventError::NilRecordId);
        }
        if self.device_sequence == 0 {
            return Err(EventError::InvalidDeviceSequence);
        }
        Ok(())
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&UnsignedEvent {
            event_id: self.event_id,
            record_id: self.record_id,
            mutation: &self.mutation,
            causal_version: &self.causal_version,
            author: self.author,
            device_sequence: self.device_sequence,
        })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    #[test]
    fn signs_and_verifies_each_supported_mutation() {
        let key = signing_key();
        let author = DeviceId::random();
        for event_type in [
            EventType::Create,
            EventType::Update,
            EventType::Delete,
            EventType::Restore,
        ] {
            let event = Event::sign(
                RecordId::new_v4(),
                RecordMutation::new(event_type, vec![1, 2, 3]),
                VersionVector::new(),
                author,
                1,
                &key,
            )
            .unwrap();
            event.verify(&key.verifying_key()).unwrap();
        }
    }

    #[test]
    fn rejects_tampered_event_and_wrong_signer() {
        let key = signing_key();
        let mut event = Event::sign(
            RecordId::new_v4(),
            RecordMutation::new(EventType::Update, b"ciphertext".to_vec()),
            VersionVector::new(),
            DeviceId::random(),
            1,
            &key,
        )
        .unwrap();
        event.mutation.encrypted_payload[0] ^= 1;
        assert!(matches!(
            event.verify(&key.verifying_key()),
            Err(EventError::InvalidSignature)
        ));

        let other_key = SigningKey::from_bytes(&[8; 32]);
        assert!(matches!(
            event.verify(&other_key.verifying_key()),
            Err(EventError::InvalidSignature)
        ));
    }

    #[test]
    fn events_have_unique_ids_and_reject_zero_sequence() {
        let key = signing_key();
        let make_event = || {
            Event::sign(
                RecordId::new_v4(),
                RecordMutation::new(EventType::Create, Vec::new()),
                VersionVector::new(),
                DeviceId::random(),
                1,
                &key,
            )
            .unwrap()
        };
        assert_ne!(make_event().event_id(), make_event().event_id());
        assert!(matches!(
            Event::sign(
                RecordId::new_v4(),
                RecordMutation::new(EventType::Create, Vec::new()),
                VersionVector::new(),
                DeviceId::random(),
                0,
                &key,
            ),
            Err(EventError::InvalidDeviceSequence)
        ));
    }
}
