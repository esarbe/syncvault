//! Append-only vault event history abstractions.

use std::collections::{BTreeMap, HashMap};

use ed25519_dalek::VerifyingKey;

use crate::event::{Event, EventError, EventId};
use crate::record::RecordId;
use crate::version_vector::VersionVector;
use syncthing_core::DeviceId;

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("event already exists: {0}")]
    DuplicateEvent(EventId),
    #[error("invalid event signature: {0}")]
    InvalidSignature(#[from] EventError),
    #[error("invalid sequence for device {device}: expected {expected}, got {actual}")]
    InvalidSequence {
        device: DeviceId,
        expected: u64,
        actual: u64,
    },
    #[error("event causal version is ahead of known history")]
    CausalityViolation,
}

pub type Result<T> = std::result::Result<T, HistoryError>;

#[derive(Debug, Default)]
pub struct EventHistory {
    events: BTreeMap<EventId, Event>,
    order: Vec<EventId>,
    by_record: HashMap<RecordId, Vec<EventId>>,
    device_sequences: HashMap<DeviceId, u64>,
    version: VersionVector,
}

impl EventHistory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, event: Event, verifying_key: &VerifyingKey) -> Result<()> {
        let event_id = event.event_id();
        if self.events.contains_key(&event_id) {
            return Err(HistoryError::DuplicateEvent(event_id));
        }

        event.verify(verifying_key)?;
        let author = event.author();
        let expected = self.device_sequences.get(&author).copied().unwrap_or(0) + 1;
        if event.device_sequence() != expected {
            return Err(HistoryError::InvalidSequence {
                device: author,
                expected,
                actual: event.device_sequence(),
            });
        }
        if event
            .causal_version()
            .iter()
            .any(|(device, counter)| *counter > self.version.get(device))
        {
            return Err(HistoryError::CausalityViolation);
        }

        self.version.merge(event.causal_version());
        self.version
            .increment(author)
            .map_err(|_| HistoryError::InvalidSequence {
                device: author,
                expected,
                actual: event.device_sequence(),
            })?;
        self.device_sequences
            .insert(author, event.device_sequence());
        self.by_record
            .entry(event.record_id())
            .or_default()
            .push(event_id);
        self.events.insert(event_id, event);
        self.order.push(event_id);
        Ok(())
    }

    pub fn get(&self, event_id: EventId) -> Option<&Event> {
        self.events.get(&event_id)
    }

    pub fn events_for_record(&self, record_id: RecordId) -> Vec<&Event> {
        self.by_record
            .get(&record_id)
            .into_iter()
            .flatten()
            .filter_map(|event_id| self.events.get(event_id))
            .collect()
    }

    pub fn events_since(&self, version: &VersionVector) -> Vec<&Event> {
        self.order
            .iter()
            .filter_map(|event_id| self.events.get(event_id))
            .filter(|event| event.device_sequence() > version.get(&event.author()))
            .collect()
    }

    pub fn history(&self, record_id: RecordId) -> Vec<&Event> {
        self.events_for_record(record_id)
    }

    pub fn version(&self) -> &VersionVector {
        &self.version
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn events(&self) -> impl Iterator<Item = &Event> {
        self.order
            .iter()
            .filter_map(|event_id| self.events.get(event_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventType, RecordMutation};
    use uuid::Uuid;

    fn event(
        key: &ed25519_dalek::SigningKey,
        author: DeviceId,
        record_id: RecordId,
        sequence: u64,
        causal: VersionVector,
    ) -> Event {
        Event::sign(
            record_id,
            RecordMutation::new(EventType::Update, vec![sequence as u8]),
            causal,
            author,
            sequence,
            key,
        )
        .unwrap()
    }

    #[test]
    fn appends_and_queries_events_without_mutating_them() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let author = DeviceId::random();
        let record_id = Uuid::new_v4();
        let first = event(&key, author, record_id, 1, VersionVector::new());
        let first_id = first.event_id();
        let mut history = EventHistory::new();
        history.append(first.clone(), &key.verifying_key()).unwrap();

        assert_eq!(history.get(first_id), Some(&first));
        assert_eq!(history.events_for_record(record_id).len(), 1);
        assert_eq!(history.history(record_id).len(), 1);
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn enforces_unique_sequences_and_signatures() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let author = DeviceId::random();
        let record_id = RecordId::new_v4();
        let first = event(&key, author, record_id, 1, VersionVector::new());
        let mut history = EventHistory::new();
        history.append(first.clone(), &key.verifying_key()).unwrap();
        assert!(matches!(
            history.append(first, &key.verifying_key()),
            Err(HistoryError::DuplicateEvent(_))
        ));
        assert!(matches!(
            history.append(
                event(&key, author, record_id, 3, VersionVector::new()),
                &key.verifying_key()
            ),
            Err(HistoryError::InvalidSequence { .. })
        ));
    }

    #[test]
    fn events_since_uses_per_device_sequence_cutoffs() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let author = DeviceId::random();
        let record_id = RecordId::new_v4();
        let mut history = EventHistory::new();
        history
            .append(
                event(&key, author, record_id, 1, VersionVector::new()),
                &key.verifying_key(),
            )
            .unwrap();
        let mut causal = VersionVector::new();
        causal.increment(author).unwrap();
        history
            .append(
                event(&key, author, record_id, 2, causal),
                &key.verifying_key(),
            )
            .unwrap();

        let mut since = VersionVector::new();
        since.increment(author).unwrap();
        let events = history.events_since(&since);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].device_sequence(), 2);
    }

    #[test]
    fn rejects_causal_version_ahead_of_known_history() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let author = DeviceId::random();
        let unseen_device = DeviceId::random();
        let mut causal = VersionVector::new();
        causal.increment(unseen_device).unwrap();
        let event = event(&key, author, RecordId::new_v4(), 1, causal);

        assert!(matches!(
            EventHistory::new().append(event, &key.verifying_key()),
            Err(HistoryError::CausalityViolation)
        ));
    }
}
