//! Conflict detection and resolution domain types.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::event::{Event, EventError, EventId, RecordMutation};
use crate::record::RecordId;
use crate::version_vector::{VersionOrdering, VersionVector};
use syncthing_core::DeviceId;

pub type ConflictId = Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Conflict {
    pub conflict_id: ConflictId,
    pub record_id: RecordId,
    pub branches: Vec<Event>,
    pub resolution_event_id: Option<EventId>,
}

impl Conflict {
    pub fn is_resolved(&self) -> bool {
        self.resolution_event_id.is_some()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConflictError {
    #[error("events belong to different records")]
    DifferentRecords,
    #[error("events are not concurrent")]
    NotConcurrent,
    #[error("conflict not found: {0}")]
    NotFound(ConflictId),
    #[error("conflict is already resolved")]
    AlreadyResolved,
    #[error("conflict already exists: {0}")]
    AlreadyExists(ConflictId),
    #[error("persisted conflict is invalid: {0}")]
    InvalidPersisted(String),
    #[error("event error: {0}")]
    Event(#[from] EventError),
}

pub type Result<T> = std::result::Result<T, ConflictError>;

#[derive(Debug, Clone, Default)]
pub struct ConflictStore {
    conflicts: BTreeMap<ConflictId, Conflict>,
}

impl ConflictStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_conflicts(
        conflicts: Vec<Conflict>,
        history: &crate::history::EventHistory,
    ) -> Result<Self> {
        let mut store = Self::new();
        for conflict in conflicts {
            if store.conflicts.contains_key(&conflict.conflict_id) {
                return Err(ConflictError::AlreadyExists(conflict.conflict_id));
            }
            if conflict.branches.len() < 2
                || conflict
                    .branches
                    .iter()
                    .any(|branch| branch.record_id() != conflict.record_id)
            {
                return Err(ConflictError::InvalidPersisted(
                    "branches must describe one record".to_string(),
                ));
            }
            for branch in &conflict.branches {
                if history.get(branch.event_id()) != Some(branch) {
                    return Err(ConflictError::InvalidPersisted(
                        "branch is absent from history".to_string(),
                    ));
                }
            }
            if !conflict.branches.iter().enumerate().all(|(index, branch)| {
                conflict.branches.iter().skip(index + 1).all(|other| {
                    branch.causal_version().compare(other.causal_version())
                        == VersionOrdering::Concurrent
                })
            }) {
                return Err(ConflictError::InvalidPersisted(
                    "branches are not concurrent".to_string(),
                ));
            }
            if conflict
                .resolution_event_id
                .is_some_and(|event_id| history.get(event_id).is_none())
            {
                return Err(ConflictError::InvalidPersisted(
                    "resolution event is absent from history".to_string(),
                ));
            }
            store.conflicts.insert(conflict.conflict_id, conflict);
        }
        Ok(store)
    }

    pub fn detect(&mut self, left: Event, right: Event) -> Result<ConflictId> {
        if left.record_id() != right.record_id() {
            return Err(ConflictError::DifferentRecords);
        }
        if left.causal_version().compare(right.causal_version()) != VersionOrdering::Concurrent {
            return Err(ConflictError::NotConcurrent);
        }
        let id = ConflictId::new_v4();
        self.conflicts.insert(
            id,
            Conflict {
                conflict_id: id,
                record_id: left.record_id(),
                branches: vec![left, right],
                resolution_event_id: None,
            },
        );
        Ok(id)
    }

    pub fn list_conflicts(&self) -> impl Iterator<Item = &Conflict> {
        self.conflicts.values()
    }

    pub fn get_conflict(&self, id: ConflictId) -> Option<&Conflict> {
        self.conflicts.get(&id)
    }

    pub fn resolve_conflict(
        &mut self,
        id: ConflictId,
        mutation: RecordMutation,
        author: DeviceId,
        device_sequence: u64,
        signing_key: &SigningKey,
    ) -> Result<Event> {
        let conflict = self
            .conflicts
            .get_mut(&id)
            .ok_or(ConflictError::NotFound(id))?;
        if conflict.is_resolved() {
            return Err(ConflictError::AlreadyResolved);
        }
        let mut causal = VersionVector::new();
        for branch in &conflict.branches {
            causal.merge(branch.causal_version());
            causal.observe(branch.author(), branch.device_sequence());
        }
        let event = Event::sign(
            conflict.record_id,
            mutation,
            causal,
            author,
            device_sequence,
            signing_key,
        )?;
        conflict.resolution_event_id = Some(event.event_id());
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventType;

    fn event(
        key: &SigningKey,
        record_id: RecordId,
        author: DeviceId,
        causal: VersionVector,
        sequence: u64,
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
    fn preserves_concurrent_branches_and_resolves_with_both_contexts() {
        let left_key = SigningKey::from_bytes(&[21; 32]);
        let right_key = SigningKey::from_bytes(&[22; 32]);
        let resolver_key = SigningKey::from_bytes(&[23; 32]);
        let left_device = DeviceId::random();
        let right_device = DeviceId::random();
        let record_id = RecordId::new_v4();
        let mut left_context = VersionVector::new();
        left_context.increment(left_device).unwrap();
        let mut right_context = VersionVector::new();
        right_context.increment(right_device).unwrap();
        let left = event(&left_key, record_id, left_device, left_context, 1);
        let right = event(&right_key, record_id, right_device, right_context, 1);

        let mut store = ConflictStore::new();
        let conflict_id = store.detect(left.clone(), right.clone()).unwrap();
        assert_eq!(store.list_conflicts().count(), 1);
        assert_eq!(store.get_conflict(conflict_id).unwrap().branches.len(), 2);

        let resolution = store
            .resolve_conflict(
                conflict_id,
                RecordMutation::new(EventType::Update, b"merged".to_vec()),
                DeviceId::random(),
                1,
                &resolver_key,
            )
            .unwrap();
        assert!(resolution.causal_version().get(&left_device) >= 1);
        assert!(resolution.causal_version().get(&right_device) >= 1);
        resolution.verify(&resolver_key.verifying_key()).unwrap();
        assert!(store.get_conflict(conflict_id).unwrap().is_resolved());
        assert!(matches!(
            store.resolve_conflict(
                conflict_id,
                RecordMutation::new(EventType::Update, vec![]),
                DeviceId::random(),
                2,
                &resolver_key,
            ),
            Err(ConflictError::AlreadyResolved)
        ));
    }

    #[test]
    fn rejects_nonconcurrent_or_cross_record_branches() {
        let key = SigningKey::from_bytes(&[24; 32]);
        let device = DeviceId::random();
        let record_id = RecordId::new_v4();
        let first = event(&key, record_id, device, VersionVector::new(), 1);
        let mut descendant_context = VersionVector::new();
        descendant_context.increment(device).unwrap();
        let descendant = event(&key, record_id, device, descendant_context, 2);
        let mut store = ConflictStore::new();
        assert!(matches!(
            store.detect(first.clone(), descendant),
            Err(ConflictError::NotConcurrent)
        ));
        let other = event(&key, RecordId::new_v4(), device, VersionVector::new(), 1);
        assert!(matches!(
            store.detect(first, other),
            Err(ConflictError::DifferentRecords)
        ));
    }
}
