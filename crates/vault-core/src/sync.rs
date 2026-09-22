//! Summary-level synchronization comparison without transferring history.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::event::{Event, EventId};
use crate::history::EventHistory;
use crate::membership::MembershipStore;
use crate::record::{RecordId, RecordType};
use crate::vault::VaultId;
use crate::version_vector::{VersionOrdering, VersionVector};
use syncthing_core::DeviceId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordSummary {
    pub record_id: RecordId,
    pub version_vector: VersionVector,
    pub current_event_id: EventId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncSummary {
    pub vault_id: VaultId,
    pub version_vector: VersionVector,
    pub records: Vec<RecordSummary>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventRange {
    pub device_id: DeviceId,
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MissingEventsRequest {
    pub vault_id: VaultId,
    pub ranges: Vec<EventRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncEvents {
    pub vault_id: VaultId,
    pub events: Vec<TransferredEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferredEvent {
    pub event: Event,
    pub record_type: RecordType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventAck {
    pub event_id: EventId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventReject {
    pub event_id: EventId,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventTransferResult {
    Accepted(EventAck),
    Duplicate(EventAck),
    Rejected(EventReject),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EventTransferError {
    #[error("event transfer belongs to a different vault")]
    WrongVault,
    #[error("event batch exceeds the maximum size")]
    BatchTooLarge,
    #[error("event request exceeds the maximum number of ranges")]
    TooManyRanges,
    #[error("event request contains an invalid range")]
    InvalidRange,
}

pub const MAX_SYNC_EVENTS: usize = 256;
pub const MAX_EVENT_RANGES: usize = 64;

pub struct EventTransfer<'a> {
    vault_id: VaultId,
    history: &'a mut EventHistory,
    members: &'a MembershipStore,
}

impl<'a> EventTransfer<'a> {
    pub fn new(
        vault_id: VaultId,
        history: &'a mut EventHistory,
        members: &'a MembershipStore,
    ) -> Self {
        Self {
            vault_id,
            history,
            members,
        }
    }

    pub fn apply(
        &mut self,
        batch: SyncEvents,
        requested_ranges: &[EventRange],
    ) -> Result<Vec<EventTransferResult>, EventTransferError> {
        if batch.vault_id != self.vault_id {
            return Err(EventTransferError::WrongVault);
        }
        if batch.events.len() > MAX_SYNC_EVENTS {
            return Err(EventTransferError::BatchTooLarge);
        }

        let mut results = Vec::with_capacity(batch.events.len());
        for transferred in batch.events {
            let event = transferred.event;
            let event_id = event.event_id();
            if self.history.get(event_id).is_some() {
                results.push(EventTransferResult::Duplicate(EventAck { event_id }));
                continue;
            }
            let Some(member) = self
                .members
                .members()
                .find(|member| member.device_id == event.author())
            else {
                results.push(reject(event_id, "event author is not an authorized member"));
                continue;
            };
            if !member.is_active() {
                results.push(reject(event_id, "event author is revoked"));
                continue;
            }
            let Ok(public_key) = member.public_key.as_slice().try_into() else {
                results.push(reject(event_id, "member public key is invalid"));
                continue;
            };
            let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&public_key) else {
                results.push(reject(event_id, "member public key is invalid"));
                continue;
            };
            if !requested_ranges.iter().any(|range| {
                range.device_id == event.author()
                    && event.device_sequence() >= range.start
                    && event.device_sequence() <= range.end
            }) {
                results.push(reject(event_id, "event is outside the requested range"));
                continue;
            }
            if let Err(error) = event.verify(&verifying_key) {
                results.push(reject(
                    event_id,
                    &format!("invalid event signature: {error}"),
                ));
                continue;
            }
            match self.history.append(event, &verifying_key) {
                Ok(()) => results.push(EventTransferResult::Accepted(EventAck { event_id })),
                Err(error) => results.push(reject(
                    event_id,
                    &format!("history rejected event: {error}"),
                )),
            }
        }
        Ok(results)
    }
}

fn reject(event_id: EventId, reason: &str) -> EventTransferResult {
    EventTransferResult::Rejected(EventReject {
        event_id,
        reason: reason.to_string(),
    })
}

#[derive(Debug, Clone, Default)]
pub struct EventInventory {
    by_event_id: HashMap<EventId, Event>,
    by_device_sequence: HashMap<DeviceId, HashMap<u64, EventId>>,
    by_record_id: HashMap<RecordId, Vec<EventId>>,
}

impl EventInventory {
    pub fn from_history(history: &EventHistory) -> Self {
        let mut inventory = Self::default();
        for event in history.events() {
            inventory.add(event.clone());
        }
        inventory
    }

    pub fn event(&self, event_id: EventId) -> Option<&Event> {
        self.by_event_id.get(&event_id)
    }

    pub fn event_id(&self, device_id: DeviceId, device_sequence: u64) -> Option<EventId> {
        self.by_device_sequence
            .get(&device_id)
            .and_then(|events| events.get(&device_sequence))
            .copied()
    }

    pub fn events_for_device(&self, device_id: DeviceId) -> Vec<&Event> {
        self.by_device_sequence
            .get(&device_id)
            .into_iter()
            .flatten()
            .filter_map(|(_, event_id)| self.by_event_id.get(event_id))
            .collect()
    }

    pub fn events_for_record(&self, record_id: RecordId) -> Vec<&Event> {
        self.by_record_id
            .get(&record_id)
            .into_iter()
            .flatten()
            .filter_map(|event_id| self.by_event_id.get(event_id))
            .collect()
    }

    pub fn missing_events_request(
        &self,
        vault_id: VaultId,
        remote_version: &VersionVector,
    ) -> MissingEventsRequest {
        let mut ranges = Vec::new();
        for (device_id, sequences) in &self.by_device_sequence {
            let Some(max_sequence) = sequences.keys().max().copied() else {
                continue;
            };
            let remote_sequence = remote_version.get(device_id);
            if max_sequence > remote_sequence {
                ranges.push(EventRange {
                    device_id: *device_id,
                    start: remote_sequence + 1,
                    end: max_sequence,
                });
            }
        }
        ranges.sort_by_key(|range| range.device_id.to_string());
        MissingEventsRequest { vault_id, ranges }
    }

    fn add(&mut self, event: Event) {
        let event_id = event.event_id();
        self.by_device_sequence
            .entry(event.author())
            .or_default()
            .insert(event.device_sequence(), event_id);
        self.by_record_id
            .entry(event.record_id())
            .or_default()
            .push(event_id);
        self.by_event_id.insert(event_id, event);
    }
}

impl EventRange {
    pub fn is_empty(&self) -> bool {
        self.start > self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordComparison {
    Equal,
    LocalAhead,
    RemoteAhead,
    Concurrent,
    LocalOnly,
    RemoteOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordDifference {
    pub record_id: RecordId,
    pub comparison: RecordComparison,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncComparison {
    pub missing_event_ranges: Vec<EventRange>,
    pub record_differences: Vec<RecordDifference>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SyncSummaryError {
    #[error("sync summaries belong to different vaults")]
    WrongVault,
}

impl SyncSummary {
    pub fn compare(&self, remote: &Self) -> Result<SyncComparison, SyncSummaryError> {
        if self.vault_id != remote.vault_id {
            return Err(SyncSummaryError::WrongVault);
        }

        let mut missing_event_ranges = Vec::new();
        for (device_id, remote_counter) in remote.version_vector.iter() {
            let local_counter = self.version_vector.get(device_id);
            if *remote_counter > local_counter {
                missing_event_ranges.push(EventRange {
                    device_id: *device_id,
                    start: local_counter + 1,
                    end: *remote_counter,
                });
            }
        }
        missing_event_ranges.sort_by_key(|range| range.device_id.to_string());

        let local_records: HashMap<_, _> = self
            .records
            .iter()
            .map(|record| (record.record_id, record))
            .collect();
        let remote_records: HashMap<_, _> = remote
            .records
            .iter()
            .map(|record| (record.record_id, record))
            .collect();
        let mut record_differences = Vec::new();

        for record_id in local_records.keys().chain(remote_records.keys()) {
            if record_differences
                .iter()
                .any(|difference: &RecordDifference| difference.record_id == *record_id)
            {
                continue;
            }
            let comparison = match (local_records.get(record_id), remote_records.get(record_id)) {
                (Some(local), Some(remote)) => {
                    match local.version_vector.compare(&remote.version_vector) {
                        VersionOrdering::Equal => RecordComparison::Equal,
                        VersionOrdering::Dominates => RecordComparison::LocalAhead,
                        VersionOrdering::DominatedBy => RecordComparison::RemoteAhead,
                        VersionOrdering::Concurrent => RecordComparison::Concurrent,
                    }
                }
                (Some(_), None) => RecordComparison::LocalOnly,
                (None, Some(_)) => RecordComparison::RemoteOnly,
                (None, None) => continue,
            };
            if comparison != RecordComparison::Equal {
                record_differences.push(RecordDifference {
                    record_id: *record_id,
                    comparison,
                });
            }
        }
        record_differences.sort_by_key(|difference| difference.record_id.to_string());

        Ok(SyncComparison {
            missing_event_ranges,
            record_differences,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(vault_id: VaultId, device: DeviceId, counter: u64) -> SyncSummary {
        let mut version_vector = VersionVector::new();
        for _ in 0..counter {
            version_vector.increment(device).unwrap();
        }
        SyncSummary {
            vault_id,
            version_vector: version_vector.clone(),
            records: vec![RecordSummary {
                record_id: RecordId::new_v4(),
                version_vector,
                current_event_id: EventId::new_v4(),
            }],
        }
    }

    #[test]
    fn computes_remote_ahead_event_range() {
        let vault_id = VaultId::new_v4();
        let device = DeviceId::random();
        let local = summary(vault_id, device, 30);
        let remote = summary(vault_id, device, 37);
        let comparison = local.compare(&remote).unwrap();

        assert_eq!(comparison.missing_event_ranges.len(), 1);
        assert_eq!(comparison.missing_event_ranges[0].start, 31);
        assert_eq!(comparison.missing_event_ranges[0].end, 37);
    }

    #[test]
    fn detects_concurrent_and_wrong_vault_summaries() {
        let vault_id = VaultId::new_v4();
        let local_device = DeviceId::random();
        let remote_device = DeviceId::random();
        let record_id = RecordId::new_v4();
        let mut local = summary(vault_id, local_device, 1);
        let mut remote = summary(vault_id, remote_device, 1);
        local.records[0].record_id = record_id;
        remote.records[0].record_id = record_id;
        let comparison = local.compare(&remote).unwrap();
        assert_eq!(comparison.missing_event_ranges.len(), 1);
        assert_eq!(comparison.record_differences.len(), 1);
        assert_eq!(
            comparison.record_differences[0].comparison,
            RecordComparison::Concurrent
        );

        assert_eq!(
            local.compare(&summary(VaultId::new_v4(), remote_device, 1)),
            Err(SyncSummaryError::WrongVault)
        );
    }

    #[test]
    fn equal_summaries_have_no_work() {
        let vault_id = VaultId::new_v4();
        let device = DeviceId::random();
        let local = summary(vault_id, device, 2);
        let mut remote = local.clone();
        remote.records = local.records.clone();
        let comparison = local.compare(&remote).unwrap();
        assert!(comparison.missing_event_ranges.is_empty());
        assert!(comparison.record_differences.is_empty());
    }

    #[test]
    fn inventory_indexes_events_and_requests_only_missing_ranges() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[13; 32]);
        let device = DeviceId::random();
        let record_id = RecordId::new_v4();
        let mut history = EventHistory::new();
        for sequence in 1..=37 {
            let mut causal = VersionVector::new();
            if sequence > 1 {
                causal.increment(device).unwrap();
            }
            let event = Event::sign(
                record_id,
                crate::event::RecordMutation::new(
                    crate::event::EventType::Update,
                    vec![sequence as u8],
                ),
                causal,
                device,
                sequence,
                &key,
            )
            .unwrap();
            history.append(event, &key.verifying_key()).unwrap();
        }
        let inventory = EventInventory::from_history(&history);
        let mut remote = VersionVector::new();
        for _ in 0..30 {
            remote.increment(device).unwrap();
        }
        let request = inventory.missing_events_request(VaultId::new_v4(), &remote);
        assert_eq!(request.ranges.len(), 1);
        assert_eq!(request.ranges[0].start, 31);
        assert_eq!(request.ranges[0].end, 37);
        assert!(inventory.event_id(device, 31).is_some());
        assert_eq!(inventory.events_for_device(device).len(), 37);
        assert_eq!(inventory.events_for_record(record_id).len(), 37);
    }

    #[test]
    fn transfers_validate_membership_signature_and_are_idempotent() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[14; 32]);
        let device = DeviceId::random();
        let member = crate::membership::VaultMember {
            member_id: uuid::Uuid::new_v4(),
            device_id: device,
            public_key: key.verifying_key().to_bytes().to_vec(),
            encrypted_vault_key: vec![1; 32],
            role: crate::membership::MemberRole::Writer,
            created_at: 1,
            revoked_at: None,
        };
        let mut members = crate::membership::MembershipStore::new();
        members.insert_member(member).unwrap();
        let mut history = EventHistory::new();
        let event = Event::sign(
            RecordId::new_v4(),
            crate::event::RecordMutation::new(
                crate::event::EventType::Update,
                b"ciphertext".to_vec(),
            ),
            VersionVector::new(),
            device,
            1,
            &key,
        )
        .unwrap();
        let event_id = event.event_id();
        let range = EventRange {
            device_id: device,
            start: 1,
            end: 1,
        };
        let vault_id = VaultId::new_v4();
        let mut transfer = EventTransfer::new(vault_id, &mut history, &members);
        let batch = SyncEvents {
            vault_id,
            events: vec![TransferredEvent {
                event: event.clone(),
                record_type: RecordType::Custom,
            }],
        };
        assert_eq!(
            transfer.apply(batch.clone(), &[range]).unwrap(),
            vec![EventTransferResult::Accepted(EventAck { event_id })]
        );
        assert_eq!(
            transfer.apply(batch, &[range]).unwrap(),
            vec![EventTransferResult::Duplicate(EventAck { event_id })]
        );
    }

    #[test]
    fn rejects_bad_signature_revoked_member_and_wrong_vault() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[15; 32]);
        let device = DeviceId::random();
        let member = crate::membership::VaultMember {
            member_id: uuid::Uuid::new_v4(),
            device_id: device,
            public_key: key.verifying_key().to_bytes().to_vec(),
            encrypted_vault_key: vec![1; 32],
            role: crate::membership::MemberRole::Writer,
            created_at: 1,
            revoked_at: None,
        };
        let mut members = crate::membership::MembershipStore::new();
        members.insert_member(member.clone()).unwrap();
        let mut history = EventHistory::new();
        let event = Event::sign(
            RecordId::new_v4(),
            crate::event::RecordMutation::new(crate::event::EventType::Update, vec![1]),
            VersionVector::new(),
            device,
            1,
            &ed25519_dalek::SigningKey::from_bytes(&[16; 32]),
        )
        .unwrap();
        let batch = SyncEvents {
            vault_id: VaultId::new_v4(),
            events: vec![TransferredEvent {
                event: event.clone(),
                record_type: RecordType::Custom,
            }],
        };
        let mut transfer = EventTransfer::new(batch.vault_id, &mut history, &members);
        assert!(matches!(
            transfer.apply(
                batch,
                &[EventRange { device_id: device, start: 1, end: 1 }]
            ),
            Ok(results) if matches!(results.as_slice(), [EventTransferResult::Rejected(_)])
        ));

        let mut revoked_members = crate::membership::MembershipStore::new();
        let owner_key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
        let owner = crate::membership::VaultMember {
            member_id: uuid::Uuid::new_v4(),
            device_id: DeviceId::random(),
            public_key: owner_key.verifying_key().to_bytes().to_vec(),
            encrypted_vault_key: vec![1; 32],
            role: crate::membership::MemberRole::Owner,
            created_at: 1,
            revoked_at: None,
        };
        revoked_members.insert_member(owner.clone()).unwrap();
        revoked_members
            .add_member(&owner, member.clone(), &owner_key)
            .unwrap();
        revoked_members
            .revoke_member(&owner, member.member_id, &owner_key, 2)
            .unwrap();
        let mut revoked_history = EventHistory::new();
        let revoked_event = Event::sign(
            RecordId::new_v4(),
            crate::event::RecordMutation::new(crate::event::EventType::Update, vec![1]),
            VersionVector::new(),
            device,
            1,
            &key,
        )
        .unwrap();
        let revoked_id = revoked_event.event_id();
        let revoked_vault_id = VaultId::new_v4();
        let mut revoked_transfer =
            EventTransfer::new(revoked_vault_id, &mut revoked_history, &revoked_members);
        let results = revoked_transfer
            .apply(
                SyncEvents {
                    vault_id: revoked_vault_id,
                    events: vec![TransferredEvent {
                        event: revoked_event,
                        record_type: RecordType::Custom,
                    }],
                },
                &[EventRange {
                    device_id: device,
                    start: 1,
                    end: 1,
                }],
            )
            .unwrap();
        assert!(matches!(
            results.as_slice(),
            [EventTransferResult::Rejected(EventReject { event_id, .. })] if *event_id == revoked_id
        ));
    }
}
