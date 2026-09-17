//! Transactional application service for an unlocked vault.

use ed25519_dalek::SigningKey;
use syncthing_core::DeviceId;

use crate::conflict::{ConflictError, ConflictId, ConflictStore};
use crate::event::{Event, EventError, EventId, EventType, RecordMutation};
use crate::history::{EventHistory, HistoryError};
use crate::lifecycle::{UnlockedVault, VaultRegistryEntry};
use crate::membership::{
    MembershipChange, MembershipError, MembershipOperation, MembershipStore, VaultMember,
};
use crate::persistence::{
    PersistedEventIndexEntry, PersistenceError, VaultPersistence, VaultSnapshot,
};
use crate::record::{RecordData, RecordError, RecordId, RecordStore, RecordType, RecordView};
use crate::sync::EventInventory;
use crate::vault::{VaultHeader, VaultId};

#[derive(Debug, thiserror::Error)]
pub enum VaultServiceError {
    #[error("vault snapshot is inconsistent: {0}")]
    InvalidSnapshot(String),
    #[error("local vault member is missing")]
    MissingLocalMember,
    #[error("local signing key does not match the member public key")]
    SigningKeyMismatch,
    #[error("vault member device not found: {0}")]
    DeviceNotFound(DeviceId),
    #[error("membership operation failed: {0}")]
    Membership(#[from] MembershipError),
    #[error("record operation failed: {0}")]
    Record(#[from] RecordError),
    #[error("event operation failed: {0}")]
    Event(#[from] EventError),
    #[error("history operation failed: {0}")]
    History(#[from] HistoryError),
    #[error("conflict operation failed: {0}")]
    Conflict(#[from] ConflictError),
    #[error("vault persistence failed: {0}")]
    Persistence(#[from] PersistenceError),
}

pub type Result<T> = std::result::Result<T, VaultServiceError>;

#[derive(Clone)]
struct ServiceState {
    records: RecordStore,
    history: EventHistory,
    members: MembershipStore,
    membership_changes: Vec<MembershipChange>,
    conflicts: ConflictStore,
    sync_state: Vec<u8>,
}

pub struct VaultService {
    entry: VaultRegistryEntry,
    header: VaultHeader,
    encrypted_signing_key: Vec<u8>,
    signing_key: SigningKey,
    persistence: VaultPersistence,
    state: ServiceState,
}

impl VaultService {
    pub fn from_unlocked(unlocked: UnlockedVault) -> Result<Self> {
        let (entry, keys, signing_key, snapshot, persistence) = unlocked.into_parts();
        if snapshot.header.vault_id != entry.vault_id {
            return Err(VaultServiceError::InvalidSnapshot(
                "registry and header vault IDs differ".to_string(),
            ));
        }
        if snapshot.header.members != snapshot.members {
            return Err(VaultServiceError::InvalidSnapshot(
                "header and snapshot memberships differ".to_string(),
            ));
        }

        let members = MembershipStore::from_members(snapshot.members.clone())?;
        let local_member = members
            .find_member(entry.local_member_id)
            .ok_or(VaultServiceError::MissingLocalMember)?;
        if local_member.public_key != signing_key.verifying_key().to_bytes() {
            return Err(VaultServiceError::SigningKeyMismatch);
        }

        let records = RecordStore::from_records(keys, snapshot.records.clone())?;
        let history = EventHistory::from_events(snapshot.events.clone(), &members)?;
        if history.version() != &snapshot.version_vector {
            return Err(VaultServiceError::InvalidSnapshot(
                "persisted version vector does not match history".to_string(),
            ));
        }
        let event_index = event_index(&history);
        if event_index != snapshot.event_index {
            return Err(VaultServiceError::InvalidSnapshot(
                "persisted event index does not match history".to_string(),
            ));
        }
        let conflicts = ConflictStore::from_conflicts(snapshot.conflicts.clone(), &history)?;
        validate_membership_changes(&snapshot.membership_changes, &members)?;

        Ok(Self {
            entry,
            header: snapshot.header,
            encrypted_signing_key: snapshot.encrypted_signing_key,
            signing_key,
            persistence,
            state: ServiceState {
                records,
                history,
                members,
                membership_changes: snapshot.membership_changes,
                conflicts,
                sync_state: snapshot.sync_state,
            },
        })
    }

    pub fn vault_id(&self) -> VaultId {
        self.entry.vault_id
    }

    pub fn local_member(&self) -> Result<&VaultMember> {
        self.state
            .members
            .find_member(self.entry.local_member_id)
            .ok_or(VaultServiceError::MissingLocalMember)
    }

    pub fn member_by_device_id(&self, device_id: DeviceId) -> Option<&VaultMember> {
        self.state.members.find_by_device_id(device_id)
    }

    pub fn members(&self) -> impl Iterator<Item = &VaultMember> {
        self.state.members.members()
    }

    pub fn add_member(&mut self, member: VaultMember) -> Result<MembershipChange> {
        let actor = self.local_member()?.clone();
        let mut candidate = self.state.clone();
        let change = candidate
            .members
            .add_member(&actor, member, &self.signing_key)?;
        candidate.membership_changes.push(change.clone());
        let mut header = self.header.clone();
        header.members = candidate.members.members().cloned().collect();
        self.commit(candidate, header)?;
        Ok(change)
    }

    pub fn revoke_device(
        &mut self,
        device_id: DeviceId,
        timestamp: i64,
    ) -> Result<MembershipChange> {
        let actor = self.local_member()?.clone();
        let member_id = self
            .state
            .members
            .find_by_device_id(device_id)
            .map(|member| member.member_id)
            .ok_or(VaultServiceError::DeviceNotFound(device_id))?;
        let mut candidate = self.state.clone();
        let change =
            candidate
                .members
                .revoke_member(&actor, member_id, &self.signing_key, timestamp)?;
        candidate.membership_changes.push(change.clone());
        let mut header = self.header.clone();
        header.members = candidate.members.members().cloned().collect();
        self.commit(candidate, header)?;
        Ok(change)
    }

    pub fn get_record(&self, record_id: RecordId) -> Result<Option<RecordData>> {
        Ok(self.state.records.get_record(record_id)?)
    }

    pub fn get_record_including_tombstone(
        &self,
        record_id: RecordId,
    ) -> Result<Option<RecordView>> {
        Ok(self
            .state
            .records
            .get_record_including_tombstone(record_id)?)
    }

    pub fn list_records(&self) -> Result<Vec<RecordData>> {
        Ok(self.state.records.list_records()?)
    }

    pub fn history(&self) -> &EventHistory {
        &self.state.history
    }

    pub fn conflicts(&self) -> &ConflictStore {
        &self.state.conflicts
    }

    pub fn inventory(&self) -> EventInventory {
        EventInventory::from_history(&self.state.history)
    }

    pub fn sync_state(&self) -> &[u8] {
        &self.state.sync_state
    }

    pub fn set_sync_state(&mut self, sync_state: Vec<u8>) -> Result<()> {
        let mut candidate = self.state.clone();
        candidate.sync_state = sync_state;
        self.commit(candidate, self.header.clone())
    }

    pub fn create_record(&mut self, record_type: RecordType, payload: Vec<u8>) -> Result<RecordId> {
        let record_id = RecordId::new_v4();
        self.apply_local_mutation(
            record_id,
            record_type,
            EventType::Create,
            MembershipOperation::Create,
            payload,
        )?;
        Ok(record_id)
    }

    pub fn update_record(&mut self, record_id: RecordId, payload: Vec<u8>) -> Result<()> {
        let record_type = self.record_type(record_id)?;
        self.apply_local_mutation(
            record_id,
            record_type,
            EventType::Update,
            MembershipOperation::Update,
            payload,
        )
    }

    pub fn delete_record(&mut self, record_id: RecordId) -> Result<()> {
        let record_type = self.record_type(record_id)?;
        self.apply_local_mutation(
            record_id,
            record_type,
            EventType::Delete,
            MembershipOperation::Delete,
            Vec::new(),
        )
    }

    pub fn restore_record(&mut self, record_id: RecordId) -> Result<()> {
        let record_type = self.record_type(record_id)?;
        self.apply_local_mutation(
            record_id,
            record_type,
            EventType::Restore,
            MembershipOperation::Restore,
            Vec::new(),
        )
    }

    pub fn resolve_conflict(
        &mut self,
        conflict_id: ConflictId,
        payload: Vec<u8>,
    ) -> Result<EventId> {
        let local_member = self.local_member()?;
        self.state
            .members
            .authorize(local_member, MembershipOperation::Update)?;
        let author = local_member.device_id;
        let sequence = self.next_local_sequence(author)?;
        let record_id = self
            .state
            .conflicts
            .get_conflict(conflict_id)
            .ok_or(ConflictError::NotFound(conflict_id))?
            .record_id;
        let record_type = self.record_type(record_id)?;
        let encrypted_payload = self.state.records.encrypt_payload(record_id, &payload)?;

        let mut candidate = self.state.clone();
        let event = candidate.conflicts.resolve_conflict(
            conflict_id,
            RecordMutation::new(EventType::Update, encrypted_payload),
            author,
            sequence,
            &self.signing_key,
        )?;
        let event_id = event.event_id();
        candidate.records.apply_event(&event, record_type)?;
        candidate
            .history
            .append(event, &self.signing_key.verifying_key())?;
        self.commit(candidate, self.header.clone())?;
        Ok(event_id)
    }

    fn record_type(&self, record_id: RecordId) -> Result<RecordType> {
        self.state
            .records
            .encrypted_record(record_id)
            .map(|record| record.record_type)
            .ok_or(RecordError::NotFound(record_id).into())
    }

    fn apply_local_mutation(
        &mut self,
        record_id: RecordId,
        record_type: RecordType,
        event_type: EventType,
        operation: MembershipOperation,
        payload: Vec<u8>,
    ) -> Result<()> {
        let local_member = self.local_member()?;
        self.state.members.authorize(local_member, operation)?;
        let author = local_member.device_id;
        let sequence = self.next_local_sequence(author)?;
        let encrypted_payload = match event_type {
            EventType::Create | EventType::Update => {
                self.state.records.encrypt_payload(record_id, &payload)?
            }
            EventType::Delete | EventType::Restore => Vec::new(),
        };
        let event = Event::sign(
            record_id,
            RecordMutation::new(event_type, encrypted_payload),
            self.state.history.version().clone(),
            author,
            sequence,
            &self.signing_key,
        )?;

        let mut candidate = self.state.clone();
        candidate.records.apply_event(&event, record_type)?;
        candidate
            .history
            .append(event, &self.signing_key.verifying_key())?;
        self.commit(candidate, self.header.clone())
    }

    fn next_local_sequence(&self, author: DeviceId) -> Result<u64> {
        self.state
            .history
            .device_sequence(author)
            .checked_add(1)
            .ok_or_else(|| {
                VaultServiceError::InvalidSnapshot("device sequence overflow".to_string())
            })
    }

    fn commit(&mut self, candidate: ServiceState, header: VaultHeader) -> Result<()> {
        let snapshot = self.snapshot(&candidate, &header);
        self.persistence.save(&snapshot)?;
        self.state = candidate;
        self.header = header;
        Ok(())
    }

    fn snapshot(&self, state: &ServiceState, header: &VaultHeader) -> VaultSnapshot {
        VaultSnapshot {
            header: header.clone(),
            encrypted_signing_key: self.encrypted_signing_key.clone(),
            records: state.records.encrypted_records().cloned().collect(),
            events: state.history.events().cloned().collect(),
            version_vector: state.history.version().clone(),
            members: state.members.members().cloned().collect(),
            membership_changes: state.membership_changes.clone(),
            conflicts: state.conflicts.list_conflicts().cloned().collect(),
            event_index: event_index(&state.history),
            sync_state: state.sync_state.clone(),
        }
    }
}

fn validate_membership_changes(
    changes: &[MembershipChange],
    members: &MembershipStore,
) -> Result<()> {
    for change in changes {
        let actor = members.find_by_device_id(change.actor).ok_or_else(|| {
            VaultServiceError::InvalidSnapshot(
                "membership change actor is not a member".to_string(),
            )
        })?;
        let public_key: [u8; 32] = actor.public_key.as_slice().try_into().map_err(|_| {
            VaultServiceError::InvalidSnapshot(
                "membership change actor public key is invalid".to_string(),
            )
        })?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).map_err(|_| {
            VaultServiceError::InvalidSnapshot(
                "membership change actor public key is invalid".to_string(),
            )
        })?;
        change.verify(&verifying_key)?;
    }
    Ok(())
}

fn event_index(history: &EventHistory) -> Vec<PersistedEventIndexEntry> {
    history
        .events()
        .map(|event| PersistedEventIndexEntry {
            device_id: event.author(),
            device_sequence: event.device_sequence(),
            event_id: event.event_id(),
            record_id: event.record_id(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::{MemberRole, VaultMember, VaultPassword, VaultRegistry, VersionVector};
    use tempfile::tempdir;

    fn password() -> VaultPassword {
        VaultPassword::new(b"correct horse battery staple".to_vec())
    }

    #[test]
    fn record_lifecycle_persists_signed_events_and_tombstones() {
        let directory = tempdir().unwrap();
        let registry = VaultRegistry::new(directory.path());
        let device_id = DeviceId::random();
        let unlocked = registry
            .create_vault("records", &password(), device_id)
            .unwrap();
        let mut service = VaultService::from_unlocked(unlocked).unwrap();

        let record_id = service
            .create_record(RecordType::SecureNote, b"first".to_vec())
            .unwrap();
        service
            .update_record(record_id, b"second".to_vec())
            .unwrap();
        service.delete_record(record_id).unwrap();
        let tombstone = service
            .get_record_including_tombstone(record_id)
            .unwrap()
            .unwrap();
        assert!(tombstone.deleted);
        assert_eq!(tombstone.payload, b"second");
        service.restore_record(record_id).unwrap();
        service.set_sync_state(b"peer-checkpoint".to_vec()).unwrap();
        assert_eq!(service.history().len(), 4);
        assert_eq!(
            service.get_record(record_id).unwrap().unwrap().payload,
            b"second"
        );

        drop(service);
        let reopened = registry.unlock_vault("records", &password()).unwrap();
        let reopened = VaultService::from_unlocked(reopened).unwrap();
        assert_eq!(reopened.history().len(), 4);
        assert_eq!(reopened.sync_state(), b"peer-checkpoint");
        assert_eq!(
            reopened.get_record(record_id).unwrap().unwrap().payload,
            b"second"
        );
        assert_eq!(
            reopened.member_by_device_id(device_id).unwrap().member_id,
            reopened.local_member().unwrap().member_id
        );
    }

    #[test]
    fn failed_persistence_does_not_commit_candidate_state() {
        let directory = tempdir().unwrap();
        let registry = VaultRegistry::new(directory.path());
        let unlocked = registry
            .create_vault("rollback", &password(), DeviceId::random())
            .unwrap();
        let vault_path = directory.path().join(&unlocked.entry().storage_path);
        let mut service = VaultService::from_unlocked(unlocked).unwrap();
        fs::remove_file(&vault_path).unwrap();
        fs::create_dir(&vault_path).unwrap();

        assert!(matches!(
            service.create_record(RecordType::Login, b"secret".to_vec()),
            Err(VaultServiceError::Persistence(_))
        ));
        assert!(service.list_records().unwrap().is_empty());
        assert!(service.history().is_empty());
    }

    #[test]
    fn rejects_tampered_derived_snapshot_state() {
        let directory = tempdir().unwrap();
        let registry = VaultRegistry::new(directory.path());
        let unlocked = registry
            .create_vault("tampered", &password(), DeviceId::random())
            .unwrap();
        let vault_path = directory.path().join(&unlocked.entry().storage_path);
        let mut service = VaultService::from_unlocked(unlocked).unwrap();
        service
            .create_record(RecordType::Custom, b"value".to_vec())
            .unwrap();
        drop(service);

        let persistence = VaultPersistence::new(&vault_path);
        let mut snapshot = persistence.load().unwrap();
        snapshot.version_vector = VersionVector::new();
        persistence.save(&snapshot).unwrap();
        let unlocked = registry.unlock_vault("tampered", &password()).unwrap();
        assert!(matches!(
            VaultService::from_unlocked(unlocked),
            Err(VaultServiceError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn membership_changes_persist_and_reconstruct() {
        let directory = tempdir().unwrap();
        let registry = VaultRegistry::new(directory.path());
        let unlocked = registry
            .create_vault("members", &password(), DeviceId::random())
            .unwrap();
        let peer_key = SigningKey::from_bytes(&[73; 32]);
        let peer_device = DeviceId::random();
        let peer = VaultMember {
            member_id: uuid::Uuid::new_v4(),
            device_id: peer_device,
            public_key: peer_key.verifying_key().to_bytes().to_vec(),
            encrypted_vault_key: vec![1; 48],
            role: MemberRole::Writer,
            created_at: 1,
            revoked_at: None,
        };
        let mut service = VaultService::from_unlocked(unlocked).unwrap();
        let change = service.add_member(peer).unwrap();
        change.verify(&service.signing_key.verifying_key()).unwrap();
        service.revoke_device(peer_device, 42).unwrap();
        drop(service);

        let reopened = registry.unlock_vault("members", &password()).unwrap();
        let reopened = VaultService::from_unlocked(reopened).unwrap();
        let peer = reopened.member_by_device_id(peer_device).unwrap();
        assert_eq!(peer.revoked_at, Some(42));
    }

    #[test]
    fn reader_cannot_create_records() {
        let directory = tempdir().unwrap();
        let registry = VaultRegistry::new(directory.path());
        let unlocked = registry
            .create_vault("reader", &password(), DeviceId::random())
            .unwrap();
        let vault_path = directory.path().join(&unlocked.entry().storage_path);
        drop(unlocked);

        let persistence = VaultPersistence::new(&vault_path);
        let mut snapshot = persistence.load().unwrap();
        snapshot.header.members[0].role = MemberRole::Reader;
        snapshot.members[0].role = MemberRole::Reader;
        persistence.save(&snapshot).unwrap();

        let unlocked = registry.unlock_vault("reader", &password()).unwrap();
        let mut service = VaultService::from_unlocked(unlocked).unwrap();
        assert!(matches!(
            service.create_record(RecordType::Login, b"secret".to_vec()),
            Err(VaultServiceError::Membership(MembershipError::Unauthorized))
        ));
        assert!(service.history().is_empty());
    }
}
