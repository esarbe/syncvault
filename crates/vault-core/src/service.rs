//! Transactional application service for an unlocked vault.

use ed25519_dalek::SigningKey;
use syncthing_core::DeviceId;
use uuid::Uuid;

use crate::auth::{AuthError, AuthRequest, AuthResponse, VaultAuthenticator};
use crate::conflict::{ConflictError, ConflictId, ConflictStore};
use crate::event::{Event, EventError, EventId, EventType, RecordMutation};
use crate::history::{EventHistory, HistoryError};
use crate::lifecycle::{UnlockedVault, VaultPeer, VaultRegistryEntry};
use crate::membership::{
    MembershipChange, MembershipError, MembershipOperation, MembershipStore, VaultMember,
};
use crate::persistence::{
    PersistedEventIndexEntry, PersistenceError, VaultPersistence, VaultSnapshot,
};
use crate::provisioning::{
    enrollment_payload, EnrollmentBundle, EnrollmentRequest, EnrollmentSealInput, ProvisioningError,
};
use crate::record::{RecordData, RecordError, RecordId, RecordStore, RecordType, RecordView};
use crate::record_document::{
    ConflictBranchView, ConflictResolution, ConflictView, DocumentRecord, RecordDocument,
    RecordDocumentError, RecordReference,
};
use crate::sync::EventInventory;
use crate::sync::{
    EventAck, EventRange, EventReject, EventTransferError, EventTransferResult, RecordSummary,
    SyncEvents, SyncSummary, TransferredEvent, MAX_EVENT_RANGES, MAX_SYNC_EVENTS,
};
use crate::vault::{VaultHeader, VaultId};
use crate::version_vector::{VersionOrdering, VersionVector};

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
    #[error("vault authentication failed: {0}")]
    Authentication(#[from] AuthError),
    #[error("record name is ambiguous: {name} ({matches} live records)")]
    AmbiguousRecordName { name: String, matches: usize },
    #[error("record name not found: {0}")]
    RecordNameNotFound(String),
    #[error("record name is already in use: {0}")]
    DuplicateRecordName(String),
    #[error("conflict branch not found: {0}")]
    ConflictBranchNotFound(EventId),
    #[error("record document type does not match encrypted record type")]
    RecordTypeMismatch,
    #[error("record document operation failed: {0}")]
    RecordDocument(#[from] RecordDocumentError),
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
    #[error("event transfer failed: {0}")]
    EventTransfer(#[from] EventTransferError),
    #[error("vault provisioning failed: {0}")]
    Provisioning(#[from] ProvisioningError),
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

    pub fn authorize_peer(
        &self,
        device_id: DeviceId,
        operation: MembershipOperation,
    ) -> Result<&VaultMember> {
        let member = self
            .state
            .members
            .find_by_device_id(device_id)
            .ok_or(VaultServiceError::DeviceNotFound(device_id))?;
        self.state.members.authorize(member, operation)?;
        Ok(member)
    }

    pub fn metadata(&self) -> crate::vault::VaultMetadata {
        self.header.metadata()
    }

    pub fn peers(&self) -> &[VaultPeer] {
        &self.entry.peers
    }

    pub fn authenticator(&self) -> VaultAuthenticator {
        VaultAuthenticator::new(self.vault_id(), self.state.members.clone())
    }

    pub fn authentication_request(&self, nonce: Vec<u8>) -> Result<AuthRequest> {
        let member = self.local_member()?;
        Ok(VaultAuthenticator::request(
            self.vault_id(),
            member.member_id,
            member.device_id,
            nonce,
            &self.signing_key,
        )?)
    }

    pub fn authentication_response(
        &self,
        authenticator: &mut VaultAuthenticator,
        request: &AuthRequest,
        tls_peer: DeviceId,
    ) -> Result<AuthResponse> {
        let member = self.local_member()?;
        Ok(authenticator.respond(
            request,
            tls_peer,
            member.member_id,
            member.device_id,
            &self.signing_key,
        )?)
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

    pub fn prepare_enrollment(
        &mut self,
        request: &EnrollmentRequest,
        role: crate::membership::MemberRole,
        owner_address: String,
        now: i64,
        ttl_seconds: i64,
    ) -> Result<EnrollmentBundle> {
        request.verify(request.identity.device_id, now)?;
        let owner = self.local_member()?.clone();
        self.state
            .members
            .authorize(&owner, MembershipOperation::AddMember)?;
        let member_id = Uuid::new_v4();
        let member = VaultMember {
            member_id,
            device_id: request.identity.device_id,
            public_key: request.identity.signing_public_key.clone(),
            encrypted_vault_key: request.identity.wrapping_public_key.clone(),
            role,
            created_at: now,
            revoked_at: None,
        };
        let mut candidate = self.state.clone();
        let change = candidate
            .members
            .add_member(&owner, member, &self.signing_key)?;
        candidate.membership_changes.push(change);
        let mut header = self.header.clone();
        header.members = candidate.members.members().cloned().collect();
        let payload =
            enrollment_payload(candidate.records.keys(), self.snapshot(&candidate, &header));
        let bundle = EnrollmentBundle::seal(EnrollmentSealInput {
            vault_id: self.vault_id(),
            vault_name: self.entry.name.clone(),
            protocol_version: self.header.protocol_version,
            request,
            member_id,
            role,
            owner_device_id: owner.device_id,
            owner_signing_key: &self.signing_key,
            owner_address,
            payload,
            now,
            ttl_seconds,
        })?;
        self.commit(candidate, header)?;
        Ok(bundle)
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

    pub fn create_document(&mut self, document: RecordDocument) -> Result<RecordId> {
        document.validate()?;
        self.ensure_name_available(&document.name, None)?;
        self.create_record(document.record_type, document.encode()?)
    }

    pub fn update_document(
        &mut self,
        reference: &RecordReference,
        document: RecordDocument,
    ) -> Result<()> {
        document.validate()?;
        let record_id = self.resolve_record(reference)?;
        if self.record_type(record_id)? != document.record_type {
            return Err(VaultServiceError::RecordTypeMismatch);
        }
        self.ensure_name_available(&document.name, Some(record_id))?;
        self.update_record(record_id, document.encode()?)
    }

    pub fn get_document(&self, reference: &RecordReference) -> Result<Option<DocumentRecord>> {
        let record_id = match reference {
            RecordReference::Id(record_id) => *record_id,
            RecordReference::Name(_) => self.resolve_record(reference)?,
        };
        self.document_record(record_id, false)
    }

    pub fn get_document_including_tombstone(
        &self,
        reference: &RecordReference,
    ) -> Result<Option<DocumentRecord>> {
        let record_id = match reference {
            RecordReference::Id(record_id) => *record_id,
            RecordReference::Name(_) => self.resolve_record(reference)?,
        };
        self.document_record(record_id, true)
    }

    pub fn delete_document(&mut self, reference: &RecordReference) -> Result<()> {
        let record_id = self.resolve_record(reference)?;
        self.delete_record(record_id)
    }

    pub fn restore_document(&mut self, record_id: RecordId) -> Result<()> {
        let record = self
            .document_record(record_id, true)?
            .ok_or(RecordError::NotFound(record_id))?;
        if !record.deleted {
            return Ok(());
        }
        self.ensure_name_available(&record.document.name, Some(record_id))?;
        self.restore_record(record_id)
    }

    pub fn list_documents(&self) -> Result<Vec<DocumentRecord>> {
        self.state
            .records
            .list_records()?
            .into_iter()
            .map(|record| self.decode_document(record, false))
            .collect()
    }

    pub fn resolve_record(&self, reference: &RecordReference) -> Result<RecordId> {
        match reference {
            RecordReference::Id(record_id) => self
                .state
                .records
                .encrypted_record(*record_id)
                .filter(|record| !record.deleted)
                .map(|record| record.id)
                .ok_or(RecordError::NotFound(*record_id).into()),
            RecordReference::Name(name) => {
                let matches = self
                    .list_documents()?
                    .into_iter()
                    .filter(|record| record.document.name == *name)
                    .map(|record| record.id)
                    .collect::<Vec<_>>();
                match matches.as_slice() {
                    [] => Err(VaultServiceError::RecordNameNotFound(name.clone())),
                    [record_id] => Ok(*record_id),
                    _ => Err(VaultServiceError::AmbiguousRecordName {
                        name: name.clone(),
                        matches: matches.len(),
                    }),
                }
            }
        }
    }

    pub fn history(&self) -> &EventHistory {
        &self.state.history
    }

    pub fn conflicts(&self) -> &ConflictStore {
        &self.state.conflicts
    }

    pub fn conflict_view(&self, conflict_id: ConflictId) -> Result<ConflictView> {
        let conflict = self
            .state
            .conflicts
            .get_conflict(conflict_id)
            .ok_or(ConflictError::NotFound(conflict_id))?;
        let mut branches = Vec::with_capacity(conflict.branches.len());
        for branch in &conflict.branches {
            let document = match branch.mutation().event_type() {
                EventType::Create | EventType::Update => {
                    let payload = self.state.records.decrypt_payload(
                        branch.record_id(),
                        branch.mutation().encrypted_payload(),
                    )?;
                    Some(RecordDocument::decode(&payload)?)
                }
                EventType::Delete | EventType::Restore => None,
            };
            branches.push(ConflictBranchView {
                event_id: branch.event_id(),
                author: branch.author(),
                device_sequence: branch.device_sequence(),
                document,
            });
        }
        Ok(ConflictView {
            conflict_id: conflict.conflict_id,
            record_id: conflict.record_id,
            branches,
            resolution_event_id: conflict.resolution_event_id,
        })
    }

    pub fn list_conflict_views(&self) -> Result<Vec<ConflictView>> {
        self.state
            .conflicts
            .list_conflicts()
            .map(|conflict| self.conflict_view(conflict.conflict_id))
            .collect()
    }

    pub fn inventory(&self) -> EventInventory {
        EventInventory::from_history(&self.state.history)
    }

    pub fn sync_summary(&self) -> SyncSummary {
        let mut records = Vec::new();
        for encrypted_record in self.state.records.encrypted_records() {
            let events = self.state.history.events_for_record(encrypted_record.id);
            let Some(current) = events.last() else {
                continue;
            };
            let current_event_id = current.event_id();
            let mut version_vector = VersionVector::new();
            for event in events {
                version_vector.merge(event.causal_version());
                version_vector.observe(event.author(), event.device_sequence());
            }
            records.push(RecordSummary {
                record_id: encrypted_record.id,
                version_vector,
                current_event_id,
            });
        }
        records.sort_by_key(|record| record.record_id.to_string());
        SyncSummary {
            vault_id: self.vault_id(),
            version_vector: self.state.history.version().clone(),
            records,
        }
    }

    pub fn export_events(&self, ranges: &[EventRange]) -> Result<SyncEvents> {
        validate_ranges(ranges)?;
        let mut events = Vec::new();
        for event in self.state.history.events() {
            if ranges.iter().any(|range| event_in_range(event, range)) {
                let record_type = self.record_type(event.record_id())?;
                events.push(TransferredEvent {
                    event: event.clone(),
                    record_type,
                });
                if events.len() == MAX_SYNC_EVENTS {
                    break;
                }
            }
        }
        Ok(SyncEvents {
            vault_id: self.vault_id(),
            events,
        })
    }

    pub fn apply_remote_events(
        &mut self,
        batch: SyncEvents,
        requested_ranges: &[EventRange],
    ) -> Result<Vec<EventTransferResult>> {
        if batch.vault_id != self.vault_id() {
            return Err(EventTransferError::WrongVault.into());
        }
        if batch.events.len() > MAX_SYNC_EVENTS {
            return Err(EventTransferError::BatchTooLarge.into());
        }
        validate_ranges(requested_ranges)?;

        let mut candidate = self.state.clone();
        let mut results = Vec::with_capacity(batch.events.len());
        let mut changed = false;
        for transferred in batch.events {
            let event = transferred.event;
            let event_id = event.event_id();
            if candidate.history.get(event_id).is_some() {
                results.push(EventTransferResult::Duplicate(EventAck { event_id }));
                continue;
            }
            let result = apply_remote_event(
                &mut candidate,
                event,
                transferred.record_type,
                requested_ranges,
            );
            match result {
                Ok(()) => {
                    changed = true;
                    results.push(EventTransferResult::Accepted(EventAck { event_id }));
                }
                Err(reason) => results.push(EventTransferResult::Rejected(EventReject {
                    event_id,
                    reason,
                })),
            }
        }
        if changed {
            self.commit(candidate, self.header.clone())?;
        }
        Ok(results)
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
        let record_id = self
            .state
            .conflicts
            .get_conflict(conflict_id)
            .ok_or(ConflictError::NotFound(conflict_id))?
            .record_id;
        let encrypted_payload = self.state.records.encrypt_payload(record_id, &payload)?;
        self.resolve_conflict_mutation(
            conflict_id,
            RecordMutation::new(EventType::Update, encrypted_payload),
        )
    }

    fn resolve_conflict_mutation(
        &mut self,
        conflict_id: ConflictId,
        mutation: RecordMutation,
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

        let mut candidate = self.state.clone();
        let event = candidate.conflicts.resolve_conflict(
            conflict_id,
            mutation,
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

    pub fn resolve_document_conflict(
        &mut self,
        conflict_id: ConflictId,
        resolution: ConflictResolution,
    ) -> Result<EventId> {
        let conflict = self
            .state
            .conflicts
            .get_conflict(conflict_id)
            .ok_or(ConflictError::NotFound(conflict_id))?;
        let record_type = self.record_type(conflict.record_id)?;
        let mutation = match resolution {
            ConflictResolution::SelectBranch(event_id) => {
                let branch = conflict
                    .branches
                    .iter()
                    .find(|branch| branch.event_id() == event_id)
                    .ok_or(VaultServiceError::ConflictBranchNotFound(event_id))?;
                match branch.mutation().event_type() {
                    EventType::Create | EventType::Update => {
                        let payload = self.state.records.decrypt_payload(
                            branch.record_id(),
                            branch.mutation().encrypted_payload(),
                        )?;
                        let document = RecordDocument::decode(&payload)?;
                        self.validate_resolution_document(
                            conflict.record_id,
                            record_type,
                            &document,
                        )?;
                        let encrypted_payload = self
                            .state
                            .records
                            .encrypt_payload(conflict.record_id, &document.encode()?)?;
                        RecordMutation::new(EventType::Update, encrypted_payload)
                    }
                    EventType::Delete => RecordMutation::new(EventType::Delete, Vec::new()),
                    EventType::Restore => RecordMutation::new(EventType::Restore, Vec::new()),
                }
            }
            ConflictResolution::Merge(document) => {
                self.validate_resolution_document(conflict.record_id, record_type, &document)?;
                let encrypted_payload = self
                    .state
                    .records
                    .encrypt_payload(conflict.record_id, &document.encode()?)?;
                RecordMutation::new(EventType::Update, encrypted_payload)
            }
        };
        self.resolve_conflict_mutation(conflict_id, mutation)
    }

    fn record_type(&self, record_id: RecordId) -> Result<RecordType> {
        self.state
            .records
            .encrypted_record(record_id)
            .map(|record| record.record_type)
            .ok_or(RecordError::NotFound(record_id).into())
    }

    fn validate_resolution_document(
        &self,
        record_id: RecordId,
        record_type: RecordType,
        document: &RecordDocument,
    ) -> Result<()> {
        if document.record_type != record_type {
            return Err(VaultServiceError::RecordTypeMismatch);
        }
        document.validate()?;
        self.ensure_name_available(&document.name, Some(record_id))
    }

    fn document_record(
        &self,
        record_id: RecordId,
        include_tombstone: bool,
    ) -> Result<Option<DocumentRecord>> {
        let Some(record) = self
            .state
            .records
            .get_record_including_tombstone(record_id)?
        else {
            return Ok(None);
        };
        if record.deleted && !include_tombstone {
            return Ok(None);
        }
        Ok(Some(self.decode_document(
            RecordData {
                id: record.id,
                record_type: record.record_type,
                payload: record.payload,
            },
            record.deleted,
        )?))
    }

    fn decode_document(&self, record: RecordData, deleted: bool) -> Result<DocumentRecord> {
        let document = RecordDocument::decode(&record.payload)?;
        if document.record_type != record.record_type {
            return Err(VaultServiceError::RecordTypeMismatch);
        }
        Ok(DocumentRecord {
            id: record.id,
            document,
            deleted,
        })
    }

    fn ensure_name_available(&self, name: &str, except: Option<RecordId>) -> Result<()> {
        if self.list_documents()?.into_iter().any(|record| {
            record.id != except.unwrap_or(RecordId::nil()) && record.document.name == name
        }) {
            return Err(VaultServiceError::DuplicateRecordName(name.to_string()));
        }
        Ok(())
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

fn validate_ranges(ranges: &[EventRange]) -> Result<()> {
    if ranges.len() > MAX_EVENT_RANGES {
        return Err(EventTransferError::TooManyRanges.into());
    }
    if ranges.iter().any(EventRange::is_empty) {
        return Err(EventTransferError::InvalidRange.into());
    }
    Ok(())
}

fn event_in_range(event: &Event, range: &EventRange) -> bool {
    event.author() == range.device_id
        && event.device_sequence() >= range.start
        && event.device_sequence() <= range.end
}

fn apply_remote_event(
    state: &mut ServiceState,
    event: Event,
    record_type: RecordType,
    requested_ranges: &[EventRange],
) -> std::result::Result<(), String> {
    if !requested_ranges
        .iter()
        .any(|range| event_in_range(&event, range))
    {
        return Err("event is outside the requested range".to_string());
    }
    let member = state
        .members
        .find_by_device_id(event.author())
        .ok_or_else(|| "event author is not an authorized member".to_string())?;
    if !member.is_active() {
        return Err("event author is revoked".to_string());
    }
    let public_key: [u8; 32] = member
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| "member public key is invalid".to_string())?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .map_err(|_| "member public key is invalid".to_string())?;
    event
        .verify(&verifying_key)
        .map_err(|error| format!("invalid event signature: {error}"))?;

    let current = state
        .history
        .events_for_record(event.record_id())
        .last()
        .copied()
        .cloned();
    state
        .history
        .append(event.clone(), &verifying_key)
        .map_err(|error| format!("history rejected event: {error}"))?;

    if let Some(current) = current {
        match effective_version(&event).compare(&effective_version(&current)) {
            VersionOrdering::Concurrent => {
                state
                    .conflicts
                    .detect(current, event)
                    .map_err(|error| format!("conflict detection failed: {error}"))?;
                return Ok(());
            }
            VersionOrdering::DominatedBy | VersionOrdering::Equal => return Ok(()),
            VersionOrdering::Dominates => {}
        }
    }
    state
        .records
        .apply_event(&event, record_type)
        .map_err(|error| format!("record application failed: {error}"))
}

fn effective_version(event: &Event) -> VersionVector {
    let mut version = event.causal_version().clone();
    version.observe(event.author(), event.device_sequence());
    version
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
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

    #[test]
    fn document_crud_resolves_exact_names_and_enforces_live_uniqueness() {
        let directory = tempdir().unwrap();
        let registry = VaultRegistry::new(directory.path());
        let unlocked = registry
            .create_vault("documents", &password(), DeviceId::random())
            .unwrap();
        let mut service = VaultService::from_unlocked(unlocked).unwrap();
        let mut document = RecordDocument::new(RecordType::Login, "Example");
        document.value = "primary".to_string();
        document
            .fields
            .insert("username".to_string(), "alice".to_string());
        let record_id = service.create_document(document.clone()).unwrap();

        assert_eq!(
            service
                .resolve_record(&RecordReference::Name("Example".to_string()))
                .unwrap(),
            record_id
        );
        assert!(matches!(
            service.resolve_record(&RecordReference::Name("example".to_string())),
            Err(VaultServiceError::RecordNameNotFound(_))
        ));
        assert!(matches!(
            service.create_document(document.clone()),
            Err(VaultServiceError::DuplicateRecordName(_))
        ));

        document.value = "updated".to_string();
        service
            .update_document(&RecordReference::Id(record_id), document.clone())
            .unwrap();
        assert_eq!(
            service
                .get_document(&RecordReference::Name("Example".to_string()))
                .unwrap()
                .unwrap()
                .document,
            document
        );

        service
            .delete_document(&RecordReference::Id(record_id))
            .unwrap();
        let replacement = RecordDocument::new(RecordType::SecureNote, "Example");
        service.create_document(replacement).unwrap();
        assert!(matches!(
            service.restore_document(record_id),
            Err(VaultServiceError::DuplicateRecordName(_))
        ));
        assert!(
            service
                .get_document_including_tombstone(&RecordReference::Id(record_id))
                .unwrap()
                .unwrap()
                .deleted
        );
    }

    #[test]
    fn document_update_rejects_outer_type_change() {
        let directory = tempdir().unwrap();
        let registry = VaultRegistry::new(directory.path());
        let unlocked = registry
            .create_vault("types", &password(), DeviceId::random())
            .unwrap();
        let mut service = VaultService::from_unlocked(unlocked).unwrap();
        let record_id = service
            .create_document(RecordDocument::new(RecordType::Login, "account"))
            .unwrap();

        assert!(matches!(
            service.update_document(
                &RecordReference::Id(record_id),
                RecordDocument::new(RecordType::SecureNote, "account")
            ),
            Err(VaultServiceError::RecordTypeMismatch)
        ));
    }

    #[test]
    fn conflict_view_and_merge_use_validated_documents() {
        let directory = tempdir().unwrap();
        let registry = VaultRegistry::new(directory.path());
        let owner_device = DeviceId::random();
        let unlocked = registry
            .create_vault("conflicts", &password(), owner_device)
            .unwrap();
        let mut service = VaultService::from_unlocked(unlocked).unwrap();
        let record_id = service
            .create_document(RecordDocument::new(RecordType::SecureNote, "note"))
            .unwrap();

        let remote_key = SigningKey::from_bytes(&[81; 32]);
        let remote_device = DeviceId::random();
        service
            .add_member(VaultMember {
                member_id: uuid::Uuid::new_v4(),
                device_id: remote_device,
                public_key: remote_key.verifying_key().to_bytes().to_vec(),
                encrypted_vault_key: vec![1; 48],
                role: MemberRole::Writer,
                created_at: 1,
                revoked_at: None,
            })
            .unwrap();

        let mut local_document = RecordDocument::new(RecordType::SecureNote, "note");
        local_document.value = "local".to_string();
        service
            .update_document(&RecordReference::Id(record_id), local_document)
            .unwrap();
        let local_event = service.history().events().last().unwrap().clone();

        let mut remote_document = RecordDocument::new(RecordType::SecureNote, "note");
        remote_document.value = "remote".to_string();
        let encrypted_remote = service
            .state
            .records
            .encrypt_payload(record_id, &remote_document.encode().unwrap())
            .unwrap();
        let mut remote_causal = VersionVector::new();
        remote_causal.observe(owner_device, 1);
        let remote_event = Event::sign(
            record_id,
            RecordMutation::new(EventType::Update, encrypted_remote),
            remote_causal,
            remote_device,
            1,
            &remote_key,
        )
        .unwrap();
        let mut candidate = service.state.clone();
        candidate
            .history
            .append(remote_event.clone(), &remote_key.verifying_key())
            .unwrap();
        let conflict_id = candidate
            .conflicts
            .detect(local_event, remote_event)
            .unwrap();
        service.commit(candidate, service.header.clone()).unwrap();

        let view = service.conflict_view(conflict_id).unwrap();
        assert_eq!(view.branches.len(), 2);
        assert_eq!(view.branches[1].document.as_ref().unwrap().value, "remote");
        let mut merged = RecordDocument::new(RecordType::SecureNote, "note");
        merged.value = "merged".to_string();
        merged.fields = BTreeMap::from([("notes".to_string(), "resolved".to_string())]);
        service
            .resolve_document_conflict(conflict_id, ConflictResolution::Merge(merged.clone()))
            .unwrap();
        assert_eq!(
            service
                .get_document(&RecordReference::Id(record_id))
                .unwrap()
                .unwrap()
                .document,
            merged
        );
        assert!(service
            .conflict_view(conflict_id)
            .unwrap()
            .resolution_event_id
            .is_some());
    }

    #[test]
    fn conflict_can_select_an_existing_branch() {
        let directory = tempdir().unwrap();
        let registry = VaultRegistry::new(directory.path());
        let owner_device = DeviceId::random();
        let unlocked = registry
            .create_vault("branch", &password(), owner_device)
            .unwrap();
        let mut service = VaultService::from_unlocked(unlocked).unwrap();
        let record_id = service
            .create_document(RecordDocument::new(RecordType::SecureNote, "note"))
            .unwrap();
        let remote_key = SigningKey::from_bytes(&[82; 32]);
        let remote_device = DeviceId::random();
        service
            .add_member(VaultMember {
                member_id: uuid::Uuid::new_v4(),
                device_id: remote_device,
                public_key: remote_key.verifying_key().to_bytes().to_vec(),
                encrypted_vault_key: vec![2; 48],
                role: MemberRole::Writer,
                created_at: 1,
                revoked_at: None,
            })
            .unwrap();

        let mut selected = RecordDocument::new(RecordType::SecureNote, "note");
        selected.value = "selected".to_string();
        let encrypted = service
            .state
            .records
            .encrypt_payload(record_id, &selected.encode().unwrap())
            .unwrap();
        let mut causal = VersionVector::new();
        causal.observe(owner_device, 1);
        let remote_event = Event::sign(
            record_id,
            RecordMutation::new(EventType::Update, encrypted),
            causal,
            remote_device,
            1,
            &remote_key,
        )
        .unwrap();
        service
            .update_document(
                &RecordReference::Id(record_id),
                RecordDocument::new(RecordType::SecureNote, "note"),
            )
            .unwrap();
        let local_event = service.history().events().last().unwrap().clone();
        let selected_event_id = remote_event.event_id();
        let mut candidate = service.state.clone();
        candidate
            .history
            .append(remote_event.clone(), &remote_key.verifying_key())
            .unwrap();
        let conflict_id = candidate
            .conflicts
            .detect(local_event, remote_event)
            .unwrap();
        service.commit(candidate, service.header.clone()).unwrap();

        assert_eq!(service.list_conflict_views().unwrap().len(), 1);
        service
            .resolve_document_conflict(
                conflict_id,
                ConflictResolution::SelectBranch(selected_event_id),
            )
            .unwrap();
        assert_eq!(
            service
                .get_document(&RecordReference::Id(record_id))
                .unwrap()
                .unwrap()
                .document,
            selected
        );
    }

    #[test]
    fn remote_event_application_is_typed_idempotent_and_authorized() {
        let directory = tempdir().unwrap();
        let registry = VaultRegistry::new(directory.path());
        let local_device = DeviceId::random();
        let unlocked = registry
            .create_vault("remote", &password(), local_device)
            .unwrap();
        let mut service = VaultService::from_unlocked(unlocked).unwrap();
        let remote_key = SigningKey::from_bytes(&[91; 32]);
        let remote_device = DeviceId::random();
        service
            .add_member(VaultMember {
                member_id: uuid::Uuid::new_v4(),
                device_id: remote_device,
                public_key: remote_key.verifying_key().to_bytes().to_vec(),
                encrypted_vault_key: vec![3; 48],
                role: MemberRole::Writer,
                created_at: 1,
                revoked_at: None,
            })
            .unwrap();
        let record_id = RecordId::new_v4();
        let document = RecordDocument::new(RecordType::SecureNote, "remote note");
        let ciphertext = service
            .state
            .records
            .encrypt_payload(record_id, &document.encode().unwrap())
            .unwrap();
        let event = Event::sign(
            record_id,
            RecordMutation::new(EventType::Create, ciphertext),
            VersionVector::new(),
            remote_device,
            1,
            &remote_key,
        )
        .unwrap();
        let batch = SyncEvents {
            vault_id: service.vault_id(),
            events: vec![TransferredEvent {
                event: event.clone(),
                record_type: RecordType::SecureNote,
            }],
        };
        let ranges = [EventRange {
            device_id: remote_device,
            start: 1,
            end: 1,
        }];

        assert!(matches!(
            service
                .apply_remote_events(batch.clone(), &ranges)
                .unwrap()
                .as_slice(),
            [EventTransferResult::Accepted(_)]
        ));
        assert_eq!(
            service
                .get_document(&RecordReference::Id(record_id))
                .unwrap()
                .unwrap()
                .document,
            document
        );
        assert!(matches!(
            service
                .apply_remote_events(batch, &ranges)
                .unwrap()
                .as_slice(),
            [EventTransferResult::Duplicate(_)]
        ));

        let unauthorized_key = SigningKey::from_bytes(&[92; 32]);
        let unauthorized_device = DeviceId::random();
        let unauthorized = Event::sign(
            RecordId::new_v4(),
            RecordMutation::new(EventType::Create, vec![1]),
            VersionVector::new(),
            unauthorized_device,
            1,
            &unauthorized_key,
        )
        .unwrap();
        let result = service
            .apply_remote_events(
                SyncEvents {
                    vault_id: service.vault_id(),
                    events: vec![TransferredEvent {
                        event: unauthorized,
                        record_type: RecordType::Custom,
                    }],
                },
                &[EventRange {
                    device_id: unauthorized_device,
                    start: 1,
                    end: 1,
                }],
            )
            .unwrap();
        assert!(matches!(
            result.as_slice(),
            [EventTransferResult::Rejected(_)]
        ));
        assert_eq!(service.history().len(), 1);
    }
}
