//! Core domain model for the `st-vault/1` protocol.
//!
//! This crate intentionally contains no networking or transport dependencies.
//! Vault state, encryption, membership, and synchronization foundations remain
//! independent of `custom-protocol`, `syncthing-net`, and BEP.

pub mod auth;
pub mod conflict;
pub mod event;
pub mod history;
pub mod keys;
pub mod lifecycle;
pub mod membership;
pub mod persistence;
pub mod provisioning;
pub mod record;
pub mod record_document;
pub mod service;
pub mod sync;
pub mod vault;
pub mod version_vector;

pub use auth::{AuthError, AuthRequest, AuthResponse, VaultAuthenticator};
pub use conflict::{Conflict, ConflictError, ConflictId, ConflictStore};
pub use event::{Event, EventError, EventId, EventType, RecordMutation};
pub use history::{EventHistory, HistoryError};
pub use keys::{
    derive_master_key, EncryptedKeyHierarchy, KeyError, KeyRotation, VaultKeyRing, VaultKeys,
};
pub use lifecycle::{
    OpenedVault, UnlockedVault, VaultLifecycleError, VaultPassword, VaultPeer, VaultRegistry,
    VaultRegistryEntry,
};
pub use membership::{
    DeviceEnrollment, MemberRole, MembershipChange, MembershipChangeType, MembershipError,
    MembershipOperation, MembershipStore, VaultMember,
};
pub use persistence::{
    PersistedEventIndexEntry, PersistenceError, VaultPersistence, VaultSnapshot,
};
pub use provisioning::{
    DeviceIdentity, DeviceIdentityPublic, DeviceIdentityStore, EnrollmentBundle, EnrollmentRequest,
    ProvisioningError, DEFAULT_ENROLLMENT_TTL_SECONDS,
};
pub use record::{
    EncryptedRecord, RecordData, RecordError, RecordId, RecordStore, RecordType, RecordView,
};
pub use record_document::{
    ConflictBranchView, ConflictResolution, ConflictView, DocumentRecord, RecordDocument,
    RecordDocumentError, RecordReference, RECORD_DOCUMENT_VERSION,
};
pub use service::{VaultService, VaultServiceError};
pub use sync::{
    EventAck, EventInventory, EventRange, EventReject, EventTransfer, EventTransferError,
    EventTransferResult, MissingEventsRequest, RecordComparison, RecordDifference, RecordSummary,
    SyncComparison, SyncEvents, SyncSummary, SyncSummaryError, TransferredEvent, MAX_EVENT_RANGES,
    MAX_SYNC_EVENTS,
};
pub use vault::{KdfParameters, VaultHeader, VaultId, VaultMetadata};
pub use version_vector::{VersionOrdering, VersionVector, VersionVectorError};
