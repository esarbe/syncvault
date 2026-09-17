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
pub mod membership;
pub mod record;
pub mod sync;
pub mod vault;
pub mod version_vector;

pub use auth::{AuthError, AuthRequest, AuthResponse, VaultAuthenticator};
pub use conflict::{Conflict, ConflictError, ConflictId, ConflictStore};
pub use event::{Event, EventError, EventId, EventType, RecordMutation};
pub use history::{EventHistory, HistoryError};
pub use keys::{derive_master_key, EncryptedKeyHierarchy, KeyError, VaultKeys};
pub use membership::{
    MemberRole, MembershipChange, MembershipChangeType, MembershipError, MembershipOperation,
    MembershipStore, VaultMember,
};
pub use record::{EncryptedRecord, RecordData, RecordError, RecordId, RecordStore, RecordType};
pub use sync::{
    EventAck, EventInventory, EventRange, EventReject, EventTransfer, EventTransferError,
    EventTransferResult, MissingEventsRequest, RecordComparison, RecordDifference, RecordSummary,
    SyncComparison, SyncEvents, SyncSummary, SyncSummaryError, MAX_SYNC_EVENTS,
};
pub use vault::{KdfParameters, VaultHeader, VaultId, VaultMetadata};
pub use version_vector::{VersionOrdering, VersionVector, VersionVectorError};
