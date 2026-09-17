//! Atomic persistence for vault metadata and synchronization state.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::conflict::Conflict;
use crate::event::{Event, EventId};
use crate::membership::VaultMember;
use crate::record::EncryptedRecord;
use crate::vault::VaultMetadata;
use crate::version_vector::VersionVector;
use syncthing_core::DeviceId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedEventIndexEntry {
    pub device_id: DeviceId,
    pub device_sequence: u64,
    pub event_id: EventId,
    pub record_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultSnapshot {
    pub metadata: VaultMetadata,
    pub records: Vec<EncryptedRecord>,
    pub events: Vec<Event>,
    pub version_vector: VersionVector,
    pub members: Vec<VaultMember>,
    pub conflicts: Vec<Conflict>,
    pub event_index: Vec<PersistedEventIndexEntry>,
    pub sync_state: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("persistence I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("persistence serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, PersistenceError>;

#[derive(Debug, Clone)]
pub struct VaultPersistence {
    path: PathBuf,
}

impl VaultPersistence {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save(&self, snapshot: &VaultSnapshot) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(snapshot)?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary_path = self.path.with_extension(format!("tmp-{}", Uuid::new_v4()));
        fs::write(&temporary_path, bytes)?;
        if let Err(error) = fs::rename(&temporary_path, &self.path) {
            let _ = fs::remove_file(&temporary_path);
            return Err(PersistenceError::Io(error));
        }
        Ok(())
    }

    pub fn load(&self) -> Result<VaultSnapshot> {
        let bytes = fs::read(&self.path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{KdfParameters, VaultId};

    #[test]
    fn atomically_round_trips_vault_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let persistence = VaultPersistence::new(directory.path().join("vault.json"));
        let snapshot = VaultSnapshot {
            metadata: VaultMetadata {
                vault_id: VaultId::new_v4(),
                protocol_version: 1,
                kdf: KdfParameters::argon2id(vec![1; 16], 19 * 1024, 2, 1),
                members: Vec::new(),
            },
            records: Vec::new(),
            events: Vec::new(),
            version_vector: VersionVector::new(),
            members: Vec::new(),
            conflicts: Vec::new(),
            event_index: Vec::new(),
            sync_state: b"last-sync-token".to_vec(),
        };

        persistence.save(&snapshot).unwrap();
        assert_eq!(persistence.load().unwrap(), snapshot);
        assert!(persistence.path().exists());
    }

    #[test]
    fn failed_load_does_not_create_state() {
        let directory = tempfile::tempdir().unwrap();
        let persistence = VaultPersistence::new(directory.path().join("missing-vault.json"));
        assert!(matches!(persistence.load(), Err(PersistenceError::Io(_))));
    }
}
