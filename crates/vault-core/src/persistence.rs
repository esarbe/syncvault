//! Atomic persistence for vault metadata and synchronization state.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::conflict::Conflict;
use crate::event::{Event, EventId};
use crate::membership::VaultMember;
use crate::record::EncryptedRecord;
use crate::vault::VaultHeader;
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
    pub header: VaultHeader,
    pub encrypted_signing_key: Vec<u8>,
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
            set_private_directory_permissions(parent)?;
        }
        let temporary_path = self.path.with_extension(format!("tmp-{}", Uuid::new_v4()));
        fs::write(&temporary_path, bytes)?;
        set_private_permissions(&temporary_path)?;
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

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
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
            header: VaultHeader {
                vault_id: VaultId::new_v4(),
                protocol_version: 1,
                kdf: KdfParameters::argon2id(vec![1; 16], 19 * 1024, 2, 1),
                encrypted_vault_key: vec![2; 48],
                encrypted_history_key: vec![3; 48],
                key_check: vec![4; 48],
                members: Vec::new(),
            },
            encrypted_signing_key: vec![5; 72],
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

    #[cfg(unix)]
    #[test]
    fn snapshot_is_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let persistence = VaultPersistence::new(directory.path().join("vault.json"));
        let snapshot = VaultSnapshot {
            header: VaultHeader {
                vault_id: VaultId::new_v4(),
                protocol_version: 1,
                kdf: KdfParameters::argon2id(vec![1; 16], 19 * 1024, 2, 1),
                encrypted_vault_key: vec![2; 48],
                encrypted_history_key: vec![3; 48],
                key_check: vec![4; 48],
                members: Vec::new(),
            },
            encrypted_signing_key: vec![5; 72],
            records: Vec::new(),
            events: Vec::new(),
            version_vector: VersionVector::new(),
            members: Vec::new(),
            conflicts: Vec::new(),
            event_index: Vec::new(),
            sync_state: Vec::new(),
        };

        persistence.save(&snapshot).unwrap();
        let mode = fs::metadata(persistence.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn failed_load_does_not_create_state() {
        let directory = tempfile::tempdir().unwrap();
        let persistence = VaultPersistence::new(directory.path().join("missing-vault.json"));
        assert!(matches!(persistence.load(), Err(PersistenceError::Io(_))));
    }
}
