//! Durable vault discovery and password-based lifecycle operations.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use syncthing_core::DeviceId;
use uuid::Uuid;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::keys::{EncryptedKeyHierarchy, KeyError, VaultKeys};
use crate::membership::{MemberRole, VaultMember};
use crate::persistence::{PersistenceError, VaultPersistence, VaultSnapshot};
use crate::vault::{KdfParameters, VaultHeader, VaultId, VaultMetadata};
use crate::version_vector::VersionVector;

const REGISTRY_FILE: &str = "vault-registry.json";
const VAULT_DIRECTORY: &str = "vaults";
const PROTOCOL_VERSION: u16 = 1;
const SALT_SIZE: usize = 16;
const SIGNING_KEY_CONTEXT: &[u8] = b"st-vault/1/local-signing-key";

#[derive(Clone)]
pub struct VaultPassword(Zeroizing<Vec<u8>>);

impl VaultPassword {
    pub fn new(password: Vec<u8>) -> Self {
        Self(Zeroizing::new(password))
    }

    fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultPeer {
    pub device_id: DeviceId,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultRegistryEntry {
    pub name: String,
    pub vault_id: VaultId,
    pub storage_path: PathBuf,
    pub local_member_id: Uuid,
    pub peers: Vec<VaultPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RegistryManifest {
    entries: Vec<VaultRegistryEntry>,
}

#[derive(Debug, Clone)]
pub struct OpenedVault {
    entry: VaultRegistryEntry,
    metadata: VaultMetadata,
}

impl OpenedVault {
    pub fn entry(&self) -> &VaultRegistryEntry {
        &self.entry
    }

    pub fn metadata(&self) -> &VaultMetadata {
        &self.metadata
    }
}

pub struct UnlockedVault {
    entry: VaultRegistryEntry,
    metadata: VaultMetadata,
    keys: VaultKeys,
    signing_key: SigningKey,
}

impl UnlockedVault {
    pub fn entry(&self) -> &VaultRegistryEntry {
        &self.entry
    }

    pub fn metadata(&self) -> &VaultMetadata {
        &self.metadata
    }

    pub fn keys(&self) -> &VaultKeys {
        &self.keys
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VaultLifecycleError {
    #[error("vault name is invalid")]
    InvalidName,
    #[error("vault already exists: {0}")]
    AlreadyExists(String),
    #[error("vault not found: {0}")]
    NotFound(String),
    #[error("vault registry is inconsistent: {0}")]
    InconsistentRegistry(String),
    #[error("vault cryptography failed: {0}")]
    Crypto(#[from] KeyError),
    #[error("vault persistence failed: {0}")]
    Persistence(#[from] PersistenceError),
    #[error("vault registry I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault registry serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, VaultLifecycleError>;

#[derive(Debug, Clone)]
pub struct VaultRegistry {
    root: PathBuf,
}

impl VaultRegistry {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn list_vaults(&self) -> Result<Vec<VaultRegistryEntry>> {
        Ok(self.load_manifest()?.entries)
    }

    pub fn create_vault(
        &self,
        name: &str,
        password: &VaultPassword,
        local_device_id: DeviceId,
    ) -> Result<UnlockedVault> {
        validate_name(name)?;
        let mut manifest = self.load_manifest()?;
        if manifest.entries.iter().any(|entry| entry.name == name) {
            return Err(VaultLifecycleError::AlreadyExists(name.to_string()));
        }

        let vault_id = VaultId::new_v4();
        let local_member_id = Uuid::new_v4();
        let mut salt = vec![0; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        let kdf = KdfParameters::argon2id(salt, 64 * 1024, 3, 1);
        let (keys, hierarchy) = VaultKeys::create(password.expose(), &kdf)?;
        let mut signing_key_bytes = [0; 32];
        OsRng.fill_bytes(&mut signing_key_bytes);
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        signing_key_bytes.fill(0);

        let owner = VaultMember {
            member_id: local_member_id,
            device_id: local_device_id,
            public_key: signing_key.verifying_key().to_bytes().to_vec(),
            encrypted_vault_key: hierarchy.encrypted_vault_key.clone(),
            role: MemberRole::Owner,
            created_at: unix_timestamp(),
            revoked_at: None,
        };
        let header = build_header(vault_id, kdf, hierarchy, owner.clone());
        let encrypted_signing_key = keys.encrypt(
            signing_key.as_bytes(),
            &signing_key_associated_data(vault_id),
        )?;
        let storage_path = PathBuf::from(VAULT_DIRECTORY).join(format!("{vault_id}.json"));
        let entry = VaultRegistryEntry {
            name: name.to_string(),
            vault_id,
            storage_path,
            local_member_id,
            peers: Vec::new(),
        };
        let snapshot = empty_snapshot(header, encrypted_signing_key, owner);
        let persistence = VaultPersistence::new(self.resolve_storage_path(&entry)?);
        persistence.save(&snapshot)?;

        manifest.entries.push(entry.clone());
        manifest
            .entries
            .sort_by(|left, right| left.name.cmp(&right.name));
        if let Err(error) = self.save_manifest(&manifest) {
            let _ = fs::remove_file(persistence.path());
            return Err(error);
        }

        Ok(UnlockedVault {
            metadata: snapshot.header.metadata(),
            entry,
            keys,
            signing_key,
        })
    }

    pub fn open_vault(&self, name: &str) -> Result<OpenedVault> {
        let (entry, snapshot) = self.load_named_snapshot(name)?;
        Ok(OpenedVault {
            entry,
            metadata: snapshot.header.metadata(),
        })
    }

    pub fn unlock_vault(&self, name: &str, password: &VaultPassword) -> Result<UnlockedVault> {
        let (entry, snapshot) = self.load_named_snapshot(name)?;
        let hierarchy = EncryptedKeyHierarchy {
            encrypted_vault_key: snapshot.header.encrypted_vault_key.clone(),
            encrypted_history_key: snapshot.header.encrypted_history_key.clone(),
            key_check: snapshot.header.key_check.clone(),
        };
        let keys = VaultKeys::unlock(password.expose(), &snapshot.header.kdf, &hierarchy)?;
        let signing_key_bytes = keys.decrypt(
            &snapshot.encrypted_signing_key,
            &signing_key_associated_data(entry.vault_id),
        )?;
        let mut signing_key_bytes: [u8; 32] = signing_key_bytes
            .try_into()
            .map_err(|_| KeyError::InvalidCiphertext)?;
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        signing_key_bytes.zeroize();

        Ok(UnlockedVault {
            metadata: snapshot.header.metadata(),
            entry,
            keys,
            signing_key,
        })
    }

    fn load_named_snapshot(&self, name: &str) -> Result<(VaultRegistryEntry, VaultSnapshot)> {
        validate_name(name)?;
        let entry = self
            .load_manifest()?
            .entries
            .into_iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| VaultLifecycleError::NotFound(name.to_string()))?;
        let snapshot = VaultPersistence::new(self.resolve_storage_path(&entry)?).load()?;
        if snapshot.header.vault_id != entry.vault_id {
            return Err(VaultLifecycleError::InconsistentRegistry(name.to_string()));
        }
        Ok((entry, snapshot))
    }

    fn load_manifest(&self) -> Result<RegistryManifest> {
        let path = self.root.join(REGISTRY_FILE);
        match fs::read(path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(RegistryManifest::default())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn save_manifest(&self, manifest: &RegistryManifest) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        set_private_directory_permissions(&self.root)?;
        let path = self.root.join(REGISTRY_FILE);
        let temporary_path = self
            .root
            .join(format!(".{REGISTRY_FILE}.tmp-{}", Uuid::new_v4()));
        fs::write(&temporary_path, serde_json::to_vec_pretty(manifest)?)?;
        set_private_permissions(&temporary_path)?;
        if let Err(error) = fs::rename(&temporary_path, path) {
            let _ = fs::remove_file(temporary_path);
            return Err(error.into());
        }
        Ok(())
    }

    fn resolve_storage_path(&self, entry: &VaultRegistryEntry) -> Result<PathBuf> {
        if entry.storage_path.is_absolute()
            || entry.storage_path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::RootDir
                )
            })
        {
            return Err(VaultLifecycleError::InconsistentRegistry(
                entry.name.clone(),
            ));
        }
        Ok(self.root.join(&entry.storage_path))
    }
}

fn build_header(
    vault_id: VaultId,
    kdf: KdfParameters,
    hierarchy: EncryptedKeyHierarchy,
    owner: VaultMember,
) -> VaultHeader {
    VaultHeader {
        vault_id,
        protocol_version: PROTOCOL_VERSION,
        kdf,
        encrypted_vault_key: hierarchy.encrypted_vault_key,
        encrypted_history_key: hierarchy.encrypted_history_key,
        key_check: hierarchy.key_check,
        members: vec![owner],
    }
}

fn empty_snapshot(
    header: VaultHeader,
    encrypted_signing_key: Vec<u8>,
    owner: VaultMember,
) -> VaultSnapshot {
    VaultSnapshot {
        header,
        encrypted_signing_key,
        records: Vec::new(),
        events: Vec::new(),
        version_vector: VersionVector::new(),
        members: vec![owner],
        conflicts: Vec::new(),
        event_index: Vec::new(),
        sync_state: Vec::new(),
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || name.trim() != name
        || name == "."
        || name == ".."
        || name
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
    {
        return Err(VaultLifecycleError::InvalidName);
    }
    Ok(())
}

fn signing_key_associated_data(vault_id: VaultId) -> Vec<u8> {
    let mut data = SIGNING_KEY_CONTEXT.to_vec();
    data.extend_from_slice(vault_id.as_bytes());
    data
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
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
    use crate::{Event, EventType, RecordMutation, VersionVector};
    use tempfile::tempdir;

    fn password(value: &str) -> VaultPassword {
        VaultPassword::new(value.as_bytes().to_vec())
    }

    #[test]
    fn creates_lists_opens_and_unlocks_after_restart() {
        let directory = tempdir().unwrap();
        let device_id = DeviceId::random();
        let registry = VaultRegistry::new(directory.path());
        let created = registry
            .create_vault("personal", &password("correct horse"), device_id)
            .unwrap();
        let vault_id = created.entry().vault_id;
        let public_key = created.signing_key().verifying_key();
        drop(created);

        let reopened_registry = VaultRegistry::new(directory.path());
        let entries = reopened_registry.list_vaults().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "personal");
        assert_eq!(entries[0].vault_id, vault_id);

        let opened = reopened_registry.open_vault("personal").unwrap();
        assert_eq!(opened.metadata().vault_id, vault_id);
        assert_eq!(opened.metadata().members[0].device_id, device_id);
        assert_eq!(opened.metadata().members[0].role, MemberRole::Owner);

        let unlocked = reopened_registry
            .unlock_vault("personal", &password("correct horse"))
            .unwrap();
        assert_eq!(unlocked.signing_key().verifying_key(), public_key);
        let event = Event::sign(
            Uuid::new_v4(),
            RecordMutation::new(EventType::Create, vec![1]),
            VersionVector::new(),
            device_id,
            1,
            unlocked.signing_key(),
        )
        .unwrap();
        event.verify(&public_key).unwrap();
    }

    #[test]
    fn rejects_wrong_password_duplicate_and_invalid_names() {
        let directory = tempdir().unwrap();
        let registry = VaultRegistry::new(directory.path());
        registry
            .create_vault("work", &password("correct horse"), DeviceId::random())
            .unwrap();

        assert!(matches!(
            registry.unlock_vault("work", &password("wrong horse")),
            Err(VaultLifecycleError::Crypto(KeyError::KeyCheckFailed))
        ));
        assert!(matches!(
            registry.create_vault("work", &password("another password"), DeviceId::random()),
            Err(VaultLifecycleError::AlreadyExists(_))
        ));
        assert!(matches!(
            registry.create_vault("../escape", &password("password"), DeviceId::random()),
            Err(VaultLifecycleError::InvalidName)
        ));
    }

    #[test]
    fn rejects_storage_paths_that_escape_the_registry() {
        let directory = tempdir().unwrap();
        let registry = VaultRegistry::new(directory.path());
        let manifest = RegistryManifest {
            entries: vec![VaultRegistryEntry {
                name: "escaped".to_string(),
                vault_id: VaultId::new_v4(),
                storage_path: PathBuf::from("../escaped.json"),
                local_member_id: Uuid::new_v4(),
                peers: Vec::new(),
            }],
        };
        registry.save_manifest(&manifest).unwrap();

        assert!(matches!(
            registry.open_vault("escaped"),
            Err(VaultLifecycleError::InconsistentRegistry(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn registry_and_vault_files_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().unwrap();
        let registry = VaultRegistry::new(directory.path());
        let vault = registry
            .create_vault("private", &password("password"), DeviceId::random())
            .unwrap();
        let registry_mode = fs::metadata(directory.path().join(REGISTRY_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let vault_mode = fs::metadata(directory.path().join(&vault.entry().storage_path))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(registry_mode, 0o600);
        assert_eq!(vault_mode, 0o600);
        assert_eq!(
            fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(directory.path().join(VAULT_DIRECTORY))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}
