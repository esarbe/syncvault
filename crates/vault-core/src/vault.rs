//! Vault identity, header, and metadata types.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::membership::VaultMember;

/// Stable identity of a vault.
pub type VaultId = Uuid;

/// Parameters needed to reproduce password-based key derivation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParameters {
    pub algorithm: String,
    pub salt: Vec<u8>,
    pub memory_cost_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParameters {
    pub fn argon2id(
        salt: Vec<u8>,
        memory_cost_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Self {
        Self {
            algorithm: "argon2id".to_string(),
            salt,
            memory_cost_kib,
            iterations,
            parallelism,
        }
    }
}

/// Persisted vault header. Key material is always encrypted or a key check;
/// plaintext passwords and record contents must never be placed here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultHeader {
    pub vault_id: VaultId,
    pub protocol_version: u16,
    pub kdf: KdfParameters,
    pub encrypted_vault_key: Vec<u8>,
    pub encrypted_history_key: Vec<u8>,
    pub key_check: Vec<u8>,
    pub members: Vec<VaultMember>,
}

impl VaultHeader {
    pub fn metadata(&self) -> VaultMetadata {
        VaultMetadata {
            vault_id: self.vault_id,
            protocol_version: self.protocol_version,
            kdf: self.kdf.clone(),
            members: self.members.clone(),
        }
    }
}

/// Redacted metadata safe to expose without encrypted key material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultMetadata {
    pub vault_id: VaultId,
    pub protocol_version: u16,
    pub kdf: KdfParameters,
    pub members: Vec<VaultMember>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use syncthing_core::DeviceId;

    #[test]
    fn metadata_redacts_encrypted_key_material() {
        let header = VaultHeader {
            vault_id: Uuid::new_v4(),
            protocol_version: 1,
            kdf: KdfParameters::argon2id(vec![1; 16], 64 * 1024, 3, 1),
            encrypted_vault_key: b"encrypted-vault-key".to_vec(),
            encrypted_history_key: b"encrypted-history-key".to_vec(),
            key_check: b"key-check".to_vec(),
            members: vec![VaultMember {
                member_id: Uuid::new_v4(),
                device_id: DeviceId::random(),
                public_key: vec![2; 32],
                encrypted_vault_key: b"wrapped-key".to_vec(),
                role: crate::membership::MemberRole::Reader,
                created_at: 1,
                revoked_at: None,
            }],
        };

        let metadata = serde_json::to_string(&header.metadata()).unwrap();
        assert!(!metadata.contains("encrypted-vault-key"));
        assert!(!metadata.contains("encrypted-history-key"));
        assert!(!metadata.contains("key-check"));
    }
}
