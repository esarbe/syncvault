//! Vault membership, roles, authorization, and signed membership changes.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use syncthing_core::DeviceId;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemberRole {
    Owner,
    Writer,
    Reader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipOperation {
    Read,
    Create,
    Update,
    Delete,
    Restore,
    AddMember,
    RevokeMember,
    RotateKeys,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultMember {
    pub member_id: Uuid,
    pub device_id: DeviceId,
    pub public_key: Vec<u8>,
    pub encrypted_vault_key: Vec<u8>,
    pub role: MemberRole,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

impl VaultMember {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MembershipChangeType {
    Add,
    Revoke,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MembershipChange {
    pub change_id: Uuid,
    pub member_id: Uuid,
    pub change_type: MembershipChangeType,
    pub actor: DeviceId,
    pub timestamp: i64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceEnrollment {
    pub enrollment_id: Uuid,
    pub member: VaultMember,
    pub actor: DeviceId,
    pub timestamp: i64,
    pub signature: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MembershipError {
    #[error("member not found: {0}")]
    NotFound(Uuid),
    #[error("member already exists: {0}")]
    AlreadyExists(Uuid),
    #[error("device is already a member: {0}")]
    DeviceAlreadyMember(DeviceId),
    #[error("membership operation is not authorized")]
    Unauthorized,
    #[error("member is revoked")]
    Revoked,
    #[error("membership signature is invalid")]
    InvalidSignature,
    #[error("membership key is invalid")]
    InvalidPublicKey,
    #[error("membership change serialization failed")]
    Serialization,
    #[error("encrypted vault key is empty")]
    EmptyEncryptedVaultKey,
}

pub type Result<T> = std::result::Result<T, MembershipError>;

#[derive(Debug, Clone, Default)]
pub struct MembershipStore {
    members: BTreeMap<Uuid, VaultMember>,
}

impl MembershipStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_member(&mut self, member: VaultMember) -> Result<()> {
        validate_public_key(&member.public_key)?;
        if self.members.contains_key(&member.member_id) {
            return Err(MembershipError::AlreadyExists(member.member_id));
        }
        if self
            .members
            .values()
            .any(|existing| existing.device_id == member.device_id)
        {
            return Err(MembershipError::DeviceAlreadyMember(member.device_id));
        }
        self.members.insert(member.member_id, member);
        Ok(())
    }

    pub fn add_member(
        &mut self,
        actor: &VaultMember,
        member: VaultMember,
        signing_key: &SigningKey,
    ) -> Result<MembershipChange> {
        self.authorize(actor, MembershipOperation::AddMember)?;
        validate_public_key(&member.public_key)?;
        if self.members.contains_key(&member.member_id) {
            return Err(MembershipError::AlreadyExists(member.member_id));
        }
        if self
            .members
            .values()
            .any(|existing| existing.device_id == member.device_id)
        {
            return Err(MembershipError::DeviceAlreadyMember(member.device_id));
        }
        let change = MembershipChange::new(
            member.member_id,
            MembershipChangeType::Add,
            actor.device_id,
            signing_key,
        )?;
        self.members.insert(member.member_id, member);
        Ok(change)
    }

    pub fn enroll_member(
        &mut self,
        actor: &VaultMember,
        member: VaultMember,
        signing_key: &SigningKey,
    ) -> Result<DeviceEnrollment> {
        self.authorize(actor, MembershipOperation::AddMember)?;
        validate_public_key(&member.public_key)?;
        if member.encrypted_vault_key.is_empty() {
            return Err(MembershipError::EmptyEncryptedVaultKey);
        }
        if self.members.contains_key(&member.member_id) {
            return Err(MembershipError::AlreadyExists(member.member_id));
        }
        if self
            .members
            .values()
            .any(|existing| existing.device_id == member.device_id)
        {
            return Err(MembershipError::DeviceAlreadyMember(member.device_id));
        }
        let enrollment = DeviceEnrollment::new(member.clone(), actor.device_id, signing_key)?;
        self.members.insert(member.member_id, member);
        Ok(enrollment)
    }

    pub fn revoke_member(
        &mut self,
        actor: &VaultMember,
        member_id: Uuid,
        signing_key: &SigningKey,
        timestamp: i64,
    ) -> Result<MembershipChange> {
        self.authorize(actor, MembershipOperation::RevokeMember)?;
        let member = self
            .members
            .get_mut(&member_id)
            .ok_or(MembershipError::NotFound(member_id))?;
        if member.revoked_at.is_some() {
            return Err(MembershipError::Revoked);
        }
        member.revoked_at = Some(timestamp);
        MembershipChange::new_with_timestamp(
            member_id,
            MembershipChangeType::Revoke,
            actor.device_id,
            timestamp,
            signing_key,
        )
    }

    pub fn find_member(&self, member_id: Uuid) -> Option<&VaultMember> {
        self.members.get(&member_id)
    }

    pub fn authorize(&self, member: &VaultMember, operation: MembershipOperation) -> Result<()> {
        let stored = self
            .members
            .get(&member.member_id)
            .ok_or(MembershipError::NotFound(member.member_id))?;
        if stored.device_id != member.device_id || stored.public_key != member.public_key {
            return Err(MembershipError::Unauthorized);
        }
        if !stored.is_active() {
            return Err(MembershipError::Revoked);
        }
        let allowed = match stored.role {
            MemberRole::Owner => true,
            MemberRole::Writer => matches!(
                operation,
                MembershipOperation::Read
                    | MembershipOperation::Create
                    | MembershipOperation::Update
                    | MembershipOperation::Delete
                    | MembershipOperation::Restore
            ),
            MemberRole::Reader => matches!(operation, MembershipOperation::Read),
        };
        if allowed {
            Ok(())
        } else {
            Err(MembershipError::Unauthorized)
        }
    }

    pub fn members(&self) -> impl Iterator<Item = &VaultMember> {
        self.members.values()
    }
}

impl MembershipChange {
    fn new(
        member_id: Uuid,
        change_type: MembershipChangeType,
        actor: DeviceId,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        Self::new_with_timestamp(member_id, change_type, actor, unix_timestamp(), signing_key)
    }

    fn new_with_timestamp(
        member_id: Uuid,
        change_type: MembershipChangeType,
        actor: DeviceId,
        timestamp: i64,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        let mut change = Self {
            change_id: Uuid::new_v4(),
            member_id,
            change_type,
            actor,
            timestamp,
            signature: Vec::new(),
        };
        change.signature = serde_json::to_vec(&change)
            .map_err(|_| MembershipError::Serialization)
            .map(|bytes| signing_key.sign(&bytes).to_bytes().to_vec())?;
        Ok(change)
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<()> {
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| MembershipError::InvalidSignature)?;
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let bytes = serde_json::to_vec(&unsigned).map_err(|_| MembershipError::Serialization)?;
        verifying_key
            .verify(&bytes, &Signature::from_bytes(&signature))
            .map_err(|_| MembershipError::InvalidSignature)
    }
}

impl DeviceEnrollment {
    fn new(member: VaultMember, actor: DeviceId, signing_key: &SigningKey) -> Result<Self> {
        let mut enrollment = Self {
            enrollment_id: Uuid::new_v4(),
            member,
            actor,
            timestamp: unix_timestamp(),
            signature: Vec::new(),
        };
        let mut unsigned = enrollment.clone();
        unsigned.signature.clear();
        enrollment.signature = serde_json::to_vec(&unsigned)
            .map_err(|_| MembershipError::Serialization)
            .map(|bytes| signing_key.sign(&bytes).to_bytes().to_vec())?;
        Ok(enrollment)
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<()> {
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| MembershipError::InvalidSignature)?;
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let bytes = serde_json::to_vec(&unsigned).map_err(|_| MembershipError::Serialization)?;
        verifying_key
            .verify(&bytes, &Signature::from_bytes(&signature))
            .map_err(|_| MembershipError::InvalidSignature)
    }
}

fn validate_public_key(public_key: &[u8]) -> Result<()> {
    VerifyingKey::from_bytes(
        public_key
            .try_into()
            .map_err(|_| MembershipError::InvalidPublicKey)?,
    )
    .map(|_| ())
    .map_err(|_| MembershipError::InvalidPublicKey)
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(key: &SigningKey, role: MemberRole) -> VaultMember {
        VaultMember {
            member_id: Uuid::new_v4(),
            device_id: DeviceId::random(),
            public_key: key.verifying_key().to_bytes().to_vec(),
            encrypted_vault_key: b"wrapped-key".to_vec(),
            role,
            created_at: 1,
            revoked_at: None,
        }
    }

    #[test]
    fn owner_can_add_and_revoke_members_with_signed_changes() {
        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let reader_key = SigningKey::from_bytes(&[2; 32]);
        let owner = member(&owner_key, MemberRole::Owner);
        let reader = member(&reader_key, MemberRole::Reader);
        let reader_id = reader.member_id;
        let mut store = MembershipStore::new();
        store.members.insert(owner.member_id, owner.clone());

        let added = store.add_member(&owner, reader, &owner_key).unwrap();
        added.verify(&owner_key.verifying_key()).unwrap();
        let revoked = store
            .revoke_member(&owner, reader_id, &owner_key, 2)
            .unwrap();
        revoked.verify(&owner_key.verifying_key()).unwrap();
        assert_eq!(store.find_member(reader_id).unwrap().revoked_at, Some(2));
    }

    #[test]
    fn roles_and_revocation_limit_operations() {
        let owner_key = SigningKey::from_bytes(&[3; 32]);
        let writer_key = SigningKey::from_bytes(&[4; 32]);
        let reader_key = SigningKey::from_bytes(&[5; 32]);
        let owner = member(&owner_key, MemberRole::Owner);
        let writer = member(&writer_key, MemberRole::Writer);
        let reader = member(&reader_key, MemberRole::Reader);
        let mut store = MembershipStore::new();
        store.members.insert(owner.member_id, owner.clone());
        store.members.insert(writer.member_id, writer.clone());
        store.members.insert(reader.member_id, reader.clone());

        assert!(store
            .authorize(&writer, MembershipOperation::Update)
            .is_ok());
        assert!(store
            .authorize(&writer, MembershipOperation::AddMember)
            .is_err());
        assert!(store.authorize(&reader, MembershipOperation::Read).is_ok());
        assert!(store
            .authorize(&reader, MembershipOperation::Update)
            .is_err());

        store
            .revoke_member(&owner, writer.member_id, &owner_key, 3)
            .unwrap();
        assert_eq!(
            store.authorize(&writer, MembershipOperation::Read),
            Err(MembershipError::Revoked)
        );
    }

    #[test]
    fn owner_enrolls_new_device_with_signed_wrapped_key() {
        let owner_key = SigningKey::from_bytes(&[6; 32]);
        let device_key = SigningKey::from_bytes(&[7; 32]);
        let owner = member(&owner_key, MemberRole::Owner);
        let new_member = VaultMember {
            member_id: Uuid::new_v4(),
            device_id: DeviceId::random(),
            public_key: device_key.verifying_key().to_bytes().to_vec(),
            encrypted_vault_key: vec![9; 48],
            role: MemberRole::Reader,
            created_at: 2,
            revoked_at: None,
        };
        let new_id = new_member.member_id;
        let wrapped_key = new_member.encrypted_vault_key.clone();
        let mut store = MembershipStore::new();
        store.insert_member(owner.clone()).unwrap();

        let enrollment = store.enroll_member(&owner, new_member, &owner_key).unwrap();
        enrollment.verify(&owner_key.verifying_key()).unwrap();
        assert_eq!(
            store.find_member(new_id).unwrap().encrypted_vault_key,
            wrapped_key
        );
        assert!(store.find_member(new_id).unwrap().is_active());
    }

    #[test]
    fn non_owner_or_empty_wrapped_key_cannot_enroll() {
        let owner_key = SigningKey::from_bytes(&[8; 32]);
        let writer_key = SigningKey::from_bytes(&[9; 32]);
        let owner = member(&owner_key, MemberRole::Owner);
        let writer = member(&writer_key, MemberRole::Writer);
        let mut store = MembershipStore::new();
        store.insert_member(owner.clone()).unwrap();
        store.insert_member(writer.clone()).unwrap();
        let mut candidate = member(&SigningKey::from_bytes(&[10; 32]), MemberRole::Reader);
        candidate.encrypted_vault_key.clear();
        assert_eq!(
            store.enroll_member(&writer, candidate.clone(), &writer_key),
            Err(MembershipError::Unauthorized)
        );
        assert_eq!(
            store.enroll_member(&owner, candidate, &owner_key),
            Err(MembershipError::EmptyEncryptedVaultKey)
        );
    }
}
