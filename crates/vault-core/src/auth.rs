//! Vault-level member authentication after transport authentication.

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::membership::MembershipStore;
use crate::vault::VaultId;
use syncthing_core::DeviceId;

const AUTH_CONTEXT: &[u8] = b"st-vault/1/auth";
const MAX_AUTH_NONCE_SIZE: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthRequest {
    pub vault_id: VaultId,
    pub member_id: Uuid,
    pub device_id: DeviceId,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthResponse {
    pub vault_id: VaultId,
    pub member_id: Uuid,
    pub device_id: DeviceId,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("unknown vault")]
    WrongVault,
    #[error("unknown vault member")]
    UnknownMember,
    #[error("vault member is revoked")]
    RevokedMember,
    #[error("member device does not match TLS peer")]
    DeviceMismatch,
    #[error("authentication nonce is empty")]
    EmptyNonce,
    #[error("authentication nonce exceeds the maximum size")]
    NonceTooLarge,
    #[error("authentication nonce was already used")]
    ReplayedNonce,
    #[error("authentication signature is invalid")]
    InvalidSignature,
    #[error("authentication signer does not match member key")]
    InvalidSigner,
    #[error("authentication signature has invalid length")]
    InvalidSignatureLength,
}

pub type Result<T> = std::result::Result<T, AuthError>;

pub struct VaultAuthenticator {
    vault_id: VaultId,
    members: MembershipStore,
    used_nonces: HashSet<Vec<u8>>,
}

impl VaultAuthenticator {
    pub fn new(vault_id: VaultId, members: MembershipStore) -> Self {
        Self {
            vault_id,
            members,
            used_nonces: HashSet::new(),
        }
    }

    pub fn request(
        vault_id: VaultId,
        member_id: Uuid,
        device_id: DeviceId,
        nonce: Vec<u8>,
        signing_key: &SigningKey,
    ) -> Result<AuthRequest> {
        if nonce.is_empty() {
            return Err(AuthError::EmptyNonce);
        }
        if nonce.len() > MAX_AUTH_NONCE_SIZE {
            return Err(AuthError::NonceTooLarge);
        }
        let mut request = AuthRequest {
            vault_id,
            member_id,
            device_id,
            nonce,
            signature: Vec::new(),
        };
        request.signature = signing_key
            .sign(&authentication_bytes(&request))
            .to_bytes()
            .to_vec();
        Ok(request)
    }

    pub fn respond(
        &mut self,
        request: &AuthRequest,
        tls_peer: DeviceId,
        responder_member_id: Uuid,
        responder_device_id: DeviceId,
        signing_key: &SigningKey,
    ) -> Result<AuthResponse> {
        self.validate_request(request, tls_peer)?;
        let member = self
            .members
            .find_member(responder_member_id)
            .ok_or(AuthError::UnknownMember)?;
        if !member.is_active() {
            return Err(AuthError::RevokedMember);
        }
        if member.device_id != responder_device_id {
            return Err(AuthError::DeviceMismatch);
        }
        let public_key: [u8; 32] = member
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::InvalidSignature)?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .map_err(|_| AuthError::InvalidSignature)?;
        if signing_key.verifying_key() != verifying_key {
            return Err(AuthError::InvalidSigner);
        }
        let signature = signing_key
            .sign(&authentication_bytes(request))
            .to_bytes()
            .to_vec();
        self.used_nonces.insert(request.nonce.clone());
        Ok(AuthResponse {
            vault_id: request.vault_id,
            member_id: responder_member_id,
            device_id: responder_device_id,
            nonce: request.nonce.clone(),
            signature,
        })
    }

    pub fn verify_response(
        &mut self,
        request: &AuthRequest,
        response: &AuthResponse,
        tls_peer: DeviceId,
    ) -> Result<()> {
        if response.vault_id != self.vault_id || response.vault_id != request.vault_id {
            return Err(AuthError::WrongVault);
        }
        if response.device_id != tls_peer || response.nonce != request.nonce {
            return Err(AuthError::DeviceMismatch);
        }
        let member = self
            .members
            .find_member(response.member_id)
            .ok_or(AuthError::UnknownMember)?;
        if !member.is_active() {
            return Err(AuthError::RevokedMember);
        }
        if member.device_id != response.device_id {
            return Err(AuthError::DeviceMismatch);
        }
        let public_key: [u8; 32] = member
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::InvalidSignature)?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .map_err(|_| AuthError::InvalidSignature)?;
        let signature: [u8; 64] = response
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::InvalidSignatureLength)?;
        verifying_key
            .verify(
                &authentication_bytes(request),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| AuthError::InvalidSignature)?;
        if !self.used_nonces.insert(request.nonce.clone()) {
            return Err(AuthError::ReplayedNonce);
        }
        Ok(())
    }

    fn validate_request(&self, request: &AuthRequest, tls_peer: DeviceId) -> Result<()> {
        if request.vault_id != self.vault_id {
            return Err(AuthError::WrongVault);
        }
        if request.nonce.is_empty() {
            return Err(AuthError::EmptyNonce);
        }
        if request.nonce.len() > MAX_AUTH_NONCE_SIZE {
            return Err(AuthError::NonceTooLarge);
        }
        if request.device_id != tls_peer {
            return Err(AuthError::DeviceMismatch);
        }
        let member = self
            .members
            .find_member(request.member_id)
            .ok_or(AuthError::UnknownMember)?;
        if !member.is_active() {
            return Err(AuthError::RevokedMember);
        }
        if member.device_id != request.device_id {
            return Err(AuthError::DeviceMismatch);
        }
        let public_key: [u8; 32] = member
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::InvalidSignature)?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .map_err(|_| AuthError::InvalidSignature)?;
        let signature: [u8; 64] = request
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::InvalidSignatureLength)?;
        verifying_key
            .verify(
                &authentication_bytes(request),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| AuthError::InvalidSignature)?;
        if self.used_nonces.contains(&request.nonce) {
            return Err(AuthError::ReplayedNonce);
        }
        Ok(())
    }
}

fn authentication_bytes(request: &AuthRequest) -> Vec<u8> {
    let mut bytes = AUTH_CONTEXT.to_vec();
    bytes.extend_from_slice(request.vault_id.as_bytes());
    bytes.extend_from_slice(request.member_id.as_bytes());
    bytes.extend_from_slice(request.device_id.as_bytes());
    bytes.extend_from_slice(&(request.nonce.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&request.nonce);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::{MemberRole, VaultMember};

    fn member(key: &SigningKey, device_id: DeviceId, revoked_at: Option<i64>) -> VaultMember {
        VaultMember {
            member_id: Uuid::new_v4(),
            device_id,
            public_key: key.verifying_key().to_bytes().to_vec(),
            encrypted_vault_key: b"wrapped-key".to_vec(),
            role: MemberRole::Reader,
            created_at: 1,
            revoked_at,
        }
    }

    fn setup(revoked_at: Option<i64>) -> (VaultAuthenticator, SigningKey, VaultId, DeviceId, Uuid) {
        let key = SigningKey::from_bytes(&[11; 32]);
        let device_id = DeviceId::random();
        let vault_id = Uuid::new_v4();
        let vault_member = member(&key, device_id, revoked_at);
        let member_id = vault_member.member_id;
        let mut members = MembershipStore::new();
        members.insert_member(vault_member).unwrap();
        (
            VaultAuthenticator::new(vault_id, members),
            key,
            vault_id,
            device_id,
            member_id,
        )
    }

    #[test]
    fn authenticates_authorized_member_and_rejects_replay() {
        let (mut verifier, key, vault_id, device_id, member_id) = setup(None);
        let request =
            VaultAuthenticator::request(vault_id, member_id, device_id, vec![1; 32], &key).unwrap();
        let response = verifier
            .respond(&request, device_id, member_id, device_id, &key)
            .unwrap();
        let mut client = VaultAuthenticator::new(verifier.vault_id, verifier.members.clone());
        client
            .verify_response(&request, &response, device_id)
            .unwrap();
        assert_eq!(
            client.verify_response(&request, &response, device_id),
            Err(AuthError::ReplayedNonce)
        );
    }

    #[test]
    fn rejects_wrong_vault_revoked_member_and_device_mismatch() {
        let (mut verifier, key, vault_id, device_id, member_id) = setup(Some(2));
        let request =
            VaultAuthenticator::request(vault_id, member_id, device_id, vec![2; 16], &key).unwrap();
        assert_eq!(
            verifier.respond(&request, device_id, member_id, device_id, &key),
            Err(AuthError::RevokedMember)
        );

        let (mut verifier, key, _, device_id, member_id) = setup(None);
        let request =
            VaultAuthenticator::request(Uuid::new_v4(), member_id, device_id, vec![3], &key)
                .unwrap();
        assert_eq!(
            verifier.respond(&request, device_id, member_id, device_id, &key),
            Err(AuthError::WrongVault)
        );

        let request =
            VaultAuthenticator::request(verifier.vault_id, member_id, device_id, vec![4], &key)
                .unwrap();
        let wrong_peer = DeviceId::random();
        assert_eq!(
            verifier.respond(&request, wrong_peer, member_id, device_id, &key),
            Err(AuthError::DeviceMismatch)
        );
    }

    #[test]
    fn rejects_response_from_wrong_private_key() {
        let (mut verifier, key, vault_id, device_id, member_id) = setup(None);
        let request =
            VaultAuthenticator::request(vault_id, member_id, device_id, vec![5], &key).unwrap();
        let wrong_key = SigningKey::from_bytes(&[12; 32]);
        assert_eq!(
            verifier.respond(&request, device_id, member_id, device_id, &wrong_key),
            Err(AuthError::InvalidSigner)
        );
    }

    #[test]
    fn revoked_member_cannot_authenticate_after_owner_revoke() {
        let owner_key = SigningKey::from_bytes(&[13; 32]);
        let member_key = SigningKey::from_bytes(&[14; 32]);
        let owner_device = DeviceId::random();
        let member_device = DeviceId::random();
        let owner = VaultMember {
            member_id: Uuid::new_v4(),
            device_id: owner_device,
            public_key: owner_key.verifying_key().to_bytes().to_vec(),
            encrypted_vault_key: vec![1; 32],
            role: MemberRole::Owner,
            created_at: 1,
            revoked_at: None,
        };
        let member = VaultMember {
            member_id: Uuid::new_v4(),
            device_id: member_device,
            public_key: member_key.verifying_key().to_bytes().to_vec(),
            encrypted_vault_key: vec![2; 32],
            role: MemberRole::Reader,
            created_at: 1,
            revoked_at: None,
        };
        let member_id = member.member_id;
        let vault_id = Uuid::new_v4();
        let mut members = MembershipStore::new();
        members.insert_member(owner.clone()).unwrap();
        members.enroll_member(&owner, member, &owner_key).unwrap();

        let mut authenticator = VaultAuthenticator::new(vault_id, members.clone());
        let request = VaultAuthenticator::request(
            vault_id,
            member_id,
            member_device,
            vec![6; 16],
            &member_key,
        )
        .unwrap();
        let response = authenticator
            .respond(
                &request,
                member_device,
                member_id,
                member_device,
                &member_key,
            )
            .unwrap();
        let mut verifier = VaultAuthenticator::new(vault_id, members.clone());
        verifier
            .verify_response(&request, &response, member_device)
            .unwrap();

        let mut revoked_members = members;
        let change = revoked_members
            .revoke_member(&owner, member_id, &owner_key, 2)
            .unwrap();
        change.verify(&owner_key.verifying_key()).unwrap();
        let mut revoked_authenticator = VaultAuthenticator::new(vault_id, revoked_members);
        assert_eq!(
            revoked_authenticator.respond(
                &request,
                member_device,
                member_id,
                member_device,
                &member_key,
            ),
            Err(AuthError::RevokedMember)
        );
    }
}
