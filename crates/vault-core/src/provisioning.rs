//! Device identity provisioning and recipient-sealed vault enrollment.

use std::fs;
use std::path::{Path, PathBuf};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use syncthing_core::DeviceId;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::keys::{derive_master_key, KeyError, VaultKeys};
use crate::membership::MemberRole;
use crate::persistence::VaultSnapshot;
use crate::vault::{KdfParameters, VaultId};

const IDENTITY_VERSION: u16 = 1;
const ENROLLMENT_VERSION: u16 = 1;
const IDENTITY_FILE: &str = "vault-device-identity.json";
const IDENTITY_CONTEXT: &[u8] = b"st-vault/1/device-identity";
const ENROLLMENT_CONTEXT: &[u8] = b"st-vault/1/enrollment";
const NONCE_SIZE: usize = 24;
const SALT_SIZE: usize = 16;
const MAX_ENROLLMENT_BYTES: usize = 1024 * 1024;

pub const DEFAULT_ENROLLMENT_TTL_SECONDS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceIdentityPublic {
    pub version: u16,
    pub device_id: DeviceId,
    pub signing_public_key: Vec<u8>,
    pub wrapping_public_key: Vec<u8>,
}

pub struct DeviceIdentity {
    public: DeviceIdentityPublic,
    signing_key: SigningKey,
    wrapping_secret: StaticSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedDeviceIdentity {
    public: DeviceIdentityPublic,
    kdf: KdfParameters,
    encrypted_private_keys: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentRequest {
    pub version: u16,
    pub request_id: Uuid,
    pub created_at: i64,
    pub expires_at: i64,
    pub identity: DeviceIdentityPublic,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentBundle {
    pub version: u16,
    pub enrollment_id: Uuid,
    pub vault_id: VaultId,
    pub vault_name: String,
    pub protocol_version: u16,
    pub recipient: DeviceIdentityPublic,
    pub member_id: Uuid,
    pub role: MemberRole,
    pub owner_device_id: DeviceId,
    pub owner_public_key: Vec<u8>,
    pub owner_address: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub ephemeral_public_key: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct EnrollmentPayload {
    pub vault_keys: Vec<u8>,
    pub snapshot: VaultSnapshot,
}

pub(crate) struct EnrollmentSealInput<'a> {
    pub vault_id: VaultId,
    pub vault_name: String,
    pub protocol_version: u16,
    pub request: &'a EnrollmentRequest,
    pub member_id: Uuid,
    pub role: MemberRole,
    pub owner_device_id: DeviceId,
    pub owner_signing_key: &'a SigningKey,
    pub owner_address: String,
    pub payload: EnrollmentPayload,
    pub now: i64,
    pub ttl_seconds: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum ProvisioningError {
    #[error("device identity already exists")]
    IdentityAlreadyExists,
    #[error("device identity does not exist")]
    IdentityNotFound,
    #[error("device identity password or ciphertext is invalid")]
    InvalidIdentityCiphertext,
    #[error("device identity is inconsistent")]
    InvalidIdentity,
    #[error("enrollment request is invalid: {0}")]
    InvalidRequest(String),
    #[error("enrollment bundle is invalid: {0}")]
    InvalidBundle(String),
    #[error("enrollment material is expired")]
    Expired,
    #[error("enrollment material targets another device")]
    WrongRecipient,
    #[error("enrollment signature is invalid")]
    InvalidSignature,
    #[error("enrollment payload is too large")]
    PayloadTooLarge,
    #[error("provisioning cryptography failed")]
    Crypto,
    #[error("provisioning I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("provisioning serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("provisioning key operation failed: {0}")]
    Key(#[from] KeyError),
}

pub type Result<T> = std::result::Result<T, ProvisioningError>;

#[derive(Debug, Clone)]
pub struct DeviceIdentityStore {
    path: PathBuf,
}

impl DeviceIdentityStore {
    pub fn new(config_root: impl AsRef<Path>) -> Self {
        Self {
            path: config_root.as_ref().join(IDENTITY_FILE),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn generate(&self, device_id: DeviceId, password: &[u8]) -> Result<DeviceIdentityPublic> {
        if self.path.exists() {
            return Err(ProvisioningError::IdentityAlreadyExists);
        }
        let mut signing_seed = [0u8; 32];
        OsRng.fill_bytes(&mut signing_seed);
        let signing_key = SigningKey::from_bytes(&signing_seed);
        signing_seed.zeroize();
        let wrapping_secret = StaticSecret::random_from_rng(OsRng);
        let public = DeviceIdentityPublic {
            version: IDENTITY_VERSION,
            device_id,
            signing_public_key: signing_key.verifying_key().to_bytes().to_vec(),
            wrapping_public_key: X25519PublicKey::from(&wrapping_secret).as_bytes().to_vec(),
        };
        validate_public_identity(&public)?;

        let kdf = random_kdf();
        let key = derive_master_key(password, &kdf)?;
        let mut private = Zeroizing::new(Vec::with_capacity(64));
        private.extend_from_slice(signing_key.as_bytes());
        private.extend_from_slice(wrapping_secret.as_bytes());
        let encrypted_private_keys = encrypt(&key, &private, &identity_aad(&public))?;
        let persisted = PersistedDeviceIdentity {
            public: public.clone(),
            kdf,
            encrypted_private_keys,
        };
        atomic_write(&self.path, &serde_json::to_vec_pretty(&persisted)?)?;
        Ok(public)
    }

    pub fn show(&self) -> Result<DeviceIdentityPublic> {
        let persisted = self.load_persisted()?;
        validate_public_identity(&persisted.public)?;
        Ok(persisted.public)
    }

    pub fn unlock(&self, password: &[u8]) -> Result<DeviceIdentity> {
        let persisted = self.load_persisted()?;
        validate_public_identity(&persisted.public)?;
        let key = derive_master_key(password, &persisted.kdf)?;
        let private = decrypt(
            &key,
            &persisted.encrypted_private_keys,
            &identity_aad(&persisted.public),
        )
        .map_err(|_| ProvisioningError::InvalidIdentityCiphertext)?;
        if private.len() != 64 {
            return Err(ProvisioningError::InvalidIdentityCiphertext);
        }
        let mut signing_bytes: [u8; 32] = private[..32]
            .try_into()
            .map_err(|_| ProvisioningError::InvalidIdentityCiphertext)?;
        let mut wrapping_bytes: [u8; 32] = private[32..]
            .try_into()
            .map_err(|_| ProvisioningError::InvalidIdentityCiphertext)?;
        let signing_key = SigningKey::from_bytes(&signing_bytes);
        let wrapping_secret = StaticSecret::from(wrapping_bytes);
        signing_bytes.zeroize();
        wrapping_bytes.zeroize();
        if signing_key.verifying_key().to_bytes() != persisted.public.signing_public_key.as_slice()
            || X25519PublicKey::from(&wrapping_secret).as_bytes()
                != persisted.public.wrapping_public_key.as_slice()
        {
            return Err(ProvisioningError::InvalidIdentity);
        }
        Ok(DeviceIdentity {
            public: persisted.public,
            signing_key,
            wrapping_secret,
        })
    }

    fn load_persisted(&self) -> Result<PersistedDeviceIdentity> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(ProvisioningError::IdentityNotFound)
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl DeviceIdentity {
    pub fn public(&self) -> &DeviceIdentityPublic {
        &self.public
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn create_request(&self, now: i64, ttl_seconds: i64) -> Result<EnrollmentRequest> {
        if ttl_seconds <= 0 {
            return Err(ProvisioningError::InvalidRequest(
                "TTL must be positive".to_string(),
            ));
        }
        let expires_at = now
            .checked_add(ttl_seconds)
            .ok_or_else(|| ProvisioningError::InvalidRequest("TTL overflow".to_string()))?;
        let mut request = EnrollmentRequest {
            version: ENROLLMENT_VERSION,
            request_id: Uuid::new_v4(),
            created_at: now,
            expires_at,
            identity: self.public.clone(),
            signature: Vec::new(),
        };
        request.signature = self
            .signing_key
            .sign(&request.signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(request)
    }

    pub(crate) fn open_bundle(
        &self,
        bundle: &EnrollmentBundle,
        now: i64,
    ) -> Result<EnrollmentPayload> {
        bundle.verify(now)?;
        if bundle.recipient != self.public {
            return Err(ProvisioningError::WrongRecipient);
        }
        let ephemeral: [u8; 32] = bundle
            .ephemeral_public_key
            .as_slice()
            .try_into()
            .map_err(|_| ProvisioningError::InvalidBundle("invalid ephemeral key".to_string()))?;
        let shared = self
            .wrapping_secret
            .diffie_hellman(&X25519PublicKey::from(ephemeral));
        let key = enrollment_key(shared.as_bytes(), bundle.enrollment_id, bundle.vault_id)?;
        let plaintext = decrypt(&key, &bundle.encrypted_payload, &bundle_aad(bundle))?;
        let payload: EnrollmentPayload = serde_json::from_slice(&plaintext)?;
        if payload.vault_keys.len() != 64 {
            return Err(ProvisioningError::InvalidBundle(
                "invalid vault key payload".to_string(),
            ));
        }
        Ok(payload)
    }
}

impl EnrollmentRequest {
    pub fn verify(&self, expected_device: DeviceId, now: i64) -> Result<()> {
        if self.version != ENROLLMENT_VERSION || self.request_id.is_nil() {
            return Err(ProvisioningError::InvalidRequest(
                "unsupported version or nil request ID".to_string(),
            ));
        }
        validate_public_identity(&self.identity)?;
        if self.identity.device_id != expected_device {
            return Err(ProvisioningError::WrongRecipient);
        }
        if now > self.expires_at || self.created_at > now || self.created_at >= self.expires_at {
            return Err(ProvisioningError::Expired);
        }
        verify_signature(
            &self.identity.signing_public_key,
            &self.signature,
            &self.signing_bytes()?,
        )
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(serde_json::to_vec(&unsigned)?)
    }
}

impl EnrollmentBundle {
    pub(crate) fn seal(input: EnrollmentSealInput<'_>) -> Result<Self> {
        let EnrollmentSealInput {
            vault_id,
            vault_name,
            protocol_version,
            request,
            member_id,
            role,
            owner_device_id,
            owner_signing_key,
            owner_address,
            payload,
            now,
            ttl_seconds,
        } = input;
        request.verify(request.identity.device_id, now)?;
        if ttl_seconds <= 0 || owner_address.is_empty() || vault_name.is_empty() {
            return Err(ProvisioningError::InvalidBundle(
                "invalid enrollment metadata".to_string(),
            ));
        }
        let expires_at = now
            .checked_add(ttl_seconds)
            .ok_or_else(|| ProvisioningError::InvalidBundle("TTL overflow".to_string()))?
            .min(request.expires_at);
        let enrollment_id = Uuid::new_v4();
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        let recipient_key: [u8; 32] = request
            .identity
            .wrapping_public_key
            .as_slice()
            .try_into()
            .map_err(|_| ProvisioningError::WrongRecipient)?;
        let shared = ephemeral_secret.diffie_hellman(&X25519PublicKey::from(recipient_key));
        let key = enrollment_key(shared.as_bytes(), enrollment_id, vault_id)?;
        let mut bundle = Self {
            version: ENROLLMENT_VERSION,
            enrollment_id,
            vault_id,
            vault_name,
            protocol_version,
            recipient: request.identity.clone(),
            member_id,
            role,
            owner_device_id,
            owner_public_key: owner_signing_key.verifying_key().to_bytes().to_vec(),
            owner_address,
            created_at: now,
            expires_at,
            ephemeral_public_key: ephemeral_public.as_bytes().to_vec(),
            encrypted_payload: Vec::new(),
            signature: Vec::new(),
        };
        let plaintext = serde_json::to_vec(&payload)?;
        if plaintext.len() > MAX_ENROLLMENT_BYTES {
            return Err(ProvisioningError::PayloadTooLarge);
        }
        bundle.encrypted_payload = encrypt(&key, &plaintext, &bundle_aad(&bundle))?;
        bundle.signature = owner_signing_key
            .sign(&bundle.signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(bundle)
    }

    pub fn verify(&self, now: i64) -> Result<()> {
        if self.version != ENROLLMENT_VERSION
            || self.enrollment_id.is_nil()
            || self.vault_id.is_nil()
            || self.member_id.is_nil()
            || self.vault_name.is_empty()
            || self.owner_address.is_empty()
            || self.encrypted_payload.len() > MAX_ENROLLMENT_BYTES
        {
            return Err(ProvisioningError::InvalidBundle(
                "invalid bounded metadata".to_string(),
            ));
        }
        validate_public_identity(&self.recipient)?;
        if now > self.expires_at || self.created_at > now || self.created_at >= self.expires_at {
            return Err(ProvisioningError::Expired);
        }
        verify_signature(
            &self.owner_public_key,
            &self.signature,
            &self.signing_bytes()?,
        )
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(serde_json::to_vec(&unsigned)?)
    }
}

pub(crate) fn payload_keys(payload: &EnrollmentPayload) -> Result<VaultKeys> {
    Ok(VaultKeys::from_secret_bytes(&payload.vault_keys)?)
}

pub(crate) fn enrollment_payload(keys: &VaultKeys, snapshot: VaultSnapshot) -> EnrollmentPayload {
    EnrollmentPayload {
        vault_keys: keys.secret_bytes().to_vec(),
        snapshot,
    }
}

fn validate_public_identity(identity: &DeviceIdentityPublic) -> Result<()> {
    if identity.version != IDENTITY_VERSION {
        return Err(ProvisioningError::InvalidIdentity);
    }
    let signing: [u8; 32] = identity
        .signing_public_key
        .as_slice()
        .try_into()
        .map_err(|_| ProvisioningError::InvalidIdentity)?;
    VerifyingKey::from_bytes(&signing).map_err(|_| ProvisioningError::InvalidIdentity)?;
    let _: [u8; 32] = identity
        .wrapping_public_key
        .as_slice()
        .try_into()
        .map_err(|_| ProvisioningError::InvalidIdentity)?;
    Ok(())
}

fn verify_signature(public_key: &[u8], signature: &[u8], message: &[u8]) -> Result<()> {
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| ProvisioningError::InvalidSignature)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| ProvisioningError::InvalidSignature)?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ProvisioningError::InvalidSignature)?
        .verify(message, &Signature::from_bytes(&signature))
        .map_err(|_| ProvisioningError::InvalidSignature)
}

fn random_kdf() -> KdfParameters {
    let mut salt = vec![0; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    KdfParameters::argon2id(salt, 64 * 1024, 3, 1)
}

fn identity_aad(public: &DeviceIdentityPublic) -> Vec<u8> {
    let mut aad = IDENTITY_CONTEXT.to_vec();
    aad.extend_from_slice(public.device_id.as_bytes());
    aad.extend_from_slice(&public.signing_public_key);
    aad.extend_from_slice(&public.wrapping_public_key);
    aad
}

fn bundle_aad(bundle: &EnrollmentBundle) -> Vec<u8> {
    let mut aad = ENROLLMENT_CONTEXT.to_vec();
    aad.extend_from_slice(bundle.enrollment_id.as_bytes());
    aad.extend_from_slice(bundle.vault_id.as_bytes());
    aad.extend_from_slice(bundle.member_id.as_bytes());
    aad.extend_from_slice(bundle.recipient.device_id.as_bytes());
    aad
}

fn enrollment_key(shared: &[u8], enrollment_id: Uuid, vault_id: VaultId) -> Result<[u8; 32]> {
    let mut salt = Vec::with_capacity(32);
    salt.extend_from_slice(enrollment_id.as_bytes());
    salt.extend_from_slice(vault_id.as_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0u8; 32];
    hkdf.expand(ENROLLMENT_CONTEXT, &mut key)
        .map_err(|_| ProvisioningError::Crypto)?;
    Ok(key)
}

fn encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ProvisioningError::Crypto)?;
    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn decrypt(key: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if ciphertext.len() < NONCE_SIZE + 16 {
        return Err(ProvisioningError::Crypto);
    }
    let (nonce, ciphertext) = ciphertext.split_at(NONCE_SIZE);
    let plaintext = XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ProvisioningError::Crypto)?;
    Ok(Zeroizing::new(plaintext))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_private_directory_permissions(parent)?;
    }
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    fs::write(&temporary, bytes)?;
    set_private_permissions(&temporary)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(temporary);
        return Err(error.into());
    }
    Ok(())
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
    use crate::{RecordType, VaultLifecycleError, VaultPassword, VaultRegistry, VaultService};
    use tempfile::tempdir;

    fn password(value: &str) -> VaultPassword {
        VaultPassword::new(value.as_bytes().to_vec())
    }

    #[test]
    fn identity_is_private_restartable_and_publicly_redacted() {
        let directory = tempdir().unwrap();
        let store = DeviceIdentityStore::new(directory.path());
        let public = store
            .generate(DeviceId::random(), b"identity password")
            .unwrap();

        assert_eq!(store.show().unwrap(), public);
        assert_eq!(
            store
                .unlock(b"identity password")
                .unwrap()
                .signing_key()
                .verifying_key()
                .to_bytes()
                .as_slice(),
            public.signing_public_key
        );
        assert!(matches!(
            store.unlock(b"wrong password"),
            Err(ProvisioningError::InvalidIdentityCiphertext)
        ));
        let serialized_public = serde_json::to_string(&public).unwrap();
        assert!(!serialized_public.contains("private"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn request_rejects_tampering_expiration_and_wrong_device() {
        let directory = tempdir().unwrap();
        let store = DeviceIdentityStore::new(directory.path());
        let public = store.generate(DeviceId::random(), b"password").unwrap();
        let identity = store.unlock(b"password").unwrap();
        let request = identity.create_request(100, 60).unwrap();

        request.verify(public.device_id, 120).unwrap();
        assert!(matches!(
            request.verify(DeviceId::random(), 120),
            Err(ProvisioningError::WrongRecipient)
        ));
        assert!(matches!(
            request.verify(public.device_id, 161),
            Err(ProvisioningError::Expired)
        ));
        let mut tampered = request;
        tampered.expires_at += 1;
        assert!(matches!(
            tampered.verify(public.device_id, 120),
            Err(ProvisioningError::InvalidSignature)
        ));
    }

    #[test]
    fn imports_enrollment_across_roots_and_rejects_replay_and_tampering() {
        let owner_root = tempdir().unwrap();
        let recipient_root = tempdir().unwrap();
        let owner_device = DeviceId::random();
        let recipient_device = DeviceId::random();
        let owner_registry = VaultRegistry::new(owner_root.path());
        let unlocked = owner_registry
            .create_vault("shared", &password("owner password"), owner_device)
            .unwrap();
        let mut owner_service = VaultService::from_unlocked(unlocked).unwrap();
        let mut document = crate::RecordDocument::new(RecordType::SecureNote, "enrollment proof");
        document.value = "shared secret".to_string();
        let record_id = owner_service.create_document(document).unwrap();

        let identity_store = DeviceIdentityStore::new(recipient_root.path());
        identity_store
            .generate(recipient_device, b"identity password")
            .unwrap();
        let identity = identity_store.unlock(b"identity password").unwrap();
        let request = identity.create_request(1_000, 300).unwrap();
        let bundle = owner_service
            .prepare_enrollment(
                &request,
                MemberRole::Writer,
                "127.0.0.1:22002".to_string(),
                1_010,
                120,
            )
            .unwrap();

        let recipient_registry = VaultRegistry::new(recipient_root.path());
        let imported = recipient_registry
            .import_enrollment(
                "imported",
                &password("recipient password"),
                &identity,
                &bundle,
                1_020,
            )
            .unwrap();
        assert_eq!(imported.entry().peers[0].device_id, owner_device);
        drop(imported);

        let reopened = recipient_registry
            .unlock_vault("imported", &password("recipient password"))
            .unwrap();
        let reopened = VaultService::from_unlocked(reopened).unwrap();
        assert_eq!(
            reopened
                .get_document(&crate::RecordReference::Id(record_id))
                .unwrap()
                .unwrap()
                .document
                .value,
            "shared secret"
        );
        assert_eq!(reopened.local_member().unwrap().role, MemberRole::Writer);
        assert!(matches!(
            recipient_registry.import_enrollment(
                "replay",
                &password("another password"),
                &identity,
                &bundle,
                1_020,
            ),
            Err(VaultLifecycleError::EnrollmentConsumed)
        ));

        let other_root = tempdir().unwrap();
        let other_registry = VaultRegistry::new(other_root.path());
        let other_store = DeviceIdentityStore::new(other_root.path());
        other_store
            .generate(recipient_device, b"identity password")
            .unwrap();
        let other_identity = other_store.unlock(b"identity password").unwrap();
        assert!(matches!(
            other_registry.import_enrollment(
                "wrong-recipient",
                &password("password"),
                &other_identity,
                &bundle,
                1_020,
            ),
            Err(VaultLifecycleError::Provisioning(
                ProvisioningError::WrongRecipient
            ))
        ));

        let tampered_root = tempdir().unwrap();
        let tampered_store = DeviceIdentityStore::new(tampered_root.path());
        tampered_store
            .generate(recipient_device, b"identity password")
            .unwrap();
        let mut tampered = bundle;
        tampered.owner_address = "127.0.0.1:9999".to_string();
        assert!(matches!(
            tampered_store
                .unlock(b"identity password")
                .unwrap()
                .open_bundle(&tampered, 1_020),
            Err(ProvisioningError::InvalidSignature)
        ));
    }
}
