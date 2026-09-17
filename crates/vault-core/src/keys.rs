//! Vault key hierarchy and cryptographic key-management primitives.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::vault::KdfParameters;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 24;
const KEY_CHECK: &[u8] = b"st-vault/1 key check";
const RECORD_KEY_CONTEXT: &[u8] = b"st-vault/1/record";
const ROTATION_CONTEXT: &[u8] = b"st-vault/1/key-rotation";

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid KDF parameters: {0}")]
    InvalidKdf(String),
    #[error("key derivation failed")]
    Derivation,
    #[error("encryption failed")]
    Encryption,
    #[error("decryption failed")]
    Decryption,
    #[error("invalid encrypted key material")]
    InvalidCiphertext,
    #[error("key check failed")]
    KeyCheckFailed,
}

pub type Result<T> = std::result::Result<T, KeyError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedKeyHierarchy {
    pub encrypted_vault_key: Vec<u8>,
    pub encrypted_history_key: Vec<u8>,
    pub key_check: Vec<u8>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKeys {
    vault_key: [u8; KEY_SIZE],
    history_key: [u8; KEY_SIZE],
}

pub struct VaultKeyRing {
    current: VaultKeys,
    previous: Vec<VaultKeys>,
}

pub struct KeyRotation {
    pub key_ring: VaultKeyRing,
    pub wrapped_vault_key: Vec<u8>,
}

impl VaultKeys {
    fn random(history_key: [u8; KEY_SIZE]) -> Self {
        let mut vault_key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut vault_key);
        Self {
            vault_key,
            history_key,
        }
    }

    pub fn create(password: &[u8], kdf: &KdfParameters) -> Result<(Self, EncryptedKeyHierarchy)> {
        let master_key = derive_master_key(password, kdf)?;
        let mut vault_key = [0u8; KEY_SIZE];
        let mut history_key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut vault_key);
        OsRng.fill_bytes(&mut history_key);

        let hierarchy = EncryptedKeyHierarchy {
            encrypted_vault_key: encrypt_with_key(&master_key, &vault_key, b"vault-key")?,
            encrypted_history_key: encrypt_with_key(&master_key, &history_key, b"history-key")?,
            key_check: encrypt_with_key(&master_key, KEY_CHECK, b"key-check")?,
        };
        let keys = Self {
            vault_key,
            history_key,
        };
        Ok((keys, hierarchy))
    }

    pub fn unlock(
        password: &[u8],
        kdf: &KdfParameters,
        hierarchy: &EncryptedKeyHierarchy,
    ) -> Result<Self> {
        let master_key = derive_master_key(password, kdf)?;
        let check = decrypt_with_key(&master_key, &hierarchy.key_check, b"key-check")
            .map_err(|_| KeyError::KeyCheckFailed)?;
        if check != KEY_CHECK {
            return Err(KeyError::KeyCheckFailed);
        }

        let vault = decrypt_with_key(&master_key, &hierarchy.encrypted_vault_key, b"vault-key")?;
        let history = decrypt_with_key(
            &master_key,
            &hierarchy.encrypted_history_key,
            b"history-key",
        )?;
        let vault_key: [u8; KEY_SIZE] =
            vault.try_into().map_err(|_| KeyError::InvalidCiphertext)?;
        let history_key: [u8; KEY_SIZE] = history
            .try_into()
            .map_err(|_| KeyError::InvalidCiphertext)?;
        Ok(Self {
            vault_key,
            history_key,
        })
    }

    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        encrypt_with_key(&self.vault_key, plaintext, associated_data)
    }

    pub fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        decrypt_with_key(&self.vault_key, ciphertext, associated_data)
    }

    pub fn derive_record_key(&self, record_id: &[u8]) -> Result<[u8; KEY_SIZE]> {
        let hkdf = Hkdf::<Sha256>::new(Some(RECORD_KEY_CONTEXT), &self.vault_key);
        let mut key = [0u8; KEY_SIZE];
        hkdf.expand(record_id, &mut key)
            .map_err(|_| KeyError::Derivation)?;
        Ok(key)
    }

    pub fn history_key(&self) -> &[u8; KEY_SIZE] {
        &self.history_key
    }

    pub fn key_ring(self) -> VaultKeyRing {
        VaultKeyRing {
            current: self,
            previous: Vec::new(),
        }
    }
}

impl VaultKeyRing {
    pub fn new(keys: VaultKeys) -> Self {
        keys.key_ring()
    }

    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        self.current.encrypt(plaintext, associated_data)
    }

    pub fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        match self.current.decrypt(ciphertext, associated_data) {
            Ok(plaintext) => Ok(plaintext),
            Err(error) => {
                for previous in &self.previous {
                    if let Ok(plaintext) = previous.decrypt(ciphertext, associated_data) {
                        return Ok(plaintext);
                    }
                }
                Err(error)
            }
        }
    }

    pub fn rotate(self) -> Result<KeyRotation> {
        let next = VaultKeys::random(self.current.history_key);
        let wrapped_vault_key =
            encrypt_with_key(&self.current.vault_key, &next.vault_key, ROTATION_CONTEXT)?;
        let mut previous = self.previous;
        previous.push(self.current);
        Ok(KeyRotation {
            key_ring: VaultKeyRing {
                current: next,
                previous,
            },
            wrapped_vault_key,
        })
    }

    pub fn apply_rotation(&mut self, wrapped_vault_key: &[u8]) -> Result<()> {
        let vault_key =
            decrypt_with_key(&self.current.vault_key, wrapped_vault_key, ROTATION_CONTEXT)?;
        let vault_key: [u8; KEY_SIZE] = vault_key
            .try_into()
            .map_err(|_| KeyError::InvalidCiphertext)?;
        let history_key = self.current.history_key;
        let old = std::mem::replace(
            &mut self.current,
            VaultKeys {
                vault_key,
                history_key,
            },
        );
        self.previous.push(old);
        Ok(())
    }

    pub fn current(&self) -> &VaultKeys {
        &self.current
    }
}

pub fn derive_master_key(password: &[u8], kdf: &KdfParameters) -> Result<[u8; KEY_SIZE]> {
    if kdf.algorithm != "argon2id" || kdf.salt.is_empty() {
        return Err(KeyError::InvalidKdf(kdf.algorithm.clone()));
    }
    let params = Params::new(
        kdf.memory_cost_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(KEY_SIZE),
    )
    .map_err(|error| KeyError::InvalidKdf(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_SIZE];
    argon2
        .hash_password_into(password, &kdf.salt, &mut key)
        .map_err(|_| KeyError::Derivation)?;
    Ok(key)
}

fn encrypt_with_key(
    key: &[u8; KEY_SIZE],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| KeyError::Encryption)?;
    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn decrypt_with_key(
    key: &[u8; KEY_SIZE],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext.len() < NONCE_SIZE + 16 {
        return Err(KeyError::InvalidCiphertext);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(&ciphertext[..NONCE_SIZE]),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext[NONCE_SIZE..],
                aad: associated_data,
            },
        )
        .map_err(|_| KeyError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parameters() -> KdfParameters {
        KdfParameters::argon2id(vec![7; 16], 19 * 1024, 2, 1)
    }

    #[test]
    fn derives_deterministically_for_same_password_and_salt() {
        assert_eq!(
            derive_master_key(b"correct horse", &parameters()).unwrap(),
            derive_master_key(b"correct horse", &parameters()).unwrap()
        );
    }

    #[test]
    fn wrong_password_cannot_unlock_keys() {
        let (_, hierarchy) = VaultKeys::create(b"correct horse", &parameters()).unwrap();
        assert!(matches!(
            VaultKeys::unlock(b"wrong horse", &parameters(), &hierarchy),
            Err(KeyError::KeyCheckFailed)
        ));
    }

    #[test]
    fn encrypts_and_decrypts_with_authenticated_data() {
        let (keys, _) = VaultKeys::create(b"password", &parameters()).unwrap();
        let encrypted = keys.encrypt(b"secret", b"record-1").unwrap();
        assert_eq!(keys.decrypt(&encrypted, b"record-1").unwrap(), b"secret");
        assert!(keys.decrypt(&encrypted, b"record-2").is_err());
    }

    #[test]
    fn detects_tampered_ciphertext_and_bad_nonce() {
        let (keys, _) = VaultKeys::create(b"password", &parameters()).unwrap();
        let mut encrypted = keys.encrypt(b"secret", b"record-1").unwrap();
        encrypted[NONCE_SIZE] ^= 1;
        assert!(keys.decrypt(&encrypted, b"record-1").is_err());
        assert!(matches!(
            keys.decrypt(&[0; NONCE_SIZE], b"record-1"),
            Err(KeyError::InvalidCiphertext)
        ));
    }

    #[test]
    fn derives_stable_distinct_record_keys() {
        let (keys, _) = VaultKeys::create(b"password", &parameters()).unwrap();
        assert_eq!(
            keys.derive_record_key(b"record-1").unwrap(),
            keys.derive_record_key(b"record-1").unwrap()
        );
        assert_ne!(
            keys.derive_record_key(b"record-1").unwrap(),
            keys.derive_record_key(b"record-2").unwrap()
        );
    }

    #[test]
    fn rotation_keeps_old_ciphertext_readable_and_wraps_new_key() {
        let (keys, _) = VaultKeys::create(b"password", &parameters()).unwrap();
        let mut receiver = VaultKeyRing::new(keys.clone());
        let ring = VaultKeyRing::new(keys);
        let old_ciphertext = ring.encrypt(b"legacy", b"record").unwrap();
        let rotation = ring.rotate().unwrap();
        let rotated = rotation.key_ring;

        assert_eq!(
            rotated.decrypt(&old_ciphertext, b"record").unwrap(),
            b"legacy"
        );
        let new_ciphertext = rotated.encrypt(b"new", b"record").unwrap();
        assert_eq!(rotated.decrypt(&new_ciphertext, b"record").unwrap(), b"new");

        receiver
            .apply_rotation(&rotation.wrapped_vault_key)
            .unwrap();
        assert_eq!(
            receiver.decrypt(&new_ciphertext, b"record").unwrap(),
            b"new"
        );
    }
}
