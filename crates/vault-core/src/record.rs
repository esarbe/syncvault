//! Opaque encrypted vault record types and record operations.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::keys::{KeyError, VaultKeys};

pub type RecordId = Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecordType {
    Login,
    SecureNote,
    Identity,
    CreditCard,
    Passkey,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedRecord {
    pub id: RecordId,
    pub record_type: RecordType,
    pub ciphertext: Vec<u8>,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordData {
    pub id: RecordId,
    pub record_type: RecordType,
    pub payload: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("record not found: {0}")]
    NotFound(RecordId),
    #[error("record already exists: {0}")]
    AlreadyExists(RecordId),
    #[error("record is deleted: {0}")]
    Deleted(RecordId),
    #[error("record cryptography failed: {0}")]
    Crypto(#[from] KeyError),
}

pub type Result<T> = std::result::Result<T, RecordError>;

pub struct RecordStore {
    keys: VaultKeys,
    records: BTreeMap<RecordId, EncryptedRecord>,
}

impl RecordStore {
    pub fn new(keys: VaultKeys) -> Self {
        Self {
            keys,
            records: BTreeMap::new(),
        }
    }

    pub fn create_record(&mut self, record_type: RecordType, payload: Vec<u8>) -> Result<RecordId> {
        let id = RecordId::new_v4();
        let ciphertext = self.encrypt(id, &payload)?;
        let record = EncryptedRecord {
            id,
            record_type,
            ciphertext,
            deleted: false,
        };
        if self.records.insert(id, record).is_some() {
            return Err(RecordError::AlreadyExists(id));
        }
        Ok(id)
    }

    pub fn update_record(&mut self, id: RecordId, payload: Vec<u8>) -> Result<()> {
        let record = self.records.get_mut(&id).ok_or(RecordError::NotFound(id))?;
        if record.deleted {
            return Err(RecordError::Deleted(id));
        }
        let ciphertext = self.keys.encrypt(&payload, &associated_data(id))?;
        record.ciphertext = ciphertext;
        Ok(())
    }

    pub fn delete_record(&mut self, id: RecordId) -> Result<()> {
        let record = self.records.get_mut(&id).ok_or(RecordError::NotFound(id))?;
        if record.deleted {
            return Err(RecordError::Deleted(id));
        }
        record.deleted = true;
        Ok(())
    }

    pub fn restore_record(&mut self, id: RecordId) -> Result<()> {
        let record = self.records.get_mut(&id).ok_or(RecordError::NotFound(id))?;
        if !record.deleted {
            return Ok(());
        }
        record.deleted = false;
        Ok(())
    }

    pub fn get_record(&self, id: RecordId) -> Result<Option<RecordData>> {
        let Some(record) = self.records.get(&id) else {
            return Ok(None);
        };
        if record.deleted {
            return Ok(None);
        }
        Ok(Some(self.decrypt_record(record)?))
    }

    pub fn list_records(&self) -> Result<Vec<RecordData>> {
        self.records
            .values()
            .filter(|record| !record.deleted)
            .map(|record| self.decrypt_record(record))
            .collect()
    }

    pub fn encrypted_records(&self) -> impl Iterator<Item = &EncryptedRecord> {
        self.records.values()
    }

    fn encrypt(&self, id: RecordId, payload: &[u8]) -> Result<Vec<u8>> {
        Ok(self.keys.encrypt(payload, &associated_data(id))?)
    }

    fn decrypt_record(&self, record: &EncryptedRecord) -> Result<RecordData> {
        Ok(RecordData {
            id: record.id,
            record_type: record.record_type,
            payload: self
                .keys
                .decrypt(&record.ciphertext, &associated_data(record.id))?,
        })
    }
}

fn associated_data(id: RecordId) -> Vec<u8> {
    let mut data = b"st-vault/1/record/".to_vec();
    data.extend_from_slice(id.as_bytes());
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::KdfParameters;

    fn store() -> RecordStore {
        let kdf = KdfParameters::argon2id(vec![3; 16], 19 * 1024, 2, 1);
        let (keys, _) = VaultKeys::create(b"test-password", &kdf).unwrap();
        RecordStore::new(keys)
    }

    #[test]
    fn creates_reads_updates_and_lists_opaque_records() {
        let mut store = store();
        let id = store
            .create_record(RecordType::SecureNote, b"secret".to_vec())
            .unwrap();
        let encrypted = store.encrypted_records().next().unwrap();
        assert_ne!(encrypted.ciphertext, b"secret");
        assert_eq!(store.get_record(id).unwrap().unwrap().payload, b"secret");

        store.update_record(id, b"updated".to_vec()).unwrap();
        assert_eq!(store.get_record(id).unwrap().unwrap().payload, b"updated");
        assert_eq!(store.list_records().unwrap().len(), 1);
    }

    #[test]
    fn delete_hides_record_and_restore_recovers_it() {
        let mut store = store();
        let id = store
            .create_record(RecordType::Login, b"credentials".to_vec())
            .unwrap();
        store.delete_record(id).unwrap();
        assert!(store.get_record(id).unwrap().is_none());
        assert!(store.list_records().unwrap().is_empty());
        store.restore_record(id).unwrap();
        assert_eq!(
            store.get_record(id).unwrap().unwrap().payload,
            b"credentials"
        );
    }

    #[test]
    fn record_id_is_authenticated_as_associated_data() {
        let mut store = store();
        let id = store
            .create_record(RecordType::Custom, b"payload".to_vec())
            .unwrap();
        let record = store.records.get_mut(&id).unwrap();
        record.id = RecordId::new_v4();
        assert!(matches!(store.get_record(id), Err(RecordError::Crypto(_))));
    }
}
