//! Versioned plaintext documents stored only inside encrypted record payloads.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::conflict::ConflictId;
use crate::event::EventId;
use crate::record::{RecordId, RecordType};
use syncthing_core::DeviceId;

pub const RECORD_DOCUMENT_VERSION: u16 = 1;
const MAX_NAME_BYTES: usize = 128;
const MAX_VALUE_BYTES: usize = 1024 * 1024;
const MAX_FIELDS: usize = 64;
const MAX_FIELD_NAME_BYTES: usize = 64;
const MAX_FIELD_VALUE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordDocument {
    pub version: u16,
    pub name: String,
    pub record_type: RecordType,
    pub value: String,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordReference {
    Id(RecordId),
    Name(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentRecord {
    pub id: RecordId,
    pub document: RecordDocument,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictBranchView {
    pub event_id: EventId,
    pub author: DeviceId,
    pub device_sequence: u64,
    pub document: Option<RecordDocument>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictView {
    pub conflict_id: ConflictId,
    pub record_id: RecordId,
    pub branches: Vec<ConflictBranchView>,
    pub resolution_event_id: Option<EventId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictResolution {
    SelectBranch(EventId),
    Merge(RecordDocument),
}

impl RecordDocument {
    pub fn new(record_type: RecordType, name: impl Into<String>) -> Self {
        Self {
            version: RECORD_DOCUMENT_VERSION,
            name: name.into(),
            record_type,
            value: String::new(),
            fields: BTreeMap::new(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let document: Self = serde_json::from_slice(payload)?;
        document.validate()?;
        Ok(document)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != RECORD_DOCUMENT_VERSION {
            return Err(RecordDocumentError::UnsupportedVersion(self.version));
        }
        if self.name.is_empty()
            || self.name.trim() != self.name
            || self.name.len() > MAX_NAME_BYTES
            || self.name.chars().any(char::is_control)
        {
            return Err(RecordDocumentError::InvalidName);
        }
        if self.value.len() > MAX_VALUE_BYTES {
            return Err(RecordDocumentError::ValueTooLarge);
        }
        if self.fields.len() > MAX_FIELDS {
            return Err(RecordDocumentError::TooManyFields);
        }
        for (name, value) in &self.fields {
            if name.is_empty()
                || name.trim() != name
                || name.len() > MAX_FIELD_NAME_BYTES
                || name.chars().any(char::is_control)
            {
                return Err(RecordDocumentError::InvalidFieldName(name.clone()));
            }
            if value.len() > MAX_FIELD_VALUE_BYTES {
                return Err(RecordDocumentError::FieldValueTooLarge(name.clone()));
            }
            if self.record_type != RecordType::Custom
                && !allowed_fields(self.record_type).contains(&name.as_str())
            {
                return Err(RecordDocumentError::UnsupportedField {
                    record_type: self.record_type,
                    field: name.clone(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecordDocumentError {
    #[error("unsupported record document version: {0}")]
    UnsupportedVersion(u16),
    #[error("record name is invalid")]
    InvalidName,
    #[error("record value is too large")]
    ValueTooLarge,
    #[error("record has too many fields")]
    TooManyFields,
    #[error("record field name is invalid: {0}")]
    InvalidFieldName(String),
    #[error("record field value is too large: {0}")]
    FieldValueTooLarge(String),
    #[error("field '{field}' is not supported for {record_type:?}")]
    UnsupportedField {
        record_type: RecordType,
        field: String,
    },
    #[error("record document serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, RecordDocumentError>;

fn allowed_fields(record_type: RecordType) -> &'static [&'static str] {
    match record_type {
        RecordType::Login => &["username", "password", "url", "notes"],
        RecordType::SecureNote => &["notes"],
        RecordType::Identity => &[
            "first_name",
            "last_name",
            "email",
            "phone",
            "address",
            "notes",
        ],
        RecordType::CreditCard => &[
            "cardholder",
            "number",
            "expiry_month",
            "expiry_year",
            "security_code",
            "pin",
            "notes",
        ],
        RecordType::Passkey => &[
            "relying_party_id",
            "credential_id",
            "user_handle",
            "private_key",
            "notes",
        ],
        RecordType::Custom => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_record_type() {
        for record_type in [
            RecordType::Login,
            RecordType::SecureNote,
            RecordType::Identity,
            RecordType::CreditCard,
            RecordType::Passkey,
            RecordType::Custom,
        ] {
            let document = RecordDocument::new(record_type, format!("{record_type:?}"));
            assert_eq!(
                RecordDocument::decode(&document.encode().unwrap()).unwrap(),
                document
            );
        }
    }

    #[test]
    fn validates_type_specific_and_custom_fields() {
        let mut login = RecordDocument::new(RecordType::Login, "example");
        login
            .fields
            .insert("username".to_string(), "alice".to_string());
        login.validate().unwrap();
        login
            .fields
            .insert("unknown".to_string(), "value".to_string());
        assert!(matches!(
            login.validate(),
            Err(RecordDocumentError::UnsupportedField { .. })
        ));

        let mut custom = RecordDocument::new(RecordType::Custom, "custom");
        custom
            .fields
            .insert("anything".to_string(), "value".to_string());
        custom.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_name_and_version() {
        let mut document = RecordDocument::new(RecordType::SecureNote, " note ");
        assert!(matches!(
            document.validate(),
            Err(RecordDocumentError::InvalidName)
        ));
        document.name = "note".to_string();
        document.version += 1;
        assert!(matches!(
            document.validate(),
            Err(RecordDocumentError::UnsupportedVersion(_))
        ));
    }
}
