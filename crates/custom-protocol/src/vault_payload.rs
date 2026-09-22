//! Typed and bounded payloads for the `st-vault/1` request/response protocol.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vault_core::{
    EventRange, EventTransferResult, MissingEventsRequest, SyncEvents, SyncSummary, VaultId,
    VaultMetadata, MAX_EVENT_RANGES, MAX_SYNC_EVENTS,
};

use crate::error::{ProtocolError, Result};

pub const MAX_PROTOCOL_TEXT_BYTES: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultInfoRequest {
    pub vault_id: VaultId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultInfoResponse {
    pub metadata: VaultMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncSummaryRequest {
    pub summary: SyncSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncSummaryResponse {
    pub summary: SyncSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncRequestPayload {
    pub request: MissingEventsRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncEventsPayload {
    pub requested_ranges: Vec<EventRange>,
    pub batch: SyncEvents,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventResultsPayload {
    pub results: Vec<EventTransferResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncCompletePayload {
    pub vault_id: VaultId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorPayload {
    pub request_id: Uuid,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoodbyePayload {
    pub reason: String,
}

pub trait ValidatePayload {
    fn validate(&self) -> Result<()>;
}

impl ValidatePayload for VaultInfoRequest {
    fn validate(&self) -> Result<()> {
        validate_vault_id(self.vault_id)
    }
}

impl ValidatePayload for SyncSummaryRequest {
    fn validate(&self) -> Result<()> {
        validate_summary(&self.summary)
    }
}

impl ValidatePayload for SyncSummaryResponse {
    fn validate(&self) -> Result<()> {
        validate_summary(&self.summary)
    }
}

impl ValidatePayload for SyncRequestPayload {
    fn validate(&self) -> Result<()> {
        validate_vault_id(self.request.vault_id)?;
        validate_ranges(&self.request.ranges)
    }
}

impl ValidatePayload for SyncEventsPayload {
    fn validate(&self) -> Result<()> {
        validate_vault_id(self.batch.vault_id)?;
        validate_ranges(&self.requested_ranges)?;
        if self.batch.events.len() > MAX_SYNC_EVENTS {
            return Err(invalid("event batch exceeds protocol limit"));
        }
        Ok(())
    }
}

impl ValidatePayload for EventResultsPayload {
    fn validate(&self) -> Result<()> {
        if self.results.len() > MAX_SYNC_EVENTS {
            return Err(invalid("event result batch exceeds protocol limit"));
        }
        Ok(())
    }
}

impl ValidatePayload for SyncCompletePayload {
    fn validate(&self) -> Result<()> {
        validate_vault_id(self.vault_id)
    }
}

impl ValidatePayload for ErrorPayload {
    fn validate(&self) -> Result<()> {
        if self.request_id.is_nil()
            || self.code.is_empty()
            || self.code.len() > MAX_PROTOCOL_TEXT_BYTES
            || self.message.len() > MAX_PROTOCOL_TEXT_BYTES
        {
            return Err(invalid("invalid error payload"));
        }
        Ok(())
    }
}

impl ValidatePayload for GoodbyePayload {
    fn validate(&self) -> Result<()> {
        if self.reason.len() > MAX_PROTOCOL_TEXT_BYTES {
            return Err(invalid("goodbye reason exceeds protocol limit"));
        }
        Ok(())
    }
}

fn validate_summary(summary: &SyncSummary) -> Result<()> {
    validate_vault_id(summary.vault_id)?;
    if summary.records.len() > MAX_SYNC_EVENTS {
        return Err(invalid("record summary exceeds protocol limit"));
    }
    Ok(())
}

fn validate_ranges(ranges: &[EventRange]) -> Result<()> {
    if ranges.len() > MAX_EVENT_RANGES || ranges.iter().any(EventRange::is_empty) {
        return Err(invalid("invalid event ranges"));
    }
    Ok(())
}

fn validate_vault_id(vault_id: VaultId) -> Result<()> {
    if vault_id.is_nil() {
        return Err(invalid("vault ID must not be nil"));
    }
    Ok(())
}

fn invalid(message: &str) -> ProtocolError {
    ProtocolError::InvalidMessage(message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use syncthing_core::DeviceId;
    use vault_core::VersionVector;

    #[test]
    fn rejects_excessive_and_empty_ranges() {
        let range = EventRange {
            device_id: DeviceId::random(),
            start: 2,
            end: 1,
        };
        let payload = SyncRequestPayload {
            request: MissingEventsRequest {
                vault_id: VaultId::new_v4(),
                ranges: vec![range],
            },
        };
        assert!(payload.validate().is_err());

        let payload = SyncRequestPayload {
            request: MissingEventsRequest {
                vault_id: VaultId::new_v4(),
                ranges: vec![
                    EventRange {
                        device_id: DeviceId::random(),
                        start: 1,
                        end: 1,
                    };
                    MAX_EVENT_RANGES + 1
                ],
            },
        };
        assert!(payload.validate().is_err());
    }

    #[test]
    fn accepts_bounded_summary() {
        let payload = SyncSummaryRequest {
            summary: SyncSummary {
                vault_id: VaultId::new_v4(),
                version_vector: VersionVector::new(),
                records: Vec::new(),
            },
        };
        payload.validate().unwrap();
    }
}
