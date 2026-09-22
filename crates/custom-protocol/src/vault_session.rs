//! Vault application session above the authenticated custom transport.

use ed25519_dalek::SigningKey;
use serde::de::DeserializeOwned;
use serde::Serialize;
use syncthing_core::DeviceId;
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;
use vault_core::{
    AuthRequest, AuthResponse, EventRange, EventTransferResult, MembershipOperation,
    MissingEventsRequest, SyncSummary, VaultAuthenticator, VaultService,
};

use crate::error::{ProtocolError, Result};
use crate::frame::{read_frame, write_frame, Frame};
use crate::message::{VaultMessage, VaultMessageType};
use crate::vault_payload::{
    ErrorPayload, EventResultsPayload, GoodbyePayload, SyncCompletePayload, SyncEventsPayload,
    SyncRequestPayload, SyncSummaryRequest, SyncSummaryResponse, ValidatePayload, VaultInfoRequest,
    VaultInfoResponse,
};
use crate::MAX_FRAME_SIZE;

const MAX_SYNC_ROUNDS: usize = 1024;

pub struct VaultSession<S> {
    stream: S,
    peer_id: DeviceId,
    local_id: DeviceId,
}

impl<S> VaultSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S, peer_id: DeviceId, local_id: DeviceId) -> Self {
        Self {
            stream,
            peer_id,
            local_id,
        }
    }

    pub fn peer_id(&self) -> DeviceId {
        self.peer_id
    }

    pub async fn authenticate_client(
        &mut self,
        authenticator: &mut VaultAuthenticator,
        request: AuthRequest,
    ) -> Result<AuthResponse> {
        let message = VaultMessage::new(
            self.local_id,
            VaultMessageType::AuthRequest,
            encode(&request)?,
        )?;
        write_message(&mut self.stream, &message).await?;

        let response: VaultMessage = read_message(&mut self.stream).await?;
        validate_message(&response, self.peer_id, VaultMessageType::AuthResponse)?;
        let response: AuthResponse = decode(&response.payload)?;
        authenticator
            .verify_response(&request, &response, self.peer_id)
            .map_err(|error| ProtocolError::InvalidMessage(error.to_string()))?;
        Ok(response)
    }

    pub async fn authenticate_server(
        &mut self,
        authenticator: &mut VaultAuthenticator,
        member_id: uuid::Uuid,
        signing_key: &SigningKey,
    ) -> Result<AuthResponse> {
        let request_message: VaultMessage = read_message(&mut self.stream).await?;
        validate_message(
            &request_message,
            self.peer_id,
            VaultMessageType::AuthRequest,
        )?;
        let request: AuthRequest = decode(&request_message.payload)?;
        let response = authenticator
            .respond(
                &request,
                self.peer_id,
                member_id,
                self.local_id,
                signing_key,
            )
            .map_err(|error| ProtocolError::InvalidMessage(error.to_string()))?;
        let response_message = VaultMessage::new(
            self.local_id,
            VaultMessageType::AuthResponse,
            encode(&response)?,
        )?;
        write_message(&mut self.stream, &response_message).await?;
        Ok(response)
    }

    pub async fn synchronize(&mut self, service: &mut VaultService, nonce: Vec<u8>) -> Result<()> {
        let request = service
            .authentication_request(nonce)
            .map_err(protocol_error)?;
        let mut authenticator = service.authenticator();
        self.authenticate_client(&mut authenticator, request)
            .await?;
        service
            .authorize_peer(self.peer_id, MembershipOperation::Read)
            .map_err(protocol_error)?;

        for _ in 0..MAX_SYNC_ROUNDS {
            let local_summary = service.sync_summary();
            let remote_summary: SyncSummaryResponse = self
                .exchange(
                    VaultMessageType::SyncSummary,
                    &SyncSummaryRequest {
                        summary: local_summary.clone(),
                    },
                )
                .await?;
            remote_summary.validate()?;
            ensure_vault(local_summary.vault_id, remote_summary.summary.vault_id)?;

            let pull_ranges = missing_ranges(
                &local_summary.version_vector,
                &remote_summary.summary.version_vector,
            );
            if !pull_ranges.is_empty() {
                let payload: SyncEventsPayload = self
                    .exchange(
                        VaultMessageType::SyncRequest,
                        &SyncRequestPayload {
                            request: MissingEventsRequest {
                                vault_id: local_summary.vault_id,
                                ranges: pull_ranges.clone(),
                            },
                        },
                    )
                    .await?;
                payload.validate()?;
                if payload.requested_ranges != pull_ranges {
                    return Err(invalid("sync response ranges do not match request"));
                }
                let results = service
                    .apply_remote_events(payload.batch, &pull_ranges)
                    .map_err(protocol_error)?;
                let response_type = event_result_message_type(&results);
                self.send(
                    response_type,
                    &EventResultsPayload {
                        results: results.clone(),
                    },
                )
                .await?;
                reject_failed_events(results)?;
            }

            let push_ranges = service
                .inventory()
                .missing_events_request(service.vault_id(), &remote_summary.summary.version_vector)
                .ranges;
            if !push_ranges.is_empty() {
                let payload = SyncEventsPayload {
                    requested_ranges: push_ranges.clone(),
                    batch: service
                        .export_events(&push_ranges)
                        .map_err(protocol_error)?,
                };
                payload.validate()?;
                let results: EventResultsPayload = self
                    .exchange(VaultMessageType::SyncEvents, &payload)
                    .await?;
                results.validate()?;
                reject_failed_events(results.results)?;
            }

            if pull_ranges.is_empty() && push_ranges.is_empty() {
                let complete = SyncCompletePayload {
                    vault_id: service.vault_id(),
                };
                let response: SyncCompletePayload = self
                    .exchange(VaultMessageType::SyncComplete, &complete)
                    .await?;
                response.validate()?;
                ensure_vault(service.vault_id(), response.vault_id)?;
                self.send(
                    VaultMessageType::Goodbye,
                    &GoodbyePayload {
                        reason: "sync complete".to_string(),
                    },
                )
                .await?;
                return Ok(());
            }
        }
        Err(ProtocolError::Protocol(
            "vault synchronization exceeded round limit".to_string(),
        ))
    }

    pub async fn serve(&mut self, service: &mut VaultService) -> Result<()> {
        let mut authenticator = service.authenticator();
        let request = self
            .authenticate_server_with_service(&mut authenticator, service)
            .await?;
        service
            .authorize_peer(request.device_id, MembershipOperation::Read)
            .map_err(protocol_error)?;

        let mut peer_summary: Option<SyncSummary> = None;
        loop {
            let message = self.receive().await?;
            let result = self.dispatch(service, &message, &mut peer_summary).await;
            match result {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(error) => {
                    self.send_error(message.id, "REQUEST_REJECTED", &error.to_string())
                        .await?;
                }
            }
        }
    }

    async fn authenticate_server_with_service(
        &mut self,
        authenticator: &mut VaultAuthenticator,
        service: &VaultService,
    ) -> Result<AuthRequest> {
        let request_message = self.receive_expected(VaultMessageType::AuthRequest).await?;
        let request: AuthRequest = decode(&request_message.payload)?;
        let response = service
            .authentication_response(authenticator, &request, self.peer_id)
            .map_err(protocol_error)?;
        self.send(VaultMessageType::AuthResponse, &response).await?;
        Ok(request)
    }

    async fn dispatch(
        &mut self,
        service: &mut VaultService,
        message: &VaultMessage,
        peer_summary: &mut Option<SyncSummary>,
    ) -> Result<bool> {
        service
            .authorize_peer(self.peer_id, MembershipOperation::Read)
            .map_err(protocol_error)?;
        match message.message_type {
            VaultMessageType::VaultInfo => {
                let request: VaultInfoRequest = decode_validated(&message.payload)?;
                ensure_vault(service.vault_id(), request.vault_id)?;
                self.send(
                    VaultMessageType::VaultInfo,
                    &VaultInfoResponse {
                        metadata: service.metadata(),
                    },
                )
                .await?;
            }
            VaultMessageType::SyncSummary => {
                let request: SyncSummaryRequest = decode_validated(&message.payload)?;
                ensure_vault(service.vault_id(), request.summary.vault_id)?;
                *peer_summary = Some(request.summary);
                self.send(
                    VaultMessageType::SyncSummary,
                    &SyncSummaryResponse {
                        summary: service.sync_summary(),
                    },
                )
                .await?;
            }
            VaultMessageType::SyncRequest => {
                let payload: SyncRequestPayload = decode_validated(&message.payload)?;
                ensure_vault(service.vault_id(), payload.request.vault_id)?;
                let batch = service
                    .export_events(&payload.request.ranges)
                    .map_err(protocol_error)?;
                self.send(
                    VaultMessageType::SyncEvents,
                    &SyncEventsPayload {
                        requested_ranges: payload.request.ranges,
                        batch,
                    },
                )
                .await?;
            }
            VaultMessageType::SyncEvents => {
                let payload: SyncEventsPayload = decode_validated(&message.payload)?;
                let advertised = peer_summary
                    .as_ref()
                    .ok_or_else(|| invalid("SYNC_EVENTS requires a preceding SYNC_SUMMARY"))?;
                let expected_ranges = missing_ranges(
                    &service.sync_summary().version_vector,
                    &advertised.version_vector,
                );
                if payload.requested_ranges != expected_ranges {
                    return Err(invalid("event ranges were not requested by this peer"));
                }
                let results = service
                    .apply_remote_events(payload.batch, &expected_ranges)
                    .map_err(protocol_error)?;
                let response_type = event_result_message_type(&results);
                self.send(response_type, &EventResultsPayload { results })
                    .await?;
            }
            VaultMessageType::SyncComplete => {
                let payload: SyncCompletePayload = decode_validated(&message.payload)?;
                ensure_vault(service.vault_id(), payload.vault_id)?;
                self.send(VaultMessageType::SyncComplete, &payload).await?;
            }
            VaultMessageType::Goodbye => {
                let _: GoodbyePayload = decode_validated(&message.payload)?;
                return Ok(true);
            }
            VaultMessageType::EventAck | VaultMessageType::EventReject => {
                let payload: EventResultsPayload = decode_validated(&message.payload)?;
                reject_failed_events(payload.results)?;
            }
            VaultMessageType::VaultList
            | VaultMessageType::SyncInventory
            | VaultMessageType::ConflictList
            | VaultMessageType::ConflictResolve
            | VaultMessageType::DeviceAdd
            | VaultMessageType::DeviceRevoke
            | VaultMessageType::KeyRotate => {
                return Err(ProtocolError::Protocol(format!(
                    "{:?} is not supported by this endpoint",
                    message.message_type
                )));
            }
            VaultMessageType::AuthRequest
            | VaultMessageType::AuthResponse
            | VaultMessageType::Error => {
                return Err(invalid("unexpected vault message type"));
            }
        }
        Ok(false)
    }

    async fn exchange<T, R>(&mut self, message_type: VaultMessageType, payload: &T) -> Result<R>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        self.send(message_type, payload).await?;
        let response = self.receive().await?;
        if response.message_type == VaultMessageType::Error {
            let error: ErrorPayload = decode_validated(&response.payload)?;
            return Err(ProtocolError::Protocol(format!(
                "{}: {}",
                error.code, error.message
            )));
        }
        let expected = match message_type {
            VaultMessageType::SyncRequest => VaultMessageType::SyncEvents,
            VaultMessageType::SyncEvents => {
                if response.message_type != VaultMessageType::EventAck
                    && response.message_type != VaultMessageType::EventReject
                {
                    return Err(unexpected(message_type, response.message_type));
                }
                response.message_type
            }
            _ => message_type,
        };
        validate_message(&response, self.peer_id, expected)?;
        decode(&response.payload)
    }

    async fn send<T: Serialize>(
        &mut self,
        message_type: VaultMessageType,
        payload: &T,
    ) -> Result<()> {
        let message = VaultMessage::new(self.local_id, message_type, encode(payload)?)?;
        write_message(&mut self.stream, &message).await
    }

    async fn send_error(&mut self, request_id: Uuid, code: &str, message: &str) -> Result<()> {
        let payload = ErrorPayload {
            request_id,
            code: code.to_string(),
            message: message.chars().take(1024).collect(),
        };
        self.send(VaultMessageType::Error, &payload).await
    }

    async fn receive(&mut self) -> Result<VaultMessage> {
        let message = read_message(&mut self.stream).await?;
        if message.sender != self.peer_id {
            return Err(ProtocolError::UnauthorizedPeer(message.sender.to_string()));
        }
        Ok(message)
    }

    async fn receive_expected(&mut self, expected: VaultMessageType) -> Result<VaultMessage> {
        let message = self.receive().await?;
        validate_message(&message, self.peer_id, expected)?;
        Ok(message)
    }
}

fn missing_ranges(
    local: &vault_core::VersionVector,
    remote: &vault_core::VersionVector,
) -> Vec<EventRange> {
    let mut ranges = remote
        .iter()
        .filter_map(|(device_id, remote_sequence)| {
            let local_sequence = local.get(device_id);
            (*remote_sequence > local_sequence).then_some(EventRange {
                device_id: *device_id,
                start: local_sequence + 1,
                end: *remote_sequence,
            })
        })
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| range.device_id.to_string());
    ranges
}

fn reject_failed_events(results: Vec<EventTransferResult>) -> Result<()> {
    let rejected = results
        .into_iter()
        .filter_map(|result| match result {
            EventTransferResult::Rejected(rejection) => Some(rejection.reason),
            EventTransferResult::Accepted(_) | EventTransferResult::Duplicate(_) => None,
        })
        .collect::<Vec<_>>();
    if rejected.is_empty() {
        Ok(())
    } else {
        Err(ProtocolError::Protocol(format!(
            "peer rejected events: {}",
            rejected.join("; ")
        )))
    }
}

fn event_result_message_type(results: &[EventTransferResult]) -> VaultMessageType {
    if results
        .iter()
        .any(|result| matches!(result, EventTransferResult::Rejected(_)))
    {
        VaultMessageType::EventReject
    } else {
        VaultMessageType::EventAck
    }
}

fn ensure_vault(expected: Uuid, actual: Uuid) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(invalid("message belongs to a different vault"))
    }
}

fn decode_validated<T>(payload: &[u8]) -> Result<T>
where
    T: DeserializeOwned + ValidatePayload,
{
    let value: T = decode(payload)?;
    value.validate()?;
    Ok(value)
}

fn invalid(message: &str) -> ProtocolError {
    ProtocolError::InvalidMessage(message.to_string())
}

fn protocol_error(error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::Protocol(error.to_string())
}

fn unexpected(expected: VaultMessageType, actual: VaultMessageType) -> ProtocolError {
    invalid(&format!("expected {:?}, got {:?}", expected, actual))
}

async fn write_message<S>(stream: &mut S, message: &VaultMessage) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_frame(stream, &Frame::new(serde_json::to_vec(message)?)?).await
}

async fn read_message<S>(stream: &mut S) -> Result<VaultMessage>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = read_frame(stream, MAX_FRAME_SIZE).await?;
    let message: VaultMessage = decode(&frame.payload)?;
    message.validate()?;
    Ok(message)
}

fn validate_message(
    message: &VaultMessage,
    expected_sender: DeviceId,
    expected_type: VaultMessageType,
) -> Result<()> {
    if message.sender != expected_sender {
        return Err(ProtocolError::UnauthorizedPeer(message.sender.to_string()));
    }
    if message.message_type != expected_type {
        return Err(ProtocolError::InvalidMessage(format!(
            "expected {:?}, got {:?}",
            expected_type, message.message_type
        )));
    }
    Ok(())
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

fn decode<T: DeserializeOwned>(payload: &[u8]) -> Result<T> {
    serde_json::from_slice(payload)
        .map_err(|error| ProtocolError::InvalidMessage(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use uuid::Uuid;
    use vault_core::{
        MemberRole, MembershipStore, RecordType, VaultId, VaultMember, VaultPassword, VaultRegistry,
    };

    fn setup() -> (
        VaultAuthenticator,
        VaultAuthenticator,
        SigningKey,
        SigningKey,
        VaultId,
        DeviceId,
        DeviceId,
        Uuid,
        Uuid,
    ) {
        let client_key = SigningKey::from_bytes(&[41; 32]);
        let server_key = SigningKey::from_bytes(&[42; 32]);
        let client_device = DeviceId::random();
        let server_device = DeviceId::random();
        let client_member = VaultMember {
            member_id: Uuid::new_v4(),
            device_id: client_device,
            public_key: client_key.verifying_key().to_bytes().to_vec(),
            encrypted_vault_key: vec![1; 32],
            role: MemberRole::Reader,
            created_at: 1,
            revoked_at: None,
        };
        let server_member = VaultMember {
            member_id: Uuid::new_v4(),
            device_id: server_device,
            public_key: server_key.verifying_key().to_bytes().to_vec(),
            encrypted_vault_key: vec![2; 32],
            role: MemberRole::Reader,
            created_at: 1,
            revoked_at: None,
        };
        let client_member_id = client_member.member_id;
        let server_member_id = server_member.member_id;
        let mut members = MembershipStore::new();
        members.insert_member(client_member).unwrap();
        members.insert_member(server_member).unwrap();
        let vault_id = Uuid::new_v4();
        (
            VaultAuthenticator::new(vault_id, members.clone()),
            VaultAuthenticator::new(vault_id, members),
            client_key,
            server_key,
            vault_id,
            client_device,
            server_device,
            client_member_id,
            server_member_id,
        )
    }

    #[tokio::test]
    async fn translates_framed_vault_auth_to_vault_core() {
        let (
            server_auth,
            _client_auth,
            client_key,
            server_key,
            vault_id,
            client_id,
            server_id,
            client_member_id,
            server_member_id,
        ) = setup();
        let (mut client_stream, server_stream) = duplex(4096);
        let mut server = VaultSession::new(server_stream, client_id, server_id);
        let server_task = tokio::spawn(async move {
            let mut auth = server_auth;
            server
                .authenticate_server(&mut auth, server_member_id, &server_key)
                .await
        });
        let request = VaultAuthenticator::request(
            vault_id,
            client_member_id,
            client_id,
            vec![7; 16],
            &client_key,
        )
        .unwrap();
        let request_message = VaultMessage::new(
            client_id,
            VaultMessageType::AuthRequest,
            encode(&request).unwrap(),
        )
        .unwrap();
        write_message(&mut client_stream, &request_message)
            .await
            .unwrap();
        let response_message = read_message(&mut client_stream).await.unwrap();
        assert_eq!(
            response_message.message_type,
            VaultMessageType::AuthResponse
        );
        let response: AuthResponse = decode(&response_message.payload).unwrap();
        assert_eq!(response.device_id, server_id);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn synchronizes_independent_service_instances_and_duplicate_delivery() {
        let directory = tempfile::tempdir().unwrap();
        let registry = VaultRegistry::new(directory.path());
        let password = VaultPassword::new(b"session-test-password".to_vec());
        let device_id = DeviceId::random();
        let unlocked = registry
            .create_vault("session-sync", &password, device_id)
            .unwrap();
        let mut client_service = VaultService::from_unlocked(unlocked).unwrap();
        let record_id = client_service
            .create_record(RecordType::SecureNote, b"encrypted payload".to_vec())
            .unwrap();
        let server_unlocked = registry.unlock_vault("session-sync", &password).unwrap();
        let mut server_service = VaultService::from_unlocked(server_unlocked).unwrap();
        client_service
            .update_record(record_id, b"updated payload".to_vec())
            .unwrap();

        run_sync_pair(&mut client_service, &mut server_service, device_id)
            .await
            .unwrap();
        assert_eq!(
            server_service
                .get_record(record_id)
                .unwrap()
                .unwrap()
                .payload,
            b"updated payload"
        );

        run_sync_pair(&mut client_service, &mut server_service, device_id)
            .await
            .unwrap();
        assert_eq!(server_service.history().len(), 2);
    }

    #[tokio::test]
    async fn rejects_tls_peer_that_is_not_a_vault_member() {
        let directory = tempfile::tempdir().unwrap();
        let registry = VaultRegistry::new(directory.path());
        let password = VaultPassword::new(b"session-test-password".to_vec());
        let member_device = DeviceId::random();
        let unlocked = registry
            .create_vault("unauthorized", &password, member_device)
            .unwrap();
        let service = VaultService::from_unlocked(unlocked).unwrap();
        let unauthorized = DeviceId::random();
        let (mut client_stream, server_stream) = duplex(4096);
        let mut server = VaultSession::new(server_stream, unauthorized, member_device);
        let request = service.authentication_request(vec![8; 32]).unwrap();
        let request_message = VaultMessage::new(
            unauthorized,
            VaultMessageType::AuthRequest,
            encode(&request).unwrap(),
        )
        .unwrap();
        let server_task = tokio::spawn(async move {
            let mut service = service;
            server.serve(&mut service).await
        });
        write_message(&mut client_stream, &request_message)
            .await
            .unwrap();
        assert!(server_task.await.unwrap().is_err());
    }

    async fn run_sync_pair(
        client_service: &mut VaultService,
        server_service: &mut VaultService,
        device_id: DeviceId,
    ) -> Result<()> {
        let (client_stream, server_stream) = duplex(MAX_FRAME_SIZE * 2);
        let mut client = VaultSession::new(client_stream, device_id, device_id);
        let mut server = VaultSession::new(server_stream, device_id, device_id);
        let (client_result, server_result) = tokio::join!(
            client.synchronize(client_service, vec![9; 32]),
            server.serve(server_service),
        );
        client_result?;
        server_result
    }
}
