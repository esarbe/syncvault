//! Vault application session above the authenticated custom transport.

use ed25519_dalek::SigningKey;
use serde::de::DeserializeOwned;
use serde::Serialize;
use syncthing_core::DeviceId;
use tokio::io::{AsyncRead, AsyncWrite};
use vault_core::{AuthRequest, AuthResponse, VaultAuthenticator};

use crate::error::{ProtocolError, Result};
use crate::frame::{read_frame, write_frame, Frame};
use crate::message::{VaultMessage, VaultMessageType};
use crate::MAX_FRAME_SIZE;

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
            .respond(&request, self.peer_id, signing_key)
            .map_err(|error| ProtocolError::InvalidMessage(error.to_string()))?;
        let response_message = VaultMessage::new(
            self.local_id,
            VaultMessageType::AuthResponse,
            encode(&response)?,
        )?;
        write_message(&mut self.stream, &response_message).await?;
        Ok(response)
    }
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
    use vault_core::{MemberRole, MembershipStore, VaultId, VaultMember};

    fn setup() -> (
        VaultAuthenticator,
        VaultAuthenticator,
        SigningKey,
        VaultId,
        DeviceId,
        Uuid,
    ) {
        let key = SigningKey::from_bytes(&[41; 32]);
        let device = DeviceId::random();
        let member = VaultMember {
            member_id: Uuid::new_v4(),
            device_id: device,
            public_key: key.verifying_key().to_bytes().to_vec(),
            encrypted_vault_key: vec![1; 32],
            role: MemberRole::Reader,
            created_at: 1,
            revoked_at: None,
        };
        let member_id = member.member_id;
        let mut members = MembershipStore::new();
        members.insert_member(member).unwrap();
        let vault_id = Uuid::new_v4();
        (
            VaultAuthenticator::new(vault_id, members.clone()),
            VaultAuthenticator::new(vault_id, members),
            key,
            vault_id,
            device,
            member_id,
        )
    }

    #[tokio::test]
    async fn translates_framed_vault_auth_to_vault_core() {
        let (server_auth, _client_auth, signing_key, vault_id, peer_id, member_id) = setup();
        let local_id = DeviceId::random();
        let (mut client_stream, server_stream) = duplex(4096);
        let mut server = VaultSession::new(server_stream, peer_id, local_id);
        let server_task = tokio::spawn(async move {
            let mut auth = server_auth;
            server.authenticate_server(&mut auth, &signing_key).await
        });
        let request = AuthRequest {
            vault_id,
            member_id,
            device_id: peer_id,
            nonce: vec![7; 16],
        };
        let request_message = VaultMessage::new(
            peer_id,
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
        assert_eq!(response.device_id, peer_id);
        server_task.await.unwrap().unwrap();
    }
}
