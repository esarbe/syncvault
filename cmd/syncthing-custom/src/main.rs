use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use custom_protocol::{
    negotiate_client, negotiate_server, CustomConnection, PayloadAck, VaultSession,
    VAULT_PROTOCOL_NAME,
};
use syncthing_core::DeviceId;
use syncthing_net::SyncthingTlsConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use vault_core::VaultService;

use crate::vault_cli::{DeviceKeyArgs, VaultAction, VaultArgs, VaultCliContext};

mod vault_cli;

const DEFAULT_LISTEN: &str = "0.0.0.0:22002";

#[derive(Parser, Debug)]
#[command(name = "syncthing-custom")]
#[command(about = "Standalone st-custom protocol endpoint")]
struct Cli {
    #[arg(long, value_name = "DIR")]
    config: PathBuf,

    #[arg(long, global = true)]
    json: bool,

    #[arg(long, global = true)]
    yes: bool,

    #[arg(long, global = true, value_name = "FILE")]
    password_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Listen {
        #[arg(long, default_value = DEFAULT_LISTEN)]
        listen: String,
        #[arg(long, value_parser = parse_device_id)]
        peer: Option<DeviceId>,
        #[arg(long, requires = "password_file")]
        vault: Option<String>,
        #[arg(long, value_name = "FILE", requires = "vault")]
        password_file: Option<PathBuf>,
    },
    Send {
        #[arg(long, value_parser = parse_device_id)]
        peer: DeviceId,
        #[arg(long)]
        addr: String,
        #[arg(long)]
        payload: String,
        #[arg(long, default_value = "text")]
        payload_type: String,
    },
    DeviceKey(DeviceKeyArgs),
    Vault(VaultArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = cli.config.clone();
    let tls_config = SyncthingTlsConfig::load_or_generate(&cli.config)
        .await
        .context("failed to load custom protocol TLS identity")?;

    match cli.command {
        Command::Listen {
            listen,
            peer,
            vault,
            password_file,
        } => {
            if let (Some(vault), Some(password_file)) = (vault, password_file) {
                let service = vault_cli::unlock_service(&cli.config, &vault, Some(&password_file))?;
                serve_vault(tls_config, &listen, service, peer).await
            } else {
                listen_for_connections(tls_config, &listen, peer).await
            }
        }
        Command::Send {
            peer,
            addr,
            payload,
            payload_type,
        } => {
            let (peer_id, ack) =
                send_payload_to_peer(&tls_config, &addr, peer, payload_type, payload.into_bytes())
                    .await?;
            println!("payload acknowledged by {peer_id}: {}", ack.message_id);
            Ok(())
        }
        Command::DeviceKey(args) => vault_cli::execute_device_key(
            args,
            VaultCliContext {
                config: &config,
                password_file: cli.password_file.as_deref(),
                json: cli.json,
                yes: cli.yes,
                local_device_id: tls_config.device_id(),
            },
        ),
        Command::Vault(args) => match vault_cli::execute(
            args,
            VaultCliContext {
                config: &config,
                password_file: cli.password_file.as_deref(),
                json: cli.json,
                yes: cli.yes,
                local_device_id: tls_config.device_id(),
            },
        )? {
            VaultAction::Done => Ok(()),
            VaultAction::Sync {
                mut service,
                peer,
                address,
            } => {
                let mut nonce = vec![0_u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
                sync_vault_with_peer(&tls_config, &address, peer, &mut service, nonce).await
            }
            VaultAction::Serve {
                service,
                listen,
                peer,
            } => serve_vault(tls_config, &listen, service, peer).await,
        },
    }
}

async fn listen_for_connections(
    tls_config: SyncthingTlsConfig,
    listen: &str,
    expected_peer: Option<DeviceId>,
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind custom protocol listener at {listen}"))?;
    let tls_config = Arc::new(tls_config);
    let local_id = tls_config.device_id();

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("failed to accept TCP connection")?;
        let tls_config = Arc::clone(&tls_config);
        tokio::spawn(async move {
            if let Err(error) = handle_incoming(stream, tls_config, local_id, expected_peer).await {
                eprintln!("custom incoming connection failed: {error}");
            }
        });
    }
}

async fn handle_incoming(
    stream: TcpStream,
    tls_config: Arc<SyncthingTlsConfig>,
    local_id: DeviceId,
    expected_peer: Option<DeviceId>,
) -> Result<()> {
    let (mut tls_stream, peer_id) = syncthing_net::tls::accept_tls_stream(stream, &tls_config)
        .await
        .context("custom TLS handshake failed")?;

    negotiate_server(
        &mut tls_stream,
        local_id,
        expected_peer,
        vec!["payload".to_string()],
    )
    .await
    .with_context(|| format!("custom handshake rejected for {peer_id}"))?;

    let session = CustomConnection::new(tls_stream, peer_id).into_session(local_id);
    session.run().await.context("custom session failed")
}

async fn send_payload_to_peer(
    tls_config: &SyncthingTlsConfig,
    addr: &str,
    expected_peer: DeviceId,
    payload_type: String,
    payload: Vec<u8>,
) -> Result<(DeviceId, PayloadAck)> {
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("failed to connect to custom peer at {addr}"))?;
    let (mut tls_stream, peer_id) =
        syncthing_net::tls::connect_tls_stream(stream, tls_config, Some(expected_peer))
            .await
            .context("custom TLS connection failed")?;
    negotiate_client(
        &mut tls_stream,
        tls_config.device_id(),
        Some(expected_peer),
        vec!["payload".to_string()],
    )
    .await
    .context("custom protocol handshake failed")?;

    let mut session =
        CustomConnection::new(tls_stream, peer_id).into_session(tls_config.device_id());
    let ack = session
        .send_payload(payload_type, payload)
        .await
        .context("custom payload exchange failed")?;
    Ok((peer_id, ack))
}

async fn serve_vault(
    tls_config: SyncthingTlsConfig,
    listen: &str,
    service: VaultService,
    expected_peer: Option<DeviceId>,
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind vault listener at {listen}"))?;
    let tls_config = Arc::new(tls_config);
    let service = Arc::new(Mutex::new(service));
    let local_id = tls_config.device_id();

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("failed to accept vault connection")?;
        let tls_config = Arc::clone(&tls_config);
        let service = Arc::clone(&service);
        tokio::spawn(async move {
            if let Err(error) =
                handle_vault_connection(stream, tls_config, service, local_id, expected_peer).await
            {
                eprintln!("vault incoming connection failed: {error}");
            }
        });
    }
}

async fn handle_vault_connection(
    stream: TcpStream,
    tls_config: Arc<SyncthingTlsConfig>,
    service: Arc<Mutex<VaultService>>,
    local_id: DeviceId,
    expected_peer: Option<DeviceId>,
) -> Result<()> {
    let (mut tls_stream, peer_id) = syncthing_net::tls::accept_tls_stream(stream, &tls_config)
        .await
        .context("vault TLS handshake failed")?;
    negotiate_server(
        &mut tls_stream,
        local_id,
        expected_peer,
        vec![VAULT_PROTOCOL_NAME.to_string()],
    )
    .await
    .with_context(|| format!("vault handshake rejected for {peer_id}"))?;

    let mut service = service.lock().await;
    VaultSession::new(tls_stream, peer_id, local_id)
        .serve(&mut service)
        .await
        .context("vault session failed")
}

async fn sync_vault_with_peer(
    tls_config: &SyncthingTlsConfig,
    address: &str,
    expected_peer: DeviceId,
    service: &mut VaultService,
    nonce: Vec<u8>,
) -> Result<()> {
    let stream = TcpStream::connect(address)
        .await
        .with_context(|| format!("failed to connect to vault peer at {address}"))?;
    let (mut tls_stream, peer_id) =
        syncthing_net::tls::connect_tls_stream(stream, tls_config, Some(expected_peer))
            .await
            .context("vault TLS connection failed")?;
    negotiate_client(
        &mut tls_stream,
        tls_config.device_id(),
        Some(expected_peer),
        vec![VAULT_PROTOCOL_NAME.to_string()],
    )
    .await
    .context("vault protocol handshake failed")?;

    VaultSession::new(tls_stream, peer_id, tls_config.device_id())
        .synchronize(service, nonce)
        .await
        .context("vault synchronization failed")
}

fn parse_device_id(value: &str) -> Result<DeviceId, String> {
    value.parse::<DeviceId>().map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn client_path_completes_tls_handshake_and_payload_ack() {
        let server_dir = tempdir().unwrap();
        let client_dir = tempdir().unwrap();
        let server_tls = SyncthingTlsConfig::load_or_generate(server_dir.path())
            .await
            .unwrap();
        let client_tls = SyncthingTlsConfig::load_or_generate(client_dir.path())
            .await
            .unwrap();
        let server_id = server_tls.device_id();
        let client_id = client_tls.device_id();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_incoming(stream, Arc::new(server_tls), server_id, Some(client_id)).await
        });

        let (peer_id, ack) = send_payload_to_peer(
            &client_tls,
            &address.to_string(),
            server_id,
            "text".to_string(),
            b"phase 4".to_vec(),
        )
        .await
        .unwrap();
        assert_eq!(peer_id, server_id);
        assert!(!ack.message_id.is_nil());

        let _ = server_task.await;
    }
}
