use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use custom_protocol::{negotiate_client, negotiate_server, CustomConnection, PayloadAck};
use syncthing_core::DeviceId;
use syncthing_net::SyncthingTlsConfig;
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_LISTEN: &str = "0.0.0.0:22002";

#[derive(Parser, Debug)]
#[command(name = "syncthing-custom")]
#[command(about = "Standalone st-custom protocol endpoint")]
struct Cli {
    #[arg(long, value_name = "DIR")]
    config: PathBuf,

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
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    Record {
        vault: String,
        #[command(subcommand)]
        command: RecordCommand,
    },
    History {
        vault: String,
        record: Option<String>,
    },
    Conflicts {
        vault: String,
        #[command(subcommand)]
        command: ConflictCommand,
    },
    Sync {
        vault: String,
    },
}

#[derive(Subcommand, Debug)]
enum VaultCommand {
    Info,
    List,
    Create {
        name: String,
    },
    Devices {
        #[command(subcommand)]
        command: DeviceCommand,
    },
}

#[derive(Subcommand, Debug)]
enum DeviceCommand {
    Add,
    Revoke { device_id: String },
}

#[derive(Subcommand, Debug)]
enum RecordCommand {
    List,
    Create {
        record_type: String,
        name: String,
    },
    Get {
        name: String,
    },
    Update {
        name: String,
        #[arg(short = 'f', long = "field", value_names = ["FIELD", "VALUE"], num_args = 2)]
        fields: Vec<String>,
    },
    Edit {
        name: String,
    },
    Delete {
        name: String,
    },
    Restore {
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum ConflictCommand {
    Show,
    Resolve { conflict_id: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let tls_config = SyncthingTlsConfig::load_or_generate(&cli.config)
        .await
        .context("failed to load custom protocol TLS identity")?;

    match cli.command {
        Command::Listen { listen, peer } => listen_for_connections(tls_config, &listen, peer).await,
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
        Command::Vault { command } => handle_vault_command(&tls_config, command),
        Command::Record { vault, command } => {
            service_required(&format!("record command for vault '{vault}' ({command:?})"))
        }
        Command::History { vault, record } => service_required(&format!(
            "history command for vault '{vault}'{}",
            record
                .map(|record| format!(" and record '{record}'"))
                .unwrap_or_default()
        )),
        Command::Conflicts { vault, command } => service_required(&format!(
            "conflict command for vault '{vault}' ({command:?})"
        )),
        Command::Sync { vault } => service_required(&format!("sync command for vault '{vault}'")),
    }
}

fn handle_vault_command(tls_config: &SyncthingTlsConfig, command: VaultCommand) -> Result<()> {
    match command {
        VaultCommand::Info => {
            println!("device_id: {}", tls_config.device_id());
            println!("protocol: st-vault/1");
            Ok(())
        }
        VaultCommand::List => service_required("vault list"),
        VaultCommand::Create { name } => service_required(&format!("vault create '{name}'")),
        VaultCommand::Devices { command } => {
            service_required(&format!("vault devices ({command:?})"))
        }
    }
}

fn service_required(operation: &str) -> Result<()> {
    anyhow::bail!(
        "{operation} requires the vault service; the CLI command surface is ready, but no vault is unlocked"
    )
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
