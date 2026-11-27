use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use syncthing_core::DeviceId;
use syncthing_net::relay::dial::{parse_relay_url, resolve_session_addr};
use syncthing_net::relay::protocol::SessionInvitation;
use syncthing_net::relay::{join_session, RelayProtocolClient};
use syncthing_net::tcp_transport::validate_outbound_addr;
use syncthing_net::GlobalDiscovery;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::config::RuntimeConfig;
use super::direct::report_connection;
use super::discovery::DiscoveryRuntime;
use super::{session, CONNECT_TIMEOUT};

fn relay_address(url: &str) -> Result<(SocketAddr, Option<DeviceId>)> {
    let (address, id) = parse_relay_url(url)?;
    validate_outbound_addr(&address)?;
    if address.port() == 0 {
        bail!("relay port must not be zero");
    }
    Ok((address, url.contains("?id=").then_some(id)))
}

async fn protocol_client(runtime: &RuntimeConfig, url: &str) -> Result<RelayProtocolClient> {
    let (address, id) = relay_address(url)?;
    timeout(
        CONNECT_TIMEOUT,
        RelayProtocolClient::connect_authenticated(address, &runtime.tls, id),
    )
    .await
    .context("relay control connection timed out")?
    .map_err(Into::into)
}

async fn join_invitation(address: SocketAddr, invitation: &SessionInvitation) -> Result<TcpStream> {
    let address = resolve_session_addr(address, invitation)?;
    validate_outbound_addr(&address)?;
    timeout(CONNECT_TIMEOUT, join_session(address, &invitation.key))
        .await
        .context("relay session join timed out")?
        .map_err(Into::into)
}

pub async fn connect(
    runtime: &RuntimeConfig,
    peer_id: DeviceId,
    url: &str,
) -> Result<session::Session> {
    let mut client = protocol_client(runtime, url).await?;
    let address = client.peer_addr()?;
    let invitation = timeout(CONNECT_TIMEOUT, client.request_session(peer_id))
        .await
        .context("relay session request timed out")??;
    drop(client);
    let stream = join_invitation(address, &invitation).await?;
    session::establish(stream, runtime, Some(peer_id), invitation.server_socket).await
}

pub fn start_listeners(
    runtime: &Arc<RuntimeConfig>,
    discovery: &DiscoveryRuntime,
    permits: &Arc<Semaphore>,
) -> Result<JoinSet<()>> {
    let mut tasks = JoinSet::new();
    if !runtime.config.options.relays_enabled {
        return Ok(tasks);
    }
    let mut urls = Vec::new();
    for url in &runtime.config.options.listen_addresses {
        if url.starts_with("relay://") && !urls.contains(url) {
            relay_address(url)?;
            urls.push(url.clone());
        }
    }
    for url in urls {
        let runtime = Arc::clone(runtime);
        let addresses = Arc::clone(&discovery.addresses);
        let global = discovery.global.clone();
        let permits = Arc::clone(permits);
        tasks.spawn(async move {
            let mut connections = JoinSet::new();
            let mut backoff = Duration::from_secs(1);
            loop {
                let started = tokio::time::Instant::now();
                if let Err(error) = listen_on_relay(
                    &runtime,
                    &url,
                    &addresses,
                    global.as_deref(),
                    &permits,
                    &mut connections,
                )
                .await
                {
                    eprintln!("relay listener {url} failed: {error:#}; retrying in {backoff:?}");
                }
                addresses.lock().await.retain(|address| address != &url);
                if let Some(global) = &global {
                    global.trigger_reannounce();
                }
                if started.elapsed() >= Duration::from_secs(60) {
                    backoff = Duration::from_secs(1);
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        });
    }
    Ok(tasks)
}

async fn listen_on_relay(
    runtime: &Arc<RuntimeConfig>,
    url: &str,
    addresses: &Mutex<Vec<String>>,
    global: Option<&GlobalDiscovery>,
    permits: &Arc<Semaphore>,
    connections: &mut JoinSet<Result<()>>,
) -> Result<()> {
    let mut client = protocol_client(runtime, url).await?;
    timeout(CONNECT_TIMEOUT, client.join_relay())
        .await
        .context("relay registration timed out")??;
    let address = client.peer_addr()?;
    addresses.lock().await.push(url.to_string());
    if let Some(global) = global {
        global.trigger_reannounce();
    }
    println!("relay registered: {url}");
    loop {
        while let Some(result) = connections.try_join_next() {
            report_connection(result);
        }
        let invitation = client.wait_invitation().await?;
        let peer_id = DeviceId::from_bytes(&invitation.from)?;
        if !runtime.is_trusted(peer_id) {
            eprintln!("relay invitation rejected: peer {peer_id} is not configured or is paused");
            continue;
        }
        let Ok(permit) = Arc::clone(permits).try_acquire_owned() else {
            eprintln!("relay invitation from {peer_id} rejected: connection limit reached");
            continue;
        };
        let runtime = Arc::clone(runtime);
        connections.spawn(async move {
            let _permit = permit;
            let result = async {
                let stream = join_invitation(address, &invitation).await?;
                let session =
                    session::establish(stream, &runtime, Some(peer_id), invitation.server_socket)
                        .await?;
                session::receive(session).await
            }
            .await;
            if let Err(error) = result {
                eprintln!("relay peer {peer_id} connection ended: {error:#}");
            }
            Ok(())
        });
    }
}
