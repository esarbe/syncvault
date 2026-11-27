use std::sync::Arc;

use anyhow::{bail, Context, Result};
use syncthing_core::DeviceId;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::config::RuntimeConfig;
use super::discovery::{discover_peer, start_listener_discovery, PeerRoutes};
use super::{relay, session, CONNECT_TIMEOUT, MAX_CONNECTIONS, PROTOCOL_TIMEOUT};

pub async fn listen(runtime: Arc<RuntimeConfig>, bind_address: &str) -> Result<()> {
    let listener = TcpListener::bind(bind_address).await?;
    let listen_address = listener.local_addr()?;
    let discovery = start_listener_discovery(&runtime, listen_address).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut relays = relay::start_listeners(&runtime, &discovery, &permits)?;
    let mut connections = JoinSet::new();
    println!("listening on {} as {}", listen_address, runtime.local_id);

    let result = loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, remote_address) = match result {
                    Ok(connection) => connection,
                    Err(error) => break Err(error.into()),
                };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    eprintln!("connection from {remote_address} rejected: connection limit reached");
                    continue;
                };
                let runtime = Arc::clone(&runtime);
                connections.spawn(async move {
                    let _permit = permit;
                    let session = session::establish(stream, &runtime, None, true).await?;
                    session::receive(session).await
                });
            }
            Some(result) = connections.join_next() => report_connection(result),
            result = tokio::signal::ctrl_c() => break result.map_err(Into::into),
        }
    };
    connections.shutdown().await;
    relays.shutdown().await;
    discovery.shutdown().await;
    result
}

pub fn report_connection(result: Result<Result<()>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("peer connection ended: {error:#}"),
        Err(error) => eprintln!("peer task failed: {error}"),
    }
}

pub async fn send(runtime: &RuntimeConfig, peer_id: DeviceId, text: String) -> Result<()> {
    let peer = runtime
        .config
        .devices
        .iter()
        .find(|device| device.id == peer_id && !device.paused)
        .with_context(|| format!("peer {peer_id} is not configured or is paused"))?;
    let mut routes = PeerRoutes::default();
    routes
        .add(
            peer.addresses.iter().map(ToString::to_string).collect(),
            runtime.config.options.relays_enabled,
        )
        .await;
    let mut attempted = Vec::new();

    // Resolve dynamic routes only after configured TCP routes have failed.
    for discover in [false, true] {
        if discover {
            discover_peer(runtime, peer_id, &mut routes).await;
        }
        for address in routes.tcp.clone() {
            if attempted.contains(&address) {
                continue;
            }
            attempted.push(address);
            let result = async {
                let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
                    .await
                    .context("TCP connection timed out")??;
                session::establish(stream, runtime, Some(peer_id), false).await
            }
            .await;
            match result {
                Ok(session) => return deliver(session, &text, &address.to_string()).await,
                Err(error) => routes.failure(format!("{address}: {error:#}")),
            }
        }
    }
    for relay_url in routes.relay.clone() {
        match relay::connect(runtime, peer_id, &relay_url).await {
            Ok(session) => return deliver(session, &text, &relay_url).await,
            Err(error) => routes.failure(format!("{relay_url}: {error:#}")),
        }
    }
    bail!(
        "no usable route to {peer_id}; {}",
        routes.failures.join("; ")
    )
}

async fn deliver(mut session: session::Session, text: &str, route: &str) -> Result<()> {
    // Once a payload is sent, do not retry on another route: a lost ACK is ambiguous.
    timeout(
        PROTOCOL_TIMEOUT,
        session.send_payload("text".to_string(), text.as_bytes().to_vec()),
    )
    .await
    .context("payload acknowledgement timed out; delivery is unknown, not retried")?
    .context("payload delivery failed; delivery may be unknown, not retried")?;
    println!("message acknowledged by {} via {route}", session.peer_id());
    Ok(())
}
