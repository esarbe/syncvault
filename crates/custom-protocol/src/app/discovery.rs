use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use syncthing_core::DeviceId;
use syncthing_net::discovery::local::LOCAL_DISCOVERY_INTERVAL;
use syncthing_net::tcp_transport::validate_outbound_addr;
use syncthing_net::{DiscoveryEvent, GlobalDiscovery, LocalDiscovery};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::{config::RuntimeConfig, CONNECT_TIMEOUT};

#[derive(Default)]
pub struct PeerRoutes {
    pub tcp: Vec<SocketAddr>,
    pub relay: Vec<String>,
    pub failures: Vec<String>,
}

impl PeerRoutes {
    pub async fn add(&mut self, addresses: Vec<String>, relays_enabled: bool) {
        for value in addresses {
            if let Some(host) = value.strip_prefix("tcp://") {
                match resolve_tcp(host).await {
                    Ok(addresses) => {
                        for address in addresses {
                            match validate_outbound_addr(&address) {
                                Ok(()) if address.port() != 0 => {
                                    if !self.tcp.contains(&address) {
                                        self.tcp.push(address);
                                    }
                                }
                                Ok(()) => self.failure(format!("{value}: port must not be zero")),
                                Err(error) => self.failure(format!("{value}: {error}")),
                            }
                        }
                    }
                    Err(error) => self.failure(format!("{value}: {error:#}")),
                }
            } else if value.starts_with("relay://") {
                if relays_enabled && !self.relay.contains(&value) {
                    self.relay.push(value);
                } else if !relays_enabled {
                    self.failure(format!("{value}: relays are disabled"));
                }
            } else if value != "dynamic" {
                self.failure(format!("unsupported peer address: {value}"));
            }
        }
    }

    pub fn failure(&mut self, message: String) {
        eprintln!("{message}");
        self.failures.push(message);
    }
}

async fn resolve_tcp(host: &str) -> Result<Vec<SocketAddr>> {
    let addresses: Vec<_> = timeout(CONNECT_TIMEOUT, tokio::net::lookup_host(host))
        .await
        .context("DNS lookup timed out")??
        .collect();
    if addresses.is_empty() {
        bail!("DNS lookup returned no addresses");
    }
    Ok(addresses)
}

pub struct DiscoveryRuntime {
    tasks: JoinSet<()>,
    pub addresses: Arc<Mutex<Vec<String>>>,
    pub global: Option<Arc<GlobalDiscovery>>,
}

impl DiscoveryRuntime {
    pub async fn shutdown(mut self) {
        self.tasks.shutdown().await;
    }
}

async fn global_client(runtime: &RuntimeConfig) -> Result<GlobalDiscovery> {
    Ok(GlobalDiscovery::from_cert_files(
        runtime.local_id,
        &runtime.config_dir.join("cert.pem"),
        &runtime.config_dir.join("key.pem"),
        runtime.messenger.discovery_server.clone(),
    )
    .await?)
}

pub async fn start_listener_discovery(
    runtime: &RuntimeConfig,
    listen_address: SocketAddr,
) -> Result<DiscoveryRuntime> {
    let mut announced: Vec<_> = runtime
        .config
        .options
        .listen_addresses
        .iter()
        .filter(|address| address.starts_with("tcp://"))
        .cloned()
        .collect();
    if announced.is_empty() {
        announced.push(format!("tcp://{listen_address}"));
    }
    let global = if runtime.config.options.global_announce_enabled {
        Some(Arc::new(global_client(runtime).await?))
    } else {
        None
    };
    let addresses = Arc::new(Mutex::new(announced.clone()));
    let mut tasks = JoinSet::new();
    if runtime.config.options.local_announce_enabled {
        let discovery =
            LocalDiscovery::new(runtime.local_id, announced).with_port(runtime.discovery_port());
        tasks.spawn(async move {
            let (event_tx, mut event_rx) = mpsc::channel(16);
            tokio::select! {
                result = discovery.run(event_tx) => {
                    if let Err(error) = result {
                        eprintln!("local discovery ended: {error}");
                    }
                }
                _ = async { while event_rx.recv().await.is_some() {} } => {}
            }
        });
    }
    if let Some(global) = &global {
        let global = Arc::clone(global);
        let addresses = Arc::clone(&addresses);
        tasks.spawn(async move {
            // Dropping this owned task also cancels requests and retry sleeps.
            global.run(addresses).await;
        });
    }
    Ok(DiscoveryRuntime {
        tasks,
        addresses,
        global,
    })
}

pub async fn discover_peer(runtime: &RuntimeConfig, peer_id: DeviceId, routes: &mut PeerRoutes) {
    let (local, global) = tokio::join!(
        async {
            if runtime.config.options.local_announce_enabled {
                lookup_local(runtime, peer_id).await
            } else {
                Ok(Vec::new())
            }
        },
        async {
            if runtime.config.options.global_announce_enabled {
                Ok(global_client(runtime).await?.query(peer_id).await?)
            } else {
                Ok(Vec::new())
            }
        }
    );
    for (source, result) in [("local", local), ("global", global)] {
        match result {
            Ok(addresses) => {
                routes
                    .add(addresses, runtime.config.options.relays_enabled)
                    .await
            }
            Err(error) => routes.failure(format!("{source} discovery failed: {error:#}")),
        }
    }
}

async fn lookup_local(runtime: &RuntimeConfig, peer_id: DeviceId) -> Result<Vec<String>> {
    let discovery =
        LocalDiscovery::new(runtime.local_id, Vec::new()).with_port(runtime.discovery_port());
    let (event_tx, mut event_rx) = mpsc::channel(16);
    let listener = discovery.listen(event_tx);
    tokio::pin!(listener);
    let deadline = tokio::time::sleep(LOCAL_DISCOVERY_INTERVAL + Duration::from_secs(1));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            result = &mut listener => {
                result?;
                bail!("local discovery listener exited");
            }
            event = event_rx.recv() => {
                match event {
                    Some(DiscoveryEvent::DeviceDiscovered { device_id, addresses, .. })
                        if device_id == peer_id => return Ok(addresses),
                    Some(_) => {}
                    None => bail!("local discovery channel closed"),
                }
            }
            _ = &mut deadline => return Ok(Vec::new()),
        }
    }
}
