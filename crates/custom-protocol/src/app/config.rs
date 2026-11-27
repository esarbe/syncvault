use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use syncthing_core::{Config, DeviceId};
use syncthing_net::discovery::local::LOCAL_DISCOVERY_PORT;
use syncthing_net::SyncthingTlsConfig;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MessengerOptions {
    pub discovery_server: Option<String>,
    pub local_discovery_port: Option<u16>,
}

#[derive(Deserialize)]
struct ConfigFile {
    #[serde(flatten)]
    config: Config,
    #[serde(default)]
    messenger: MessengerOptions,
}

pub struct RuntimeConfig {
    pub config: Config,
    pub config_dir: PathBuf,
    pub tls: Arc<SyncthingTlsConfig>,
    pub local_id: DeviceId,
    pub messenger: MessengerOptions,
}

impl RuntimeConfig {
    pub async fn load(config_dir: &Path) -> Result<Self> {
        let config_path = config_dir.join("config.json");
        let content = tokio::fs::read_to_string(&config_path)
            .await
            .with_context(|| format!("failed to read {}", config_path.display()))?;
        let ConfigFile { config, messenger } = serde_json::from_str(&content)
            .with_context(|| format!("failed to parse {}", config_path.display()))?;
        if messenger.local_discovery_port == Some(0) {
            bail!("messenger.local_discovery_port must not be zero");
        }
        let tls = load_identity(config_dir).await?;
        let local_id = tls.device_id();

        if let Some(configured_id) = config.local_device_id {
            if configured_id != local_id {
                bail!(
                    "configured local device ID {} does not match certificate ID {}",
                    configured_id,
                    local_id
                );
            }
        }

        Ok(Self {
            config,
            config_dir: config_dir.to_path_buf(),
            tls,
            local_id,
            messenger,
        })
    }

    pub fn discovery_port(&self) -> u16 {
        self.messenger
            .local_discovery_port
            .unwrap_or(LOCAL_DISCOVERY_PORT)
    }

    pub fn is_trusted(&self, peer_id: DeviceId) -> bool {
        self.config
            .devices
            .iter()
            .any(|device| device.id == peer_id && !device.paused)
    }
}

pub async fn load_identity(config_dir: &Path) -> Result<Arc<SyncthingTlsConfig>> {
    let cert_path = config_dir.join("cert.pem");
    let key_path = config_dir.join("key.pem");
    if tokio::fs::try_exists(&cert_path).await? || tokio::fs::try_exists(&key_path).await? {
        let cert = tokio::fs::read(&cert_path)
            .await
            .with_context(|| format!("failed to read {}", cert_path.display()))?;
        let key = tokio::fs::read(&key_path)
            .await
            .with_context(|| format!("failed to read {}", key_path.display()))?;
        return Ok(Arc::new(SyncthingTlsConfig::from_pem(&cert, &key)?));
    }
    Ok(Arc::new(
        SyncthingTlsConfig::load_or_generate(config_dir).await?,
    ))
}
