mod app;

use std::env;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{bail, Result};
use app::config::{load_identity, RuntimeConfig};
use syncthing_core::DeviceId;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    let arguments: Vec<String> = env::args().collect();
    match arguments.get(1).map(String::as_str) {
        Some("id") if arguments.len() == 4 && arguments[2] == "--config-dir" => {
            let identity = load_identity(Path::new(&arguments[3])).await?;
            println!("{}", identity.device_id());
            Ok(())
        }
        Some("listen") => listen_command(&arguments).await,
        Some("send") if arguments.len() >= 6 && arguments[2] == "--config-dir" => {
            let runtime = RuntimeConfig::load(Path::new(&arguments[3])).await?;
            let peer_id = DeviceId::from_str(&arguments[4])?;
            app::direct::send(&runtime, peer_id, arguments[5..].join(" ")).await
        }
        _ => bail!(usage()),
    }
}

async fn listen_command(arguments: &[String]) -> Result<()> {
    if arguments.len() != 4 && arguments.len() != 6 {
        bail!(usage());
    }
    if arguments[2] != "--config-dir" {
        bail!(usage());
    }

    let config_dir = PathBuf::from(&arguments[3]);
    let runtime = RuntimeConfig::load(&config_dir).await?;
    let bind_address = if arguments.len() == 6 {
        if arguments[4] != "--bind" {
            bail!(usage());
        }
        arguments[5].clone()
    } else {
        runtime.config.listen_addr.clone()
    };
    app::direct::listen(Arc::new(runtime), &bind_address).await
}

fn usage() -> &'static str {
    "usage:\n  custom-protocol id --config-dir <dir>\n  custom-protocol listen --config-dir <dir> [--bind <address>]\n  custom-protocol send --config-dir <dir> <peer-device-id> <text>"
}
