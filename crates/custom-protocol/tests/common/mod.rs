use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::json;
use syncthing_core::{Config, Device, DeviceId};
use syncthing_test_utils::harness::TestNode;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::TcpListener;
use tokio::process::{Child, ChildStdout, Command};
use tokio::task::JoinSet;
use tokio::time::timeout;

pub const TEST_TIMEOUT: Duration = Duration::from_secs(15);

pub fn command(operation: &str, config_dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_custom-protocol"));
    command
        .arg(operation)
        .arg("--config-dir")
        .arg(config_dir)
        .kill_on_drop(true)
        .env("RUST_LOG", "warn");
    command
}

pub fn config(node: &TestNode, peer: DeviceId, addresses: &[String]) -> Config {
    Config {
        listen_addr: "127.0.0.1:0".to_string(),
        local_device_id: Some(node.device_id),
        devices: vec![Device {
            id: peer,
            name: None,
            addresses: addresses
                .iter()
                .map(|address| serde_json::from_value(json!(address)).unwrap())
                .collect(),
            paused: false,
            introducer: false,
        }],
        ..Config::default()
    }
}

pub async fn write_config(node: &TestNode, config: &Config, messenger: serde_json::Value) {
    let mut value = serde_json::to_value(config).unwrap();
    value["messenger"] = messenger;
    tokio::fs::write(
        node.config_dir.join("config.json"),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .await
    .unwrap();
}

pub struct Listener {
    child: Child,
    lines: Lines<BufReader<ChildStdout>>,
    pub address: SocketAddr,
}

impl Listener {
    pub async fn start(node: &TestNode) -> Self {
        let mut child = command("listen", &node.config_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let first = timeout(TEST_TIMEOUT, lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .expect("listener exited before becoming ready");
        let address = first
            .strip_prefix("listening on ")
            .unwrap()
            .split_once(" as ")
            .unwrap()
            .0
            .parse()
            .unwrap();
        Self {
            child,
            lines,
            address,
        }
    }

    pub async fn line(&mut self) -> String {
        timeout(TEST_TIMEOUT, self.lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .expect("listener exited unexpectedly")
    }

    pub async fn stop(mut self) {
        self.child.kill().await.unwrap();
        self.child.wait().await.unwrap();
    }
}

pub async fn send(node: &TestNode, peer: DeviceId, text: &str) -> std::process::Output {
    timeout(
        TEST_TIMEOUT,
        command("send", &node.config_dir)
            .arg(peer.to_string())
            .arg(text)
            .output(),
    )
    .await
    .expect("send timed out")
    .unwrap()
}

pub fn assert_sent(output: &std::process::Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(stdout.contains("message acknowledged by"), "{stdout}");
    stdout
}

pub async fn mock_discovery(
    peer: DeviceId,
    routes: Vec<String>,
    tasks: &mut JoinSet<()>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tasks.spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 8192);
            request.push(stream.read_u8().await.unwrap());
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with(&format!("GET /?device={peer} ")), "{request}");
        let body = json!({ "addresses": routes }).to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(), body
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    format!("http://{address}/")
}
