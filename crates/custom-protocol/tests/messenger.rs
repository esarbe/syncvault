mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use serde_json::json;
use syncthing_core::DeviceId;
use syncthing_net::discovery::local::{Announce, LOCAL_DISCOVERY_MAGIC};
use syncthing_net::relay::protocol::{read_message, write_message, Message, Ping, Response};
use syncthing_net::relay::server::RelayServer;
use syncthing_net::tls::{accept_tls_stream_with_alpn, connect_tls_stream_with_alpn, RELAY_ALPN};
use syncthing_net::SyncthingTlsConfig;
use syncthing_test_utils::harness::TestNode;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::timeout;

#[tokio::test]
async fn direct_tls_messaging_and_bep_coexist_between_two_nodes() {
    let temp = tempfile::tempdir().unwrap();
    let a = TestNode::new_with_dir("a", temp.path().join("a"))
        .await
        .unwrap();
    let b = TestNode::new_with_dir("b", temp.path().join("b"))
        .await
        .unwrap();
    a.connect_to(&b).await.unwrap();
    b.connect_to(&a).await.unwrap();
    a.wait_for_connection(b.device_id, TEST_TIMEOUT)
        .await
        .unwrap();
    b.wait_for_connection(a.device_id, TEST_TIMEOUT)
        .await
        .unwrap();

    write_config(&a, &config(&a, b.device_id, &[]), json!({})).await;
    write_config(&b, &config(&b, a.device_id, &[]), json!({})).await;
    let mut a_listener = Listener::start(&a).await;
    let mut b_listener = Listener::start(&b).await;

    let mut a_config = config(
        &a,
        b.device_id,
        &[format!("tcp://localhost:{}", b_listener.address.port())],
    );
    // An unavailable discovery service must not prevent an explicit connection.
    a_config.options.global_announce_enabled = true;
    write_config(
        &a,
        &a_config,
        json!({ "discovery_server": "http://127.0.0.1:0/" }),
    )
    .await;
    write_config(
        &b,
        &config(&b, a.device_id, &[format!("tcp://{}", a_listener.address)]),
        json!({}),
    )
    .await;

    assert_sent(&send(&a, b.device_id, "hello over TLS").await);
    assert_eq!(
        b_listener.line().await,
        format!("[{}] hello over TLS", a.device_id)
    );
    assert_sent(&send(&b, a.device_id, "reply over TLS").await);
    assert_eq!(
        a_listener.line().await,
        format!("[{}] reply over TLS", b.device_id)
    );

    let id = command("id", &a.config_dir).output().await.unwrap();
    assert!(id.status.success());
    assert_eq!(
        String::from_utf8(id.stdout).unwrap().trim(),
        a.device_id.to_string()
    );
    a_listener.stop().await;
    b_listener.stop().await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn rejects_untrusted_peers_and_wrong_certificate_identity() {
    let temp = tempfile::tempdir().unwrap();
    let a = TestNode::new_with_dir("a", temp.path().join("a"))
        .await
        .unwrap();
    let b = TestNode::new_with_dir("b", temp.path().join("b"))
        .await
        .unwrap();
    let mut b_config = config(&b, a.device_id, &[]);
    b_config.devices[0].paused = true;
    write_config(&b, &b_config, json!({})).await;
    let b_listener = Listener::start(&b).await;
    let address = format!("tcp://{}", b_listener.address);
    write_config(
        &a,
        &config(&a, b.device_id, std::slice::from_ref(&address)),
        json!({}),
    )
    .await;
    let output = send(&a, b.device_id, "must not arrive").await;
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("acknowledged"));

    let wrong_id = DeviceId::random();
    write_config(&a, &config(&a, wrong_id, &[address]), json!({})).await;
    let output = send(&a, wrong_id, "wrong certificate").await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("device ID mismatch"));
    b_listener.stop().await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn discovers_local_peer_and_replaces_wildcard_address() {
    let temp = tempfile::tempdir().unwrap();
    let a = TestNode::new_with_dir("a", temp.path().join("a"))
        .await
        .unwrap();
    let b = TestNode::new_with_dir("b", temp.path().join("b"))
        .await
        .unwrap();
    write_config(&b, &config(&b, a.device_id, &[]), json!({})).await;
    let mut listener = Listener::start(&b).await;
    let reserved = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let discovery_port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let mut a_config = config(&a, b.device_id, &["dynamic".to_string()]);
    a_config.options.local_announce_enabled = true;
    write_config(
        &a,
        &a_config,
        json!({ "local_discovery_port": discovery_port }),
    )
    .await;
    let announce = Announce {
        id: b.device_id.as_bytes().to_vec(),
        addresses: vec![format!("tcp://0.0.0.0:{}", listener.address.port())],
        instance_id: 1,
    };
    let mut packet = LOCAL_DISCOVERY_MAGIC.to_be_bytes().to_vec();
    packet.extend(announce.encode().unwrap());
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.set_broadcast(true).unwrap();
        loop {
            socket
                .send_to(&packet, ("127.255.255.255", discovery_port))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    let (first, second) = tokio::join!(
        send(&a, b.device_id, "local message one"),
        send(&a, b.device_id, "local message two"),
    );
    assert_sent(&first);
    assert_sent(&second);
    let mut received = vec![listener.line().await, listener.line().await];
    received.sort();
    assert_eq!(
        received,
        vec![
            format!("[{}] local message one", a.device_id),
            format!("[{}] local message two", a.device_id),
        ]
    );
    tasks.shutdown().await;
    listener.stop().await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn discovers_global_tcp_route_after_configured_route_fails() {
    let temp = tempfile::tempdir().unwrap();
    let a = TestNode::new_with_dir("a", temp.path().join("a"))
        .await
        .unwrap();
    let b = TestNode::new_with_dir("b", temp.path().join("b"))
        .await
        .unwrap();
    write_config(&b, &config(&b, a.device_id, &[]), json!({})).await;
    let mut listener = Listener::start(&b).await;
    let mut tasks = JoinSet::new();
    let discovery = mock_discovery(
        b.device_id,
        vec![format!("tcp://{}", listener.address)],
        &mut tasks,
    )
    .await;
    let mut a_config = config(&a, b.device_id, &["tcp://127.0.0.1:0".to_string()]);
    a_config.options.global_announce_enabled = true;
    write_config(&a, &a_config, json!({ "discovery_server": discovery })).await;
    assert_sent(&send(&a, b.device_id, "discovered globally").await);
    assert_eq!(
        listener.line().await,
        format!("[{}] discovered globally", a.device_id)
    );
    timeout(TEST_TIMEOUT, tasks.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    listener.stop().await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn relay_fallback_delivers_text_through_real_relay_server() {
    let temp = tempfile::tempdir().unwrap();
    let a = TestNode::new_with_dir("a", temp.path().join("a"))
        .await
        .unwrap();
    let b = TestNode::new_with_dir("b", temp.path().join("b"))
        .await
        .unwrap();
    let relay_tls = Arc::new(
        SyncthingTlsConfig::load_or_generate(&temp.path().join("relay"))
            .await
            .unwrap(),
    );
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_address = reserved.local_addr().unwrap();
    drop(reserved);
    let url = format!("relay://{relay_address}/?id={}", relay_tls.device_id());
    let relay_id = relay_tls.device_id();
    let server = Arc::new(RelayServer::new(
        relay_address,
        "127.0.0.1:0".parse().unwrap(),
        relay_tls,
    ));
    let mut relay_tasks = JoinSet::new();
    let relay = Arc::clone(&server);
    relay_tasks.spawn(async move { relay.run().await.unwrap() });
    timeout(TEST_TIMEOUT, async {
        loop {
            if TcpStream::connect(relay_address).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();

    let probe_tls = SyncthingTlsConfig::load_or_generate(&temp.path().join("probe"))
        .await
        .unwrap();
    let (mut probe, _) = connect_tls_stream_with_alpn(
        TcpStream::connect(relay_address).await.unwrap(),
        &probe_tls,
        Some(relay_id),
        RELAY_ALPN,
    )
    .await
    .unwrap();
    // TCP may split a protocol frame across any number of reads.
    for byte in Message::Ping(Ping).encode() {
        probe.write_all(&[byte]).await.unwrap();
        probe.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    timeout(TEST_TIMEOUT, async {
        loop {
            match read_message(&mut probe).await.unwrap() {
                Message::Pong(_) => break,
                Message::Ping(_) => {
                    write_message(
                        &mut probe,
                        &Message::Pong(syncthing_net::relay::protocol::Pong),
                    )
                    .await
                    .unwrap();
                }
                other => panic!("unexpected relay message: {other:?}"),
            }
        }
    })
    .await
    .unwrap();
    drop(probe);

    let mut b_config = config(&b, a.device_id, &[]);
    b_config.options.relays_enabled = true;
    b_config.options.listen_addresses = vec![url.clone()];
    write_config(&b, &b_config, json!({})).await;
    let mut listener = Listener::start(&b).await;
    assert_eq!(listener.line().await, format!("relay registered: {url}"));

    let mut a_listener_config = config(&a, b.device_id, &[]);
    a_listener_config.options.relays_enabled = true;
    a_listener_config.options.listen_addresses = vec![url.clone()];
    write_config(&a, &a_listener_config, json!({})).await;
    let mut a_listener = Listener::start(&a).await;
    assert_eq!(a_listener.line().await, format!("relay registered: {url}"));

    let mut discovery_tasks = JoinSet::new();
    let discovery = mock_discovery(b.device_id, vec![url.clone()], &mut discovery_tasks).await;
    let mut a_config = config(&a, b.device_id, &["tcp://127.0.0.1:0".to_string()]);
    a_config.options.relays_enabled = true;
    a_config.options.global_announce_enabled = true;
    write_config(&a, &a_config, json!({ "discovery_server": discovery })).await;
    let stdout = assert_sent(&send(&a, b.device_id, "relayed and encrypted").await);
    assert!(stdout.contains(&format!("via {url}")));
    assert_eq!(
        listener.line().await,
        format!("[{}] relayed and encrypted", a.device_id)
    );
    timeout(TEST_TIMEOUT, discovery_tasks.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let mut b_config = config(&b, a.device_id, std::slice::from_ref(&url));
    b_config.options.relays_enabled = true;
    write_config(&b, &b_config, json!({})).await;
    assert_sent(&send(&b, a.device_id, "reply via relay").await);
    assert_eq!(
        a_listener.line().await,
        format!("[{}] reply via relay", b.device_id)
    );

    let mut a_config = config(&a, b.device_id, std::slice::from_ref(&url));
    a_config.options.relays_enabled = true;
    write_config(&a, &a_config, json!({})).await;
    assert_sent(&send(&a, b.device_id, "still registered").await);
    assert_eq!(
        listener.line().await,
        format!("[{}] still registered", a.device_id)
    );

    // URL certificate pinning must reject the wrong relay before requesting a session.
    let wrong_url = format!("relay://{relay_address}/?id={}", DeviceId::random());
    let mut a_config = config(&a, b.device_id, &[wrong_url]);
    a_config.options.relays_enabled = true;
    write_config(&a, &a_config, json!({})).await;
    let output = send(&a, b.device_id, "wrong relay").await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("device ID mismatch"));

    listener.stop().await;
    a_listener.stop().await;
    server.shutdown();
    timeout(TEST_TIMEOUT, relay_tasks.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn relay_listener_reconnects_after_control_disconnect() {
    let temp = tempfile::tempdir().unwrap();
    let node = TestNode::new_with_dir("listener", temp.path().join("listener"))
        .await
        .unwrap();
    let relay_tls = SyncthingTlsConfig::load_or_generate(&temp.path().join("relay"))
        .await
        .unwrap();
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "relay://{}/?id={}",
        control.local_addr().unwrap(),
        relay_tls.device_id()
    );
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        for attempt in 0..2 {
            let (stream, _) = control.accept().await.unwrap();
            let (mut stream, _) = accept_tls_stream_with_alpn(stream, &relay_tls, RELAY_ALPN)
                .await
                .unwrap();
            assert!(matches!(
                read_message(&mut stream).await.unwrap(),
                Message::JoinRelayRequest(_)
            ));
            // Heartbeats may arrive before the response to a registration request.
            write_message(&mut stream, &Message::Ping(Ping))
                .await
                .unwrap();
            assert!(matches!(
                read_message(&mut stream).await.unwrap(),
                Message::Pong(_)
            ));
            write_message(&mut stream, &Message::Response(Response::success()))
                .await
                .unwrap();
            if attempt == 0 {
                stream.shutdown().await.unwrap();
            } else {
                assert!(read_message(&mut stream).await.is_err());
            }
        }
    });
    let mut node_config = config(&node, DeviceId::random(), &[]);
    node_config.options.relays_enabled = true;
    node_config.options.listen_addresses = vec![url.clone()];
    write_config(&node, &node_config, json!({})).await;
    let mut listener = Listener::start(&node).await;
    assert_eq!(listener.line().await, format!("relay registered: {url}"));
    assert_eq!(listener.line().await, format!("relay registered: {url}"));
    listener.stop().await;
    timeout(TEST_TIMEOUT, tasks.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    node.shutdown().await;
}
