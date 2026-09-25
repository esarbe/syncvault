use std::env;
use std::error::Error;
use std::io;
use std::str::FromStr;

use custom_protocol::{negotiate_client, negotiate_server, CustomConnection, ProtocolError};
use syncthing_core::DeviceId;
use tokio::net::{TcpListener, TcpStream};

type MainResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::main]
async fn main() -> MainResult {
    let arguments: Vec<String> = env::args().collect();
    match arguments.get(1).map(String::as_str) {
        Some("id") if arguments.len() == 2 => {
            println!("{}", DeviceId::random());
            Ok(())
        }
        Some("listen") if arguments.len() == 4 => {
            let local_id = parse_device_id(&arguments[3])?;
            listen(&arguments[2], local_id).await
        }
        Some("send") if arguments.len() >= 6 => {
            let local_id = parse_device_id(&arguments[3])?;
            let peer_id = parse_device_id(&arguments[4])?;
            send(&arguments[2], local_id, peer_id, arguments[5..].join(" ")).await
        }
        _ => Err(usage().into()),
    }
}

async fn listen(address: &str, local_id: DeviceId) -> MainResult {
    let listener = TcpListener::bind(address).await?;
    println!("listening on {address} as {local_id}");

    loop {
        let (stream, remote_address) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(error) = receive_messages(stream, local_id).await {
                eprintln!("connection from {remote_address} ended: {error}");
            }
        });
    }
}

async fn receive_messages(mut stream: TcpStream, local_id: DeviceId) -> MainResult {
    let hello = negotiate_server(&mut stream, local_id, None, vec!["text".to_string()]).await?;
    let peer_id = hello.device_id;
    let mut session = CustomConnection::new(stream, peer_id).into_session(local_id);

    loop {
        match session.receive_payload().await {
            Ok(payload) if payload.payload_type == "text" => {
                let text = String::from_utf8(payload.payload)?;
                println!("[{peer_id}] {text}");
            }
            Ok(payload) => {
                eprintln!("[{peer_id}] ignored payload type {}", payload.payload_type);
            }
            Err(ProtocolError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn send(address: &str, local_id: DeviceId, peer_id: DeviceId, text: String) -> MainResult {
    let mut stream = TcpStream::connect(address).await?;
    negotiate_client(
        &mut stream,
        local_id,
        Some(peer_id),
        vec!["text".to_string()],
    )
    .await?;

    let mut session = CustomConnection::new(stream, peer_id).into_session(local_id);
    session
        .send_payload("text".to_string(), text.into_bytes())
        .await?;
    println!("message acknowledged by {peer_id}");
    Ok(())
}

fn parse_device_id(value: &str) -> MainResult<DeviceId> {
    Ok(DeviceId::from_str(value)?)
}

fn usage() -> &'static str {
    "usage:\n  custom-protocol id\n  custom-protocol listen <address> <local-device-id>\n  custom-protocol send <address> <local-device-id> <peer-device-id> <text>"
}
