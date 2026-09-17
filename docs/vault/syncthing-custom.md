# Custom Syncthing Protocol Binary — Implementation Plan & Code Memory

## Objective

Create a standalone Rust binary that sends custom application messages between nodes that implement this specific protocol.

The protocol:

- does **not** reuse BEP
- does not need to communicate with ordinary Syncthing nodes
- may reuse Syncthing's TCP/TLS and DeviceId machinery
- must remain independent of BEP message types, sessions, and synchronization logic

## Architecture

    syncthing-custom
           |
           +-- custom-protocol
           |     +-- framing
           |     +-- handshake
           |     +-- messages
           |     +-- session
           |
           +-- syncthing-net
                 +-- TCP
                 +-- TLS
                 +-- DeviceId

The critical dependency boundary is:

    custom-protocol ----X----> bep-protocol

Reuse transport and identity infrastructure, but implement an entirely separate application protocol.

---

## 1. Define the custom protocol

Create:

    crates/custom-protocol/
    ├── Cargo.toml
    └── src/
        ├── lib.rs
        ├── connection.rs
        ├── frame.rs
        ├── handshake.rs
        ├── message.rs
        ├── session.rs
        └── error.rs

Use an explicit protocol identifier, for example:

    st-custom/1

A minimal logical message should contain:

    version
    message_type
    flags
    message_id
    payload_length
    payload

Define:

- protocol version
- handshake
- supported capabilities
- maximum frame size
- message types
- request/response semantics
- acknowledgement semantics
- malformed-message behavior
- connection-close behavior

Serialization can use `prost`, `serde`, or another format, but do not import BEP message definitions.

---

## 2. Reuse TLS and DeviceId

Relevant source:

    crates/syncthing-net/src/tls.rs

Important implementation anchors:

- `SyncthingTlsConfig`
- `load_or_generate`
- `accept_tls_stream`
- `connect_tls_stream`

The intended flow is:

    TCP socket
        |
        v
    Syncthing TLS
        |
        v
    peer DeviceId
        |
        v
    custom handshake
        |
        v
    custom protocol

Use the generic TLS-stream functions rather than the BEP-specific connection path.

The custom protocol should explicitly verify the expected peer DeviceId for outbound connections.

---

## 3. Server connection path

Implement a custom listener rather than using the existing BEP connection path.

Flow:

    syncthing-custom
            |
            v
    TcpListener
            |
            v
         accept()
            |
            v
    accept_tls_stream()
            |
            v
       peer DeviceId
            |
            v
    CustomServerHello
            |
            v
      message loop

Use a dedicated port initially, for example:

    22001  normal BEP
    22002  custom protocol

A separate port makes protocol separation explicit and simplifies firewall and operational testing.

---

## 4. Client connection path

The client should perform:

    configured peer
          |
          v
    TcpStream::connect()
          |
          v
    connect_tls_stream()
          |
          v
    verify expected DeviceId
          |
          v
    CustomClientHello
          |
          v
    CustomServerHello
          |
          v
    send payload
          |
          v
    receive ACK/response

The expected peer DeviceId should be explicitly configured rather than trusting arbitrary TLS clients.

---

## 5. Custom handshake

Create:

    crates/custom-protocol/src/handshake.rs

Conceptually:

    ClientHello {
        protocol = "st-custom"
        version = 1
        device_id
        capabilities
    }

    ServerHello {
        protocol = "st-custom"
        version = 1
        device_id
        capabilities
    }

Reject the connection when:

- protocol identifier is wrong
- version is unsupported
- peer DeviceId is not authorized
- capabilities are incompatible
- frame limits are unacceptable

The custom handshake completely replaces BEP Hello.

Do not invoke:

    BepHandshaker::client_handshake()
    BepHandshaker::server_handshake()

---

## 6. Custom session

Create:

    crates/custom-protocol/src/session.rs

Responsibilities:

- read frames
- enforce maximum frame size
- decode messages
- validate message contents
- dispatch message types
- send ACKs/responses
- enforce timeouts
- terminate invalid sessions

Do not build this on `BepSession`.

The custom session should conceptually look like:

    struct CustomSession<S> {
        stream: S,
        peer_id: DeviceId,
        max_frame_size: usize,
    }

and:

    async fn run(&mut self) -> Result<()> {
        loop {
            let frame = read_frame(&mut self.stream).await?;
            let response = dispatch(frame).await?;
            write_frame(&mut self.stream, response).await?;
        }
    }

The exact implementation should follow the project's current async/runtime conventions.

---

## 7. Payload API

Start with a small envelope:

    Message {
        id
        sender
        payload_type
        payload
    }

Optional fields:

    timestamp
    correlation_id
    flags

Initially support one application operation:

    SEND_PAYLOAD

with:

    SEND_PAYLOAD
        |
        v
    PAYLOAD_ACK

Keep application semantics above the framing layer.

---

## 8. Standalone binary

Create:

    cmd/syncthing-custom/
    ├── Cargo.toml
    └── src/
        └── main.rs

Suggested commands:

    syncthing-custom listen \
        --config <directory> \
        --listen <address>

    syncthing-custom send \
        --config <directory> \
        --peer <device-id> \
        --addr <address> \
        --payload <data>

The binary should:

1. load or generate the TLS identity
2. start a TCP listener or dial a configured peer
3. establish TLS
4. obtain and/or verify the DeviceId
5. perform the custom handshake
6. exchange custom frames

Build with:

    cargo build --release --bin syncthing-custom

Keep `main.rs` thin. CLI parsing and process setup should call into the protocol/service layer rather than contain framing or protocol logic.

---

## 9. Workspace changes

Update the workspace `Cargo.toml` to add:

    crates/custom-protocol
    cmd/syncthing-custom

The repository already uses a multi-crate workspace containing protocol, networking, and binary crates.

Target dependency direction:

    syncthing-custom
     ├── custom-protocol
     └── syncthing-net

    custom-protocol
     └── generic serialization/framing dependencies

    custom-protocol ----X----> bep-protocol

---

## 10. Files to inspect first

### `crates/syncthing-net/src/tls.rs`

Purpose:

- TLS identity
- certificate loading/generation
- TLS stream setup
- DeviceId extraction
- peer identity verification

Implementation anchors:

- `SyncthingTlsConfig`
- `load_or_generate`
- `accept_tls_stream`
- `connect_tls_stream`

### `crates/syncthing-net/src/tcp_transport.rs`

Purpose:

- TCP listener
- TCP accept loop
- existing TCP-to-TLS flow
- outbound TCP connection flow

Use it as the reference for transport setup.

Do not reuse the BEP-specific connection function as the final implementation because it continues into the BEP handshake.

### `crates/syncthing-net/src/handshaker.rs`

Purpose:

Reference only.

Look at:

- `BepHandshaker`
- `client_handshake`
- `server_handshake`

Use this to understand the project's existing handshake patterns, but implement a new custom handshake.

### `crates/syncthing-net/src/session/mod.rs`

Purpose:

Reference only.

Look at:

- `BepSession`
- `BepSessionHandler`

Use it to understand the project's read/decode/dispatch/respond architecture.

Do not inherit or wrap `BepSession`.

### `crates/bep-protocol/src/lib.rs`

Purpose:

Reference only.

This is where BEP messages and encoding live.

The new `custom-protocol` crate should not depend on it.

### `cmd/syncthing/src/main.rs`

Purpose:

- CLI structure
- Tokio/runtime initialization
- configuration handling
- application startup

Use it as the structural reference for the new binary.

### `Cargo.toml`

Purpose:

- workspace membership
- dependencies
- release configuration

### `docs/design/topology.md`

Purpose:

- understand existing crate boundaries
- understand networking/protocol/core relationships

---

# Implementation Memory

This section is a compact coding reference containing the important source concepts to keep beside the implementation.

## Memory A — TLS

Source:

    crates/syncthing-net/src/tls.rs

Look for:

    SyncthingTlsConfig
    load_or_generate
    accept_tls_stream
    connect_tls_stream

The useful abstraction is:

    raw TCP stream
          |
          v
    TLS stream
          |
          v
    peer DeviceId

Conceptually:

    let (stream, peer_id) =
        accept_tls_stream(tcp_stream, &tls_config).await?;

    custom_handshake(stream, peer_id).await?;

For outbound connections:

    let (stream, peer_id) =
        connect_tls_stream(
            tcp_stream,
            &tls_config,
            Some(expected_peer_id),
        ).await?;

    custom_handshake(stream, peer_id).await?;

Use the exact current function signatures from `tls.rs`; do not assume they remain unchanged.

---

## Memory B — TCP

Source:

    crates/syncthing-net/src/tcp_transport.rs

Study:

    SyncthingTcpListener
    accept loop
    TCP -> TLS setup
    connect_bep()

The conceptual sequence is:

    TcpListener
        |
        v
      accept
        |
        v
       TLS
        |
        v
    peer identity

For outbound connections:

    TcpStream::connect
        |
        v
       TLS
        |
        v
    peer identity

### Critical distinction

`connect_bep()` is useful as a reference for transport setup, but the custom implementation must stop before the BEP handshake.

Do not implement:

    TCP
      |
      v
    TLS
      |
      v
    BEP Hello
      |
      v
    BEP session

Implement:

    TCP
      |
      v
    TLS
      |
      v
    Custom Hello
      |
      v
    Custom session

---

## Memory C — BEP Handshaker

Source:

    crates/syncthing-net/src/handshaker.rs

Look for:

    BepHandshaker
    client_handshake
    server_handshake

This file is useful for understanding the project's existing handshake style.

It is not a dependency for the custom protocol.

Replace:

    BEP ClientHello/Hello

with:

    Custom ClientHello/ServerHello

---

## Memory D — BEP Session

Source:

    crates/syncthing-net/src/session/mod.rs

Look for:

    BepSession
    BepSessionHandler

Use it only as an architectural reference for:

    read
      |
      v
    decode
      |
      v
    dispatch
      |
      v
    respond

Do not inherit or wrap `BepSession`.

The custom session should instead resemble:

    struct CustomSession<S> {
        stream: S,
        peer_id: DeviceId,
        max_frame_size: usize,
    }

with a loop equivalent to:

    async fn run(&mut self) -> Result<()> {
        loop {
            let frame = read_frame(&mut self.stream).await?;
            let response = dispatch(frame).await?;
            write_frame(&mut self.stream, response).await?;
        }
    }

---

## Memory E — Protocol crate

Target structure:

    custom-protocol/
    ├── src/
    │   ├── lib.rs
    │   ├── connection.rs
    │   ├── frame.rs
    │   ├── handshake.rs
    │   ├── message.rs
    │   ├── session.rs
    │   └── error.rs

Responsibilities:

    frame.rs
        length-prefix framing
        frame limits
        read/write

    handshake.rs
        ClientHello
        ServerHello
        version negotiation

    message.rs
        message types
        payload envelope

    session.rs
        message loop
        dispatch
        ACKs

    connection.rs
        TCP + TLS + peer identity

    error.rs
        protocol/transport errors

---

## Memory F — Binary

Target:

    cmd/syncthing-custom/src/main.rs

Keep `main.rs` thin:

    CLI parsing
          |
          v
    configuration
          |
          v
    listen/send command
          |
          v
    custom-protocol API

Avoid placing framing, serialization, or protocol-state logic directly in the CLI.

---

# Testing Memory

Minimum test matrix:

    +-----------------------------+----------+
    | Test                        | Required |
    +-----------------------------+----------+
    | Frame encode/decode         | yes      |
    | Partial frame reads        | yes      |
    | Oversized frame rejection  | yes      |
    | Unknown message type       | yes      |
    | Bad protocol version       | yes      |
    | Unauthorized DeviceId      | yes      |
    | TLS + custom handshake     | yes      |
    | Payload + ACK              | yes      |
    | Two-node E2E               | yes      |
    | Ordinary BEP peer rejected | yes      |
    +-----------------------------+----------+

Run the normal repository checks:

    cargo test --workspace
    cargo clippy --workspace --all-targets -- -D warnings
    cargo fmt --all -- --check

Also run focused tests:

    cargo test -p custom-protocol
    cargo test --bin syncthing-custom

Finally perform an actual two-process test:

    node A
      |
      | custom TCP/TLS
      v
    node B
      |
      +-- PAYLOAD_ACK

Verify that an ordinary BEP-only Syncthing peer cannot successfully complete the custom handshake.

---

# Final Architecture

                         +---------------------+
                         | syncthing-custom    |
                         |       binary        |
                         +----------+----------+
                                    |
                         +----------v----------+
                         |   custom-protocol   |
                         |                     |
                         | handshake           |
                         | framing             |
                         | messages            |
                         | session             |
                         +----------+----------+
                                    |
                         +----------v----------+
                         |    syncthing-net    |
                         |                     |
                         | TCP                 |
                         | TLS                 |
                         | DeviceId            |
                         +---------------------+


        +---------------------------------------------+
        |              Explicit boundary              |
        |                                             |
        | custom-protocol ----X----> BEP              |
        |                                             |
        +---------------------------------------------+

## Core rule

Reuse Syncthing's:

- TCP transport
- TLS implementation
- certificates
- DeviceId handling

Implement independently:

- protocol identifier
- handshake
- framing
- messages
- session
- application semantics
- CLI

Do not reuse:

- BEP Hello
- BEP message types
- `BepConnection`
- `BepSession`
- Syncthing synchronization/model machinery

The result should be a small, deliberately incompatible protocol that can communicate only with nodes implementing `st-custom/1`, while still benefiting from Syncthing's existing authenticated transport and peer-identity infrastructure.