# Custom Protocol Messenger

A small TCP program for sending text messages between devices with the custom
protocol.

## Usage

Generate a unique device ID on each device:

```bash
cargo run -p custom-protocol -- id
```

On the receiving device, start a listener with its generated ID:

```bash
cargo run -p custom-protocol -- listen 0.0.0.0:9000 <receiver-device-id>
```

On another device, send a message using the sender ID and receiver ID:

```bash
cargo run -p custom-protocol -- send \
  <receiver-host>:9000 \
  <sender-device-id> \
  <receiver-device-id> \
  "Hello from another device"
```

The listener accepts multiple devices concurrently and prints each message with
its sender ID. The sender exits after the receiver acknowledges the message.

## Security

This example uses unencrypted TCP, and device IDs exchanged by the handshake are
not cryptographically authenticated. Use an authenticated encrypted transport
before exposing it to an untrusted network.