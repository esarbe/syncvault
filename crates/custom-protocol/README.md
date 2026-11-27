# Custom Protocol Messenger

A standalone text messenger using certificate-authenticated TLS over direct TCP
or Syncthing Relay Protocol v1. It uses the `st-custom/1` ALPN protocol, not BEP:
it does not sync files or exchange messages with the Syncthing daemon.

## Setup

Use a **separate configuration directory and identity** for the messenger on
each device. Sharing a daemon's identity can overwrite its discovery records
or compete for its relay registration.

Generate each device's persistent certificate and print its device ID:

```bash
cargo run -p custom-protocol -- id --config-dir ./messenger-a
cargo run -p custom-protocol -- id --config-dir ./messenger-b
```

Create `config.json` inside each directory. For device A, substitute device B's
ID and reachable address in this example:

```json
{
  "version": 1,
  "listen_addr": "0.0.0.0:9000",
  "folders": [],
  "devices": [
    {
      "id": "<device-b-id>",
      "name": "Device B",
      "addresses": ["tcp://192.168.1.20:9000"],
      "paused": false,
      "introducer": false
    }
  ],
  "options": {
    "listen_addresses": [],
    "global_announce_enabled": false,
    "local_announce_enabled": false,
    "relays_enabled": false
  }
}
```

Device B must likewise list device A as a non-paused peer. Device IDs are derived
from certificates; an optional `local_device_id` must match that certificate.
Existing incomplete or invalid certificate/key pairs cause an error rather than
being silently replaced.

## Send and receive

Start the receiver:

```bash
cargo run -p custom-protocol -- listen --config-dir ./messenger-b
```

Optionally override its bind address with `--bind 127.0.0.1:9000`. Then send:

```bash
cargo run -p custom-protocol -- send --config-dir ./messenger-a \
  <device-b-id> "Hello from another device"
```

The listener prints `[sender-device-id] message`. The sender exits successfully
only after receiving a matching protocol acknowledgement. Both devices can run
a listener while invoking `send` separately. Ctrl+C stops listener-owned tasks.
Set `RUST_LOG=debug` for network diagnostics on stderr.

## Discovery and route selection

1. Try configured TCP addresses, including DNS hostnames.
2. If those fail, query enabled local/global discovery and try new TCP addresses.
3. If TCP still fails and `relays_enabled` is true, try configured/discovered relays.

Use `"dynamic"` in a peer's address list for discovery-only routing; the peer must
still be explicitly trusted by ID. Discovery failures are reported and do not
discard other routes. A working configured TCP address does not depend on discovery.

- `local_announce_enabled`: listeners announce on UDP port 21027; senders listen
  for up to 31 seconds without advertising a nonexistent listener. Wildcard TCP
  addresses in local announcements use the UDP sender's IP.
- `global_announce_enabled`: enables the existing Syncthing discovery client,
  including certificate-authenticated announcements. This publishes the
  messenger's device ID and addresses to the configured discovery service.
- `options.listen_addresses`: optional `tcp://host:port` addresses to advertise
  instead of the bound address (e.g. a reachable public endpoint behind NAT).
  This does not configure additional TCP listeners or perform port forwarding.

Optional top-level messenger settings:

```json
"messenger": {
  "discovery_server": "https://discovery.example.org/v2/",
  "local_discovery_port": 21027
}
```

Omit `discovery_server` to use the existing client's default Syncthing service.
Use HTTPS outside isolated loopback tests. The UDP port must be nonzero and match
the peer's announcement port. Discovery listeners share the UDP port, allowing
concurrent lookup commands; another program using an exclusive bind can prevent
discovery startup.

## Relay support

Enable `options.relays_enabled` on both peers. On each receiving device, add the
relay's URL to `options.listen_addresses`, for example:

```json
"listen_addresses": [
  "relay://192.168.1.50:22067/?id=<relay-device-id>"
]
```

On the sender, put the same URL in the receiving peer's `addresses`, or obtain
it through global discovery. Only successfully registered relays are globally
advertised. Listener registration reconnects with backoff from 1 to 60 seconds.
No public relay pool is contacted automatically.

Relay URLs currently require a numeric IP address and port (bracket IPv6
addresses); `?id=` optionally pins the relay's certificate. Extra URL query
parameters and relay hostnames are not supported. The relay must report a valid
session port. Raw IPv4/IPv6 invitation addresses and the bundled server's textual
address form are supported.

Relay control connections use `bep-relay`; the paired session carries a separate
end-to-end `st-custom/1` TLS connection. Both TLS roles from relay invitations
are supported, and peer authentication is independent of the relay's identity.

## Limits and delivery semantics

- Only configured, non-paused peers may establish a messaging session.
- TCP/relay destinations use the shared outbound-address validator. A loopback
  relay may use its own IP for sessions, but cannot redirect to another loopback IP.
- At most 64 incoming sessions (direct and relay combined), 10-second connection,
  handshake and acknowledgement deadlines, and a 120-second receive-idle timeout.
- Frames are limited to 128 KiB of serialized data; text capacity is lower because
  the JSON envelope also occupies space.
- Route fallback happens **before sending the payload**. If delivery or its ACK
  fails afterward, the command reports failure/uncertain delivery without retrying
  and potentially duplicating a message.
- An ACK confirms protocol receipt, not durable storage, display, or exactly-once
  delivery. There is no offline queue or persistent message history.

## Validation

```bash
cargo test -p custom-protocol
```

The integration suite launches real messenger processes with temporary
`TestNode` identities. It covers bidirectional direct TLS alongside BEP,
untrusted peers, local/global discovery, bidirectional relay fallback, relay
certificate pinning, fragmented relay frames, and relay reconnection.
All integration network traffic stays on loopback; no public discovery or relay
service is required.
