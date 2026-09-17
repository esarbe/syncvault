# st-vault/1 — Password Vault Synchronization Protocol

## 1. Goal

Implement an encrypted password-vault sharing and synchronization protocol over the existing Syncthing-derived:

* TCP transport
* TLS
* DeviceId authentication

The protocol is **not BEP** and must not depend on BEP messages, sessions, or synchronization logic.

Protocol identifier:

```text
st-vault/1
```

Architecture:

```text
TCP
  ↓
Syncthing TLS
  ↓
peer DeviceId
  ↓
st-vault/1 handshake
  ↓
vault authorization
  ↓
encrypted event synchronization
```

---

## 2. Security boundaries

Keep three concepts separate:

```text
DeviceId
    → authenticates the transport peer

Vault membership key
    → authorizes the peer for a particular vault

Vault encryption key
    → permits access to vault contents
```

A valid Syncthing DeviceId does **not** automatically grant access to a vault.

Remote peers must never directly modify local vault state.

Every remote mutation must pass:

```text
decode
  ↓
size validation
  ↓
signature validation
  ↓
membership/authorization validation
  ↓
cryptographic validation
  ↓
causal validation
  ↓
conflict detection
  ↓
state transition
  ↓
persist
```

---

# 3. Crate structure

```text
crates/
├── custom-protocol/
│   └── src/
│       ├── lib.rs
│       ├── connection.rs
│       ├── frame.rs
│       ├── handshake.rs
│       ├── message.rs
│       ├── session.rs
│       ├── sync.rs
│       └── error.rs
│
├── vault-core/
│   └── src/
│       ├── lib.rs
│       ├── vault.rs
│       ├── record.rs
│       ├── event.rs
│       ├── version_vector.rs
│       ├── conflict.rs
│       ├── history.rs
│       ├── membership.rs
│       └── keys.rs
│
└── syncthing-net/
```

Binary:

```text
cmd/syncthing-custom/
└── src/
    └── main.rs
```

Dependency direction:

```text
syncthing-custom
    ├── custom-protocol
    └── vault-core

custom-protocol
    └── syncthing-net

custom-protocol ----X----> BEP
vault-core       ----X----> networking
```

---

# 4. Cryptographic model

Use password-based key derivation:

```text
Vault Password
      ↓
    Argon2id
      ↓
K_master
```

Generate independent vault keys:

```text
K_vault
K_history
```

Do not use the password directly for encryption.

Per-record keys may be derived with HKDF:

```text
K_record = HKDF(
    K_vault,
    "st-vault/1/record" || RecordId
)
```

Use authenticated encryption:

```text
XChaCha20-Poly1305
```

or another explicitly supported AEAD.

Encrypted payloads contain:

```text
nonce
ciphertext
authentication tag
```

Bind protocol context using AEAD associated data:

```text
protocol_version
vault_id
record_id
event_id
event_type
```

---

# 5. Vault identity

Every vault has a stable UUID:

```text
VaultId = UUID
```

Vault header:

```text
VaultHeader {
    vault_id
    protocol_version
    kdf_parameters
    encrypted_vault_key
    encrypted_history_key
    key_check
    members[]
}
```

No plaintext passwords or secret record contents belong in the header.

---

# 6. Vault membership

Represent authorized devices as:

```text
VaultMember {
    member_id
    device_id
    public_key
    encrypted_vault_key
    role
    created_at
    revoked_at
}
```

Roles:

```text
OWNER
WRITER
READER
```

Owner:

* add devices
* revoke devices
* rotate keys
* read/write vault

Writer:

* read
* create
* update
* delete

Reader:

* read/synchronize

Membership changes are themselves signed history events.

---

# 7. Device authentication

After TLS establishes the peer DeviceId, perform vault-level authentication.

Conceptual message:

```text
AUTH_REQUEST {
    vault_id
    member_id
    nonce
    signature
}
```

The signature covers:

```text
protocol
vault_id
member_id
peer_device_id
nonce
```

Verify:

```text
member.device_id == TLS peer DeviceId
```

and:

```text
member not revoked
```

The peer must prove possession of the vault membership private key.

---

# 8. Protocol handshake

After TLS:

```text
Client                         Server

ClientHello -------------------->

             <------------------ ServerHello

AuthRequest -------------------->

             <------------------ AuthResponse
```

Hello messages negotiate:

```text
protocol version
maximum frame size
supported features
compression, if implemented
```

Keep v1 cryptographic choices fixed rather than implementing unnecessary algorithm negotiation.

---

# 9. Frame format

Use a simple binary frame:

```text
+----------------+----------------+-------------------+
| length u32     | type u16       | payload           |
+----------------+----------------+-------------------+
```

Network byte order.

Initial default maximum:

```text
1 MiB
```

Reject oversized frames before allocating their payload.

Large synchronization transfers should use multiple frames.

---

# 10. Record model

Records have stable UUIDs:

```text
RecordId = UUID
```

Record types:

```text
LOGIN
SECURE_NOTE
IDENTITY
CREDIT_CARD
PASSKEY
CUSTOM
```

The protocol should treat the record payload as opaque encrypted data.

Conceptual record:

```text
Record {
    record_id
    type
    ciphertext
    nonce
    author_device_id
    modification_metadata
}
```

The protocol should not require knowledge of individual password fields.

---

# 11. Event model

Synchronization is event-based.

Do not synchronize whole database snapshots.

Mutation types:

```text
CREATE
UPDATE
DELETE
RESTORE
```

Event:

```text
RecordMutation {
    mutation_id
    record_id
    type
    causal_context
    ciphertext
    nonce
    author_device_id
    logical_time
    signature
}
```

Every event is immutable.

---

# 12. Version vectors

Each device maintains a monotonically increasing sequence.

Example:

```text
[A:17, B:4, C:9]
```

Use version vectors to determine causal relationships.

Example:

```text
A = [A:10, B:3]
B = [A:10, B:4]
```

B descends from A.

Concurrent:

```text
A = [A:11, B:3]
B = [A:10, B:4]
```

Neither event dominates the other.

Never resolve concurrent mutations by silently choosing one.

---

# 13. History

History is append-only:

```text
CREATE
  ↓
UPDATE
  ↓
UPDATE
  ↓
DELETE
```

History event types:

```text
RECORD_CREATED
RECORD_UPDATED
RECORD_DELETED
RECORD_RESTORED

DEVICE_ADDED
DEVICE_REVOKED

VAULT_KEY_ROTATED

CONFLICT_CREATED
CONFLICT_RESOLVED
```

Deletion creates a tombstone.

Do not physically remove deleted records in v1.

Do not implement history garbage collection in v1.

---

# 14. Conflict handling

Concurrent changes create conflicts.

Example:

```text
Device A:
    password = AAA

Device B:
    password = BBB
```

when both changes are concurrent.

Represent:

```text
CONFLICT
├── version A
└── version B
```

Do not automatically merge password records in v1.

Resolution creates a new mutation referencing both parents:

```text
parents = [event_A, event_B]
```

Keep the previous conflicting versions in history.

---

# 15. Synchronization protocol

Basic flow:

```text
Client                         Server

Vault authorization
        <-------------------------->

SYNC_SUMMARY ---------------------->

             <-------------------- SYNC_SUMMARY

SYNC_INVENTORY ------------------->

             <-------------------- SYNC_INVENTORY

SYNC_REQUEST --------------------->

             <-------------------- SYNC_EVENTS

EVENT_ACK ------------------------>

             <-------------------- SYNC_COMPLETE
```

The actual implementation may combine these messages where efficient.

---

# 16. Sync summary

```text
SyncSummary {
    vault_id
    version_vector
    records[]
}
```

Record summary:

```text
RecordSummary {
    record_id
    version_vector
    current_event_id
}
```

For larger vaults, use an event inventory.

---

# 17. Event inventory

Track events by:

```text
event_id
device_id
device_sequence
record_id
```

Request missing ranges:

```text
MissingEventsRequest {
    ranges[]
}

EventRange {
    device_id
    first_sequence
    last_sequence
}
```

This allows synchronization without transmitting the complete event history every time.

---

# 18. Synchronization application

Incoming events are processed:

```text
receive event
    ↓
verify signature
    ↓
verify member authorization
    ↓
verify AEAD
    ↓
validate causal context
    ↓
detect conflict
    ↓
apply state transition
    ↓
persist event
    ↓
update version vector
    ↓
ACK
```

Events must be idempotent.

Receiving the same event twice must not change state twice.

---

# 19. Device enrollment

Owner creates:

```text
DEVICE_ADD
```

containing:

```text
member_id
device_id
public_key
role
encrypted_vault_key
```

The vault key is encrypted specifically for the new device.

The new device can then synchronize normally.

---

# 20. Device revocation

Create:

```text
DEVICE_REVOKE
```

containing:

```text
member_id
device_id
timestamp
reason
```

Revocation prevents future authorization but does not erase keys already obtained by the device.

Therefore revocation should normally be followed by:

```text
revoke device
      ↓
rotate K_vault
      ↓
re-wrap active keys
      ↓
distribute new key to remaining members
```

---

# 21. Key rotation

Use envelope encryption so key rotation does not require immediately re-encrypting every record.

Conceptually:

```text
old K_vault
     ↓
new K_vault
     ↓
re-wrap record keys
```

The rotation becomes a signed history event:

```text
VAULT_KEY_ROTATED
```

---

# 22. Protocol messages

Initial message set:

```text
CLIENT_HELLO
SERVER_HELLO

AUTH_REQUEST
AUTH_RESPONSE

VAULT_LIST
VAULT_INFO

SYNC_SUMMARY
SYNC_INVENTORY
SYNC_REQUEST
SYNC_EVENTS
SYNC_COMPLETE

EVENT_ACK
EVENT_REJECT

CONFLICT_LIST
CONFLICT_RESOLVE

DEVICE_ADD
DEVICE_REVOKE

KEY_ROTATE

PING
PONG

ERROR
GOODBYE
```

Keep the message set small until the synchronization state machine is stable.

---

# 23. Local vault API

`vault-core` should expose operations such as:

```rust
trait Vault {
    fn create_record(...);
    fn update_record(...);
    fn delete_record(...);
    fn restore_record(...);

    fn list_records(...);
    fn get_record(...);

    fn history(...);
    fn conflicts(...);
    fn resolve_conflict(...);

    fn add_device(...);
    fn revoke_device(...);
    fn rotate_keys(...);

    fn sync(...);
}
```

The exact API can be adapted to the repository's existing Rust conventions.

Networking must not leak into `vault-core`.

---

# 24. Local persistence

Persist at least:

```text
vault
records
events
version_vectors
members
conflicts
sync_peers
```

Optionally:

```text
checkpoints
event_index
```

The local storage must not contain plaintext vault secrets unless explicitly required by the application and protected by an appropriate local security mechanism.

---

# 25. Initial implementation scope

### Implement in v1

```text
✓ st-vault/1
✓ custom binary framing
✓ Syncthing TCP/TLS
✓ DeviceId authentication
✓ vault membership authentication
✓ one vault
✓ Argon2id
✓ XChaCha20-Poly1305
✓ vault encryption key
✓ encrypted records
✓ OWNER / WRITER / READER
✓ CREATE
✓ UPDATE
✓ DELETE
✓ RESTORE
✓ append-only history
✓ version vectors
✓ conflict detection
✓ explicit conflict resolution
✓ event synchronization
✓ idempotent event application
✓ device enrollment
✓ device revocation
✓ key rotation
```

### Defer

```text
- history garbage collection
- checkpoint compaction
- encrypted record identifiers
- compression
- automatic semantic field merging
- cloud relay
- multi-vault optimization
```

---

# 26. Required invariants

The implementation should enforce these invariants:

1. A DeviceId alone never grants vault access.
2. Every vault mutation is authenticated and authorized.
3. Every secret payload is encrypted and authenticated.
4. Every event is immutable.
5. Every event has a causal context.
6. Duplicate events are idempotent.
7. Concurrent updates are never silently discarded.
8. Deletes are represented by tombstones.
9. Revoked devices cannot authorize new operations.
10. Vault-core never trusts the network layer.
11. The custom protocol never depends on BEP.
12. Remote events cannot bypass the vault state machine.

---

# 27. Final architecture

```text
                       syncthing-custom
                              |
                +-------------+-------------+
                |                           |
                v                           v
        custom-protocol                 vault-core
                |                           |
                |                 +---------+---------+
                |                 |         |         |
                |                 v         v         v
                |              records   history    keys
                |
                v
          syncthing-net
          TCP / TLS / DeviceId


                PEER A                  PEER B
                  |                       |
                  | TLS + DeviceId        |
                  |<--------------------->|
                  |                       |
                  | st-vault/1            |
                  |<--------------------->|
                  |                       |
                  | authenticate member   |
                  |<--------------------->|
                  |                       |
                  | compare vectors       |
                  |<--------------------->|
                  |                       |
                  | exchange events       |
                  |<--------------------->|
                  |                       |
                  | verify/apply/ACK      |
                  |<--------------------->|
```

## Core principle

The protocol is an **encrypted append-only event replication system layered over Syncthing's authenticated transport**.

```text
DeviceId
    = Who is this peer?

Vault membership
    = Is this peer authorized for this vault?

Vault key
    = Can this peer decrypt the secrets?

Version vector
    = Which state does this peer know?

Event history
    = What happened?

Conflict
    = Which concurrent states require explicit resolution?
```
