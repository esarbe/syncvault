# st-vault/1 — Compact Implementation Plan

Assumption: `syncthing-custom` already provides working TCP/TLS transport, Syncthing `DeviceId` authentication, custom framing, handshake, sessions, and a standalone binary.

## 1. Create `vault-core`

Add:

    crates/vault-core/
    ├── Cargo.toml
    └── src/
        ├── lib.rs
        ├── vault.rs
        ├── record.rs
        ├── event.rs
        ├── version_vector.rs
        ├── conflict.rs
        ├── history.rs
        ├── membership.rs
        └── keys.rs

Keep `vault-core` independent of networking.

---

## 2. Implement vault identity and metadata

Define:

    VaultId = UUID

Implement:

    VaultHeader
    KdfParameters
    VaultMetadata

Store:

    vault_id
    protocol_version
    KDF parameters
    encrypted vault key
    encrypted history key
    key-check value
    members

No plaintext secrets in metadata.

---

## 3. Implement key hierarchy

Implement:

    password
      ↓
    Argon2id
      ↓
    K_master
      ↓
    K_vault
    K_history

Use random salts and cryptographically secure random keys.

Use an AEAD such as:

    XChaCha20-Poly1305

Use HKDF for deterministic per-record key derivation if required.

Add tests for:

- key derivation
- wrong password
- encryption/decryption
- tampered ciphertext
- nonce handling

---

## 4. Implement records

Define:

    RecordId = UUID

Support initially:

    LOGIN
    SECURE_NOTE
    IDENTITY
    CREDIT_CARD
    PASSKEY
    CUSTOM

Represent record contents as opaque encrypted payloads.

Implement:

    create_record()
    update_record()
    delete_record()
    restore_record()
    get_record()
    list_records()

Do not put application-specific password fields into the synchronization protocol.

---

## 5. Implement version vectors

Create:

    VersionVector

Support:

    increment(device_id)
    merge(other)
    dominates(other)
    is_concurrent(other)
    compare(other)

Test:

- equal vectors
- ancestor/descendant
- concurrent vectors
- merge
- missing devices

This becomes the causal foundation of synchronization.

---

## 6. Implement immutable events

Define:

    EventId
    RecordMutation
    EventType

Support:

    CREATE
    UPDATE
    DELETE
    RESTORE

Each event contains at least:

    event_id
    record_id
    mutation type
    causal version vector
    encrypted payload
    author DeviceId
    device sequence
    signature

Events must be immutable and uniquely identifiable.

---

## 7. Implement history

Create an append-only event store.

Operations:

    append(event)
    get(event_id)
    events_for_record(record_id)
    events_since(version_vector)
    history(record_id)

Enforce:

- event uniqueness
- valid device sequence
- valid signatures
- causal consistency

Do not implement history garbage collection yet.

---

## 8. Implement membership

Define:

    VaultMember
    OWNER
    WRITER
    READER

Implement:

    add_member()
    revoke_member()
    find_member()
    authorize(member, operation)

Bind every member to:

    DeviceId
    public key
    role
    encrypted vault key

Membership changes must become signed events.

---

## 9. Implement vault-level authentication

Extend `syncthing-custom` with the `st-vault/1` application handshake.

After transport authentication:

    TLS
      ↓
    peer DeviceId
      ↓
    st-vault handshake
      ↓
    vault authentication

Implement:

    AUTH_REQUEST
    AUTH_RESPONSE

Authentication proves that the peer owns the private key corresponding to an authorized vault member.

Verify:

    member.device_id == TLS peer DeviceId

Reject:

- unknown member
- revoked member
- invalid signature
- wrong vault
- replayed nonce

---

## 10. Define `st-vault/1` messages

Add vault-specific messages to `custom-protocol`:

    VAULT_LIST
    VAULT_INFO

    AUTH_REQUEST
    AUTH_RESPONSE

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

    ERROR
    GOODBYE

Reuse the already implemented custom framing.

---

## 11. Implement sync summaries

Define:

    SyncSummary {
        vault_id
        version_vector
        records
    }

and:

    RecordSummary {
        record_id
        version_vector
        current_event_id
    }

Implement comparison of local and remote state.

The result should be a set of missing event ranges.

---

## 12. Implement event inventory

Index events by:

    device_id
    device_sequence
    event_id
    record_id

Implement:

    MissingEventsRequest
    EventRange

Example:

    Device A: 1..37
    Device B: 1..12

A peer possessing:

    A: 1..30
    B: 1..12

requests:

    A: 31..37

Avoid transmitting the entire history during every synchronization.

---

## 13. Implement event transfer

Implement:

    SYNC_REQUEST
    SYNC_EVENTS
    EVENT_ACK
    EVENT_REJECT

For each received event:

    decode
      ↓
    validate size
      ↓
    verify signature
      ↓
    verify membership
      ↓
    decrypt/verify AEAD
      ↓
    validate causal context
      ↓
    detect duplicate
      ↓
    detect conflict
      ↓
    apply
      ↓
    persist
      ↓
    ACK

Make event application idempotent.

---

## 14. Implement conflict detection

When two mutations are concurrent:

    VersionVector(A)
          ↕
    concurrent
          ↕
    VersionVector(B)

do not overwrite either version.

Create a conflict containing both branches.

Expose:

    list_conflicts()
    get_conflict()
    resolve_conflict()

Resolution creates a new event whose causal context contains both conflicting versions.

Never silently discard the losing branch.

---

## 15. Implement tombstones

`DELETE` creates a persistent tombstone.

Do not physically remove the record from synchronization state.

This prevents an offline peer from resurrecting deleted data.

Implement:

    delete_record()
    restore_record()

as events rather than direct database mutations.

---

## 16. Implement device enrollment

Implement:

    DEVICE_ADD

Owner supplies:

    member_id
    device_id
    public_key
    role

Generate/wrap the vault key specifically for the new device.

The enrollment itself becomes a signed event.

Test:

    owner → new device → authenticate → sync

---

## 17. Implement device revocation

Implement:

    DEVICE_REVOKE

Reject future authentication from the revoked member.

Then implement key rotation:

    revoke device
      ↓
    rotate K_vault
      ↓
    re-wrap keys
      ↓
    distribute new vault key

Do not claim that revocation cryptographically removes previously obtained plaintext or keys.

---

## 18. Implement key rotation

Implement:

    KEY_ROTATE

Generate a new vault key.

Use envelope encryption so active record ciphertext does not need to be rewritten unnecessarily.

Authorize rotation only for `OWNER`.

Record the rotation in history.

---

## 19. Add persistence

Persist at least:

    vault metadata
    records
    events
    version vectors
    members
    conflicts
    event index
    sync state

Use transactions around:

    event persistence
    state transition
    version-vector update

A successfully acknowledged event must survive process restart.

---

## 20. Connect to `syncthing-custom`

Add a vault service above the existing custom session:

    syncthing-custom
          ↓
    custom-protocol
          ↓
    vault session
          ↓
    vault-core

`vault-core` must never access sockets directly.

The protocol layer converts network messages into vault-core operations.

---

## 21. Implement vault registry and unlock lifecycle

Add a durable vault registry that maps a user-facing vault name to:

    vault_id
    storage path
    local member_id
    configured peers

Persist the complete `VaultHeader`, including the encrypted key hierarchy needed
to unlock the vault. Do not persist only redacted `VaultMetadata`.

Implement:

    create_vault(name, password)
    list_vaults()
    open_vault(name)
    unlock_vault(name, password)

Vault creation must generate KDF parameters, initialize the owner membership,
and securely persist the local signing identity. Reject duplicate or invalid
vault names.

Passwords must be supplied through a secret-input abstraction and must never be
accepted from an insecure default command-line argument or written to logs.

---

## 22. Implement operational state reconstruction and vault service

Add import/reconstruction APIs for:

    RecordStore
    EventHistory
    MembershipStore
    ConflictStore
    version vectors
    event indexes
    sync state

Create a `VaultService` or equivalent application facade above these stores.
It owns an unlocked vault and exposes authorized operations for records,
history, membership, conflicts, and synchronization.

Every mutating operation must:

    authorize
      ↓
    encrypt and sign an immutable event
      ↓
    update history and derived state
      ↓
    persist atomically

Add lookups required by callers, including device ID to member ID, record name
to record ID, and access to tombstoned records for restore operations.

The CLI and protocol handlers must call this facade instead of composing
low-level stores directly.

---

## 23. Define record and conflict presentation semantics

Define a versioned plaintext record document inside the encrypted payload. It
must support:

    record name
    record type
    value
    named fields

Implement validation and serialization for each supported record type while
keeping the synchronization protocol payload opaque.

Define deterministic record-name lookup behavior, including duplicate-name
handling and whether commands may accept a `RecordId` to disambiguate.

Define conflict display and resolution inputs. Resolution must explicitly
select a branch or provide a merged record value before creating the signed
resolution event.

---

## 24. Complete vault protocol dispatch and sync orchestration

Extend the authenticated vault session beyond `AUTH_REQUEST` and
`AUTH_RESPONSE`.

Implement typed request/response handling for:

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
    ERROR
    GOODBYE

Route incoming messages through `VaultService`, enforce authorization for each
operation, and bound all decoded collections and payloads.

Add client-side synchronization orchestration and a server-side vault listener.
Peer selection must resolve a configured device and address from the vault
registry or require them explicitly.

---

## 25. Define the CLI contract and support utilities

Use the command hierarchy:

    vault info
    vault list
    vault create <name>
    vault <name> ...

Define all required inputs before wiring handlers:

- `add-device`: device ID, public key, role, and key-enrollment material
- `revoke-device`: device ID resolved to a member ID
- `record update`: replacement value and/or repeated field updates
- `conflicts resolve`: selected branch or merged value
- `sync`: configured peer or explicit device ID and address

Add reusable support for secure password prompts, `$EDITOR` integration through
a permission-restricted temporary file, confirmation prompts, structured JSON
output, secret redaction, and stable process exit codes.

---

## 26. Add CLI operations

Extend the existing binary with commands similar to:

    vault info // show device id and other info
    vault list
    vault create <name>

    vault <name> devices
    vault <name> add-device
    vault <name> revoke-device <device-id>

    vault <name> record list
    vault <name> record create <type> <name>
    vault <name> record get <name>
    vault <name> record update <name> <value> -f <field> <value> --field <field> <value>
    vault <name> record edit <name>
    vault <name> record delete <name>
    vault <name> record restore <name>

    vault <name> history
    vault <name> history <record>

    vault <name> conflicts show
    vault <name> conflicts resolve <conflict-id>

    vault <name> sync   

Keep CLI code thin.

---

## 27. Test in layers

### Crypto

    key derivation
    encryption/decryption
    authentication failure
    tampering
    wrong password

### Core state

    record lifecycle
    version vectors
    event application
    duplicate events
    tombstones
    conflicts

### Membership

    add
    authorize
    revoke
    unauthorized access

### Protocol

    handshake
    authentication
    sync summary
    missing events
    ACK/rejection
    malformed messages
    oversized messages

### Integration

    two devices
    create → sync
    update → sync
    delete → sync
    offline concurrent updates
    conflict resolution
    device enrollment
    device revocation
    key rotation
    restart during synchronization

---

## 28. Two-device end-to-end test

Start:

    Device A
    Device B

Enroll B into A's vault.

Then verify:

    A creates record
        ↓
    B syncs
        ↓
    B decrypts record

Then:

    B updates record
        ↓
    A syncs
        ↓
    A sees update

Then create concurrent updates:

    A offline → update
    B offline → update

Reconnect:

    conflict detected
        ↓
    both versions retained
        ↓
    resolve conflict
        ↓
    resolution syncs to both devices

---

## 29. Security review before release

Verify explicitly:

- secrets never appear in logs
- passwords are never sent over the protocol
- DeviceId alone cannot unlock a vault
- revoked members cannot authenticate
- signatures cannot be replayed
- events cannot be modified undetected
- ciphertext cannot be moved between records
- duplicate events are harmless
- concurrent updates are retained
- deletes cannot be resurrected by stale state
- frame sizes are bounded
- malformed peers cannot panic the process
- synchronization is transactional

---

## 30. Final implementation order

Implement in this order:

1. `vault-core` skeleton
2. cryptographic key hierarchy
3. encrypted records
4. version vectors
5. immutable events
6. history/event store
7. membership and authorization
8. vault authentication
9. protocol messages
10. sync summaries
11. event inventory
12. event transfer/application
13. conflict handling
14. tombstones
15. device enrollment
16. device revocation
17. key rotation
18. persistence and complete encrypted header storage
19. vault registry and unlock lifecycle
20. operational state reconstruction
21. transactional vault service
22. record and conflict presentation semantics
23. vault protocol dispatch and sync orchestration
24. CLI contract and support utilities
25. CLI integration
26. persistence/recovery testing
27. two-device end-to-end tests
28. security review

The critical dependency chain is:

    crypto
      ↓
    records
      ↓
    events
      ↓
    version vectors
      ↓
    history
      ↓
    membership
      ↓
    authentication
      ↓
    synchronization
      ↓
    conflicts
      ↓
    enrollment/revocation
      ↓
    key rotation
      ↓
    end-to-end integration