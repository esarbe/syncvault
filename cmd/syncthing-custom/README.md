# syncthing-custom

`syncthing-custom` is the standalone executable for the generic `st-custom`
payload protocol and the encrypted `st-vault/1` vault protocol.

## Build

From the workspace root:

```bash
cargo build --release -p syncthing-custom
```

The binary is written to:

```text
target/release/syncthing-custom
```

Run tests and strict checks with:

```bash
cargo test -p syncthing-custom
cargo clippy -p syncthing-custom --all-targets -- -D warnings -W clippy::await_holding_lock
cargo fmt --all -- --check
```

## Global Options

Every invocation requires a configuration directory. TLS identity files and the
vault registry are stored below this directory.

```text
syncthing-custom --config <DIR> [--json] [--yes] [--password-file <FILE>] <COMMAND>
```

- `--json` emits machine-readable JSON for vault operations.
- `--yes` confirms destructive operations without an interactive prompt.
- `--password-file <FILE>` reads the vault password from a file. One trailing
  CR/LF sequence is ignored. File input is required in non-interactive use.
- Without `--password-file`, commands that unlock a vault securely prompt on a
  terminal. Vault creation prompts twice.

Passwords, encrypted enrollment material, and private signing keys are never
included in metadata output.

Exit statuses are stable: `0` for success, `1` for an operational failure, and
`2` for command-line usage errors reported by Clap.

## Endpoint Information

Show the local TLS device ID and supported vault protocol:

```bash
syncthing-custom --config ./config vault info
```

Show metadata for a named vault without unlocking it:

```bash
syncthing-custom --config ./config vault personal info
```

## Vault Lifecycle

List registered vaults:

```bash
syncthing-custom --config ./config vault list
```

Create a vault:

```bash
syncthing-custom --config ./config vault create personal
syncthing-custom --config ./config --password-file ./password.txt vault create personal
```

Vault names are exact and case-sensitive.

## Device Identity And Enrollment

Vault enrollment uses three distinct identities:

- The TLS certificate determines the Syncthing `DeviceId` used to authenticate
  network peers.
- An Ed25519 key signs vault events and enrollment requests.
- An X25519 key seals enrollment material so only the requested device can
  import it.

`device-key generate` creates both vault key pairs locally, binds their public
identity to the TLS `DeviceId`, and encrypts the private keys under the supplied
password. It does not print private keys.

On the device joining the vault, generate its identity and signed request:

```bash
syncthing-custom --config ./device-b --password-file ./device-b-password.txt \
  device-key generate

syncthing-custom --config ./device-b --password-file ./device-b-password.txt \
  device-key request --output ./device-b-request.json
```

Show only the public identity at any later time:

```bash
syncthing-custom --config ./device-b device-key show
```

Transfer `device-b-request.json` to an existing vault owner. On the owner,
prepare a recipient-sealed, owner-signed enrollment bundle:

```bash
syncthing-custom --config ./device-a --password-file ./device-a-password.txt \
  vault personal enrollment prepare \
  --request ./device-b-request.json \
  --role writer \
  --owner-address 192.0.2.10:22002 \
  --output ./device-b-enrollment.json
```

Transfer the enrollment file to the joining device and import it. The same
password unlocks the local device identity and becomes the imported vault's
local password wrapper:

```bash
syncthing-custom --config ./device-b --password-file ./device-b-password.txt \
  vault import ./device-b-enrollment.json --name personal
```

The enrollment request and bundle expire after 24 hours by default. Use
`--ttl <SECONDS>` when creating either artifact to shorten their lifetime.
Import rejects altered, expired, replayed, wrong-recipient, duplicate, or
owner-inconsistent bundles. The owner's address is persisted as the imported
vault's peer, so synchronization can then use:

```bash
syncthing-custom --config ./device-b --password-file ./device-b-password.txt \
  vault personal sync
```

## Devices

List members. Output includes public identity data but redacts wrapped vault
keys:

```bash
syncthing-custom --config ./config vault personal devices
```

`add-device` is a low-level membership operation for externally provisioned
systems. Normal use should follow the signed enrollment workflow above. Public
keys must be 32-byte Ed25519 keys encoded as hexadecimal, and the encrypted
vault key must be opaque externally prepared enrollment material.

```bash
syncthing-custom --config ./config vault personal add-device \
  --device-id <DEVICE_ID> \
  --public-key <64_HEX_CHARACTERS> \
  --role writer \
  --encrypted-vault-key <HEX>
```

Roles are `owner`, `writer`, and `reader`. Use `--member-id <UUID>` to preserve
an externally assigned member ID; otherwise a UUID is generated.

Revoke a device:

```bash
syncthing-custom --config ./config vault personal revoke-device <DEVICE_ID>
```

Revocation asks for confirmation. Supply `--yes` for unattended operation.

## Records

Supported record types are `login`, `secure-note`, `identity`, `credit-card`,
`passkey`, and `custom`.

List records:

```bash
syncthing-custom --config ./config vault personal record list
```

Create records:

```bash
syncthing-custom --config ./config vault personal record create secure-note notes \
  --value "private text"

syncthing-custom --config ./config vault personal record create login example \
  --value "primary secret" \
  --field username alice \
  --field url https://example.com
```

Get a record by exact name or UUID:

```bash
syncthing-custom --config ./config vault personal record get example
syncthing-custom --config ./config vault personal record get <RECORD_UUID>
```

Update the value, fields, or both:

```bash
syncthing-custom --config ./config vault personal record update example "new secret"
syncthing-custom --config ./config vault personal record update example \
  --field username bob \
  --field notes "rotated credentials"
```

Field updates replace fields with matching names and retain other fields.
Allowed field names depend on the record type; custom records accept arbitrary
validated field names.

Edit the complete decrypted record document with `$VISUAL` or `$EDITOR`:

```bash
EDITOR="code --wait" syncthing-custom --config ./config vault personal record edit example
```

The editor file is created with owner-only permissions where supported and is
removed automatically. The edited JSON must preserve the record type.

Delete a record by exact name or UUID:

```bash
syncthing-custom --config ./config vault personal record delete example
```

Restore a tombstone by UUID:

```bash
syncthing-custom --config ./config vault personal record restore <RECORD_UUID>
```

Delete requires confirmation unless `--yes` is supplied. Tombstones are
addressed by UUID because deleted names may be reused.

## History

Show all immutable events:

```bash
syncthing-custom --config ./config vault personal history
```

Show history for one live record by exact name or UUID:

```bash
syncthing-custom --config ./config vault personal history example
```

History output includes event identifiers, authors, sequence numbers, mutation
types, encrypted payloads, and signatures. It does not decrypt historical
payloads.

## Conflicts

List conflicts and branch metadata:

```bash
syncthing-custom --config ./config vault personal conflicts show
```

Resolve by selecting an existing branch:

```bash
syncthing-custom --config ./config vault personal conflicts resolve <CONFLICT_UUID> \
  --branch <EVENT_UUID>
```

Resolve by creating a merged document from an existing branch and replacing its
value and optional fields:

```bash
syncthing-custom --config ./config vault personal conflicts resolve <CONFLICT_UUID> \
  --merge-value "merged value" \
  --field notes "reviewed"
```

Exactly one of `--branch` and `--merge-value` is required.

## Synchronization

Synchronize with an explicitly identified TLS peer:

```bash
syncthing-custom --config ./config vault personal sync \
  --peer <DEVICE_ID> \
  --addr 192.0.2.10:22002
```

`--peer` and `--addr` must be supplied together. If omitted, the command uses
the vault registry when exactly one peer with an address is configured.
Synchronization performs TLS identity verification, mutual vault-member
authentication, bounded event exchange, and per-event acknowledgements.

Serve one unlocked vault:

```bash
syncthing-custom --config ./config vault personal serve \
  --listen 0.0.0.0:22002 \
  --peer <EXPECTED_DEVICE_ID>
```

Omit `--peer` to accept any TLS peer that subsequently passes vault membership
authentication.

## Generic Payload Protocol

Listen for generic `st-custom` payload sessions:

```bash
syncthing-custom --config ./config listen --listen 0.0.0.0:22002
syncthing-custom --config ./config listen --peer <DEVICE_ID>
```

Send a generic payload and wait for its acknowledgement:

```bash
syncthing-custom --config ./config send \
  --peer <DEVICE_ID> \
  --addr 192.0.2.10:22002 \
  --payload "hello" \
  --payload-type text
```

The legacy listener can also serve a vault when both `--vault` and
`--password-file` are supplied:

```bash
syncthing-custom --config ./config listen \
  --vault personal \
  --password-file ./password.txt \
  --peer <DEVICE_ID>
```

Prefer `vault <name> serve` for new scripts.

## JSON Automation

Place global options before or after subcommands:

```bash
syncthing-custom --config ./config vault list --json
syncthing-custom --config ./config --json --password-file ./password.txt \
  vault personal record list
```

For destructive automation, also pass `--yes`:

```bash
syncthing-custom --config ./config --json --yes \
  --password-file ./password.txt \
  vault personal record delete example
```
