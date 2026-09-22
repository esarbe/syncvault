use std::collections::BTreeMap;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::json;
use syncthing_core::DeviceId;
use tempfile::NamedTempFile;
use uuid::Uuid;
use vault_core::{
    ConflictResolution, DeviceIdentityStore, EnrollmentBundle, EnrollmentRequest, MemberRole,
    RecordDocument, RecordReference, RecordType, VaultMember, VaultPassword, VaultRegistry,
    VaultService, DEFAULT_ENROLLMENT_TTL_SECONDS,
};
use zeroize::Zeroizing;

#[derive(Args, Debug)]
pub struct VaultArgs {
    pub name: Option<String>,
    #[command(subcommand)]
    pub command: VaultCommand,
}

#[derive(Args, Debug)]
pub struct DeviceKeyArgs {
    #[command(subcommand)]
    pub command: DeviceKeyCommand,
}

#[derive(Subcommand, Debug)]
pub enum DeviceKeyCommand {
    Generate,
    Show,
    Request {
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
        #[arg(long, default_value_t = DEFAULT_ENROLLMENT_TTL_SECONDS)]
        ttl: i64,
    },
}

#[derive(Subcommand, Debug)]
pub enum VaultCommand {
    Info,
    List,
    Create {
        name: String,
    },
    Import {
        enrollment_file: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
    Enrollment {
        #[command(subcommand)]
        command: EnrollmentCommand,
    },
    Devices,
    AddDevice(AddDeviceArgs),
    RevokeDevice {
        device_id: DeviceId,
    },
    Record {
        #[command(subcommand)]
        command: RecordCommand,
    },
    History {
        record: Option<String>,
    },
    Conflicts {
        #[command(subcommand)]
        command: ConflictCommand,
    },
    Sync(SyncArgs),
    Serve(ServeArgs),
}

#[derive(Subcommand, Debug)]
pub enum EnrollmentCommand {
    Prepare {
        #[arg(long, value_name = "FILE")]
        request: PathBuf,
        #[arg(long, value_enum)]
        role: RoleArg,
        #[arg(long)]
        owner_address: String,
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
        #[arg(long, default_value_t = DEFAULT_ENROLLMENT_TTL_SECONDS)]
        ttl: i64,
    },
}

#[derive(Args, Debug)]
pub struct AddDeviceArgs {
    #[arg(long)]
    pub device_id: DeviceId,
    #[arg(long, value_parser = parse_hex_32)]
    pub public_key: Vec<u8>,
    #[arg(long, value_enum)]
    pub role: RoleArg,
    #[arg(long, value_parser = parse_nonempty_hex)]
    pub encrypted_vault_key: Vec<u8>,
    #[arg(long)]
    pub member_id: Option<Uuid>,
}

#[derive(Args, Debug)]
pub struct SyncArgs {
    #[arg(long)]
    pub peer: Option<DeviceId>,
    #[arg(long)]
    pub addr: Option<String>,
}

#[derive(Args, Debug)]
pub struct ServeArgs {
    #[arg(long, default_value = "0.0.0.0:22002")]
    pub listen: String,
    #[arg(long)]
    pub peer: Option<DeviceId>,
}

#[derive(Subcommand, Debug)]
pub enum RecordCommand {
    List,
    Create {
        #[arg(value_enum)]
        record_type: RecordTypeArg,
        name: String,
        #[arg(long, default_value = "")]
        value: String,
        #[arg(short = 'f', long = "field", value_names = ["FIELD", "VALUE"], num_args = 2)]
        fields: Vec<String>,
    },
    Get {
        record: String,
    },
    Update {
        record: String,
        value: Option<String>,
        #[arg(short = 'f', long = "field", value_names = ["FIELD", "VALUE"], num_args = 2)]
        fields: Vec<String>,
    },
    Edit {
        record: String,
    },
    Delete {
        record: String,
    },
    Restore {
        record_id: Uuid,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConflictCommand {
    Show,
    Resolve {
        conflict_id: Uuid,
        #[arg(
            long,
            conflicts_with = "merge_value",
            required_unless_present = "merge_value"
        )]
        branch: Option<Uuid>,
        #[arg(long, conflicts_with = "branch", required_unless_present = "branch")]
        merge_value: Option<String>,
        #[arg(short = 'f', long = "field", value_names = ["FIELD", "VALUE"], num_args = 2)]
        fields: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum RecordTypeArg {
    Login,
    SecureNote,
    Identity,
    CreditCard,
    Passkey,
    Custom,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum RoleArg {
    Owner,
    Writer,
    Reader,
}

pub enum VaultAction {
    Done,
    Sync {
        service: VaultService,
        peer: DeviceId,
        address: String,
    },
    Serve {
        service: VaultService,
        listen: String,
        peer: Option<DeviceId>,
    },
}

pub struct VaultCliContext<'a> {
    pub config: &'a Path,
    pub password_file: Option<&'a Path>,
    pub json: bool,
    pub yes: bool,
    pub local_device_id: DeviceId,
}

pub fn execute_device_key(args: DeviceKeyArgs, context: VaultCliContext<'_>) -> Result<()> {
    let store = DeviceIdentityStore::new(context.config);
    match args.command {
        DeviceKeyCommand::Generate => {
            let password = read_password(context.password_file, true)?;
            let public = store.generate(context.local_device_id, &password)?;
            output(serde_json::to_value(public)?, context.json)
        }
        DeviceKeyCommand::Show => output(serde_json::to_value(store.show()?)?, context.json),
        DeviceKeyCommand::Request { output: path, ttl } => {
            let password = read_password(context.password_file, false)?;
            let identity = store.unlock(&password)?;
            let request = identity.create_request(unix_timestamp()?, ttl)?;
            write_private_json(&path, &request)?;
            output(
                json!({ "request_id": request.request_id, "output": path }),
                context.json,
            )
        }
    }
}

pub fn execute(args: VaultArgs, context: VaultCliContext<'_>) -> Result<VaultAction> {
    match args.command {
        VaultCommand::Info if args.name.is_none() => {
            output(
                json!({
                    "device_id": context.local_device_id,
                    "protocol": "st-vault/1",
                }),
                context.json,
            )?;
            Ok(VaultAction::Done)
        }
        VaultCommand::List => {
            require_no_name(args.name.as_deref(), "list")?;
            let entries = VaultRegistry::new(context.config).list_vaults()?;
            if context.json {
                print_json(&entries)?;
            } else if entries.is_empty() {
                println!("No vaults configured.");
            } else {
                for entry in entries {
                    println!("{}\t{}", entry.name, entry.vault_id);
                }
            }
            Ok(VaultAction::Done)
        }
        VaultCommand::Create { name } => {
            require_no_name(args.name.as_deref(), "create")?;
            let password = read_password(context.password_file, true)?;
            let unlocked = VaultRegistry::new(context.config).create_vault(
                &name,
                &VaultPassword::new(password.to_vec()),
                context.local_device_id,
            )?;
            if context.json {
                print_json(&json!({
                    "name": unlocked.entry().name,
                    "vault_id": unlocked.entry().vault_id,
                    "local_member_id": unlocked.entry().local_member_id,
                }))?;
            } else {
                println!("Created vault '{}' ({})", name, unlocked.entry().vault_id);
            }
            Ok(VaultAction::Done)
        }
        VaultCommand::Import {
            enrollment_file,
            name,
        } => {
            require_no_name(args.name.as_deref(), "import")?;
            let bundle: EnrollmentBundle = read_json(&enrollment_file)?;
            let password = read_password(context.password_file, false)?;
            let identity = DeviceIdentityStore::new(context.config).unlock(&password)?;
            let import_name = name.unwrap_or_else(|| bundle.vault_name.clone());
            let imported = VaultRegistry::new(context.config).import_enrollment(
                &import_name,
                &VaultPassword::new(password.to_vec()),
                &identity,
                &bundle,
                unix_timestamp()?,
            )?;
            output(
                json!({
                    "name": imported.entry().name,
                    "vault_id": imported.entry().vault_id,
                    "local_member_id": imported.entry().local_member_id,
                    "owner": bundle.owner_device_id,
                }),
                context.json,
            )?;
            Ok(VaultAction::Done)
        }
        command => {
            let name = args
                .name
                .as_deref()
                .context("this command requires a vault name")?;
            execute_for_vault(name, command, context)
        }
    }
}

fn execute_for_vault(
    name: &str,
    command: VaultCommand,
    context: VaultCliContext<'_>,
) -> Result<VaultAction> {
    if matches!(command, VaultCommand::Info) {
        let opened = VaultRegistry::new(context.config).open_vault(name)?;
        let metadata = opened.metadata();
        let value = json!({
            "name": opened.entry().name,
            "vault_id": metadata.vault_id,
            "protocol_version": metadata.protocol_version,
            "members": metadata.members.iter().map(member_view).collect::<Vec<_>>(),
            "peers": opened.entry().peers,
        });
        return output(value, context.json).map(|()| VaultAction::Done);
    }

    let mut service = unlock_service(context.config, name, context.password_file)?;
    match command {
        VaultCommand::Devices => {
            let members = service.members().map(member_view).collect::<Vec<_>>();
            output(json!(members), context.json)?;
        }
        VaultCommand::AddDevice(args) => {
            let member = VaultMember {
                member_id: args.member_id.unwrap_or_else(Uuid::new_v4),
                device_id: args.device_id,
                public_key: args.public_key,
                encrypted_vault_key: args.encrypted_vault_key,
                role: args.role.into(),
                created_at: unix_timestamp()?,
                revoked_at: None,
            };
            let change = service.add_member(member)?;
            output(
                json!({ "change_id": change.change_id, "member_id": change.member_id }),
                context.json,
            )?;
        }
        VaultCommand::RevokeDevice { device_id } => {
            confirm(context.yes, &format!("Revoke device {device_id}?"))?;
            let change = service.revoke_device(device_id, unix_timestamp()?)?;
            output(
                json!({ "change_id": change.change_id, "member_id": change.member_id }),
                context.json,
            )?;
        }
        VaultCommand::Enrollment { command } => match command {
            EnrollmentCommand::Prepare {
                request,
                role,
                owner_address,
                output: path,
                ttl,
            } => {
                let request: EnrollmentRequest = read_json(&request)?;
                let bundle = service.prepare_enrollment(
                    &request,
                    role.into(),
                    owner_address,
                    unix_timestamp()?,
                    ttl,
                )?;
                write_private_json(&path, &bundle)?;
                output(
                    json!({
                        "enrollment_id": bundle.enrollment_id,
                        "recipient": bundle.recipient.device_id,
                        "output": path,
                    }),
                    context.json,
                )?;
            }
        },
        VaultCommand::Record { command } => execute_record(&mut service, command, context)?,
        VaultCommand::History { record } => {
            let events = match record {
                Some(reference) => {
                    let id = match parse_record_reference(&reference) {
                        RecordReference::Id(record_id) => service
                            .get_record_including_tombstone(record_id)?
                            .map(|record| record.id)
                            .context("record not found")?,
                        name @ RecordReference::Name(_) => service.resolve_record(&name)?,
                    };
                    service.history().history(id)
                }
                None => service.history().events().collect(),
            };
            output(json!(events), context.json)?;
        }
        VaultCommand::Conflicts { command } => execute_conflict(&mut service, command, context)?,
        VaultCommand::Sync(args) => {
            let (peer, address) = resolve_peer(&service, args.peer, args.addr)?;
            return Ok(VaultAction::Sync {
                service,
                peer,
                address,
            });
        }
        VaultCommand::Serve(args) => {
            return Ok(VaultAction::Serve {
                service,
                listen: args.listen,
                peer: args.peer,
            });
        }
        VaultCommand::Info
        | VaultCommand::List
        | VaultCommand::Create { .. }
        | VaultCommand::Import { .. } => {
            bail!("invalid vault command placement")
        }
    }
    Ok(VaultAction::Done)
}

fn execute_record(
    service: &mut VaultService,
    command: RecordCommand,
    context: VaultCliContext<'_>,
) -> Result<()> {
    match command {
        RecordCommand::List => {
            let records = service.list_documents()?;
            output(
                json!(records.iter().map(document_view).collect::<Vec<_>>()),
                context.json,
            )
        }
        RecordCommand::Create {
            record_type,
            name,
            value,
            fields,
        } => {
            let mut document = RecordDocument::new(record_type.into(), name);
            document.value = value;
            document.fields = parse_fields(fields)?;
            let record_id = service.create_document(document)?;
            output(json!({ "record_id": record_id }), context.json)
        }
        RecordCommand::Get { record } => {
            let document = service
                .get_document(&parse_record_reference(&record))?
                .context("record not found")?;
            output(document_view(&document), context.json)
        }
        RecordCommand::Update {
            record,
            value,
            fields,
        } => {
            if value.is_none() && fields.is_empty() {
                bail!("record update requires a value or at least one --field pair");
            }
            let reference = parse_record_reference(&record);
            let mut current = service
                .get_document(&reference)?
                .context("record not found")?;
            if let Some(value) = value {
                current.document.value = value;
            }
            current.document.fields.extend(parse_fields(fields)?);
            service.update_document(&reference, current.document)?;
            output(
                json!({ "record_id": current.id, "updated": true }),
                context.json,
            )
        }
        RecordCommand::Edit { record } => {
            let reference = parse_record_reference(&record);
            let current = service
                .get_document(&reference)?
                .context("record not found")?;
            let edited = edit_document(&current.document)?;
            service.update_document(&reference, edited)?;
            output(
                json!({ "record_id": current.id, "updated": true }),
                context.json,
            )
        }
        RecordCommand::Delete { record } => {
            confirm(context.yes, &format!("Delete record '{record}'?"))?;
            let reference = parse_record_reference(&record);
            let record_id = service.resolve_record(&reference)?;
            service.delete_document(&reference)?;
            output(
                json!({ "record_id": record_id, "deleted": true }),
                context.json,
            )
        }
        RecordCommand::Restore { record_id } => {
            service.restore_document(record_id)?;
            output(
                json!({ "record_id": record_id, "restored": true }),
                context.json,
            )
        }
    }
}

fn execute_conflict(
    service: &mut VaultService,
    command: ConflictCommand,
    context: VaultCliContext<'_>,
) -> Result<()> {
    match command {
        ConflictCommand::Show => {
            let conflicts = service.list_conflict_views()?;
            let views = conflicts.iter().map(conflict_view).collect::<Vec<_>>();
            output(json!(views), context.json)
        }
        ConflictCommand::Resolve {
            conflict_id,
            branch,
            merge_value,
            fields,
        } => {
            let resolution = if let Some(event_id) = branch {
                ConflictResolution::SelectBranch(event_id)
            } else {
                let view = service.conflict_view(conflict_id)?;
                let mut document = view
                    .branches
                    .iter()
                    .find_map(|branch| branch.document.clone())
                    .context("conflict has no document branch to merge")?;
                document.value = merge_value.context("merged value is required")?;
                document.fields.extend(parse_fields(fields)?);
                ConflictResolution::Merge(document)
            };
            let event_id = service.resolve_document_conflict(conflict_id, resolution)?;
            output(
                json!({ "conflict_id": conflict_id, "resolution_event_id": event_id }),
                context.json,
            )
        }
    }
}

pub fn read_password(path: Option<&Path>, confirm_password: bool) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(path) = path {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read password file {}", path.display()))?;
        let password = trim_line_endings(bytes);
        if password.is_empty() {
            bail!("password must not be empty");
        }
        return Ok(Zeroizing::new(password));
    }
    if !io::stdin().is_terminal() {
        bail!("interactive password prompt requires a terminal; use --password-file");
    }
    let password = Zeroizing::new(rpassword::prompt_password("Vault password: ")?.into_bytes());
    if password.is_empty() {
        bail!("password must not be empty");
    }
    if confirm_password {
        let confirmation =
            Zeroizing::new(rpassword::prompt_password("Confirm password: ")?.into_bytes());
        if *password != *confirmation {
            bail!("passwords do not match");
        }
    }
    Ok(password)
}

pub fn unlock_service(
    config: &Path,
    vault: &str,
    password_file: Option<&Path>,
) -> Result<VaultService> {
    let password = read_password(password_file, false)?;
    let unlocked = VaultRegistry::new(config)
        .unlock_vault(vault, &VaultPassword::new(password.to_vec()))
        .with_context(|| format!("failed to unlock vault '{vault}'"))?;
    VaultService::from_unlocked(unlocked)
        .with_context(|| format!("failed to initialize vault service for '{vault}'"))
}

fn edit_document(document: &RecordDocument) -> Result<RecordDocument> {
    let mut file = NamedTempFile::new().context("failed to create editor file")?;
    set_private_permissions(file.path())?;
    serde_json::to_writer_pretty(file.as_file_mut(), document)?;
    file.flush()?;
    let editor = std::env::var_os("VISUAL")
        .or_else(|| std::env::var_os("EDITOR"))
        .context("set VISUAL or EDITOR to use record edit")?;
    let editor = editor
        .to_str()
        .context("VISUAL or EDITOR contains invalid Unicode")?;
    let mut command = shell_words::split(editor).context("VISUAL or EDITOR is invalid")?;
    if command.is_empty() {
        bail!("VISUAL or EDITOR must not be empty");
    }
    let executable = command.remove(0);
    let status = ProcessCommand::new(executable)
        .args(command)
        .arg(file.path())
        .status()
        .context("failed to start editor")?;
    if !status.success() {
        bail!("editor exited unsuccessfully");
    }
    let edited = fs::read(file.path())?;
    serde_json::from_slice(&edited).context("editor content is not a valid record document")
}

fn confirm(assume_yes: bool, prompt: &str) -> Result<()> {
    if assume_yes {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        bail!("confirmation requires a terminal; pass --yes to confirm");
    }
    eprint!("{prompt} [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        bail!("operation cancelled");
    }
    Ok(())
}

fn resolve_peer(
    service: &VaultService,
    explicit_peer: Option<DeviceId>,
    explicit_address: Option<String>,
) -> Result<(DeviceId, String)> {
    match (explicit_peer, explicit_address) {
        (Some(peer), Some(address)) => Ok((peer, address)),
        (None, None) => {
            let mut peers = service.peers().iter();
            let peer = peers
                .next()
                .context("no configured peer; pass --peer and --addr")?;
            if peers.next().is_some() {
                bail!("multiple peers are configured; pass --peer and --addr");
            }
            Ok((peer.device_id, peer.address.clone()))
        }
        _ => bail!("--peer and --addr must be supplied together"),
    }
}

fn parse_record_reference(value: &str) -> RecordReference {
    Uuid::parse_str(value)
        .map(RecordReference::Id)
        .unwrap_or_else(|_| RecordReference::Name(value.to_string()))
}

fn parse_fields(values: Vec<String>) -> Result<BTreeMap<String, String>> {
    if !values.len().is_multiple_of(2) {
        bail!("fields must be provided as name/value pairs");
    }
    let mut fields = BTreeMap::new();
    let mut values = values.into_iter();
    while let (Some(name), Some(value)) = (values.next(), values.next()) {
        fields.insert(name, value);
    }
    Ok(fields)
}

fn document_view(record: &vault_core::DocumentRecord) -> serde_json::Value {
    json!({
        "id": record.id,
        "name": record.document.name,
        "record_type": record.document.record_type,
        "value": record.document.value,
        "fields": record.document.fields,
        "deleted": record.deleted,
    })
}

fn conflict_view(conflict: &vault_core::ConflictView) -> serde_json::Value {
    json!({
        "conflict_id": conflict.conflict_id,
        "record_id": conflict.record_id,
        "resolution_event_id": conflict.resolution_event_id,
        "branches": conflict.branches.iter().map(|branch| json!({
            "event_id": branch.event_id,
            "author": branch.author,
            "device_sequence": branch.device_sequence,
            "document": branch.document,
        })).collect::<Vec<_>>(),
    })
}

fn member_view(member: &VaultMember) -> serde_json::Value {
    json!({
        "member_id": member.member_id,
        "device_id": member.device_id,
        "public_key": hex::encode(&member.public_key),
        "role": member.role,
        "created_at": member.created_at,
        "revoked_at": member.revoked_at,
    })
}

fn output(value: serde_json::Value, json_output: bool) -> Result<()> {
    if json_output {
        print_json(&value)
    } else if let Some(array) = value.as_array() {
        if array.is_empty() {
            println!("No results.");
        } else {
            for item in array {
                println!("{}", serde_json::to_string_pretty(item)?);
            }
        }
        Ok(())
    } else {
        println!("{}", serde_json::to_string_pretty(&value)?);
        Ok(())
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("{} is not valid JSON", path.display()))
}

fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".enrollment-{}.tmp", Uuid::new_v4()));
    fs::write(&temporary, serde_json::to_vec_pretty(value)?)?;
    set_private_permissions(&temporary)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(temporary);
        return Err(error.into());
    }
    Ok(())
}

fn require_no_name(name: Option<&str>, command: &str) -> Result<()> {
    if let Some(name) = name {
        bail!("vault {command} does not accept vault name '{name}'");
    }
    Ok(())
}

fn parse_hex_32(value: &str) -> Result<Vec<u8>, String> {
    let bytes = hex::decode(value).map_err(|error| error.to_string())?;
    if bytes.len() != 32 {
        return Err("public key must decode to exactly 32 bytes".to_string());
    }
    Ok(bytes)
}

fn parse_nonempty_hex(value: &str) -> Result<Vec<u8>, String> {
    let bytes = hex::decode(value).map_err(|error| error.to_string())?;
    if bytes.is_empty() {
        return Err("encrypted vault key must not be empty".to_string());
    }
    Ok(bytes)
}

fn trim_line_endings(mut bytes: Vec<u8>) -> Vec<u8> {
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    bytes
}

fn unix_timestamp() -> Result<i64> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    i64::try_from(seconds).context("system time exceeds supported range")
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

impl From<RecordTypeArg> for RecordType {
    fn from(value: RecordTypeArg) -> Self {
        match value {
            RecordTypeArg::Login => Self::Login,
            RecordTypeArg::SecureNote => Self::SecureNote,
            RecordTypeArg::Identity => Self::Identity,
            RecordTypeArg::CreditCard => Self::CreditCard,
            RecordTypeArg::Passkey => Self::Passkey,
            RecordTypeArg::Custom => Self::Custom,
        }
    }
}

impl From<RoleArg> for MemberRole {
    fn from(value: RoleArg) -> Self {
        match value {
            RoleArg::Owner => Self::Owner,
            RoleArg::Writer => Self::Writer,
            RoleArg::Reader => Self::Reader,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tempfile::tempdir;

    use crate::{Cli, Command};

    #[test]
    fn parses_nested_vault_commands_and_global_options() {
        let cli = Cli::try_parse_from([
            "syncthing-custom",
            "--config",
            "/tmp/config",
            "vault",
            "personal",
            "record",
            "update",
            "account",
            "new value",
            "--field",
            "username",
            "alice",
            "--json",
        ])
        .unwrap();
        assert!(cli.json);
        let Command::Vault(args) = cli.command else {
            panic!("expected vault command");
        };
        assert_eq!(args.name.as_deref(), Some("personal"));
        assert!(matches!(
            args.command,
            VaultCommand::Record {
                command: RecordCommand::Update { .. }
            }
        ));
    }

    #[test]
    fn parses_global_and_named_vault_info() {
        for arguments in [
            vec![
                "syncthing-custom",
                "--config",
                "/tmp/config",
                "vault",
                "info",
            ],
            vec![
                "syncthing-custom",
                "--config",
                "/tmp/config",
                "vault",
                "personal",
                "info",
            ],
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            assert!(matches!(cli.command, Command::Vault(_)));
        }
    }

    #[test]
    fn parses_device_key_and_enrollment_commands() {
        let request = Cli::try_parse_from([
            "syncthing-custom",
            "--config",
            "/tmp/config",
            "device-key",
            "request",
            "--output",
            "/tmp/request.json",
        ])
        .unwrap();
        assert!(matches!(request.command, Command::DeviceKey(_)));

        let prepare = Cli::try_parse_from([
            "syncthing-custom",
            "--config",
            "/tmp/config",
            "vault",
            "personal",
            "enrollment",
            "prepare",
            "--request",
            "/tmp/request.json",
            "--role",
            "writer",
            "--owner-address",
            "127.0.0.1:22002",
            "--output",
            "/tmp/enrollment.json",
        ])
        .unwrap();
        assert!(matches!(prepare.command, Command::Vault(_)));

        let import = Cli::try_parse_from([
            "syncthing-custom",
            "--config",
            "/tmp/config",
            "vault",
            "import",
            "/tmp/enrollment.json",
            "--name",
            "personal",
        ])
        .unwrap();
        assert!(matches!(import.command, Command::Vault(_)));
    }

    #[test]
    fn password_file_trims_only_line_endings() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("password");
        fs::write(&path, b" leading and trailing \r\n").unwrap();
        let password = read_password(Some(&path), false).unwrap();
        assert_eq!(&*password, b" leading and trailing ");
    }

    #[test]
    fn cli_facade_creates_and_updates_document() {
        let directory = tempdir().unwrap();
        let password_file = directory.path().join("password");
        fs::write(&password_file, b"test-password\n").unwrap();
        let device_id = DeviceId::random();
        let context = || VaultCliContext {
            config: directory.path(),
            password_file: Some(password_file.as_path()),
            json: true,
            yes: true,
            local_device_id: device_id,
        };

        execute(
            VaultArgs {
                name: None,
                command: VaultCommand::Create {
                    name: "personal".to_string(),
                },
            },
            context(),
        )
        .unwrap();
        execute(
            VaultArgs {
                name: Some("personal".to_string()),
                command: VaultCommand::Record {
                    command: RecordCommand::Create {
                        record_type: RecordTypeArg::Login,
                        name: "account".to_string(),
                        value: "secret".to_string(),
                        fields: vec!["username".to_string(), "alice".to_string()],
                    },
                },
            },
            context(),
        )
        .unwrap();
        execute(
            VaultArgs {
                name: Some("personal".to_string()),
                command: VaultCommand::Record {
                    command: RecordCommand::Update {
                        record: "account".to_string(),
                        value: Some("new-secret".to_string()),
                        fields: vec!["username".to_string(), "bob".to_string()],
                    },
                },
            },
            context(),
        )
        .unwrap();

        let service = unlock_service(directory.path(), "personal", Some(&password_file)).unwrap();
        let record = service
            .get_document(&RecordReference::Name("account".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(record.document.value, "new-secret");
        assert_eq!(record.document.fields["username"], "bob");
    }

    #[test]
    fn cli_facade_provisions_and_imports_vault() {
        let owner = tempdir().unwrap();
        let recipient = tempdir().unwrap();
        let owner_password = owner.path().join("password");
        let recipient_password = recipient.path().join("password");
        fs::write(&owner_password, b"owner-password").unwrap();
        fs::write(&recipient_password, b"recipient-password").unwrap();
        let owner_device = DeviceId::random();
        let recipient_device = DeviceId::random();
        let request_path = recipient.path().join("request.json");
        let enrollment_path = recipient.path().join("enrollment.json");

        execute(
            VaultArgs {
                name: None,
                command: VaultCommand::Create {
                    name: "shared".to_string(),
                },
            },
            VaultCliContext {
                config: owner.path(),
                password_file: Some(&owner_password),
                json: true,
                yes: true,
                local_device_id: owner_device,
            },
        )
        .unwrap();
        execute_device_key(
            DeviceKeyArgs {
                command: DeviceKeyCommand::Generate,
            },
            VaultCliContext {
                config: recipient.path(),
                password_file: Some(&recipient_password),
                json: true,
                yes: true,
                local_device_id: recipient_device,
            },
        )
        .unwrap();
        execute_device_key(
            DeviceKeyArgs {
                command: DeviceKeyCommand::Request {
                    output: request_path.clone(),
                    ttl: 300,
                },
            },
            VaultCliContext {
                config: recipient.path(),
                password_file: Some(&recipient_password),
                json: true,
                yes: true,
                local_device_id: recipient_device,
            },
        )
        .unwrap();
        execute(
            VaultArgs {
                name: Some("shared".to_string()),
                command: VaultCommand::Enrollment {
                    command: EnrollmentCommand::Prepare {
                        request: request_path,
                        role: RoleArg::Writer,
                        owner_address: "127.0.0.1:22002".to_string(),
                        output: enrollment_path.clone(),
                        ttl: 300,
                    },
                },
            },
            VaultCliContext {
                config: owner.path(),
                password_file: Some(&owner_password),
                json: true,
                yes: true,
                local_device_id: owner_device,
            },
        )
        .unwrap();
        execute(
            VaultArgs {
                name: None,
                command: VaultCommand::Import {
                    enrollment_file: enrollment_path,
                    name: Some("shared-copy".to_string()),
                },
            },
            VaultCliContext {
                config: recipient.path(),
                password_file: Some(&recipient_password),
                json: true,
                yes: true,
                local_device_id: recipient_device,
            },
        )
        .unwrap();

        let imported = VaultRegistry::new(recipient.path())
            .unlock_vault(
                "shared-copy",
                &VaultPassword::new(b"recipient-password".to_vec()),
            )
            .unwrap();
        assert_eq!(imported.entry().peers[0].device_id, owner_device);
        assert_eq!(
            imported.signing_key().verifying_key().to_bytes().as_slice(),
            DeviceIdentityStore::new(recipient.path())
                .show()
                .unwrap()
                .signing_public_key
        );
    }

    #[test]
    fn rejects_partial_sync_target_and_empty_update() {
        let directory = tempdir().unwrap();
        let password_file = directory.path().join("password");
        fs::write(&password_file, b"test-password").unwrap();
        let device_id = DeviceId::random();
        let registry = VaultRegistry::new(directory.path());
        let unlocked = registry
            .create_vault(
                "personal",
                &VaultPassword::new(b"test-password".to_vec()),
                device_id,
            )
            .unwrap();
        let service = VaultService::from_unlocked(unlocked).unwrap();
        assert!(resolve_peer(&service, Some(DeviceId::random()), None).is_err());
        assert!(parse_fields(vec!["name".to_string()]).is_err());
    }
}
