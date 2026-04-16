use clap::{Subcommand, Args, ValueEnum};
use std::fs;
use std::fs::{File, metadata};
use std::io::Write;
use std::fmt::Debug;
use std::time::SystemTime;
use std::path::{Path, PathBuf};
use reqwest;
use serde::{Serialize, Deserialize, Deserializer};
use secrecy::{SecretString, ExposeSecret};
use anyhow::{anyhow, bail, Context};
use chrono::{Utc, Local, Duration, DateTime};
use humantime::format_duration;
use chrono_humanize::HumanTime;
use comfy_table::Table;
use comfy_table::presets::{UTF8_FULL, NOTHING};
use comfy_table::modifiers::{UTF8_ROUND_CORNERS, UTF8_SOLID_INNER_BORDERS};
use log::{info, debug, trace};

use crate::config::Config;
use crate::oidc::get_access_token;
use crate::completion::{CompletionArgs, generate_completion};
use crate::http;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Download a new SSH key pair
    ///
    /// This command downloads a new SSH key pair from the SSH service.
    /// The private key will be saved to the path specified in the config or -f/--file.
    /// Default private key path is ~/.ssh/cscs-key.
    /// The public key certificate will be saved the same path with '-cert.pub' suffix.
    Gen(GenArgs),
    /// Sign an existing SSH public key
    ///
    /// This command reads an existing SSH public key from the path specified in the config
    /// or -f/--file with '.pub' suffix, sends it to the SSH service for signing, and saves the signed
    /// certificate to the same path with '-cert.pub' suffix.
    /// Default private key path is ~/.ssh/cscs-key.
    Sign(SignArgs),
    /// Print status of generated keys
    #[clap(hide = true)]
    Status,
    /// List all SSH keys associated with the user
    List(ListArgs),
    /// Revoke keys associated with the user
    Revoke(RevokeArgs),
    /// Generate shell completion script
    Completion(CompletionArgs),
}

#[derive(Args, Debug)]
pub struct GenArgs {
    #[arg(short, long, help = "Path to save the private SSH key. Default is ~/.ssh/cscs-key")]
    pub file: Option<PathBuf>,
    #[arg(short, long, help = "Validity duration for the SSH key: '1d' (default) or '1min'")]
    pub duration: Option<KeyDuration>,
    #[arg(short, long, help = "Overwrite existing private key without asking")]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct SignArgs {
    #[arg(short, long, help = "Path to save the private SSH key. Default is ~/.ssh/cscs-key")]
    pub file: Option<PathBuf>,
    #[arg(short, long, help = "Validity duration for the SSH key: '1d' (default) or '1min'")]
    pub duration: Option<KeyDuration>,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    #[arg(short, long, help = "List all SSH keys, including expired and revoked ones")]
    pub all: bool,
}

#[derive(Args, Debug)]
pub struct RevokeArgs {
    #[arg(num_args = 1.., help = "Serial numbers of the SSH key certificates to revoke, \"all\" revokes all keys")]
    pub key_id: Vec<String>,
    #[arg(short, long, help = "Revoke all SSH keys")]
    pub all: bool,
    #[arg(long, help = "Dry run: print which keys would be revoked without actually revoking them")]
    pub dry: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, ValueEnum)]
pub enum KeyDuration {
    #[default]
    #[serde(rename = "1d")]
    #[clap(name = "1d")]
    Day,
    #[serde(rename = "1min")]
    #[clap(name = "1min")]
    Minute,
}

impl Into<Duration> for KeyDuration {
    fn into(self) -> Duration {
        match self {
            KeyDuration::Day => Duration::days(1),
            KeyDuration::Minute => Duration::minutes(1),
        }
    }
}

#[derive(Debug, Serialize)]
struct SshKeyDuration {
    duration: KeyDuration,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicKey {
    public_key: String,
    duration: KeyDuration,
}

#[derive(Debug, Serialize)]
struct ListKeys {
    include_revoked: bool,
    include_expired: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RevokeKey {
    serial_number: String,
    reason: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshKey {
    #[serde(deserialize_with = "ensure_newline_string")]
    public_key: String,
    #[serde(deserialize_with = "ensure_newline_secretstring")]
    private_key: SecretString,
    expire_time: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshserviceSuccessResponse {
    ssh_key: SshKey,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshKeyCert {
    #[serde(deserialize_with = "ensure_newline_string")]
    public_key: String,
    expire_time: DateTime<Utc>,
    serial_number: String,
    revocation_time: Option<DateTime<Utc>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshserviceSuccessResponseCert {
    ssh_key: SshKeyCert,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshserviceErrorResponse {
    message: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshserviceSuccessResponseCerts {
    ssh_keys: Vec<SshKeyCert>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshserviceSuccessResponseRevoke {
    revoked: bool,
    message: String,
}

// Ensure downloaded ssh keys end with \n
fn ensure_newline(mut s: String) -> String {
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

fn ensure_newline_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    Ok(ensure_newline(s))
}

fn ensure_newline_secretstring<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    Ok(SecretString::from(ensure_newline(s)))
}

fn redact_private_key(s: &str) -> String {
    let re = regex::Regex::new(r"(?s)(-----BEGIN [A-Z ]+PRIVATE KEY-----).*?(-----END [A-Z ]+PRIVATE KEY-----)").unwrap();
    re.replace_all(s, "[REDACTED PRIVATE KEY]").to_string()
}

pub fn run(command: &Commands, config: &Config) -> anyhow::Result<()> {
    trace!("{} entrypoint", env!("CARGO_PKG_NAME"));
    trace!("{:?}", config);
    match command {
        Commands::Gen(args) => download_key(&config, args)?,
        Commands::Sign(args) => sign_key(&config, args)?,
        Commands::Status => status_key(&config)?,
        Commands::List(args) => list_keys(&config, args)?,
        Commands::Revoke(args) => revoke_keys(&config, args)?,
        Commands::Completion(args) => generate_completion(args)?,
    }

    Ok(())
}

fn verify_key_pair(private_key_path: &Path, public_key_path: &Path) -> anyhow::Result<()> {
    if !private_key_path.exists() {
        bail!(
            "Private key not found at {}.\nGenerate a new key pair with: ssh-keygen -t ed25519 -f {}",
            private_key_path.display(),
            private_key_path.display()
        );
    }

    if !public_key_path.exists() {
        bail!(
            "Public key not found at {}.\n\
            This key was likely generated server-side (via 'cscs-key gen' or the older SSH service tool) and should be replaced with a locally generated key pair.\n\
            Generate a new key pair with: ssh-keygen -t ed25519 -f {}",
            public_key_path.display(),
            private_key_path.display()
        );
    }

    let private_key = ssh_key::PrivateKey::read_openssh_file(private_key_path)
        .with_context(|| format!("Failed to read private key at {}", private_key_path.display()))?;
    let public_key_content = fs::read_to_string(public_key_path)
        .with_context(|| format!("Failed to read public key at {}", public_key_path.display()))?;
    let public_key = ssh_key::PublicKey::from_openssh(&public_key_content)
        .with_context(|| format!("Failed to parse public key at {}", public_key_path.display()))?;

    if private_key.fingerprint(ssh_key::HashAlg::Sha256) != public_key.fingerprint(ssh_key::HashAlg::Sha256) {
        bail!(
            "Public key at {} does not match private key at {}.\n\
            Generate a new key pair with: ssh-keygen -t ed25519 -f {}",
            public_key_path.display(),
            private_key_path.display(),
            private_key_path.display()
        );
    }

    Ok(())
}

fn download_key(config: &Config, args: &GenArgs) -> anyhow::Result<()> {
    trace!("gen subcommand");
    trace!("{:?}", args);

    let key_duration = SshKeyDuration {
        duration: args.duration.unwrap_or(config.key_validity),
    };

    let access_token = get_access_token(&config)?;

    let client = reqwest::blocking::Client::builder()
        .user_agent(http::user_agent())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to initialize HTTP client.")?;

    let response = client.post(config.env.keys_url.clone())
        .bearer_auth(&access_token)
        .json(&key_duration)
        .send()
        .context("Failed to send request to the ssh service.")?;

    let status = response.status();
    let response_bytes = response.bytes()?;

    if !status.is_success() {
        let error_response_struct: SshserviceErrorResponse = serde_json::from_slice(&response_bytes)?;
        bail!("{}", error_response_struct.message);
    }

    let response_struct: SshserviceSuccessResponse = serde_json::from_slice(&response_bytes)
        .with_context(||
            format!(
                "Failed to parse the respons form SSH service. Response body: {:?}",
                redact_private_key(
                    &String::from_utf8_lossy(&response_bytes)
                )
            )
        )?;
    trace!("Parsed SSH service response: {:?}", response_struct);

    //let private_key_path = args.file.clone();
    let private_key_path = args.file.clone().unwrap_or(config.key_path.clone());
    let public_key_path = PathBuf::from(format!("{}-cert.pub", private_key_path.display()));

    if let Some(parent) = private_key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // if we're overwriting an existing private file, we should probably ask the user
    if private_key_path.exists() && !args.yes {
        use dialoguer::Confirm;
        let confirm = Confirm::new()
            .with_prompt(format!("Private key already exists at {}. Overwrite?", private_key_path.display()))
            .default(false)
            .interact()?;
        if !confirm {
            bail!("Operation cancelled by user.");
        }
    }

    // Save public key
    let mut public_file = File::create(&public_key_path)?;
    debug!("Saving public key in {}", public_key_path.display());
    public_file.write_all(response_struct.ssh_key.public_key.as_bytes())?;
    #[cfg(unix)] // Only apply on Unix-like systems
    {
        debug!("Setting permissions for public key to 0o644: {}", public_key_path.display());
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = public_file.metadata()?.permissions();
        permissions.set_mode(0o644); // Read/write for owner only
        std::fs::set_permissions(&public_key_path, permissions)?;
    }
    info!("Public SSH key successfully downloaded to {}", public_key_path.display());

    // Save private key with restricted permissions from creation
    debug!("Saving private key in {}", private_key_path.display());
    #[cfg(unix)]
    let mut private_file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&private_key_path)?
    };
    #[cfg(not(unix))]
    let mut private_file = File::create(&private_key_path)?;
    private_file.write_all(response_struct.ssh_key.private_key.expose_secret().as_bytes())?;
    info!("Private SSH key successfully downloaded to: {}", private_key_path.display());

    Ok(())
}

fn sign_key(config: &Config, args: &SignArgs) -> anyhow::Result<()> {
    trace!("sign subcommand");
    trace!("{:?}", args);

    let private_key_path = args.file.clone().unwrap_or(config.key_path.clone());
    let public_key_path = PathBuf::from(format!("{}.pub", private_key_path.display()));

    verify_key_pair(&private_key_path, &public_key_path)?;

    debug!("Reading public key in {}", public_key_path.display());
    let content = fs::read_to_string(public_key_path)?;

    let public_key = PublicKey {
        public_key: content,
        duration: args.duration.unwrap_or(config.key_validity),
    };
    trace!("public_key: {:?}", serde_json::to_string(&public_key)?);

    let access_token = get_access_token(&config)?;

    let client = reqwest::blocking::Client::builder()
        .user_agent(http::user_agent())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to initialize HTTP client.")?;

    let response = client.post(config.env.sign_url.clone())
        .bearer_auth(&access_token)
        .json(&public_key)
        .send()
        .context("Failed to send request to the ssh service.")?;

    let status = response.status();
    let response_bytes = response.bytes()?;

    if !status.is_success() {
        let error_response_struct: SshserviceErrorResponse = serde_json::from_slice(&response_bytes)?;
        bail!("{}", error_response_struct.message);
    }

    let response_struct: SshserviceSuccessResponseCert = serde_json::from_slice(&response_bytes)
        .with_context(||
            format!(
                "Failed to parse the respons form SSH service. Response body: {:?}",
                String::from_utf8_lossy(&response_bytes)
            ))?;
    trace!("Parsed SSH service response: {:?}", response_struct);

    let private_key_path = args.file.clone().unwrap_or(config.key_path.clone());
    let public_key_path = PathBuf::from(format!("{}-cert.pub", private_key_path.display()));

    if let Some(parent) = private_key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Save public key
    let mut public_file = File::create(&public_key_path)?;
    debug!("Saving public key in {}", public_key_path.display());
    public_file.write_all(response_struct.ssh_key.public_key.as_bytes())?;
    #[cfg(unix)] // Only apply on Unix-like systems
    {
        debug!("Setting permissions for public key to 0o644: {}", public_key_path.display());
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = public_file.metadata()?.permissions();
        permissions.set_mode(0o644); // Read/write for owner only
        std::fs::set_permissions(&public_key_path, permissions)?;
    }
    info!("Public SSH certificate successfully downloaded to {}", public_key_path.display());

    Ok(())
}

fn status_key(config: &Config) -> anyhow::Result<()> {
    trace!("status subcommand");

    let metadata_result = metadata(&config.key_path);
    let file_metadata = match metadata_result {
        Ok(meta) => {
            if meta.is_file() {
                debug!("SSH key file found at: {}", &config.key_path.display());
                meta
            } else {
                bail!("Path '{}' exists but is not a file (it's a directory or other type).", &config.key_path.display());
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("SSH key file not found at: {}. Please run 'ssh-key download'.", &config.key_path.display());
        },
        Err(e) => {
            bail!("Error accessing SSH key file at {}: {}", &config.key_path.display(), e);
        }
    };

    trace!("{:?}", file_metadata);
    let modified_time = file_metadata.modified()?;
    let now = SystemTime::now();
    let duration_since_modified = now.duration_since(modified_time)
        .map_err(|e| anyhow!("System time is earlier than file modification time: {}", e))?;

    let validity: Duration = config.key_validity.into();

    if duration_since_modified > validity.to_std().unwrap() {
        info!("SSH key is EXPIRED (last modified {} ago).",
            format_duration(duration_since_modified));
        bail!("SSH key is expired. Please run 'ssh-key download' to renew.");
    } else {
        info!("SSH key is VALID (last modified {} ago).",
            format_duration(duration_since_modified));
    }

    Ok(())
}

fn list_keys(config: &Config, args: &ListArgs) -> anyhow::Result<()> {
    trace!("list subcommand");
    trace!("{:?}", args);

    let ssh_keys = list_keys_internal(&config, args.all)?;

    let mut table = Table::new();
    if table.is_tty() {
        table.load_preset(UTF8_FULL);
        table.apply_modifier(UTF8_ROUND_CORNERS);
        table.apply_modifier(UTF8_SOLID_INNER_BORDERS);
    } else {
        table.load_preset(NOTHING);
    }
    table.set_header(vec!["Serial Number", "Valid", "Expiration", "Expire Time"]);
    for key in ssh_keys {
        let valid = if key.revocation_time.is_some() {
            "❌ REVOKED"
        } else if key.expire_time < Utc::now() {
            "❌ EXPIRED"
        } else {
            "✅ VALID"
        };
        let expiration = key.expire_time.clone() - Utc::now();

        table.add_row(vec![key.serial_number, valid.to_string(), HumanTime::from(expiration).to_string(), key.expire_time.with_timezone(&Local).to_string()]);
    }
    println!("{table}");

    Ok(())
}

fn revoke_keys(config: &Config, args: &RevokeArgs) -> anyhow::Result<()> {
    trace!("revoke subcommand");
    trace!("{:?}", args);

    if args.all || (args.key_id.len() == 1 && args.key_id[0].to_lowercase() == "all") {
        let ssh_keys = list_keys_internal(&config, false)?;
        for key in ssh_keys {
            revoke_key(&config, key.serial_number, args.dry)?;
        }
    } else {
        for key in &args.key_id {
            revoke_key(&config, key.to_string(), args.dry)?;
        }
    }

    Ok(())
}

fn list_keys_internal(config: &Config, all: bool) -> anyhow::Result<Vec<SshKeyCert>> {
    let list_keys = ListKeys {
        include_revoked: all,
        include_expired: all,
    };
    trace!("{:?}", list_keys);

    let access_token = get_access_token(&config)?;

    let client = reqwest::blocking::Client::builder()
        .user_agent(http::user_agent())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to initialize HTTP client.")?;

    let response = client.get(config.env.keys_url.clone())
        .bearer_auth(&access_token)
        .query(&list_keys)
        .send()
        .context("Failed to send request to the ssh service.")?;

    let status = response.status();
    let response_bytes = response.bytes()?;

    if !status.is_success() {
        let error_response_struct: SshserviceErrorResponse = serde_json::from_slice(&response_bytes)?;
        bail!("{}", error_response_struct.message);
    }

    let response_struct: SshserviceSuccessResponseCerts = serde_json::from_slice(&response_bytes)
        .with_context(||
            format!(
                "Failed to parse the respons form SSH service. Response body: {:?}",
                String::from_utf8_lossy(&response_bytes)
            ))?;

    Ok(response_struct.ssh_keys)
}

fn revoke_key(config: &Config, key_id: String, dry: bool) -> anyhow::Result<()> {
    if dry {
        info!("Dry run: Would revoke key {}", key_id);
        return Ok(());
    }

    let revoke_key = RevokeKey {
        serial_number: key_id.to_string(),
        reason: "user request".to_string(),
    };
    trace!("{:?}", revoke_key);

    let access_token = get_access_token(&config)?;

    let client = reqwest::blocking::Client::builder()
        .user_agent(http::user_agent())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to initialize HTTP client.")?;

    let response = client.put(config.env.revoke_url.clone())
        .bearer_auth(&access_token)
        .json(&revoke_key)
        .send()
        .context("Failed to send request to the ssh service.")?;

    let status = response.status();
    let response_bytes = response.bytes()?;

    if !status.is_success() {
        let error_response_struct: SshserviceErrorResponse = serde_json::from_slice(&response_bytes)?;
        bail!("{}", error_response_struct.message);
    }

    let response_struct: SshserviceSuccessResponseRevoke = serde_json::from_slice(&response_bytes)
        .with_context(||
            format!(
                "Failed to parse the respons form SSH service. Response body: {:?}",
                String::from_utf8_lossy(&response_bytes)
            ))?;
    trace!("Parsed SSH service response: {:?}", response_struct);

    let revoked = if response_struct.revoked {
        "✅"
    } else {
        "❌"
    };

    info!("{}: {} {}", key_id, revoked, response_struct.message);

    Ok(())
}
