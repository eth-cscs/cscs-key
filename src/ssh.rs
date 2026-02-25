use clap::{Subcommand, Args, ValueEnum};
use std::fs;
use std::fs::{File, metadata};
use std::io::Write;
use std::fmt::Debug;
use std::time::SystemTime;
use std::path::PathBuf;
use reqwest;
use serde::{Serialize, Deserialize, Deserializer};
use anyhow::{anyhow, bail, Context};
use chrono::{Utc, Local, Duration, DateTime};
use humantime::format_duration;
use chrono_humanize::HumanTime;
use comfy_table::Table;
use comfy_table::presets::UTF8_FULL;
use log::{info, debug};

use crate::config::Config;
use crate::oidc::get_access_token;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Download a new SSH key pair
    ///
    /// This command downloads a new SSH key pair from the SSH service.
    /// The private key will be saved to the path specified in the config or -f/--file.
    /// The public key certificate will be saved the same path with '-cert.pub' suffix.
    Gen(GenArgs),
    /// Sign an existing SSH public key
    ///
    /// This command reads an existing SSH public key from the path specified in the config
    /// or -f/--file with'-signing.pub' suffix, sends it to the SSH service for signing, and saves the signed
    /// certificate to the same path with '-signing-cert.pub' suffix.
    Sign(SignArgs),
    /// Print status of generated keys
    Status,
    /// List all SSH keys associated with the user
    List(ListArgs),
    /// Revoke kyes associated with the user
    Revoke(RevokeArgs),
}

#[derive(Args, Debug)]
pub struct GenArgs {
    #[arg(short, long, help = "Path to save the private SSH key. Default is ~/.ssh/cscs-key")]
    pub file: PathBuf,
    #[arg(short, long, help = "Validity duration for the SSH key: '1d' (default) or '1min'")]
    pub duration: KeyDuration,
}

#[derive(Args, Debug)]
pub struct SignArgs {
    #[arg(short, long, help = "Path to save the private SSH key. Default is ~/.ssh/cscs-key")]
    pub file: PathBuf,
    #[arg(short, long, help = "Validity duration for the SSH key: '1d' (default) or '1min'")]
    pub duration: KeyDuration,
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
struct RevokeKey {
    serial_number: String,
    reason: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshKeyNew {
    #[serde(deserialize_with = "ensure_newline")]
    public_key: String,
    #[serde(deserialize_with = "ensure_newline")]
    private_key: String,
    expire_time: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshserviceSuccessResponseNew {
    ssh_key: SshKeyNew,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshKeyCertNew {
    #[serde(deserialize_with = "ensure_newline")]
    public_key: String,
    expire_time: DateTime<Utc>,
    serial_number: String,
    revocation_time: Option<DateTime<Utc>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshserviceSuccessResponseCertNew {
    ssh_key: SshKeyCertNew,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshserviceErrorResponse {
    message: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshserviceSuccessResponseCertsNew {
    ssh_keys: Vec<SshKeyCertNew>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SshserviceSuccessResponseRevoke {
    revoked: bool,
    message: String,
}

// Ensure downloaded ssh keys end with \n
fn ensure_newline<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let mut s = String::deserialize(deserializer)?;

    if !s.ends_with('\n') {
        s.push('\n');
    }

    Ok(s)
}

pub fn run(command: &Commands, config: &Config) -> anyhow::Result<()> {
    debug!{"ssh-key command"};
    match command {
        Commands::Gen(args) => download_key(&config, args)?,
        Commands::Sign(args) => sign_key(&config, args)?,
        Commands::Status => status_key(&config)?,
        Commands::List(args) => list_keys(&config, args)?,
        Commands::Revoke(args) => revoke_keys(&config, args)?,
    }

    Ok(())
}

fn download_key(config: &Config, args: &GenArgs) -> anyhow::Result<()> {
    debug!("ssh-key gen-new subcommand");
    debug!("{:?}", config);

    let key_duration = SshKeyDuration {
        // todo
        duration: args.duration,
    };

    info!("Get OIDC token");

    let access_token = get_access_token(&config)?;

    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to initialize HTTP client.")?;

    let response = client.post(config.env.keys_url.clone())
        .bearer_auth(&access_token)
        .json(&key_duration)
        .send()
        .context("Failed to send request to the ssh service.")?;

    if !response.status().is_success() {
        let error_response_struct: SshserviceErrorResponse = response.json()?;
        bail!("{}", error_response_struct.message);
    }

    let response_struct: SshserviceSuccessResponseNew = response.json()?;

    let private_key_path = args.file.clone();
    let public_key_path = PathBuf::from(format!("{}-cert.pub", private_key_path.display()));

    if let Some(parent) = private_key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Save public key
    let mut public_file = File::create(&public_key_path)?;
    info!("Saving public key in {}", public_key_path.display());
    public_file.write_all(response_struct.ssh_key.public_key.as_bytes())?;
    #[cfg(unix)] // Only apply on Unix-like systems
    {
        info!("Setting permissions for public key to 0o644: {}", public_key_path.display());
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = public_file.metadata()?.permissions();
        permissions.set_mode(0o644); // Read/write for owner only
        std::fs::set_permissions(&public_key_path, permissions)?;
    }
    info!("Public SSH key successfully downloaded to {}", public_key_path.display());

    // Save private key
    let mut private_file = File::create(&private_key_path)?;
    info!("Saving private key in {}", private_key_path.display());
    private_file.write_all(response_struct.ssh_key.private_key.as_bytes())?;
    #[cfg(unix)] // Only apply on Unix-like systems
    {
        info!("Setting permissions for private key to 0o600: {}", private_key_path.display());
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = private_file.metadata()?.permissions();
        permissions.set_mode(0o600); // Read/write for owner only
        std::fs::set_permissions(&private_key_path, permissions)?;
    }
    println!("Private SSH key successfully downloaded to: {}", private_key_path.display());

    Ok(())
}

fn sign_key(config: &Config, args: &SignArgs) -> anyhow::Result<()> {
    debug!("ssh-key gen-new subcommand");
    debug!("{:?}", config);

    let private_key_path = args.file.clone();
    let public_key_path = PathBuf::from(format!("{}-signing.pub", private_key_path.display()));
    info!("Reading public key in {}", public_key_path.display());
    let content = fs::read_to_string(public_key_path)?;

    let public_key = PublicKey {
        public_key: content,
        duration: args.duration,
    };
    debug!("public_key: {:?}", serde_json::to_string(&public_key)?);

    info!("Get OIDC token");

    let access_token = get_access_token(&config)?;

    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to initialize HTTP client.")?;

    let response = client.post(config.env.sign_url.clone())
        .bearer_auth(&access_token)
        .json(&public_key)
        .send()
        .context("Failed to send request to the ssh service.")?;

    if !response.status().is_success() {
        let error_response_struct: SshserviceErrorResponse = response.json()?;
        bail!("{}", error_response_struct.message);
    }

    //debug!("response: {:?}", response);
    //debug!("response.text: {:?}", response.text()?);

    let response_struct: SshserviceSuccessResponseCertNew = response.json()?;
    //let response_struct = response.text()?;
    debug!("{:?}", response_struct);

    let private_key_path = args.file.clone();
    let public_key_path = PathBuf::from(format!("{}-signing-cert.pub", private_key_path.display()));

    if let Some(parent) = private_key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Save public key
    let mut public_file = File::create(&public_key_path)?;
    info!("Saving public key in {}", public_key_path.display());
    public_file.write_all(response_struct.ssh_key.public_key.as_bytes())?;
    #[cfg(unix)] // Only apply on Unix-like systems
    {
        info!("Setting permissions for public key to 0o644: {}", public_key_path.display());
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = public_file.metadata()?.permissions();
        permissions.set_mode(0o644); // Read/write for owner only
        std::fs::set_permissions(&public_key_path, permissions)?;
    }
    info!("Public SSH key successfully downloaded to {}", public_key_path.display());

    Ok(())
}

fn status_key(config: &Config) -> anyhow::Result<()> {
    debug!("ssh-key status subcommand");
    debug!("{:?}", config);

    let metadata_result = metadata(&config.key_path);
    let file_metadata = match metadata_result {
        Ok(meta) => {
            if meta.is_file() {
                info!("SSH key file found at: {}", &config.key_path.display());
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

    debug!("{:?}", file_metadata);
    let modified_time = file_metadata.modified()?;
    let now = SystemTime::now();
    let duration_since_modified = now.duration_since(modified_time)
        .map_err(|e| anyhow!("System time is earlier than file modification time: {}", e))?;

    let validity = duration_str::parse(config.key_validity.clone()).unwrap();

    if duration_since_modified > validity {
        println!("SSH key is EXPIRED (last modified {} ago).",
            format_duration(duration_since_modified));
        bail!("SSH key is expired. Please run 'ssh-key download' to renew.");
    } else {
        println!("SSH key is VALID (last modified {} ago).",
            format_duration(duration_since_modified));
    }

    Ok(())
}

fn list_keys(config: &Config, args: &ListArgs) -> anyhow::Result<()> {
    debug!("ssh-key list subcommand");
    debug!("{:?}", config);
    debug!("{:?}", args);

    let ssh_keys = list_keys_internal(&config, args.all)?;

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
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
    debug!("ssh-key revoke subcommand");
    debug!("{:?}", config);

    if args.key_id.len() == 1 && args.key_id[0].to_lowercase() == "all" {
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

fn list_keys_internal(config: &Config, all: bool) -> anyhow::Result<Vec<SshKeyCertNew>> {
    let list_keys = ListKeys {
        include_revoked: all,
        include_expired: all,
    };
    debug!("{:?}", list_keys);

    let access_token = get_access_token(&config)?;

    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to initialize HTTP client.")?;

    let response = client.get(config.env.keys_url.clone())
        .bearer_auth(&access_token)
        .query(&list_keys)
        .send()
        .context("Failed to send request to the ssh service.")?;

    if !response.status().is_success() {
        let error_response_struct: SshserviceErrorResponse = response.json()?;
        bail!("{}", error_response_struct.message);
    }

    //debug!("response: {:?}", response);
    //debug!("response.text: {:?}", response.text()?);

    let response_struct: SshserviceSuccessResponseCertsNew = response.json()?;
    //let response_struct = response.text()?;
    //debug!("{:?}", response_struct);

    Ok(response_struct.ssh_keys)
}

fn revoke_key(config: &Config, key_id: String, dry: bool) -> anyhow::Result<()> {
    if dry {
        println!("Dry run: Would revoke key {}", key_id);
        return Ok(());
    }

    let revoke_key = RevokeKey {
        serial_number: key_id.to_string(),
        reason: "user request".to_string(),
    };
    debug!("{:?}", revoke_key);

    let access_token = get_access_token(&config)?;

    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to initialize HTTP client.")?;

    let response = client.put(config.env.revoke_url.clone())
        .bearer_auth(&access_token)
        .json(&revoke_key)
        .send()
        .context("Failed to send request to the ssh service.")?;

    if !response.status().is_success() {
        let error_response_struct: SshserviceErrorResponse = response.json()?;
        bail!("{}", error_response_struct.message);
    }

    //debug!("response: {:?}", response);
    //debug!("response.text: {:?}", response.text()?);

    let response_struct: SshserviceSuccessResponseRevoke = response.json()?;
    //debug!("{:?}", response_struct);

    let revoked = if response_struct.revoked {
        "✅"
    } else {
        "❌"
    };

    println!("{}: {} {}", key_id, revoked, response_struct.message);

    Ok(())
}
