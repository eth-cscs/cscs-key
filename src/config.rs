use anyhow::Context;
use clap::{Parser, ValueEnum};
use directories::ProjectDirs;
use figment::{
    Figment,
    providers::{Format, Serialized, Toml},
};
use log::trace;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::ssh::KeyDuration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvConfig {
    pub name: String,
    pub pkce_client_id: String,
    pub issuer_url: String,
    pub token_url: String,
    pub keys_url: String,
    pub sign_url: String,
    pub revoke_url: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    #[default]
    Prod,
    Tds,
}

impl Environment {
    pub fn to_config(self) -> EnvConfig {
        match self {
            Self::Prod => EnvConfig {
                name: "prod".to_string(),
                pkce_client_id: "authx-cli".to_string(),
                issuer_url: "https://auth.cscs.ch/auth/realms/cscs".to_string(),
                token_url:
                    "https://authx-gateway.svc.cscs.ch/api-service-account/api/v1/auth/token"
                        .to_string(),
                keys_url: "https://authx-gateway.svc.cscs.ch/api-ssh-service/api/v1/ssh-keys"
                    .to_string(),
                sign_url: "https://authx-gateway.svc.cscs.ch/api-ssh-service/api/v1/ssh-keys/sign"
                    .to_string(),
                revoke_url:
                    "https://authx-gateway.svc.cscs.ch/api-ssh-service/api/v1/ssh-keys/revoke"
                        .to_string(),
            },
            Self::Tds => EnvConfig {
                name: "tds".to_string(),
                pkce_client_id: "authx-cli".to_string(),
                issuer_url: "https://auth-tds.cscs.ch/auth/realms/cscs".to_string(),
                token_url:
                    "https://authx-gateway.tds.cscs.ch/api-service-account/api/v1/auth/token"
                        .to_string(),
                keys_url: "https://authx-gateway.tds.cscs.ch/api-ssh-service/api/v1/ssh-keys"
                    .to_string(),
                sign_url: "https://authx-gateway.tds.cscs.ch/api-ssh-service/api/v1/ssh-keys/sign"
                    .to_string(),
                revoke_url:
                    "https://authx-gateway.tds.cscs.ch/api-ssh-service/api/v1/ssh-keys/revoke"
                        .to_string(),
            },
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RawConfig {
    pub key_path: PathBuf,
    pub key_validity: KeyDuration,
    #[serde(default)]
    pub headless: bool,
    #[serde(default)]
    pub env: Environment,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub key_path: PathBuf,
    pub key_validity: KeyDuration,
    pub headless: bool,
    pub env: EnvConfig,
}

impl Config {
    pub fn load(
        cli_env: Option<Environment>,
        cli_overrides: &ConfigCliOverride,
    ) -> anyhow::Result<Self> {
        trace!("Loading app configuration");

        let proj_dirs = ProjectDirs::from("ch", "cscs", "cscs-key")
            .context("Could not determine configuration directory")?;
        let config_dir = proj_dirs.config_dir();
        let config_file_path = config_dir.join("config.toml");

        #[cfg(unix)]
        if config_file_path.exists() {
            use std::os::unix::fs::MetadataExt;
            let mode = std::fs::metadata(&config_file_path)?.mode();
            if mode & 0o022 != 0 {
                anyhow::bail!(
                    "Config file {} is writable by group or others (mode {:04o}). \
                     Fix with: chmod go-w {}",
                    config_file_path.display(),
                    mode & 0o777,
                    config_file_path.display()
                );
            }
        }

        trace!(
            "Config priorities:
    1. cli args
    2. config file {}
    3. default values",
            config_file_path.display()
        );

        let raw_config: RawConfig = Figment::new()
            .merge(Serialized::defaults(RawConfig::default()))
            .merge(Toml::file(config_file_path))
            .merge(Serialized::defaults(cli_overrides))
            .extract()?;

        let active_env = cli_env.unwrap_or(raw_config.env);
        trace!("Using environment: {}", active_env.to_config().name);

        Ok(Self {
            key_path: raw_config.key_path,
            key_validity: raw_config.key_validity,
            headless: raw_config.headless,
            env: active_env.to_config(),
        })
    }
}

#[derive(Parser, Debug, Deserialize, Serialize)]
pub struct ConfigCliOverride {
    #[arg(long, global = true, hide = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<PathBuf>,
    #[arg(long, global = true, hide = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_validity: Option<KeyDuration>,
    #[arg(
        long,
        global = true,
        num_args = 0,
        default_missing_value = "true",
        help = "Use device authorization flow instead of opening a browser"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headless: Option<bool>,
}

impl Default for RawConfig {
    fn default() -> Self {
        Self {
            key_path: dirs::home_dir()
                .expect("Could not determine home directory")
                .join(".ssh")
                .join("cscs-key"),
            key_validity: KeyDuration::Day,
            headless: false,
            env: Environment::default(),
        }
    }
}
