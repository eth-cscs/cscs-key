use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use directories::ProjectDirs;
use std::path::PathBuf;
use anyhow::Context;
use figment::{Figment, providers::{Format, Toml, Serialized}};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvConfig {
    pub pkce_client_id: String,
    pub issuer_url: String,
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
    pub fn to_config(&self) -> EnvConfig {
        match self {
            Self::Prod => EnvConfig {
                pkce_client_id: "authx-cli".to_string(),
                issuer_url: "https://auth.cscs.ch/auth/realms/cscs".to_string(),
                keys_url: "https://api-ssh-service.hpc-ssh.svc.cscs.ch/api/v1/ssh-keys".to_string(),
                sign_url: "https://api-ssh-service.hpc-ssh.svc.cscs.ch/api/v1/ssh-keys/sign".to_string(),
                revoke_url: "https://api-ssh-service.hpc-ssh.svc.cscs.ch/api/v1/ssh-keys/revoke".to_string(),
            },
            Self::Tds => EnvConfig {
                pkce_client_id: "authx-cli".to_string(),
                issuer_url: "https://auth-tds.cscs.ch/auth/realms/cscs".to_string(),
                keys_url: "https://api-ssh-service.hpc-ssh.tds.cscs.ch/api/v1/ssh-keys".to_string(),
                sign_url: "https://api-ssh-service.hpc-ssh.tds.cscs.ch/api/v1/ssh-keys/sign".to_string(),
                revoke_url: "https://api-ssh-service.hpc-ssh.tds.cscs.ch/api/v1/ssh-keys/revoke".to_string(),
            },
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RawConfig {
    pub key_path: PathBuf,
    pub key_validity: String,
    #[serde(default)]
    pub env: Environment,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub key_path: PathBuf,
    pub key_validity: String,
    pub env: EnvConfig,
}

impl Config {
    pub fn load(cli_env: Option<Environment>, cli_overrides: &ConfigCliOverride) -> anyhow::Result<Self> {
        let proj_dirs = ProjectDirs::from("ch", "cscs", "cscs-key")
            .context("Could not determine configuration directory")?;
        let config_dir = proj_dirs.config_dir();
        let config_file_path = config_dir.join("config.toml");

        let raw_config: RawConfig = Figment::new()
            .merge(Serialized::defaults(RawConfig::default()))
            .merge(Toml::file(config_file_path))
            .merge(Serialized::defaults(cli_overrides))
            .extract()?;

        let active_env = cli_env.unwrap_or(raw_config.env);

        Ok(Self {
            key_path: raw_config.key_path,
            key_validity: raw_config.key_validity,
            env: active_env.to_config(),
        })
    }
}

#[derive(Parser, Debug, Deserialize, Serialize)]
pub struct ConfigCliOverride {
    #[arg(long, global = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<PathBuf>,
    #[arg(long, global = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_validity: Option<String>,
}

impl Default for RawConfig {
    fn default() -> Self {
        Self {
            key_path: dirs::home_dir()
                .expect("Could not determine home directory")
                .join(".ssh/cscs-key"),
            key_validity: "1min".to_string(),
            env: Environment::default(),
        }
    }
}
