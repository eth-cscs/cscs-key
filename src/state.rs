use chrono::{DateTime, Duration, Utc};
use directories::ProjectDirs;
use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Default)]
pub struct AppState {
    pub oidc_token: Option<TokenStore>,
    pub keys: Option<HashMap<PathBuf, CertMetadata>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TokenStore {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub expiration: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum KeyOrigin {
    Local,
    Remote,
}

#[derive(Serialize, Deserialize)]
pub struct CertMetadata {
    pub key_path: PathBuf,
    pub cert_path: PathBuf,
    pub origin: KeyOrigin,
    pub serial_number: String,
    pub expires_at: DateTime<Utc>,
}

impl AppState {
    fn get_path() -> anyhow::Result<PathBuf> {
        let proj_dirs = ProjectDirs::from("ch", "cscs", "cscs-key")
            .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
        let cache_dir = proj_dirs.cache_dir();
        fs::create_dir_all(cache_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(cache_dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(cache_dir.join("token.json"))
    }

    pub fn load() -> anyhow::Result<Self> {
        let path = Self::get_path()?;
        debug!("Trying to load state from cache {}", path.display());
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::get_path()?;
        debug!("Saving state to cache {}", path.display());
        let json = serde_json::to_string_pretty(self)?;
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(json.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&path, json)?;
        }
        Ok(())
    }
}

impl TokenStore {
    pub fn is_expired(&self) -> bool {
        let grace_period = Duration::seconds(10);
        match self.expiration {
            Some(expire_at) => Utc::now() + grace_period > expire_at,
            None => true,
        }
    }
}
