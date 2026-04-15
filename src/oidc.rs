//use std::fs::{File, metadata};
use std::io::Write;
use reqwest;
use serde::Deserialize;
use secrecy::{SecretString, ExposeSecret};
use anyhow::{anyhow, bail, Context};
use chrono::{Utc, Duration};
use log::{info, debug, trace};
use qrcode::QrCode;
use qrcode::render::unicode;

use crate::config::Config;
use crate::state::{AppState, TokenStore};
use crate::http;

use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, IssuerUrl,
    PkceCodeChallenge, RedirectUrl, Scope,
    CsrfToken, Nonce,
    OAuth2TokenResponse,
    TokenResponse,
    RefreshToken,
    AccessTokenHash,
};
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use url::Url;

#[derive(Deserialize, Debug)]
struct ApiKeyResponse {
    access_token: SecretString,
    expires_in: i64,
    id_token: SecretString,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ApiKeyErrorResponse {
    message: String,
}

#[derive(Deserialize, Debug)]
struct DeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Deserialize, Debug)]
struct DeviceTokenSuccess {
    access_token: SecretString,
    refresh_token: Option<SecretString>,
    id_token: Option<SecretString>,
    expires_in: Option<i64>,
}

#[derive(Deserialize, Debug)]
struct OAuthError {
    error: String,
    error_description: Option<String>,
}

pub fn get_access_token(config: &Config) -> anyhow::Result<String> {
    trace!("get access token");

    if let Ok(api_key) = std::env::var("CSCS_API_KEY") {
        debug!("Authenticating via Service Account API Key...");
        let new_store = login_via_api_key(config, &api_key)?;
        // We probably DON'T want to save service account tokens to the user's home cache
        return Ok(new_store.access_token);
    }

    let mut state = AppState::load()?;

    // Try to load token from cache
    if let Some(token) = state.oidc_token {
        debug!("Access token exists in store.");
        // Is the access token still valid?
        if !token.is_expired() {
            debug!("Access token is valid.");
            return Ok(token.access_token);
        }

        // Token is expired, try to use the refresh token
        if let Some(refresh_token) = &token.refresh_token {
            debug!("Access token is expired, attempting refresh...");
            match refresh_access_token(config, refresh_token) {
                Ok(new_token) => {
                    let ret_access_token = new_token.access_token.clone();
                    state.oidc_token = Some(new_token);
                    state.save()?;
                    return Ok(ret_access_token);
                }
                Err(e) => {
                    debug!("Access token refresh failed: {}. Falling back to interactive login.", e);
                }
            }
        }
    }

    // Cache or refresh failed -> interactive login
    let new_token = if config.headless {
        debug!("Headless mode enabled, using device authorization flow.");
        login_via_device_code(config)?
    } else {
        debug!("Token does not exist in store or was not refreshed -> browser authentication.");
        login_via_browser(config)?
    };
    let ret_access_token = new_token.access_token.clone();
    state.oidc_token = Some(new_token);
    state.save()?;
    Ok(ret_access_token)
}

fn refresh_access_token(config: &Config, refresh_token: &str) -> anyhow::Result<TokenStore> {
    trace!("refresh access token");

    let http_client = http::client_builder()
        .build()
        .context("Failed to initialize HTTP client.")?;
    let issuer_url = IssuerUrl::new(config.env.issuer_url.clone())?;
    let provider_metadata = CoreProviderMetadata::discover(&issuer_url, &http_client)?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.env.pkce_client_id.clone()),
        None,
    );

    let token_response = client
        .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))?
        .request(&http_client)
        .context("Failed to exchange refresh token")?;

    let id_token = token_response
        .id_token()
        .ok_or_else(|| anyhow!("Server did not return an ID token"))?;
    let expires_in = token_response.expires_in().unwrap_or(std::time::Duration::ZERO);
    let expiration = Utc::now() + Duration::from_std(expires_in).unwrap();

    Ok(TokenStore {
        access_token: token_response.access_token().secret().to_string(),
        refresh_token: Some(token_response.refresh_token().unwrap().secret().to_string()),
        id_token: Some(id_token.to_string()),
        expiration: Some(expiration),
    })
}

fn login_via_browser(config: &Config) -> anyhow::Result<TokenStore> {
    trace!("login via browser");

    // In 4.x, we create a reusable reqwest client first
    let http_client = http::client_builder()
        .redirect(reqwest::redirect::Policy::none()) // Recommended for OIDC security
        .build()?;

    let issuer_url = IssuerUrl::new(config.env.issuer_url.clone())?;

    // Discovery takes a reference to the client
    let provider_metadata = CoreProviderMetadata::discover(&issuer_url, &http_client)?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.env.pkce_client_id.clone()),
        None,
    )
    .set_redirect_uri(RedirectUrl::new("http://localhost:8765".to_string())?);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random, // State/CSRF provider
            Nonce::new_random,     // Nonce provider
        )
        .add_scope(Scope::new("openid".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Open the browser!
    if let Err(e) = webbrowser::open(auth_url.as_str()) {
        debug!("Failed to open browser automatically: {}", e);
        info!("Browser window did not open automatically. Log in here :\n{}", auth_url);
    }

    // Simple listener
    let listener = TcpListener::bind("127.0.0.1:8765")?;
    let (mut stream, _) = listener.accept()?;
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let redirect_url = request_line.split_whitespace().nth(1).unwrap_or("");
    let url = Url::parse(&format!("http://localhost:8765{}", redirect_url))?;

    // Check CSRF: Unlikely on localhost, but better be careful
    let returned_state = url.query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .context("No state found")?;
    if returned_state != *csrf_token.secret() {
        return Err(anyhow!("CSRF detected! State mismatch."));
    }

    let code = url.query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())
        .context("No code found")?;

    const SUCCESS_HTML: &str = include_str!("../templates/oidc_auth_success.html");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
        SUCCESS_HTML.len(),
        SUCCESS_HTML
    );
    stream.write_all(response.as_bytes())?;

    // Pass the reference to the client here too
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))?
        .set_pkce_verifier(pkce_verifier)
        .request(&http_client)?; // Look Ma, no http_client() helper!

    let id_token = token_response
        .id_token()
        .ok_or_else(|| anyhow!("Server did not return an ID token"))?;

    // Check nonce: Replay protection
    // Verify the access token hash to ensure that the access token
    // hasn't been substituted for another user's.
    let id_token_verifier = client.id_token_verifier();
    let claims = id_token.claims(&id_token_verifier, &nonce)?;
    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            token_response.access_token(),
            id_token.signing_alg()?,
            id_token.signing_key(&id_token_verifier)?,
        )?;
        if actual_access_token_hash != *expected_access_token_hash {
            return Err(anyhow!("Invalid access token"));
        }
    }

    let expires_in = token_response.expires_in().unwrap_or(std::time::Duration::ZERO);
    let expiration = Utc::now() + Duration::from_std(expires_in).unwrap();

    Ok(TokenStore {
        access_token: token_response.access_token().secret().to_string(),
        refresh_token: Some(token_response.refresh_token().unwrap().secret().to_string()),
        id_token: Some(id_token.to_string()),
        expiration: Some(expiration),
    })
}

fn login_via_device_code(config: &Config) -> anyhow::Result<TokenStore> {
    trace!("login via device code");

    let http_client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Failed to initialize HTTP client.")?;

    // Discover endpoints from OIDC well-known configuration
    let well_known_url = format!("{}/.well-known/openid-configuration", config.env.issuer_url);
    let discovery: serde_json::Value = http_client
        .get(&well_known_url)
        .send()
        .context("Failed to fetch OIDC discovery document.")?
        .json()
        .context("Failed to parse OIDC discovery document.")?;

    let device_auth_endpoint = discovery["device_authorization_endpoint"]
        .as_str()
        .ok_or_else(|| anyhow!(
            "Device authorization is not enabled on this server. \
             Please contact the administrator to enable it, or authenticate \
             locally and copy the token cache to this machine."
        ))?;

    let token_endpoint = discovery["token_endpoint"]
        .as_str()
        .ok_or_else(|| anyhow!("Token endpoint not found in OIDC discovery document."))?;

    // Request device code
    let response = http_client
        .post(device_auth_endpoint)
        .form(&[
            ("client_id", config.env.pkce_client_id.as_str()),
            ("scope", "openid"),
        ])
        .send()
        .context("Failed to request device authorization code.")?;

    if !response.status().is_success() {
        let err: OAuthError = response.json()
            .context("Failed to parse device authorization error response.")?;
        bail!("{}", err.error_description.unwrap_or(err.error));
    }

    let device_auth: DeviceAuthResponse = response.json()
        .context("Failed to parse device authorization response.")?;

    // Display instructions to the user
    info!("To authenticate, open this URL in a browser:");
    info!("");
    info!("  {}", device_auth.verification_uri);
    info!("");
    info!("And enter the code: {}", device_auth.user_code);
    if let Some(ref uri) = device_auth.verification_uri_complete {
        info!("");
        info!("Or open this URL directly:");
        info!("  {}", uri);
    }

    let qr_url = device_auth.verification_uri_complete.as_deref()
        .unwrap_or(&device_auth.verification_uri);
    if let Ok(code) = QrCode::new(qr_url) {
        let qr_string = code.render::<unicode::Dense1x2>()
            .quiet_zone(false)
            .module_dimensions(1, 1)
            .build();
        info!("");
        info!("Or scan this QR code:");
        info!("\n{}", qr_string);
    }

    info!("");
    info!("Waiting for authentication...");

    // Poll the token endpoint until the user completes authentication
    let mut interval = std::time::Duration::from_secs(device_auth.interval.unwrap_or(5));
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(device_auth.expires_in);

    loop {
        std::thread::sleep(interval);

        if std::time::Instant::now() > deadline {
            bail!("Device authorization expired. Please try again.");
        }

        let response = http_client
            .post(token_endpoint)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", config.env.pkce_client_id.as_str()),
                ("device_code", device_auth.device_code.as_str()),
            ])
            .send()
            .context("Failed to poll for token.")?;

        let status = response.status();
        let response_bytes = response.bytes()?;

        if status.is_success() {
            let token: DeviceTokenSuccess = serde_json::from_slice(&response_bytes)
                .context("Failed to parse token response.")?;

            let expires_in = token.expires_in.unwrap_or(0);
            let expiration = Utc::now() + Duration::seconds(expires_in);

            info!("Authentication successful!");

            return Ok(TokenStore {
                access_token: token.access_token.expose_secret().to_string(),
                refresh_token: token.refresh_token.map(|t| t.expose_secret().to_string()),
                id_token: token.id_token.map(|t| t.expose_secret().to_string()),
                expiration: Some(expiration),
            });
        }

        let err: OAuthError = serde_json::from_slice(&response_bytes)
            .with_context(|| format!(
                "Failed to parse device token error response: {:?}",
                String::from_utf8_lossy(&response_bytes)
            ))?;

        match err.error.as_str() {
            "authorization_pending" => {
                trace!("Authorization pending, continuing to poll...");
                continue;
            }
            "slow_down" => {
                interval += std::time::Duration::from_secs(5);
                debug!("Server requested slow down, polling interval now {:?}.", interval);
                continue;
            }
            "expired_token" => bail!("Device code expired. Please try again."),
            "access_denied" => bail!("Authorization was denied."),
            _ => bail!(
                "Authentication error: {}",
                err.error_description.unwrap_or(err.error)
            ),
        }
    }
}

fn login_via_api_key(config: &Config, api_key: &str) -> anyhow::Result<TokenStore> {
    trace!("get access token using API key");

    let client = http::client_builder()
        .build()
        .context("Failed to initialize HTTP client.")?;

    let response = client.post(config.env.token_url.clone())
        .header("X-API-Key", api_key)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .send()
        .context("Failed to send request to get access token.")?;

    let status = response.status();
    let response_bytes = response.bytes()?;

    if !status.is_success() {
        let error_response_struct: ApiKeyErrorResponse = serde_json::from_slice(&response_bytes)?;
        bail!("{}", error_response_struct.message);
    }

    let response_struct: ApiKeyResponse = serde_json::from_slice(&response_bytes)
        .with_context(||
            format!(
                "Failed to parse the respons form Keycloak. Response body: {:?}",
                String::from_utf8_lossy(&response_bytes)
            ))?;
    trace!("Parsed Keycloak response: {:?}", response_struct);

    let expires_in = Duration::seconds(response_struct.expires_in);
    let expiration = Utc::now() + expires_in;

    Ok(TokenStore {
        access_token: response_struct.access_token.expose_secret().to_string(),
        refresh_token: None,
        id_token: Some(response_struct.id_token.expose_secret().to_string()),
        expiration: Some(expiration),
    })
}
