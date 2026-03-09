//use std::fs::{File, metadata};
use std::io::Write;
use reqwest;
use serde::Deserialize;
//use anyhow::{anyhow, bail, Context};
use anyhow::{anyhow, Context};
use chrono::{Utc, Duration};
//use log::{info, debug};
use log::info;

use crate::config::Config;
use crate::state::{AppState, TokenStore};

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
    access_token: String,
    expires_in: i64,
    id_token: String,
}

pub fn get_access_token(config: &Config) -> anyhow::Result<String> {
    if let Ok(api_key) = std::env::var("CSCS_API_KEY") {
        info!("Authenticating via Service Account API Key...");
        let new_store = login_via_api_key(config, &api_key)?;
        // We probably DON'T want to save service account tokens to the user's home cache
        return Ok(new_store.access_token);
    }

    let mut state = AppState::load()?;

    // Try to load token from cache
    if let Some(token) = state.oidc_token {
        info!("Token exists in store.");
        // Is the access token still valid?
        if !token.is_expired() {
            info!("Token exists in store and is valid.");
            return Ok(token.access_token);
        }

        // Token is expired, try to use the refresh token
        if let Some(refresh_token) = &token.refresh_token {
            info!("Access token expired, attempting refresh...");
            match refresh_access_token(config, refresh_token) {
                Ok(new_token) => {
                    let ret_access_token = new_token.access_token.clone();
                    state.oidc_token = Some(new_token);
                    state.save()?;
                    return Ok(ret_access_token);
                }
                Err(e) => {
                    info!("Refresh failed: {}. Falling back to browser login.", e);
                }
            }
        }
    }

    info!("Token does not exist in store or was not refreshed -> browser authentication.");
    // Cache or refresh failed -> Browser login
    let new_token = login_via_browser(config)?;
    let ret_access_token = new_token.access_token.clone();
    state.oidc_token = Some(new_token);
    state.save()?;
    Ok(ret_access_token)
}

fn refresh_access_token(config: &Config, refresh_token: &str) -> anyhow::Result<TokenStore> {
    let http_client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
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
    info!("Get OIDC token");

    // In 4.x, we create a reusable reqwest client first
    let http_client = reqwest::blocking::Client::builder()
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
        eprintln!("Failed to open browser automatically: {}", e);
        println!("Browser window did not open automatically. Log in here :\n{}", auth_url);
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

fn login_via_api_key(config: &Config, api_key: &str) -> anyhow::Result<TokenStore> {
    info!("Get OIDC token using API Key");

    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to initialize HTTP client.")?;

    let response = client.post(config.env.token_url.clone())
        .header("X-API-Key", api_key)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .send()
        .context("Failed to send request to get access token.")?;

    let response_struct: ApiKeyResponse = response.json()?;

    let expires_in = Duration::seconds(response_struct.expires_in);
    let expiration = Utc::now() + expires_in;

    Ok(TokenStore {
        access_token: response_struct.access_token,
        refresh_token: None,
        id_token: Some(response_struct.id_token),
        expiration: Some(expiration),
    })
}
