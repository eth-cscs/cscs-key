use reqwest::header::{HeaderMap, HeaderValue};

/// User-Agent string sent with all HTTP requests.
/// Format: `<app-name>/<version> (<os> <os-version>; <arch>)`
/// Example: `cscs-key/1.0.0 (Mac OS 26.4; aarch64)`
fn user_agent() -> String {
    let info = os_info::get();
    format!(
        "{}/{} ({} {}; {})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        info.os_type(),
        info.version(),
        std::env::consts::ARCH,
    )
}

/// Default headers added to all HTTP requests.
fn default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("X-Client-Type", HeaderValue::from_static("cli"));
    headers
}

/// Pre-configured HTTP client builder with standard headers and timeouts.
pub fn client_builder() -> reqwest::blocking::ClientBuilder {
    reqwest::blocking::Client::builder()
        .user_agent(user_agent())
        .default_headers(default_headers())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
}
