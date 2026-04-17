use reqwest::header::{HeaderMap, HeaderValue};

/// User-Agent string sent with all HTTP requests.
/// Format: `<app-name>/<version> (<os> <os-version>; <arch>)`
/// Example: `cscs-key/1.0.0 (Mac OS 26.4; aarch64)`
pub fn user_agent() -> String {
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
pub fn default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("X-Client-Type", HeaderValue::from_static("cli"));
    headers
}
