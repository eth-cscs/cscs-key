/// User-Agent string sent with all HTTP requests.
/// Format: `<app-name>/<version> (<os>; <arch>)`
/// Example: `cscs-key/1.0.0 (macos; aarch64)`
pub fn user_agent() -> String {
    format!(
        "{}/{} ({}; {})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    )
}
