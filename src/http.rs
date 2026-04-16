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
