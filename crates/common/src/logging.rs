use tracing_subscriber::EnvFilter;

/// Initialise the global tracing subscriber. `RUST_LOG`, when set, overrides `default_level`.
pub fn init(default_level: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
