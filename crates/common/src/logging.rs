use std::io::IsTerminal;

use tracing_subscriber::EnvFilter;

/// Initialise the global tracing subscriber. `RUST_LOG`, when set, overrides `default_level`.
/// Colours only go to a terminal and honour `NO_COLOR`, so journald and log files stay plain.
pub fn init(default_level: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    let ansi = std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(ansi)
        .init();
}
