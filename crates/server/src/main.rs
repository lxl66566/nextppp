//! CLI entry point of the openppp3 server.

use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
};

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::EnvFilter;

const EXAMPLE_CONFIG: &str = r#"{
    // Listen address for openppp3 client connections.
    "listen": "0.0.0.0:6666",

    // Outbound (server -> target) connect timeout, seconds.
    "connect_timeout": 10,

    // Handshake timeout, seconds. Raises the cost of slow-loris probing.
    "handshake_timeout": 15,

    // Obfuscation parameters; every field except the passwords feeds the
    // handshake flag-canary, so they must match the client configuration.
    // Secrets must be changed per deployment.
    "obfuscation": {
        // "kf": 154543927,
        // "kl": 10,
        // "kh": 12,
        // "kx": 128,
        // "protocol": "aes-128-cfb",
        "protocol_key": "CHANGE_ME",
        // "transport": "aes-256-cfb",
        "transport_key": "CHANGE_ME_TOO",
        // "masked": true,
        // "plaintext": true,
        // "delta_encode": true,
        // "shuffle_data": true,
    },
}
"#;

/// openppp3 anti-censorship proxy server.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Configuration file path (jsonc).
    #[arg(short, long, default_value = "openppp3-server.jsonc")]
    config: PathBuf,

    /// Write a commented example configuration to PATH and exit.
    #[arg(long, value_name = "PATH", default_missing_value = "openppp3-server.jsonc", num_args = 0..=1)]
    init: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    if let Some(path) = args.init {
        write_example(&path)?;
        return Ok(());
    }

    let cfg = openppp3_common::ServerConfig::load(&args.config)?;
    let listen: std::net::SocketAddr = cfg
        .listen
        .parse()
        .with_context(|| format!("invalid listen address {:?}", cfg.listen))?;
    let listener = TcpListener::bind(listen).with_context(|| format!("bind {listen}"))?;
    let rt = openppp3_server::ServerRuntime::from_config(&cfg)?;
    openppp3_server::serve(listener, rt)
}

fn write_example(path: &Path) -> anyhow::Result<()> {
    fs::write(path, EXAMPLE_CONFIG)
        .with_context(|| format!("write {}", path.display()))?;
    println!("wrote example configuration to {}", path.display());
    Ok(())
}
