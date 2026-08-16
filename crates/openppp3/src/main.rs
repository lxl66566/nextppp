//! openppp3 unified binary: `openppp3 server` / `openppp3 client`.
//!
//! One binary, two roles: the protocol core (and most of the anti-blocking
//! machinery) is shared anyway, and shipping both ends together keeps their
//! versions from drifting. Role logic lives in the `openppp3-server` /
//! `openppp3-client` library crates; this crate is CLI glue only.

use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

const SERVER_EXAMPLE_CONFIG: &str = r#"{
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

const CLIENT_EXAMPLE_CONFIG: &str = r#"{
    // Local SOCKS5 inbound. Point a front-end proxy (e.g. sing-box's
    // socks outbound) here; routing/splitting is its job.
    "listen": "127.0.0.1:1080",

    // Remote openppp3 server.
    "server": {
        "address": "your.server.example:6666",
        // "connect_timeout": 10,
        // Must mirror the server configuration (secrets included).
        "obfuscation": {
            // "kf": 154543927,
            // "protocol": "aes-128-cfb",
            "protocol_key": "CHANGE_ME",
            // "transport": "aes-256-cfb",
            "transport_key": "CHANGE_ME_TOO",
        },
    },
}
"#;

/// openppp3 anti-censorship proxy (single binary, server + client).
#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    role: Role,
}

#[derive(Subcommand)]
enum Role {
    /// Run the proxy server.
    Server {
        /// Configuration file path (jsonc).
        #[arg(short, long, default_value = "openppp3-server.jsonc")]
        config: PathBuf,

        /// Write a commented example configuration to PATH and exit.
        #[arg(long, value_name = "PATH", default_missing_value = "openppp3-server.jsonc", num_args = 0..=1)]
        init: Option<PathBuf>,
    },
    /// Run the local socks5 -> tunnel forwarder client.
    Client {
        /// Configuration file path (jsonc).
        #[arg(short, long, default_value = "openppp3-client.jsonc")]
        config: PathBuf,

        /// Write a commented example configuration to PATH and exit.
        #[arg(long, value_name = "PATH", default_missing_value = "openppp3-client.jsonc", num_args = 0..=1)]
        init: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match Args::parse().role {
        Role::Server { config, init } => run_server(&config, init),
        Role::Client { config, init } => run_client(&config, init),
    }
}

fn run_server(config: &Path, init: Option<PathBuf>) -> anyhow::Result<()> {
    if let Some(path) = init {
        return write_example(&path, SERVER_EXAMPLE_CONFIG);
    }
    let cfg = openppp3_common::ServerConfig::load(config)?;
    let listener = bind_listen(&cfg.listen)?;
    let rt = openppp3_server::ServerRuntime::from_config(&cfg)?;
    openppp3_server::serve(listener, rt)
}

fn run_client(config: &Path, init: Option<PathBuf>) -> anyhow::Result<()> {
    if let Some(path) = init {
        return write_example(&path, CLIENT_EXAMPLE_CONFIG);
    }
    let cfg = openppp3_common::ClientConfig::load(config)?;
    let listener = bind_listen(&cfg.listen)?;
    let rt = Arc::new(openppp3_client::ClientRuntime::from_config(&cfg)?);
    openppp3_client::serve(listener, rt)
}

fn bind_listen(spec: &str) -> anyhow::Result<TcpListener> {
    let listen: SocketAddr = spec
        .parse()
        .with_context(|| format!("invalid listen address {spec:?}"))?;
    TcpListener::bind(listen).with_context(|| format!("bind {listen}"))
}

fn write_example(path: &Path, example: &str) -> anyhow::Result<()> {
    fs::write(path, example).with_context(|| format!("write {}", path.display()))?;
    println!("wrote example configuration to {}", path.display());
    Ok(())
}
