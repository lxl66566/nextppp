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

const SERVER_EXAMPLE_CONFIG: &str = include_str!("../examples/openppp3-server.jsonc");

const CLIENT_EXAMPLE_CONFIG: &str = include_str!("../examples/openppp3-client.jsonc");

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

#[cfg_attr(feature = "hotpath", hotpath::main)]
fn main() -> anyhow::Result<()> {
    // Runtime level control via SPDLOG_RS_LEVEL (e.g. `debug`, `trace`,
    // `off`); info+ by default.
    spdlog::init_env_level()?;
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
