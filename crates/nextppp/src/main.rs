//! nextppp unified binary: `nextppp server` / `nextppp client`.
//!
//! One binary, two roles: the protocol core (and most of the anti-blocking
//! machinery) is shared anyway, and shipping both ends together keeps their
//! versions from drifting. Role logic lives in the `nextppp-server` /
//! `nextppp-client` library crates; this crate is CLI glue only.

use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use clap::{Parser, Subcommand};

const SERVER_EXAMPLE_CONFIG: &str = include_str!("../examples/nextppp-server.jsonc");

const CLIENT_EXAMPLE_CONFIG: &str = include_str!("../examples/nextppp-client.jsonc");

/// nextppp anti-censorship proxy (single binary, server + client).
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
        #[arg(short, long, default_value = "nextppp-server.jsonc")]
        config: PathBuf,

        /// Write a commented example configuration to PATH and exit.
        #[arg(long, value_name = "PATH", default_missing_value = "nextppp-server.jsonc", num_args = 0..=1)]
        init: Option<PathBuf>,
    },
    /// Run the local socks5 -> tunnel forwarder client.
    Client {
        /// Configuration file path (jsonc).
        #[arg(short, long, default_value = "nextppp-client.jsonc")]
        config: PathBuf,

        /// Write a commented example configuration to PATH and exit.
        #[arg(long, value_name = "PATH", default_missing_value = "nextppp-client.jsonc", num_args = 0..=1)]
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
    let cfg = nextppp_common::ServerConfig::load(config)?;
    let listener = bind_listen(&cfg.listen)?;
    let rt = nextppp_server::ServerRuntime::from_config(&cfg)?;
    nextppp_server::serve(listener, rt)
}

fn run_client(config: &Path, init: Option<PathBuf>) -> anyhow::Result<()> {
    if let Some(path) = init {
        return write_example(&path, CLIENT_EXAMPLE_CONFIG);
    }
    let cfg = nextppp_common::ClientConfig::load(config)?;
    let listener = bind_listen(&cfg.listen)?;
    let rt = Arc::new(nextppp_client::ClientRuntime::from_config(&cfg)?);
    nextppp_client::serve(listener, rt)
}

fn bind_listen(spec: &str) -> anyhow::Result<TcpListener> {
    let listen: SocketAddr = spec
        .parse()
        .with_context(|| format!("invalid listen address {spec:?}"))?;
    TcpListener::bind(listen).with_context(|| format!("bind {listen}"))
}

fn write_example(path: &Path, example: &str) -> anyhow::Result<()> {
    // The default PATH coincides with the default config path: blindly
    // overwriting could destroy a real deployment's configuration.
    match path.try_exists() {
        Ok(true) => anyhow::bail!(
            "{} already exists; refusing to overwrite (remove it first or pass an explicit \
             --init PATH)",
            path.display()
        ),
        Ok(false) => {},
        Err(e) => return Err(e).with_context(|| format!("check {}", path.display())),
    }
    fs::write(path, example).with_context(|| format!("write {}", path.display()))?;
    println!("wrote example configuration to {}", path.display());
    Ok(())
}
