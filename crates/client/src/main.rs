//! CLI entry point of the openppp3 client.

use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::EnvFilter;

const EXAMPLE_CONFIG: &str = r#"{
    // Local mixed-protocol inbound: SOCKS5 and HTTP proxy on one port.
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

    // Routing rules: first match wins. Types: domain, domain-suffix,
    // domain-keyword, ip-cidr. Policies: proxy, direct, block.
    "rules": [
        "ip-cidr:127.0.0.0/8,direct",
        "ip-cidr:10.0.0.0/8,direct",
        "ip-cidr:172.16.0.0/12,direct",
        "ip-cidr:192.168.0.0/16,direct",
        "domain-suffix:cn,direct",
        // "domain:ads.example.com,block",
    ],

    // Fallback policy when no rule matches.
    "final": "proxy",

    // While running, point the desktop system proxy at the local inbound
    // and restore the previous settings on exit.
    "system_proxy": {
        "enable": false,
        // "bypass": ["localhost", "127.*", "<local>"],
    },
}
"#;

/// openppp3 anti-censorship proxy client.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Configuration file path (jsonc).
    #[arg(short, long, default_value = "openppp3-client.jsonc")]
    config: PathBuf,

    /// Write a commented example configuration to PATH and exit.
    #[arg(long, value_name = "PATH", default_missing_value = "openppp3-client.jsonc", num_args = 0..=1)]
    init: Option<PathBuf>,
}

// Held globally so the Ctrl-C handler can restore the system proxy.
#[cfg(feature = "system-proxy")]
static PROXY_GUARD: Mutex<Option<openppp3_client::sysproxy::SysProxyGuard>> = Mutex::new(None);

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

    let cfg = openppp3_common::ClientConfig::load(&args.config)?;
    let listen: SocketAddr = cfg
        .listen
        .parse()
        .with_context(|| format!("invalid listen address {:?}", cfg.listen))?;
    let listener = TcpListener::bind(listen).with_context(|| format!("bind {listen}"))?;
    let rt = Arc::new(openppp3_client::ClientRuntime::from_config(&cfg)?);

    install_system_proxy(&listen, &cfg.system_proxy);
    let result = openppp3_client::serve(listener, rt);
    restore_system_proxy();
    result
}

/// Installs the system proxy (if enabled) and the Ctrl-C restore handler.
#[cfg(feature = "system-proxy")]
fn install_system_proxy(listen: &SocketAddr, sp: &openppp3_common::SystemProxyConfig) {
    if !sp.enable {
        return;
    }
    match openppp3_client::sysproxy::SysProxyGuard::enable(
        "127.0.0.1",
        listen.port(),
        &sp.bypass,
    ) {
        Ok(guard) => {
            *PROXY_GUARD.lock().expect("proxy guard") = Some(guard);
            tracing::info!("system proxy enabled (127.0.0.1:{})", listen.port());
        }
        Err(e) => tracing::warn!("failed to enable system proxy: {e:#}"),
    }

    // The guard lives in a static, which never drops: restore explicitly
    // on Ctrl-C (and after serve() returns in main).
    ctrlc::set_handler(|| {
        restore_system_proxy();
        std::process::exit(130);
    })
    .ok();
}

#[cfg(feature = "system-proxy")]
fn restore_system_proxy() {
    if let Some(guard) = PROXY_GUARD.lock().expect("proxy guard").take() {
        drop(guard);
    }
}

#[cfg(not(feature = "system-proxy"))]
fn install_system_proxy(_listen: &SocketAddr) {}

#[cfg(not(feature = "system-proxy"))]
fn restore_system_proxy() {}

fn write_example(path: &Path) -> anyhow::Result<()> {
    fs::write(path, EXAMPLE_CONFIG)
        .with_context(|| format!("write {}", path.display()))?;
    println!("wrote example configuration to {}", path.display());
    Ok(())
}
