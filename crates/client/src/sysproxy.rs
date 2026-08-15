//! System proxy integration: install on startup, restore on exit.
//!
//! The guard stores the previous desktop proxy settings and writes them
//! back on drop. If the process is killed (`kill -9`, power loss) the
//! restore cannot happen — same caveat as every consumer proxy tool.

use anyhow::Context;

/// Default bypass list when the configuration leaves it empty. Windows
/// patterns; other platforms simply match less.
pub const DEFAULT_BYPASS: &[&str] = &[
    "localhost",
    "127.*",
    "192.168.*",
    "10.*",
    "172.16.*",
    "172.17.*",
    "172.18.*",
    "172.19.*",
    "172.2?.*",
    "172.30.*",
    "172.31.*",
    "<local>",
];

/// RAII guard: enables the system proxy while alive, restores the previous
/// state on drop.
pub struct SysProxyGuard {
    saved: Option<sysproxy::Sysproxy>,
}

impl SysProxyGuard {
    /// Saves the current settings and installs `host:port` as the system
    /// HTTP proxy.
    ///
    /// # Errors
    ///
    /// The platform proxy backend rejected the change.
    pub fn enable(host: &str, port: u16, bypass: &[String]) -> anyhow::Result<Self> {
        let saved = sysproxy::Sysproxy::get_system_proxy().ok();
        let separator = if cfg!(windows) { ";" } else { "," };
        let bypass = if bypass.is_empty() {
            DEFAULT_BYPASS.join(separator)
        } else {
            bypass.join(separator)
        };
        let new = sysproxy::Sysproxy {
            enable: true,
            host: host.to_owned(),
            port,
            bypass,
        };
        sysproxy::Sysproxy::set_system_proxy(&new).context("set system proxy")?;
        Ok(Self { saved })
    }
}

impl Drop for SysProxyGuard {
    fn drop(&mut self) {
        if let Some(old) = self.saved.take() {
            if sysproxy::Sysproxy::set_system_proxy(&old).is_err() {
                tracing::warn!("failed to restore the previous system proxy settings");
            }
        }
    }
}
