//! Tiny human-readable formatting helpers for log lines.

use std::time::Duration;

/// Formats a byte count with binary prefixes, e.g. `42 B`, `1.5 MiB`.
#[allow(clippy::cast_precision_loss)] // log-only display, rounding irrelevant
#[must_use]
pub fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Formats a duration compactly, e.g. `3s`, `5m04s`, `2h07m33s`, `3d02h`.
#[must_use]
pub fn fmt_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let days = h / 24;
    let h = h % 24;
    if days > 0 {
        format!("{days}d{h:02}h{m:02}m")
    } else if h > 0 {
        format!("{h}h{m:02}m{s:02}s")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_and_durations_render() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1024), "1.0 KiB");
        assert_eq!(fmt_bytes(3 * 1024 * 1024), "3.0 MiB");
        assert_eq!(fmt_duration(Duration::from_secs(3)), "3s");
        assert_eq!(fmt_duration(Duration::from_secs(64)), "1m04s");
        assert_eq!(fmt_duration(Duration::from_secs(3600)), "1h00m00s");
        assert_eq!(fmt_duration(Duration::from_secs(3 * 86_400)), "3d00h00m");
        assert_eq!(
            fmt_duration(Duration::from_secs(86_400 + 3 * 3600 + 5 * 60)),
            "1d03h05m"
        );
    }
}
