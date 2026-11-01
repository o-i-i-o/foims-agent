//! selinux 采集器：SELinux 状态。
//!
//! 对齐 node_exporter `selinux_linux.go`（默认启用）：
//! - /sys/fs/selinux 目录不存在（未启用）时仅输出 `node_selinux_enabled` 0；
//! - 启用时输出 `node_selinux_enabled` 1、`node_selinux_config_mode` 与
//!   `node_selinux_current_mode`（Gauge，数值编码）；
//! - current mode 读取 /sys/fs/selinux/enforce（1=enforcing，0=permissive）；
//! - config mode 解析 /etc/selinux/config 的 SELINUX= 行，数值编码对齐
//!   go-selinux 库（1=disabled，2=permissive，3=enforcing）；配置文件或
//!   SELINUX= 键缺失时按库的兜底行为记 permissive(2)。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// selinux 虚拟文件系统目录（相对 sys_path）
const SELINUX_DIR: &str = "fs/selinux";
/// selinux 配置文件（相对 etc_path）
const CONFIG_FILE: &str = "selinux/config";

/// go-selinux 的模式编码：disabled=1，permissive=2，enforcing=3
const MODE_DISABLED: f64 = 1.0;
const MODE_PERMISSIVE: f64 = 2.0;
const MODE_ENFORCING: f64 = 3.0;

pub struct SelinuxCollector {
    sys_path: PathBuf,
    etc_path: PathBuf,
}

impl SelinuxCollector {
    /// 生产构造：读取真实 /sys 与 /etc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"), PathBuf::from("/etc"))
    }

    /// 指定 /sys 与 /etc 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf, etc_path: PathBuf) -> Self {
        Self { sys_path, etc_path }
    }
}

impl Default for SelinuxCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 解析 config 文件的 SELINUX= 行 → go-selinux 模式编码；
/// 配置缺失或键缺失记 permissive（对齐 DefaultEnforceMode 兜底）
fn parse_config_mode(text: Option<&str>) -> f64 {
    let Some(text) = text else {
        return MODE_PERMISSIVE;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(value) = line
            .strip_prefix("SELINUX=")
            .map(str::trim)
            .map(str::to_ascii_lowercase)
        {
            return match value.as_str() {
                "disabled" => MODE_DISABLED,
                "enforcing" => MODE_ENFORCING,
                "permissive" => MODE_PERMISSIVE,
                // 未知取值按 permissive 兜底
                _ => MODE_PERMISSIVE,
            };
        }
    }
    MODE_PERMISSIVE
}

impl Collector for SelinuxCollector {
    fn name(&self) -> &'static str {
        "selinux"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let mut enabled = MetricFamily::new(
            "node_selinux_enabled",
            "SELinux is enabled, 1 is true, 0 is false",
            MetricType::Gauge,
        );
        if !self.sys_path.join(SELINUX_DIR).exists() {
            enabled.push(0.0);
            return Ok(vec![enabled]);
        }

        enabled.push(1.0);
        let mut out = vec![enabled];

        let mut config_mode = MetricFamily::new(
            "node_selinux_config_mode",
            "Configured SELinux enforcement mode",
            MetricType::Gauge,
        );
        let config_text = std::fs::read_to_string(self.etc_path.join(CONFIG_FILE)).ok();
        config_mode.push(parse_config_mode(config_text.as_deref()));
        out.push(config_mode);

        // enforce 文件在 selinux 启用但策略未加载时可能缺失，按 Go 语义报错
        let enforce_text =
            std::fs::read_to_string(self.sys_path.join(SELINUX_DIR).join("enforce"))?;
        let current =
            enforce_text
                .trim()
                .parse::<f64>()
                .map_err(|error| CollectorError::Parse {
                    file: CONFIG_FILE,
                    reason: format!("enforce 内容非法: {error}"),
                })?;
        let mut current_mode = MetricFamily::new(
            "node_selinux_current_mode",
            "Current SELinux enforcement mode",
            MetricType::Gauge,
        );
        current_mode.push(current);
        out.push(current_mode);

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sys")
    }

    fn etc_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/etc")
    }

    #[test]
    fn test_collect_enabled() {
        let collector = SelinuxCollector::with_root(fixture_root(), etc_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 3);
        assert_eq!(families[0].name, "node_selinux_enabled");
        assert_eq!(families[0].samples[0].value, 1.0);
        // config: SELINUX=enforcing → 3
        assert_eq!(families[1].name, "node_selinux_config_mode");
        assert_eq!(families[1].samples[0].value, MODE_ENFORCING);
        // enforce 文件 = 1 → current mode 1
        assert_eq!(families[2].name, "node_selinux_current_mode");
        assert_eq!(families[2].samples[0].value, 1.0);
    }

    #[test]
    fn test_collect_disabled() {
        // sys 根目录不存在 → 仅输出 enabled=0
        let collector =
            SelinuxCollector::with_root(PathBuf::from("/nonexistent-foims-test"), etc_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 1);
        assert_eq!(families[0].name, "node_selinux_enabled");
        assert_eq!(families[0].samples[0].value, 0.0);
    }

    #[test]
    fn test_parse_config_mode() {
        assert_eq!(parse_config_mode(Some("SELINUX=enforcing\n")), 3.0);
        assert_eq!(parse_config_mode(Some("# 注释\nSELINUX=Permissive\n")), 2.0);
        assert_eq!(parse_config_mode(Some("SELINUX=disabled")), 1.0);
        // 键缺失 / 文件缺失 → permissive
        assert_eq!(parse_config_mode(Some("NAME=distro\n")), 2.0);
        assert_eq!(parse_config_mode(None), 2.0);
    }

    #[test]
    fn test_missing_enforce_file_is_error() {
        // sys 根存在 fs/selinux 目录但缺 enforce 文件 → 对齐 Go 报错
        let broken_sys =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sys-missing-enforce");
        let collector = SelinuxCollector::with_root(broken_sys, etc_root());
        assert!(matches!(collector.collect(), Err(CollectorError::Io(_))));
    }
}
