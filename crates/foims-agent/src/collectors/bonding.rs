//! bonding 采集器：bonding 接口从属状态。
//!
//! 对齐 node_exporter `bonding_linux.go`（默认启用）：读取
//! /sys/class/net/bonding_masters（空格分隔的主接口列表），对每个主接口
//! 读取 bonding/slaves（空格分隔），逐从属读取 lower_<slave>/bonding_slave/
//! mii_status（回退 slave_<slave>/...），输出：
//! - `node_bonding_slaves{master}`（Gauge，从属总数）；
//! - `node_bonding_active{master}`（Gauge，mii_status 为 up 的从属数）。
//!
//! bonding_masters 缺失（无 bonding 模块）返回 NoData。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// 网络类目录（相对 sys_path）
const NET_DIR: &str = "class/net";

pub struct BondingCollector {
    sys_path: PathBuf,
}

impl BondingCollector {
    /// 生产构造：读取真实 /sys
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/sys"))
    }

    /// 指定 /sys 根目录（测试注入 fixture）
    pub fn with_root(sys_path: PathBuf) -> Self {
        Self { sys_path }
    }

    fn net_dir(&self) -> PathBuf {
        self.sys_path.join(NET_DIR)
    }

    /// 读取单个主接口的 (从属数, 活跃数)
    fn master_stats(&self, master: &str) -> Result<(u64, u64), CollectorError> {
        let master_dir = self.net_dir().join(master);
        let slaves_text = std::fs::read_to_string(master_dir.join("bonding/slaves"))?;
        let mut slaves = 0u64;
        let mut active = 0u64;
        for slave in slaves_text.split_whitespace() {
            // 从属 sysfs 前缀随内核版本为 lower_ 或 slave_
            let status = std::fs::read_to_string(
                master_dir.join(format!("lower_{slave}/bonding_slave/mii_status")),
            )
            .or_else(|_| {
                std::fs::read_to_string(
                    master_dir.join(format!("slave_{slave}/bonding_slave/mii_status")),
                )
            })?;
            slaves += 1;
            if status.trim() == "up" {
                active += 1;
            }
        }
        Ok((slaves, active))
    }
}

impl Default for BondingCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for BondingCollector {
    fn name(&self) -> &'static str {
        "bonding"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let masters_text = match std::fs::read_to_string(self.net_dir().join("bonding_masters")) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(CollectorError::NoData);
            }
            Err(error) => return Err(error.into()),
        };
        // 按 bonding_masters 中的顺序输出（对齐 Go 的发现顺序语义）
        let mut slaves = MetricFamily::new(
            "node_bonding_slaves",
            "Number of configured slaves per bonding interface.",
            MetricType::Gauge,
        );
        let mut active = MetricFamily::new(
            "node_bonding_active",
            "Number of active slaves per bonding interface.",
            MetricType::Gauge,
        );
        for master in masters_text.split_whitespace() {
            let (slave_count, active_count) = self.master_stats(master)?;
            let label = vec![("master".to_string(), master.to_string())];
            slaves.push_labeled(label.clone(), slave_count as f64);
            active.push_labeled(label, active_count as f64);
        }
        Ok(vec![slaves, active])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sys")
    }

    #[test]
    fn test_collect_matches_fixture() {
        let collector = BondingCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 2);
        let value = |family: usize, master: &str| -> f64 {
            families[family]
                .samples
                .iter()
                .find(|s| s.labels.iter().any(|(k, v)| k == "master" && v == master))
                .unwrap_or_else(|| panic!("缺少主接口 {master} 样本"))
                .value
        };
        // fixture：bond0 空（0/0）、dmz 两从属全 up（2/2）、int 两从属一 up（2/1）
        assert_eq!(value(0, "bond0"), 0.0);
        assert_eq!(value(1, "bond0"), 0.0);
        assert_eq!(value(0, "dmz"), 2.0);
        assert_eq!(value(1, "dmz"), 2.0);
        assert_eq!(value(0, "int"), 2.0);
        assert_eq!(value(1, "int"), 1.0);
    }

    #[test]
    fn test_missing_bonding_masters_is_nodata() {
        let collector = BondingCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::NoData)));
    }
}
