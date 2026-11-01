//! arp 采集器：ARP 邻居表。
//!
//! 对齐 node_exporter `arp_linux.go`（默认启用）：按设备聚合 ARP 条目，
//! 输出 `node_arp_entries{device}`（Gauge）。原版默认经 netlink 采集
//! （含 IPv6 邻居并过滤 NUD_NOARP），按移植规格采用 /proc/net/arp 路径
//! （即原版 `--collector.arp.netlink=false` 行为）；设备正则过滤参数未移植。
//! 表头行跳过；字段数不足 6 的残缺行跳过（对齐 procfs 的宽容策略）。

use std::collections::BTreeMap;
use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// arp 表文件（相对 proc_path）
const ARP_FILE: &str = "net/arp";

pub struct ArpCollector {
    proc_path: PathBuf,
}

impl ArpCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for ArpCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 解析 arp 表文本：按设备统计条目数（设备名列固定为第 6 列）
fn parse_arp_entries(text: &str) -> BTreeMap<String, u64> {
    let mut entries: BTreeMap<String, u64> = BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // 表头行（IP address ...）与残缺行跳过
        if fields.len() != 6 || fields[0] == "IP" {
            continue;
        }
        *entries.entry(fields[5].to_string()).or_insert(0) += 1;
    }
    entries
}

impl Collector for ArpCollector {
    fn name(&self) -> &'static str {
        "arp"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let text = std::fs::read_to_string(self.proc_path.join(ARP_FILE))?;
        let entries = parse_arp_entries(&text);

        let mut family = MetricFamily::new(
            "node_arp_entries",
            "ARP entries by device",
            MetricType::Gauge,
        );
        for (device, count) in &entries {
            family.push_labeled(vec![("device".to_string(), device.clone())], *count as f64);
        }
        Ok(vec![family])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn test_collect_matches_fixture() {
        let collector = ArpCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 1);
        let family = &families[0];
        assert_eq!(family.name, "node_arp_entries");
        assert_eq!(family.mtype, MetricType::Gauge);
        // fixture：eth0 三条、eth1 三条、nope 一条
        let value = |device: &str| -> f64 {
            family
                .samples
                .iter()
                .find(|s| s.labels.iter().any(|(k, v)| k == "device" && v == device))
                .unwrap_or_else(|| panic!("缺少设备 {device} 样本"))
                .value
        };
        assert_eq!(value("eth0"), 3.0);
        assert_eq!(value("eth1"), 3.0);
        assert_eq!(value("nope"), 1.0);
    }

    #[test]
    fn test_parse_skips_header_and_malformed_lines() {
        let entries = parse_arp_entries(
            "IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.1 0x1 0x2 cc:aa:dd:ee:aa:bb * eth0\n残缺行 1 2 3\n",
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(entries["eth0"], 1);
    }

    #[test]
    fn test_missing_file_is_error() {
        // 对齐 Go：读取失败（缺文件）报错而非 NoData
        let collector = ArpCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::Io(_))));
    }
}
