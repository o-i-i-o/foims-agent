//! netdev 采集器：网络设备流量统计。
//!
//! 对齐 node_exporter `netdev_common.go` + `netdev_linux.go` 的
//! `/proc/net/dev` 数据路径（procNetDevStats）：16 列经典键名经默认
//! `legacy()` 转换（`--collector.netdev.enable-detailed-metrics` 默认 false）
//! 后输出 `node_network_<key>_total` 计数器系列，device 标签取自冒号前的
//! 接口名（Linux 版对设备名直通，不做 sanitize）。
//!
//! 未移植：netlink 数据路径（`--collector.netdev.netlink`）、
//! device-include/exclude 过滤、ifAlias 标签与 address-info 扩展。

use std::collections::HashMap;
use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

const NETDEV_FILE: &str = "net/dev";

/// /proc/net/dev 16 列 → procNetDevStats 键名（对齐 Go procNetDevStats 的映射）
const PROC_DEV_KEYS: [(&str, usize); 16] = [
    ("receive_bytes", 0),
    ("receive_packets", 1),
    ("receive_errors", 2),
    ("receive_dropped", 3),
    ("receive_fifo", 4),
    ("receive_frame", 5),
    ("receive_compressed", 6),
    ("receive_multicast", 7),
    ("transmit_bytes", 8),
    ("transmit_packets", 9),
    ("transmit_errors", 10),
    ("transmit_dropped", 11),
    ("transmit_fifo", 12),
    ("transmit_colls", 13),
    ("transmit_carrier", 14),
    ("transmit_compressed", 15),
];

/// legacy() 转换后的输出键名与顺序（对齐 netdev_linux_test.go 的
/// TestNetDevLegacyMetricNames 期望列表）
const LEGACY_KEYS: [&str; 16] = [
    "receive_packets",
    "transmit_packets",
    "receive_bytes",
    "transmit_bytes",
    "receive_errs",
    "transmit_errs",
    "receive_drop",
    "transmit_drop",
    "receive_multicast",
    "transmit_colls",
    "receive_frame",
    "receive_fifo",
    "transmit_carrier",
    "transmit_fifo",
    "receive_compressed",
    "transmit_compressed",
];

pub struct NetdevCollector {
    proc_path: PathBuf,
}

impl NetdevCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for NetdevCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 单设备解析结果：接口名 + procNetDevStats 键名 → 值映射
type DeviceStats = Vec<(String, HashMap<String, u64>)>;

/// 解析 /proc/net/dev：返回各设备的 procNetDevStats 键值表。
/// 对齐 procfs NetDev 解析：跳过两行表头，每行按冒号拆出接口名，
/// 冒号后必须恰好 16 个数值字段。
fn parse_net_dev(text: &str) -> Result<DeviceStats, CollectorError> {
    let mut devices = Vec::new();
    // 跳过两行表头
    for line in text.lines().skip(2) {
        if line.trim().is_empty() {
            continue;
        }
        let Some((name_part, values_part)) = line.split_once(':') else {
            return Err(CollectorError::Parse {
                file: NETDEV_FILE,
                reason: format!("缺少冒号分隔: {line}"),
            });
        };
        let device = name_part.trim().to_string();
        let fields: Vec<&str> = values_part.split_whitespace().collect();
        if fields.len() != PROC_DEV_KEYS.len() {
            return Err(CollectorError::Parse {
                file: NETDEV_FILE,
                reason: format!("设备 {device} 字段数 {} != 16", fields.len()),
            });
        }
        let mut stats = HashMap::with_capacity(PROC_DEV_KEYS.len());
        for (key, index) in PROC_DEV_KEYS {
            let value: u64 = fields[index]
                .parse()
                .map_err(|error| CollectorError::Parse {
                    file: NETDEV_FILE,
                    reason: format!("设备 {device} 字段 {key} 值非法: {error}"),
                })?;
            stats.insert(key.to_string(), value);
        }
        devices.push((device, stats));
    }
    Ok(devices)
}

/// 弹出键值（对齐 Go pop：存在则取出并删除）
fn pop(stats: &mut HashMap<String, u64>, key: &str) -> Option<u64> {
    stats.remove(key)
}

/// 弹出键值，不存在时按 0（对齐 Go popz）
fn popz(stats: &mut HashMap<String, u64>, key: &str) -> u64 {
    stats.remove(key).unwrap_or(0)
}

/// 对齐 netdev_common.go 的 legacy()：将详细键名合并为 /proc/net/dev
/// 传统键名（receive_errors → receive_errs 等）
fn legacy(stats: &mut HashMap<String, u64>) {
    if let Some(value) = pop(stats, "receive_errors") {
        stats.insert("receive_errs".to_string(), value);
    }
    if let Some(value) = pop(stats, "receive_dropped") {
        let missed = popz(stats, "receive_missed_errors");
        stats.insert("receive_drop".to_string(), value + missed);
    }
    if let Some(value) = pop(stats, "receive_fifo_errors") {
        stats.insert("receive_fifo".to_string(), value);
    }
    if let Some(value) = pop(stats, "receive_frame_errors") {
        let total = value
            + popz(stats, "receive_length_errors")
            + popz(stats, "receive_over_errors")
            + popz(stats, "receive_crc_errors");
        stats.insert("receive_frame".to_string(), total);
    }
    if let Some(value) = pop(stats, "multicast") {
        stats.insert("receive_multicast".to_string(), value);
    }
    if let Some(value) = pop(stats, "transmit_errors") {
        stats.insert("transmit_errs".to_string(), value);
    }
    if let Some(value) = pop(stats, "transmit_dropped") {
        stats.insert("transmit_drop".to_string(), value);
    }
    if let Some(value) = pop(stats, "transmit_fifo_errors") {
        stats.insert("transmit_fifo".to_string(), value);
    }
    if let Some(value) = pop(stats, "collisions") {
        stats.insert("transmit_colls".to_string(), value);
    }
    if let Some(value) = pop(stats, "transmit_carrier_errors") {
        let total = value
            + popz(stats, "transmit_aborted_errors")
            + popz(stats, "transmit_heartbeat_errors")
            + popz(stats, "transmit_window_errors");
        stats.insert("transmit_carrier".to_string(), total);
    }
}

impl Collector for NetdevCollector {
    fn name(&self) -> &'static str {
        "netdev"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let text = std::fs::read_to_string(self.proc_path.join(NETDEV_FILE))?;
        let mut devices = parse_net_dev(&text)?;
        if devices.is_empty() {
            return Err(CollectorError::NoData);
        }

        // 逐设备执行 legacy() 键名转换（对齐 Update 中 !detailed 分支）
        for (_, stats) in &mut devices {
            legacy(stats);
        }

        // 每个键一个指标族，样本按设备追加；设备名直通作 device 标签
        let mut families = Vec::with_capacity(LEGACY_KEYS.len());
        for key in LEGACY_KEYS {
            let mut family = MetricFamily::new(
                &format!("node_network_{key}_total"),
                &format!("Network device statistic {key}."),
                MetricType::Counter,
            );
            for (device, stats) in &devices {
                // 对齐 Go：map 中不存在的键不输出样本
                if let Some(value) = stats.get(key) {
                    family
                        .push_labeled(vec![("device".to_string(), device.clone())], *value as f64);
                }
            }
            families.push(family);
        }
        Ok(families)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    /// 按设备标签取样本值
    fn device_value(family: &MetricFamily, device: &str) -> f64 {
        family
            .samples
            .iter()
            .find(|s| s.labels.iter().any(|(k, v)| k == "device" && v == device))
            .unwrap_or_else(|| panic!("缺少设备 {device} 样本"))
            .value
    }

    #[test]
    fn test_collect_matches_fixture() {
        let collector = NetdevCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));

        // 全部 16 个指标族名称与顺序对齐 legacy 键名列表
        let expected: Vec<String> = LEGACY_KEYS
            .iter()
            .map(|key| format!("node_network_{key}_total"))
            .collect();
        let names: Vec<&str> = families.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            expected.iter().map(String::as_str).collect::<Vec<_>>()
        );

        // 全部为 Counter 类型，help 文案对齐 Go metricDesc
        for family in &families {
            assert_eq!(family.mtype, MetricType::Counter);
            let key = family
                .name
                .trim_start_matches("node_network_")
                .trim_end_matches("_total");
            assert_eq!(family.help, format!("Network device statistic {key}."));
        }

        // 每台设备都有样本（fixture 共 6 台）
        for family in &families {
            assert_eq!(family.samples.len(), 6, "指标 {} 样本数不符", family.name);
        }

        // 抽查数值：eth0 原始 16 列经 legacy 重命名后取值
        assert_eq!(device_value(&families[2], "eth0"), 68210035552.0);
        // receive_errors → receive_errs
        assert_eq!(device_value(&families[4], "eth0"), 14.0);
        // receive_dropped → receive_drop
        assert_eq!(device_value(&families[6], "eth0"), 10.0);
        // /proc 列 receive_frame 原名保留
        assert_eq!(device_value(&families[10], "eth0"), 5.0);
        // flannel.1 的 transmit_dropped
        assert_eq!(device_value(&families[7], "flannel.1"), 64.0);
        // lxcbr0 仅有发送流量
        assert_eq!(device_value(&families[0], "lxcbr0"), 0.0);
        assert_eq!(device_value(&families[3], "lxcbr0"), 2630299.0);
    }

    #[test]
    fn test_parse_rejects_malformed_lines() {
        assert!(matches!(
            parse_net_dev("Inter-| Receive | Transmit\n face |cols\nlo: 1 2"),
            Err(CollectorError::Parse { .. })
        ));
        assert!(matches!(
            parse_net_dev("Inter-| Receive | Transmit\n face |cols\nlo: 1 2 3"),
            Err(CollectorError::Parse { .. })
        ));
        assert!(matches!(
            parse_net_dev(
                "Inter-| Receive | Transmit\n face |cols\nlo: a b c d e f g h i j k l m n o p",
            ),
            Err(CollectorError::Parse { .. })
        ));
    }

    #[test]
    fn test_parse_skips_blank_lines() {
        let text = "Inter-|   Receive   |  Transmit\n face |cols\n\n  lo: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n";
        let devices = parse_net_dev(text).unwrap_or_else(|error| panic!("解析失败: {error}"));
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].0, "lo");
        assert_eq!(devices[0].1["receive_bytes"], 1);
        assert_eq!(devices[0].1["transmit_compressed"], 16);
    }
}
