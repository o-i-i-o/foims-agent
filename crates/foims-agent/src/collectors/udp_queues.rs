//! udp_queues 采集器：UDP 收发队列占用。
//!
//! 对齐 node_exporter `udp_queues_linux.go`（默认启用）：解析
//! /proc/net/udp 与 /proc/net/udp6 每条 socket 的 tx_queue:rx_queue
//! 十六进制字段（第 5 列，冒号分隔）并求和，输出单一指标族
//! `node_udp_queues{queue,ip}`（Gauge；queue=tx/rx，ip=v4/v6）。
//! 单边文件缺失时跳过该侧；两侧均缺失返回 NoData；
//! 队列字段非法时按 0 计（对齐 procfs 的宽容策略）。

use std::path::PathBuf;

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

/// UDP socket 表（相对 proc_path）
const UDP_FILE: &str = "net/udp";
const UDP6_FILE: &str = "net/udp6";

pub struct UdpQueuesCollector {
    proc_path: PathBuf,
}

impl UdpQueuesCollector {
    /// 生产构造：读取真实 /proc
    pub fn new() -> Self {
        Self::with_root(PathBuf::from("/proc"))
    }

    /// 指定 /proc 根目录（测试注入 fixture）
    pub fn with_root(proc_path: PathBuf) -> Self {
        Self { proc_path }
    }
}

impl Default for UdpQueuesCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 单个 socket 表的 (tx, rx) 队列长度合计
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct UdpQueueSums {
    tx: u64,
    rx: u64,
}

/// 解析 socket 表文本：累加每行 tx_queue:rx_queue（第 5 列，冒号分隔的
/// 两个十六进制值）；表头行与残缺行跳过，非法字段按 0 计
fn parse_udp_queues(text: &str) -> UdpQueueSums {
    let mut sums = UdpQueueSums::default();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // 数据行首列以冒号结尾（如 "0:"）；表头行 "sl" 跳过
        if fields.len() < 5 || !fields[0].ends_with(':') {
            continue;
        }
        let Some((tx, rx)) = fields[4].split_once(':') else {
            continue;
        };
        // 非法值按 0 计（对齐 procfs 解析失败置零的行为）
        sums.tx += u64::from_str_radix(tx, 16).unwrap_or(0);
        sums.rx += u64::from_str_radix(rx, 16).unwrap_or(0);
    }
    sums
}

impl Collector for UdpQueuesCollector {
    fn name(&self) -> &'static str {
        "udp_queues"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        let read_sums = |file: &str| -> Result<Option<UdpQueueSums>, CollectorError> {
            match std::fs::read_to_string(self.proc_path.join(file)) {
                Ok(text) => Ok(Some(parse_udp_queues(&text))),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
            }
        };
        let v4 = read_sums(UDP_FILE)?;
        let v6 = read_sums(UDP6_FILE)?;
        if v4.is_none() && v6.is_none() {
            return Err(CollectorError::NoData);
        }

        let mut family = MetricFamily::new(
            "node_udp_queues",
            "Number of allocated memory in the kernel for UDP datagrams in bytes.",
            MetricType::Gauge,
        );
        let mut push = |ip: &str, sums: UdpQueueSums| {
            family.push_labeled(
                vec![
                    ("queue".to_string(), "tx".to_string()),
                    ("ip".to_string(), ip.to_string()),
                ],
                sums.tx as f64,
            );
            family.push_labeled(
                vec![
                    ("queue".to_string(), "rx".to_string()),
                    ("ip".to_string(), ip.to_string()),
                ],
                sums.rx as f64,
            );
        };
        if let Some(sums) = v4 {
            push("v4", sums);
        }
        if let Some(sums) = v6 {
            push("v6", sums);
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
        let collector = UdpQueuesCollector::with_root(fixture_root());
        let families = collector
            .collect()
            .unwrap_or_else(|e| panic!("采集失败: {e}"));
        assert_eq!(families.len(), 1);
        let family = &families[0];
        assert_eq!(family.name, "node_udp_queues");
        assert_eq!(family.mtype, MetricType::Gauge);
        // fixture：udp6 缺失 → 仅 v4 两个样本；tx=0x15=21，rx=0
        assert_eq!(family.samples.len(), 2);
        let value = |queue: &str, ip: &str| -> f64 {
            family
                .samples
                .iter()
                .find(|s| {
                    s.labels.iter().any(|(k, v)| k == "queue" && v == queue)
                        && s.labels.iter().any(|(k, v)| k == "ip" && v == ip)
                })
                .unwrap_or_else(|| panic!("缺少样本 queue={queue} ip={ip}"))
                .value
        };
        assert_eq!(value("tx", "v4"), 21.0);
        assert_eq!(value("rx", "v4"), 0.0);
    }

    #[test]
    fn test_parse_sums_queue_lengths() {
        let sums = parse_udp_queues(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0016 00000000:0000 0A 00000015:00000000 00:00000000 00000000     0        0 2740\n   1: 00000000:0035 00000000:0000 07 00000005:00000002 00:00000000 00000000     0        0 2741\n",
        );
        assert_eq!(sums.tx, 0x15 + 5);
        assert_eq!(sums.rx, 2);
    }

    #[test]
    fn test_missing_both_files_is_nodata() {
        let collector = UdpQueuesCollector::with_root(PathBuf::from("/nonexistent-foims-test"));
        assert!(matches!(collector.collect(), Err(CollectorError::NoData)));
    }
}
