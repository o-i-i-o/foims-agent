//! net 采集器（对齐 Go `internal/collector/net/` 的 metrics 子采集器）。
//!
//! PDH 对象 `Network Interface`，通配实例；输出 13 个指标族（与
//! perfDataCounterValues 的 13 个 perfdata 标签一一对应，标签 {nic} =
//! 实例名）。全部为 counter，仅 output_queue_length_packets 与
//! current_bandwidth_bytes 为 gauge（后者由 bits 换算 bytes，÷8）。
//!
//! 与 Go 的偏离：
//! - `nic_info` 子采集器（上游标注 experimental，需 GetAdaptersAddresses
//!   解析适配器链表）跳过：windows_net_nic_info / windows_net_nic_operation_status
//!   / windows_net_nic_address_info 三个指标族不输出；
//! - include/exclude 正则过滤未移植（本 crate 无采集器级配置面）。

use foims_agent_core::collector::{Collector, CollectorError};
use foims_agent_core::metric::{MetricFamily, MetricType};

use super::CollectorRow;

/// PDH 计数器清单（与 Go perfDataCounterValues 的 perfdata 标签逐字一致，
/// 顺序即索引约定，勿调整）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const COUNTERS: &[&str] = &[
    "Bytes Received/sec",
    "Bytes Sent/sec",
    "Bytes Total/sec",
    "Current Bandwidth",
    "Output Queue Length",
    "Packets Outbound Discarded",
    "Packets Outbound Errors",
    "Packets/sec",
    "Packets Received Discarded",
    "Packets Received Errors",
    "Packets Received/sec",
    "Packets Received Unknown",
    "Packets Sent/sec",
];

// 上述清单的索引常量（采集器取值用；跨平台供发射函数与测试引用）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
mod idx {
    pub(super) const BYTES_RECEIVED: usize = 0;
    pub(super) const BYTES_SENT: usize = 1;
    pub(super) const BYTES_TOTAL: usize = 2;
    pub(super) const CURRENT_BANDWIDTH: usize = 3;
    pub(super) const OUTPUT_QUEUE_LENGTH: usize = 4;
    pub(super) const PACKETS_OUTBOUND_DISCARDED: usize = 5;
    pub(super) const PACKETS_OUTBOUND_ERRORS: usize = 6;
    pub(super) const PACKETS: usize = 7;
    pub(super) const PACKETS_RECEIVED_DISCARDED: usize = 8;
    pub(super) const PACKETS_RECEIVED_ERRORS: usize = 9;
    pub(super) const PACKETS_RECEIVED: usize = 10;
    pub(super) const PACKETS_RECEIVED_UNKNOWN: usize = 11;
    pub(super) const PACKETS_SENT: usize = 12;
}

/// net 采集器：持有 PDH 计数器集
pub struct NetCollector {
    /// PDH 计数器集（初始化失败或非 windows 目标为 None）
    #[cfg(target_os = "windows")]
    set: Option<super::PdhCounterSet>,
}

impl NetCollector {
    /// 默认构造（对齐 Go New(&ConfigDefaults)）
    pub fn new() -> Self {
        #[cfg(target_os = "windows")]
        {
            match super::PdhCounterSet::new("Network Interface", COUNTERS) {
                Ok(set) => Self { set: Some(set) },
                // PDH 初始化失败时保留空集，collect 时按 NoData 上报，
                // 保证单采集器故障不拖垮其余采集器
                Err(error) => {
                    tracing::warn!(%error, "net 采集器 PDH 初始化失败");
                    Self { set: None }
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        Self {}
    }
}

impl Default for NetCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for NetCollector {
    fn name(&self) -> &'static str {
        "net"
    }

    fn collect(&self) -> Result<Vec<MetricFamily>, CollectorError> {
        #[cfg(target_os = "windows")]
        match &self.set {
            None => Err(CollectorError::NoData),
            Some(set) => {
                set.collect().map_err(super::collector_error)?;
                let rows = set.sample_instanced().map_err(super::collector_error)?;
                Ok(emit_net(&rows))
            }
        }
        #[cfg(not(target_os = "windows"))]
        Err(CollectorError::NoData)
    }
}

/// Current Bandwidth（bits/s）→ current_bandwidth_bytes（bytes/s，÷8，
/// 对齐 Go 的 data.CurrentBandwidth/8）
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn bandwidth_bytes(bits_per_sec: f64) -> f64 {
    bits_per_sec / 8.0
}

/// 由通配实例样本构造全部 net 指标族（纯函数，Linux 宿主可测）。
///
/// 发射顺序镜像 Go collect()：bytes_received → bytes_sent → bytes_total →
/// output_queue_length → packets_outbound_discarded → packets_outbound_errors
/// → packets_total → packets_received_discarded → packets_received_errors →
/// packets_received → packets_received_unknown → packets_sent →
/// current_bandwidth。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn emit_net(rows: &[CollectorRow]) -> Vec<MetricFamily> {
    use idx::{
        BYTES_RECEIVED, BYTES_SENT, BYTES_TOTAL, CURRENT_BANDWIDTH, OUTPUT_QUEUE_LENGTH, PACKETS,
        PACKETS_OUTBOUND_DISCARDED, PACKETS_OUTBOUND_ERRORS, PACKETS_RECEIVED,
        PACKETS_RECEIVED_DISCARDED, PACKETS_RECEIVED_ERRORS, PACKETS_RECEIVED_UNKNOWN,
        PACKETS_SENT,
    };

    // (名称, help, 类型, 计数器索引, 是否为带宽换算)
    let definitions: &[(&str, &str, MetricType, usize, bool)] = &[
        (
            "windows_net_bytes_received_total",
            "(Network.BytesReceivedPerSec)",
            MetricType::Counter,
            BYTES_RECEIVED,
            false,
        ),
        (
            "windows_net_bytes_sent_total",
            "(Network.BytesSentPerSec)",
            MetricType::Counter,
            BYTES_SENT,
            false,
        ),
        (
            "windows_net_bytes_total",
            "(Network.BytesTotalPerSec)",
            MetricType::Counter,
            BYTES_TOTAL,
            false,
        ),
        (
            "windows_net_output_queue_length_packets",
            "(Network.OutputQueueLength)",
            MetricType::Gauge,
            OUTPUT_QUEUE_LENGTH,
            false,
        ),
        (
            "windows_net_packets_outbound_discarded_total",
            "(Network.PacketsOutboundDiscarded)",
            MetricType::Counter,
            PACKETS_OUTBOUND_DISCARDED,
            false,
        ),
        (
            "windows_net_packets_outbound_errors_total",
            "(Network.PacketsOutboundErrors)",
            MetricType::Counter,
            PACKETS_OUTBOUND_ERRORS,
            false,
        ),
        (
            "windows_net_packets_total",
            "(Network.PacketsPerSec)",
            MetricType::Counter,
            PACKETS,
            false,
        ),
        (
            "windows_net_packets_received_discarded_total",
            "(Network.PacketsReceivedDiscarded)",
            MetricType::Counter,
            PACKETS_RECEIVED_DISCARDED,
            false,
        ),
        (
            "windows_net_packets_received_errors_total",
            "(Network.PacketsReceivedErrors)",
            MetricType::Counter,
            PACKETS_RECEIVED_ERRORS,
            false,
        ),
        (
            "windows_net_packets_received_total",
            "(Network.PacketsReceivedPerSec)",
            MetricType::Counter,
            PACKETS_RECEIVED,
            false,
        ),
        (
            "windows_net_packets_received_unknown_total",
            "(Network.PacketsReceivedUnknown)",
            MetricType::Counter,
            PACKETS_RECEIVED_UNKNOWN,
            false,
        ),
        (
            "windows_net_packets_sent_total",
            "(Network.PacketsSentPerSec)",
            MetricType::Counter,
            PACKETS_SENT,
            false,
        ),
        (
            "windows_net_current_bandwidth_bytes",
            "(Network.CurrentBandwidth)",
            MetricType::Gauge,
            CURRENT_BANDWIDTH,
            true,
        ),
    ];

    let mut out = Vec::with_capacity(definitions.len());
    for (name, help, mtype, index, is_bandwidth) in definitions {
        let mut family = MetricFamily::new(name, help, *mtype);
        for row in rows {
            // sample_instanced 已保证全计数器有效，缺项仅可能来自直接调用发射函数的测试
            if let Some(sample) = row.values.get(*index).and_then(Option::as_ref) {
                let value = if *is_bandwidth {
                    bandwidth_bytes(sample.value())
                } else {
                    sample.value()
                };
                family.push_labeled(nic_labels(&row.instance), value);
            }
        }
        if !family.samples.is_empty() {
            out.push(family);
        }
    }
    out
}

fn nic_labels(nic: &str) -> Vec<(String, String)> {
    vec![("nic".to_string(), nic.to_string())]
}

#[cfg(test)]
mod tests {
    use super::super::RawSample;
    use super::*;

    /// 以原值类型构造样本行
    fn row(instance: &str, first: i64) -> CollectorRow {
        CollectorRow {
            instance: instance.to_string(),
            values: COUNTERS
                .iter()
                .map(|_| {
                    Some(RawSample {
                        first,
                        second: 0,
                        counter_type: 0,
                    })
                })
                .collect(),
        }
    }

    /// 13 个指标族齐全，顺序与类型正确，{nic} 标签取实例名
    #[test]
    fn test_emit_net_family_layout() {
        let rows = vec![row("Ethernet", 800), row("Loopback*", 100)];
        let families = emit_net(&rows);

        let names: Vec<&str> = families.iter().map(|family| family.name.as_str()).collect();
        assert_eq!(names.len(), 13, "{names:?}");
        assert_eq!(names[0], "windows_net_bytes_received_total");
        assert_eq!(names[3], "windows_net_output_queue_length_packets");
        assert_eq!(names[12], "windows_net_current_bandwidth_bytes");

        // gauge 抽查
        let queue = families
            .iter()
            .find(|family| family.name == "windows_net_output_queue_length_packets")
            .unwrap_or_else(|| panic!("缺少 output_queue_length_packets"));
        assert_eq!(queue.mtype, MetricType::Gauge);
        // counter 抽查
        let received = families
            .iter()
            .find(|family| family.name == "windows_net_bytes_received_total")
            .unwrap_or_else(|| panic!("缺少 bytes_received_total"));
        assert_eq!(received.mtype, MetricType::Counter);
        assert_eq!(received.samples.len(), 2);
        assert_eq!(
            received.samples[0].labels,
            vec![("nic".to_string(), "Ethernet".to_string())]
        );
        assert_eq!(received.samples[0].value, 800.0);
    }

    /// Current Bandwidth 原值 ÷8 进 current_bandwidth_bytes
    #[test]
    fn test_current_bandwidth_scaled() {
        let rows = vec![row("Ethernet", 1_000_000_000)];
        let families = emit_net(&rows);
        let bandwidth = families
            .iter()
            .find(|family| family.name == "windows_net_current_bandwidth_bytes")
            .unwrap_or_else(|| panic!("缺少 current_bandwidth_bytes"));
        assert_eq!(bandwidth.samples[0].value, 125_000_000.0);
        assert_eq!(bandwidth_bytes(1_000_000_000.0), 125_000_000.0);
        assert_eq!(bandwidth_bytes(0.0), 0.0);
    }

    /// 无实例行时不输出任何指标族（对齐 Go 逐条发射语义）
    #[test]
    fn test_emit_net_empty() {
        assert!(emit_net(&[]).is_empty());
    }

    /// 计数器清单与索引常量一致（防手误）
    #[cfg(target_os = "windows")]
    #[test]
    fn test_counter_index_layout() {
        assert_eq!(COUNTERS.len(), 13);
        assert_eq!(COUNTERS[idx::BYTES_RECEIVED], "Bytes Received/sec");
        assert_eq!(COUNTERS[idx::PACKETS_SENT], "Packets Sent/sec");
    }
}
